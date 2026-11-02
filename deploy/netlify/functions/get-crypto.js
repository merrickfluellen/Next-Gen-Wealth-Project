/**
 * get-crypto — live crypto price proxy via CoinGecko (free, no API key)
 * GET /.netlify/functions/get-crypto → { BTC: { price, change24h, marketCap }, ... }
 *
 * Hardening:
 *  - The coin list is a fixed server-side allowlist; nothing from the request reaches the upstream URL.
 *  - GET/HEAD only; same-origin only (no wildcard CORS — the app calls this from its own origin).
 *  - Upstream call has a hard AbortController timeout, a response size cap, a status check and
 *    numeric sanity checks (finite, non-negative, bounded); malformed entries are skipped, not fatal.
 *  - One in-flight refresh per warm instance + 60 s in-memory cache + CDN caching (s-maxage) to cut
 *    CoinGecko usage (free tier is rate-limited) and prevent DoS amplification.
 *  - On upstream failure, recent stale data is served; upstream errors are never echoed to the client.
 */

const COIN_IDS = [
  'bitcoin','ethereum','tether','binancecoin','solana','ripple','usd-coin',
  'cardano','avalanche-2','dogecoin','tron','chainlink','polkadot','matic-network',
  'the-open-network','shiba-inu','dai','litecoin','bitcoin-cash','uniswap',
  'cosmos','stellar','near','monero','ethereum-classic','algorand',
  'hedera-hashgraph','filecoin','aave','vechain',
];

const ID_TO_SYM = {
  'bitcoin':'BTC','ethereum':'ETH','tether':'USDT','binancecoin':'BNB',
  'solana':'SOL','ripple':'XRP','usd-coin':'USDC','cardano':'ADA',
  'avalanche-2':'AVAX','dogecoin':'DOGE','tron':'TRX','chainlink':'LINK',
  'polkadot':'DOT','matic-network':'MATIC','the-open-network':'TON',
  'shiba-inu':'SHIB','dai':'DAI','litecoin':'LTC','bitcoin-cash':'BCH',
  'uniswap':'UNI','cosmos':'ATOM','stellar':'XLM','near':'NEAR',
  'monero':'XMR','ethereum-classic':'ETC','algorand':'ALGO',
  'hedera-hashgraph':'HBAR','filecoin':'FIL','aave':'AAVE','vechain':'VET',
};

const ID_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;   // defensive: list is static, but never send anything odd upstream
const MAX_IDS = 50;
const SAFE_IDS = COIN_IDS
  .filter(id => typeof id === 'string' && id.length <= 40 && ID_RE.test(id) && Object.prototype.hasOwnProperty.call(ID_TO_SYM, id))
  .slice(0, MAX_IDS);

const UPSTREAM_URL = 'https://api.coingecko.com/api/v3/simple/price?ids=' + SAFE_IDS.map(encodeURIComponent).join('%2C')
  + '&vs_currencies=usd&include_24hr_change=true&include_market_cap=true&precision=6';
const TIMEOUT_MS = 6000;
const MAX_UPSTREAM_BYTES = 256 * 1024;   // the real response is ~5 KB
const MAX_PRICE = 1e9;
const MAX_MCAP = 1e15;
const MAX_CHANGE_PCT = 1e5;

const CACHE_TTL = 60 * 1000;
const STALE_TTL = 30 * 60 * 1000;

let _cache = null;
let _cacheAt = 0;
let _inflight = null;

const BASE_HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'X-Content-Type-Options': 'nosniff',
};
const CACHE_HEADERS = {
  'Cache-Control': 'public, max-age=30',
  'Netlify-CDN-Cache-Control': 'public, s-maxage=60, stale-while-revalidate=120',
};
const NO_STORE = { 'Cache-Control': 'no-store' };

function reply(statusCode, obj, extra) {
  return { statusCode, headers: { ...BASE_HEADERS, ...extra }, body: JSON.stringify(obj) };
}

// Fetch JSON with a hard timeout, a status check and a body size cap. Returns null on any failure.
async function fetchJson(url, { timeoutMs, maxBytes, headers }) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { headers, signal: ctrl.signal, redirect: 'error' });
    if (!res || !res.ok) return null;
    const len = Number(res.headers && res.headers.get && res.headers.get('content-length'));
    if (Number.isFinite(len) && len > maxBytes) { ctrl.abort(); return null; }
    let text = '';
    if (res.body && typeof res.body.getReader === 'function') {
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let total = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > maxBytes) { ctrl.abort(); return null; }
        text += decoder.decode(value, { stream: true });
      }
      text += decoder.decode();
    } else {
      text = await res.text();
      if (Buffer.byteLength(text) > maxBytes) return null;
    }
    return JSON.parse(text);
  } catch {
    return null;   // network error, abort/timeout, bad JSON — never surfaced to the client
  } finally {
    clearTimeout(timer);
  }
}

const finiteIn = (v, lo, hi) => typeof v === 'number' && Number.isFinite(v) && v >= lo && v <= hi;

function parseCoins(json) {
  const result = {};
  if (!json || typeof json !== 'object' || Array.isArray(json)) return result;
  for (const id of SAFE_IDS) {                       // iterate our allowlist, not upstream keys
    const data = Object.prototype.hasOwnProperty.call(json, id) ? json[id] : null;
    if (!data || typeof data !== 'object') continue;
    if (!finiteIn(data.usd, 0, MAX_PRICE) || data.usd === 0) continue;
    const ch = data.usd_24h_change;
    const mc = data.usd_market_cap;
    result[ID_TO_SYM[id]] = {
      price: data.usd,
      change24h: finiteIn(ch, -100, MAX_CHANGE_PCT) ? Math.round(ch * 100) / 100 : 0,
      marketCap: finiteIn(mc, 0, MAX_MCAP) ? mc : 0,
    };
  }
  return result;
}

async function refresh() {
  const json = await fetchJson(UPSTREAM_URL, {
    timeoutMs: TIMEOUT_MS,
    maxBytes: MAX_UPSTREAM_BYTES,
    headers: { 'User-Agent': 'InvestEd-Pro/1.0', 'Accept': 'application/json' },
  });
  const result = parseCoins(json);
  if (Object.keys(result).length > 0) {
    _cache = result;
    _cacheAt = Date.now();
  }
  return result;
}

exports.handler = async (event) => {
  const method = ((event && event.httpMethod) || 'GET').toUpperCase();
  if (method !== 'GET' && method !== 'HEAD') {
    return reply(405, { error: 'Method not allowed' }, { ...NO_STORE, Allow: 'GET, HEAD' });
  }

  if (_cache && Date.now() - _cacheAt < CACHE_TTL) return reply(200, _cache, CACHE_HEADERS);

  if (!_inflight) _inflight = refresh().finally(() => { _inflight = null; });
  const result = await _inflight;

  if (Object.keys(result).length > 0) return reply(200, result, CACHE_HEADERS);
  if (_cache && Date.now() - _cacheAt < STALE_TTL) return reply(200, _cache, { 'Cache-Control': 'public, max-age=15' });
  return reply(503, {}, NO_STORE);
};
