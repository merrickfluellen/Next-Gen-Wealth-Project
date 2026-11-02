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
 *  - Quotes are kept PER COIN: a reply missing some coins updates the others and keeps each missing
 *    coin's last good quote (for up to 30 min).
 *  - A price is rejected (the last good one is kept) when it moves more than 50 % from the last good
 *    quote of the last 30 min, is more than 20x away from a rough reference price, or — for the
 *    stablecoins USDT/USDC/DAI — is outside 0.90–1.10. Prices are rounded to 8 significant digits.
 *  - The CDN may cache an answer only when EVERY coin was refreshed just now; a partial / stale
 *    answer is "private, max-age=15" (browser only).
 *  - lib/firewall.js in front (GET/HEAD, Origin allow-list, light per-IP limit 30/min per instance,
 *    attack filter); CDN hits never reach the function, so the limit only meets cache misses.
 *  - On upstream failure, recent stale data is served; upstream errors are never echoed to the client.
 */
const { withFirewall } = require('./lib/firewall');

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
const MAX_JUMP = 0.5;                    // reject a price > 50 % away from the last good one
const REF_BAND = 20;                     // …or > 20x away from the rough reference below
const STABLE = new Set(['USDT', 'USDC', 'DAI']);
const STABLE_LO = 0.9, STABLE_HI = 1.1;
// Rough reference prices (mid-2025, the app's built-in defaults). Only a wide 20x sanity band.
const REF = { BTC: 105000, ETH: 3800, BNB: 710, SOL: 185, XRP: 2.45, ADA: 0.72, AVAX: 38, DOGE: 0.21, TRX: 0.26,
  LINK: 18, DOT: 7.5, MATIC: 0.52, TON: 5.8, SHIB: 0.0000265, LTC: 95, BCH: 430, UNI: 9.2, ATOM: 7.1, XLM: 0.38,
  NEAR: 5.8, XMR: 185, ETC: 27, ALGO: 0.22, HBAR: 0.095, FIL: 5.1, AAVE: 225, VET: 0.038 };

const CACHE_TTL = 60 * 1000;
const STALE_TTL = 30 * 60 * 1000;
const RETRY_MS = 20 * 1000;            // after a partial / failed refresh, try again sooner than CACHE_TTL

const _quotes = Object.create(null);   // sym → { q:{price,change24h,marketCap}, at } (last GOOD quote)
let _refreshedAt = 0;
let _nextRefresh = 0;
let _complete = false;
let _inflight = null;

const BASE_HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'X-Content-Type-Options': 'nosniff',
};
const CACHE_HEADERS = {
  'Cache-Control': 'public, max-age=30',
  'Netlify-CDN-Cache-Control': 'public, s-maxage=60, stale-while-revalidate=120',
};
const PARTIAL_HEADERS = { 'Cache-Control': 'private, max-age=15' };
const NO_STORE = { 'Cache-Control': 'no-store' };

// lib/firewall.js always sets Cache-Control itself (no-store by default), so the policy this handler
// wants for a 200 is remembered per event and put back by the outer wrapper below.
const _wantCache = new WeakMap();
function reply(event, statusCode, obj, extra) {
  const headers = { ...BASE_HEADERS, ...extra };
  if (headers['Cache-Control']) _wantCache.set(event, headers['Cache-Control']);
  return { statusCode, headers, body: JSON.stringify(obj) };
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
const round8 = (v) => Number(v.toPrecision(8));

/** Last good quote for `sym` if it is younger than STALE_TTL, else null. */
function recent(sym, now = Date.now()) {
  const e = _quotes[sym];
  return e && now - e.at < STALE_TTL ? e.q : null;
}

/** Sanity checks on a new price: stablecoin band / reference band, then max move vs the last good quote. */
function plausible(sym, price, prev) {
  if (!finiteIn(price, 0, MAX_PRICE) || price <= 0) return false;
  if (STABLE.has(sym)) return price >= STABLE_LO && price <= STABLE_HI;
  const ref = REF[sym];
  if (ref && (price > ref * REF_BAND || price < ref / REF_BAND)) return false;
  if (prev && Math.abs(price / prev - 1) > MAX_JUMP) return false;
  return true;
}

/** Upstream JSON → { SYM: {price, change24h, marketCap} } for well-formed entries (no plausibility check yet). */
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
      price: round8(data.usd),
      change24h: finiteIn(ch, -100, MAX_CHANGE_PCT) ? Math.round(ch * 100) / 100 : 0,
      marketCap: finiteIn(mc, 0, MAX_MCAP) ? Math.round(mc) : 0,
    };
  }
  return result;
}

function snapshot() {
  const now = Date.now();
  const out = {};
  for (const id of SAFE_IDS) { const sym = ID_TO_SYM[id]; const q = recent(sym, now); if (q) out[sym] = q; }
  return out;
}

async function refresh() {
  const json = await fetchJson(UPSTREAM_URL, {
    timeoutMs: TIMEOUT_MS,
    maxBytes: MAX_UPSTREAM_BYTES,
    headers: { 'User-Agent': 'InvestEd-Pro/1.0', 'Accept': 'application/json' },
  });
  const parsed = parseCoins(json);
  let fresh = 0;
  const now = Date.now();
  for (const [sym, q] of Object.entries(parsed)) {
    const prev = recent(sym, now);
    if (plausible(sym, q.price, prev && prev.price)) { _quotes[sym] = { q, at: now }; fresh++; }
  }
  _complete = fresh === SAFE_IDS.length;
  _refreshedAt = Date.now();
  _nextRefresh = _refreshedAt + (_complete ? CACHE_TTL : RETRY_MS);
}

function answer(event) {
  const data = snapshot();
  if (!Object.keys(data).length) return reply(event, 503, {}, NO_STORE);
  return reply(event, 200, data, _complete ? CACHE_HEADERS : PARTIAL_HEADERS);
}

async function handle(event) {
  if (Date.now() < _nextRefresh) return answer(event);
  if (!_inflight) _inflight = refresh().catch(() => {}).finally(() => { _inflight = null; });
  await _inflight;
  return answer(event);
}

const firewalled = withFirewall(handle, {
  name: 'get-crypto',
  methods: ['GET', 'HEAD'],
  rateLimit: { windowMs: 60 * 1000, max: 30 },
  json: false,
});

exports.handler = async (event, context) => {
  event = event && typeof event === 'object' ? event : {};
  const res = await firewalled(event, context);
  const cc = _wantCache.get(event);
  if (res && res.statusCode === 200 && cc && res.headers) res.headers['Cache-Control'] = cc;
  return res;
};
