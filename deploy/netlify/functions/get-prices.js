/**
 * get-prices — live stock price proxy via Yahoo Finance
 * GET /.netlify/functions/get-prices → { AAPL: 293.64, MSFT: 412.67, ... }
 *
 * Fetches prices server-side so the browser never touches Yahoo Finance directly
 * (avoids CORS issues and keeps CSP clean).
 *
 * Hardening:
 *  - The symbol list is a fixed server-side allowlist; nothing from the request reaches the upstream URL.
 *  - GET/HEAD only; same-origin only (no wildcard CORS — the app calls this from its own origin).
 *  - Every upstream call has a hard AbortController timeout, a response size cap, a status check
 *    and numeric sanity checks (finite, positive, bounded).
 *  - One in-flight refresh per warm instance (concurrent requests share it) + 60 s in-memory cache
 *    + CDN caching (s-maxage) so traffic spikes can't be amplified into upstream request floods.
 *  - On upstream failure, recent stale data is served; upstream errors are never echoed to the client.
 */

const SYMBOLS = [
  'AAPL','MSFT','GOOGL','AMZN','TSLA','META','NVDA',
  'JNJ','PG','KO','WMT','XOM','BAC',
  'SPY','VOO','BND','TLT',
];
const SYMBOL_RE = /^[A-Z]{1,5}(?:[.-][A-Z]{1,2})?$/;   // defensive: list is static, but never send anything odd upstream
const MAX_SYMBOLS = 25;
const SAFE_SYMBOLS = SYMBOLS.filter(s => typeof s === 'string' && s.length <= 8 && SYMBOL_RE.test(s)).slice(0, MAX_SYMBOLS);

const UPSTREAM_HOST = 'https://query1.finance.yahoo.com';
const PER_REQUEST_TIMEOUT_MS = 4000;
const MAX_UPSTREAM_BYTES = 256 * 1024;     // a 1d chart response is a few KB
const MAX_PRICE = 1e7;                     // sanity bound for a share price (USD)

const CACHE_TTL = 60 * 1000;               // fresh for 60 s
const STALE_TTL = 30 * 60 * 1000;          // serve stale up to 30 min if Yahoo is down

let _cache = null;
let _cacheAt = 0;
let _inflight = null;

const BASE_HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'X-Content-Type-Options': 'nosniff',
};
// Browser may reuse for 30 s; Netlify's CDN caches for 60 s and may serve stale while it refreshes.
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

async function fetchPrice(symbol) {
  const url = `${UPSTREAM_HOST}/v8/finance/chart/${encodeURIComponent(symbol)}?interval=1d&range=1d`;
  const json = await fetchJson(url, {
    timeoutMs: PER_REQUEST_TIMEOUT_MS,
    maxBytes: MAX_UPSTREAM_BYTES,
    headers: { 'User-Agent': 'Mozilla/5.0 (compatible; InvestEdBot/1.0)', 'Accept': 'application/json' },
  });
  const price = json && json.chart && Array.isArray(json.chart.result) && json.chart.result[0]
    && json.chart.result[0].meta && json.chart.result[0].meta.regularMarketPrice;
  if (typeof price !== 'number' || !Number.isFinite(price) || price <= 0 || price > MAX_PRICE) return null;
  return Math.round(price * 100) / 100;
}

async function refresh() {
  const results = {};
  await Promise.allSettled(SAFE_SYMBOLS.map(async (sym) => {
    const price = await fetchPrice(sym);
    if (price !== null) results[sym] = price;
  }));
  if (Object.keys(results).length > 0) {
    _cache = results;
    _cacheAt = Date.now();
  }
  return results;
}

exports.handler = async (event) => {
  const method = ((event && event.httpMethod) || 'GET').toUpperCase();
  if (method !== 'GET' && method !== 'HEAD') {
    return reply(405, { error: 'Method not allowed' }, { ...NO_STORE, Allow: 'GET, HEAD' });
  }

  const now = Date.now();
  if (_cache && now - _cacheAt < CACHE_TTL) return reply(200, _cache, CACHE_HEADERS);

  // Coalesce concurrent refreshes so a burst of requests triggers one upstream fan-out, not N.
  if (!_inflight) _inflight = refresh().finally(() => { _inflight = null; });
  const results = await _inflight;

  if (Object.keys(results).length > 0) return reply(200, results, CACHE_HEADERS);
  if (_cache && Date.now() - _cacheAt < STALE_TTL) return reply(200, _cache, { 'Cache-Control': 'public, max-age=15' });
  // Nothing usable: non-200 (frontend checks res.ok and keeps its built-in prices); don't let the CDN cache it.
  return reply(503, {}, NO_STORE);
};
