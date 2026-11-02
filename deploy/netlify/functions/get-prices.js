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
 *  - Quotes are kept PER SYMBOL: a refresh where only some symbols succeed updates those and keeps the
 *    others' last good quote (for up to 30 min), so a partial Yahoo answer never drops prices.
 *  - A quote is rejected (the last good one is kept) when it moves more than 50 % from the last good
 *    quote of the last 30 min, or is more than 20x away from a rough reference price.
 *  - The CDN may cache an answer only when EVERY symbol was refreshed just now; a partial / stale
 *    answer is "private, max-age=15" (browser only).
 *  - lib/firewall.js in front (GET/HEAD, Origin allow-list, light per-IP limit 30/min per instance,
 *    attack filter); CDN hits never reach the function, so the limit only meets cache misses.
 *  - On upstream failure, recent stale data is served; upstream errors are never echoed to the client.
 */
const { withFirewall } = require('./lib/firewall');

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
const MAX_JUMP = 0.5;                      // reject a quote > 50 % away from the last good one
const REF_BAND = 20;                       // …or > 20x away from the rough reference below
// Rough reference prices (mid-2025, same as the app's built-in table). Only used as a wide 20x sanity
// band (it allows splits and big moves); update if a symbol ever legitimately leaves it.
const REF = { AAPL: 293.64, MSFT: 412.67, GOOGL: 183.41, AMZN: 227.88, TSLA: 290.12, META: 685.3, NVDA: 216.09,
  JNJ: 162.45, PG: 178.2, KO: 66.8, WMT: 97.35, XOM: 112.7, BAC: 46.18, SPY: 595.42, VOO: 546.88, BND: 73.15, TLT: 88.42 };

const CACHE_TTL = 60 * 1000;               // fresh for 60 s
const STALE_TTL = 30 * 60 * 1000;
const RETRY_MS = 20 * 1000;            // after a partial / failed refresh, try again sooner than CACHE_TTL          // serve stale up to 30 min if Yahoo is down

const _quotes = Object.create(null);   // sym → { price, at } (last GOOD quote)
let _refreshedAt = 0;
let _nextRefresh = 0;
let _complete = false;                 // did the last refresh get a fresh, accepted quote for every symbol?
let _inflight = null;

const BASE_HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'X-Content-Type-Options': 'nosniff',
};
// Complete answer: browser may reuse for 30 s; Netlify's CDN caches for 60 s and may serve stale while it refreshes.
const CACHE_HEADERS = {
  'Cache-Control': 'public, max-age=30',
  'Netlify-CDN-Cache-Control': 'public, s-maxage=60, stale-while-revalidate=120',
};
// Partial / stale answer: never in the CDN, briefly in the browser.
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

/** Last good quote for `sym` if it is younger than STALE_TTL, else 0. */
function recent(sym, now = Date.now()) {
  const e = _quotes[sym];
  return e && now - e.at < STALE_TTL ? e.price : 0;
}

/** Sanity checks on a new quote: reference band, then max move vs the last good quote. */
function plausible(sym, price, prev) {
  if (typeof price !== 'number' || !Number.isFinite(price) || price <= 0 || price > MAX_PRICE) return false;
  const ref = REF[sym];
  if (ref && (price > ref * REF_BAND || price < ref / REF_BAND)) return false;
  if (prev && Math.abs(price / prev - 1) > MAX_JUMP) return false;
  return true;
}

/** Every symbol with a good quote younger than STALE_TTL. */
function snapshot() {
  const now = Date.now();
  const out = {};
  for (const sym of SAFE_SYMBOLS) { const p = recent(sym, now); if (p) out[sym] = p; }
  return out;
}

async function refresh() {
  let fresh = 0;
  await Promise.allSettled(SAFE_SYMBOLS.map(async (sym) => {
    const price = await fetchPrice(sym);
    if (price !== null && plausible(sym, price, recent(sym))) { _quotes[sym] = { price, at: Date.now() }; fresh++; }
  }));
  _complete = fresh === SAFE_SYMBOLS.length;
  _refreshedAt = Date.now();
  _nextRefresh = _refreshedAt + (_complete ? CACHE_TTL : RETRY_MS);
}

function answer(event) {
  const data = snapshot();
  if (!Object.keys(data).length) return reply(event, 503, {}, NO_STORE);   // frontend keeps its built-in prices
  return reply(event, 200, data, _complete ? CACHE_HEADERS : PARTIAL_HEADERS);
}

async function handle(event) {
  if (Date.now() < _nextRefresh) return answer(event);
  // Coalesce concurrent refreshes so a burst of requests triggers one upstream fan-out, not N.
  if (!_inflight) _inflight = refresh().catch(() => {}).finally(() => { _inflight = null; });
  await _inflight;
  return answer(event);
}

const firewalled = withFirewall(handle, {
  name: 'get-prices',
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
