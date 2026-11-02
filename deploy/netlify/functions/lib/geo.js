/**
 * lib/geo.js — shared geocoding helpers for the Money City real-US-map feature.
 *
 * Sources (all free, no key):
 *   - US Census Geocoder (geocoding.geo.census.gov) — street address → lat/lng + tract FIPS,
 *     and lat/lng → tract FIPS.
 *   - Nominatim / OpenStreetMap (nominatim.openstreetmap.org) — city / ZIP / place search.
 *     Policy: real User-Agent, max 1 req/sec, cache results, no per-keystroke autocomplete.
 *
 * Every exported async function NEVER throws — failures return null / [].
 * Caches are in-memory per warm Lambda instance and hold typed addresses, so every entry is
 * dropped after its TTL (20 min here): expired entries are swept on the next cache use, not kept
 * until the cache fills. Nothing here logs a query or an address.
 *
 * Nominatim's 1 request/second policy is enforced SITE-WIDE through lib/ratelimit.js
 * budget('nominatim', 1 per 1 s window) — shared by every instance — plus a per-instance 1.1 s
 * spacing. When the slot can't be had quickly, nominatimSearch() returns null ("busy") and
 * re-geocode answers 503, so the app falls back to its bundled city list.
 *
 * Also holds small request helpers shared by the re-* functions (client IP key, text sanitizer,
 * query normaliser). Rate limiting itself is lib/ratelimit.js (durable, cross-instance).
 */
const RL = require('./ratelimit');

const USER_AGENT = 'MoneyQuest-InvestEdPro/1.0 (https://nextgenwealthproject.netlify.app)';
const CENSUS_BASE = 'https://geocoding.geo.census.gov/geocoder/geographies';
const CENSUS_PARAMS = 'benchmark=Public_AR_Current&vintage=Current_Current&format=json';
const NOMINATIM_BASE = 'https://nominatim.openstreetmap.org/search';
const DEFAULT_TIMEOUT = 8000;
const MAX_BODY_BYTES = 2 * 1024 * 1024;   // upstream JSON bigger than this is refused
const CACHE_TTL = 20 * 60 * 1000; // 20 min
const CACHE_MAX = 500;
const NOMINATIM_MAX_WAIT = 2500;          // don't queue a request behind more than ~2 others
const SWEEP_EVERY_MS = 30 * 1000;

// ── tiny TTL cache (Map-backed, so any string key is safe) ───────────────────
// An entry lives at most `ttl` ms from when it was stored (reads don't extend it). Expired entries
// are swept (at most every 30 s) on the next get/set, so stale addresses don't linger in memory.
function makeCache(ttl = CACHE_TTL, max = CACHE_MAX) {
  const m = new Map();
  let nextSweep = 0;
  function sweep(now) {
    if (now < nextSweep) return;
    nextSweep = now + SWEEP_EVERY_MS;
    for (const [k, e] of m) if (now - e.at > ttl) m.delete(k);
  }
  return {
    get(k) {
      const now = Date.now();
      sweep(now);
      const hit = m.get(k);
      if (!hit) return undefined;
      if (now - hit.at > ttl) { m.delete(k); return undefined; }
      return hit.v;
    },
    set(k, v) {
      const now = Date.now();
      sweep(now);
      if (m.has(k)) m.delete(k);
      else if (m.size >= max) m.delete(m.keys().next().value); // drop oldest
      m.set(k, { v, at: now });
    },
    get size() { return m.size; },
    ttl,
  };
}

const _addrCache = makeCache();
const _tractCache = makeCache();
const _placeCache = makeCache();

// ── fetch with timeout ────────────────────────────────────────────────────────
// Returns parsed JSON or null. Never surfaces upstream error bodies. `redirect:'error'` is used for
// keyed APIs so a redirect can never carry an API-key header to another host.
async function fetchJson(url, { timeoutMs = DEFAULT_TIMEOUT, headers = {}, method = 'GET', body, redirect = 'follow', maxBytes = MAX_BODY_BYTES } = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), Math.max(100, Math.min(Number(timeoutMs) || DEFAULT_TIMEOUT, 15000)));
  try {
    const res = await fetch(url, {
      method,
      body,
      redirect,
      signal: ctrl.signal,
      headers: { 'User-Agent': USER_AGENT, Accept: 'application/json', ...headers },
    });
    if (!res.ok) return null;
    const len = Number(res.headers && res.headers.get && res.headers.get('content-length'));
    if (len > maxBytes) return null;
    const text = await res.text();
    if (text.length > maxBytes) return null;
    return JSON.parse(text);
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// Nominatim (usage policy: max 1 request/second for the whole site, which shares one User-Agent).
//  1. per instance: calls ≥1.1 s apart; if the local queue is already long, give up (no pile-up).
//  2. site-wide: one slot per 1-second window in the shared counter (RL.budget). If the slot is
//     taken, wait for the next second (up to twice, within the caller's deadline); still taken → busy.
//     With a database configured this fails CLOSED (DB error → busy → the app's bundled city list),
//     because per-instance spacing alone can't keep the whole site at 1/s. With no database configured
//     at all (local dev: no SUPA_SERVICE_KEY or RATE_LIMIT_DB=off) the per-instance counter is used.
let _nomNext = 0;
const dbConfigured = () => !!process.env.SUPA_SERVICE_KEY && process.env.RATE_LIMIT_DB !== 'off';
async function nominatimThrottle(deadline) {
  const now = Date.now();
  const wait = Math.max(0, _nomNext - now);
  if (wait > NOMINATIM_MAX_WAIT) return false;
  _nomNext = Math.max(now, _nomNext) + 1100;
  if (wait) await sleep(wait);
  for (let attempt = 0; attempt < 3; attempt++) {
    const r = await RL.budget('nominatim', { windowSec: 1, max: 1, failClosed: dbConfigured() });
    if (r && r.ok) return true;
    if (!r || !r.count) return false;                       // count 0 = limiter unavailable (failed closed): don't wait
    const next = 1000 - (Date.now() % 1000) + 25;           // start of the next 1-second window
    if (attempt === 2 || Date.now() + next > deadline) return false;
    await sleep(next);
  }
  return false;
}

// ── request helpers (shared by re-value / re-geocode / re-listings) ──────────
// Strip control chars, angle brackets and backticks; collapse whitespace; cap length.
// Only strings and numbers are accepted (objects/arrays → ''), so a JSON value like {"toString":1}
// can never throw. The input is cut to a bounded length BEFORE the regexes run (bounded CPU).
function cleanText(s, max = 120) {
  if (s == null) return '';
  if (typeof s !== 'string' && typeof s !== 'number') return '';
  const lim = Math.max(0, Math.min(Number(max) || 0, 100000));
  return String(s).slice(0, lim * 4 + 16).replace(/[\u0000-\u001f\u007f-\u009f<>`\u2028\u2029]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, lim);
}

// Primitive → string, anything else → '' (never calls an attacker-controlled toString).
const str = (v) => (typeof v === 'string' ? v : typeof v === 'number' && isFinite(v) ? String(v) : '');
// Primitive → number, anything else → NaN (Number({toString:1}) would throw).
const toNum = (v) => (typeof v === 'number' ? v : typeof v === 'string' && v.trim() !== '' ? Number(v) : NaN);

/**
 * Cache key for a free-text place / address query: lower-case, every run of punctuation or
 * whitespace → one space. "400 Grand Blvd., Kansas City,  MO" and "400 grand blvd kansas city mo"
 * share one entry (and one upstream call).
 */
function normQuery(s) {
  return str(s).slice(0, 400).toLowerCase().replace(/[^\p{L}\p{M}0-9]+/gu, ' ').trim();
}

function header(event, name) {
  const h = (event && event.headers) || {};
  const v = h[name] != null ? h[name] : h[name.toLowerCase()];
  return typeof v === 'string' ? v : '';
}

// Rate-limit key for the caller: lib/ratelimit.js ipKey (Netlify's client-IP header first; IPv6 → /64).
function clientIp(event) {
  return RL.ipKey((event && event.headers) || {});
}

// Only echo CORS for our own site / deploy previews / local dev. Same-origin calls don't need it.
function allowedOrigin(event) {
  const o = header(event, 'origin');
  if (!o) return null;
  const site = [process.env.URL, process.env.DEPLOY_PRIME_URL, process.env.SITE_URL].filter(Boolean);
  if (site.includes(o)) return o;
  if (/^https:\/\/([a-z0-9-]+--)?nextgenwealthproject\.netlify\.app$/i.test(o)) return o;
  if (/^http:\/\/(localhost|127\.0\.0\.1)(:\d{1,5})?$/.test(o)) return o;
  return null;
}

function corsHeaders(event, methods) {
  const o = allowedOrigin(event);
  const h = { Vary: 'Origin' };
  if (o) Object.assign(h, { 'Access-Control-Allow-Origin': o, 'Access-Control-Allow-Methods': methods, 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Max-Age': '600' });
  return h;
}

/**
 * Durable per-client limiter (lib/ratelimit.js hit(), shared across instances, IPv6 keyed by /64).
 * Replaces the old per-instance makeRateLimiter. Returns async (key) → boolean.
 * @param {string} bucket  stable name, e.g. 'rc-value'
 * @param {number} max     events allowed per window
 * @param {number} windowSec
 * @param {{failClosed?:boolean}} [opts]  failClosed for anything that costs money
 */
function makeRateLimiter(bucket, max, windowSec, opts = {}) {
  if (typeof bucket !== 'string') throw new TypeError('makeRateLimiter(bucket, max, windowSec): the per-instance form was removed');
  return async (key) => {
    const r = await RL.hit(bucket, String(key || 'unknown'), { windowSec, max, failClosed: !!opts.failClosed });
    return !!(r && r.ok);
  };
}

// ── helpers ───────────────────────────────────────────────────────────────────
const SMALL_WORDS = new Set(['of', 'and', 'the']);
function titleCase(s) {
  return String(s || '').toLowerCase().split(/(\s+)/).map((w, i) => {
    if (/^\s+$/.test(w)) return w;
    if (i > 0 && SMALL_WORDS.has(w)) return w;
    // keep directionals / ordinals sensible: NW, NE, SW, SE, 1st, 2nd…
    if (/^(n|s|e|w|ne|nw|se|sw)$/.test(w)) return w.toUpperCase();
    if (/^\d+(st|nd|rd|th)$/.test(w)) return w;
    return w.charAt(0).toUpperCase() + w.slice(1);
  }).join('');
}

const normKey = normQuery;

function isNum(n) { return typeof n === 'number' && isFinite(n); }
function validLatLng(lat, lng) { return isNum(lat) && isNum(lng) && lat >= -90 && lat <= 90 && lng >= -180 && lng <= 180; }

// FIPS codes are used as keys into re-data.json — only accept the exact digit shapes.
function tractFrom(geographies) {
  const list = geographies && geographies['Census Tracts'];
  const t = Array.isArray(list) && list[0];
  if (!t) return null;
  const state = str(t.STATE), county = str(t.COUNTY), tract = str(t.TRACT);
  if (!/^\d{2}$/.test(state) || !/^\d{3}$/.test(county) || !/^\d{6}$/.test(tract)) return null;
  return { state, county, tract };
}

// ── Census: one-line address → match ─────────────────────────────────────────
/**
 * @returns {Promise<{address,city,state,zip,lat,lng,matchedAddress,geo:{state,county,tract}|null}|null>}
 */
async function censusGeocode(oneLineAddress, timeoutMs = DEFAULT_TIMEOUT) {
  const q = cleanText(oneLineAddress, 200);
  if (q.length < 5) return null;
  const key = normKey(q);
  const cached = _addrCache.get(key);
  if (cached !== undefined) return cached;

  const url = `${CENSUS_BASE}/onelineaddress?address=${encodeURIComponent(q)}&${CENSUS_PARAMS}`;
  const j = await fetchJson(url, { timeoutMs });
  if (!j) return null; // network failure — don't cache
  const m = j.result && Array.isArray(j.result.addressMatches) && j.result.addressMatches[0];
  if (!m || !m.coordinates) { _addrCache.set(key, null); return null; }

  // NOTE: coordinates.x = LONGITUDE, coordinates.y = LATITUDE
  const lng = toNum(m.coordinates.x);
  const lat = toNum(m.coordinates.y);
  if (!validLatLng(lat, lng)) { _addrCache.set(key, null); return null; }

  const ac = m.addressComponents || {};
  // matchedAddress = "400 GRAND BLVD, KANSAS CITY, MO, 64106"
  // addressComponents only has a house-number RANGE, so take the street line from matchedAddress.
  const matched = cleanText(m.matchedAddress, 200);
  const parts = matched.split(',').map(s => s.trim());
  const street = parts[0] || '';
  const st = cleanText(ac.state || parts[2] || '', 2).toUpperCase();
  const zip = cleanText(ac.zip || parts[3] || '', 10).replace(/\D/g, '').slice(0, 5);
  const out = {
    address: titleCase(cleanText(street, 100)),
    city: titleCase(cleanText(ac.city || parts[1] || '', 60)),
    state: /^[A-Z]{2}$/.test(st) ? st : '',
    zip,
    lat: +lat.toFixed(6),
    lng: +lng.toFixed(6),
    matchedAddress: matched,
    geo: tractFrom(m.geographies),
  };
  _addrCache.set(key, out);
  if (out.geo) _tractCache.set(`${lat.toFixed(4)},${lng.toFixed(4)}`, out.geo);
  return out;
}

// ── Census: lat/lng → tract FIPS ─────────────────────────────────────────────
/** @returns {Promise<{state,county,tract}|null>} */
async function censusTractForPoint(lat, lng, timeoutMs = DEFAULT_TIMEOUT) {
  lat = toNum(lat); lng = toNum(lng);
  if (!validLatLng(lat, lng)) return null;
  const key = `${lat.toFixed(4)},${lng.toFixed(4)}`;
  const cached = _tractCache.get(key);
  if (cached !== undefined) return cached;

  const url = `${CENSUS_BASE}/coordinates?x=${lng.toFixed(6)}&y=${lat.toFixed(6)}&${CENSUS_PARAMS}`;
  const j = await fetchJson(url, { timeoutMs });
  if (!j) return null;
  const geo = tractFrom(j.result && j.result.geographies);
  _tractCache.set(key, geo);
  return geo;
}

// ── Nominatim place search ───────────────────────────────────────────────────
function zoomForPlace(r) {
  const t = str(r.addresstype || r.type).toLowerCase();
  const cls = str(r.category || r.class).toLowerCase();
  if (t === 'state') return 6;
  if (t === 'county') return 9;
  if (t === 'postcode' || cls === 'postcode') return 13;
  if (['city', 'town', 'village', 'hamlet', 'municipality', 'administrative'].includes(t)) return 12;
  if (['suburb', 'neighbourhood', 'quarter', 'borough'].includes(t)) return 14;
  return 15;
}

function placeLabel(r) {
  const a = (r.address && typeof r.address === 'object') ? r.address : {};
  const city = str(a.city) || str(a.town) || str(a.village) || str(a.hamlet) || str(a.municipality);
  const state = str(a.state);
  const t = str(r.addresstype || r.type).toLowerCase();
  const postcode = str(a.postcode);
  if (t === 'postcode' && postcode) return [postcode, city, state].filter(Boolean).join(', ');
  if (t === 'state') return state || str(r.name) || str(r.display_name);
  const name = str(r.name) || city;
  const bits = [name];
  if (city && city !== name) bits.push(city);
  if (state && state !== name) bits.push(state);
  return bits.filter(Boolean).join(', ') || str(r.display_name);
}

/**
 * @returns {Promise<Array<{label,kind:'place',lat,lng,zoom,type,city?,state?,zip?,bbox?}>|null>}
 *   [] = Nominatim answered with no match (cached); null = busy (site-wide 1 req/s slot taken) or
 *   upstream failure (not cached) — callers should answer "try again" (503), not "not found".
 */
async function nominatimSearch(q, timeoutMs = DEFAULT_TIMEOUT) {
  const t0 = Date.now();
  q = cleanText(q, 200);
  if (q.length < 2) return [];
  const key = normKey(q);
  const cached = _placeCache.get(key);
  if (cached !== undefined) return cached;

  // US ZIP code → use the structured postalcode param (much more reliable than free text)
  const zipOnly = /^\d{5}$/.test(q);
  const params = zipOnly
    ? `postalcode=${q}&country=us`
    : `q=${encodeURIComponent(q)}&countrycodes=us`;
  const url = `${NOMINATIM_BASE}?${params}&format=jsonv2&limit=5&addressdetails=1`;

  if (!(await nominatimThrottle(t0 + Math.max(0, timeoutMs - 1500)))) return null; // too busy — don't cache
  const left = timeoutMs - (Date.now() - t0);
  if (left < 800) return null;
  const j = await fetchJson(url, { timeoutMs: left, headers: { 'Accept-Language': 'en-US' } });
  if (!Array.isArray(j)) return null; // failure — don't cache

  const seen = new Set();
  const out = [];
  for (const r of j.slice(0, 10)) {
    if (!r || typeof r !== 'object') continue;
    const lat = toNum(r.lat), lng = toNum(r.lon);
    if (!validLatLng(lat, lng)) continue;
    const a = (r.address && typeof r.address === 'object') ? r.address : {};
    const label = cleanText(placeLabel(r), 160);
    if (!label || seen.has(label)) continue;
    seen.add(label);
    const item = {
      label,
      kind: 'place',
      lat: +lat.toFixed(6),
      lng: +lng.toFixed(6),
      zoom: zoomForPlace(r),
      type: cleanText(str(r.addresstype) || str(r.type), 40),
    };
    const city = cleanText(str(a.city) || str(a.town) || str(a.village) || str(a.hamlet) || str(a.municipality), 60);
    if (city) item.city = city;
    const stName = cleanText(a.state, 40);
    if (stName) item.state = stName; // full name e.g. "Missouri" (Nominatim), not "MO"
    const iso = str(a['ISO3166-2-lvl4']);
    if (/^US-[A-Z]{2}$/.test(iso)) item.stateCode = iso.slice(3); // "MO"
    const zip = str(a.postcode).replace(/\D/g, '').slice(0, 5);
    if (zip.length === 5) item.zip = zip;
    if (Array.isArray(r.boundingbox) && r.boundingbox.length === 4) {
      // Nominatim order: [south, north, west, east] (strings)
      const [s, n, w, e] = r.boundingbox.map(toNum);
      if (validLatLng(s, w) && validLatLng(n, e) && n >= s && e >= w) item.bbox = { south: s, west: w, north: n, east: e };
    }
    out.push(item);
  }
  _placeCache.set(key, out);
  return out;
}

module.exports = {
  USER_AGENT,
  fetchJson,
  censusGeocode,
  censusTractForPoint,
  nominatimSearch,
  makeCache,
  makeRateLimiter,
  titleCase,
  cleanText,
  normQuery,
  str,
  clientIp,
  corsHeaders,
  validLatLng,
};
