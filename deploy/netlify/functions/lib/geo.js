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
 * Caches are in-memory per warm Lambda instance.
 *
 * Also holds small request helpers shared by the re-* functions (CORS origin check, client IP,
 * per-instance rate limiter, text sanitizer) so those functions stay standalone.
 */

const USER_AGENT = 'MoneyQuest-InvestEdPro/1.0 (https://nextgenwealthproject.netlify.app)';
const CENSUS_BASE = 'https://geocoding.geo.census.gov/geocoder/geographies';
const CENSUS_PARAMS = 'benchmark=Public_AR_Current&vintage=Current_Current&format=json';
const NOMINATIM_BASE = 'https://nominatim.openstreetmap.org/search';
const DEFAULT_TIMEOUT = 8000;
const MAX_BODY_BYTES = 2 * 1024 * 1024;   // upstream JSON bigger than this is refused
const CACHE_TTL = 20 * 60 * 1000; // 20 min
const CACHE_MAX = 500;
const NOMINATIM_MAX_WAIT = 2500;          // don't queue a request behind more than ~2 others

// ── tiny TTL cache (Map-backed, so any string key is safe) ───────────────────
function makeCache(ttl = CACHE_TTL, max = CACHE_MAX) {
  const m = new Map();
  return {
    get(k) {
      const hit = m.get(k);
      if (!hit) return undefined;
      if (Date.now() - hit.at > ttl) { m.delete(k); return undefined; }
      return hit.v;
    },
    set(k, v) {
      if (m.has(k)) m.delete(k);
      else if (m.size >= max) m.delete(m.keys().next().value); // drop oldest
      m.set(k, { v, at: Date.now() });
    },
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

// Nominatim: serialize calls ≥1.1s apart within this instance (usage policy). If the queue is already
// long, give up instead of holding the function open (and piling up waits) — caller returns [].
let _nomNext = 0;
async function nominatimThrottle() {
  const now = Date.now();
  const wait = Math.max(0, _nomNext - now);
  if (wait > NOMINATIM_MAX_WAIT) return false;
  _nomNext = Math.max(now, _nomNext) + 1100;
  if (wait) await new Promise(r => setTimeout(r, wait));
  return true;
}

// ── request helpers (shared by re-value / re-geocode / re-listings) ──────────
// Strip control chars, angle brackets and backticks; collapse whitespace; cap length.
function cleanText(s, max = 120) {
  if (s == null) return '';
  if (typeof s !== 'string' && typeof s !== 'number') return '';
  return String(s).replace(/[\u0000-\u001f\u007f-\u009f<>`\u2028\u2029]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
}

function header(event, name) {
  const h = (event && event.headers) || {};
  const v = h[name] != null ? h[name] : h[name.toLowerCase()];
  return typeof v === 'string' ? v : '';
}

function clientIp(event) {
  return (header(event, 'x-nf-client-connection-ip') || header(event, 'client-ip') ||
    header(event, 'x-forwarded-for').split(',')[0] || 'unknown').trim().slice(0, 64);
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

// Fixed-window per-key limiter (per warm instance — a speed bump, not a guarantee).
function makeRateLimiter(max, windowMs, maxKeys = 5000) {
  const m = new Map();
  return function hit(key) {
    const now = Date.now();
    let e = m.get(key);
    if (!e || now - e.start >= windowMs) {
      if (!e && m.size >= maxKeys) m.delete(m.keys().next().value);
      e = { start: now, n: 0 };
      m.delete(key);
      m.set(key, e);
    }
    e.n++;
    return e.n <= max;
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

function normKey(s) { return String(s || '').trim().toLowerCase().replace(/\s+/g, ' '); }

function isNum(n) { return typeof n === 'number' && isFinite(n); }
function validLatLng(lat, lng) { return isNum(lat) && isNum(lng) && lat >= -90 && lat <= 90 && lng >= -180 && lng <= 180; }

// FIPS codes are used as keys into re-data.json — only accept the exact digit shapes.
function tractFrom(geographies) {
  const list = geographies && geographies['Census Tracts'];
  const t = Array.isArray(list) && list[0];
  if (!t) return null;
  const state = String(t.STATE || ''), county = String(t.COUNTY || ''), tract = String(t.TRACT || '');
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
  const lng = Number(m.coordinates.x);
  const lat = Number(m.coordinates.y);
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
  lat = Number(lat); lng = Number(lng);
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
  const t = String(r.addresstype || r.type || '').toLowerCase();
  const cls = String(r.category || r.class || '').toLowerCase();
  if (t === 'state') return 6;
  if (t === 'county') return 9;
  if (t === 'postcode' || cls === 'postcode') return 13;
  if (['city', 'town', 'village', 'hamlet', 'municipality', 'administrative'].includes(t)) return 12;
  if (['suburb', 'neighbourhood', 'quarter', 'borough'].includes(t)) return 14;
  return 15;
}

function placeLabel(r) {
  const a = (r.address && typeof r.address === 'object') ? r.address : {};
  const city = a.city || a.town || a.village || a.hamlet || a.municipality || '';
  const state = a.state || '';
  const t = String(r.addresstype || r.type || '').toLowerCase();
  if (t === 'postcode' && a.postcode) return [a.postcode, city, state].filter(Boolean).join(', ');
  if (t === 'state') return state || r.name || r.display_name;
  const name = r.name || city;
  const bits = [name];
  if (city && city !== name) bits.push(city);
  if (state && state !== name) bits.push(state);
  return bits.filter(Boolean).join(', ') || r.display_name || '';
}

/**
 * @returns {Promise<Array<{label,kind:'place',lat,lng,zoom,type,city?,state?,zip?,bbox?}>>}
 */
async function nominatimSearch(q, timeoutMs = DEFAULT_TIMEOUT) {
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

  if (!(await nominatimThrottle())) return []; // too busy — don't cache
  const j = await fetchJson(url, { timeoutMs, headers: { 'Accept-Language': 'en-US' } });
  if (!Array.isArray(j)) return []; // failure — don't cache

  const seen = new Set();
  const out = [];
  for (const r of j.slice(0, 10)) {
    if (!r || typeof r !== 'object') continue;
    const lat = Number(r.lat), lng = Number(r.lon);
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
      type: cleanText(r.addresstype || r.type || '', 40),
    };
    const city = cleanText(a.city || a.town || a.village || a.hamlet || a.municipality, 60);
    if (city) item.city = city;
    const stName = cleanText(a.state, 40);
    if (stName) item.state = stName; // full name e.g. "Missouri" (Nominatim), not "MO"
    const iso = String(a['ISO3166-2-lvl4'] || '');
    if (/^US-[A-Z]{2}$/.test(iso)) item.stateCode = iso.slice(3); // "MO"
    const zip = String(a.postcode || '').replace(/\D/g, '').slice(0, 5);
    if (zip.length === 5) item.zip = zip;
    if (Array.isArray(r.boundingbox) && r.boundingbox.length === 4) {
      // Nominatim order: [south, north, west, east] (strings)
      const [s, n, w, e] = r.boundingbox.map(Number);
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
  clientIp,
  corsHeaders,
  validLatLng,
};
