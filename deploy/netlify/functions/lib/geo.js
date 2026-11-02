/**
 * lib/geo.js — shared geocoding helpers for the Money City real-US-map feature.
 *
 * Sources (all free, no key):
 *   - US Census Geocoder (geocoding.geo.census.gov) — street address → lat/lng + tract FIPS,
 *     and lat/lng → tract FIPS.
 *   - Nominatim / OpenStreetMap (nominatim.openstreetmap.org) — city / ZIP / place search.
 *     Policy: real User-Agent, max 1 req/sec, cache results, no per-keystroke autocomplete.
 *
 * Every exported function NEVER throws — failures return null / [].
 * Caches are in-memory per warm Lambda instance.
 */

const USER_AGENT = 'MoneyQuest-InvestEdPro/1.0 (https://nextgenwealthproject.netlify.app)';
const CENSUS_BASE = 'https://geocoding.geo.census.gov/geocoder/geographies';
const CENSUS_PARAMS = 'benchmark=Public_AR_Current&vintage=Current_Current&format=json';
const NOMINATIM_BASE = 'https://nominatim.openstreetmap.org/search';
const DEFAULT_TIMEOUT = 8000;
const CACHE_TTL = 20 * 60 * 1000; // 20 min
const CACHE_MAX = 500;

// ── tiny TTL cache ────────────────────────────────────────────────────────────
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
      if (m.size >= max) m.delete(m.keys().next().value); // drop oldest
      m.set(k, { v, at: Date.now() });
    },
  };
}

const _addrCache = makeCache();
const _tractCache = makeCache();
const _placeCache = makeCache();

// ── fetch with timeout ────────────────────────────────────────────────────────
async function fetchJson(url, { timeoutMs = DEFAULT_TIMEOUT, headers = {} } = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      headers: { 'User-Agent': USER_AGENT, Accept: 'application/json', ...headers },
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// Nominatim: serialize calls ≥1.1s apart within this instance (usage policy).
let _nomNext = 0;
async function nominatimThrottle() {
  const now = Date.now();
  const wait = Math.max(0, _nomNext - now);
  _nomNext = Math.max(now, _nomNext) + 1100;
  if (wait) await new Promise(r => setTimeout(r, wait));
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

function tractFrom(geographies) {
  const t = geographies && geographies['Census Tracts'] && geographies['Census Tracts'][0];
  if (!t || !t.STATE || !t.COUNTY || !t.TRACT) return null;
  return { state: String(t.STATE), county: String(t.COUNTY), tract: String(t.TRACT) };
}

function isNum(n) { return typeof n === 'number' && isFinite(n); }

// ── Census: one-line address → match ─────────────────────────────────────────
/**
 * @returns {Promise<{address,city,state,zip,lat,lng,matchedAddress,geo:{state,county,tract}|null}|null>}
 */
async function censusGeocode(oneLineAddress) {
  const q = String(oneLineAddress || '').trim();
  if (q.length < 5) return null;
  const key = normKey(q);
  const cached = _addrCache.get(key);
  if (cached !== undefined) return cached;

  const url = `${CENSUS_BASE}/onelineaddress?address=${encodeURIComponent(q)}&${CENSUS_PARAMS}`;
  const j = await fetchJson(url);
  if (!j) return null; // network failure — don't cache
  const m = j.result && Array.isArray(j.result.addressMatches) && j.result.addressMatches[0];
  if (!m || !m.coordinates) { _addrCache.set(key, null); return null; }

  // NOTE: coordinates.x = LONGITUDE, coordinates.y = LATITUDE
  const lng = Number(m.coordinates.x);
  const lat = Number(m.coordinates.y);
  if (!isNum(lat) || !isNum(lng)) { _addrCache.set(key, null); return null; }

  const ac = m.addressComponents || {};
  // matchedAddress = "400 GRAND BLVD, KANSAS CITY, MO, 64106"
  // addressComponents only has a house-number RANGE, so take the street line from matchedAddress.
  const parts = String(m.matchedAddress || '').split(',').map(s => s.trim());
  const street = parts[0] || '';
  const out = {
    address: titleCase(street),
    city: titleCase(ac.city || parts[1] || ''),
    state: String(ac.state || parts[2] || '').toUpperCase(),
    zip: String(ac.zip || parts[3] || ''),
    lat: +lat.toFixed(6),
    lng: +lng.toFixed(6),
    matchedAddress: m.matchedAddress || '',
    geo: tractFrom(m.geographies),
  };
  _addrCache.set(key, out);
  if (out.geo) _tractCache.set(`${lat.toFixed(4)},${lng.toFixed(4)}`, out.geo);
  return out;
}

// ── Census: lat/lng → tract FIPS ─────────────────────────────────────────────
/** @returns {Promise<{state,county,tract}|null>} */
async function censusTractForPoint(lat, lng) {
  lat = Number(lat); lng = Number(lng);
  if (!isNum(lat) || !isNum(lng) || Math.abs(lat) > 90 || Math.abs(lng) > 180) return null;
  const key = `${lat.toFixed(4)},${lng.toFixed(4)}`;
  const cached = _tractCache.get(key);
  if (cached !== undefined) return cached;

  const url = `${CENSUS_BASE}/coordinates?x=${lng}&y=${lat}&${CENSUS_PARAMS}`;
  const j = await fetchJson(url);
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
  const a = r.address || {};
  const city = a.city || a.town || a.village || a.hamlet || a.municipality || '';
  const state = a.state || '';
  const t = String(r.addresstype || r.type || '').toLowerCase();
  if (t === 'postcode' && a.postcode) return [a.postcode, city, state].filter(Boolean).join(', ');
  if (t === 'state') return state || r.name || r.display_name;
  const name = r.name || city;
  const bits = [name];
  if (city && city !== name) bits.push(city);
  if (a.county && t === 'county') { /* name already is county */ }
  if (state && state !== name) bits.push(state);
  return bits.filter(Boolean).join(', ') || r.display_name || '';
}

/**
 * @returns {Promise<Array<{label,kind:'place',lat,lng,zoom,type,city?,state?,zip?,bbox?}>>}
 */
async function nominatimSearch(q) {
  q = String(q || '').trim();
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

  await nominatimThrottle();
  const j = await fetchJson(url, { headers: { 'Accept-Language': 'en-US' } });
  if (!Array.isArray(j)) return []; // failure — don't cache

  const seen = new Set();
  const out = [];
  for (const r of j) {
    const lat = Number(r.lat), lng = Number(r.lon);
    if (!isNum(lat) || !isNum(lng)) continue;
    const a = r.address || {};
    const label = placeLabel(r);
    if (seen.has(label)) continue;
    seen.add(label);
    const item = {
      label,
      kind: 'place',
      lat: +lat.toFixed(6),
      lng: +lng.toFixed(6),
      zoom: zoomForPlace(r),
      type: r.addresstype || r.type || '',
    };
    const city = a.city || a.town || a.village || a.hamlet || a.municipality;
    if (city) item.city = city;
    if (a.state) item.state = a.state; // full name e.g. "Missouri" (Nominatim), not "MO"
    const iso = String(a['ISO3166-2-lvl4'] || '');
    if (/^US-[A-Z]{2}$/.test(iso)) item.stateCode = iso.slice(3); // "MO"
    if (a.postcode) item.zip = String(a.postcode).slice(0, 5);
    if (Array.isArray(r.boundingbox) && r.boundingbox.length === 4) {
      // Nominatim order: [south, north, west, east] (strings)
      const [s, n, w, e] = r.boundingbox.map(Number);
      if ([s, n, w, e].every(isNum)) item.bbox = { south: s, west: w, north: n, east: e };
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
  titleCase,
};
