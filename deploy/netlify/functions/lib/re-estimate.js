/**
 * lib/re-estimate.js — home value / rent estimator for the Money City real-US-map feature.
 *
 * Free data (bundled in re-data.json, rebuilt by /tmp/qe/mls/build-data.js style script):
 *   - U.S. Census Bureau ACS 2024 5-year, table-based summary file (public, no key), per census tract,
 *     county and state: B25077 median home value, B25064 median gross rent, B25103 median real estate
 *     taxes paid, B25018 median rooms, B25035 median year built.
 *   - FHFA All-Transactions House Price Index by state: `factor` = latest quarter ÷ 2022–2024 average
 *     (brings ACS values forward to today), `appr` = 3-year annualized growth (clamped 1%–6%).
 * Optional paid data: RentCast API (env RENTCAST_API_KEY) — AVM value and real for-sale listings.
 *   Every paid call must pass, in order: the in-memory answer cache (1 h; a hit costs nothing), the
 *   caller's per-client gate (lib/ratelimit.js hit(), durable, fails closed), and the SITE-WIDE hourly
 *   budget (lib/ratelimit.js budget('rentcast'), one counter shared by every instance and by both
 *   re-value and re-listings; fails closed, so no DB → no paid calls).
 *   RENTCAST_MAX_CALLS_PER_HOUR (parsed strictly):
 *     unset or ""          → 40 calls/hour
 *     1–6 digits (≥ 0)     → that many per hour (capped at 10000); "0" turns paid calls OFF
 *     anything else        → OFF (e.g. "-1", "5.5", "abc", "40/h") — a typo can't mean "unlimited"
 *   With the key unset or the cap at 0, hasRentcast() is false and no paid code runs at all.
 *   Cache keys are normalised (lower-case, single spaces); listings are fetched for a center snapped
 *   to a 0.01° grid with one fixed radius, so nearby map views share one paid call.
 *
 * Rules: never invent negative facts about a real home (condition only Excellent/Good/Average,
 * no school/crime ratings). Everything is deterministic per address (no Math.random).
 *
 * All lookups into re-data.json go through own()/Maps so keys like "__proto__" or "constructor"
 * can never resolve to Object.prototype members.
 */

const DATA = require('./re-data.json');
const { fetchJson, makeCache, cleanText, validLatLng, USER_AGENT, str } = require('./geo');
const RL = require('./ratelimit');

const own = (obj, k) => (obj && typeof k === 'string' && Object.prototype.hasOwnProperty.call(obj, k)) ? obj[k] : undefined;

const STATE_FIPS = new Map();               // 'MO' → '29'
for (const [f, s] of Object.entries(DATA.states)) if (s && typeof s.ab === 'string') STATE_FIPS.set(s.ab, f);
const STATE_NAMES = new Map(Object.entries({ Alabama:'AL', Alaska:'AK', Arizona:'AZ', Arkansas:'AR', California:'CA', Colorado:'CO', Connecticut:'CT', Delaware:'DE', 'District of Columbia':'DC', Florida:'FL', Georgia:'GA', Hawaii:'HI', Idaho:'ID', Illinois:'IL', Indiana:'IN', Iowa:'IA', Kansas:'KS', Kentucky:'KY', Louisiana:'LA', Maine:'ME', Maryland:'MD', Massachusetts:'MA', Michigan:'MI', Minnesota:'MN', Mississippi:'MS', Missouri:'MO', Montana:'MT', Nebraska:'NE', Nevada:'NV', 'New Hampshire':'NH', 'New Jersey':'NJ', 'New Mexico':'NM', 'New York':'NY', 'North Carolina':'NC', 'North Dakota':'ND', Ohio:'OH', Oklahoma:'OK', Oregon:'OR', Pennsylvania:'PA', 'Rhode Island':'RI', 'South Carolina':'SC', 'South Dakota':'SD', Tennessee:'TN', Texas:'TX', Utah:'UT', Vermont:'VT', Virginia:'VA', Washington:'WA', 'West Virginia':'WV', Wisconsin:'WI', Wyoming:'WY', 'Puerto Rico':'PR' }));
const stateAb = (s) => {
  if (typeof s !== 'string') return '';
  s = s.trim();
  if (/^[A-Za-z]{2}$/.test(s)) return s.toUpperCase();
  return STATE_NAMES.get(s) || '';
};

// ── deterministic helpers ─────────────────────────────────────────────────────
function hash(str) {                        // FNV-1a 32-bit
  str = String(str);
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; }
  return h >>> 0;
}
function rngFrom(seed) {                    // xorshift32 → [0,1)
  let s = (seed ^ 0x9e3779b9) >>> 0 || 1;
  return () => { s ^= s << 13; s >>>= 0; s ^= s >> 17; s ^= s << 5; s >>>= 0; return s / 4294967296; };
}
const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
const r1000 = (v) => Math.round(v / 1000) * 1000;
const r25 = (v) => Math.round(v / 25) * 25;
const dayNum = () => Math.floor(Date.now() / 86400000);
const THIS_YEAR = () => new Date().getUTCFullYear();
// A finite number inside [lo, hi], else 0 (= "unknown", callers fall back to an estimate)
const numIn = (v, lo, hi) => { if (typeof v !== 'number' && typeof v !== 'string') return 0; if (v === '') return 0; const n = Number(v); return isFinite(n) && n >= lo && n <= hi ? n : 0; };
const posNum = (v) => { const n = Number(v); return isFinite(n) && n > 0 ? n : 0; };

// ── ACS lookup: tract → county → state → US, field by field ───────────────────
function cleanGeo(geo) {
  if (!geo || typeof geo !== 'object') return null;
  const state = /^\d{2}$/.test(geo.state) ? geo.state : '';
  const county = state && /^\d{3}$/.test(geo.county) ? geo.county : '';
  const tract = county && /^\d{6}$/.test(geo.tract) ? geo.tract : '';
  return state ? { state, county, tract } : null;
}

function acsFor(geoIn, stAb) {
  const geo = cleanGeo(geoIn);
  const stF = (geo && geo.state) || STATE_FIPS.get(stAb) || '';
  const tractRow = geo && geo.tract ? own(DATA.tracts, geo.state + geo.county + geo.tract) : undefined;
  const countyRow = geo && geo.county ? own(DATA.counties, geo.state + geo.county) : undefined;
  const stRec = own(DATA.states, stF);
  const rows = [tractRow, countyRow, stRec && stRec.acs, DATA.us].filter(Array.isArray);
  const pick = (i) => { for (const r of rows) { const v = Number(r[i]); if (isFinite(v) && v > 0) return v; } return 0; };
  // Most specific level that actually has a median value
  const has = (r) => Array.isArray(r) && Number(r[0]) > 0;
  const level = has(tractRow) ? 'tract' : has(countyRow) ? 'county' : has(stRec && stRec.acs) ? 'state' : 'us';
  const st = stRec || { ab: stAb || '', factor: 1.1, appr: 0.03 };
  const factor = numIn(st.factor, 0.5, 3) || 1.1;
  const appr = numIn(st.appr, -0.2, 0.3) || 0.03;
  const value = pick(0), taxes = pick(2);
  return {
    value: value * factor, rent: pick(1) * factor, taxes, rooms: pick(3) / 10 || 5.5, yearBuilt: pick(4) || 1980,
    taxRate: taxes && value ? clamp(taxes / value, 0.002, 0.03) : 0.01,
    appr, stateAb: typeof st.ab === 'string' ? st.ab : '', level,
  };
}

// ── core estimator ────────────────────────────────────────────────────────────
const OSM_TYPE = new Map(Object.entries({ house:'Single Family', detached:'Single Family', residential:'Single Family', bungalow:'Single Family', cabin:'Single Family', farm:'Single Family', yes:'Single Family',
  semidetached_house:'Duplex', terrace:'Townhouse', apartments:'Multi-Family', dormitory:'Multi-Family' }));
const TYPES = new Set(['Single Family', 'Condo', 'Townhouse', 'Multi-Family', 'Duplex']);

/**
 * @param {object} h  { address, city, state, zip, lat, lng, geo?, osmBuilding?, levels?, footprintSqft?, beds?, sqft?, type?, yearBuilt?, source, synthetic?, forSale? }
 * @param {object} opts { exact:true } → no per-home jitter (used for "my home" lookups)
 */
function estimateHome(h, opts = {}) {
  h = h || {};
  const st = stateAb(h.state);
  const a = acsFor(h.geo, st);
  const key = str(h.address).toLowerCase() + '|' + (str(h.zip) || str(h.city)).toLowerCase();
  const rng = rngFrom(hash(key));
  const type = TYPES.has(h.type) ? h.type : (typeof h.osmBuilding === 'string' && OSM_TYPE.get(h.osmBuilding)) || 'Single Family';

  const medianSqft = clamp(a.rooms * 300, 900, 3200);          // ~300 sq ft per room (never 0 → no ÷0 below)
  let sqft = numIn(h.sqft, 1, 1e6);
  const fp = numIn(h.footprintSqft, 1, 1e7);
  if (!sqft && fp) {
    const lv = clamp(numIn(h.levels, 0.5, 200) || (type === 'Single Family' ? 1.4 : 2), 1, 4);
    const s = fp * lv * 0.85;                                     // outer footprint → living area
    if (s >= 500 && s <= 6000 && type !== 'Multi-Family') sqft = s;
  }
  if (!sqft) sqft = opts.exact ? medianSqft : medianSqft * (0.72 + rng() * 0.56);
  if (type === 'Condo') sqft = Math.min(sqft, 1800);
  sqft = Math.round(clamp(sqft, 500, 6000) / 10) * 10;

  const sizeAdj = Math.pow(sqft / medianSqft, 0.65);
  const jitter = opts.exact ? 1 : 0.88 + rng() * 0.24;            // ±12% per home
  const typeAdj = type === 'Condo' ? 0.8 : type === 'Townhouse' ? 0.9 : type === 'Multi-Family' ? 1.5 : type === 'Duplex' ? 1.2 : 1;
  const value = r1000(clamp((a.value * sizeAdj * jitter * typeAdj) || 0, 25000, 20000000));

  const beds = Math.round(numIn(h.beds, 1, 20)) || clamp(Math.round(sqft / 550 + (type === 'Condo' ? -0.3 : 0.3)), 1, 6);
  const baths = Math.round(numIn(h.baths, 0.5, 20) * 2) / 2 || clamp(Math.round((beds * 0.55 + sqft / 2600) * 2) / 2, 1, 5);
  const yearBuilt = Math.round(numIn(h.yearBuilt, 1600, THIS_YEAR() + 2)) || Math.round(clamp(a.yearBuilt + (opts.exact ? 0 : (rng() - 0.5) * 30), 1880, 2025));
  const rentHi = Math.max(450, value * 0.012);
  const rent = r25(clamp((a.rent * Math.pow(beds / 2.5, 0.55) * (type === 'Multi-Family' ? 2.2 : type === 'Duplex' ? 1.8 : 1)) || 0, 450, rentHi));

  // Condition: only neutral/positive words for real homes
  const cr = rng();
  const condition = opts.exact ? 'Good' : cr < 0.2 ? 'Excellent' : cr < 0.7 ? 'Good' : 'Average';
  const arv = value;
  const price = condition === 'Average' ? r1000(arv * 0.92) : arv;
  const repairCost = condition === 'Average' ? r1000((arv - price) * 0.6) : 0;
  const spread = numIn(opts.spread, 0.01, 0.9) || 0.2;
  const lat = numIn(h.lat, -90, 90) || (h.lat === 0 ? 0 : NaN), lng = numIn(h.lng, -180, 180) || (h.lng === 0 ? 0 : NaN);
  const domN = typeof h.daysOnMarket === 'number' || typeof h.daysOnMarket === 'string' ? numIn(h.daysOnMarket, 0, 3650) || (Number(h.daysOnMarket) === 0 ? 0 : NaN) : NaN;
  const hasDom = !!h.forSale && isFinite(domN) && domN >= 0 && domN <= 3650;

  return {
    id: 're_' + hash(key).toString(36),
    address: cleanText(h.address, 120), city: cleanText(h.city, 60), state: st || a.stateAb || '', zip: str(h.zip).replace(/\D/g, '').slice(0, 5),
    lat: isFinite(lat) ? +lat.toFixed(6) : null, lng: isFinite(lng) ? +lng.toFixed(6) : null,
    type, condition, beds, baths, sqft, yearBuilt,
    price, arv, repairCost, estimatedRent: rent,
    taxes: Math.round(value * a.taxRate / 12),
    insurance: Math.round(value * 0.005 / 12),
    hoa: type === 'Condo' || type === 'Townhouse' ? Math.round(150 + rng() * 200) : 0,
    lotSize: type === 'Single Family' ? Math.round((4000 + rng() * 8000) / 100) * 100 : 0,
    daysOnMarket: hasDom ? Math.round(domN) : Math.floor(rng() * 90) + 1,
    schoolRating: null, crimeRating: null,
    appreciationRate: a.appr,
    photoSeed: hash(key) % 999 + 1,
    source: str(h.source) || 'census-estimate', forSale: !!h.forSale, synthetic: !!h.synthetic,
    valueLow: r1000(value * (1 - spread)), valueHigh: r1000(value * (1 + spread)),
    dataLevel: a.level,
  };
}

// ── RentCast (only when RENTCAST_API_KEY is set) ──────────────────────────────
const RC_BASE = 'https://api.rentcast.io/v1';
const rcKey = () => process.env.RENTCAST_API_KEY || '';
// Paid answers are reused for 1 hour (the privacy policy promises lookups are kept "about an hour").
const RC_CACHE_TTL_MS = 60 * 60 * 1000;
const _rcCache = makeCache(RC_CACHE_TTL_MS, 1000);
const RC_DEFAULT_PER_HOUR = 40;
const RC_MAX_BYTES = 1024 * 1024;        // a 40-listing or AVM answer is tens of KB

/** RENTCAST_MAX_CALLS_PER_HOUR, strictly: unset/"" → 40; digits → that number (≤ 10000; "0" = off); else → 0 (off). */
function rcMaxPerHour() {
  const raw = process.env.RENTCAST_MAX_CALLS_PER_HOUR;
  if (raw === undefined || String(raw).trim() === '') return RC_DEFAULT_PER_HOUR;
  const s = String(raw).trim();
  if (!/^\d{1,6}$/.test(s)) return 0;
  return Math.min(10000, Number(s));
}
const hasRentcast = () => !!rcKey() && rcMaxPerHour() > 0;

/** Address → lower-case + single spaces, so "400 Grand Blvd" and "400  GRAND blvd" share one cache entry / paid call. */
const normParam = (k, v) => (k === 'address' ? String(v).trim().toLowerCase().replace(/\s+/g, ' ') : String(v));

/**
 * One RentCast GET. Returns parsed JSON or null (no key, over a limit, out of time, upstream error).
 * @param {() => Promise<boolean>} [gate]  per-client check, run ONLY on a cache miss (= a billable call)
 */
async function rc(path, params, timeoutMs = 7000, gate) {
  if (!hasRentcast()) return null;
  const t0 = Date.now();
  const qs = Object.entries(params).filter(([, v]) => v !== undefined && v !== '').map(([k, v]) => k + '=' + encodeURIComponent(normParam(k, v))).join('&');
  const ck = path + '?' + qs;
  const hit = _rcCache.get(ck);
  if (hit !== undefined) return hit;
  if (gate && !(await gate())) return null;                                   // per-client cap
  const b = await RL.budget('rentcast', { windowSec: 3600, max: rcMaxPerHour() });  // site-wide cap, fails closed
  if (!b || !b.ok) return null;
  const left = timeoutMs - (Date.now() - t0);
  if (left < 800) return null;
  // redirect:'error' → the X-Api-Key header can never follow a redirect to another host
  const j = await fetchJson(RC_BASE + ck, { timeoutMs: left, redirect: 'error', maxBytes: RC_MAX_BYTES, headers: { 'X-Api-Key': rcKey() } });
  if (j !== null) _rcCache.set(ck, j);   // don't cache network / HTTP failures
  return j;
}
const RC_TYPE = new Map(Object.entries({ 'Single Family':'Single Family', Condo:'Condo', Townhouse:'Townhouse', 'Multi-Family':'Multi-Family', Apartment:'Multi-Family', Manufactured:'Single Family' }));
const rcType = (t) => (typeof t === 'string' && RC_TYPE.get(t)) || '';

/** RentCast /listings/sale item → Property (real for-sale listing) */
function fromRentcastListing(x, geo) {
  if (!x || typeof x !== 'object' || x.propertyType === 'Land') return null;
  const lat = numIn(x.latitude, -90, 90), lng = numIn(x.longitude, -180, 180);
  const rawPrice = numIn(x.price, 1000, 1e9);
  if (!validLatLng(lat, lng) || !rawPrice) return null;
  const address = cleanText(x.addressLine1 || x.formattedAddress, 120);
  if (!address) return null;
  const base = estimateHome({ address, city: x.city, state: x.state, zip: x.zipCode,
    lat, lng, geo, beds: x.bedrooms, baths: x.bathrooms, sqft: x.squareFootage, yearBuilt: x.yearBuilt,
    type: rcType(x.propertyType) || 'Single Family', source: 'rentcast', forSale: true, daysOnMarket: x.daysOnMarket }, { exact: true });
  const price = r1000(rawPrice);
  const hoaFee = x.hoa && typeof x.hoa === 'object' ? numIn(x.hoa.fee, 1, 20000) : 0;
  return Object.assign(base, {
    id: 're_rc_' + hash(str(x.id) || str(x.formattedAddress) || address).toString(36),
    price, arv: price, repairCost: 0, condition: 'Good',
    taxes: Math.round(price * (base.taxes * 12 / Math.max(1, base.arv)) / 12), insurance: Math.round(price * 0.005 / 12),
    hoa: hoaFee ? Math.round(hoaFee) : base.hoa,
    lotSize: Math.round(numIn(x.lotSize, 1, 1e8)) || base.lotSize, valueLow: null, valueHigh: null,
  });
}

// Listings are asked for around a point snapped to a 0.01° grid (~1.1 km) with ONE fixed radius, so every
// map view whose center falls in the same cell shares one paid call. 1.5 mi covers the cell plus the
// app's ~2 km query box around any center inside it.
const RC_GRID = 0.01;
const RC_LIST_RADIUS_MI = 1.5;
const snapGrid = (v) => +(Math.round(Number(v) / RC_GRID) * RC_GRID).toFixed(2);

/** @param radiusMiles ignored (kept for the old signature); @param {object} [opts] { gate } per-client check on a miss */
async function rentcastListings(lat, lng, radiusMiles, geo, timeoutMs = 7000, opts = {}) {
  lat = snapGrid(lat); lng = snapGrid(lng);
  if (!validLatLng(lat, lng)) return null;
  const j = await rc('/listings/sale', { latitude: lat.toFixed(2), longitude: lng.toFixed(2), radius: RC_LIST_RADIUS_MI.toFixed(1), status: 'Active', limit: 40 }, timeoutMs, opts.gate);
  if (!Array.isArray(j) || !j.length) return null;
  const g = await geo;                          // may be a promise so the tract lookup runs in parallel
  return j.slice(0, 200).map(x => fromRentcastListing(x, g)).filter(Boolean).slice(0, 40);
}

/**
 * RentCast AVM for one address → { property, valueLow, valueHigh, rentLow, rentHigh, comps } or null.
 * ONE paid call per address (value AVM). The rent comes from the free Census estimate unless
 * opts.withRent is set (a second paid call, /avm/rent/long-term).
 * @param {object} [opts] { gate, withRent }
 */
async function rentcastValue(address, fallback, timeoutMs = 7000, opts = {}) {
  if (!hasRentcast()) return null;
  address = cleanText(address, 200);
  if (address.length < 5) return null;
  fallback = fallback || {};
  const [v, r] = await Promise.all([
    rc('/avm/value', { address, compCount: 5 }, timeoutMs, opts.gate),
    opts.withRent ? rc('/avm/rent/long-term', { address, compCount: 5 }, timeoutMs, opts.gate) : null,
  ]);
  const vPrice = v && typeof v === 'object' ? numIn(v.price, 1000, 1e9) : 0;
  if (!vPrice) return null;
  const sp = v.subjectProperty && typeof v.subjectProperty === 'object' ? v.subjectProperty : {};
  const pick = (a, b) => (a != null && a !== '' ? a : b);
  const p = estimateHome(Object.assign({}, fallback, { beds: pick(sp.bedrooms, fallback.beds), baths: pick(sp.bathrooms, fallback.baths),
    sqft: pick(sp.squareFootage, fallback.sqft), yearBuilt: pick(sp.yearBuilt, fallback.yearBuilt),
    type: rcType(sp.propertyType) || fallback.type, source: 'rentcast' }), { exact: true });
  const price = r1000(vPrice);
  let low = r1000(numIn(v.priceRangeLow, 1000, 1e9) || price * 0.9);
  let high = r1000(numIn(v.priceRangeHigh, 1000, 1e9) || price * 1.1);
  if (low > price) low = r1000(price * 0.9);
  if (high < price) high = r1000(price * 1.1);
  const rr = r && typeof r === 'object' ? r : {};
  const rent = numIn(rr.rent, 50, 1e6);
  const estimatedRent = rent ? r25(rent) : p.estimatedRent;
  let rentLow = r25(numIn(rr.rentRangeLow, 50, 1e6) || estimatedRent * 0.9);
  let rentHigh = r25(numIn(rr.rentRangeHigh, 50, 1e6) || estimatedRent * 1.1);
  if (rentLow > estimatedRent) rentLow = r25(estimatedRent * 0.9);
  if (rentHigh < estimatedRent) rentHigh = r25(estimatedRent * 1.1);
  Object.assign(p, { price, arv: price, repairCost: 0, valueLow: low, valueHigh: high,
    estimatedRent, taxes: Math.round(price * (p.taxes * 12 / Math.max(1, p.arv)) / 12), insurance: Math.round(price * 0.005 / 12) });
  return { property: p, valueLow: low, valueHigh: high, rentLow, rentHigh,
    comps: Array.isArray(v.comparables) ? v.comparables.length : 0 };
}

module.exports = { estimateHome, acsFor, stateAb, hash, rngFrom, dayNum, rentcastListings, rentcastValue, fromRentcastListing, hasRentcast,
  rcMaxPerHour, snapGrid, RC_CACHE_TTL_MS, RC_LIST_RADIUS_MI, DATA_META: DATA.meta, USER_AGENT };
