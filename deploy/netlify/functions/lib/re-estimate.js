/**
 * lib/re-estimate.js — home value / rent estimator for the Money City real-US-map feature.
 *
 * Free data (bundled in re-data.json, rebuilt by /tmp/qe/mls/build-data.js style script):
 *   - U.S. Census Bureau ACS 2024 5-year, table-based summary file (public, no key), per census tract,
 *     county and state: B25077 median home value, B25064 median gross rent, B25103 median real estate
 *     taxes paid, B25018 median rooms, B25035 median year built.
 *   - FHFA All-Transactions House Price Index by state: `factor` = latest quarter ÷ 2022–2024 average
 *     (brings ACS values forward to today), `appr` = 3-year annualized growth (clamped 1%–6%).
 * Optional paid data: RentCast API (env RENTCAST_API_KEY) — AVM values, rent AVM, real for-sale listings.
 *
 * Rules: never invent negative facts about a real home (condition only Excellent/Good/Average,
 * no school/crime ratings). Everything is deterministic per address (no Math.random).
 */

const DATA = require('./re-data.json');
const { fetchJson, USER_AGENT } = require('./geo');

const STATE_FIPS = {};                      // 'MO' → '29'
for (const [f, s] of Object.entries(DATA.states)) STATE_FIPS[s.ab] = f;
const STATE_NAMES = { Alabama:'AL', Alaska:'AK', Arizona:'AZ', Arkansas:'AR', California:'CA', Colorado:'CO', Connecticut:'CT', Delaware:'DE', 'District of Columbia':'DC', Florida:'FL', Georgia:'GA', Hawaii:'HI', Idaho:'ID', Illinois:'IL', Indiana:'IN', Iowa:'IA', Kansas:'KS', Kentucky:'KY', Louisiana:'LA', Maine:'ME', Maryland:'MD', Massachusetts:'MA', Michigan:'MI', Minnesota:'MN', Mississippi:'MS', Missouri:'MO', Montana:'MT', Nebraska:'NE', Nevada:'NV', 'New Hampshire':'NH', 'New Jersey':'NJ', 'New Mexico':'NM', 'New York':'NY', 'North Carolina':'NC', 'North Dakota':'ND', Ohio:'OH', Oklahoma:'OK', Oregon:'OR', Pennsylvania:'PA', 'Rhode Island':'RI', 'South Carolina':'SC', 'South Dakota':'SD', Tennessee:'TN', Texas:'TX', Utah:'UT', Vermont:'VT', Virginia:'VA', Washington:'WA', 'West Virginia':'WV', Wisconsin:'WI', Wyoming:'WY', 'Puerto Rico':'PR' };
const stateAb = (s) => { s = String(s || '').trim(); if (/^[A-Za-z]{2}$/.test(s)) return s.toUpperCase(); return STATE_NAMES[s] || ''; };

// ── deterministic helpers ─────────────────────────────────────────────────────
function hash(str) {                        // FNV-1a 32-bit
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

// ── ACS lookup: tract → county → state → US, field by field ───────────────────
function acsFor(geo, stAb) {
  const stF = (geo && geo.state) || STATE_FIPS[stAb] || '';
  const rows = [];
  if (geo && geo.state && geo.county && geo.tract) rows.push(DATA.tracts[geo.state + geo.county + geo.tract]);
  if (geo && geo.state && geo.county) rows.push(DATA.counties[geo.state + geo.county]);
  if (stF && DATA.states[stF]) rows.push(DATA.states[stF].acs);
  rows.push(DATA.us);
  const pick = (i) => { for (const r of rows) if (r && r[i] > 0) return r[i]; return 0; };
  const level = rows[0] && rows[0][0] > 0 ? (geo && geo.tract ? 'tract' : 'county') : 'state';
  const st = DATA.states[stF] || { ab: stAb || '', factor: 1.1, appr: 0.03 };
  return {
    value: pick(0) * st.factor, rent: pick(1) * st.factor, taxes: pick(2), rooms: pick(3) / 10 || 5.5, yearBuilt: pick(4) || 1980,
    taxRate: pick(2) && pick(0) ? clamp(pick(2) / pick(0), 0.002, 0.03) : 0.01,
    appr: st.appr, stateAb: st.ab, level,
  };
}

// ── core estimator ────────────────────────────────────────────────────────────
const OSM_TYPE = { house:'Single Family', detached:'Single Family', residential:'Single Family', bungalow:'Single Family', cabin:'Single Family', farm:'Single Family', yes:'Single Family',
  semidetached_house:'Duplex', terrace:'Townhouse', apartments:'Multi-Family', dormitory:'Multi-Family' };

/**
 * @param {object} h  { address, city, state, zip, lat, lng, geo?, osmBuilding?, levels?, footprintSqft?, beds?, sqft?, type?, yearBuilt?, source, synthetic?, forSale? }
 * @param {object} opts { exact:true } → no per-home jitter (used for "my home" lookups)
 */
function estimateHome(h, opts = {}) {
  const st = stateAb(h.state);
  const a = acsFor(h.geo, st);
  const key = String(h.address || '').toLowerCase() + '|' + String(h.zip || h.city || '').toLowerCase();
  const rng = rngFrom(hash(key));
  const type = h.type || OSM_TYPE[h.osmBuilding] || 'Single Family';

  const medianSqft = clamp(a.rooms * 300, 900, 3200);          // ~300 sq ft per room
  let sqft = Number(h.sqft) || 0;
  if (!sqft && h.footprintSqft) {
    const lv = clamp(Number(h.levels) || (type === 'Single Family' ? 1.4 : 2), 1, 4);
    const s = h.footprintSqft * lv * 0.85;                        // outer footprint → living area
    if (s >= 500 && s <= 6000 && type !== 'Multi-Family') sqft = s;
  }
  if (!sqft) sqft = opts.exact ? medianSqft : medianSqft * (0.72 + rng() * 0.56);
  if (type === 'Condo') sqft = Math.min(sqft, 1800);
  sqft = Math.round(clamp(sqft, 500, 6000) / 10) * 10;

  const sizeAdj = Math.pow(sqft / medianSqft, 0.65);
  const jitter = opts.exact ? 1 : 0.88 + rng() * 0.24;            // ±12% per home
  const typeAdj = type === 'Condo' ? 0.8 : type === 'Townhouse' ? 0.9 : type === 'Multi-Family' ? 1.5 : type === 'Duplex' ? 1.2 : 1;
  const value = r1000(clamp(a.value * sizeAdj * jitter * typeAdj, 25000, 20000000));

  const beds = Number(h.beds) || clamp(Math.round(sqft / 550 + (type === 'Condo' ? -0.3 : 0.3)), 1, 6);
  const baths = Number(h.baths) || clamp(Math.round((beds * 0.55 + sqft / 2600) * 2) / 2, 1, 5);
  const yearBuilt = Number(h.yearBuilt) || Math.round(clamp(a.yearBuilt + (opts.exact ? 0 : (rng() - 0.5) * 30), 1880, 2025));
  const rent = r25(clamp(a.rent * Math.pow(beds / 2.5, 0.55) * (type === 'Multi-Family' ? 2.2 : type === 'Duplex' ? 1.8 : 1), 450, value * 0.012));

  // Condition: only neutral/positive words for real homes
  const cr = rng();
  const condition = opts.exact ? 'Good' : cr < 0.2 ? 'Excellent' : cr < 0.7 ? 'Good' : 'Average';
  const arv = value;
  const price = condition === 'Average' ? r1000(arv * 0.92) : arv;
  const repairCost = condition === 'Average' ? r1000((arv - price) * 0.6) : 0;
  const spread = opts.spread || 0.2;

  return {
    id: 're_' + hash(key).toString(36),
    address: h.address, city: h.city || '', state: st || a.stateAb || '', zip: h.zip || '',
    lat: +Number(h.lat).toFixed(6), lng: +Number(h.lng).toFixed(6),
    type, condition, beds, baths, sqft, yearBuilt,
    price, arv, repairCost, estimatedRent: rent,
    taxes: Math.round(value * a.taxRate / 12),
    insurance: Math.round(value * 0.005 / 12),
    hoa: type === 'Condo' || type === 'Townhouse' ? Math.round(150 + rng() * 200) : 0,
    lotSize: type === 'Single Family' ? Math.round((4000 + rng() * 8000) / 100) * 100 : 0,
    daysOnMarket: h.forSale && h.daysOnMarket != null ? h.daysOnMarket : Math.floor(rng() * 90) + 1,
    schoolRating: null, crimeRating: null,
    appreciationRate: a.appr,
    photoSeed: hash(key) % 999 + 1,
    source: h.source || 'census-estimate', forSale: !!h.forSale, synthetic: !!h.synthetic,
    valueLow: r1000(value * (1 - spread)), valueHigh: r1000(value * (1 + spread)),
    dataLevel: a.level,
  };
}

// ── RentCast (only when RENTCAST_API_KEY is set) ──────────────────────────────
const RC_BASE = 'https://api.rentcast.io/v1';
const rcKey = () => process.env.RENTCAST_API_KEY || '';
async function rc(path, params) {
  if (!rcKey()) return null;
  const qs = Object.entries(params).filter(([, v]) => v !== undefined && v !== '').map(([k, v]) => k + '=' + encodeURIComponent(v)).join('&');
  return fetchJson(RC_BASE + path + '?' + qs, { timeoutMs: 7000, headers: { 'X-Api-Key': rcKey() } });
}
const RC_TYPE = { 'Single Family':'Single Family', Condo:'Condo', Townhouse:'Townhouse', 'Multi-Family':'Multi-Family', Apartment:'Multi-Family', Manufactured:'Single Family' };

/** RentCast /listings/sale item → Property (real for-sale listing) */
function fromRentcastListing(x, geo) {
  if (!x || !isFinite(x.latitude) || !isFinite(x.longitude) || !x.price || x.propertyType === 'Land') return null;
  const base = estimateHome({ address: x.addressLine1 || x.formattedAddress, city: x.city, state: x.state, zip: x.zipCode,
    lat: x.latitude, lng: x.longitude, geo, beds: x.bedrooms, baths: x.bathrooms, sqft: x.squareFootage, yearBuilt: x.yearBuilt,
    type: RC_TYPE[x.propertyType] || 'Single Family', source: 'rentcast', forSale: true, daysOnMarket: x.daysOnMarket }, { exact: true });
  const price = r1000(x.price);
  return Object.assign(base, {
    id: 're_rc_' + hash(String(x.id || x.formattedAddress)).toString(36),
    price, arv: price, repairCost: 0, condition: 'Good',
    taxes: Math.round(price * (base.taxes * 12 / Math.max(1, base.arv)) / 12), insurance: Math.round(price * 0.005 / 12),
    hoa: x.hoa && x.hoa.fee ? Math.round(x.hoa.fee) : base.hoa,
    lotSize: x.lotSize || base.lotSize, valueLow: null, valueHigh: null,
  });
}

async function rentcastListings(lat, lng, radiusMiles, geo) {
  const j = await rc('/listings/sale', { latitude: lat, longitude: lng, radius: radiusMiles.toFixed(2), status: 'Active', limit: 40 });
  if (!Array.isArray(j) || !j.length) return null;
  return j.map(x => fromRentcastListing(x, geo)).filter(Boolean).slice(0, 40);
}

/** RentCast AVM for one address → { property, valueLow, valueHigh, rentLow, rentHigh } or null */
async function rentcastValue(address, fallback) {
  if (!rcKey()) return null;
  const [v, r] = await Promise.all([rc('/avm/value', { address, compCount: 5 }), rc('/avm/rent/long-term', { address, compCount: 5 })]);
  if (!v || !v.price) return null;
  const sp = v.subjectProperty || {};
  const p = estimateHome(Object.assign({}, fallback, { beds: sp.bedrooms, baths: sp.bathrooms, sqft: sp.squareFootage, yearBuilt: sp.yearBuilt,
    type: RC_TYPE[sp.propertyType] || fallback.type, source: 'rentcast' }), { exact: true });
  const price = r1000(v.price);
  Object.assign(p, { price, arv: price, repairCost: 0, valueLow: r1000(v.priceRangeLow || price * 0.9), valueHigh: r1000(v.priceRangeHigh || price * 1.1),
    estimatedRent: r && r.rent ? r25(r.rent) : p.estimatedRent, taxes: Math.round(price * (p.taxes * 12 / Math.max(1, p.arv)) / 12), insurance: Math.round(price * 0.005 / 12) });
  return { property: p, valueLow: p.valueLow, valueHigh: p.valueHigh,
    rentLow: r && r.rentRangeLow ? r25(r.rentRangeLow) : r25(p.estimatedRent * 0.9), rentHigh: r && r.rentRangeHigh ? r25(r.rentRangeHigh) : r25(p.estimatedRent * 1.1),
    comps: Array.isArray(v.comparables) ? v.comparables.length : 0 };
}

module.exports = { estimateHome, acsFor, stateAb, hash, rngFrom, dayNum, rentcastListings, rentcastValue, fromRentcastListing, hasRentcast: () => !!rcKey(), DATA_META: DATA.meta, USER_AGENT };
