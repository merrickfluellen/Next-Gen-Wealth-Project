/**
 * re-listings — homes to show on the Money City map for one small map area.
 * POST /.netlify/functions/re-listings  body: { south, west, north, east, city?, state?, elements?:[Overpass elements] }
 * GET  /.netlify/functions/re-listings?south=&west=&north=&east=[&city=&state=]
 *   → { source:'rentcast'|'osm'|'synthetic', listings:[Property], attribution, tooBig? }
 *
 * The public Overpass servers refuse most server-side requests (HTTP 406), so the browser fetches the
 * OpenStreetMap addresses itself (Overpass allows CORS) and POSTs the raw elements here to be priced.
 * GET still tries Overpass from the server as a fallback.
 *
 * With RENTCAST_API_KEY: real active for-sale listings (forSale:true). Paid → only for US map areas,
 * cached per ~1 km cell for a day, capped per client and per instance.
 * Free: real street addresses from OpenStreetMap (Overpass API) with values estimated from
 * Census neighborhood data (see lib/re-estimate.js). These are practice listings — the homes
 * are not actually for sale. If an area has few mapped addresses, practice homes are added on
 * real residential streets (synthetic:true).
 *
 * Posted elements are untrusted: every field is type-checked, length-capped and must sit inside the box.
 */

const { censusTractForPoint, makeCache, makeRateLimiter, clientIp, corsHeaders, cleanText, fetchJson } = require('./lib/geo');
const { estimateHome, hash, rngFrom, dayNum, rentcastListings, hasRentcast } = require('./lib/re-estimate');

const MAX_BOX = 0.05;
const MAX_LISTINGS = 40;
const MIN_REAL = 12;
const MAX_ELEMENTS = 600;
const MAX_BODY = 3 * 1024 * 1024;
const DEADLINE_MS = 9000;                       // stay under Netlify's 10 s limit
const OVERPASS = ['https://overpass-api.de/api/interpreter', 'https://overpass.kumi.systems/api/interpreter'];
const OSM_ATTR = 'Addresses © OpenStreetMap contributors (ODbL). Values estimated from U.S. Census ACS 2024 + FHFA HPI.';
const _cache = makeCache(30 * 60 * 1000, 300);
const _ipLimit = makeRateLimiter(60, 5 * 60 * 1000);       // requests per client per 5 min
const _ipOverpass = makeRateLimiter(10, 5 * 60 * 1000);    // server-side Overpass calls per client per 5 min
const _ipPaidLimit = makeRateLimiter(15, 60 * 60 * 1000);  // RentCast cache misses per client per hour

// Buildings that are not homes
const NOT_HOME = new Set(['commercial', 'retail', 'industrial', 'warehouse', 'office', 'school', 'church', 'chapel', 'cathedral', 'mosque', 'temple', 'synagogue',
  'hospital', 'university', 'college', 'kindergarten', 'public', 'civic', 'government', 'train_station', 'transportation', 'supermarket', 'hotel', 'garage', 'garages',
  'parking', 'shed', 'barn', 'service', 'hangar', 'stadium', 'sports_hall', 'fire_station', 'kiosk', 'roof', 'construction', 'manufacture', 'fast_food', 'bank']);

function reply(event, obj, status = 200, cache = 'no-store') {
  return {
    statusCode: status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': cache, 'X-Content-Type-Options': 'nosniff', ...corsHeaders(event, 'GET, POST, OPTIONS') },
    body: JSON.stringify(obj),
  };
}

// Rough US footprint (50 states, DC, PR) — RentCast only covers the US
function inUS(lat, lng) {
  return lat >= 17 && lat <= 72 && ((lng >= -180 && lng <= -64) || lng >= 172);
}

async function overpass(query, deadline) {
  for (const url of OVERPASS) {
    const left = deadline - Date.now();
    if (left < 1000) break;
    const j = await fetchJson(url, { method: 'POST', timeoutMs: Math.min(7500, left), maxBytes: 8 * 1024 * 1024,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'data=' + encodeURIComponent(query) });
    if (j && Array.isArray(j.elements)) return j;
  }
  return null;
}

const num = (v) => (typeof v === 'number' ? v : typeof v === 'string' && v.trim() !== '' ? Number(v) : NaN);

// Rough footprint area (sq ft) of an OSM way from its bounds
function footprintSqft(b) {
  if (!b || typeof b !== 'object') return 0;
  const minlat = num(b.minlat), maxlat = num(b.maxlat), minlon = num(b.minlon), maxlon = num(b.maxlon);
  if (![minlat, maxlat, minlon, maxlon].every(isFinite)) return 0;
  const mLat = 111320, mLng = 111320 * Math.cos(((minlat + maxlat) / 2) * Math.PI / 180);
  const m2 = Math.abs(maxlat - minlat) * mLat * Math.abs(maxlon - minlon) * Math.abs(mLng) * 0.75;   // bbox × fill factor
  const sq = m2 * 10.764;
  return isFinite(sq) && sq > 0 && sq < 1e7 ? sq : 0;
}

function parseBody(event) {
  let raw = event.body || '';
  if (typeof raw !== 'string') return null;
  if (raw.length > (event.isBase64Encoded ? MAX_BODY * 1.4 : MAX_BODY)) return null;
  if (event.isBase64Encoded) raw = Buffer.from(raw, 'base64').toString('utf8');
  if (!raw.trim()) return {};
  const b = JSON.parse(raw);
  return b && typeof b === 'object' && !Array.isArray(b) ? b : null;
}

exports.handler = async (event) => {
  event = event || {};
  const t0 = Date.now();
  const method = event.httpMethod || 'GET';
  if (method === 'OPTIONS') return { statusCode: 204, headers: corsHeaders(event, 'GET, POST, OPTIONS'), body: '' };
  if (method !== 'GET' && method !== 'POST' && method !== 'HEAD') {
    const r = reply(event, { listings: [], error: 'method not allowed' }, 405);
    r.headers.Allow = 'GET, POST, OPTIONS';
    return r;
  }
  try {
    let q = event.queryStringParameters || {};
    let posted = null;
    if (method === 'POST') {
      let b = null;
      try { b = parseBody(event); } catch { b = null; }
      if (!b) return reply(event, { listings: [], error: 'bad body' });
      q = b;
      posted = Array.isArray(b.elements) ? b.elements.slice(0, MAX_ELEMENTS) : [];
    }
    const south = num(q.south), west = num(q.west), north = num(q.north), east = num(q.east);
    if (![south, west, north, east].every(isFinite) || north <= south || east <= west ||
        south < -90 || north > 90 || west < -180 || east > 180) {
      return reply(event, { listings: [], error: 'bad bbox' });
    }
    if (north - south > MAX_BOX || east - west > MAX_BOX) {
      return reply(event, { listings: [], tooBig: true });
    }
    const r3 = (n) => n.toFixed(3);
    const cacheKey = [r3(south), r3(west), r3(north), r3(east), dayNum()].join(',');
    const hit = posted ? null : _cache.get(cacheKey);
    if (hit) return reply(event, hit, 200, 'public, max-age=300');

    const ip = clientIp(event);
    if (!_ipLimit(ip)) return reply(event, { listings: [], error: 'rate_limited' }, 429);

    const cLat = (south + north) / 2, cLng = (west + east) / 2;
    const hintCity = cleanText(q.city, 60), hintState = cleanText(q.state, 30);
    const deadline = t0 + DEADLINE_MS;

    // Tract lookup and map data in parallel (keeps us well under Netlify's 10s limit)
    const geoP = censusTractForPoint(cLat, cLng, 5000);

    // Paid path: real for-sale listings (falls through to the free path if RentCast has none / fails).
    // The lib caches by rounded center, so the per-client cap only bites on real (billable) misses.
    if (hasRentcast() && inUS(cLat, cLng) && _ipPaidLimit(ip)) {
      const radius = Math.max(0.3, Math.min(3, (north - south) * 69 / 2));
      const listings = await rentcastListings(cLat, cLng, radius, geoP, Math.max(1000, Math.min(7000, deadline - Date.now() - 2500)));
      if (listings && listings.length) {
        const out = { source: 'rentcast', listings, attribution: 'Listings and values: RentCast' };
        _cache.set(cacheKey, out);
        return reply(event, out, 200, posted ? 'no-store' : 'public, max-age=300');
      }
    }

    let osmP;
    if (posted) osmP = { elements: posted };
    else if (_ipOverpass(ip)) {
      const bbox = [south, west, north, east].map(n => n.toFixed(6)).join(',');   // numbers only → no QL injection
      const query = `[out:json][timeout:12][maxsize:16777216];
nwr["addr:housenumber"]["addr:street"](${bbox})->.a;
.a out center tags bb 400;
way["highway"~"^(residential|living_street)$"]["name"](${bbox});
out center tags 60;`;
      osmP = overpass(query, deadline);
    } else osmP = null;
    const [geo, osm] = await Promise.all([geoP, osmP]);
    const els = (osm && Array.isArray(osm.elements)) ? osm.elements : [];

    // Posted coordinates must sit in (or right next to) the requested box
    const M = 0.005;
    const inBox = (lat, lng) => lat >= south - M && lat <= north + M && lng >= west - M && lng <= east + M;
    const seen = new Set();
    const real = [];
    const streets = [];
    const maxYear = new Date().getUTCFullYear();
    for (const el of els) {
      if (!el || typeof el !== 'object') continue;
      const t = (el.tags && typeof el.tags === 'object' && !Array.isArray(el.tags)) ? el.tags : {};
      // nodes: lat/lon · ways with `out center`: center · ways with `out bb`: bounds only
      const b = el.bounds && typeof el.bounds === 'object' ? el.bounds : null;
      const c = el.center && typeof el.center === 'object' ? el.center : null;
      const lat = el.lat != null ? num(el.lat) : c ? num(c.lat) : b ? (num(b.minlat) + num(b.maxlat)) / 2 : NaN;
      const lng = el.lon != null ? num(el.lon) : c ? num(c.lon) : b ? (num(b.minlon) + num(b.maxlon)) / 2 : NaN;
      if (!isFinite(lat) || !isFinite(lng) || !inBox(lat, lng)) continue;
      if (t.highway) {
        const name = cleanText(t.name, 80);
        if (name && streets.length < 200) streets.push({ name, lat, lng });
        continue;
      }
      if (t.shop || t.amenity || t.office || t.tourism || t.craft || t.leisure || (typeof t.building === 'string' && NOT_HOME.has(t.building))) continue;
      const num0 = cleanText(t['addr:housenumber'], 40).split(/[;,]/)[0].trim();
      if (!num0 || num0.length > 6 || !/\d/.test(num0)) continue;   // drops junk tags like "60865201"
      const street = cleanText(t['addr:street'], 80);
      if (!street) continue;
      const unit = cleanText(t['addr:unit'], 10);
      const address = num0 + ' ' + street + (unit ? ' #' + unit : '');
      const key = address.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      const yb = /^\d{4}$/.test(String(t.start_date || '')) ? Number(t.start_date) : 0;
      real.push({ address, city: cleanText(t['addr:city'], 60) || hintCity, state: cleanText(t['addr:state'], 30) || hintState,
        zip: String(t['addr:postcode'] || '').replace(/\D/g, '').slice(0, 5),
        lat, lng, osmBuilding: typeof t.building === 'string' ? t.building.slice(0, 40) : '', levels: num(t['building:levels']) || 0,
        footprintSqft: el.type === 'way' ? footprintSqft(b) : 0,
        yearBuilt: yb >= 1600 && yb <= maxYear ? yb : 0, source: 'osm' });
    }

    // Same homes all day for a given spot: order by hash(address + day)
    const day = dayNum();
    real.sort((a, b) => hash(a.address + day) - hash(b.address + day));
    const picked = real.slice(0, MAX_LISTINGS);

    // Sparse area → practice homes on real residential streets
    if (picked.length < MIN_REAL && streets.length) {
      const rng = rngFrom(hash(cacheKey));
      const used = new Set(picked.map(p => p.address.toLowerCase()));
      for (let i = 0; picked.length < MIN_REAL && i < streets.length * 3; i++) {
        const s = streets[i % streets.length];
        const n = (Math.floor(rng() * 90) + 1) * 100 + Math.floor(rng() * 50) * 2 + (rng() < 0.5 ? 1 : 0);
        const address = n + ' ' + s.name;
        if (used.has(address.toLowerCase())) continue;
        used.add(address.toLowerCase());
        picked.push({ address, city: hintCity, state: hintState, zip: '', lat: s.lat + (rng() - 0.5) * 0.0012, lng: s.lng + (rng() - 0.5) * 0.0012, source: 'synthetic', synthetic: true });
      }
    }

    // Nothing mapped at all (or Overpass down) → practice homes with made-up street names around the center
    if (!picked.length) {
      const rng = rngFrom(hash(cacheKey));
      const NAMES = ['Oak', 'Maple', 'Pine', 'Cedar', 'Elm', 'Park', 'Lake', 'Hill', 'Walnut', 'Willow', 'Cherry', 'Lincoln', 'Madison', 'Meadow', 'Sunset'];
      const SFX = ['St', 'Ave', 'Dr', 'Ln', 'Ct', 'Way'];
      for (let i = 0; i < 16; i++) {
        picked.push({ address: ((Math.floor(rng() * 89) + 1) * 100 + Math.floor(rng() * 99)) + ' ' + NAMES[Math.floor(rng() * NAMES.length)] + ' ' + SFX[Math.floor(rng() * SFX.length)],
          city: hintCity, state: hintState, zip: '', lat: south + (0.15 + rng() * 0.7) * (north - south), lng: west + (0.15 + rng() * 0.7) * (east - west), source: 'synthetic', synthetic: true });
      }
    }

    const stFallback = geo ? null : hintState;
    const listings = picked.map(h => estimateHome(Object.assign(h, { geo, state: h.state || stFallback || '' })));
    const out = { source: real.length ? 'osm' : 'synthetic', listings, attribution: OSM_ATTR, dataLevel: geo ? 'tract' : 'state', osmOk: !!osm };
    if (osm && !posted) _cache.set(cacheKey, out);     // don't cache an Overpass outage or client-supplied data
    return reply(event, out, 200, posted || !osm ? 'no-store' : 'public, max-age=300');
  } catch {
    return reply(event, { listings: [], error: 'unavailable' });
  }
};
