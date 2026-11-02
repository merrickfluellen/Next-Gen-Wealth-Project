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
 * With RENTCAST_API_KEY: real active for-sale listings (forSale:true). Paid → only for US map areas; asked
 * for around the map center snapped to a 0.01° (~1 km) grid with one fixed radius and cached for 1 hour,
 * so nearby views share one call; each billable miss must pass a per-client cap (15/hour, durable, fails
 * closed) and the site-wide hourly budget (lib/re-estimate.js).
 * Free: real street addresses from OpenStreetMap (Overpass API) with values estimated from
 * Census neighborhood data (see lib/re-estimate.js). These are practice listings — the homes
 * are not actually for sale. If an area has few mapped addresses, practice homes are added on
 * real residential streets (synthetic:true).
 *
 * Posted elements are untrusted: every field is type-checked, length-capped and must sit inside the box.
 * Request order: firewall (method, Origin, durable per-client limit, 256 KB body cap) → nesting-depth
 * pre-scan → JSON.parse. So a rate-limited or oversized request costs no parsing.
 */

const { withFirewall } = require('./lib/firewall');
const RL = require('./lib/ratelimit');
const { censusTractForPoint, makeCache, cleanText, fetchJson, str } = require('./lib/geo');
const { estimateHome, hash, rngFrom, dayNum, rentcastListings, hasRentcast, snapGrid } = require('./lib/re-estimate');

const MAX_BOX = 0.05;
const MAX_LISTINGS = 40;
const MIN_REAL = 12;
const MAX_ELEMENTS = 600;
const MAX_BODY = 256 * 1024;                    // the app posts ≤ 360 Overpass elements
const MAX_DEPTH = 6;                            // { elements:[ { tags:{…} } ] } is 4 deep
const DEADLINE_MS = 9000;                       // stay under Netlify's 10 s limit
const OVERPASS = ['https://overpass-api.de/api/interpreter', 'https://overpass.kumi.systems/api/interpreter'];
const OSM_ATTR = 'Addresses © OpenStreetMap contributors (ODbL). Values estimated from U.S. Census ACS 2024 + FHFA HPI.';
const _cache = makeCache(30 * 60 * 1000, 300);  // GET answers (no personal data: a map box + city/state hints)
const OVERPASS_PER_CLIENT = { windowSec: 5 * 60, max: 10 };   // server-side Overpass calls per client
const PAID_PER_CLIENT = { windowSec: 3600, max: 15, failClosed: true };  // RentCast cache misses per client

// Buildings that are not homes
const NOT_HOME = new Set(['commercial', 'retail', 'industrial', 'warehouse', 'office', 'school', 'church', 'chapel', 'cathedral', 'mosque', 'temple', 'synagogue',
  'hospital', 'university', 'college', 'kindergarten', 'public', 'civic', 'government', 'train_station', 'transportation', 'supermarket', 'hotel', 'garage', 'garages',
  'parking', 'shed', 'barn', 'service', 'hangar', 'stadium', 'sports_hall', 'fire_station', 'kiosk', 'roof', 'construction', 'manufacture', 'fast_food', 'bank']);

function reply(obj, status = 200) {
  return { statusCode: status, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(obj) };
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

const num = (v) => (typeof v === 'number' ? v : typeof v === 'string' && v.trim() !== '' && v.length < 40 ? Number(v) : NaN);

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

/** True when no array/object in the JSON text nests deeper than `max` (string-aware, linear). */
function depthOk(s, max) {
  let d = 0;
  let inStr = false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (inStr) {
      if (c === 92) i++;                     // backslash: skip the escaped char
      else if (c === 34) inStr = false;
      continue;
    }
    if (c === 34) inStr = true;
    else if (c === 91 || c === 123) { if (++d > max) return false; }
    else if (c === 93 || c === 125) d--;
  }
  return true;
}

function parseBody(event) {
  let raw = event.body == null ? '' : event.body;
  if (typeof raw !== 'string') return null;
  if (raw.length > (event.isBase64Encoded ? MAX_BODY * 1.4 : MAX_BODY)) return null;   // the firewall caps it too
  if (event.isBase64Encoded) raw = Buffer.from(raw, 'base64').toString('utf8');
  if (raw.length > MAX_BODY) return null;
  if (!raw.trim()) return {};
  if (!depthOk(raw, MAX_DEPTH)) return null;
  const b = JSON.parse(raw);
  return b && typeof b === 'object' && !Array.isArray(b) ? b : null;
}

async function handle(event) {
  const t0 = Date.now();
  const method = event.httpMethod || 'GET';
  try {
    let q = event.queryStringParameters || {};
    let posted = null;
    if (method === 'POST') {
      let b = null;
      try { b = parseBody(event); } catch { b = null; }
      if (!b) return reply({ listings: [], error: 'bad body' });
      q = b;
      posted = Array.isArray(b.elements) ? b.elements.slice(0, MAX_ELEMENTS) : [];
    }
    const south = num(q.south), west = num(q.west), north = num(q.north), east = num(q.east);
    if (![south, west, north, east].every(isFinite) || north <= south || east <= west ||
        south < -90 || north > 90 || west < -180 || east > 180) {
      return reply({ listings: [], error: 'bad bbox' });
    }
    if (north - south > MAX_BOX || east - west > MAX_BOX) {
      return reply({ listings: [], tooBig: true });
    }
    const hintCity = cleanText(q.city, 60), hintState = cleanText(q.state, 30);
    const r3 = (n) => n.toFixed(3);
    // The city/state hints end up in the listings, so they are part of the key: a GET with made-up
    // hints can only ever be served back to a request with the same hints (no cache poisoning).
    const cacheKey = [r3(south), r3(west), r3(north), r3(east), dayNum(), hintCity.toLowerCase(), hintState.toLowerCase()].join('|');
    const hit = posted ? null : _cache.get(cacheKey);
    if (hit) return reply(hit);

    const ip = RL.ipKey(event.headers);
    const cLat = (south + north) / 2, cLng = (west + east) / 2;
    const deadline = t0 + DEADLINE_MS;

    // Tract lookup and map data in parallel (keeps us well under Netlify's 10s limit)
    const geoP = censusTractForPoint(cLat, cLng, 5000);

    // Paid path: real for-sale listings (falls through to the free path if RentCast has none / fails).
    // The lib snaps the center to a 0.01° grid with a fixed radius and caches the answer; the per-client
    // gate runs only on a cache miss (a billable call).
    const sLat = snapGrid(cLat), sLng = snapGrid(cLng);
    if (hasRentcast() && inUS(sLat, sLng)) {
      const gate = async () => (await RL.hit('rc-list', ip, PAID_PER_CLIENT)).ok;
      const listings = await rentcastListings(sLat, sLng, null, geoP, Math.max(1000, Math.min(7000, deadline - Date.now() - 2500)), { gate });
      if (listings && listings.length) {
        const out = { source: 'rentcast', listings, attribution: 'Listings and values: RentCast' };
        if (!posted) _cache.set(cacheKey, out);
        return reply(out);
      }
    }

    let osmP;
    if (posted) osmP = { elements: posted };
    else if ((await RL.hit('re-overpass', ip, OVERPASS_PER_CLIENT)).ok) {
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
      if (t.shop || t.amenity || t.office || t.tourism || t.craft || t.leisure || NOT_HOME.has(str(t.building))) continue;
      const num0 = cleanText(t['addr:housenumber'], 40).split(/[;,]/)[0].trim();
      if (!num0 || num0.length > 6 || !/\d/.test(num0)) continue;   // drops junk tags like "60865201"
      const street = cleanText(t['addr:street'], 80);
      if (!street) continue;
      const unit = cleanText(t['addr:unit'], 10);
      const address = num0 + ' ' + street + (unit ? ' #' + unit : '');
      const key = address.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      const sd = cleanText(t.start_date, 10);
      const yb = /^\d{4}$/.test(sd) ? Number(sd) : 0;
      real.push({ address, city: cleanText(t['addr:city'], 60) || hintCity, state: cleanText(t['addr:state'], 30) || hintState,
        zip: cleanText(t['addr:postcode'], 20).replace(/\D/g, '').slice(0, 5),
        lat, lng, osmBuilding: cleanText(t.building, 40), levels: num(t['building:levels']) || 0,
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
    return reply(out);
  } catch {
    return reply({ listings: [], error: 'unavailable' });
  }
}

// Firewall first: method/Origin checks, the per-client limit (durable, across instances) and the 256 KB
// body cap all run before the body is touched. json:false → the body is parsed here, after the
// nesting-depth pre-scan. Responses are no-store (the app POSTs; POST answers aren't cacheable anyway).
exports.handler = withFirewall(handle, {
  name: 're-listings',
  methods: ['GET', 'POST'],
  rateLimit: { windowMs: 5 * 60 * 1000, max: 60 },           // requests per client per 5 min
  durable: true,
  maxBodyBytes: MAX_BODY,
  json: false,
  allowedOrigins: ['https://nextgenwealthproject.netlify.app'],
});
