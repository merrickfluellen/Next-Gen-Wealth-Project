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
 * With RENTCAST_API_KEY: real active for-sale listings (forSale:true).
 * Free: real street addresses from OpenStreetMap (Overpass API) with values estimated from
 * Census neighborhood data (see lib/re-estimate.js). These are practice listings — the homes
 * are not actually for sale. If an area has few mapped addresses, practice homes are added on
 * real residential streets (synthetic:true).
 */

const { censusTractForPoint, makeCache, USER_AGENT } = require('./lib/geo');
const { estimateHome, hash, rngFrom, dayNum, rentcastListings, hasRentcast } = require('./lib/re-estimate');

const HEADERS = { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=300', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type' };
const MAX_BOX = 0.05;
const MAX_LISTINGS = 40;
const MIN_REAL = 12;
const OVERPASS = ['https://overpass-api.de/api/interpreter', 'https://overpass.kumi.systems/api/interpreter'];
const OSM_ATTR = 'Addresses © OpenStreetMap contributors (ODbL). Values estimated from U.S. Census ACS 2024 + FHFA HPI.';
const _cache = makeCache(30 * 60 * 1000, 300);

// Buildings that are not homes
const NOT_HOME = new Set(['commercial', 'retail', 'industrial', 'warehouse', 'office', 'school', 'church', 'chapel', 'cathedral', 'mosque', 'temple', 'synagogue',
  'hospital', 'university', 'college', 'kindergarten', 'public', 'civic', 'government', 'train_station', 'transportation', 'supermarket', 'hotel', 'garage', 'garages',
  'parking', 'shed', 'barn', 'service', 'hangar', 'stadium', 'sports_hall', 'fire_station', 'kiosk', 'roof', 'construction', 'manufacture', 'fast_food', 'bank']);

async function overpass(query) {
  for (const url of OVERPASS) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 7500);
    try {
      const res = await fetch(url, { method: 'POST', signal: ctrl.signal, headers: { 'User-Agent': USER_AGENT, 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'data=' + encodeURIComponent(query) });
      if (res.ok) return await res.json();
    } catch { /* try next mirror */ } finally { clearTimeout(t); }
  }
  return null;
}

// Rough footprint area (sq ft) of an OSM way from its bounds
function footprintSqft(el) {
  const b = el.bounds;
  if (!b) return 0;
  const mLat = 111320, mLng = 111320 * Math.cos(((b.minlat + b.maxlat) / 2) * Math.PI / 180);
  const m2 = (b.maxlat - b.minlat) * mLat * (b.maxlon - b.minlon) * mLng * 0.75;   // bbox × fill factor
  return m2 * 10.764;
}

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: HEADERS, body: '' };
  let q = event.queryStringParameters || {};
  let posted = null;
  if (event.httpMethod === 'POST') {
    try { const b = JSON.parse(event.isBase64Encoded ? Buffer.from(event.body || '', 'base64').toString() : event.body || '{}'); q = b; posted = Array.isArray(b.elements) ? b.elements.slice(0, 600) : []; }
    catch { return { statusCode: 200, headers: HEADERS, body: JSON.stringify({ listings: [], error: 'bad body' }) }; }
  }
  const south = Number(q.south), west = Number(q.west), north = Number(q.north), east = Number(q.east);
  if (![south, west, north, east].every(isFinite) || north <= south || east <= west) {
    return { statusCode: 200, headers: HEADERS, body: JSON.stringify({ listings: [], error: 'bad bbox' }) };
  }
  if (north - south > MAX_BOX || east - west > MAX_BOX) {
    return { statusCode: 200, headers: HEADERS, body: JSON.stringify({ listings: [], tooBig: true }) };
  }
  const r3 = (n) => n.toFixed(3);
  const cacheKey = [r3(south), r3(west), r3(north), r3(east), dayNum()].join(',');
  const hit = posted ? null : _cache.get(cacheKey);
  if (hit) return { statusCode: 200, headers: HEADERS, body: JSON.stringify(hit) };

  const cLat = (south + north) / 2, cLng = (west + east) / 2;
  const hintCity = String(q.city || '').slice(0, 60), hintState = String(q.state || '').slice(0, 30);

  // Tract lookup and map data in parallel (keeps us well under Netlify's 10s limit)
  const bbox = `${south},${west},${north},${east}`;
  const query = `[out:json][timeout:12];
nwr["addr:housenumber"]["addr:street"](${bbox})->.a;
.a out center tags bb 400;
way["highway"~"^(residential|living_street)$"]["name"](${bbox});
out center tags 60;`;
  const geoP = censusTractForPoint(cLat, cLng);

  // Paid path: real for-sale listings (falls through to the free path if RentCast has none / fails)
  if (hasRentcast()) {
    const radius = Math.max(0.3, Math.min(3, (north - south) * 69 / 2));
    const listings = await rentcastListings(cLat, cLng, radius, await geoP);
    if (listings && listings.length) {
      const out = { source: 'rentcast', listings, attribution: 'Listings and values: RentCast' };
      _cache.set(cacheKey, out);
      return { statusCode: 200, headers: HEADERS, body: JSON.stringify(out) };
    }
  }

  const [geo, osm] = await Promise.all([geoP, posted ? { elements: posted } : overpass(query)]);
  const els = (osm && Array.isArray(osm.elements)) ? osm.elements : [];
  const seen = new Set();
  const real = [];
  const streets = [];
  for (const el of els) {
    const t = el.tags || {};
    // nodes: lat/lon · ways with `out center`: center · ways with `out bb`: bounds only
    const b = el.bounds;
    const lat = el.lat != null ? el.lat : el.center ? el.center.lat : b ? (b.minlat + b.maxlat) / 2 : NaN;
    const lng = el.lon != null ? el.lon : el.center ? el.center.lon : b ? (b.minlon + b.maxlon) / 2 : NaN;
    if (!isFinite(lat) || !isFinite(lng)) continue;
    if (t.highway) { streets.push({ name: t.name, lat, lng }); continue; }
    if (t.shop || t.amenity || t.office || t.tourism || t.craft || t.leisure || NOT_HOME.has(t.building)) continue;
    const num = String(t['addr:housenumber']).split(/[;,]/)[0].trim();
    if (!num || num.length > 6) continue;   // drops junk tags like "60865201"
    const address = num + ' ' + t['addr:street'] + (t['addr:unit'] ? ' #' + t['addr:unit'] : '');
    const key = address.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    real.push({ address, city: t['addr:city'] || hintCity, state: t['addr:state'] || hintState, zip: (t['addr:postcode'] || '').slice(0, 5),
      lat, lng, osmBuilding: t.building, levels: Number(t['building:levels']) || 0, footprintSqft: el.type === 'way' ? footprintSqft(el) : 0,
      yearBuilt: /^\d{4}$/.test(t.start_date || '') ? Number(t.start_date) : 0, source: 'osm' });
  }

  // Same homes all day for a given spot: order by hash(address + day)
  const day = dayNum();
  real.sort((a, b) => hash(a.address + day) - hash(b.address + day));
  let picked = real.slice(0, MAX_LISTINGS);

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
  if (osm && !posted) _cache.set(cacheKey, out);     // don't cache an Overpass outage
  return { statusCode: 200, headers: HEADERS, body: JSON.stringify(out) };
};
