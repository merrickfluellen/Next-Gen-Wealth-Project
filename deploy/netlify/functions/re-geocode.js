/**
 * re-geocode — search box for the Money City real-US map.
 * POST /.netlify/functions/re-geocode  body: { q:'<text>' }      (what the app sends)
 * GET  /.netlify/functions/re-geocode?q=<text>                   (older clients)
 *   → { results: [ { label, kind:'address'|'place', lat, lng, zoom, address?, city?, state?, zip?, geo? } ] }
 *   → 503 { results:[], error:'busy' } when the place search is busy (site-wide 1 request/second
 *     Nominatim slot taken) or down. The app then searches its bundled city list instead.
 *   → 429 when one client asks too often (lib/firewall.js, durable across instances).
 *
 * - Starts with a house number ("400 Grand Blvd, Kansas City MO") → US Census Geocoder (kind 'address', zoom 17,
 *   includes tract FIPS in geo:{state,county,tract}). If Census finds nothing, falls back to Nominatim.
 * - Anything else (city, "Kansas City MO", ZIP, landmark) → Nominatim / OpenStreetMap (kind 'place').
 * Empty / too-short / not-a-place-name query → { results: [] } with no upstream call.
 *
 * Privacy: a query can be a street address, so every response is Cache-Control: no-store, the app
 * POSTs it (no address in URLs), nothing is logged, and the in-memory caches (keyed by the normalised
 * query: lower-case, punctuation → spaces) expire after 20 min.
 */

const { withFirewall } = require('./lib/firewall');
const { censusGeocode, nominatimSearch, makeCache, normQuery, str } = require('./lib/geo');

const _cache = makeCache(20 * 60 * 1000, 500);
const MAX_Q = 120;
// Letters (any language), digits, spaces and the punctuation place names / addresses use
const QUERY_RE = /^[\p{L}\p{M}0-9 ,.#'\-\/&()]+$/u;

const json = (status, obj, extra) => ({ statusCode: status, headers: { 'Content-Type': 'application/json', ...extra }, body: JSON.stringify(obj) });

// "123 Main St", "1600 Pennsylvania Ave NW" — but not a bare 5-digit ZIP.
function looksLikeAddress(q) {
  return /^\d+[a-z]?(-\d+)?\s+\S/i.test(q);
}

async function handle(event) {
  try {
    const src = event.httpMethod === 'POST' ? (event.jsonBody || {}) : (event.queryStringParameters || {});
    const raw = str(src.q);
    if (raw.length > 400) return json(200, { results: [] });
    const q = raw.trim().replace(/\s+/g, ' ').slice(0, MAX_Q);
    if (q.length < 2 || !QUERY_RE.test(q) || !/[\p{L}0-9]/u.test(q)) return json(200, { results: [] });

    const key = normQuery(q);
    if (key.length < 2) return json(200, { results: [] });
    const hit = _cache.get(key);
    if (hit) return json(200, hit);

    let results = [];
    if (looksLikeAddress(q)) {
      const m = await censusGeocode(q, 4500);
      if (m) {
        results.push({
          label: [m.address, m.city, [m.state, m.zip].filter(Boolean).join(' ')].filter(Boolean).join(', '),
          kind: 'address',
          lat: m.lat,
          lng: m.lng,
          zoom: 17,
          address: m.address,
          city: m.city,
          state: m.state,
          zip: m.zip,
          geo: m.geo || null,
        });
      }
    }
    if (!results.length) {
      const places = await nominatimSearch(q, 4500);
      // null = busy / upstream down: "try again" (the app falls back to its bundled list), not "no such place"
      if (places === null) return json(503, { results: [], error: 'busy' }, { 'Retry-After': '2' });
      results = places;
    }

    const body = { results };
    if (results.length) _cache.set(key, body);
    return json(200, body);
  } catch {
    return json(503, { results: [], error: 'unavailable' });
  }
}

// Firewall first: method/Origin checks and the per-client limit (durable) run before anything is parsed.
exports.handler = withFirewall(handle, {
  name: 're-geocode',
  methods: ['GET', 'POST'],
  rateLimit: { windowMs: 5 * 60 * 1000, max: 40 },           // searches per client per 5 min
  durable: true,
  maxBodyBytes: 2048,
  allowedOrigins: ['https://nextgenwealthproject.netlify.app'],
});
