/**
 * re-geocode — search box for the Money City real-US map.
 * GET /.netlify/functions/re-geocode?q=<text>
 *   → { results: [ { label, kind:'address'|'place', lat, lng, zoom, address?, city?, state?, zip?, geo? } ] }
 *
 * - Starts with a house number ("400 Grand Blvd, Kansas City MO") → US Census Geocoder (kind 'address', zoom 17,
 *   includes tract FIPS in geo:{state,county,tract}). If Census finds nothing, falls back to Nominatim.
 * - Anything else (city, "Kansas City MO", ZIP, landmark) → Nominatim / OpenStreetMap (kind 'place').
 * Empty / too-short query → { results: [] }. Never throws. 20-min in-memory cache (in lib/geo + here).
 */

const { censusGeocode, nominatimSearch, makeCache } = require('./lib/geo');

const HEADERS = {
  'Content-Type': 'application/json',
  'Cache-Control': 'public, max-age=300',
  'Access-Control-Allow-Origin': '*',
};

const _cache = makeCache(20 * 60 * 1000, 500);

function reply(obj) {
  return { statusCode: 200, headers: HEADERS, body: JSON.stringify(obj) };
}

// "123 Main St", "1600 Pennsylvania Ave NW" — but not a bare 5-digit ZIP.
function looksLikeAddress(q) {
  return /^\d+[a-z]?(-\d+)?\s+\S/i.test(q);
}

exports.handler = async (event) => {
  try {
    if (event && event.httpMethod === 'OPTIONS') {
      return { statusCode: 204, headers: { ...HEADERS, 'Access-Control-Allow-Methods': 'GET, OPTIONS' }, body: '' };
    }
    const qs = (event && event.queryStringParameters) || {};
    const q = String(qs.q || '').trim().replace(/\s+/g, ' ').slice(0, 200);
    if (q.length < 2) return reply({ results: [] });

    const key = q.toLowerCase();
    const hit = _cache.get(key);
    if (hit) return reply(hit);

    let results = [];
    if (looksLikeAddress(q)) {
      const m = await censusGeocode(q);
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
      results = await nominatimSearch(q);
    }

    const body = { results };
    if (results.length) _cache.set(key, body);
    return reply(body);
  } catch {
    return reply({ results: [] });
  }
};
