/**
 * re-geocode — search box for the Money City real-US map.
 * GET /.netlify/functions/re-geocode?q=<text>
 *   → { results: [ { label, kind:'address'|'place', lat, lng, zoom, address?, city?, state?, zip?, geo? } ] }
 *
 * - Starts with a house number ("400 Grand Blvd, Kansas City MO") → US Census Geocoder (kind 'address', zoom 17,
 *   includes tract FIPS in geo:{state,county,tract}). If Census finds nothing, falls back to Nominatim.
 * - Anything else (city, "Kansas City MO", ZIP, landmark) → Nominatim / OpenStreetMap (kind 'place').
 * Empty / too-short / not-a-place-name query → { results: [] } with no upstream call. Never throws.
 * 20-min in-memory cache (in lib/geo + here). Per-client rate limit → 429.
 */

const { censusGeocode, nominatimSearch, makeCache, makeRateLimiter, clientIp, corsHeaders } = require('./lib/geo');

const _cache = makeCache(20 * 60 * 1000, 500);
const _ipLimit = makeRateLimiter(40, 5 * 60 * 1000);   // upstream searches per client per 5 min
const MAX_Q = 120;
// Letters (any language), digits, spaces and the punctuation place names / addresses use
const QUERY_RE = /^[\p{L}\p{M}0-9 ,.#'\-\/&()]+$/u;

function reply(event, obj, status = 200) {
  return {
    statusCode: status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': status === 200 && obj.results && obj.results.length ? 'public, max-age=300' : 'no-store',
      'X-Content-Type-Options': 'nosniff',
      ...corsHeaders(event, 'GET, OPTIONS'),
    },
    body: JSON.stringify(obj),
  };
}

// "123 Main St", "1600 Pennsylvania Ave NW" — but not a bare 5-digit ZIP.
function looksLikeAddress(q) {
  return /^\d+[a-z]?(-\d+)?\s+\S/i.test(q);
}

exports.handler = async (event) => {
  event = event || {};
  try {
    const method = event.httpMethod || 'GET';
    if (method === 'OPTIONS') return { statusCode: 204, headers: corsHeaders(event, 'GET, OPTIONS'), body: '' };
    if (method !== 'GET' && method !== 'HEAD') {
      const r = reply(event, { results: [], error: 'method_not_allowed' }, 405);
      r.headers.Allow = 'GET, OPTIONS';
      return r;
    }
    const qs = event.queryStringParameters || {};
    const raw = typeof qs.q === 'string' ? qs.q : '';
    if (raw.length > 400) return reply(event, { results: [] });
    const q = raw.trim().replace(/\s+/g, ' ').slice(0, MAX_Q);
    if (q.length < 2 || !QUERY_RE.test(q) || !/[\p{L}0-9]/u.test(q)) return reply(event, { results: [] });

    const key = q.toLowerCase();
    const hit = _cache.get(key);
    if (hit) return reply(event, hit);

    if (!_ipLimit(clientIp(event))) return reply(event, { results: [], error: 'rate_limited' }, 429);

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
      results = await nominatimSearch(q, 4500);
    }

    const body = { results };
    if (results.length) _cache.set(key, body);
    return reply(event, body);
  } catch {
    return reply(event, { results: [] });
  }
};
