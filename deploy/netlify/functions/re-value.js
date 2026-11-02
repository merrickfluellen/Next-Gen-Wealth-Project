/**
 * re-value — estimated value of one real home (Money City "Find my home").
 * GET /.netlify/functions/re-value?address=<one line>[&beds=&sqft=]
 *   → { property, valueLow, valueHigh, rentLow, rentHigh, source:'rentcast'|'census-estimate', confidence, explain }
 *   → { error:'bad_address' } for input that can't be an address (no upstream call is made)
 *   → { error:'not_found' } when the address can't be matched.
 *   → 429 { error:'rate_limited' } when one client asks too often.
 *
 * With RENTCAST_API_KEY: RentCast AVM (automated valuation from nearby sales) — paid, so it is only called
 * after the free Census geocoder has matched a real address, results are cached for a day, and calls are
 * capped per client and per instance (see lib/re-estimate.js).
 * Free: Census Geocoder → census tract → ACS neighborhood median value, adjusted to today with FHFA HPI
 * and for the size the player enters. Addresses are not logged or stored here.
 */

const { censusGeocode, makeCache, makeRateLimiter, clientIp, corsHeaders } = require('./lib/geo');
const { estimateHome, rentcastValue, hasRentcast } = require('./lib/re-estimate');

const _cache = makeCache(60 * 60 * 1000, 300);
const _ipLimit = makeRateLimiter(30, 10 * 60 * 1000);      // lookups per client per 10 min
const _ipPaidLimit = makeRateLimiter(10, 60 * 60 * 1000);  // RentCast lookups per client per hour
const DEADLINE_MS = 9000;                                    // stay under Netlify's 10 s limit
const r25 = (v) => Math.round(v / 25) * 25;
// Letters (any language), digits, spaces and the punctuation real addresses use
const ADDRESS_RE = /^[\p{L}\p{M}0-9 ,.#'\-\/&()]+$/u;

function reply(event, status, obj, cache) {
  return {
    statusCode: status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': cache || 'no-store', 'X-Content-Type-Options': 'nosniff', ...corsHeaders(event, 'GET, OPTIONS') },
    body: JSON.stringify(obj),
  };
}

// Whole number inside [lo, hi], else 0 ("not given")
function intIn(v, lo, hi) {
  if (v == null || v === '') return 0;
  const s = String(v).trim();
  if (!/^\d{1,6}$/.test(s)) return 0;
  const n = Number(s);
  return n >= lo && n <= hi ? n : 0;
}

exports.handler = async (event) => {
  event = event || {};
  const t0 = Date.now();
  const method = event.httpMethod || 'GET';
  if (method === 'OPTIONS') return { statusCode: 204, headers: corsHeaders(event, 'GET, OPTIONS'), body: '' };
  if (method !== 'GET' && method !== 'HEAD') {
    const r = reply(event, 405, { error: 'method_not_allowed' });
    r.headers.Allow = 'GET, OPTIONS';
    return r;
  }
  try {
    const q = event.queryStringParameters || {};
    const raw = typeof q.address === 'string' ? q.address : '';
    if (raw.length > 300) return reply(event, 200, { error: 'bad_address' });
    const address = raw.replace(/\s+/g, ' ').trim().slice(0, 200);
    if (address.length < 8 || !/\d/.test(address) || !/\p{L}/u.test(address) || !ADDRESS_RE.test(address)) {
      return reply(event, 200, { error: 'bad_address' });
    }
    const beds = intIn(q.beds, 1, 10);
    const sqft = intIn(q.sqft, 300, 15000);

    const key = [address.toLowerCase(), beds, sqft].join('|');
    const hit = _cache.get(key);
    if (hit) return reply(event, 200, hit, 'private, max-age=300');

    const ip = clientIp(event);
    if (!_ipLimit(ip)) return reply(event, 429, { error: 'rate_limited' });

    const g = await censusGeocode(address, 6000);
    if (!g) return reply(event, 200, { error: 'not_found' });

    const base = { address: g.address, city: g.city, state: g.state, zip: g.zip, lat: g.lat, lng: g.lng, geo: g.geo, beds, sqft };

    let out = null;
    const left = DEADLINE_MS - (Date.now() - t0);
    if (hasRentcast() && left > 1500 && _ipPaidLimit(ip)) {
      const rc = await rentcastValue([g.address, g.city, g.state, g.zip].filter(Boolean).join(', '), base, Math.min(7000, left - 300));
      if (rc) {
        out = Object.assign(rc, { source: 'rentcast', confidence: rc.comps >= 3 ? 'high' : 'medium',
          explain: 'RentCast estimated this value by comparing your home to ' + (rc.comps || 'several') + ' similar homes that sold nearby.' });
      }
    }
    if (!out) {
      const told = base.sqft ? 'the size you entered' : 'a typical size for your area';
      const p = estimateHome(Object.assign({}, base, { source: 'census-estimate' }), { exact: true, spread: base.sqft ? 0.18 : 0.25 });
      out = { property: p, valueLow: p.valueLow, valueHigh: p.valueHigh, rentLow: r25(p.estimatedRent * 0.85), rentHigh: r25(p.estimatedRent * 1.15),
        source: 'census-estimate', confidence: 'low',
        explain: 'We started with what homes in your neighborhood are worth (U.S. Census), updated it to today with the government house price index, and adjusted for ' + told + '. A real appraiser would also look inside the house.' };
    }
    out.property.isHome = true;
    _cache.set(key, out);
    return reply(event, 200, out, 'private, max-age=300');
  } catch {
    return reply(event, 200, { error: 'not_found' });
  }
};
