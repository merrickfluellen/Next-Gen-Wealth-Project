/**
 * re-value — estimated value of one real home (Money City "Find my home").
 * GET /.netlify/functions/re-value?address=<one line>[&beds=&sqft=]
 *   → { property, valueLow, valueHigh, rentLow, rentHigh, source:'rentcast'|'census-estimate', confidence, explain }
 *   → { error:'not_found' } when the address can't be matched.
 *
 * With RENTCAST_API_KEY: RentCast AVM (automated valuation from nearby sales).
 * Free: Census Geocoder → census tract → ACS neighborhood median value, adjusted to today with FHFA HPI
 * and for the size the player enters. Addresses are not logged or stored here.
 */

const { censusGeocode, makeCache } = require('./lib/geo');
const { estimateHome, rentcastValue } = require('./lib/re-estimate');

const HEADERS = { 'Content-Type': 'application/json', 'Cache-Control': 'private, max-age=300', 'Access-Control-Allow-Origin': '*' };
const _cache = makeCache(60 * 60 * 1000, 300);
const r25 = (v) => Math.round(v / 25) * 25;

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: HEADERS, body: '' };
  const q = event.queryStringParameters || {};
  const address = String(q.address || '').trim().slice(0, 200);
  const beds = Math.round(Number(q.beds)) || 0;
  const sqft = Math.round(Number(q.sqft)) || 0;
  if (address.length < 8 || !/\d/.test(address)) {
    return { statusCode: 200, headers: HEADERS, body: JSON.stringify({ error: 'bad_address' }) };
  }
  const key = [address.toLowerCase(), beds, sqft].join('|');
  const hit = _cache.get(key);
  if (hit) return { statusCode: 200, headers: HEADERS, body: JSON.stringify(hit) };

  const g = await censusGeocode(address);
  if (!g) return { statusCode: 200, headers: HEADERS, body: JSON.stringify({ error: 'not_found' }) };

  const base = { address: g.address, city: g.city, state: g.state, zip: g.zip, lat: g.lat, lng: g.lng, geo: g.geo,
    beds: beds >= 1 && beds <= 10 ? beds : 0, sqft: sqft >= 300 && sqft <= 15000 ? sqft : 0 };

  let out = null;
  const rc = await rentcastValue([g.address, g.city, g.state, g.zip].filter(Boolean).join(', '), base);
  if (rc) {
    out = Object.assign(rc, { source: 'rentcast', confidence: rc.comps >= 3 ? 'high' : 'medium',
      explain: 'RentCast estimated this value by comparing your home to ' + (rc.comps || 'several') + ' similar homes that sold nearby.' });
  } else {
    const told = base.sqft ? 'the size you entered' : 'a typical size for your area';
    const p = estimateHome(Object.assign(base, { source: 'census-estimate' }), { exact: true, spread: base.sqft ? 0.18 : 0.25 });
    out = { property: p, valueLow: p.valueLow, valueHigh: p.valueHigh, rentLow: r25(p.estimatedRent * 0.85), rentHigh: r25(p.estimatedRent * 1.15),
      source: 'census-estimate', confidence: 'low',
      explain: 'We started with what homes in your neighborhood are worth (U.S. Census), updated it to today with the government house price index, and adjusted for ' + told + '. A real appraiser would also look inside the house.' };
  }
  out.property.isHome = true;
  _cache.set(key, out);
  return { statusCode: 200, headers: HEADERS, body: JSON.stringify(out) };
};
