/**
 * re-value — estimated value of one real home (Money City "Find my home").
 * POST /.netlify/functions/re-value  body: { address:'<one line>', beds?, sqft? }      (what the app sends)
 * GET  /.netlify/functions/re-value?address=<one line>[&beds=&sqft=]                  (older clients)
 *   → { property, valueLow, valueHigh, rentLow, rentHigh, source:'rentcast'|'census-estimate', confidence, explain }
 *   → { error:'bad_address' } for input that can't be an address (no upstream call is made)
 *   → { error:'not_found' } when the address can't be matched.
 *   → 429 when one client asks too often (lib/firewall.js, durable across instances).
 *
 * POST keeps the street address out of URLs (and so out of request logs, proxies and history).
 * Every response is Cache-Control: no-store, so the answer never lands in a browser or CDN cache.
 *
 * With RENTCAST_API_KEY: RentCast AVM (automated valuation from nearby sales) — paid, so it is only called
 * after the free Census geocoder has matched a real address, ONE paid call per address (value AVM; the rent
 * comes from the Census estimate), keyed by the normalised Census-matched address, and every paid call must
 * pass a per-client cap (10/hour, durable, fails closed) and the site-wide hourly budget (lib/re-estimate.js).
 * Free: Census Geocoder → census tract → ACS neighborhood median value, adjusted to today with FHFA HPI
 * and for the size the player enters.
 *
 * Privacy: addresses are never logged or written anywhere. In-memory caches holding them expire after
 * 30 min (this file), 20 min (Census match, lib/geo.js) and 60 min (RentCast answer, lib/re-estimate.js).
 */

const { withFirewall } = require('./lib/firewall');
const RL = require('./lib/ratelimit');
const { censusGeocode, makeCache, normQuery, str } = require('./lib/geo');
const { estimateHome, rentcastValue, hasRentcast } = require('./lib/re-estimate');

const RESULT_TTL_MS = 30 * 60 * 1000;
const _cache = makeCache(RESULT_TTL_MS, 300);
const PAID_PER_CLIENT_HOUR = 10;                             // RentCast lookups per client per hour
const DEADLINE_MS = 9000;                                    // stay under Netlify's 10 s limit
const r25 = (v) => Math.round(v / 25) * 25;
// Letters (any language), digits, spaces and the punctuation real addresses use
const ADDRESS_RE = /^[\p{L}\p{M}0-9 ,.#'\-\/&()]+$/u;

const json = (status, obj) => ({ statusCode: status, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(obj) });

// Whole number inside [lo, hi], else 0 ("not given"). Only strings / numbers are read.
function intIn(v, lo, hi) {
  const s = str(v).trim().replace(/,/g, '');
  if (!s || s.length > 12 || !/^\d{1,6}(\.\d{1,3})?$/.test(s)) return 0;
  const n = Math.round(Number(s));
  return n >= lo && n <= hi ? n : 0;
}

async function handle(event) {
  const t0 = Date.now();
  try {
    const q = event.httpMethod === 'POST'
      ? (event.jsonBody || {})
      : (event.queryStringParameters || {});
    const raw = str(q.address);
    if (raw.length > 300) return json(200, { error: 'bad_address' });
    const address = raw.replace(/\s+/g, ' ').trim().slice(0, 200);
    if (address.length < 8 || !/\d/.test(address) || !/\p{L}/u.test(address) || !ADDRESS_RE.test(address)) {
      return json(200, { error: 'bad_address' });
    }
    const beds = intIn(q.beds, 1, 10);
    const sqft = intIn(q.sqft, 300, 15000);

    const key = [normQuery(address), beds, sqft].join('|');
    const hit = _cache.get(key);
    if (hit) return json(200, hit);

    const g = await censusGeocode(address, 6000);
    if (!g) return json(200, { error: 'not_found' });

    const base = { address: g.address, city: g.city, state: g.state, zip: g.zip, lat: g.lat, lng: g.lng, geo: g.geo, beds, sqft };

    let out = null;
    const left = DEADLINE_MS - (Date.now() - t0);
    if (hasRentcast() && left > 1500) {
      const ip = RL.ipKey(event.headers);
      // Counted only when the answer isn't cached (a real, billable call); no DB → no paid call.
      const gate = async () => (await RL.hit('rc-value', ip, { windowSec: 3600, max: PAID_PER_CLIENT_HOUR, failClosed: true })).ok;
      const rc = await rentcastValue([g.address, g.city, g.state, g.zip].filter(Boolean).join(', '), base, Math.min(7000, left - 300), { gate });
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
    return json(200, out);
  } catch {
    return json(200, { error: 'not_found' });
  }
}

// Firewall first: method/Origin checks and the per-client limit (durable, across instances) run before
// anything is parsed or looked up; the POST body is capped at 2 KB. Responses are always no-store.
exports.handler = withFirewall(handle, {
  name: 're-value',
  methods: ['GET', 'POST'],
  rateLimit: { windowMs: 10 * 60 * 1000, max: 30 },          // lookups per client per 10 min
  durable: true,
  maxBodyBytes: 2048,
  allowedOrigins: ['https://nextgenwealthproject.netlify.app'],
});
