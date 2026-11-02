/**
 * map-config — which map tiles the Money City map should use.
 * GET /.netlify/functions/map-config → { url, attribution, subdomains, maxZoom, provider, darkFilter }
 *
 * Set ONE of these in Netlify → Site configuration → Environment variables:
 *   MAPTILER_KEY     (maptiler.com → Account → API keys)        → dark "dataviz" map
 *   STADIA_API_KEY   (client.stadiamaps.com → your property → API key) → "Alidade Smooth Dark" map
 *
 * SECURITY: a raster-tile key is necessarily public — Leaflet puts it in every <img> tile URL, so anyone
 * using the site can read it. This endpoint only avoids hard-coding it in the repo. The real protection
 * MUST be configured at the provider:
 *   - MapTiler: Account → API keys → restrict the key to "Allowed HTTP origins" = nextgenwealthproject.netlify.app
 *   - Stadia:   prefer domain-based auth (add the domain to your property) and leave STADIA_API_KEY unset
 *               if possible; otherwise restrict the key to the domain.
 * Use a dedicated tiles-only key with no other scopes. With no key, the app uses standard OpenStreetMap
 * tiles with a dark filter (fine for light use, per the OSM tile policy).
 *
 * Only the tile URL template + display fields are returned. No CORS header is sent: the app calls this
 * same-origin, so other sites can't read the config cross-origin from a browser.
 */
const KEY_RE = /^[A-Za-z0-9_-]{8,128}$/;   // MapTiler / Stadia keys are short alphanumeric (+ dashes) tokens

const BASE_HEADERS = { 'Content-Type': 'application/json; charset=utf-8', 'X-Content-Type-Options': 'nosniff' };
// 10 min so a rotated/revoked key stops being handed out quickly.
const CACHE_HEADERS = { 'Cache-Control': 'public, max-age=600', 'Netlify-CDN-Cache-Control': 'public, s-maxage=600' };

const OSM = { provider: 'osm', url: 'https://tile.openstreetmap.org/{z}/{x}/{y}.png',
  attribution: '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors', subdomains: '', maxZoom: 19, darkFilter: true };

function cleanKey(name) {
  const v = (process.env[name] || '').trim();
  return KEY_RE.test(v) ? v : '';   // malformed value → ignored (falls back), never echoed
}

function buildConfig() {
  const mt = cleanKey('MAPTILER_KEY');
  if (mt) {
    return { provider: 'maptiler', url: 'https://api.maptiler.com/maps/dataviz-dark/256/{z}/{x}/{y}.png?key=' + encodeURIComponent(mt),
      attribution: '© <a href="https://www.maptiler.com/copyright/">MapTiler</a> © <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors', subdomains: '', maxZoom: 19, darkFilter: false };
  }
  const st = cleanKey('STADIA_API_KEY');
  if (st) {
    return { provider: 'stadia', url: 'https://tiles.stadiamaps.com/tiles/alidade_smooth_dark/{z}/{x}/{y}{r}.png?api_key=' + encodeURIComponent(st),
      attribution: '© <a href="https://stadiamaps.com/">Stadia Maps</a> © <a href="https://openmaptiles.org/">OpenMapTiles</a> © <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors', subdomains: '', maxZoom: 20, darkFilter: false };
  }
  return OSM;
}

exports.handler = async (event) => {
  const method = ((event && event.httpMethod) || 'GET').toUpperCase();
  if (method !== 'GET' && method !== 'HEAD') {
    return { statusCode: 405, headers: { ...BASE_HEADERS, 'Cache-Control': 'no-store', Allow: 'GET, HEAD' }, body: JSON.stringify({ error: 'Method not allowed' }) };
  }
  return { statusCode: 200, headers: { ...BASE_HEADERS, ...CACHE_HEADERS }, body: JSON.stringify(buildConfig()) };
};
