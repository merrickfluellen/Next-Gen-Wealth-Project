/**
 * map-config — which map tiles the Money City map should use.
 * GET /.netlify/functions/map-config → { provider, url, subdomains, maxZoom, darkFilter, attribution }
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
 * Only the provider name, a fixed tile URL template per provider (+ the validated key) and display
 * numbers are returned. The app picks the attribution HTML itself from `provider` (Leaflet writes it
 * with innerHTML, so it must never come from the network). `attribution` is still sent for older
 * clients, as PLAIN TEXT (no markup), so even an old client that renders it can't be handed HTML.
 * lib/firewall.js in front (GET/HEAD, Origin allow-list, light per-IP limit); no CORS for other sites.
 */
const { withFirewall } = require('./lib/firewall');

const KEY_RE = /^[A-Za-z0-9_-]{8,128}$/;   // MapTiler / Stadia keys are short alphanumeric (+ dashes) tokens

// 10 min so a rotated/revoked key stops being handed out quickly.
const CACHE_CONTROL = 'public, max-age=600';
const CDN_HEADERS = { 'Content-Type': 'application/json; charset=utf-8', 'Netlify-CDN-Cache-Control': 'public, s-maxage=600' };

// Plain-text attribution (back-compat only; the app uses its own linked HTML per provider).
const ATTR = {
  osm: '© OpenStreetMap contributors',
  maptiler: '© MapTiler © OpenStreetMap contributors',
  stadia: '© Stadia Maps © OpenMapTiles © OpenStreetMap contributors',
};
const OSM = { provider: 'osm', url: 'https://tile.openstreetmap.org/{z}/{x}/{y}.png', subdomains: '', maxZoom: 19, darkFilter: true, attribution: ATTR.osm };

function cleanKey(name) {
  const v = (process.env[name] || '').trim();
  return KEY_RE.test(v) ? v : '';   // malformed value → ignored (falls back), never echoed
}

function buildConfig() {
  const mt = cleanKey('MAPTILER_KEY');
  if (mt) {
    return { provider: 'maptiler', url: 'https://api.maptiler.com/maps/dataviz-dark/256/{z}/{x}/{y}.png?key=' + encodeURIComponent(mt),
      subdomains: '', maxZoom: 19, darkFilter: false, attribution: ATTR.maptiler };
  }
  const st = cleanKey('STADIA_API_KEY');
  if (st) {
    return { provider: 'stadia', url: 'https://tiles.stadiamaps.com/tiles/alidade_smooth_dark/{z}/{x}/{y}{r}.png?api_key=' + encodeURIComponent(st),
      subdomains: '', maxZoom: 20, darkFilter: false, attribution: ATTR.stadia };
  }
  return OSM;
}

// cacheControl applies to the 200 only; firewall errors (405/403/429) are always no-store.
exports.handler = withFirewall(async () => ({ statusCode: 200, headers: CDN_HEADERS, body: JSON.stringify(buildConfig()) }), {
  name: 'map-config',
  methods: ['GET', 'HEAD'],
  rateLimit: { windowMs: 60 * 1000, max: 30 },
  json: false,
  cacheControl: CACHE_CONTROL,
});
