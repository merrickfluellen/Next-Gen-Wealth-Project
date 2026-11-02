/**
 * map-config — which map tiles the Money City map should use.
 * GET /.netlify/functions/map-config → { url, attribution, subdomains, maxZoom, provider, darkFilter }
 *
 * Set ONE of these in Netlify → Site configuration → Environment variables:
 *   MAPTILER_KEY     (maptiler.com → Account → API keys)        → dark "dataviz" map
 *   STADIA_API_KEY   (client.stadiamaps.com → your property → API key) → "Alidade Smooth Dark" map
 * Map tile keys always end up in the browser (that's how tiles load), so also lock the key to your
 * domain (nextgenwealthproject.netlify.app) in the provider's dashboard. With no key, the app uses
 * standard OpenStreetMap tiles with a dark filter (fine for light use, per the OSM tile policy).
 */
const HEADERS = { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=3600', 'Access-Control-Allow-Origin': '*' };

exports.handler = async () => {
  const mt = (process.env.MAPTILER_KEY || '').trim();
  const st = (process.env.STADIA_API_KEY || '').trim();
  let cfg;
  if (mt) {
    cfg = { provider: 'maptiler', url: 'https://api.maptiler.com/maps/dataviz-dark/256/{z}/{x}/{y}.png?key=' + encodeURIComponent(mt),
      attribution: '© <a href="https://www.maptiler.com/copyright/">MapTiler</a> © <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors', subdomains: '', maxZoom: 19, darkFilter: false };
  } else if (st) {
    cfg = { provider: 'stadia', url: 'https://tiles.stadiamaps.com/tiles/alidade_smooth_dark/{z}/{x}/{y}{r}.png?api_key=' + encodeURIComponent(st),
      attribution: '© <a href="https://stadiamaps.com/">Stadia Maps</a> © <a href="https://openmaptiles.org/">OpenMapTiles</a> © <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors', subdomains: '', maxZoom: 20, darkFilter: false };
  } else {
    cfg = { provider: 'osm', url: 'https://tile.openstreetmap.org/{z}/{x}/{y}.png', attribution: '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors', subdomains: '', maxZoom: 19, darkFilter: true };
  }
  return { statusCode: 200, headers: HEADERS, body: JSON.stringify(cfg) };
};
