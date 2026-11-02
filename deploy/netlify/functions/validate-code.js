/**
 * validate-code — server-side access code check
 * POST { code: string } → { valid: boolean, free: boolean }
 *
 * The hash arrays live here on the server so they are never sent to the browser.
 *
 * Hardening (see lib/firewall.js):
 *   - POST only, origin allowlist, 1 KB body cap, JSON required.
 *   - Strict per-IP rate limit (best-effort per warm instance) against code brute-forcing.
 *   - Constant-time comparison against EVERY stored hash (no early exit → no timing signal).
 *   - Any malformed/oversized code gets the same { valid:false, free:false } answer as a wrong
 *     code, so responses never hint at the code format. Codes are never logged.
 */
const crypto = require('crypto');
const { withFirewall } = require('./lib/firewall');

const MAX_CODE_LEN = 64;
// Printable ASCII only — rejects control chars / exotic Unicode without guessing the code alphabet.
const CODE_RE = /^[\x20-\x7E]+$/;

const VALID_CODE_HASHES = [
  "h10o44zi25","h1sazc2l22","h1iagmip22","hzp045922","h1qifltf22","h1eznbf822",
  "h1tquonf22","h12pxxk122","h1bx1cil22","h5yw35y22","h3h1znb22","h1csptyu22",
  "hcc6rpd22","h1fv9xzz22","hh3x5c522","hs34qhl22","h1sh49mr22","hh8uprg22",
  "h6ek1o922","h1cm4egc22","h1d1ctij22","hbubnx22","hbw38z522","h1nkhj3u22",
  "hv3s3gj22","h1wzuqik22","hi64vly22","hlfj2g822","hvtvrcw22","hh0k3u422",
  "h1oneqz222","hb6szt022","h1eb9txw22","hq9acbi22","hvl5y1f22","hcvi6im22",
  "hkq6egm22","h3kkqnp22","h162x5z422","hpd8e4b22","hia97ww22","h16abb5j22",
  "hhs2e7m22","h11xvod022","h1350e8r22","hu2f2me22","h14u3fv022","hx3770b22",
  "hxwd1zd22","h1dzppmw22","ht9ypg722","hrud5ec20","hf6zm1z20","h13jlrd220",
  "h1p5mpmt20","h1jy6dyv20","hxxpnmc20","h1ebrlcd20","hk619fv20","hgxhh2y20",
  "h1yy6lnn20","h1bj3fh420","hc26o5j20","h4wyzfc20","hn4378p20","hhpgz3e20",
  "hlu78lb20","hfy4wa020","h16ut24z20","h1gud3xf20","h1vgkt7y20","haln9f720",
  "hcnioa520","h1llwbdm20","h10milqp20","h1rupjbw20","hc563be20","ho8u2zr20",
  "hti2fso20","hs6c6ks20","hkvq99z20","h16j11a920","hzo2iau20","h932t0m20",
  "h1ryt7uh20","h7m6etn20","h1eivcpl20","h2a8szq20","h37vz6720","h1gfnxco20",
  "h12j6mjb20","h8s2ou620","h17ea70q20","h2jha0920","hlut2x820","h10ahit920",
  "h189pofe20","h1sfikp220","h1glc63a20","hhy3zox20","hudrhrl20","h1aivr6v20",
  "h97477920","h15xo7uv20","h1bi3ra720","hcc3yus20","h1czsim620","h1ct1i120",
  "h11o0tqq20","h1ro1po720","hdcasom20","h1k5myzw20","h1j1czfz20","h97fcjr20",
  "h1mb646x20","hype80a20","h1tjm3ul20","h1u6obm420","h1bsgnfw20","hj6op2h20",
  "hsey24420","hxdr4ji20","h5m7u5u20","h9ijhez20","hxa3qua20","h1hho5320",
  "hgsywer20","h40ao6520","hbrcls520","h1uxscaw20","hmi9dhs20","h573v8520",
  "h1jzy07d20","h1iyqgnx20","h1lyoikf20","h88t35d20","h1smjzge20","hyh3hmx20",
  "h3nxtv320","hds0hfv20","h1148hxx20","h1vt7huv20","h1p72n3m20","hjhpjia20",
  "h1n1gsag20","h104n9wa20","h69nyt720","h74rmnq20","h16hvu0e20","h1rk5kyy20",
  "h1umilvv20",
];

const FREE_CODE_HASHES = [
  "h1sazc2l22",
  "h1iagmip22",
  "hzp045922",
  "h1qifltf22",
  "h1eznbf822",
  "h1tquonf22",
  "h12pxxk122",
];

/** Same djb2-style hash used client-side for user passwords. */
function hashPw(str) {
  let h = 5381;
  for (let i = 0; i < str.length; i++) h = ((h << 5) + h + str.charCodeAt(i)) >>> 0;
  return 'h' + h.toString(36) + str.length;
}

/** Fixed-width buffer so timingSafeEqual always compares equal lengths. */
function toBuf(str) {
  const b = Buffer.alloc(MAX_CODE_LEN);
  b.write(str, 'utf8');
  return b;
}
const VALID_BUFS = VALID_CODE_HASHES.map(toBuf);
const FREE_BUFS  = FREE_CODE_HASHES.map(toBuf);

/** True if `buf` equals any entry; always scans the whole list in constant time per entry. */
function inList(buf, list) {
  let hit = 0;
  for (const b of list) hit |= crypto.timingSafeEqual(buf, b) ? 1 : 0;
  return hit === 1;
}

/** NFKC + trim + uppercase, matching the client's `code.trim().toUpperCase()` for ASCII codes. */
function normalizeCode(code) {
  if (typeof code !== 'string' || code.length > MAX_CODE_LEN * 4) return null;
  const n = code.normalize('NFKC').trim().toUpperCase();
  if (!n || n.length > MAX_CODE_LEN || !CODE_RE.test(n)) return null;
  return n;
}

async function validateCode(event) {
  const { code } = event.jsonBody || {};
  if (typeof code !== 'string' || code.trim().length === 0) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Missing code' }) };
  }

  const normalized = normalizeCode(code);
  // Hash even when the format is invalid so timing does not reveal the format check.
  const hash = toBuf(hashPw('code::' + (normalized || '\u0000invalid')));
  const valid = normalized !== null && inList(hash, VALID_BUFS);
  const free  = valid && inList(hash, FREE_BUFS);

  return { statusCode: 200, body: JSON.stringify({ valid, free }) };
}

exports.handler = withFirewall(validateCode, {
  name: 'validate-code',
  methods: ['POST'],
  // A real student enters a code once or twice; 10 tries / 15 min per IP stops brute-force loops.
  rateLimit: { windowMs: 15 * 60 * 1000, max: 10 },
  maxBodyBytes: 1024,
  json: true,
});
