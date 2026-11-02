/**
 * lib/legacy-hash.js — access-code hashing for auth-signup (and scripts/generate-access-codes.js).
 *
 * Two kinds of access code are accepted:
 *
 *  v2 (new)  Random codes made by scripts/generate-access-codes.js. Only
 *            HMAC-SHA256(CODE_PEPPER, normalizeV2(code)) is stored, in the Supabase table
 *            `access_codes` (code_hash, free). Without CODE_PEPPER the stored hashes are useless
 *            to an attacker, and the codes have ~59 bits of entropy.
 *
 *  legacy    The original 151 codes, stored as the 32-bit djb2 hash of 'code::' + CODE.
 *            These hashes are PUBLIC (git history) and can be collided offline in seconds
 *            (see the audit, C3), so they are only accepted while env LEGACY_CODES is not 'off',
 *            and every legacy hash can be redeemed exactly ONCE in total (code_redemptions has
 *            UNIQUE(code_hash)), which caps the damage of forgery at the size of this list.
 *            (validate-code.js, which held a copy, has been removed.)
 */
'use strict';

const crypto = require('crypto');
const { legacyHash } = require('./crypto');

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

const VALID_SET = new Set(VALID_CODE_HASHES);
const FREE_SET = new Set(FREE_CODE_HASHES);
const MAX_CODE_LEN = 64;
const PRINTABLE_RE = /^[\x20-\x7E]+$/;

/** Legacy normalisation, identical to the old client (and the retired validate-code.js): NFKC + trim + uppercase. */
function normalizeLegacy(code) {
  if (typeof code !== 'string' || code.length > MAX_CODE_LEN * 4) return null;
  const n = code.normalize('NFKC').trim().toUpperCase();
  if (!n || n.length > MAX_CODE_LEN || !PRINTABLE_RE.test(n)) return null;
  return n;
}

/**
 * Look a code up in the legacy list. Returns { hash, free } or null.
 * `hash` is namespaced ('legacy:' + djb2) for the code_redemptions table.
 * (Set lookup is fine here: the list itself is public, so timing reveals nothing secret.)
 */
function legacyLookup(code) {
  const n = normalizeLegacy(code);
  if (!n) return null;
  const h = legacyHash('code::' + n);
  if (!VALID_SET.has(h)) return null;
  return { hash: 'legacy:' + h, free: FREE_SET.has(h) };
}

function legacyEnabled() {
  return String(process.env.LEGACY_CODES || '').trim().toLowerCase() !== 'off';
}

// ─── v2 codes ────────────────────────────────────────────────────────────────
/** Alphabet without look-alikes (no 0/O, 1/I/L). 31 symbols → 12 chars ≈ 59.4 bits. */
const V2_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const V2_LEN = 12;

/** NFKC, uppercase, drop spaces and dashes (codes are printed as XXXX-XXXX-XXXX). */
function normalizeV2(code) {
  if (typeof code !== 'string' || code.length > 256) return null;
  const n = code.normalize('NFKC').toUpperCase().replace(/[\s\-‐-―]/g, '');
  if (n.length !== V2_LEN) return null;
  for (const ch of n) if (!V2_ALPHABET.includes(ch)) return null;
  return n;
}

function pepper() {
  const p = process.env.CODE_PEPPER;
  return typeof p === 'string' && p.length >= 32 ? p : null;
}

/** Hex HMAC-SHA256(CODE_PEPPER, normalized code) — the value stored in access_codes.code_hash. */
function v2Hash(normalized, pep = pepper()) {
  if (!pep) throw new Error('CODE_PEPPER is not set (min 32 chars)');
  return crypto.createHmac('sha256', pep).update(normalized, 'utf8').digest('hex');
}

module.exports = {
  VALID_CODE_HASHES, FREE_CODE_HASHES, normalizeLegacy, legacyLookup, legacyEnabled,
  V2_ALPHABET, V2_LEN, normalizeV2, pepper, v2Hash,
};
