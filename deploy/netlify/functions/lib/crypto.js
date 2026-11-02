/**
 * lib/crypto.js — shared cryptography + request-hardening helpers for the
 * auth functions (admin-auth, verify-admin, reset-password, confirm-reset).
 *
 * Uses ONLY Node's built-in `crypto` module. No dependencies.
 *
 * ─── Environment variables ───────────────────────────────────────────────────
 *   SESSION_SECRET   (required, >= 32 characters — shorter values are REJECTED: every
 *                    key operation throws and callers fail closed with 500/503)
 *                    Master secret. Every key used here is derived
 *                    from it with HKDF-SHA256 (one 256-bit key per purpose), so
 *                    the same secret never directly keys two different jobs.
 *                    Use a long random value, e.g.
 *                      node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
 *                    Rotating it invalidates every admin session and every
 *                    in-flight password-reset code (that is the revocation lever).
 *   ADMIN_EMAIL_HASH (admin-auth) hash of 'email::' + email.toLowerCase()
 *   ADMIN_PW_HASH    (admin-auth) hash of 'adminpw::' + password
 *   ADMIN_CODE_HASH  (admin-auth) hash of 'admincode::' + code.toUpperCase()
 *                    The three ADMIN_* hashes may be EITHER the legacy hashPw
 *                    format ('h' + base36 + length, still accepted so existing
 *                    env vars keep working) OR the stronger scrypt format made by:
 *                      node deploy/netlify/functions/lib/crypto.js hash 'adminpw::YourPassword'
 *                    (include the prefix exactly as listed above). Upgrading is
 *                    strongly recommended: the legacy hash is only 32 bits.
 *   SITE_URL         (optional) Public origin of the site, e.g.
 *                    https://nextgenwealthproject.netlify.app. Added to the CORS
 *                    allow-list. Same-origin requests need no CORS at all.
 *   ALLOWED_ORIGINS  (optional) Extra comma-separated origins allowed by CORS
 *                    (e.g. a custom domain or a deploy-preview URL).
 *
 * ─── Formats ─────────────────────────────────────────────────────────────────
 *   encrypt()  →  v1.<iv>.<ciphertext>.<tag>     (AES-256-GCM, base64url parts,
 *                 96-bit random IV, 128-bit tag, purpose bound as AAD)
 *   sign()     →  v1.<payload-json-b64url>.<hmac-sha256-b64url>
 *                 (payload always carries iat/exp; purpose is bound into the MAC)
 *   hashSecret() → scrypt$<N>$<r>$<p>$<salt-b64url>$<hash-b64url>
 */

'use strict';

const crypto = require('crypto');

const HKDF_SALT = Buffer.from('moneyquest/auth/hkdf-salt/v1');
const keyCache = new Map();

const MIN_SECRET_LEN = 32;

/** The HKDF master secret. Throws (callers fail closed) if unset or shorter than 32 characters. */
function masterSecret() {
  const s = process.env.SESSION_SECRET;
  if (!s || typeof s !== 'string') throw new Error('SESSION_SECRET is not set');
  if (s.length < MIN_SECRET_LEN) throw new Error(`SESSION_SECRET must be at least ${MIN_SECRET_LEN} characters`);
  return s;
}

/** True when SESSION_SECRET is usable (set and long enough). Never throws. */
function secretConfigured() {
  try { masterSecret(); return true; } catch { return false; }
}

/** Derive a 32-byte key for one purpose (HKDF-SHA256). Cached per secret+purpose. */
function deriveKey(purpose, secret = masterSecret()) {
  if (!purpose || typeof purpose !== 'string') throw new Error('deriveKey: purpose required');
  const cacheKey = crypto.createHash('sha256').update(secret).digest('hex') + '|' + purpose;
  let k = keyCache.get(cacheKey);
  if (!k) {
    k = Buffer.from(crypto.hkdfSync('sha256', Buffer.from(secret, 'utf8'), HKDF_SALT, Buffer.from('moneyquest:' + purpose), 32));
    keyCache.set(cacheKey, k);
  }
  return k;
}

const b64u = (buf) => Buffer.from(buf).toString('base64url');
const unb64u = (s) => Buffer.from(s, 'base64url');
const B64U_RE = /^[A-Za-z0-9_-]*$/;

// ─── Constant-time comparison ────────────────────────────────────────────────
/**
 * Constant-time string/buffer equality. Both sides are hashed first so the
 * comparison takes the same time regardless of input lengths (timingSafeEqual
 * itself throws on unequal lengths, which would leak length).
 */
function safeEqual(a, b) {
  if (a == null || b == null) return false;
  const ha = crypto.createHash('sha256').update(Buffer.isBuffer(a) ? a : String(a)).digest();
  const hb = crypto.createHash('sha256').update(Buffer.isBuffer(b) ? b : String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// ─── Random values ───────────────────────────────────────────────────────────
/** URL-safe random token, default 256 bits. */
function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

/** Uniform random numeric code with the given number of digits (leading zeros allowed). */
function randomDigits(digits = 6) {
  let out = '';
  for (let i = 0; i < digits; i++) out += String(crypto.randomInt(0, 10));
  return out;
}

// ─── AES-256-GCM ─────────────────────────────────────────────────────────────
/**
 * Encrypt a string (or JSON-serialisable value) with AES-256-GCM.
 * `purpose` selects the HKDF-derived key and is bound as AAD, so a ciphertext
 * made for one purpose cannot be replayed into another.
 */
function encrypt(plaintext, { purpose = 'data', aad = '' } = {}) {
  const data = typeof plaintext === 'string' ? plaintext : JSON.stringify(plaintext);
  const key = deriveKey('enc:' + purpose);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from('v1|' + purpose + '|' + aad, 'utf8'));
  const ct = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return ['v1', b64u(iv), b64u(ct), b64u(tag)].join('.');
}

/** Decrypt a v1 token. Returns the plaintext string, or null on ANY failure (tamper, wrong key, bad format). */
function decrypt(token, { purpose = 'data', aad = '' } = {}) {
  try {
    if (typeof token !== 'string' || token.length > 8192) return null;
    const parts = token.split('.');
    if (parts.length !== 4 || parts[0] !== 'v1' || !parts.slice(1).every(p => B64U_RE.test(p))) return null;
    const iv = unb64u(parts[1]);
    const ct = unb64u(parts[2]);
    const tag = unb64u(parts[3]);
    if (iv.length !== 12 || tag.length !== 16) return null;
    const key = deriveKey('enc:' + purpose);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
    decipher.setAAD(Buffer.from('v1|' + purpose + '|' + aad, 'utf8'));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
  } catch {
    return null;
  }
}

/** encrypt/decrypt for JSON objects. decryptJSON returns null on any failure. */
function encryptJSON(obj, opts) { return encrypt(JSON.stringify(obj), opts); }
function decryptJSON(token, opts) {
  const s = decrypt(token, opts);
  if (s == null) return null;
  try { return JSON.parse(s); } catch { return null; }
}

// ─── HMAC-SHA256 signed tokens ───────────────────────────────────────────────
/** HMAC-SHA256 of `data` with the key for `purpose`. Returns a Buffer. */
function hmac(purpose, data) {
  return crypto.createHmac('sha256', deriveKey('mac:' + purpose)).update(data).digest();
}

/**
 * Sign a JSON payload. Adds iat/exp (seconds). The full 256-bit MAC is kept.
 * Payload is NOT secret (base64url JSON) — put secrets through encrypt() instead.
 */
function sign(payload, { purpose, ttlSeconds }) {
  if (!purpose) throw new Error('sign: purpose required');
  if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) throw new Error('sign: ttlSeconds required');
  const now = Math.floor(Date.now() / 1000);
  const body = b64u(JSON.stringify({ ...payload, iat: now, exp: now + Math.floor(ttlSeconds) }));
  const sig = b64u(hmac(purpose, 'v1.' + purpose + '.' + body));
  return 'v1.' + body + '.' + sig;
}

/** Verify a signed token. Returns the payload, or null if malformed, forged or expired. */
function verify(token, { purpose }) {
  try {
    if (!purpose || typeof token !== 'string' || token.length > 4096) return null;
    const parts = token.split('.');
    if (parts.length !== 3 || parts[0] !== 'v1' || !B64U_RE.test(parts[1]) || !B64U_RE.test(parts[2])) return null;
    const expected = b64u(hmac(purpose, 'v1.' + purpose + '.' + parts[1]));
    if (!safeEqual(parts[2], expected)) return null;
    const payload = JSON.parse(unb64u(parts[1]).toString('utf8'));
    if (!payload || typeof payload !== 'object') return null;
    const now = Math.floor(Date.now() / 1000);
    if (!Number.isFinite(payload.exp) || now >= payload.exp) return null;
    if (Number.isFinite(payload.iat) && payload.iat > now + 60) return null; // issued in the future
    return payload;
  } catch {
    return null;
  }
}

// ─── Password / code hashing ─────────────────────────────────────────────────
/** Legacy DJB2-style hash used by app.html and the original env vars. 32-bit — weak. */
function legacyHash(str) {
  let h = 5381;
  for (let i = 0; i < str.length; i++) h = ((h << 5) + h + str.charCodeAt(i)) >>> 0;
  return 'h' + h.toString(36) + str.length;
}

const SCRYPT = { N: 32768, r: 8, p: 1, keylen: 32 };
// Highest cost verifySecret will run for a STORED hash (we issue N=32768,r=8,p=1). Bigger values
// (e.g. a corrupted/planted row with N=2^20,r=32) would need GBs and OOM-kill the instance.
const SCRYPT_MAX = { N: 131072, r: 16, p: 4 };
const scryptOpts = (N, r, p) => ({ N, r, p, maxmem: 128 * N * r * p * 2 });

/** New-style hash: scrypt with a per-hash 128-bit salt. */
function hashSecret(str) {
  const salt = crypto.randomBytes(16);
  const dk = crypto.scryptSync(String(str), salt, SCRYPT.keylen, scryptOpts(SCRYPT.N, SCRYPT.r, SCRYPT.p));
  return ['scrypt', SCRYPT.N, SCRYPT.r, SCRYPT.p, b64u(salt), b64u(dk)].join('$');
}

/**
 * Check `str` against a stored hash in either format:
 *   scrypt$N$r$p$salt$hash  → scrypt verify (constant-time)
 *   h<base36><len>           → legacy hash, constant-time compare
 * Always returns a boolean; never throws.
 */
function verifySecret(str, stored) {
  try {
    if (typeof str !== 'string' || typeof stored !== 'string' || !stored) return false;
    if (stored.startsWith('scrypt$')) {
      const [, Ns, rs, ps, saltS, hashS] = stored.split('$');
      const N = parseInt(Ns, 10), r = parseInt(rs, 10), p = parseInt(ps, 10);
      if (!(N >= 1024 && N <= SCRYPT_MAX.N && (N & (N - 1)) === 0 &&
            r >= 1 && r <= SCRYPT_MAX.r && p >= 1 && p <= SCRYPT_MAX.p)) return false;
      if (!B64U_RE.test(saltS || '') || !B64U_RE.test(hashS || '')) return false;
      const expected = unb64u(hashS);
      if (expected.length < 16 || expected.length > 64) return false;
      const dk = crypto.scryptSync(str, unb64u(saltS), expected.length, scryptOpts(N, r, p));
      return crypto.timingSafeEqual(dk, expected);
    }
    return safeEqual(legacyHash(str), stored.trim());
  } catch {
    return false;
  }
}

// ─── HTTP hardening helpers ──────────────────────────────────────────────────
const DEFAULT_ORIGINS = ['https://nextgenwealthproject.netlify.app'];

function allowedOrigins() {
  const list = [...DEFAULT_ORIGINS];
  if (process.env.SITE_URL) list.push(process.env.SITE_URL.replace(/\/+$/, ''));
  if (process.env.ALLOWED_ORIGINS) {
    for (const o of process.env.ALLOWED_ORIGINS.split(',')) if (o.trim()) list.push(o.trim().replace(/\/+$/, ''));
  }
  return list;
}

function header(event, name) {
  const h = (event && event.headers) || {};
  const lower = name.toLowerCase();
  for (const k of Object.keys(h)) if (k.toLowerCase() === lower) return h[k];
  return undefined;
}

/**
 * Response headers for auth endpoints: JSON, never cached, no sniffing, and a
 * CORS origin echoed ONLY for allow-listed origins (no wildcard).
 */
function securityHeaders(event) {
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store, max-age=0',
    Pragma: 'no-cache',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    Vary: 'Origin',
  };
  const origin = header(event, 'origin');
  if (origin && allowedOrigins().includes(origin)) {
    headers['Access-Control-Allow-Origin'] = origin;
    headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS';
    headers['Access-Control-Allow-Headers'] = 'Content-Type';
    headers['Access-Control-Max-Age'] = '600';
  }
  return headers;
}

/** Build a JSON response. */
function respond(event, statusCode, body) {
  return { statusCode, headers: securityHeaders(event), body: body === undefined ? '' : JSON.stringify(body) };
}

/**
 * Common method gate: OPTIONS → 204, anything but POST → 405 (with Allow header).
 * Returns a response to send, or null if the request should proceed.
 */
function methodGate(event) {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: securityHeaders(event), body: '' };
  if (event.httpMethod !== 'POST') {
    const r = respond(event, 405, { error: 'Method not allowed' });
    r.headers.Allow = 'POST, OPTIONS';
    return r;
  }
  return null;
}

/** Parse a JSON object body with a size cap. Returns the object, or null if too big / invalid / not an object. */
function parseJsonBody(event, maxBytes = 4096) {
  let raw = event.body || '';
  if (event.isBase64Encoded) { try { raw = Buffer.from(raw, 'base64').toString('utf8'); } catch { return null; } }
  if (Buffer.byteLength(raw, 'utf8') > maxBytes) return null;
  try {
    const obj = JSON.parse(raw || '{}');
    return obj && typeof obj === 'object' && !Array.isArray(obj) ? obj : null;
  } catch { return null; }
}

/**
 * Rate-limit key for the client (lib/ratelimit.js ipKey: Netlify's x-nf-client-connection-ip first;
 * IPv6 reduced to its /64, IPv4-mapped IPv6 to IPv4).
 */
function clientIp(event) {
  return require('./ratelimit').ipKey((event && event.headers) || {});
}

/**
 * Best-effort in-memory throttle (per warm function instance only — NOT a
 * substitute for a durable store; use lib/ratelimit.js hit() for that).
 * Returns true if the caller is over the limit.
 *
 * Memory is bounded (THROTTLE_MAX_KEYS). When full: expired buckets are dropped, then single-hit
 * buckets (oldest first); a bucket with 2+ hits is never evicted, so flooding fresh keys cannot reset
 * a live counter. If still full the new key is throttled (fail closed). Full scans happen at most
 * once a second, so a flood can't make every call O(n).
 */
const THROTTLE_MAX_KEYS = 10000;
const buckets = new Map();
let throttleNextScan = 0;
function throttleRoom(now) {
  if (buckets.size < THROTTLE_MAX_KEYS) return true;
  if (now < throttleNextScan) return false;
  for (const [k, v] of buckets) if (v.until <= now) buckets.delete(k);
  if (buckets.size >= THROTTLE_MAX_KEYS) {
    let toFree = Math.ceil(THROTTLE_MAX_KEYS / 10);
    for (const [k, v] of buckets) {
      if (toFree <= 0) break;
      if (v.count <= 1) { buckets.delete(k); toFree--; }
    }
  }
  if (buckets.size >= THROTTLE_MAX_KEYS) { throttleNextScan = now + 1000; return false; }
  return true;
}
function throttled(key, max, windowMs) {
  const now = Date.now();
  let b = buckets.get(key);
  if (b && b.until <= now) { buckets.delete(key); b = null; }
  if (!b) {
    if (!throttleRoom(now)) return true;
    b = { count: 0, until: now + windowMs };
    buckets.set(key, b);
  }
  if (b.count <= max) b.count++;
  return b.count > max;
}

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

/**
 * True only if the request declares Content-Type: application/json (parameters such as
 * charset allowed). Browsers cannot send this cross-site without a CORS preflight, so
 * requiring it stops "simple" text/plain / form posts from other sites.
 */
function isJsonRequest(event) {
  const ct = String(header(event, 'content-type') || '');
  return /^\s*application\/json\s*(;|$)/i.test(ct);
}

module.exports = {
  MIN_SECRET_LEN,
  secretConfigured,
  deriveKey,
  safeEqual,
  randomToken,
  randomDigits,
  encrypt,
  decrypt,
  encryptJSON,
  decryptJSON,
  hmac,
  sign,
  verify,
  legacyHash,
  hashSecret,
  verifySecret,
  securityHeaders,
  respond,
  methodGate,
  parseJsonBody,
  clientIp,
  throttled,
  THROTTLE_MAX_KEYS,
  sleep,
  isJsonRequest,
};

// CLI: node lib/crypto.js hash '<prefix::value>'  → prints a scrypt hash for an env var
if (require.main === module) {
  const [cmd, value] = process.argv.slice(2);
  if (cmd === 'hash' && value) {
    console.log(hashSecret(value));
  } else {
    console.log("usage: node lib/crypto.js hash 'adminpw::YourPassword'");
    process.exitCode = 1;
  }
}
