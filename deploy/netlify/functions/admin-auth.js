/**
 * admin-auth — server-side admin credential check (three factors, ALL required)
 * POST { email, password, adminCode }   (Content-Type: application/json, same-origin only)
 *   → 200 { ok: true, token } | 401 { ok: false } | 429 { ok: false } | 415/400/403 { ok: false }
 *
 * Admin credential hashes are read from Netlify environment variables
 * (Netlify dashboard → Site configuration → Environment variables):
 *   ADMIN_EMAIL_HASH   — hash of 'email::' + adminEmail.toLowerCase()
 *   ADMIN_PW_HASH      — hash of 'adminpw::' + password
 *   ADMIN_CODE_HASH    — hash of 'admincode::' + code.toUpperCase()
 *   SESSION_SECRET     — long random string; HKDF-derived keys sign the session tokens
 * Each hash may be the legacy hashPw format or a scrypt hash from
 *   node deploy/netlify/functions/lib/crypto.js hash 'adminpw::YourPassword'
 * Use scrypt: the legacy format is only 32 bits (see lib/crypto.js).
 *
 * Login succeeds only if email AND password AND admin code all match. All three checks are
 * always evaluated (no short-circuit) and combined without branching on which one failed.
 *
 * Brute-force limits (best-effort, per warm instance — see lib/firewall.js):
 *   - firewall: 5 requests per 15 min per IP (successful logins count too);
 *   - 30 failed attempts per 15 min across ALL IPs locks admin login on that instance.
 *
 * Session token: v1.<payload>.<HMAC-SHA256>, payload { sub:'admin', jti, cv, iat, exp }.
 * `cv` fingerprints the current admin hashes (lib/session.js adminCredentialVersion), so changing
 * any admin credential revokes every outstanding session. Rotating SESSION_SECRET does the same.
 * Tokens are checked by verify-admin.js and lib/session.js isAdminToken().
 */

'use strict';

const C = require('./lib/crypto');
const S = require('./lib/session');
const { withFirewall, createRateLimiter } = require('./lib/firewall');

const SESSION_TTL_SECONDS = 8 * 60 * 60; // 8-hour session
const MAX_FIELD = 256;
const MIN_FAIL_MS = 600;                  // every failure takes at least this long
const globalFails = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 30 });
let lockedUntil = 0;

const str = (v) => (typeof v === 'string' && v.length > 0 && v.length <= MAX_FIELD ? v : '');

async function adminAuth(event) {
  const started = Date.now();
  if (!C.isJsonRequest(event)) return S.json(415, { ok: false, error: 'Content-Type must be application/json' });

  const env = process.env;
  if (!env.ADMIN_EMAIL_HASH || !env.ADMIN_PW_HASH || !env.ADMIN_CODE_HASH || !env.SESSION_SECRET) {
    console.error('admin-auth: required env vars are not configured');
    return S.json(500, { ok: false, error: 'Server misconfigured' });
  }

  if (lockedUntil > Date.now()) {
    await S.padTo(started, MIN_FAIL_MS, 200);
    return S.json(429, { ok: false });
  }

  const body = event.jsonBody || {};
  const email = str(body.email).trim().toLowerCase();
  const password = str(body.password);
  const adminCode = str(body.adminCode).trim().toUpperCase();

  // Evaluate every check (no short-circuit). A missing field is hashed as '\0' so the work is the
  // same, and is then forced to false.
  const emailMatch = C.verifySecret('email::' + (email || '\u0000'), env.ADMIN_EMAIL_HASH) && email !== '';
  const pwMatch    = C.verifySecret('adminpw::' + (password || '\u0000'), env.ADMIN_PW_HASH) && password !== '';
  const codeMatch  = C.verifySecret('admincode::' + (adminCode || '\u0000'), env.ADMIN_CODE_HASH) && adminCode !== '';
  const ok = (Number(emailMatch) & Number(pwMatch) & Number(codeMatch)) === 1;

  if (!ok) {
    if (!globalFails('all').ok) {
      lockedUntil = Date.now() + 15 * 60 * 1000;
      console.warn('admin-auth: too many failed admin logins; admin login locked for 15 minutes on this instance');
    }
    await S.padTo(started, MIN_FAIL_MS, 200);
    return S.json(401, { ok: false });
  }

  const token = C.sign(
    { sub: 'admin', jti: C.randomToken(16), cv: S.adminCredentialVersion(env) },
    { purpose: 'admin-session', ttlSeconds: SESSION_TTL_SECONDS }
  );
  return S.json(200, { ok: true, token });
}

exports.handler = withFirewall(adminAuth, {
  name: 'admin-auth',
  methods: ['POST'],
  rateLimit: { windowMs: 15 * 60 * 1000, max: 5 },
  maxBodyBytes: 2048,
  json: true,
  inspect: false,   // passwords/codes are only hashed; the signature filter would reject valid ones
});
