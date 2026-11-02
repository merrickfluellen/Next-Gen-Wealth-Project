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
 * always evaluated (no short-circuit) and combined without branching on which one failed. The
 * credentials are checked FIRST: a request whose three factors all match always gets its token, so
 * other people's failures can never lock the owner out.
 *
 * Brute-force limits (durable, shared by every instance via lib/ratelimit.js; IPv6 per /64):
 *   - firewall: 5 requests per 15 min per IP (successful logins count too);
 *   - 10 failed attempts per hour per IP → further failures from that IP get 429;
 *   - 30 failed attempts per 15 min across ALL IPs → failures get 429 (logged as an alert).
 *   The 429s only ever answer wrong credentials, so they reveal nothing about a guess.
 *
 * Session token (2-hour lifetime): v1.<payload>.<HMAC-SHA256>, payload { sub:'admin', jti, cv, iat, exp }.
 * `cv` fingerprints the current admin hashes (lib/session.js adminCredentialVersion), so changing
 * any admin credential revokes every outstanding session. Rotating SESSION_SECRET does the same.
 * Tokens are checked by verify-admin.js and lib/session.js isAdminToken().
 */

'use strict';

const C = require('./lib/crypto');
const S = require('./lib/session');
const RL = require('./lib/ratelimit');
const { withFirewall } = require('./lib/firewall');

const SESSION_TTL_SECONDS = 2 * 60 * 60; // 2-hour session (the dashboard re-checks it on every load)
const MAX_FIELD = 256;
const MIN_FAIL_MS = 600;                  // every failure takes at least this long
const LIM_FAIL_IP = { windowSec: 60 * 60, max: 10 };
const LIM_FAIL_ALL = { windowSec: 15 * 60, max: 30 };
let lastAlert = 0;                        // log the "under attack" line at most once a minute per instance

const str = (v) => (typeof v === 'string' && v.length > 0 && v.length <= MAX_FIELD ? v : '');

async function adminAuth(event) {
  const started = Date.now();
  if (!C.isJsonRequest(event)) return S.json(415, { ok: false, error: 'Content-Type must be application/json' });

  const env = process.env;
  if (!env.ADMIN_EMAIL_HASH || !env.ADMIN_PW_HASH || !env.ADMIN_CODE_HASH || !env.SESSION_SECRET) {
    console.error('admin-auth: required env vars are not configured');
    return S.json(500, { ok: false, error: 'Server misconfigured' });
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
    const [perIp, all] = await Promise.all([
      RL.hit('admin-fail-ip', RL.ipKey(event.headers), LIM_FAIL_IP),
      RL.hit('admin-fail-all', '*', LIM_FAIL_ALL),
    ]);
    if (!all.ok && Date.now() - lastAlert > 60 * 1000) {
      lastAlert = Date.now();
      console.warn('admin-auth: more than 30 failed admin logins in 15 minutes (all IPs) — check for an attack');
    }
    await S.padTo(started, MIN_FAIL_MS, 200);
    if (!perIp.ok || !all.ok) {
      return S.json(429, { ok: false }, { 'Retry-After': String(Math.max(perIp.retryAfter, all.retryAfter) || 60) });
    }
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
  durable: true,
  maxBodyBytes: 2048,
  json: true,
  inspect: false,   // passwords/codes are only hashed; the signature filter would reject valid ones
});
