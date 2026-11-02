/**
 * admin-auth — server-side admin credential check
 * POST { email, password, adminCode } → 200 { ok: true, token } | 401 { ok: false } | 429 { ok: false }
 *
 * Admin credential hashes are read from Netlify environment variables
 * (Netlify dashboard → Site configuration → Environment variables):
 *   ADMIN_EMAIL_HASH   — hash of 'email::' + adminEmail.toLowerCase()
 *   ADMIN_PW_HASH      — hash of 'adminpw::' + password
 *   ADMIN_CODE_HASH    — hash of 'admincode::' + code.toUpperCase()
 *   SESSION_SECRET     — long random string; HKDF-derived keys sign the session tokens
 * Each hash may be the legacy hashPw format or a scrypt hash from
 *   node deploy/netlify/functions/lib/crypto.js hash 'adminpw::YourPassword'
 * (see lib/crypto.js for details).
 *
 * Session token: v1.<payload>.<HMAC-SHA256>, payload { sub:'admin', jti, cv, iat, exp }.
 * `cv` fingerprints the current admin hashes, so changing any admin credential
 * revokes every outstanding session. Rotating SESSION_SECRET does the same.
 */

'use strict';

const C = require('./lib/crypto');

const SESSION_TTL_SECONDS = 8 * 60 * 60; // 8-hour session
const MAX_FIELD = 256;

/** Fingerprint of the configured admin credentials (bound into every session token).
 *  Must stay identical to credentialVersion() in verify-admin.js. */
function credentialVersion(env) {
  return C.hmac('admin-cred-version', [env.ADMIN_EMAIL_HASH, env.ADMIN_PW_HASH, env.ADMIN_CODE_HASH].join('\n'))
    .toString('base64url').slice(0, 22);
}

const str = (v) => (typeof v === 'string' && v.length > 0 && v.length <= MAX_FIELD ? v : '');

exports.handler = async (event) => {
  const gate = C.methodGate(event);
  if (gate) return gate;

  const env = process.env;
  if (!env.ADMIN_EMAIL_HASH || !env.ADMIN_PW_HASH || !env.ADMIN_CODE_HASH || !env.SESSION_SECRET) {
    console.error('admin-auth: required env vars are not configured');
    return C.respond(event, 500, { ok: false, error: 'Server misconfigured' });
  }

  // Best-effort server-side brute-force throttle (per IP, per warm instance).
  if (C.throttled('admin-auth:' + C.clientIp(event), 10, 15 * 60 * 1000)) {
    await C.sleep(400);
    return C.respond(event, 429, { ok: false });
  }

  const body = C.parseJsonBody(event, 2048);
  if (!body) return C.respond(event, 400, { ok: false, error: 'Invalid request' });

  const email = str(body.email);
  const password = str(body.password);
  const adminCode = str(body.adminCode);

  try {
    // Evaluate every check (no short-circuit) so timing doesn't reveal which field matched.
    const emailMatch = C.verifySecret('email::' + (email ? email.trim().toLowerCase() : '\u0000'), env.ADMIN_EMAIL_HASH) && !!email;
    const pwMatch    = C.verifySecret('adminpw::' + (password || '\u0000'), env.ADMIN_PW_HASH) && !!password;
    const codeMatch  = C.verifySecret('admincode::' + (adminCode ? adminCode.trim().toUpperCase() : '\u0000'), env.ADMIN_CODE_HASH) && !!adminCode;

    const ok = (emailMatch && pwMatch) || codeMatch;

    if (!ok) {
      // Small delay + jitter to slow brute force even if the throttle is bypassed
      await C.sleep(400 + Math.floor(Math.random() * 200));
      return C.respond(event, 401, { ok: false });
    }

    const token = C.sign(
      { sub: 'admin', jti: C.randomToken(16), cv: credentialVersion(env) },
      { purpose: 'admin-session', ttlSeconds: SESSION_TTL_SECONDS }
    );
    return C.respond(event, 200, { ok: true, token });
  } catch (err) {
    console.error('admin-auth: internal error', err && err.message);
    return C.respond(event, 500, { ok: false, error: 'Server error' });
  }
};

