/**
 * verify-admin — validate a previously issued admin session token
 * POST { token: string } → 200 { ok: boolean }
 *
 * Requires the same env vars as admin-auth.js (SESSION_SECRET, ADMIN_EMAIL_HASH,
 * ADMIN_PW_HASH, ADMIN_CODE_HASH). The client calls this on page load to restore
 * admin sessions without ever storing hashes in the browser.
 *
 * A token is valid only if: its HMAC-SHA256 verifies (constant-time), it has not
 * expired, it is an admin-session token (purpose-bound key), and its credential
 * fingerprint matches the CURRENT admin hashes (changing credentials revokes it).
 * Tokens in the pre-v1 "<expires>.<sig>" format are rejected (forces one re-login).
 */

'use strict';

const C = require('./lib/crypto');

/** Must stay identical to credentialVersion() in admin-auth.js. */
function credentialVersion(env) {
  return C.hmac('admin-cred-version', [env.ADMIN_EMAIL_HASH, env.ADMIN_PW_HASH, env.ADMIN_CODE_HASH].join('\n'))
    .toString('base64url').slice(0, 22);
}

exports.handler = async (event) => {
  const gate = C.methodGate(event);
  if (gate) return gate;

  const body = C.parseJsonBody(event, 4096);
  if (!body) return C.respond(event, 400, { ok: false, error: 'Invalid request' });

  const token = body.token;
  const env = process.env;
  // Fail closed on anything missing or malformed.
  if (typeof token !== 'string' || !token || token.length > 2048 ||
      !env.SESSION_SECRET || !env.ADMIN_EMAIL_HASH || !env.ADMIN_PW_HASH || !env.ADMIN_CODE_HASH) {
    return C.respond(event, 200, { ok: false });
  }

  try {
    const payload = C.verify(token, { purpose: 'admin-session' });
    const ok = !!payload &&
      payload.sub === 'admin' &&
      typeof payload.cv === 'string' &&
      C.safeEqual(payload.cv, credentialVersion(env));
    return C.respond(event, 200, { ok });
  } catch (err) {
    console.error('verify-admin: internal error', err && err.message);
    return C.respond(event, 200, { ok: false });
  }
};
