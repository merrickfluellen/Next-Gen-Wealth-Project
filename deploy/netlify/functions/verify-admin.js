/**
 * verify-admin — validate a previously issued admin session token
 * POST { token: string }  (Content-Type: application/json, same-origin only) → 200 { ok: boolean }
 *
 * Requires the same env vars as admin-auth.js (SESSION_SECRET, ADMIN_EMAIL_HASH,
 * ADMIN_PW_HASH, ADMIN_CODE_HASH). The client calls this on page load to restore
 * admin sessions without ever storing hashes in the browser.
 *
 * A token is valid only if: its HMAC-SHA256 verifies (constant-time), it has not
 * expired, it is an admin-session token (purpose-bound key), and its credential
 * fingerprint matches the CURRENT admin hashes (changing credentials revokes it). Tokens from
 * admin-auth live 2 hours.
 * The check itself is lib/session.js isAdminToken() — the single source of truth, also used by
 * admin-users.js.
 */

'use strict';

const C = require('./lib/crypto');
const S = require('./lib/session');
const { withFirewall } = require('./lib/firewall');

async function verifyAdmin(event) {
  if (!C.isJsonRequest(event)) return S.json(415, { ok: false, error: 'Content-Type must be application/json' });
  const token = (event.jsonBody || {}).token;
  if (typeof token !== 'string' || !token || token.length > 2048) return S.json(200, { ok: false });
  let ok = false;
  try { ok = S.isAdminToken(token); } catch (err) {
    console.error('verify-admin: internal error', err && err.message);
  }
  return S.json(200, { ok });
}

exports.handler = withFirewall(verifyAdmin, {
  name: 'verify-admin',
  methods: ['POST'],
  rateLimit: { windowMs: 60 * 1000, max: 30 },
  maxBodyBytes: 4096,
  json: true,
});
