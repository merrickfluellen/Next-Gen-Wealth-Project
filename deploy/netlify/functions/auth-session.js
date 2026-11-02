/**
 * auth-session — who am I?
 *
 * GET  (header  Authorization: Bearer <token>)
 *   200 { user: { name, email, free_access }, token? }   `token` is present when the session is
 *                                                       more than 7 days old: a fresh 30-day token
 *                                                       the client should store in place of the old one
 *   401 { error: 'Not signed in' }                      missing / forged / expired token, deleted
 *                                                       user, or password changed since sign-in
 *   503 { error }                                       database unavailable
 *
 * A fresh token is only ever issued after lib/session.js authenticate() has re-read the user row and
 * matched the token's `ver` against the CURRENT pw_hash, so a token from before a password change /
 * reset, or of a deleted account, can never be refreshed. The new token carries the same binding.
 *
 * Env: SESSION_SECRET, SUPA_SERVICE_KEY, SUPABASE_URL (optional).
 */
'use strict';

const S = require('./lib/session');
const { withFirewall } = require('./lib/firewall');

async function session(event) {
  if (!S.configured()) return S.json(503, { error: 'Service unavailable' });
  const a = await S.authenticate(event);
  if (a.error) return S.json(a.status, { error: a.error });
  const body = { user: S.publicUser(a.user) };
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isFinite(a.payload.iat) || now - a.payload.iat > S.SESSION_REFRESH_AFTER) body.token = S.issueSession(a.user);
  return S.json(200, body);
}

exports.handler = withFirewall(session, {
  name: 'auth-session',
  methods: ['GET'],
  rateLimit: { windowMs: 60 * 1000, max: 120 },
  maxBodyBytes: 0,
});
