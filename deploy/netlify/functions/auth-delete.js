/**
 * auth-delete — "Delete my account": permanently delete the signed-in user's account and data.
 *
 * POST { confirm: true }   (Content-Type: application/json)
 *   headers: Authorization: Bearer <user session token>
 *            X-Expected-User: <email>   optional; 409 if it is not the token's account
 *   200 { ok: true }                    deleted (users, progress and password_resets rows, rate-limit
 *                                       counters keyed by the email; the redeemed access code stays
 *                                       burned but its email is blanked) — see public.delete_account
 *                                       in supabase/001_security.sql (A10)
 *   400 { error }                       body is not { confirm: true }
 *   401 { error: 'Not signed in' }      missing / forged / expired token, password changed, or the
 *                                       account is already gone
 *   409 { error, code:'wrong_user' }    X-Expected-User names a different account
 *   415 { error }                       not application/json
 *   429 { error }                       rate limited (5 per hour per IP, durable)
 *   503 { error, code? }                database unavailable, or delete_account missing
 *                                       (code:'db_not_migrated': SQL Part A not run). The deletion is
 *                                       one transaction, so the account is either fully deleted or
 *                                       untouched; the client may retry (a retry after a deletion that
 *                                       did commit gets 401)
 *
 * Every session token of the account dies with the users row (lib/session.js authenticate()).
 *
 * Env: SESSION_SECRET, SUPA_SERVICE_KEY, SUPABASE_URL (optional).
 */
'use strict';

const C = require('./lib/crypto');
const S = require('./lib/session');
const { withFirewall } = require('./lib/firewall');

function headerValue(event, name) {
  for (const [k, v] of Object.entries(event.headers || {})) if (k.toLowerCase() === name) return String(v == null ? '' : v);
  return '';
}

async function authDelete(event) {
  if (!C.isJsonRequest(event)) return S.json(415, { error: 'Content-Type must be application/json' });
  if (!S.configured()) return S.json(503, { error: 'Service unavailable' });

  const a = await S.authenticate(event);
  if (a.error) return S.json(a.status, { error: a.error });

  const expected = headerValue(event, 'x-expected-user');
  if (expected && S.normEmail(expected) !== a.email) {
    return S.json(409, { error: 'This tab is signed in to a different account.', code: 'wrong_user' });
  }

  const b = event.jsonBody || {};
  if (b.confirm !== true || Object.keys(b).length !== 1) return S.json(400, { error: 'Please confirm that you want to delete your account.' });

  const r = await S.rpc('delete_account', { p_email: a.email });
  if (!S.ok2xx(r)) {
    if (r.status === 404 || (r.error && (r.error.code === 'PGRST202' || r.error.code === '42883'))) {
      console.error('auth-delete: *** DATABASE NOT MIGRATED *** public.delete_account does not exist. ' +
        'Account deletion is impossible until supabase/001_security.sql Part A is run (see supabase/README.md step 2).');
      return S.json(503, { error: "We couldn't delete your account right now. Please try again later.", code: 'db_not_migrated' });
    } console.error('auth-delete: delete_account failed', r.status, r.error && r.error.code);
    return S.json(503, { error: "We couldn't delete your account right now. Please try again in a minute." });
  }
  return S.json(200, { ok: true });
}

exports.handler = withFirewall(authDelete, {
  name: 'auth-delete',
  methods: ['POST'],
  rateLimit: { windowMs: 60 * 60 * 1000, max: 5 },
  durable: true,
  maxBodyBytes: 256,
  json: true,
});
