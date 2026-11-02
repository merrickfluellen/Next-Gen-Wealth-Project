/**
 * admin-users — the owner's user list, served with the service key.
 *
 * GET  (header Authorization: Bearer <admin token from admin-auth>)
 *   200 { users: [ { name, email, free_access, created_at }, ... ] }   newest first, max 5000
 *   401 { error: 'Not authorized' }    missing / forged / expired admin token, or a USER session token
 *   503 { error }                      misconfigured / database unavailable
 *
 * Only the four listed columns are ever selected — never pw_hash.
 * Env: SESSION_SECRET, ADMIN_EMAIL_HASH, ADMIN_PW_HASH, ADMIN_CODE_HASH, SUPA_SERVICE_KEY.
 */
'use strict';

const C = require('./lib/crypto');
const S = require('./lib/session');
const { withFirewall } = require('./lib/firewall');

const SELECT = 'name,email,free_access,created_at';

async function adminUsers(event) {
  if (!S.isAdminToken(S.bearer(event))) {
    await C.sleep(200 + Math.floor(Math.random() * 100));
    return S.json(401, { error: 'Not authorized' });
  }
  if (!process.env.SUPA_SERVICE_KEY) return S.json(503, { error: 'Service unavailable' });
  const r = await S.supa('GET', `users?select=${SELECT}&order=created_at.desc&limit=5000`);
  if (!S.ok2xx(r)) return S.json(503, { error: 'Service unavailable' });
  const users = S.rows(r).map((u) => ({
    name: String(u.name || ''),
    email: String(u.email || ''),
    free_access: u.free_access === true,
    created_at: u.created_at || null,
  }));
  return S.json(200, { users });
}

exports.handler = withFirewall(adminUsers, {
  name: 'admin-users',
  methods: ['GET'],
  rateLimit: { windowMs: 60 * 1000, max: 30 },
  maxBodyBytes: 0,
});
