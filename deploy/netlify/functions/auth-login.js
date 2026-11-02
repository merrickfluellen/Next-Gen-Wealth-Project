/**
 * auth-login — verify email + password on the server and issue a session token.
 *
 * POST { email, password }
 *   200 { token, user: { name, email, free_access } }
 *   401 { error: 'Incorrect email or password.' }   any credential failure (unknown email, wrong
 *                                                   password, malformed input) — one message, padded timing
 *   429 { error }                                   rate limited (per IP via the firewall, per email here)
 *   503 { error }                                   server misconfigured / database unavailable
 *
 * pw_hash may be the legacy 32-bit djb2 hash (written by the old browser client and by
 * confirm-reset) or a scrypt hash. A successful legacy login transparently rewrites pw_hash as
 * scrypt with a compare-and-swap on the old value.
 *
 * Env: SESSION_SECRET, SUPA_SERVICE_KEY, SUPABASE_URL (optional).
 */
'use strict';

const C = require('./lib/crypto');
const S = require('./lib/session');
const { withFirewall, createRateLimiter } = require('./lib/firewall');

const MIN_MS = 450;                 // every credential failure takes at least this long
const BAD = 'Incorrect email or password.';
const failsPerEmail = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 10 });
const failsPerIp = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 30 });

let DUMMY_HASH = null;               // scrypt work for unknown emails / legacy rows (equal timing)
const dummy = () => (DUMMY_HASH ||= C.hashSecret(C.randomToken(16)));

/** Peek at a limiter without counting (limiter counts on every call, so we only call it on failure). */
const blocked = new Map();
function isBlocked(key) {
  const until = blocked.get(key);
  if (!until) return false;
  if (until <= Date.now()) { blocked.delete(key); return false; }
  return true;
}
function recordFail(key, limiter, windowMs) {
  if (!limiter(key).ok) {
    if (blocked.size > 5000) for (const [k, u] of blocked) if (u <= Date.now()) blocked.delete(k);
    blocked.set(key, Date.now() + windowMs);
  }
}

async function login(event) {
  const started = Date.now();
  if (!S.configured()) {
    console.error('auth-login: SUPA_SERVICE_KEY / SESSION_SECRET not configured');
    return S.json(503, { error: 'Sign-in is unavailable right now. Please try again later.' });
  }
  const b = event.jsonBody || {};
  const email = S.normEmail(b.email);
  const password = typeof b.password === 'string' && b.password.length <= S.PW_MAX ? b.password : '';
  const ipKey = 'ip:' + C.clientIp(event);
  const emailKey = 'em:' + (email || '-');

  if (isBlocked(ipKey) || (email && isBlocked(emailKey))) {
    await S.padTo(started, MIN_MS);
    return S.json(429, { error: 'Too many failed attempts. Please wait 15 minutes and try again.' });
  }

  const fail = async () => {
    recordFail(ipKey, failsPerIp, 15 * 60 * 1000);
    if (email) recordFail(emailKey, failsPerEmail, 15 * 60 * 1000);
    await S.padTo(started, MIN_MS);
    return S.json(401, { error: BAD });
  };

  if (!email || !password || !S.pwForLegacy(password)) { C.verifySecret('x', dummy()); return fail(); }

  const g = await S.getUser(email);
  if (g.error === 'db') { await S.padTo(started, MIN_MS); return S.json(503, { error: 'Sign-in is unavailable right now. Please try again in a minute.' }); }
  const user = g.user;
  const stored = user && typeof user.pw_hash === 'string' ? user.pw_hash : '';

  let ok = false, legacy = false;
  if (!user || !stored) {
    C.verifySecret(S.pwForScrypt(password), dummy());          // same work as a real check
  } else if (stored.startsWith('scrypt$')) {
    ok = C.verifySecret(S.pwForScrypt(password), stored);
  } else {
    legacy = true;
    C.verifySecret(S.pwForScrypt(password), dummy());          // equalise with the scrypt path
    ok = C.verifySecret(S.pwForLegacy(password), stored);
  }
  if (!ok) return fail();

  // Transparent upgrade: legacy djb2 → scrypt (compare-and-swap so a concurrent reset wins).
  if (legacy) {
    const newHash = C.hashSecret(S.pwForScrypt(password));
    const up = await S.supa('PATCH',
      `users?email=eq.${S.q(email)}&pw_hash=eq.${S.q(stored)}&select=email,name,pw_hash,free_access`,
      { body: { pw_hash: newHash }, prefer: 'return=representation' });
    const row = S.rows(up)[0];
    if (row && row.pw_hash === newHash) user.pw_hash = newHash;
    else console.error('auth-login: pw_hash upgrade skipped', up.status, up.error && up.error.code);
  }

  return S.json(200, { token: S.issueSession(user), user: S.publicUser(user) });
}

exports.handler = withFirewall(login, {
  name: 'auth-login',
  methods: ['POST'],
  // Generous per-IP request cap (a whole class can sign in from one school IP); failed attempts
  // are limited much harder above (10 per email / 30 per IP per 15 min).
  rateLimit: { windowMs: 10 * 60 * 1000, max: 120 },
  maxBodyBytes: 1024,
  json: true,
  inspect: false,   // passwords are never interpolated anywhere; the filter would block valid ones
});
