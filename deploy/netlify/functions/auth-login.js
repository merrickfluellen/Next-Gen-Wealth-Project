/**
 * auth-login — verify email + password on the server and issue a session token.
 *
 * POST { email, password }
 *   200 { token, user: { name, email, free_access } }
 *   401 { error: 'Incorrect email or password.' }   any credential failure (unknown email, wrong
 *                                                   password, malformed input) — one message, padded timing
 *   429 { error }  (+ Retry-After)                  too many failures for this email or this IP
 *   503 { error }                                   server misconfigured / database unavailable
 *
 * Lockout (durable, shared by every instance via lib/ratelimit.js; IPv6 counted per /64):
 *   - per email: 10 failures per 15 minutes. Checked BEFORE the password: once reached, every attempt
 *     for that email is refused, right or wrong (no success oracle). In addition at most 20 attempts
 *     per email per 15 minutes are accepted, counted atomically before the check, so a burst of
 *     parallel guesses cannot outrun the failure count.
 *   - per IP: 100 failures per 15 minutes. Applied only to FAILED attempts (they get 429 instead of
 *     401), never to a correct password — a whole class signs in from one school IP, and one
 *     student's typos must not lock the others out. Password spraying from one IP is bounded by the
 *     firewall's 120 requests per 10 minutes (durable) and by the per-email limits.
 *   Successful sign-ins never count as failures.
 *
 * pw_hash may be the legacy 32-bit djb2 hash (written by the old browser client and by older
 * versions of confirm-reset) or a scrypt hash. A successful legacy login transparently rewrites
 * pw_hash as scrypt with a compare-and-swap on the old value.
 *
 * Env: SESSION_SECRET, SUPA_SERVICE_KEY, SUPABASE_URL (optional).
 */
'use strict';

const C = require('./lib/crypto');
const S = require('./lib/session');
const RL = require('./lib/ratelimit');
const { withFirewall } = require('./lib/firewall');

const MIN_MS = 450;                 // every failure / lockout takes at least this long
const BAD = 'Incorrect email or password.';
const WINDOW = 15 * 60;
const LIM_EMAIL = { windowSec: WINDOW, max: 10 };
const LIM_IP = { windowSec: WINDOW, max: 100 };
// Every attempt (right or wrong) per email, counted atomically BEFORE the check: bounds a burst of
// parallel guesses that would all pass the failure peek() before any of them is recorded.
const LIM_EMAIL_TRIES = { windowSec: WINDOW, max: 20 };

let DUMMY_HASH = null;               // scrypt work for unknown emails / legacy rows (equal timing)
const dummy = () => (DUMMY_HASH ||= C.hashSecret(C.randomToken(16)));

async function login(event) {
  const started = Date.now();
  if (!S.configured()) {
    console.error('auth-login: SUPA_SERVICE_KEY / SESSION_SECRET not configured');
    return S.json(503, { error: 'Sign-in is unavailable right now. Please try again later.' });
  }
  const b = event.jsonBody || {};
  const email = S.normEmail(b.email);
  const password = typeof b.password === 'string' && b.password.length <= S.PW_MAX ? b.password : '';
  const ip = RL.ipKey(event.headers);

  const locked = (wait) => S.json(429, { error: 'Too many failed attempts. Please wait 15 minutes and try again.' }, { 'Retry-After': String(wait || WINDOW) });
  const fail = async () => {
    const [ipHit] = await Promise.all([
      RL.hit('login-fail-ip', ip, LIM_IP),
      email ? RL.hit('login-fail-email', email, LIM_EMAIL) : null,
    ]);
    await S.padTo(started, MIN_MS);
    return ipHit.ok ? S.json(401, { error: BAD }) : locked(ipHit.retryAfter);
  };

  if (!email || !password || !S.pwForLegacy(password)) { C.verifySecret('x', dummy()); return fail(); }

  // Lockout check and user lookup in parallel (same latency for every outcome).
  const [emailState, tries, g] = await Promise.all([
    RL.peek('login-fail-email', email, LIM_EMAIL),
    RL.hit('login-try-email', email, LIM_EMAIL_TRIES),
    S.getUser(email),
  ]);
  if (!emailState.ok || !tries.ok) {
    C.verifySecret(S.pwForScrypt(password), dummy());          // same work as a real check
    await S.padTo(started, MIN_MS);
    return locked(Math.max(emailState.retryAfter || 0, tries.retryAfter || 0));
  }
  if (g.error === 'db') { await S.padTo(started, MIN_MS); return S.json(503, { error: 'Sign-in is unavailable right now. Please try again in a minute.' }); }
  const user = g.user;   // a duplicate-rows error is treated as "no such user"
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
  // are limited much harder above (per email, durable; see header).
  rateLimit: { windowMs: 10 * 60 * 1000, max: 120 },
  durable: true,
  maxBodyBytes: 1024,
  json: true,
  inspect: false,   // passwords are never interpolated anywhere; the filter would block valid ones
});
