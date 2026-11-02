/**
 * auth-signup — create an account, redeeming an access code server-side (exactly once, ever).
 *
 * POST { name, email, password, code }
 *   201 { token, user: { name, email, free_access } }
 *   400 { error }                  invalid input (message is safe to show)
 *   403 { error }                  invalid access code
 *   409 { error, reason:'code_used' }      code already redeemed
 *   409 { error, reason:'account_exists' } email already registered (only reachable with a valid code)
 *   429 { error }                  rate limited
 *   503 { error }                  server misconfigured / database unavailable
 *
 * Flow: validate input → look the code up (v2 HMAC table, then the legacy list) → reject an
 * existing email → INSERT into code_redemptions (UNIQUE(code_hash): a concurrent or repeated use
 * loses here) → INSERT users (UNIQUE(email)) — on failure the redemption is rolled back →
 * INSERT the progress row → issue a session token.
 *
 * Env: SESSION_SECRET, SUPA_SERVICE_KEY, CODE_PEPPER (v2 codes), LEGACY_CODES ('off' disables the
 * old 151 public-hash codes), SUPABASE_URL (optional).
 */
'use strict';

const C = require('./lib/crypto');
const S = require('./lib/session');
const L = require('./lib/legacy-hash');
const { withFirewall, createRateLimiter } = require('./lib/firewall');

const perEmail = createRateLimiter({ windowMs: 60 * 60 * 1000, max: 5 });
const badCodePerIp = createRateLimiter({ windowMs: 60 * 60 * 1000, max: 10 });

const MSG = {
  input: 'Please check your details and try again.',
  code: 'Invalid access code. Purchase a code to create an account.',
  used: 'This access code has already been used. Each code creates one account.',
  exists: 'An account with this email already exists. Sign in instead.',
  busy: 'Too many attempts. Please wait and try again.',
  down: "We couldn't create your account right now. Please try again in a minute.",
};

/** Returns { hash, free, source } or null. */
async function lookupCode(code) {
  const v2 = L.normalizeV2(code);
  if (v2 && L.pepper()) {
    const hash = L.v2Hash(v2);
    const r = await S.supa('GET', `access_codes?code_hash=eq.${hash}&select=code_hash,free,disabled&limit=1`);
    if (!S.ok2xx(r)) {
      // Table missing (SQL not run yet) is a config problem; anything else is transient.
      return { error: true };
    }
    const row = S.rows(r)[0];
    if (row && row.disabled !== true) return { hash: 'v2:' + hash, free: row.free === true, source: 'v2' };
  }
  if (L.legacyEnabled()) {
    const leg = L.legacyLookup(code);
    if (leg) return { ...leg, source: 'legacy' };
  }
  return null;
}

async function signup(event) {
  if (!S.configured()) {
    console.error('auth-signup: SUPA_SERVICE_KEY / SESSION_SECRET not configured');
    return S.json(503, { error: MSG.down });
  }
  const b = event.jsonBody || {};
  const name = S.normName(b.name);
  const email = S.normEmail(b.email, { strict: true });
  const code = typeof b.code === 'string' ? b.code : '';

  if (!name) return S.json(400, { error: 'Please enter your name (1–40 characters, no special symbols).', field: 'name' });
  if (!email) return S.json(400, { error: 'Please enter a valid email address.', field: 'email' });
  const pwErr = S.validNewPassword(b.password);
  if (pwErr) return S.json(400, { error: pwErr, field: 'password' });
  if (!code || code.length > 256) return S.json(400, { error: MSG.code, field: 'code' });

  if (!perEmail('signup:' + email).ok) return S.json(429, { error: MSG.busy });

  const found = await lookupCode(code);
  if (found && found.error) return S.json(503, { error: MSG.down });
  if (!found) {
    const rl = badCodePerIp('badcode:' + C.clientIp(event));
    await C.sleep(300 + Math.floor(Math.random() * 200));
    if (!rl.ok) return S.json(429, { error: MSG.busy });
    return S.json(403, { error: MSG.code, field: 'code' });
  }

  // Existing account? (checked before burning the code)
  const existing = await S.getUser(email, 'email');
  if (existing.error) return S.json(existing.error === 'duplicate' ? 409 : 503, existing.error === 'duplicate' ? { error: MSG.exists, reason: 'account_exists' } : { error: MSG.down });
  if (existing.user) return S.json(409, { error: MSG.exists, reason: 'account_exists' });

  // Hash before redeeming so nothing slow/fallible sits between redeem and insert.
  const pwHash = C.hashSecret(S.pwForScrypt(b.password));

  // 1. Redeem — the UNIQUE(code_hash) constraint makes this the single point of truth.
  const red = await S.supa('POST', 'code_redemptions', {
    body: { code_hash: found.hash, email, source: found.source },
    prefer: 'return=minimal',
  });
  if (S.isUniqueViolation(red)) return S.json(409, { error: MSG.used, reason: 'code_used' });
  if (!S.ok2xx(red)) {
    console.error('auth-signup: code_redemptions insert failed', red.status, red.error && red.error.code);
    return S.json(503, { error: MSG.down });
  }
  const rollback = () => S.supa('DELETE',
    `code_redemptions?code_hash=eq.${S.q(found.hash)}&email=eq.${S.q(email)}`, { prefer: 'return=minimal' });

  // 2. Create the user.
  const ins = await S.supa('POST', 'users', {
    body: { email, name, pw_hash: pwHash, free_access: found.free === true },
    prefer: 'return=representation',
  });
  if (!S.ok2xx(ins)) {
    await rollback();
    if (S.isUniqueViolation(ins)) return S.json(409, { error: MSG.exists, reason: 'account_exists' });
    console.error('auth-signup: users insert failed', ins.status, ins.error && ins.error.code);
    return S.json(503, { error: MSG.down });
  }
  const user = (Array.isArray(ins.data) && ins.data[0]) || { email, name, pw_hash: pwHash, free_access: found.free === true };
  if (user.pw_hash !== pwHash || user.email !== email) {
    // Should never happen; refuse to mint a session for a row we can't vouch for.
    console.error('auth-signup: inserted row mismatch');
    return S.json(503, { error: MSG.down });
  }

  // 3. Progress row. A row for this email can only be an orphan (no account existed until now) —
  //    possibly planted through the old open table — so drop it rather than inherit it.
  await S.supa('DELETE', `progress?email=eq.${S.q(email)}`, { prefer: 'return=minimal' });
  const prog = await S.supa('POST', 'progress', {
    body: { email, portfolio: { cash: 0, investments: [], debt: 0 } },
    prefer: 'return=minimal',
  });
  if (!S.ok2xx(prog) && !S.isUniqueViolation(prog)) {
    console.error('auth-signup: progress insert failed', prog.status, prog.error && prog.error.code);
  }

  return S.json(201, { token: S.issueSession(user), user: S.publicUser(user) });
}

exports.handler = withFirewall(signup, {
  name: 'auth-signup',
  methods: ['POST'],
  // A classroom may sign up together behind one school IP, so the per-IP cap is generous; the
  // per-email and bad-code limits above do the real work.
  rateLimit: { windowMs: 60 * 60 * 1000, max: 40 },
  maxBodyBytes: 2048,
  json: true,
  // Passwords are hashed and every value goes to PostgREST as JSON, so the signature filter would
  // only reject legitimate passwords such as "../Tr0ub4dor" (false positives, no protection).
  inspect: false,
});
exports._internals = { lookupCode };
