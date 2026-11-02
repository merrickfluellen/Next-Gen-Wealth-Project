/**
 * auth-signup — create an account, redeeming an access code server-side (exactly once, ever).
 *
 * POST { name, email, password, code, ageBand, consentVersion }
 *   ageBand        '13-17' | '18+'      (lib/session.js AGE_BANDS; under-13 never reaches the server)
 *   consentVersion lib/session.js CONSENT_VERSION (the Terms/Privacy version the user agreed to)
 *
 *   201 { token, user: { name, email, free_access } }
 *   400 { error, field? }          invalid input (message is safe to show); field is one of
 *                                  name | email | password | code | ageBand | consent
 *   403 { error, field:'code' }    invalid access code
 *   409 { error, reason:'code_used' }      code already redeemed
 *   409 { error, reason:'account_exists' } email already registered (only reachable with a valid,
 *                                          unused code; counted against the per-IP failure budget
 *                                          and a per-code budget, so one code cannot probe many emails)
 *   429 { error }                  rate limited
 *   503 { error, code? }           server misconfigured / database unavailable (code:'db_not_migrated'
 *                                  when supabase/001_security.sql Part A has not been run). Never retried and
 *                                  never rolled back: if the database committed, the account exists
 *                                  and the code is spent (sign in); if not, the code is still unused.
 *
 * Flow: validate input → durable limits → look the code up (v2 HMAC table, then the legacy list;
 * no DB write, no scrypt for a bad code) → hash the password → ONE call to the Postgres function
 * public.create_user_with_code (supabase/001_security.sql A9), which claims the code, creates the
 * user with the consent record and resets the progress row in a single transaction →
 * issue a session token.
 *
 * Limits (durable, shared by every instance via lib/ratelimit.js; IPv6 counted per /64):
 *   - firewall: 40 signup requests per hour per IP (a classroom shares one school IP);
 *   - 5 attempts per email per hour;
 *   - 10 failures (bad code / account_exists) per IP per hour — once reached, every attempt from
 *     that IP is refused, valid code or not (no success oracle);
 *   - 3 account_exists answers per code per day.
 *
 * Env: SESSION_SECRET, SUPA_SERVICE_KEY, CODE_PEPPER (v2 codes), LEGACY_CODES ('off' disables the
 * old 151 public-hash codes), SUPABASE_URL (optional).
 */
'use strict';

const C = require('./lib/crypto');
const S = require('./lib/session');
const L = require('./lib/legacy-hash');
const RL = require('./lib/ratelimit');
const { withFirewall } = require('./lib/firewall');

const HOUR = 3600, DAY = 86400;
const LIM = {
  email: { windowSec: HOUR, max: 5 },
  failIp: { windowSec: HOUR, max: 10 },
  existsPerCode: { windowSec: DAY, max: 3 },
};

const MSG = {
  code: 'Invalid access code. Purchase a code to create an account.',
  used: 'This access code has already been used. Each code creates one account.',
  exists: 'An account with this email already exists. Sign in instead.',
  age: 'Please choose your age group.',
  consent: 'Please agree to the Terms of Service and Privacy Policy to create an account.',
  busy: 'Too many attempts. Please wait and try again.',
  down: "We couldn't create your account right now. Please try again in a minute.",
};

const busy = (r) => S.json(429, { error: MSG.busy }, { 'Retry-After': String((r && r.retryAfter) || 60) });

/** Returns { hash, free, source }, null (no such code) or { error: true } (database problem). */
async function lookupCode(code) {
  const v2 = L.normalizeV2(code);
  if (v2 && L.pepper()) {
    const hash = L.v2Hash(v2);
    const r = await S.supa('GET', `access_codes?code_hash=eq.${hash}&select=code_hash,free,disabled&limit=1`);
    if (!S.ok2xx(r)) return { error: true };
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
  const ageBand = S.normAgeBand(b.ageBand);

  if (!name) return S.json(400, { error: 'Please enter your name (1–40 characters, no special symbols).', field: 'name' });
  if (!email) return S.json(400, { error: 'Please enter a valid email address.', field: 'email' });
  const pwErr = S.validNewPassword(b.password);
  if (pwErr) return S.json(400, { error: pwErr, field: 'password' });
  if (!code || code.length > 256) return S.json(400, { error: MSG.code, field: 'code' });
  if (!ageBand) return S.json(400, { error: MSG.age, field: 'ageBand' });
  if (b.consentVersion !== S.CONSENT_VERSION) return S.json(400, { error: MSG.consent, field: 'consent' });

  const ip = RL.ipKey(event.headers);
  // An IP that has used up its failure budget is refused BEFORE the code is looked at, so a valid
  // code cannot be told apart from an invalid one once the budget is gone.
  const [failState, perEmail] = await Promise.all([
    RL.peek('signup-fail-ip', ip, LIM.failIp),
    RL.hit('signup-email', email, LIM.email),
  ]);
  if (!failState.ok) return busy(failState);
  if (!perEmail.ok) return busy(perEmail);

  const countFailure = () => RL.hit('signup-fail-ip', ip, LIM.failIp);

  const found = await lookupCode(code);
  if (found && found.error) return S.json(503, { error: MSG.down });
  if (!found) {
    await Promise.all([countFailure(), C.sleep(300 + Math.floor(Math.random() * 200))]);
    return S.json(403, { error: MSG.code, field: 'code' });
  }

  const pwHash = C.hashSecret(S.pwForScrypt(b.password));

  // One atomic step. Nothing to roll back: the function writes everything or nothing.
  const r = await S.rpc('create_user_with_code', {
    p_email: email,
    p_name: name,
    p_pw_hash: pwHash,
    p_code_hash: found.hash,
    p_source: found.source,
    p_free: found.free === true,
    p_age_band: ageBand,
    p_consent_version: S.CONSENT_VERSION,
  });
  const status = S.ok2xx(r) && typeof r.data === 'string' ? r.data : '';

  if (status === 'ok') {
    const user = { email, name, pw_hash: pwHash, free_access: found.free === true };
    return S.json(201, { token: S.issueSession(user), user: S.publicUser(user) });
  }
  if (status === 'code_used') return S.json(409, { error: MSG.used, reason: 'code_used' });
  if (status === 'code_invalid') {   // v2 code disabled between the lookup and the claim
    await countFailure();
    return S.json(403, { error: MSG.code, field: 'code' });
  }
  if (status === 'account_exists') {
    const [, perCode] = await Promise.all([countFailure(), RL.hit('signup-exists-code', found.hash, LIM.existsPerCode)]);
    if (!perCode.ok) return busy(perCode);
    return S.json(409, { error: MSG.exists, reason: 'account_exists' });
  }

  // status 0 (timeout / network) or 5xx: the transaction may or may not have committed. Do NOT
  // retry or undo anything — the database is the single source of truth.
  if (r.status === 400) {
    console.error('auth-signup: create_user_with_code rejected its input', r.error && r.error.code);
    return S.json(400, { error: 'Please check your details and try again.' });
  }
  if (r.status === 404 || (r.error && (r.error.code === 'PGRST202' || r.error.code === '42883'))) {
    console.error('auth-signup: *** DATABASE NOT MIGRATED *** public.create_user_with_code does not exist. ' +
      'Nobody can sign up until supabase/001_security.sql Part A is run (see supabase/README.md step 2).');
    return S.json(503, { error: MSG.down, code: 'db_not_migrated' });
  } console.error('auth-signup: create_user_with_code failed', r.status, r.error && r.error.code, status ? 'unexpected ' + status : '');
  return S.json(503, { error: MSG.down });
}

exports.handler = withFirewall(signup, {
  name: 'auth-signup',
  methods: ['POST'],
  // A classroom may sign up together behind one school IP, so the per-IP request cap is generous;
  // the per-email and failure limits above do the real work.
  rateLimit: { windowMs: 60 * 60 * 1000, max: 40 },
  durable: true,
  maxBodyBytes: 2048,
  json: true,
  // Passwords are hashed and every value goes to PostgREST as JSON, so the signature filter would
  // only reject legitimate passwords such as "../Tr0ub4dor" (false positives, no protection).
  inspect: false,
});
exports._internals = { lookupCode };
