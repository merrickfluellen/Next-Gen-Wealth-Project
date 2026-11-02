/**
 * confirm-reset — steps 2 & 3 combined
 * POST { email, code, verifyToken, newPassword }   (Content-Type: application/json, same-origin only)
 *   → 200 { ok: true } | 200 { error: "..." }
 *   → 415 wrong Content-Type · 403 foreign Origin · 429 per-IP limit (lib/firewall.js)
 *
 * 1. Decrypts the AES-256-GCM verifyToken from reset-password (tamper-proof), checks email and
 *    expiry.
 * 2. Claims one attempt slot on the token's public.password_resets row with a compare-and-swap
 *    (attempts=N → N+1, only while used=false and N < 5) BEFORE looking at the code, so at most
 *    5 guesses per code exist across all instances/IPs. Concurrent guesses that lose the CAS are
 *    rejected without being checked. (If the table is missing: per-instance limits only; see
 *    reset-password.js for the SQL.)
 * 3. Checks the code's keyed MAC (constant-time) and that the token is still bound to the user's
 *    CURRENT pw_hash, then writes a scrypt hash with a compare-and-swap on the old pw_hash — so a
 *    token works exactly once (replay after a successful reset fails), and every existing user
 *    session is revoked (session tokens fingerprint pw_hash, lib/session.js).
 *
 * New passwords: C.hashSecret(S.pwForScrypt(pw)), min 8 chars (same rule as auth-signup),
 * verified by auth-login's scrypt branch.
 *
 * The client routes on the error text (contains "expired"/"Invalid" → back to step 1, contains
 * "code" → back to step 2), so keep that wording stable.
 *
 * Required Netlify env vars: SUPA_SERVICE_KEY, SESSION_SECRET, SUPABASE_URL (optional).
 */

'use strict';

const C = require('./lib/crypto');
const S = require('./lib/session');
const { withFirewall } = require('./lib/firewall');

const MAX_CODE_TRIES = 5;

const MSG = {
  noToken:  'Invalid or expired code. Check that the email is the one on your account, then request a new code.',
  missing:  'Missing required fields.',
  invalid:  'Invalid request. Please start over.',
  expired:  'This code has expired. Please request a new one.',
  wrong:    'Incorrect code. Check your email and try again.',
  tooMany:  'Invalid code entered too many times. Please request a new one.',
  used:     'Invalid or already-used code. Please request a new one.',
  busy:     'Please wait a moment and try again.',
  failed:   'Failed to update password. Please try again.',
  config:   'Server misconfigured — contact support.',
};

// Tokens already redeemed on this instance (defence in depth; the CAS below is the real guard).
const usedNonces = new Map();

function codeMac(nonce, email, code) {
  return C.hmac('reset-code', `${nonce}|${email}|${code}`).toString('base64url');
}
function pwBinding(email, pwHash) {
  return C.hmac('reset-pw-binding', `${email}|${pwHash == null ? '' : String(pwHash)}`).toString('base64url');
}
const storeMissing = (r) => r.status === 404 || !!(r.error && (r.error.code === 'PGRST205' || r.error.code === '42P01'));

/**
 * Claim one guess for this token. Returns
 *   { ok: true, last: bool, durable: bool }   go ahead and check the code
 *   { error: MSG.* }                          stop
 */
async function claimAttempt(nonce, email, expiry) {
  // Per-instance cap (always on; the only cap when the table is missing).
  if (C.throttled('confirm:nonce:' + nonce, MAX_CODE_TRIES, Math.max(1000, expiry - Date.now()))) {
    return { error: MSG.tooMany };
  }
  const cur = await S.supa('GET', `password_resets?id=eq.${S.q(nonce)}&select=email,attempts,used&limit=1`);
  if (storeMissing(cur)) {
    console.error('confirm-reset: table public.password_resets is missing — per-instance attempt limit only');
    return { ok: true, last: false, durable: false };
  }
  if (!S.ok2xx(cur)) return { error: MSG.failed };
  const row = S.rows(cur)[0];
  if (!row || row.email !== email || row.used === true) return { error: MSG.used };
  const n = Number(row.attempts);
  if (!Number.isInteger(n) || n < 0) return { error: MSG.failed };
  if (n >= MAX_CODE_TRIES) return { error: MSG.tooMany };
  const up = await S.supa('PATCH', `password_resets?id=eq.${S.q(nonce)}&attempts=eq.${n}&used=is.false&select=id`,
    { body: { attempts: n + 1 }, prefer: 'return=representation' });
  if (!S.ok2xx(up)) return { error: MSG.failed };
  if (S.rows(up).length !== 1) return { error: MSG.busy };   // a concurrent guess took this slot
  return { ok: true, last: n + 1 >= MAX_CODE_TRIES, durable: true };
}

const markUsed = (nonce) => S.supa('PATCH', `password_resets?id=eq.${S.q(nonce)}`, { body: { used: true }, prefer: 'return=minimal' });

async function confirmReset(event) {
  const reply = (obj) => S.json(200, obj);
  if (!C.isJsonRequest(event)) return S.json(415, { error: MSG.invalid });

  if (!S.configured()) {
    console.error('confirm-reset: SUPA_SERVICE_KEY or SESSION_SECRET not configured');
    return reply({ error: MSG.config });
  }

  const b = event.jsonBody || {};
  const email       = typeof b.email === 'string' ? b.email.trim().toLowerCase() : '';
  const code        = typeof b.code === 'string' || typeof b.code === 'number' ? String(b.code).trim() : '';
  const verifyToken = typeof b.verifyToken === 'string' ? b.verifyToken : '';
  const newPassword = typeof b.newPassword === 'string' ? b.newPassword : '';

  // No token means no code was sent; send them back to step 1
  if (email && !verifyToken) return reply({ error: MSG.noToken });
  if (!email || !code || !verifyToken || !newPassword) return reply({ error: MSG.missing });
  if (email.length > 254 || verifyToken.length > 1024 || code.length > 16) return reply({ error: MSG.invalid });
  const pwErr = S.validNewPassword(newPassword);
  if (pwErr) return reply({ error: pwErr });

  // 1. Decrypt + authenticate the token (any tampering → null)
  const t = C.decryptJSON(verifyToken, { purpose: 'reset-verify' });
  if (!t || typeof t.e !== 'string' || typeof t.n !== 'string' || typeof t.c !== 'string' ||
      typeof t.p !== 'string' || !Number.isFinite(t.x)) {
    return reply({ error: MSG.invalid });
  }
  if (!C.safeEqual(t.e, email)) return reply({ error: MSG.invalid });
  if (Date.now() > t.x) return reply({ error: MSG.expired });
  if (usedNonces.has(t.n)) return reply({ error: MSG.used });

  // 2. Claim a guess (durable, CAS) before the code is looked at.
  const slot = await claimAttempt(t.n, email, t.x);
  if (slot.error) return reply({ error: slot.error });

  if (!/^\d{6}$/.test(code) || !C.safeEqual(codeMac(t.n, email, code), t.c)) {
    await C.sleep(300 + Math.floor(Math.random() * 200));
    if (slot.last) { if (slot.durable) await markUsed(t.n); return reply({ error: MSG.tooMany }); }
    return reply({ error: MSG.wrong });
  }

  // 3. Token must still be bound to the user's current password hash (single use)
  const g = await S.getUser(email, 'email,pw_hash');
  if (g.error === 'db') return reply({ error: MSG.failed });
  if (g.error || !g.user) return reply({ error: MSG.used });
  const oldHash = g.user.pw_hash;
  if (!C.safeEqual(pwBinding(email, oldHash), t.p)) return reply({ error: MSG.used });

  // Compare-and-swap update: only succeeds if pw_hash is unchanged since the check
  const newHash = C.hashSecret(S.pwForScrypt(newPassword));   // verified by auth-login (scrypt branch)
  const casFilter = oldHash == null ? 'pw_hash=is.null' : `pw_hash=eq.${S.q(oldHash)}`;
  const result = await S.supa('PATCH', `users?email=eq.${S.q(email)}&${casFilter}&select=email`,
    { body: { pw_hash: newHash }, prefer: 'return=representation' });

  if (!S.ok2xx(result)) {
    console.error('confirm-reset: Supabase update failed with status', result.status);
    return reply({ error: MSG.failed });
  }
  if (S.rows(result).length === 0) return reply({ error: MSG.used });

  usedNonces.set(t.n, t.x);
  if (usedNonces.size > 5000) { const now = Date.now(); for (const [k, x] of usedNonces) if (x < now) usedNonces.delete(k); }
  if (slot.durable) {
    const m = await markUsed(t.n);
    if (!S.ok2xx(m)) console.error('confirm-reset: could not mark reset row used (pw_hash CAS still prevents replay)');
  }
  return reply({ ok: true });
}

exports.handler = withFirewall(confirmReset, {
  name: 'confirm-reset',
  methods: ['POST'],
  rateLimit: { windowMs: 15 * 60 * 1000, max: 20 },
  maxBodyBytes: 4096,
  json: true,
  inspect: false,   // the body carries a new password; the signature filter would reject valid ones
});
