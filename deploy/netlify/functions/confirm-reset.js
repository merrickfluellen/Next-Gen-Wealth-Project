/**
 * confirm-reset — steps 2 & 3 combined
 * POST { email, code, verifyToken, newPassword }
 *   → 200 { ok: true } | 200 { error: "..." }
 *
 * 1. Decrypts the AES-256-GCM verifyToken from reset-password (tamper-proof),
 *    checks email, expiry and the code's keyed MAC (constant-time).
 * 2. Checks the token is still bound to the user's CURRENT pw_hash, then updates
 *    pw_hash with a compare-and-swap on the old value — so a token works exactly
 *    once (replay after a successful reset fails).
 *
 * The client routes on the error text (contains "expired"/"Invalid" → back to
 * step 1, contains "code" → back to step 2), so keep that wording stable.
 *
 * NOTE: pw_hash must stay in the legacy hashPw format because app.html checks
 * logins client-side with the same function. Moving to a real password hash
 * requires moving login verification server-side first.
 *
 * Required Netlify env vars:
 *   SUPA_SERVICE_KEY  — Supabase service role key
 *   SESSION_SECRET    — same secret used by reset-password (keys derived via HKDF)
 */

'use strict';

const https = require('https');
const C     = require('./lib/crypto');

const SUPA_HOST       = 'vtxuvmtnqlxidnswnunx.supabase.co';
const MAX_CODE_TRIES  = 5;                // per token, per warm instance
const PW_MIN = 6, PW_MAX = 128;

const MSG = {
  noToken:  'Invalid or expired code. Check that the email is the one on your account, then request a new code.',
  missing:  'Missing required fields.',
  pwShort:  `Password must be at least ${PW_MIN} characters.`,
  pwLong:   `Password must be at most ${PW_MAX} characters.`,
  invalid:  'Invalid request. Please start over.',
  expired:  'This code has expired. Please request a new one.',
  wrong:    'Incorrect code. Check your email and try again.',
  tooMany:  'Invalid code entered too many times. Please request a new one.',
  used:     'Invalid or already-used code. Please request a new one.',
  failed:   'Failed to update password. Please try again.',
  server:   'Server error. Please try again.',
  config:   'Server misconfigured — contact support.',
};

// Tokens already redeemed on this instance (defence in depth; the CAS below is the real guard).
const usedNonces = new Map();

function supaFetch(method, path, key, body, prefer) {
  return new Promise((resolve) => {
    const data = body ? JSON.stringify(body) : null;
    const headers = {
      apikey: key,
      Authorization: `Bearer ${key}`,
      'Content-Type': 'application/json',
      Accept: 'application/json',
      ...(prefer ? { Prefer: prefer } : {}),
      ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}),
    };
    const req = https.request({ hostname: SUPA_HOST, path, method, headers }, res => {
      let raw = '';
      res.on('data', c => { if (raw.length < 1e6) raw += c; });
      res.on('end', () => resolve({ status: res.statusCode, body: raw }));
    });
    req.setTimeout(8000, () => req.destroy(new Error('timeout')));
    req.on('error', () => resolve({ status: 0, body: '' }));
    if (data) req.write(data);
    req.end();
  });
}

const parseRows = (r) => { try { const j = JSON.parse(r.body); return Array.isArray(j) ? j : []; } catch { return []; } };

function codeMac(nonce, email, code) {
  return C.hmac('reset-code', `${nonce}|${email}|${code}`).toString('base64url');
}
function pwBinding(email, pwHash) {
  return C.hmac('reset-pw-binding', `${email}|${pwHash == null ? '' : String(pwHash)}`).toString('base64url');
}

exports.handler = async (event) => {
  const gate = C.methodGate(event);
  if (gate) return gate;
  const reply = (obj) => C.respond(event, 200, obj);

  try {
    const supaKey = process.env.SUPA_SERVICE_KEY;
    const secret  = process.env.SESSION_SECRET;
    if (!supaKey || !secret) {
      console.error('confirm-reset: SUPA_SERVICE_KEY or SESSION_SECRET not configured');
      return reply({ error: MSG.config });
    }

    const b = C.parseJsonBody(event, 4096);
    if (!b) return reply({ error: 'Invalid request.' });

    const email       = typeof b.email === 'string' ? b.email.trim().toLowerCase() : '';
    const code        = typeof b.code === 'string' || typeof b.code === 'number' ? String(b.code).trim() : '';
    const verifyToken = typeof b.verifyToken === 'string' ? b.verifyToken : '';
    const newPassword = typeof b.newPassword === 'string' ? b.newPassword : '';

    // No token means no code was sent; send them back to step 1
    if (email && !verifyToken) return reply({ error: MSG.noToken });
    if (!email || !code || !verifyToken || !newPassword) return reply({ error: MSG.missing });
    if (email.length > 254 || verifyToken.length > 1024) return reply({ error: MSG.invalid });
    if (newPassword.trim().length < PW_MIN) return reply({ error: MSG.pwShort });
    if (newPassword.length > PW_MAX) return reply({ error: MSG.pwLong });

    // Per-IP throttle against online code guessing (best-effort, per warm instance).
    if (C.throttled('confirm:ip:' + C.clientIp(event), 20, 15 * 60 * 1000)) {
      await C.sleep(500);
      return reply({ error: MSG.tooMany });
    }

    // 1. Decrypt + authenticate the token (any tampering → null)
    const t = C.decryptJSON(verifyToken, { purpose: 'reset-verify' });
    if (!t || typeof t.e !== 'string' || typeof t.n !== 'string' || typeof t.c !== 'string' ||
        typeof t.p !== 'string' || !Number.isFinite(t.x)) {
      return reply({ error: MSG.invalid });
    }
    if (!C.safeEqual(t.e, email)) return reply({ error: MSG.invalid });
    if (Date.now() > t.x) return reply({ error: MSG.expired });
    if (usedNonces.has(t.n)) return reply({ error: MSG.used });

    // Cap guesses per token (6-digit code = 1e6 space)
    if (C.throttled('confirm:nonce:' + t.n, MAX_CODE_TRIES, Math.max(1000, t.x - Date.now()))) {
      return reply({ error: MSG.tooMany });
    }

    if (!/^\d{6}$/.test(code) || !C.safeEqual(codeMac(t.n, email, code), t.c)) {
      await C.sleep(400 + Math.floor(Math.random() * 200));
      return reply({ error: MSG.wrong });
    }

    // 2. Token must still be bound to the user's current password hash (single use)
    const emailQ = encodeURIComponent(email);
    const cur = await supaFetch('GET', `/rest/v1/users?email=eq.${emailQ}&select=pw_hash&limit=1`, supaKey);
    const rows = parseRows(cur);
    if (cur.status < 200 || cur.status >= 300) return reply({ error: MSG.failed });
    if (rows.length === 0) return reply({ error: MSG.used });
    const oldHash = rows[0].pw_hash;
    if (!C.safeEqual(pwBinding(email, oldHash), t.p)) return reply({ error: MSG.used });

    // 3. Compare-and-swap update: only succeeds if pw_hash is unchanged since the check
    const newHash = C.legacyHash(newPassword.trim());   // must match hashPw() in app.html
    const casFilter = oldHash == null ? 'pw_hash=is.null' : `pw_hash=eq.${encodeURIComponent(String(oldHash))}`;
    const result = await supaFetch(
      'PATCH',
      `/rest/v1/users?email=eq.${emailQ}&${casFilter}&select=email`,
      supaKey,
      { pw_hash: newHash },
      'return=representation'
    );

    if (result.status >= 200 && result.status < 300) {
      if (parseRows(result).length === 0) return reply({ error: MSG.used });
      usedNonces.set(t.n, t.x);
      if (usedNonces.size > 5000) { const now = Date.now(); for (const [k, x] of usedNonces) if (x < now) usedNonces.delete(k); }
      return reply({ ok: true });
    }
    console.error('confirm-reset: Supabase update failed with status', result.status);
    return reply({ error: MSG.failed });

  } catch (err) {
    console.error('confirm-reset: internal error', err && err.message);
    return reply({ error: MSG.server });
  }
};
