/**
 * reset-password — step 1 of 3
 * POST { email }   (Content-Type: application/json, same-origin only)
 *   → 200 { ok: true, verifyToken: "..." }   (ALWAYS — see "No user enumeration" below)
 *   → 415 wrong Content-Type · 403 foreign Origin · 429 per-IP limit (lib/firewall.js)
 *
 * Looks the email up in Supabase, generates a 6-digit code, emails it, and returns an opaque
 * verifyToken the client hands back to confirm-reset.
 *
 * verifyToken = AES-256-GCM( { e: email, x: expiry, n: nonce,
 *                               c: HMAC(nonce|email|code), p: HMAC(email|current pw_hash) } )
 *   - the code is never in the token, only a keyed MAC of it;
 *   - `p` binds the token to the CURRENT password hash, so once the password is changed the token
 *     is dead (single use);
 *   - encryption makes decoy tokens for unknown emails indistinguishable from real ones.
 *
 * Durable state: table public.password_resets (supabase/001_security.sql Part A, A4b), one row per
 * issued code, keyed by the nonce, holding `attempts` and `used`. confirm-reset claims an attempt
 * slot with a compare-and-swap BEFORE checking the code, so a code can be guessed at most 5 times
 * in total, across every function instance and IP (and at most 10 guesses per email per day across
 * all codes — see confirm-reset). Issuing a new code retires the older ones for that email.
 *
 * Unknown emails get a row too: that is what makes every later answer from confirm-reset identical
 * for real and unknown addresses. To keep this from storing whatever address anyone types, the
 * row's `email` column holds emailRef(email) — a keyed HMAC ("h1:…"), never the address itself —
 * and rows are deleted after 2 days by the pg_cron job in Part A (A11).
 *
 * Email limits (anti email-bombing / protects the Resend quota). When a limit is reached no email is
 * sent and the response is the usual decoy:
 *   - 3 codes per email per hour (durable, via password_resets) and 5 emails per email per day;
 *   - 20 reset requests per IP per day (durable; IPv6 per /64), firewall 10 per 15 min;
 *   - global: RESET_EMAILS_PER_DAY (default 80) emails per day for the whole site. Fails closed:
 *     if the counter cannot be read, no email is sent.
 *
 * No user enumeration: unknown email, rate-limited, mail-provider failure and success all return
 * the same body (with a decoy token where needed) and are padded to the same minimum time.
 *
 * Required Netlify env vars:
 *   SUPA_SERVICE_KEY  — Supabase service role key
 *   SESSION_SECRET    — master secret (keys derived via HKDF, see lib/crypto.js)
 *   RESEND_API_KEY    — Resend.com API key (without it no email is ever sent; logged only)
 *   RESEND_FROM       — verified sender; the default onboarding@resend.dev only delivers to the
 *                       Resend account owner, so set it in production
 *   RESET_EMAILS_PER_DAY — (optional) site-wide daily email cap, default 80; keep it below the
 *                       Resend plan's daily quota
 *   SUPABASE_URL      — (optional) see lib/session.js
 */

'use strict';

const C = require('./lib/crypto');
const S = require('./lib/session');
const RL = require('./lib/ratelimit');
const { withFirewall } = require('./lib/firewall');

const CODE_TTL_MS        = 15 * 60 * 1000;   // 15 minutes (the email says so too)
// Pad every response to hide which path ran. The slowest normal path (known email: lookup, 4 DB
// calls, 2 counters, one Resend call) takes well under a second; Resend calls slower than the pad
// are logged.
const MIN_RESPONSE_MS    = 1800;
const PER_EMAIL_PER_HOUR = 3;
const DAY = 86400;
const LIM_EMAIL_DAY = { windowSec: DAY, max: 5 };
const LIM_IP_DAY = { windowSec: DAY, max: 20 };
function emailsPerDay() {
  const n = parseInt(process.env.RESET_EMAILS_PER_DAY || '', 10);
  return Number.isFinite(n) && n >= 0 && n <= 100000 ? n : 80;
}

const escapeHtml = (s) => String(s).replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));

function codeMac(nonce, email, code) {
  return C.hmac('reset-code', `${nonce}|${email}|${code}`).toString('base64url');
}
function pwBinding(email, pwHash) {
  return C.hmac('reset-pw-binding', `${email}|${pwHash == null ? '' : String(pwHash)}`).toString('base64url');
}
/** What password_resets.email holds: a keyed HMAC of the address, never the address (see header). */
function emailRef(email) {
  return 'h1:' + C.hmac('reset-email-ref', email).toString('base64url');
}
/** PostgREST answers 404 / PGRST205 / 42P01 when the table has not been created yet. */
const storeMissing = (r) => r.status === 404 || !!(r.error && (r.error.code === 'PGRST205' || r.error.code === '42P01'));

/** Real token (code known) or decoy (code=null → random MACs that no 6-digit code can match). */
function makeVerifyToken(email, code, pwHash, nonce = C.randomToken(16), expiry = Date.now() + CODE_TTL_MS) {
  return C.encryptJSON({
    e: email,
    x: expiry,
    n: nonce,
    c: code ? codeMac(nonce, email, code) : C.randomToken(32),
    p: code ? pwBinding(email, pwHash) : C.randomToken(32),
  }, { purpose: 'reset-verify' });
}

/** Display name for the email: bounded, no control chars, HTML-escaped. */
function safeName(name) {
  const n = String(name || '').replace(/[\p{Cc}\p{Cf}\u2028\u2029]/gu, '').replace(/\s+/g, ' ').trim();
  return escapeHtml([...(n || 'there')].slice(0, 40).join(''));
}

/**
 * Records a new code in password_resets — for real AND unknown emails alike, so confirm-reset
 * behaves identically for both (no enumeration oracle). The row stores emailRef(email). Returns 'ok' | 'limited' | 'missing' | 'error'.
 * The per-email cap is race-safe: after inserting, only the first PER_EMAIL_PER_HOUR rows of the
 * last hour (by created_at, id) are allowed; a row that lost the race is retired immediately.
 */
async function recordReset(email, nonce, expiry) {
  const ref = emailRef(email);
  const since = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  const windowQ = `password_resets?email=eq.${S.q(ref)}&created_at=gte.${S.q(since)}&select=id` +
    `&order=created_at.asc,id.asc&limit=${PER_EMAIL_PER_HOUR}`;
  const recent = await S.supa('GET', windowQ);
  if (storeMissing(recent)) return 'missing';
  if (!S.ok2xx(recent)) return 'error';
  if (S.rows(recent).length >= PER_EMAIL_PER_HOUR) return 'limited';

  const createdAt = new Date().toISOString();
  const ins = await S.supa('POST', 'password_resets',
    { body: { id: nonce, email: ref, attempts: 0, used: false, expires_at: new Date(expiry).toISOString(), created_at: createdAt }, prefer: 'return=minimal' });
  if (!S.ok2xx(ins)) return 'error';

  const first = await S.supa('GET', windowQ);
  if (!S.ok2xx(first) || !S.rows(first).some((r) => r && r.id === nonce)) {
    await S.supa('PATCH', `password_resets?id=eq.${S.q(nonce)}`, { body: { used: true }, prefer: 'return=minimal' });
    return S.ok2xx(first) ? 'limited' : 'error';
  }
  // Retire every OLDER open code for this email (only the newest code works).
  const retire = await S.supa('PATCH', `password_resets?email=eq.${S.q(ref)}&used=is.false&created_at=lt.${S.q(createdAt)}`,
    { body: { used: true }, prefer: 'return=minimal' });
  if (!S.ok2xx(retire)) console.error('reset-password: could not retire older codes');
  return 'ok';
}

async function sendEmail(email, userName, code) {
  const t0 = Date.now();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 8000);
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      signal: ctrl.signal,
      body: JSON.stringify({
        from: `InvestEd Pro <${process.env.RESEND_FROM || 'onboarding@resend.dev'}>`,
        to: [email],
        subject: `${code} is your InvestEd Pro verification code`,
        html: `
          <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:480px;margin:0 auto;background:#0a0e27;color:#f5f7fa;padding:32px;border-radius:12px;border:1px solid #1e2640">
            <div style="font-size:24px;font-weight:900;color:#dc2626;margin-bottom:4px">InvestEd Pro</div>
            <div style="color:#8896b3;font-size:12px;margin-bottom:28px">Financial Education Platform</div>
            <h2 style="color:#f5f7fa;font-size:20px;margin:0 0 10px">Hey ${userName}, verify it's you</h2>
            <p style="color:#8896b3;line-height:1.7;margin-bottom:24px">
              You requested a password reset. Enter this code in the app to prove you own this email address:
            </p>
            <div style="background:#111627;border:2px solid #dc2626;border-radius:12px;padding:24px;text-align:center;margin-bottom:24px">
              <div style="font-size:42px;font-weight:900;letter-spacing:10px;color:#fff;font-family:monospace">${code}</div>
              <div style="font-size:12px;color:#8896b3;margin-top:8px">This code expires in <strong style="color:#f5f7fa">15 minutes</strong></div>
            </div>
            <p style="color:#4b5563;font-size:12px;line-height:1.6">
              If you didn't request this, you can safely ignore this email — your account won't be changed.
              Never share this code with anyone.
            </p>
          </div>
        `,
      }),
    });
    return res.status;
  } catch {
    return 0;
  } finally {
    clearTimeout(timer);
    const ms = Date.now() - t0;
    if (ms > MIN_RESPONSE_MS - 600) console.warn(`reset-password: Resend took ${ms} ms (longer than the response pad allows for)`);
  }
}

async function resetPassword(event) {
  if (!C.isJsonRequest(event)) {
    return S.json(415, { ok: false, error: 'Something went wrong. Please refresh the page and try again.' });
  }
  const started = Date.now();
  const finish = async (body) => { await S.padTo(started, MIN_RESPONSE_MS, 250); return S.json(200, body); };

  if (!process.env.SESSION_SECRET) {
    console.error('reset-password: SESSION_SECRET not configured');
    return finish({ ok: true, verifyToken: '' });
  }

  const raw = (event.jsonBody || {}).email;
  const email = S.normEmail(raw);
  if (!email) {
    const e = typeof raw === 'string' ? raw.trim().toLowerCase() : '';
    return finish({ ok: true, verifyToken: e && e.length <= 254 ? makeVerifyToken(e, null) : '' });
  }
  const decoy = () => finish({ ok: true, verifyToken: makeVerifyToken(email, null) });

  if (!process.env.SUPA_SERVICE_KEY || !process.env.RESEND_API_KEY) {
    console.error('reset-password: SUPA_SERVICE_KEY or RESEND_API_KEY not configured');
    return decoy();
  }

  // Cheap per-instance guard first (the durable per-email limit is in recordReset).
  if (C.throttled('reset:email:' + email, PER_EMAIL_PER_HOUR, 60 * 60 * 1000)) return decoy();
  const perIp = await RL.hit('reset-ip-day', RL.ipKey(event.headers), LIM_IP_DAY);
  if (!perIp.ok) return decoy();

  const g = await S.getUser(email, 'email,name,pw_hash');
  if (g.error === 'db') return decoy();
  const user = g.error ? null : g.user;   // duplicate rows are treated like an unknown email

  const code   = C.randomDigits(6);
  const nonce  = C.randomToken(16);
  const expiry = Date.now() + CODE_TTL_MS;

  // A row is recorded for unknown emails too (with a decoy token), so every later answer from
  // confirm-reset is the same whether or not the account exists.
  const rec = await recordReset(email, nonce, expiry);
  if (rec === 'missing') {
    console.error('reset-password: table public.password_resets is missing — using per-instance limits only. Run supabase/001_security.sql Part A.');
  } else if (rec !== 'ok') {
    if (rec === 'error') console.error('reset-password: could not record the reset code');
    return decoy();   // no email sent; same response as everything else
  }
  if (!user) return finish({ ok: true, verifyToken: makeVerifyToken(email, null, null, nonce, expiry) });

  // Email budgets: per address per day, then site-wide per day (fails closed). Over budget → the
  // row stays recorded, but the token is a decoy and nothing is sent (same answer as always).
  const perEmail = await RL.hit('reset-email-day', emailRef(email), LIM_EMAIL_DAY);
  if (!perEmail.ok) return finish({ ok: true, verifyToken: makeVerifyToken(email, null, null, nonce, expiry) });
  const site = await RL.budget('reset-email', { windowSec: DAY, max: emailsPerDay() });
  if (!site.ok) {
    console.error('reset-password: daily reset-email budget reached (RESET_EMAILS_PER_DAY) — no email sent');
    return finish({ ok: true, verifyToken: makeVerifyToken(email, null, null, nonce, expiry) });
  }

  const status = await sendEmail(email, safeName(user.name), code);
  if (status < 200 || status >= 300) {
    // Logged for the owner; NOT surfaced to the client (a distinct error would reveal the account exists).
    console.error('reset-password: Resend API returned status', status);
  }
  return finish({ ok: true, verifyToken: makeVerifyToken(email, code, user.pw_hash, nonce, expiry) });
}

exports.handler = withFirewall(resetPassword, {
  name: 'reset-password',
  methods: ['POST'],
  rateLimit: { windowMs: 15 * 60 * 1000, max: 10 },
  durable: true,
  maxBodyBytes: 1024,
  json: true,
});
exports._internals = { codeMac, pwBinding, safeName, emailRef };
