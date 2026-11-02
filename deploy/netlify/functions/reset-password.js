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
 * Durable state (table public.password_resets, see SQL below): one row per issued code, keyed by
 * the nonce, holding `attempts` and `used`. confirm-reset claims an attempt slot with a
 * compare-and-swap BEFORE checking the code, so a code can be guessed at most 5 times in total,
 * across every function instance and IP. Issuing a new code retires the older ones for that
 * email, and at most 3 codes per email per hour are emailed (anti email-bombing).
 * If the table does not exist yet, both functions fall back to the old per-instance in-memory
 * limits and log an error on every request — create the table:
 *
 *   create table if not exists public.password_resets (
 *     id         text primary key,                 -- token nonce
 *     email      text not null,
 *     attempts   int  not null default 0,
 *     used       boolean not null default false,
 *     expires_at timestamptz not null,
 *     created_at timestamptz not null default now()
 *   );
 *   create index if not exists password_resets_email_created on public.password_resets (email, created_at desc);
 *   alter table public.password_resets enable row level security;
 *   revoke all on table public.password_resets from anon, authenticated, public;
 *   grant  all on table public.password_resets to service_role;
 *   -- optional housekeeping: delete from public.password_resets where created_at < now() - interval '2 days';
 *
 * No user enumeration: unknown email, rate-limited, mail-provider failure and success all return
 * the same body (with a decoy token where needed) and are padded to the same minimum time.
 *
 * Required Netlify env vars:
 *   SUPA_SERVICE_KEY  — Supabase service role key
 *   SESSION_SECRET    — master secret (keys derived via HKDF, see lib/crypto.js)
 *   RESEND_API_KEY    — Resend.com API key
 *   RESEND_FROM       — (optional) verified sender; default onboarding@resend.dev
 *   SUPABASE_URL      — (optional) see lib/session.js
 */

'use strict';

const C = require('./lib/crypto');
const S = require('./lib/session');
const { withFirewall } = require('./lib/firewall');

const CODE_TTL_MS        = 15 * 60 * 1000;   // 15 minutes (the email says so too)
const MIN_RESPONSE_MS    = 2500;             // pad every response to hide which path ran
const PER_EMAIL_PER_HOUR = 3;

const escapeHtml = (s) => String(s).replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));

function codeMac(nonce, email, code) {
  return C.hmac('reset-code', `${nonce}|${email}|${code}`).toString('base64url');
}
function pwBinding(email, pwHash) {
  return C.hmac('reset-pw-binding', `${email}|${pwHash == null ? '' : String(pwHash)}`).toString('base64url');
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
  const n = String(name || '').replace(/[\p{Cc}\p{Cf}  ]/gu, '').replace(/\s+/g, ' ').trim();
  return escapeHtml([...(n || 'there')].slice(0, 40).join(''));
}

/** Records a new code in password_resets. Returns 'ok' | 'limited' | 'missing' | 'error'. */
async function recordReset(email, nonce, expiry) {
  const since = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  const recent = await S.supa('GET', `password_resets?email=eq.${S.q(email)}&created_at=gte.${S.q(since)}&select=id&limit=${PER_EMAIL_PER_HOUR}`);
  if (storeMissing(recent)) return 'missing';
  if (!S.ok2xx(recent)) return 'error';
  if (S.rows(recent).length >= PER_EMAIL_PER_HOUR) return 'limited';
  // Retire every older open code for this email (only the newest code works).
  const retire = await S.supa('PATCH', `password_resets?email=eq.${S.q(email)}&used=is.false`,
    { body: { used: true }, prefer: 'return=minimal' });
  if (!S.ok2xx(retire)) return 'error';
  const ins = await S.supa('POST', 'password_resets',
    { body: { id: nonce, email, attempts: 0, used: false, expires_at: new Date(expiry).toISOString() }, prefer: 'return=minimal' });
  return S.ok2xx(ins) ? 'ok' : 'error';
}

async function sendEmail(email, userName, code) {
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

  // Cheap per-instance guards (the durable per-email limit is in recordReset).
  if (C.throttled('reset:email:' + email, PER_EMAIL_PER_HOUR, 60 * 60 * 1000)) return decoy();

  const g = await S.getUser(email, 'email,name,pw_hash');
  if (g.error || !g.user) return decoy();   // never reveal whether the email exists

  const code   = C.randomDigits(6);
  const nonce  = C.randomToken(16);
  const expiry = Date.now() + CODE_TTL_MS;

  const rec = await recordReset(email, nonce, expiry);
  if (rec === 'missing') {
    console.error('reset-password: table public.password_resets is missing — using per-instance limits only. Create it (SQL in reset-password.js).');
  } else if (rec !== 'ok') {
    if (rec === 'error') console.error('reset-password: could not record the reset code');
    return decoy();   // no email sent; same response as everything else
  }

  const status = await sendEmail(email, safeName(g.user.name), code);
  if (status < 200 || status >= 300) {
    // Logged for the owner; NOT surfaced to the client (a distinct error would reveal the account exists).
    console.error('reset-password: Resend API returned status', status);
  }
  return finish({ ok: true, verifyToken: makeVerifyToken(email, code, g.user.pw_hash, nonce, expiry) });
}

exports.handler = withFirewall(resetPassword, {
  name: 'reset-password',
  methods: ['POST'],
  rateLimit: { windowMs: 15 * 60 * 1000, max: 10 },
  maxBodyBytes: 1024,
  json: true,
});
exports._internals = { codeMac, pwBinding, safeName };
