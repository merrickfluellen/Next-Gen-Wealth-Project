/**
 * reset-password — step 1 of 3
 * POST { email }
 *   → 200 { ok: true, verifyToken: "..." }   (ALWAYS — see "No user enumeration" below)
 *
 * Looks the email up in Supabase, generates a 6-digit code, emails it, and
 * returns an opaque verifyToken the client hands back to confirm-reset.
 *
 * verifyToken = AES-256-GCM( { e: email, x: expiry, n: nonce,
 *                               c: HMAC(nonce|email|code), p: HMAC(email|current pw_hash) } )
 *   - the code is never in the token, only a keyed MAC of it;
 *   - `p` binds the token to the CURRENT password hash, so once the password is
 *     changed the token is dead (single use). It is encrypted because the legacy
 *     pw_hash is only 32 bits — exposing even a MAC of it to the browser is not OK;
 *   - encryption also makes decoy tokens for unknown emails indistinguishable.
 *
 * No user enumeration: unknown email, rate-limited, mail-provider failure and
 * success all return the same body shape (with a decoy token where needed) and
 * are padded to the same minimum response time.
 *
 * Required Netlify env vars:
 *   SUPA_SERVICE_KEY  — Supabase service role key (Project Settings → API → service_role)
 *   SESSION_SECRET    — same secret used by admin-auth (keys derived via HKDF, see lib/crypto.js)
 *   RESEND_API_KEY    — Resend.com API key (resend.com, free tier)
 *   RESEND_FROM       — (optional) verified sender; default onboarding@resend.dev
 */

'use strict';

const https = require('https');
const C     = require('./lib/crypto');

const SUPA_HOST       = 'vtxuvmtnqlxidnswnunx.supabase.co';
const CODE_TTL_MS     = 15 * 60 * 1000;   // 15 minutes (the email says so too)
const MIN_RESPONSE_MS = 1500;             // pad every response to hide which path ran
const EMAIL_RE        = /^[^\s@<>"',;]+@[^\s@<>"',;]+\.[^\s@<>"',;]+$/;

function httpsRequest(method, hostname, path, headers, body, timeoutMs = 8000) {
  return new Promise((resolve) => {
    const data = body ? JSON.stringify(body) : null;
    const req = https.request(
      { hostname, path, method, headers: { ...headers, ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}) } },
      res => {
        let raw = '';
        res.on('data', c => { if (raw.length < 1e6) raw += c; });
        res.on('end', () => resolve({ status: res.statusCode, body: raw }));
      }
    );
    req.setTimeout(timeoutMs, () => req.destroy(new Error('timeout')));
    req.on('error', () => resolve({ status: 0, body: '' }));
    if (data) req.write(data);
    req.end();
  });
}

const escapeHtml = (s) => String(s).replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));

function codeMac(nonce, email, code) {
  return C.hmac('reset-code', `${nonce}|${email}|${code}`).toString('base64url');
}

function pwBinding(email, pwHash) {
  return C.hmac('reset-pw-binding', `${email}|${pwHash == null ? '' : String(pwHash)}`).toString('base64url');
}

/** Real token (code known) or decoy (code=null → random MAC that no 6-digit code can match). */
function makeVerifyToken(email, code, pwHash) {
  const n = C.randomToken(16);
  return C.encryptJSON({
    e: email,
    x: Date.now() + CODE_TTL_MS,
    n,
    c: code ? codeMac(n, email, code) : C.randomToken(32),
    p: code ? pwBinding(email, pwHash) : C.randomToken(32),
  }, { purpose: 'reset-verify' });
}

exports.handler = async (event) => {
  const gate = C.methodGate(event);
  if (gate) return gate;

  const started = Date.now();
  const finish = async (body) => {
    const wait = MIN_RESPONSE_MS + Math.floor(Math.random() * 250) - (Date.now() - started);
    if (wait > 0) await C.sleep(wait);
    return C.respond(event, 200, body);
  };

  const secret = process.env.SESSION_SECRET;
  if (!secret) {
    console.error('reset-password: SESSION_SECRET not configured');
    return finish({ ok: true, verifyToken: '' });
  }

  try {
    const supaKey   = process.env.SUPA_SERVICE_KEY;
    const resendKey = process.env.RESEND_API_KEY;
    const fromAddr  = process.env.RESEND_FROM || 'onboarding@resend.dev';

    const body  = C.parseJsonBody(event, 2048);
    const email = body && typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    if (!email || email.length > 254 || !EMAIL_RE.test(email)) {
      return finish({ ok: true, verifyToken: email && email.length <= 254 ? makeVerifyToken(email, null) : '' });
    }

    const decoy = () => finish({ ok: true, verifyToken: makeVerifyToken(email, null) });

    if (!supaKey || !resendKey) {
      console.error('reset-password: SUPA_SERVICE_KEY or RESEND_API_KEY not configured');
      return decoy();
    }

    // Anti email-bombing / anti-enumeration throttles (best-effort, per warm instance).
    if (C.throttled('reset:ip:' + C.clientIp(event), 10, 15 * 60 * 1000) ||
        C.throttled('reset:email:' + email, 3, 15 * 60 * 1000)) {
      return decoy();
    }

    const lookup = await httpsRequest('GET', SUPA_HOST,
      `/rest/v1/users?email=eq.${encodeURIComponent(email)}&select=email,name,pw_hash&limit=1`,
      { apikey: supaKey, Authorization: `Bearer ${supaKey}`, Accept: 'application/json' });

    let rows = [];
    try { rows = JSON.parse(lookup.body); } catch { rows = []; }
    if (lookup.status < 200 || lookup.status >= 300 || !Array.isArray(rows) || rows.length === 0) {
      return decoy();   // never reveal whether the email exists
    }

    const user     = rows[0];
    const userName = escapeHtml(String(user.name || 'there').slice(0, 60));
    const code     = C.randomDigits(6);
    const token    = makeVerifyToken(email, code, user.pw_hash);

    const send = await httpsRequest('POST', 'api.resend.com', '/emails',
      { Authorization: `Bearer ${resendKey}`, 'Content-Type': 'application/json' },
      {
        from: `InvestEd Pro <${fromAddr}>`,
        to:   [email],
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
      }
    );

    if (send.status < 200 || send.status >= 300) {
      // Logged for the owner; NOT surfaced to the client (a distinct error would reveal the account exists).
      console.error('reset-password: Resend API returned status', send.status);
    }
    return finish({ ok: true, verifyToken: token });

  } catch (err) {
    console.error('reset-password: internal error', err && err.message);
    return finish({ ok: false, error: 'Server error. Please try again.' });
  }
};
