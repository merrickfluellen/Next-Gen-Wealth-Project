/**
 * reset-password — step 1 of 3
 * POST { email }
 *   → { ok: true, verifyToken: "..." }
 *
 * Checks Supabase for the email, generates a 6-digit code, emails it,
 * and returns a signed verifyToken so the client can prove it received the code.
 *
 * Required Netlify env vars:
 *   SUPA_SERVICE_KEY  — Supabase service role key (Project Settings → API → service_role)
 *   SESSION_SECRET    — same secret used by admin-auth
 *   RESEND_API_KEY    — Resend.com API key (resend.com, free tier)
 */

const https  = require('https');
const crypto = require('crypto');

const HEADERS_OK = { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' };

function httpsGet(hostname, path, headers) {
  return new Promise((resolve) => {
    const req = https.request({ hostname, path, method: 'GET', headers }, res => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => { try { resolve(JSON.parse(raw)); } catch { resolve([]); } });
    });
    req.on('error', () => resolve([]));
    req.end();
  });
}

function httpsPost(hostname, path, headers, body) {
  return new Promise((resolve) => {
    const data = JSON.stringify(body);
    const req = https.request(
      { hostname, path, method: 'POST', headers: { ...headers, 'Content-Length': Buffer.byteLength(data) } },
      res => { let raw = ''; res.on('data', c => raw += c); res.on('end', () => resolve(res.statusCode)); }
    );
    req.on('error', () => resolve(500));
    req.write(data);
    req.end();
  });
}

/**
 * Signed token: base64url(email|expires).HMAC(payload|code)
 * The code is NOT inside the token (the browser gets this token, and base64 is readable);
 * it is only mixed into the signature, so the token proves nothing without the emailed code.
 */
function makeVerifyToken(email, code, secret) {
  const expires = Date.now() + 15 * 60 * 1000; // 15 minutes
  const payload = Buffer.from(`${email}|${expires}`).toString('base64url');
  const sig     = crypto.createHmac('sha256', secret).update(`${payload}|${code}`).digest('hex').slice(0, 40);
  return `${payload}.${sig}`;
}

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: HEADERS_OK, body: '' };
  if (event.httpMethod !== 'POST')    return { statusCode: 405, headers: HEADERS_OK, body: JSON.stringify({ error: 'Method not allowed' }) };

  try {
    const supaKey   = process.env.SUPA_SERVICE_KEY;
    const secret    = process.env.SESSION_SECRET;
    const resendKey = process.env.RESEND_API_KEY;
    // RESEND_FROM: set this to a verified sender in your Resend dashboard
    // Default: onboarding@resend.dev works on free tier without domain verification
    const fromAddr  = process.env.RESEND_FROM || 'onboarding@resend.dev';

    // If core env vars missing, silently succeed so UI still advances
    if (!supaKey || !secret || !resendKey) {
      return { statusCode: 200, headers: HEADERS_OK, body: JSON.stringify({ ok: true, verifyToken: '' }) };
    }

    let email;
    try { email = JSON.parse(event.body || '{}').email?.toLowerCase().trim(); } catch { email = ''; }
    if (!email || !email.includes('@')) {
      return { statusCode: 200, headers: HEADERS_OK, body: JSON.stringify({ ok: true, verifyToken: '' }) };
    }

    // Check Supabase — does this email exist?
    const supaHeaders = { apikey: supaKey, Authorization: `Bearer ${supaKey}`, 'Content-Type': 'application/json' };
    const rows = await httpsGet(
      'vtxuvmtnqlxidnswnunx.supabase.co',
      `/rest/v1/users?email=eq.${encodeURIComponent(email)}&select=email,name`,
      supaHeaders
    );

    // Always return ok — never reveal whether email exists
    if (!Array.isArray(rows) || rows.length === 0) {
      return { statusCode: 200, headers: HEADERS_OK, body: JSON.stringify({ ok: true, verifyToken: '' }) };
    }

    const userName = rows[0].name || 'there';

    // Generate 6-digit code
    const code  = String(crypto.randomInt(100000, 999999));
    const token = makeVerifyToken(email, code, secret);

    // Send email via Resend
    const sendStatus = await httpsPost('api.resend.com', '/emails',
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

    // If Resend rejected the send (bad domain, invalid key, etc.), return an error
    if (sendStatus < 200 || sendStatus >= 300) {
      console.error('Resend API returned status:', sendStatus);
      return { statusCode: 200, headers: HEADERS_OK, body: JSON.stringify({ ok: false, error: 'Failed to send email. Check your Resend setup.' }) };
    }

    return { statusCode: 200, headers: HEADERS_OK, body: JSON.stringify({ ok: true, verifyToken: token }) };

  } catch (err) {
    console.error('reset-password error:', err);
    return { statusCode: 200, headers: HEADERS_OK, body: JSON.stringify({ ok: false, error: 'Server error. Please try again.' }) };
  }
};
