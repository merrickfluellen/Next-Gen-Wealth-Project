/**
 * confirm-reset — steps 2 & 3 combined
 * POST { email, code, verifyToken, newPassword }
 *   → { ok: true } | { error: "..." }
 *
 * 1. Verifies the signed verifyToken + code to prove email ownership
 * 2. Updates pw_hash in Supabase
 *
 * Required Netlify env vars:
 *   SUPA_SERVICE_KEY  — Supabase service role key
 *   SESSION_SECRET    — same secret used to sign the verifyToken
 */

const https  = require('https');
const crypto = require('crypto');

const HEADERS_OK = { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' };
const SUPA_HOST  = 'vtxuvmtnqlxidnswnunx.supabase.co';

function hashPw(str) {
  let h = 5381;
  for (let i = 0; i < str.length; i++) h = ((h << 5) + h + str.charCodeAt(i)) >>> 0;
  return 'h' + h.toString(36) + str.length;
}

function supaFetch(method, path, key, body) {
  return new Promise((resolve) => {
    const data = body ? JSON.stringify(body) : null;
    const headers = {
      apikey: key,
      Authorization: `Bearer ${key}`,
      'Content-Type': 'application/json',
      Prefer: 'return=minimal',
      ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}),
    };
    const req = https.request({ hostname: SUPA_HOST, path, method, headers }, res => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => resolve({ status: res.statusCode, body: raw }));
    });
    req.on('error', () => resolve({ status: 500, body: '' }));
    if (data) req.write(data);
    req.end();
  });
}

/**
 * Verify the signed token against the code the user typed.
 * Token format: base64url(email|expires).HMAC(payload|code) — the code is never inside the token.
 */
function verifyCodeToken(verifyToken, email, enteredCode, secret) {
  const parts = verifyToken.split('.');
  if (parts.length !== 2) return { ok: false, reason: 'invalid' };

  const [payload, sig] = parts;

  // Decode payload
  let tokenEmail, expiresStr;
  try {
    [tokenEmail, expiresStr] = Buffer.from(payload, 'base64url').toString().split('|');
  } catch { return { ok: false, reason: 'invalid' }; }
  if (!tokenEmail || !expiresStr) return { ok: false, reason: 'invalid' };

  // Check email matches
  if (tokenEmail.toLowerCase() !== email.toLowerCase()) return { ok: false, reason: 'invalid' };

  // Check expiry
  if (Date.now() > parseInt(expiresStr)) return { ok: false, reason: 'expired' };

  // The signature only matches if the typed code is the emailed code (timing-safe)
  const code = String(enteredCode).trim();
  if (!/^\d{6}$/.test(code)) return { ok: false, reason: 'wrong_code' };
  const expectedSig = crypto.createHmac('sha256', secret).update(`${payload}|${code}`).digest('hex').slice(0, 40);
  try {
    if (!crypto.timingSafeEqual(Buffer.from(sig, 'utf8'), Buffer.from(expectedSig, 'utf8'))) {
      return { ok: false, reason: 'wrong_code' };
    }
  } catch { return { ok: false, reason: 'wrong_code' }; }

  return { ok: true };
}

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: HEADERS_OK, body: '' };
  if (event.httpMethod !== 'POST')    return { statusCode: 405, headers: HEADERS_OK, body: JSON.stringify({ error: 'Method not allowed' }) };

  try {
    const supaKey = process.env.SUPA_SERVICE_KEY;
    const secret  = process.env.SESSION_SECRET;
    if (!supaKey || !secret) return { statusCode: 200, headers: HEADERS_OK, body: JSON.stringify({ error: 'Server misconfigured — contact support.' }) };

    let email, code, verifyToken, newPassword;
    try {
      const b    = JSON.parse(event.body || '{}');
      email       = b.email?.toLowerCase().trim();
      code        = String(b.code || '').trim();
      verifyToken = b.verifyToken || '';
      newPassword = b.newPassword || '';
    } catch {
      return { statusCode: 200, headers: HEADERS_OK, body: JSON.stringify({ error: 'Invalid request.' }) };
    }

    // No token means no code was sent (unknown email or email not delivered); send them back to step 1
    if (email && !verifyToken) {
      return { statusCode: 200, headers: HEADERS_OK, body: JSON.stringify({ error: 'Invalid or expired code. Check that the email is the one on your account, then request a new code.' }) };
    }

    if (!email || !code || !verifyToken || !newPassword) {
      return { statusCode: 200, headers: HEADERS_OK, body: JSON.stringify({ error: 'Missing required fields.' }) };
    }

    if (newPassword.length < 6) {
      return { statusCode: 200, headers: HEADERS_OK, body: JSON.stringify({ error: 'Password must be at least 6 characters.' }) };
    }

    // Verify the code + token
    const check = verifyCodeToken(verifyToken, email, code, secret);
    if (!check.ok) {
      const msg = check.reason === 'expired'
        ? 'This code has expired. Please request a new one.'
        : check.reason === 'wrong_code'
          ? 'Incorrect code. Check your email and try again.'
          : 'Invalid request. Please start over.';
      return { statusCode: 200, headers: HEADERS_OK, body: JSON.stringify({ error: msg }) };
    }

    // Update password in Supabase
    const newHash = hashPw(newPassword.trim());
    const result  = await supaFetch(
      'PATCH',
      `/rest/v1/users?email=eq.${encodeURIComponent(email)}`,
      supaKey,
      { pw_hash: newHash }
    );

    if (result.status >= 200 && result.status < 300) {
      return { statusCode: 200, headers: HEADERS_OK, body: JSON.stringify({ ok: true }) };
    }
    return { statusCode: 200, headers: HEADERS_OK, body: JSON.stringify({ error: 'Failed to update password. Please try again.' }) };

  } catch (err) {
    console.error('confirm-reset error:', err);
    return { statusCode: 200, headers: HEADERS_OK, body: JSON.stringify({ error: 'Server error. Please try again.' }) };
  }
};
