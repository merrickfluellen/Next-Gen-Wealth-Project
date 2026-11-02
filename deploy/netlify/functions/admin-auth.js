/**
 * admin-auth — server-side admin credential check
 * POST { email, password, adminCode } → { ok: boolean, token?: string }
 *
 * Admin credential hashes are read from Netlify environment variables
 * (set in Netlify dashboard → Site configuration → Environment variables):
 *   ADMIN_EMAIL_HASH   — hashPw('email::' + adminEmail.toLowerCase())
 *   ADMIN_PW_HASH      — hashPw('adminpw::' + password)
 *   ADMIN_CODE_HASH    — hashPw('admincode::' + code.toUpperCase())
 *   SESSION_SECRET     — any long random string (used to sign tokens)
 */

const crypto = require('crypto');

function hashPw(str) {
  let h = 5381;
  for (let i = 0; i < str.length; i++) h = ((h << 5) + h + str.charCodeAt(i)) >>> 0;
  return 'h' + h.toString(36) + str.length;
}

function makeToken(secret) {
  const expires = Date.now() + 8 * 60 * 60 * 1000; // 8-hour session
  const payload = `admin::${expires}`;
  const sig = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex')
    .slice(0, 24);
  return `${expires}.${sig}`;
}

exports.handler = async (event) => {
  const headers = {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
  };

  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  let email, password, adminCode;
  try {
    ({ email, password, adminCode } = JSON.parse(event.body || '{}'));
  } catch {
    return { statusCode: 400, headers, body: JSON.stringify({ error: 'Invalid JSON' }) };
  }

  const ADMIN_EMAIL_HASH = process.env.ADMIN_EMAIL_HASH;
  const ADMIN_PW_HASH    = process.env.ADMIN_PW_HASH;
  const ADMIN_CODE_HASH  = process.env.ADMIN_CODE_HASH;
  const SESSION_SECRET   = process.env.SESSION_SECRET;   // no fallback: a known default would let anyone forge admin tokens

  if (!ADMIN_EMAIL_HASH || !ADMIN_PW_HASH || !ADMIN_CODE_HASH || !SESSION_SECRET) {
    console.error('admin-auth: missing env vars');
    return { statusCode: 500, headers, body: JSON.stringify({ error: 'Server misconfigured' }) };
  }

  const emailMatch = email
    ? hashPw('email::' + email.trim().toLowerCase()) === ADMIN_EMAIL_HASH
    : false;
  const pwMatch = password
    ? hashPw('adminpw::' + password) === ADMIN_PW_HASH
    : false;
  const codeMatch = adminCode
    ? hashPw('admincode::' + adminCode.trim().toUpperCase()) === ADMIN_CODE_HASH
    : false;

  const ok = (emailMatch && pwMatch) || codeMatch;

  if (!ok) {
    // Small delay to slow brute-force even if rate limiter is bypassed
    await new Promise(r => setTimeout(r, 400));
    return { statusCode: 401, headers, body: JSON.stringify({ ok: false }) };
  }

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({ ok: true, token: makeToken(SESSION_SECRET) }),
  };
};
