/**
 * verify-admin — validate a previously issued admin session token
 * POST { token: string } → { ok: boolean }
 *
 * Requires the same SESSION_SECRET env var as admin-auth.js.
 * The client calls this on page load to restore admin sessions
 * without ever storing hashes in the browser.
 */

const crypto = require('crypto');

exports.handler = async (event) => {
  const headers = {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
  };

  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  let token;
  try {
    ({ token } = JSON.parse(event.body || '{}'));
  } catch {
    return { statusCode: 400, headers, body: JSON.stringify({ error: 'Invalid JSON' }) };
  }

  if (!token || typeof token !== 'string') {
    return { statusCode: 200, headers, body: JSON.stringify({ ok: false }) };
  }

  const SESSION_SECRET = process.env.SESSION_SECRET;
  if (!SESSION_SECRET) return { statusCode: 200, headers, body: JSON.stringify({ ok: false }) };   // fail closed

  const [expiresStr, sig] = token.split('.');
  const expires = parseInt(expiresStr, 10);

  if (!expires || !sig || Date.now() > expires) {
    return { statusCode: 200, headers, body: JSON.stringify({ ok: false }) };
  }

  const payload = `admin::${expires}`;
  const expected = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(payload)
    .digest('hex')
    .slice(0, 24);

  // Constant-time comparison to prevent timing attacks
  const ok = sig.length === expected.length &&
    crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));

  return { statusCode: 200, headers, body: JSON.stringify({ ok }) };
};
