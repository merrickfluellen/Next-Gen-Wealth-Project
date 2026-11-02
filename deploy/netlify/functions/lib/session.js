/**
 * lib/session.js — shared helpers for the user-auth functions
 * (auth-signup, auth-login, auth-session, progress, admin-users).
 *
 *   - Supabase REST access with the SERVICE key (server-side only; never sent to the browser).
 *   - Input normalisation (email, name, password) shared by every endpoint, so "Victim@X.com " and
 *     "victim@x.com" are always the same account.
 *   - User session tokens: crypto.sign() with purpose 'user-session'
 *       payload { sub: <email>, ver: <fingerprint of the current pw_hash>, iat, exp }
 *     The client sends it back as `Authorization: Bearer <token>`. `ver` binds the token to the
 *     user's current password hash, so a password change/reset (or deleting the user) revokes every
 *     outstanding session for that user. Rotating SESSION_SECRET revokes all sessions.
 *   - Admin token check (same rules as verify-admin.js).
 *
 * Env: SESSION_SECRET (required), SUPA_SERVICE_KEY (required), SUPABASE_URL (optional, defaults to
 * the project URL already used by app.html / reset-password.js).
 */
'use strict';

const C = require('./crypto');

const DEFAULT_SUPA_URL = 'https://vtxuvmtnqlxidnswnunx.supabase.co';
const SESSION_PURPOSE = 'user-session';
const SESSION_TTL_SECONDS = 30 * 24 * 60 * 60;   // 30 days
const SESSION_REFRESH_AFTER = 7 * 24 * 60 * 60;  // auth-session hands out a fresh token after 7 days
const PW_MIN_NEW = 8, PW_MAX = 128;

// ─── Supabase REST ───────────────────────────────────────────────────────────
function supaBase() {
  const u = String(process.env.SUPABASE_URL || DEFAULT_SUPA_URL).replace(/\/+$/, '');
  if (!/^https:\/\/[a-z0-9.-]+$/i.test(u)) throw new Error('SUPABASE_URL is invalid');
  return u;
}

function configured() {
  return !!(process.env.SUPA_SERVICE_KEY && process.env.SESSION_SECRET);
}

/**
 * Call the Supabase REST API with the service key.
 * Returns { status, data, error } — never throws. status 0 = network error/timeout.
 * `error` is the PostgREST error object ({ code, message, ... }) when status >= 400.
 */
async function supa(method, path, { body, prefer, timeoutMs = 8000 } = {}) {
  const key = process.env.SUPA_SERVICE_KEY;
  if (!key) return { status: 0, data: null, error: { code: 'config' } };
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(supaBase() + '/rest/v1/' + path, {
      method,
      headers: {
        apikey: key,
        Authorization: 'Bearer ' + key,
        Accept: 'application/json',
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...(prefer ? { Prefer: prefer } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: ctrl.signal,
    });
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch { data = null; }
    if (res.status >= 400) return { status: res.status, data: null, error: data && typeof data === 'object' ? data : { code: 'http_' + res.status } };
    return { status: res.status, data, error: null };
  } catch {
    return { status: 0, data: null, error: { code: 'network' } };
  } finally {
    clearTimeout(timer);
  }
}

const ok2xx = (r) => r.status >= 200 && r.status < 300;
const rows = (r) => (ok2xx(r) && Array.isArray(r.data) ? r.data : []);
const isUniqueViolation = (r) => r.status === 409 || (r.error && r.error.code === '23505');
const isMissingColumn = (r) => !!(r.error && (r.error.code === '42703' || r.error.code === 'PGRST204'));
const q = (v) => encodeURIComponent(String(v));

/**
 * Fetch one user row by (normalised) email. Returns:
 *   { user }        exactly one row
 *   { user: null }  no row
 *   { error }       DB error OR more than one row (duplicates must never be guessed between —
 *                   a duplicate row is exactly how C2 could plant a second password for a victim)
 */
async function getUser(email, select = 'email,name,pw_hash,free_access,created_at') {
  const r = await supa('GET', `users?email=eq.${q(email)}&select=${select}&limit=2`);
  if (!ok2xx(r)) return { error: 'db' };
  const list = rows(r);
  if (list.length > 1) { console.error('session: duplicate users rows for one email — run the dedupe in supabase/001_security.sql'); return { error: 'duplicate' }; }
  return { user: list[0] || null };
}

// ─── Input normalisation ─────────────────────────────────────────────────────
// Signup: strict ASCII email (no Unicode lookalikes can ever be registered).
const STRICT_EMAIL_RE = /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
// Login: the old client accepted /^[^\s@]+@[^\s@]+\.[^\s@]+$/, so existing accounts may have
// looser addresses. Exact-match lookup only; no control/format characters.
const LOOSE_EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const CONTROL_RE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}  ]/u;

/** trim + lowercase (exactly what the old client did). Returns '' if not a plausible email. */
function normEmail(v, { strict = false } = {}) {
  if (typeof v !== 'string' || v.length > 320) return '';
  const e = v.trim().toLowerCase();
  if (!e || e.length > 254 || CONTROL_RE.test(e)) return '';
  if (strict) {
    const at = e.lastIndexOf('@');
    if (at < 1 || at > 64 || !STRICT_EMAIL_RE.test(e)) return '';
  } else if (!LOOSE_EMAIL_RE.test(e)) return '';
  return e;
}

/** Display name: NFC, whitespace collapsed, 1–40 chars, no control/format/bidi chars, no < >. */
function normName(v) {
  if (typeof v !== 'string' || v.length > 400) return '';
  const n = v.normalize('NFC').replace(/\s+/g, ' ').trim();
  if (!n || [...n].length > 40 || CONTROL_RE.test(n) || /[<>]/.test(n)) return '';
  return n;
}

/**
 * Password as hashed by scrypt: trimmed (the old client trimmed too, so legacy users who typed a
 * trailing space keep working) and NFC-normalised (same password typed on different keyboards).
 * confirm-reset should use this too once it switches to hashSecret.
 */
function pwForScrypt(pw) { return pw.trim().normalize('NFC'); }
/** Password as the legacy djb2 hash saw it (app.html: hashPw(password.trim())). */
function pwForLegacy(pw) { return pw.trim(); }

function validNewPassword(pw) {
  if (typeof pw !== 'string') return 'Password is required.';
  const t = pwForScrypt(pw);
  if (t.length < PW_MIN_NEW) return `Password must be at least ${PW_MIN_NEW} characters.`;
  if (pw.length > PW_MAX) return `Password must be at most ${PW_MAX} characters.`;
  return '';
}

// ─── Sessions ────────────────────────────────────────────────────────────────
/** Fingerprint of the current pw_hash (changes whenever the password changes). */
function sessionVersion(email, pwHash) {
  return C.hmac('user-session-ver', email + '|' + String(pwHash == null ? '' : pwHash)).toString('base64url').slice(0, 22);
}

function issueSession(user) {
  return C.sign({ sub: user.email, ver: sessionVersion(user.email, user.pw_hash) },
    { purpose: SESSION_PURPOSE, ttlSeconds: SESSION_TTL_SECONDS });
}

/** Extract a Bearer token from the Authorization header ('' if absent/malformed). */
function bearer(event) {
  const h = (event && event.headers) || {};
  let v = '';
  for (const k of Object.keys(h)) if (k.toLowerCase() === 'authorization') v = String(h[k] || '');
  const m = /^Bearer[ ]+([A-Za-z0-9._-]{1,4096})$/.exec(v.trim());
  return m ? m[1] : '';
}

/** Verify signature/expiry/shape only (no DB). Returns payload or null. */
function verifySessionToken(token) {
  const p = C.verify(token, { purpose: SESSION_PURPOSE });
  if (!p || typeof p.sub !== 'string' || typeof p.ver !== 'string') return null;
  if (normEmail(p.sub) !== p.sub) return null;   // only ever issued for normalised emails
  return p;
}

/**
 * Full authentication of a request: valid token AND the user still exists AND the password has not
 * changed since the token was issued. Returns { email, user, payload } or { status, error }.
 */
async function authenticate(event) {
  const payload = verifySessionToken(bearer(event));
  if (!payload) return { status: 401, error: 'Not signed in' };
  const g = await getUser(payload.sub);
  if (g.error) return { status: g.error === 'duplicate' ? 401 : 503, error: g.error === 'duplicate' ? 'Not signed in' : 'Service unavailable' };
  if (!g.user || !C.safeEqual(sessionVersion(payload.sub, g.user.pw_hash), payload.ver)) {
    return { status: 401, error: 'Not signed in' };
  }
  return { email: payload.sub, user: g.user, payload };
}

/** Public view of a user row — never includes pw_hash. */
function publicUser(u) {
  return { name: String(u.name || ''), email: String(u.email || ''), free_access: u.free_access === true };
}

// ─── Admin ───────────────────────────────────────────────────────────────────
/** Must stay identical to credentialVersion() in admin-auth.js / verify-admin.js. */
function adminCredentialVersion(env) {
  return C.hmac('admin-cred-version', [env.ADMIN_EMAIL_HASH, env.ADMIN_PW_HASH, env.ADMIN_CODE_HASH].join('\n'))
    .toString('base64url').slice(0, 22);
}

/** True only for a valid, unexpired admin-session token bound to the CURRENT admin credentials. */
function isAdminToken(token) {
  const env = process.env;
  if (!token || !env.SESSION_SECRET || !env.ADMIN_EMAIL_HASH || !env.ADMIN_PW_HASH || !env.ADMIN_CODE_HASH) return false;
  const p = C.verify(token, { purpose: 'admin-session' });
  return !!p && p.sub === 'admin' && typeof p.cv === 'string' && C.safeEqual(p.cv, adminCredentialVersion(env));
}

// ─── Misc ────────────────────────────────────────────────────────────────────
/** JSON response helper for handlers wrapped by withFirewall (it adds security + CORS headers). */
function json(statusCode, body, headers) {
  return { statusCode, headers: { 'Content-Type': 'application/json; charset=utf-8', ...(headers || {}) }, body: JSON.stringify(body) };
}

/** Wait so that the total time since `started` is at least `minMs` (+ jitter). */
async function padTo(started, minMs, jitterMs = 150) {
  const wait = minMs + Math.floor(Math.random() * jitterMs) - (Date.now() - started);
  if (wait > 0) await C.sleep(wait);
}

module.exports = {
  SESSION_PURPOSE, SESSION_TTL_SECONDS, SESSION_REFRESH_AFTER, PW_MIN_NEW, PW_MAX,
  supa, ok2xx, rows, isUniqueViolation, isMissingColumn, q, getUser, configured,
  normEmail, normName, pwForScrypt, pwForLegacy, validNewPassword,
  sessionVersion, issueSession, bearer, verifySessionToken, authenticate, publicUser,
  adminCredentialVersion, isAdminToken,
  json, padTo,
};
