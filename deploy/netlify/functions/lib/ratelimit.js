/**
 * lib/ratelimit.js — shared, durable (cross-instance) rate limiter and global budgets.
 *
 * Counters live in Supabase (table public.rate_counters, written ONLY through the SECURITY DEFINER
 * RPC public.rl_hit, which the service role alone may execute — see supabase/001_security.sql A6).
 * Every Netlify instance therefore shares one counter per key, so limits no longer multiply with
 * cold starts / parallel instances. If the database is unreachable the limiter falls back to a
 * per-instance in-memory counter (same semantics as before), unless `failClosed` is set, in which
 * case the request is refused.
 *
 * ─── API ─────────────────────────────────────────────────────────────────────────────────────────
 *   ipKey(headers) → string
 *       Rate-limit key for the client IP. Prefers x-nf-client-connection-ip (set by Netlify's edge,
 *       not spoofable there), then the first X-Forwarded-For hop, then client-ip.
 *       IPv4 → the full address ("203.0.113.7"). IPv6 → its /64 prefix ("2001:db8:1:2::/64"),
 *       because one client normally controls a whole /64. "::ffff:1.2.3.4" → "1.2.3.4".
 *       Brackets, ports and zone ids ("%eth0") are stripped. Unparseable → "unknown".
 *
 *   await hit(bucket, key, { windowSec, max, failClosed = false }) → { ok, count, retryAfter }
 *       Counts one event for (bucket, key) in a fixed window of `windowSec` seconds and says
 *       whether it is within `max`. `retryAfter` is seconds until the window resets (0 when ok).
 *       Never throws. On a DB error: in-memory fallback, or { ok:false } when failClosed.
 *       Use failClosed for anything that costs money or protects secrets when you prefer
 *       "unavailable" over "unlimited".
 *
 *   await budget(name, { windowSec, max, failClosed = true }) → { ok, count, retryAfter }
 *       A GLOBAL cap (one counter for the whole site), e.g. paid API calls per hour or emails per
 *       day. Same as hit(name, '*', …) but fails closed by default.
 *
 * ─── Examples ────────────────────────────────────────────────────────────────────────────────────
 *   const RL = require('./lib/ratelimit');
 *   const ip = RL.ipKey(event.headers);
 *   const r = await RL.hit('login-ip', ip, { windowSec: 900, max: 30 });
 *   if (!r.ok) return S.json(429, { error: 'Too many attempts' }, { 'Retry-After': String(r.retryAfter) });
 *
 *   // before each paid RentCast call
 *   if (!(await RL.budget('rentcast', { windowSec: 3600, max: 20 })).ok) return fallbackEstimate();
 *   // before sending a reset email
 *   if (!(await RL.budget('reset-email', { windowSec: 86400, max: 80 })).ok) return decoy();
 *
 * Keys are stored as "<bucket>|<windowSec>|<key>" (max 512 chars; longer keys are SHA-256'd), so
 * never put secrets in a key — emails are fine (they are deleted by public.delete_account and expire
 * via the daily pg_cron cleanup).
 *
 * Env: SUPA_SERVICE_KEY / SUPABASE_URL (via lib/session.js). RATE_LIMIT_DB=off forces memory-only
 * (local dev / tests).
 */
'use strict';

const nodeCrypto = require('crypto');

const DB_TIMEOUT_MS = 2500;        // a limiter must never be the slow part of a request
const DB_COOLDOWN_MS = 30 * 1000;  // after a DB failure, skip the DB for this long (no added latency)
const MEM_MAX_KEYS = 10000;
const MAX_WINDOW_SEC = 31 * 24 * 3600;

// ─── IP keys ─────────────────────────────────────────────────────────────────────────────────────
function headerValue(headers, name) {
  if (!headers || typeof headers !== 'object') return '';
  if (headers[name] != null) return String(headers[name]);
  for (const k of Object.keys(headers)) if (k.toLowerCase() === name) return String(headers[k] == null ? '' : headers[k]);
  return '';
}

const V4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function parseV4(s) {
  const m = V4_RE.exec(s);
  if (!m) return null;
  const o = m.slice(1).map(Number);
  if (o.some((n) => n > 255)) return null;
  return o.join('.');
}

/** Expand an IPv6 address to 8 numbers (0–65535), or null. Accepts an embedded dotted IPv4 tail. */
function parseV6(s) {
  if (!/^[0-9a-f:.]+$/i.test(s) || s.length > 45) return null;
  let tail = [];
  const lastColon = s.lastIndexOf(':');
  if (s.indexOf('.') >= 0) {
    const v4 = parseV4(s.slice(lastColon + 1));
    if (!v4) return null;
    const o = v4.split('.').map(Number);
    tail = [(o[0] << 8) | o[1], (o[2] << 8) | o[3]];
    s = s.slice(0, lastColon + 1) + (s[lastColon - 1] === ':' ? '' : '0'); // keep "::" intact
    if (s.endsWith(':0') && s[lastColon - 1] !== ':') s = s.slice(0, -2);
    else if (s.endsWith(':') && !s.endsWith('::')) s = s.slice(0, -1);
  }
  const dbl = s.split('::');
  if (dbl.length > 2) return null;
  const part = (x) => (x === '' ? [] : x.split(':'));
  const head = part(dbl[0]);
  const rest = dbl.length === 2 ? part(dbl[1]) : [];
  if ([...head, ...rest].some((g) => !/^[0-9a-f]{1,4}$/i.test(g))) return null;
  const want = 8 - tail.length;
  let groups;
  if (dbl.length === 2) {
    const fill = want - head.length - rest.length;
    if (fill < 1) return null;
    groups = [...head, ...Array(fill).fill('0'), ...rest];
  } else {
    if (head.length !== want) return null;
    groups = head;
  }
  return [...groups.map((g) => parseInt(g, 16)), ...tail];
}

/** Normalise one raw IP string to a rate-limit key (see header comment). */
function normalizeIp(raw) {
  let s = String(raw || '').trim();
  if (!s || s.length > 100) return 'unknown';
  // [v6]:port or [v6]
  const br = /^\[([^\]]+)\](?::\d+)?$/.exec(s);
  if (br) s = br[1];
  // v4:port
  const v4p = /^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/.exec(s);
  if (v4p) s = v4p[1];
  const zone = s.indexOf('%');
  if (zone >= 0) s = s.slice(0, zone);
  s = s.toLowerCase();

  const v4 = parseV4(s);
  if (v4) return v4;
  const g = parseV6(s);
  if (!g) return 'unknown';
  // IPv4-mapped (::ffff:a.b.c.d) → plain IPv4
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) {
    return [g[6] >> 8, g[6] & 255, g[7] >> 8, g[7] & 255].join('.');
  }
  return g.slice(0, 4).map((x) => x.toString(16)).join(':') + '::/64';
}

/** Rate-limit key for the requesting client (headers in any letter case). */
function ipKey(headers) {
  const nf = headerValue(headers, 'x-nf-client-connection-ip').trim();
  if (nf) return normalizeIp(nf);
  const xff = headerValue(headers, 'x-forwarded-for').split(',')[0].trim();
  if (xff) return normalizeIp(xff);
  const cip = headerValue(headers, 'client-ip').trim();
  if (cip) return normalizeIp(cip);
  return 'unknown';
}

// ─── In-memory fallback (per instance, bounded, never drops a live over-limit counter) ──────────
const mem = new Map();   // fullKey -> { count, resetAt(ms), max }
let memNextScan = 0;

function memMakeRoom(now) {
  if (mem.size < MEM_MAX_KEYS) return true;
  if (now < memNextScan) return false;
  for (const [k, v] of mem) if (v.resetAt <= now) mem.delete(k);          // 1. expired windows
  if (mem.size >= MEM_MAX_KEYS) {                                           // 2. single-hit keys, oldest first
    let budgetToFree = Math.ceil(MEM_MAX_KEYS / 10);
    for (const [k, v] of mem) {
      if (budgetToFree <= 0) break;
      if (v.count <= 1 && v.count < v.max) { mem.delete(k); budgetToFree--; }
    }
  }
  if (mem.size >= MEM_MAX_KEYS) { memNextScan = now + 1000; return false; } // 3. fail closed
  return true;
}

function memHit(fullKey, windowSec, max, now = Date.now()) {
  let e = mem.get(fullKey);
  if (e && e.resetAt <= now) { mem.delete(fullKey); e = null; }
  if (!e) {
    if (!memMakeRoom(now)) return { ok: false, count: max + 1, retryAfter: Math.min(windowSec, 60) };
    e = { count: 0, resetAt: now + windowSec * 1000, max };
    mem.set(fullKey, e);
  }
  if (e.count <= max) e.count++;   // stop counting once over (no unbounded growth)
  const ok = e.count <= max;
  return { ok, count: e.count, retryAfter: ok ? 0 : Math.max(1, Math.ceil((e.resetAt - now) / 1000)) };
}

// ─── Durable (Supabase RPC) ──────────────────────────────────────────────────────────────────────
let dbDownUntil = 0;

function storageKey(bucket, windowSec, key) {
  const k = String(bucket) + '|' + windowSec + '|' + String(key);
  return k.length <= 512 ? k : String(bucket).slice(0, 64) + '|' + windowSec + '|sha256:' +
    nodeCrypto.createHash('sha256').update(String(key)).digest('hex');
}

/** Seconds until the current fixed window (aligned to the epoch, like rl_hit) ends. */
function windowRemaining(windowSec, nowMs = Date.now()) {
  const nowSec = Math.floor(nowMs / 1000);
  return Math.max(1, windowSec - (nowSec % windowSec));
}

async function dbHit(fullKey, windowSec, max) {
  if (process.env.RATE_LIMIT_DB === 'off' || Date.now() < dbDownUntil) return null;
  const S = require('./session');   // lazy: session → crypto → ratelimit must not be a load-time cycle
  if (!process.env.SUPA_SERVICE_KEY) return null;
  const r = await S.supa('POST', 'rpc/rl_hit', {
    body: { p_key: fullKey, p_window_sec: windowSec, p_max: max },
    timeoutMs: DB_TIMEOUT_MS,
  });
  const n = typeof r.data === 'number' ? r.data : Number(r.data);
  if (r.status >= 200 && r.status < 300 && Number.isFinite(n) && n >= 0) return n;
  dbDownUntil = Date.now() + DB_COOLDOWN_MS;
  console.error(`ratelimit: rl_hit failed (status ${r.status}${r.error && r.error.code ? ', ' + r.error.code : ''}); using ${'memory/fail-closed'} for ${DB_COOLDOWN_MS / 1000}s`);
  return null;
}

/**
 * Count one event and check it against the limit. Never throws.
 * @param {string} bucket   what is being limited, e.g. 'login-ip' (keep stable; part of the key)
 * @param {string} key      who, e.g. ipKey(headers) or an email
 * @param {{windowSec:number, max:number, failClosed?:boolean}} opts
 * @returns {Promise<{ok:boolean, count:number, retryAfter:number}>}
 */
async function hit(bucket, key, { windowSec, max, failClosed = false } = {}) {
  const w = Math.floor(Number(windowSec));
  const m = Math.floor(Number(max));
  if (!(w >= 1 && w <= MAX_WINDOW_SEC) || !(m >= 0)) {
    console.error('ratelimit: bad windowSec/max for bucket ' + bucket);
    return { ok: false, count: 0, retryAfter: 60 };   // misconfiguration fails closed
  }
  const fullKey = storageKey(bucket, w, key);
  let n = null;
  try { n = await dbHit(fullKey, w, m); } catch { n = null; }
  if (n !== null) {
    const ok = n <= m;
    return { ok, count: n, retryAfter: ok ? 0 : windowRemaining(w) };
  }
  if (failClosed) return { ok: false, count: 0, retryAfter: Math.min(w, 60) };
  return memHit(fullKey, w, m);
}

/**
 * Global (site-wide) budget, e.g. paid API calls per hour. Fails closed by default.
 * @param {string} name
 * @param {{windowSec:number, max:number, failClosed?:boolean}} opts
 */
function budget(name, { windowSec, max, failClosed = true } = {}) {
  return hit('budget:' + name, '*', { windowSec, max, failClosed });
}

module.exports = {
  ipKey, hit, budget,
  // exposed for tests / other libs; not part of the stable API
  _normalizeIp: normalizeIp,
  _memHit: memHit,
  _reset() { mem.clear(); memNextScan = 0; dbDownUntil = 0; },
  _MEM_MAX_KEYS: MEM_MAX_KEYS,
};
