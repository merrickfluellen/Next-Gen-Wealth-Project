/**
 * progress — read / save the signed-in user's own progress row.
 * The row is ALWAYS chosen by the session token's email; the client never names a user.
 *
 * Every request:  Authorization: Bearer <token>
 *                 X-Expected-User: <email>   optional; if present and not the token's account →
 *                                            409 { error, code:'wrong_user' } (another tab signed in
 *                                            someone else; the app signs this tab out)
 *
 * GET   [?cols=money_quest,world]
 *   200 { progress: { <allow-listed columns> } | null }    null = no row yet
 *   400 { error, code:'bad_column' }        ?cols names a column outside the allow-list
 *   422 { error, code:'column_missing', column? }   column not created in Supabase yet
 *
 * POST or PATCH  { <column>: <value>, ... }   (one or more allow-listed columns, JSON)
 *   200 { ok: true, updated_at }
 *   400 { error, code:'bad_column'|'bad_value'|'empty'|'bad_json', column? }
 *   413 { error, code:'too_large', column? }   a column over its cap (below), or body > 1.3 MB
 *   422 { error, code:'column_missing', column? }
 *
 * Both: 401 not signed in · 409 wrong_user · 429 rate limited (+ Retry-After) · 503 database unavailable.
 *
 * Writable columns, accepted types and size caps (JSON bytes). The caps add up to the whole-row cap
 * ROW_MAX_BYTES (1.25 MB), so no row can grow past it however the columns are written:
 *   lesson_notes 192 KB, portfolio 192 KB          object
 *   completed_lessons 64 KB                        array of strings (≤ 200 chars) / numbers, ≤ 5000
 *   sim_days, sim_target                           number 0..36500, or null
 *   money_quest 192 KB, real_estate 192 KB,
 *   economy 256 KB, world 160 KB                   object or null
 * Numbers anywhere in a value must be finite and below 1e21 in size (400 bad_value otherwise), and
 * numbers smaller than 1e-6 in size are stored as 0: JS writes both in exponent notation, but Postgres
 * prints jsonb numbers in full, so "1e308" (6 bytes in) would be 309 bytes on every read.
 * updated_at is set by the server. A top-level `savedAt` in a JSON column is clamped to now (so a
 * forged far-future savedAt cannot win every future local-vs-cloud merge — audit M7).
 * Keys named __proto__ / constructor / prototype are removed at every depth.
 *
 * The token is checked BEFORE the body is parsed (the firewall only enforces the byte cap here), so
 * an anonymous request cannot make the function parse a large JSON body.
 *
 * Limits (durable, per account): 120 saves/min; 20 reads/min and 120 reads/hour (a full read can
 * be ~1.25 MB, so this bounds the egress one account can cause). Firewall: 600 requests/min per IP.
 */
'use strict';

const S = require('./lib/session');
const RL = require('./lib/ratelimit');
const { withFirewall } = require('./lib/firewall');

const KB = 1024;
const COLUMN_MAX_BYTES = {
  lesson_notes: 192 * KB, portfolio: 192 * KB, completed_lessons: 64 * KB,
  sim_days: 64, sim_target: 64,
  money_quest: 192 * KB, real_estate: 192 * KB, economy: 256 * KB, world: 160 * KB,
};
const ROW_MAX_BYTES = Object.values(COLUMN_MAX_BYTES).reduce((a, b) => a + b, 0);   // ≈ 1.25 MB
const MAX_BODY_BYTES = 1300 * KB;
const MAX_DEPTH = 40;
const LIM = {
  save: { windowSec: 60, max: 120 },
  readMin: { windowSec: 60, max: 20 },
  readHour: { windowSec: 3600, max: 120 },
};

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const simNum = (v) => v === null || (typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= 36500);

const COLUMNS = {
  lesson_notes: isObj,
  portfolio: isObj,
  completed_lessons: (v) => Array.isArray(v) && v.length <= 5000 &&
    v.every((x) => (typeof x === 'number' && Number.isFinite(x)) || (typeof x === 'string' && x.length <= 200)),
  sim_days: simNum,
  sim_target: simNum,
  money_quest: (v) => v === null || isObj(v),
  real_estate: (v) => v === null || isObj(v),
  economy: (v) => v === null || isObj(v),
  world: (v) => v === null || isObj(v),
};
const READABLE = new Set([...Object.keys(COLUMNS), 'updated_at']);
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const BAD_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Deep copy into plain data, dropping dangerous keys. Throws on excessive depth, and on numbers that
 * are not finite or whose shortest form uses exponent notation (see header).
 */
function clean(v, depth = 0) {
  if (depth > MAX_DEPTH) throw new Error('depth');
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new Error('number');
    if (/e/i.test(String(v))) {
      // |v| < 1e-6: floating-point dust such as 0.1 + 0.2 - 0.3 → stored as 0 (never rejected, or one
      // rounding error would stop a whole column from syncing). |v| >= 1e21: no game value is that big.
      if (Math.abs(v) < 1) return 0;
      throw new Error('number');
    }
    return v;
  }
  if (Array.isArray(v)) return v.map((x) => clean(x, depth + 1));
  if (v !== null && typeof v === 'object') {
    const out = {};
    for (const k of Object.keys(v)) {
      if (BAD_KEYS.has(k)) continue;
      Object.defineProperty(out, k, { value: clean(v[k], depth + 1), enumerable: true, writable: true, configurable: true });
    }
    return out;
  }
  return v;
}

function missingColumn(r) {
  const m = r.error && typeof r.error.message === 'string' && /'([a-z_]+)' column|column [a-z_]+\.([a-z_]+)|column "([a-z_]+)"/i.exec(r.error.message);
  const col = m && (m[1] || m[2] || m[3]);
  return col && READABLE.has(col) ? col : undefined;
}

async function getProgress(event, email) {
  const qs = event.queryStringParameters || {};
  let select = '*';
  if (typeof qs.cols === 'string' && qs.cols.trim()) {
    const cols = [...new Set(qs.cols.split(',').map((c) => c.trim()).filter(Boolean))];
    const bad = cols.find((c) => !READABLE.has(c));
    if (bad || cols.length > 20) return S.json(400, { error: 'Unknown column', code: 'bad_column' });
    select = cols.join(',');
  }
  const r = await S.supa('GET', `progress?email=eq.${S.q(email)}&select=${select}&limit=1`);
  if (S.isMissingColumn(r)) return S.json(422, { error: 'Column not available', code: 'column_missing', column: missingColumn(r) });
  if (!S.ok2xx(r)) return S.json(503, { error: 'Service unavailable' });
  const row = S.rows(r)[0];
  if (!row) return S.json(200, { progress: null });
  const out = {};
  for (const k of Object.keys(row)) if (READABLE.has(k)) out[k] = row[k];
  return S.json(200, { progress: out });
}

/** Parse the JSON body (after authentication). Returns the object, or a response to send. */
function parseBody(event) {
  let raw = event.body == null ? '' : String(event.body);
  if (event.isBase64Encoded && raw) raw = Buffer.from(raw, 'base64').toString('utf8');
  if (Buffer.byteLength(raw, 'utf8') > MAX_BODY_BYTES) return { res: S.json(413, { error: 'Request too large', code: 'too_large' }) };
  try {
    const v = raw.trim() ? JSON.parse(raw) : null;
    if (!isObj(v)) throw new Error('not an object');
    return { body: v };
  } catch {
    return { res: S.json(400, { error: 'Invalid JSON', code: 'bad_json' }) };
  }
}

async function saveProgress(event, email) {
  const ct = Object.entries(event.headers || {}).find(([k]) => k.toLowerCase() === 'content-type');
  if (!ct || !/^\s*application\/json\s*(;|$)/i.test(String(ct[1]))) {
    return S.json(415, { error: 'Content-Type must be application/json', code: 'bad_json' });
  }
  const p = parseBody(event);
  if (p.res) return p.res;
  const body = p.body;
  const keys = Object.keys(body);
  if (!keys.length) return S.json(400, { error: 'Nothing to save', code: 'empty' });
  const update = {};
  const nowMs = Date.now();
  for (const k of keys) {
    if (!has(COLUMNS, k)) return S.json(400, { error: 'Unknown column', code: 'bad_column' });
    let v = body[k];
    if (!COLUMNS[k](v)) return S.json(400, { error: 'Invalid value', code: 'bad_value', column: k });
    try { v = clean(v); } catch { return S.json(400, { error: 'Invalid value', code: 'bad_value', column: k }); }
    if (Buffer.byteLength(JSON.stringify(v), 'utf8') > COLUMN_MAX_BYTES[k]) return S.json(413, { error: 'Value too large', code: 'too_large', column: k });
    if (isObj(v) && has(v, 'savedAt')) {
      if (typeof v.savedAt !== 'number' || !Number.isFinite(v.savedAt) || v.savedAt < 0) v.savedAt = 0;
      else if (v.savedAt > nowMs) v.savedAt = nowMs;
    }
    update[k] = v;
  }
  const updated_at = new Date().toISOString();
  update.updated_at = updated_at;

  const r = await S.supa('PATCH', `progress?email=eq.${S.q(email)}&select=email`, { body: update, prefer: 'return=representation' });
  if (S.isMissingColumn(r)) return S.json(422, { error: 'Column not available', code: 'column_missing', column: missingColumn(r) });
  if (!S.ok2xx(r)) return S.json(503, { error: 'Service unavailable' });
  if (S.rows(r).length === 0) {
    // No row yet (account created before progress rows existed) → create it for THIS email only.
    const ins = await S.supa('POST', 'progress', { body: { ...update, email }, prefer: 'return=minimal' });
    if (S.isMissingColumn(ins)) return S.json(422, { error: 'Column not available', code: 'column_missing', column: missingColumn(ins) });
    if (!S.ok2xx(ins) && !S.isUniqueViolation(ins)) return S.json(503, { error: 'Service unavailable' });
    if (S.isUniqueViolation(ins)) {
      const again = await S.supa('PATCH', `progress?email=eq.${S.q(email)}`, { body: update, prefer: 'return=minimal' });
      if (!S.ok2xx(again)) return S.json(503, { error: 'Service unavailable' });
    }
  }
  return S.json(200, { ok: true, updated_at });
}

function headerValue(event, name) {
  for (const [k, v] of Object.entries(event.headers || {})) if (k.toLowerCase() === name) return String(v == null ? '' : v);
  return '';
}

async function progress(event) {
  if (!S.configured()) return S.json(503, { error: 'Service unavailable' });
  // S.authenticate checks the token signature first (no DB, no body parsing) — anonymous and forged
  // requests stop here.
  const a = await S.authenticate(event);
  if (a.error) return S.json(a.status, { error: a.error });

  const expected = headerValue(event, 'x-expected-user');
  if (expected && S.normEmail(expected) !== a.email) {
    return S.json(409, { error: 'This tab is signed in to a different account.', code: 'wrong_user' });
  }

  const method = String(event.httpMethod || 'GET').toUpperCase();
  if (method === 'GET') {
    const [m, h] = await Promise.all([RL.hit('progress-read', a.email, LIM.readMin), RL.hit('progress-read-h', a.email, LIM.readHour)]);
    if (!m.ok || !h.ok) {
      return S.json(429, { error: 'Loading too often. Please wait a moment.' }, { 'Retry-After': String(Math.max(m.retryAfter, h.retryAfter) || 60) });
    }
    return getProgress(event, a.email);
  }
  const rl = await RL.hit('progress-save', a.email, LIM.save);
  if (!rl.ok) return S.json(429, { error: 'Saving too often. Please slow down.' }, { 'Retry-After': String(rl.retryAfter || 30) });
  return saveProgress(event, a.email);
}

exports.handler = withFirewall(progress, {
  name: 'progress',
  methods: ['GET', 'POST', 'PATCH'],
  rateLimit: { windowMs: 60 * 1000, max: 600 },   // per IP (a classroom shares one); per-account limits above
  maxBodyBytes: MAX_BODY_BYTES,
  // The body is parsed by saveProgress AFTER the token is verified (see header).
  json: false,
  // Lesson notes are free text ("sleep(8 hours)", "../", "' or 1=1" …). Values are stored as JSON
  // through PostgREST, never interpolated into SQL/HTML, so the signature filter only adds false positives.
  inspect: false,
});
exports._internals = { COLUMNS, COLUMN_MAX_BYTES, ROW_MAX_BYTES, clean };
