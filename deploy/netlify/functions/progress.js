/**
 * progress — read / save the signed-in user's own progress row.
 * The row is ALWAYS chosen by the session token's email; the client never names a user.
 *
 * GET   [?cols=money_quest,world]   (header Authorization: Bearer <token>)
 *   200 { progress: { <allow-listed columns> } | null }    null = no row yet
 *   400 { error, code:'bad_column' }        ?cols names a column outside the allow-list
 *   422 { error, code:'column_missing', column? }   column not created in Supabase yet
 *
 * POST or PATCH  { <column>: <value>, ... }   (one or more allow-listed columns)
 *   200 { ok: true, updated_at }
 *   400 { error, code:'bad_column'|'bad_value'|'empty', column? }
 *   413 { error, code:'too_large', column? }   any one column > 256 KB of JSON, or body > 1.5 MB
 *   422 { error, code:'column_missing', column? }
 *
 * Both: 401 not signed in · 429 rate limited · 503 database unavailable.
 *
 * Writable columns and their accepted types:
 *   lesson_notes, portfolio                       object
 *   completed_lessons                             array of strings/numbers (≤ 5000)
 *   sim_days, sim_target                          number 0..36500, or null
 *   money_quest, real_estate, economy, world      object or null
 * updated_at is set by the server. A top-level `savedAt` in a JSON column is clamped to now (so a
 * forged far-future savedAt cannot win every future local-vs-cloud merge — audit M7).
 * Keys named __proto__ / constructor / prototype are removed at every depth.
 */
'use strict';

const S = require('./lib/session');
const { withFirewall, createRateLimiter } = require('./lib/firewall');

const FIELD_MAX_BYTES = 256 * 1024;
const MAX_DEPTH = 40;
const perUser = createRateLimiter({ windowMs: 60 * 1000, max: 120 });

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

/** Deep copy into null-prototype-free plain data, dropping dangerous keys. Throws on excessive depth. */
function clean(v, depth = 0) {
  if (depth > MAX_DEPTH) throw new Error('depth');
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

async function saveProgress(event, email) {
  const body = event.jsonBody;
  if (!isObj(body)) return S.json(400, { error: 'Invalid body', code: 'bad_value' });
  const keys = Object.keys(body);
  if (!keys.length) return S.json(400, { error: 'Nothing to save', code: 'empty' });
  const update = {};
  const nowMs = Date.now();
  for (const k of keys) {
    if (!has(COLUMNS, k)) return S.json(400, { error: 'Unknown column', code: 'bad_column' });
    let v = body[k];
    if (!COLUMNS[k](v)) return S.json(400, { error: 'Invalid value', code: 'bad_value', column: k });
    try { v = clean(v); } catch { return S.json(400, { error: 'Value nested too deeply', code: 'bad_value', column: k }); }
    if (Buffer.byteLength(JSON.stringify(v), 'utf8') > FIELD_MAX_BYTES) return S.json(413, { error: 'Value too large', code: 'too_large', column: k });
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

async function progress(event) {
  if (!S.configured()) return S.json(503, { error: 'Service unavailable' });
  const a = await S.authenticate(event);
  if (a.error) return S.json(a.status, { error: a.error });
  if (!perUser(a.email).ok) return S.json(429, { error: 'Saving too often. Please slow down.' }, { 'Retry-After': '30' });
  const method = String(event.httpMethod || 'GET').toUpperCase();
  return method === 'GET' ? getProgress(event, a.email) : saveProgress(event, a.email);
}

exports.handler = withFirewall(progress, {
  name: 'progress',
  methods: ['GET', 'POST', 'PATCH'],
  rateLimit: { windowMs: 60 * 1000, max: 600 },   // per IP (a classroom shares one); per user is 120/min
  maxBodyBytes: 1536 * 1024,
  json: true,
  // Lesson notes are free text ("sleep(8 hours)", "../", "' or 1=1" …). Values are stored as JSON
  // through PostgREST, never interpolated into SQL/HTML, so the signature filter only adds false positives.
  inspect: false,
});
exports._internals = { COLUMNS, clean };
