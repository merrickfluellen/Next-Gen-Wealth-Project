/**
 * firewall — a small application-layer firewall for Netlify Functions.
 *
 * Netlify already provides the network edge (TLS, DDoS absorption, CDN). This wrapper adds the
 * per-function checks the edge cannot know about: allowed methods, origin allowlist, body size,
 * JSON validity, per-IP rate limiting, crude attack/bad-bot filtering, security headers, and a
 * last-resort error handler that never leaks stack traces.
 *
 * Usage (Node built-ins only, no npm deps):
 *
 *   const { withFirewall } = require('./lib/firewall');
 *   exports.handler = withFirewall(async (event, context) => {
 *     const { code } = event.jsonBody;            // already parsed when json: true
 *     return { statusCode: 200, body: JSON.stringify({ ok: true }) };
 *   }, { methods: ['POST'], rateLimit: { windowMs: 60_000, max: 30 }, maxBodyBytes: 4096 });
 *
 * Origin allowlist: env ALLOWED_ORIGINS (comma-separated, e.g. "https://example.com,https://www.example.com").
 * When unset it defaults to the origins Netlify injects at runtime: URL, DEPLOY_PRIME_URL, DEPLOY_URL
 * (plus localhost when running under `netlify dev`). Requests WITHOUT an Origin header (curl, same-origin
 * GET navigations, server-to-server) are allowed — an Origin check only stops cross-site browsers.
 *
 * RATE LIMITING: by default counters live in memory of one warm function instance (per-instance,
 * best-effort: parallel instances / cold starts each start from zero). Pass `durable: true` (or
 * `durable: { bucket: 'name' }`) to ALSO count every request in the shared Supabase counter
 * (lib/ratelimit.js → public.rl_hit), which holds across instances. The in-memory check runs first
 * (cheap rejection); the durable one adds one small DB round-trip per request.
 * Keys are lib/ratelimit.js ipKey(): full IPv4 address, or the /64 prefix for IPv6.
 *
 * Regression check for the attack signatures (catastrophic backtracking / ReDoS):
 *   node deploy/netlify/functions/lib/firewall.js selftest     (exit code 1 on failure)
 */
'use strict';

const RL = require('./ratelimit');

const DEFAULT_METHODS = ['GET'];
const DEFAULT_MAX_BODY = 16 * 1024; // 16 KB
const MAX_TRACKED_KEYS = 5000;      // bounds memory used by each rate limiter
const MAX_SCAN_CHARS = 4096;        // attack signatures only look at the first 4 KB (bounds CPU)

/** Headers added to every response the wrapper returns. */
const SECURITY_HEADERS = {
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
};

/** User agents of well-known scanners / attack tools (never matches real browsers). */
const BAD_BOT_RE = /\b(sqlmap|nikto|nmap|masscan|zgrab|acunetix|nessus|openvas|wpscan|dirbuster|gobuster|ffuf|nuclei|jaeles|havij|netsparker|w3af|commix|xsstrike)\b/i;

/**
 * High-confidence attack signatures checked against the path, query string and body.
 * Deliberately conservative: each pattern is something no legitimate MoneyQuest request contains.
 */
const ATTACK_PATTERNS = [
  /\$\{\s*jndi\s*:/i,                         // Log4Shell
  /<\s*script[\s>\/]/i,                       // reflected XSS probe
  /\bjavascript\s*:/i,
  /(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f)/i, // path traversal
  /\/etc\/(passwd|shadow)|\bwin\.ini\b/i,
  // SQL injection. The comment branch can never contain "*/", so each input has
  // exactly one parse; the old /\*.*?\*/ form backtracked exponentially (ReDoS).
  /\bunion(?:\s|\/\*[^*]*\*+(?:[^\/*][^*]*\*+)*\/)+(?:all\s+)?select\b/i,
  /'\s*or\s+'?\d+'?\s*=\s*'?\d+/i,
  /;\s*(drop|truncate)\s+table\b/i,
  /\b(sleep|benchmark|pg_sleep)\s*\(\s*\d+/i,
  /\x00|%00/,                                 // null byte
];

/** Lower-cases header names so lookups work regardless of how the platform delivered them. */
function lowerHeaders(h) {
  const out = {};
  for (const [k, v] of Object.entries(h || {})) out[k.toLowerCase()] = v;
  return out;
}

/**
 * Client key for rate limiting: Netlify's own header first, then the first X-Forwarded-For hop;
 * IPv6 is reduced to its /64 (see lib/ratelimit.js ipKey).
 */
function clientIp(headers) {
  return RL.ipKey(headers || {});
}

/** Decode %XX escapes one at a time, so a stray "%" cannot make the whole decode fail (bypass). */
function lenientDecode(s) {
  return s.replace(/%([0-9a-f]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

/** String values (and keys) of a parsed JSON body, joined, up to `limit` chars — catches \u-escaped payloads. */
function jsonStrings(v, limit) {
  const out = [];
  let len = 0;
  const stack = [v];
  let steps = 0;
  while (stack.length && len < limit && steps++ < 10000) {
    const x = stack.pop();
    if (typeof x === 'string') { out.push(x); len += x.length + 1; }
    else if (x && typeof x === 'object') {
      if (Array.isArray(x)) { for (let i = x.length - 1; i >= 0; i--) stack.push(x[i]); }
      else for (const [k, val] of Object.entries(x)) { stack.push(val); stack.push(k); }
    }
  }
  return out.join(' ').slice(0, limit);
}

/** True when any signature matches. Input is capped to MAX_SCAN_CHARS. */
function matchesAttack(text) {
  const t = String(text).slice(0, MAX_SCAN_CHARS);
  const d = lenientDecode(t);
  return ATTACK_PATTERNS.some((re) => re.test(t) || (d !== t && re.test(d)));
}

/** Handler's Vary (any case) + Origin. */
function mergeVary(h) {
  const vals = new Set(['Origin']);
  for (const [k, v] of Object.entries(h || {})) {
    if (k.toLowerCase() === 'vary') String(v).split(',').map((x) => x.trim()).filter(Boolean).forEach((x) => vals.add(x));
  }
  return [...vals].join(', ');
}

/** Drop handler headers whose name (any case) we always set ourselves. */
function stripManagedHeaders(h) {
  const out = {};
  if (!h || typeof h !== 'object') return out;
  const managed = new Set([...Object.keys(SECURITY_HEADERS), 'Vary'].map((k) => k.toLowerCase()));
  for (const [k, v] of Object.entries(h)) {
    const lk = k.toLowerCase();
    if (lk.startsWith('access-control-') || managed.has(lk)) continue;
    out[k] = v;
  }
  return out;
}

/** Normalises "https://Example.com/" → "https://example.com" (scheme + host + port only). */
function normOrigin(o) {
  try { return new URL(String(o).trim()).origin.toLowerCase(); } catch { return ''; }
}

/** Origins allowed to call functions from a browser. Read per call so env changes in tests apply. */
function allowedOrigins(extra) {
  const env = process.env.ALLOWED_ORIGINS;
  const list = env
    ? env.split(',')
    : [process.env.URL, process.env.DEPLOY_PRIME_URL, process.env.DEPLOY_URL];
  if (!env && (process.env.NETLIFY_DEV === 'true' || process.env.CONTEXT === 'dev')) {
    list.push('http://localhost:8888', 'http://127.0.0.1:8888');
  }
  return new Set([...list, ...(extra || [])].map(normOrigin).filter(Boolean));
}

/**
 * Creates an in-memory sliding-window rate limiter (per warm instance).
 *
 * Memory is bounded by `maxKeys`. When full, room is made by dropping (1) idle keys whose window
 * has passed, then (2) keys holding a single hit, oldest first. A key that has 2+ hits in its
 * window — in particular one at/over its limit — is NEVER evicted: flooding the map with fresh
 * keys cannot reset a victim's (or the attacker's own) counter. If no room can be made the new
 * key is refused (fail closed: { ok:false, full:true }) until something expires.
 *
 * @param {{windowMs:number, max:number, maxKeys?:number}} cfg
 * @returns {(key:string, now?:number) => {ok:boolean, retryAfter:number, full?:boolean}}
 */
function createRateLimiter({ windowMs, max, maxKeys = MAX_TRACKED_KEYS }) {
  const hits = new Map(); // key -> array of timestamps (ms), oldest first
  let nextScan = 0;       // after a scan that freed nothing, don't rescan for 1 s (bounds CPU)

  function makeRoom(now, since) {
    if (hits.size < maxKeys) return true;
    if (now < nextScan) return false;
    for (const [k, a] of hits) if (!a.length || a[a.length - 1] <= since) hits.delete(k);
    if (hits.size >= maxKeys) {
      let toFree = Math.max(1, Math.ceil(maxKeys / 10));
      for (const [k, a] of hits) {
        if (toFree <= 0) break;
        if (a.length <= 1 && a.length < max) { hits.delete(k); toFree--; }
      }
    }
    if (hits.size >= maxKeys) { nextScan = now + 1000; return false; }
    return true;
  }

  return function check(key, now = Date.now()) {
    const since = now - windowMs;
    let arr = hits.get(key);
    if (arr) {
      while (arr.length && arr[0] <= since) arr.shift();
    } else {
      if (!makeRoom(now, since)) {
        return { ok: false, retryAfter: Math.max(1, Math.min(60, Math.ceil(windowMs / 1000))), full: true };
      }
      arr = [];
      hits.set(key, arr);
    }
    if (arr.length >= max) {
      return { ok: false, retryAfter: Math.max(1, Math.ceil((arr[0] + windowMs - now) / 1000)) };
    }
    arr.push(now);
    return { ok: true, retryAfter: 0 };
  };
}

/**
 * Wraps a Netlify function handler with firewall checks.
 *
 * @param {(event:object, context:object) => Promise<object>} handler  the real handler
 * @param {object} [options]
 * @param {string[]} [options.methods=['GET']]       allowed methods (OPTIONS is always answered as preflight)
 * @param {{windowMs:number,max:number}|false} [options.rateLimit={windowMs:60000,max:60}] per-IP limit
 * @param {boolean|{bucket?:string, failClosed?:boolean}} [options.durable=false] also enforce rateLimit
 *        across instances via lib/ratelimit.js hit() (bucket defaults to 'fw:' + name)
 * @param {number} [options.maxBodyBytes=16384]      reject larger bodies with 413
 * @param {boolean} [options.json]                   require/parse a JSON body (default: true for POST/PUT/PATCH)
 * @param {string[]} [options.allowedOrigins]        extra origins on top of ALLOWED_ORIGINS / Netlify URLs
 * @param {boolean} [options.requireOrigin=false]    reject browser-less requests (no Origin header)
 * @param {boolean} [options.inspect=true]           run the attack-signature / bad-bot filter
 * @param {string} [options.cacheControl='no-store'] Cache-Control for successful responses (errors are always no-store)
 * @param {string} [options.name]                    label used in logs
 * @returns {(event:object, context:object) => Promise<object>}
 */
function withFirewall(handler, options = {}) {
  const methods = (options.methods || DEFAULT_METHODS).map((m) => m.toUpperCase());
  const maxBody = options.maxBodyBytes ?? DEFAULT_MAX_BODY;
  const wantsJson = options.json ?? methods.some((m) => ['POST', 'PUT', 'PATCH'].includes(m));
  const inspect = options.inspect !== false;
  const name = options.name || 'function';
  const rlCfg = options.rateLimit === false ? null : (options.rateLimit || { windowMs: 60_000, max: 60 });
  const limiter = rlCfg ? createRateLimiter(rlCfg) : null;
  const durable = rlCfg && options.durable
    ? {
        bucket: (typeof options.durable === 'object' && options.durable.bucket) || 'fw:' + name,
        failClosed: typeof options.durable === 'object' && options.durable.failClosed === true,
        windowSec: Math.max(1, Math.ceil(rlCfg.windowMs / 1000)),
        max: rlCfg.max,
      }
    : null;

  return async function firewalled(event = {}, context = {}) {
    const headers = lowerHeaders(event.headers);
    const method = String(event.httpMethod || 'GET').toUpperCase();
    const origin = headers.origin ? normOrigin(headers.origin) : '';
    const allowed = allowedOrigins(options.allowedOrigins);
    const originOk = !headers.origin || (origin && allowed.has(origin));

    // CORS headers only ever echo an allow-listed origin (never "*"). Handler-supplied
    // Access-Control-* headers are always stripped (stripManagedHeaders), so a handler can't add "*".
    const cors = originOk && origin
      ? { 'Access-Control-Allow-Origin': origin, Vary: 'Origin' }
      : { Vary: 'Origin' };
    const reply = (statusCode, body, extra) => ({
      statusCode,
      headers: { 'Content-Type': 'application/json', ...SECURITY_HEADERS, ...cors, ...extra },
      body: body === null ? '' : JSON.stringify(body),
    });

    try {
      if (!originOk || (options.requireOrigin && !headers.origin)) {
        return reply(403, { error: 'Forbidden' });
      }

      if (method === 'OPTIONS') {
        return reply(204, null, {
          'Access-Control-Allow-Methods': [...methods, 'OPTIONS'].join(', '),
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
          'Access-Control-Max-Age': '600',
        });
      }
      if (!methods.includes(method)) {
        return reply(405, { error: 'Method not allowed' }, { Allow: [...methods, 'OPTIONS'].join(', ') });
      }

      if (limiter) {
        const ip = clientIp(headers);
        let rl = limiter(ip);
        if (rl.ok && durable) {
          rl = await RL.hit(durable.bucket, ip, { windowSec: durable.windowSec, max: durable.max, failClosed: durable.failClosed });
        }
        if (!rl.ok) {
          return reply(429, { error: 'Too many requests. Please wait and try again.' },
            { 'Retry-After': String(rl.retryAfter) });
        }
      }

      // Body: decode, size-cap, scan, parse.
      let raw = event.body == null ? '' : String(event.body);
      if (event.isBase64Encoded && raw) raw = Buffer.from(raw, 'base64').toString('utf8');
      if (Buffer.byteLength(raw, 'utf8') > maxBody) {
        return reply(413, { error: 'Request too large' });
      }

      const parseJson = wantsJson && method !== 'GET' && method !== 'HEAD';
      let parsed;
      if (parseJson) {
        try {
          parsed = raw.trim() ? JSON.parse(raw) : {};
          if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not an object');
        } catch {
          return reply(400, { error: 'Invalid JSON' });
        }
      }

      if (inspect) {
        const ua = String(headers['user-agent'] || '').slice(0, 1024);
        // Each part is capped separately so a long body can't push the path/query out of the scan.
        let q = String(event.rawQuery || '');
        if (!q && event.queryStringParameters) q = Object.values(event.queryStringParameters).join(' ');
        const parts = [String(event.path || ''), q, raw];
        if (parsed) parts.push(jsonStrings(parsed, MAX_SCAN_CHARS));   // \u-escaped payloads
        if (BAD_BOT_RE.test(ua) || parts.some((p) => p && matchesAttack(p))) {
          console.warn(`[firewall:${name}] blocked suspicious request from ${clientIp(headers)}`);
          return reply(403, { error: 'Forbidden' });
        }
      }

      if (parseJson) event.jsonBody = parsed;

      const res = (await handler(event, context)) || {};
      const multi = res.multiValueHeaders ? stripManagedHeaders(res.multiValueHeaders) : undefined;
      return {
        ...res,
        ...(multi ? { multiValueHeaders: multi } : {}),
        statusCode: res.statusCode || 200,
        // Handler headers win for Content-Type etc., but security headers (+ no-store unless
        // options.cacheControl says otherwise) always apply
        // and CORS is always the firewall's (never a handler's "*").
        headers: {
          'Content-Type': 'application/json',
          ...stripManagedHeaders(res.headers),
          ...SECURITY_HEADERS,
          ...(options.cacheControl ? { 'Cache-Control': options.cacheControl } : {}),
          ...cors,
          Vary: mergeVary(res.headers),
        },
      };
    } catch (err) {
      // Log only the message — never the event (it may hold codes, passwords or tokens).
      console.error(`[firewall:${name}] unhandled error: ${err && err.message ? err.message : 'unknown'}`);
      return reply(500, { error: 'Internal error' });
    }
  };
}

/**
 * ReDoS regression check: every signature must stay linear. Each pattern is timed against 50 KB
 * adversarial strings (the production scan is capped at 4 KB, this tests the patterns themselves).
 * Returns [{ pattern, input, ms }] for every case slower than `limitMs`.
 */
function selfTest(limitMs = 50) {
  const N = 50 * 1024;
  const fill = (unit) => unit.repeat(Math.ceil(N / unit.length)).slice(0, N);
  const inputs = {
    'union+comments': 'union' + fill('/**/') + 'x',
    'union+open-comments': 'union' + fill('/*') + 'x',
    'union+stars': 'union /*' + fill('*') + 'x',
    'union+spaces': 'union' + fill(' ') + 'x',
    'unions': fill('union '),
    'quote-or': fill("' or "),
    'quote-spaces': "'" + fill(' ') + 'or 1=',
    'or-digits': "' or 1" + fill('1') + 'x',
    'sleep(': fill('sleep ('),
    'semicolon-drop': fill('; drop '),
    'jndi': fill('${ jndi'),
    'script': fill('< script'),
    'javascript': fill('javascript '),
    'traversal': fill('..%2e%2'),
    'etc': fill('/etc/'),
    'percent': fill('%'),
    'word-chars': fill('a'),
    'mixed': fill("union/*a*/ ' or '1'='"),
  };
  const slow = [];
  for (const re of ATTACK_PATTERNS) {
    for (const [label, s] of Object.entries(inputs)) {
      const t0 = process.hrtime.bigint();
      re.test(s);
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      if (ms > limitMs) slow.push({ pattern: String(re), input: label, ms: Math.round(ms) });
    }
  }
  return slow;
}

module.exports = {
  withFirewall, createRateLimiter, clientIp, allowedOrigins, SECURITY_HEADERS,
  ATTACK_PATTERNS, matchesAttack, selfTest, MAX_SCAN_CHARS,
};

if (require.main === module) {
  if (process.argv[2] === 'selftest') {
    const slow = selfTest();
    if (slow.length) { console.error('firewall selftest FAILED (super-linear signatures):', slow); process.exitCode = 1; }
    else console.log(`firewall selftest ok: ${ATTACK_PATTERNS.length} signatures linear on 50 KB inputs`);
  } else {
    console.log('usage: node lib/firewall.js selftest');
    process.exitCode = 1;
  }
}
