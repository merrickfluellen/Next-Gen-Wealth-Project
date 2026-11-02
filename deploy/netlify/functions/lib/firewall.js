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
 * RATE LIMITING IS BEST-EFFORT: counters live in memory of one warm function instance. Netlify may run
 * several instances in parallel and recycles them, so a determined attacker spread across cold starts can
 * exceed the limit. It reliably stops casual abuse and naive brute-force loops; for hard guarantees use a
 * shared store (e.g. Netlify Blobs / Supabase / Redis).
 */
'use strict';

const DEFAULT_METHODS = ['GET'];
const DEFAULT_MAX_BODY = 16 * 1024; // 16 KB
const MAX_TRACKED_KEYS = 5000;      // bounds memory used by the rate limiter

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

/** Best-guess client IP: Netlify's own header first, then the first X-Forwarded-For hop. */
function clientIp(headers) {
  const nf = headers['x-nf-client-connection-ip'];
  if (nf) return String(nf).trim();
  const xff = headers['x-forwarded-for'];
  if (xff) return String(xff).split(',')[0].trim();
  return headers['client-ip'] || 'unknown';
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
 * Creates an in-memory sliding-window rate limiter.
 * @param {{windowMs:number, max:number}} cfg
 * @returns {(key:string, now?:number) => {ok:boolean, retryAfter:number}}
 */
function createRateLimiter({ windowMs, max }) {
  const hits = new Map(); // key -> array of timestamps (ms), oldest first
  return function check(key, now = Date.now()) {
    const since = now - windowMs;
    let arr = hits.get(key);
    if (arr) {
      while (arr.length && arr[0] <= since) arr.shift();
    } else {
      if (hits.size >= MAX_TRACKED_KEYS) {
        // Drop idle keys first; if still full, evict the oldest-inserted key.
        for (const [k, a] of hits) if (!a.length || a[a.length - 1] <= since) hits.delete(k);
        if (hits.size >= MAX_TRACKED_KEYS) hits.delete(hits.keys().next().value);
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
  const limiter = options.rateLimit === false
    ? null
    : createRateLimiter(options.rateLimit || { windowMs: 60_000, max: 60 });

  return async function firewalled(event = {}, context = {}) {
    const headers = lowerHeaders(event.headers);
    const method = String(event.httpMethod || 'GET').toUpperCase();
    const origin = headers.origin ? normOrigin(headers.origin) : '';
    const allowed = allowedOrigins(options.allowedOrigins);
    const originOk = !headers.origin || (origin && allowed.has(origin));

    // CORS headers only ever echo an allow-listed origin (never "*").
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
        const rl = limiter(clientIp(headers));
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

      if (inspect) {
        const ua = String(headers['user-agent'] || '');
        let target = String(event.path || '') + ' ' + String(event.rawQuery || '');
        if (!event.rawQuery && event.queryStringParameters) {
          target += ' ' + Object.values(event.queryStringParameters).join(' ');
        }
        target += ' ' + raw;
        let decoded = target;
        try { decoded = decodeURIComponent(target); } catch { /* keep raw */ }
        if (BAD_BOT_RE.test(ua) || ATTACK_PATTERNS.some((re) => re.test(target) || re.test(decoded))) {
          console.warn(`[firewall:${name}] blocked suspicious request from ${clientIp(headers)}`);
          return reply(403, { error: 'Forbidden' });
        }
      }

      if (wantsJson && method !== 'GET' && method !== 'HEAD') {
        try {
          const parsed = raw.trim() ? JSON.parse(raw) : {};
          if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not an object');
          event.jsonBody = parsed;
        } catch {
          return reply(400, { error: 'Invalid JSON' });
        }
      }

      const res = (await handler(event, context)) || {};
      return {
        ...res,
        statusCode: res.statusCode || 200,
        // Handler headers win for Content-Type etc., but security headers (+ no-store unless
        // options.cacheControl says otherwise) always apply
        // and CORS is always the firewall's (never a handler's "*").
        headers: {
          'Content-Type': 'application/json',
          ...(res.headers || {}),
          ...SECURITY_HEADERS,
          ...(options.cacheControl ? { 'Cache-Control': options.cacheControl } : {}),
          ...cors,
        },
      };
    } catch (err) {
      // Log only the message — never the event (it may hold codes, passwords or tokens).
      console.error(`[firewall:${name}] unhandled error: ${err && err.message ? err.message : 'unknown'}`);
      return reply(500, { error: 'Internal error' });
    }
  };
}

module.exports = { withFirewall, createRateLimiter, clientIp, allowedOrigins, SECURITY_HEADERS };
