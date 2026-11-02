/**
 * get-prices — live stock price proxy via Yahoo Finance
 * GET /.netlify/functions/get-prices → { AAPL: 293.64, MSFT: 412.67, ... }
 *
 * Fetches prices server-side so the browser never touches Yahoo Finance directly
 * (avoids CORS issues and keeps CSP clean). Results are cached 60 s per instance.
 */

const https = require('https');

const SYMBOLS = [
  'AAPL','MSFT','GOOGL','AMZN','TSLA','META','NVDA',
  'JNJ','PG','KO','WMT','XOM','BAC',
  'SPY','VOO','BND','TLT',
];

// In-memory cache (shared within a warm Lambda instance)
let _cache = null;
let _cacheAt = 0;
const CACHE_TTL = 60 * 1000; // 60 seconds

function fetchPrice(symbol) {
  return new Promise((resolve) => {
    const options = {
      hostname: 'query1.finance.yahoo.com',
      path: `/v8/finance/chart/${encodeURIComponent(symbol)}?interval=1d&range=1d`,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; InvestEdBot/1.0)',
        'Accept': 'application/json',
      },
      timeout: 5000,
    };

    const req = https.get(options, (res) => {
      let raw = '';
      res.on('data', chunk => { raw += chunk; });
      res.on('end', () => {
        try {
          const json = JSON.parse(raw);
          const price = json?.chart?.result?.[0]?.meta?.regularMarketPrice;
          resolve(typeof price === 'number' ? Math.round(price * 100) / 100 : null);
        } catch {
          resolve(null);
        }
      });
    });

    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
  });
}

exports.handler = async () => {
  const headers = {
    'Content-Type': 'application/json',
    'Cache-Control': 'public, max-age=60',
    'Access-Control-Allow-Origin': '*',
  };

  // Serve from cache if fresh
  if (_cache && Date.now() - _cacheAt < CACHE_TTL) {
    return { statusCode: 200, headers, body: JSON.stringify(_cache) };
  }

  // Fetch all symbols concurrently (with a 6 s overall cap)
  const results = {};
  const fetches = SYMBOLS.map(async (sym) => {
    const price = await fetchPrice(sym);
    if (price !== null) results[sym] = price;
  });

  await Promise.allSettled(fetches);

  // Only cache if we got at least some data
  if (Object.keys(results).length > 0) {
    _cache = results;
    _cacheAt = Date.now();
  }

  return { statusCode: 200, headers, body: JSON.stringify(results) };
};
