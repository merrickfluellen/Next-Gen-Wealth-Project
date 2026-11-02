/**
 * get-crypto — live crypto price proxy via CoinGecko (free, no API key)
 * GET /.netlify/functions/get-crypto → { BTC: { price, change24h, marketCap }, ... }
 *
 * Fetches top 30 coins server-side. Results cached 60s per warm Lambda instance.
 */

const https = require('https');

const COIN_IDS = [
  'bitcoin','ethereum','tether','binancecoin','solana','ripple','usd-coin',
  'cardano','avalanche-2','dogecoin','tron','chainlink','polkadot','matic-network',
  'the-open-network','shiba-inu','dai','litecoin','bitcoin-cash','uniswap',
  'cosmos','stellar','near','monero','ethereum-classic','algorand',
  'hedera-hashgraph','filecoin','aave','vechain',
];

const ID_TO_SYM = {
  'bitcoin':'BTC','ethereum':'ETH','tether':'USDT','binancecoin':'BNB',
  'solana':'SOL','ripple':'XRP','usd-coin':'USDC','cardano':'ADA',
  'avalanche-2':'AVAX','dogecoin':'DOGE','tron':'TRX','chainlink':'LINK',
  'polkadot':'DOT','matic-network':'MATIC','the-open-network':'TON',
  'shiba-inu':'SHIB','dai':'DAI','litecoin':'LTC','bitcoin-cash':'BCH',
  'uniswap':'UNI','cosmos':'ATOM','stellar':'XLM','near':'NEAR',
  'monero':'XMR','ethereum-classic':'ETC','algorand':'ALGO',
  'hedera-hashgraph':'HBAR','filecoin':'FIL','aave':'AAVE','vechain':'VET',
};

let _cache = null;
let _cacheAt = 0;
const CACHE_TTL = 60 * 1000;

exports.handler = async () => {
  const headers = {
    'Content-Type': 'application/json',
    'Cache-Control': 'public, max-age=60',
    'Access-Control-Allow-Origin': '*',
  };

  if (_cache && Date.now() - _cacheAt < CACHE_TTL) {
    return { statusCode: 200, headers, body: JSON.stringify(_cache) };
  }

  return new Promise((resolve) => {
    const ids = COIN_IDS.join('%2C');
    const path = `/api/v3/simple/price?ids=${ids}&vs_currencies=usd&include_24hr_change=true&include_market_cap=true&precision=6`;

    const options = {
      hostname: 'api.coingecko.com',
      path,
      headers: {
        'User-Agent': 'InvestEd-Pro/1.0',
        'Accept': 'application/json',
      },
      timeout: 8000,
    };

    const req = https.get(options, (res) => {
      let raw = '';
      res.on('data', chunk => { raw += chunk; });
      res.on('end', () => {
        try {
          const json = JSON.parse(raw);
          const result = {};
          for (const [id, data] of Object.entries(json)) {
            const sym = ID_TO_SYM[id];
            if (sym && typeof data.usd === 'number') {
              result[sym] = {
                price: data.usd,
                change24h: parseFloat((data.usd_24h_change || 0).toFixed(2)),
                marketCap: data.usd_market_cap || 0,
              };
            }
          }
          if (Object.keys(result).length > 0) {
            _cache = result;
            _cacheAt = Date.now();
          }
          resolve({ statusCode: 200, headers, body: JSON.stringify(_cache || result) });
        } catch {
          resolve({ statusCode: 200, headers, body: JSON.stringify(_cache || {}) });
        }
      });
    });

    req.on('error', () => resolve({ statusCode: 200, headers, body: JSON.stringify(_cache || {}) }));
    req.on('timeout', () => { req.destroy(); resolve({ statusCode: 200, headers, body: JSON.stringify(_cache || {}) }); });
  });
};
