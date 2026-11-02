#!/usr/bin/env node
/**
 * generate-access-codes — make new single-use access codes for auth-signup.
 *
 * Usage:
 *   CODE_PEPPER='<same value as in Netlify>' node scripts/generate-access-codes.js 50
 *   CODE_PEPPER='…' node scripts/generate-access-codes.js 10 --free --note "Spring 2027 class"
 *
 * Prints:
 *   1. the codes (XXXX-XXXX-XXXX, 12 symbols, no 0/O/1/I/L) — give these to buyers; they are
 *      NOT stored anywhere, so save them now (e.g. in your password manager);
 *   2. an SQL INSERT of their HMAC-SHA256(CODE_PEPPER, code) hashes — paste it into the Supabase
 *      SQL editor. The database never holds a usable code.
 *
 * Make a pepper once with:
 *   node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"
 * and set the SAME value as CODE_PEPPER in Netlify. Changing the pepper invalidates every
 * unredeemed v2 code.
 */
'use strict';

const crypto = require('crypto');
const path = require('path');
const L = require(path.join(__dirname, '..', 'deploy', 'netlify', 'functions', 'lib', 'legacy-hash.js'));

function usage(msg) {
  if (msg) console.error('error: ' + msg);
  console.error('usage: CODE_PEPPER=… node scripts/generate-access-codes.js <count 1-1000> [--free] [--note "text"]');
  process.exit(1);
}

const args = process.argv.slice(2);
const count = parseInt(args[0], 10);
if (!Number.isInteger(count) || count < 1 || count > 1000) usage('count must be 1-1000');
const free = args.includes('--free');
const ni = args.indexOf('--note');
const note = ni >= 0 ? String(args[ni + 1] || '').slice(0, 200) : '';
const pep = L.pepper();
if (!pep) usage('set CODE_PEPPER (at least 32 characters) to the value configured in Netlify');

function makeCode() {
  let s = '';
  for (let i = 0; i < L.V2_LEN; i++) s += L.V2_ALPHABET[crypto.randomInt(0, L.V2_ALPHABET.length)];
  return s;
}

const codes = new Set();
while (codes.size < count) codes.add(makeCode());

const sqlStr = (v) => "'" + String(v).replace(/'/g, "''") + "'";
const pretty = (c) => c.match(/.{4}/g).join('-');

console.log(`# ${count} ${free ? 'FREE' : 'paid'} access code(s) — save these now, they are not stored anywhere:`);
for (const c of codes) console.log(pretty(c));
console.log('\n-- Paste into Supabase → SQL Editor → New query → Run:');
console.log('insert into public.access_codes (code_hash, free, note) values');
console.log([...codes].map((c) => `  (${sqlStr(L.v2Hash(L.normalizeV2(c), pep))}, ${free}, ${sqlStr(note)})`).join(',\n'));
console.log('on conflict (code_hash) do nothing;');
