# Environment variables

Every environment variable the code reads (`process.env` in `deploy/netlify/functions/` and `scripts/`), plus the ones Netlify and CI provide.

Set them in **Netlify → your site → Site configuration → Environment variables → Add a variable**, then redeploy (**Deploys → Trigger deploy → Deploy site**). Changes do nothing until the next deploy. Secrets go only there, never in a file in this repository.

Generate a random secret with Node:

```sh
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
```

That prints 64 characters, which is more than the 32-character minimum.

## Required

| Name | Used by | Purpose | Format / how to get it | If unset or wrong |
|---|---|---|---|---|
| `SUPA_SERVICE_KEY` | `lib/session.js` (all `auth-*`, `progress`, `admin-users`, `confirm-reset`), `reset-password`, `lib/ratelimit.js`, `lib/geo.js` | Supabase **service role** key. All database access goes through the functions with this key. | Supabase → **Project Settings → API Keys** → the `service_role` / secret key. Never put it in a page. | Sign-in, sign-up, saving, account deletion and admin answer 503. Password reset returns a normal-looking answer but sends no email. Rate limits fall back to per-instance memory; paid map lookups and reset emails are refused. |
| `SESSION_SECRET` | `lib/crypto.js` (every token and keyed hash, via HKDF), `lib/session.js`, `admin-auth`, `reset-password` | Master secret for user sessions, admin sessions, reset tokens and the hashed email in reset records. | Random, **at least 32 characters** (command above). | Shorter than 32 characters is **rejected**: sign-in, sign-up, admin and reset all fail ("unavailable"). Changing it signs out every user and admin and cancels reset codes in progress. |
| `CODE_PEPPER` | `lib/legacy-hash.js` (`auth-signup`), `scripts/generate-access-codes.js` | Secret key for new (v2) access codes. The database stores only `HMAC-SHA256(CODE_PEPPER, code)`. | Random, **at least 32 characters**. Keep a copy in a password manager: you need the **same** value on your computer to generate codes. | Shorter values are **silently ignored**, and then every new code is rejected as invalid. Changing it makes every unused new code stop working. Legacy codes are not affected. |
| `RESEND_API_KEY` | `reset-password` | Sends password-reset emails through Resend. | Resend → **API Keys** → create a key with "Sending access" only. | No reset email is ever sent; the app still says "check your email". Only a log line shows the problem. |
| `RESEND_FROM` | `reset-password` | Sender address for reset emails, shown as `InvestEd Pro <address>`. | An address on a domain you verified in Resend → **Domains**, e.g. `no-reply@yourdomain.com`. Not secret (listed in `SECRETS_SCAN_OMIT_KEYS`). | Defaults to `onboarding@resend.dev`, which Resend delivers **only to the Resend account owner's own email**. Everyone else gets nothing. Treat it as required. |
| `ADMIN_EMAIL_HASH` | `admin-auth`, `lib/session.js` (`verify-admin`, `admin-users`) | Admin login, factor 1. | `node deploy/netlify/functions/lib/crypto.js hash 'email::you@example.com'` (email in lower case). | Admin login answers 500 "Server misconfigured"; the admin dashboard is unavailable. The rest of the site works. |
| `ADMIN_PW_HASH` | same | Admin login, factor 2 (password). | `node deploy/netlify/functions/lib/crypto.js hash 'adminpw::YourAdminPassword'` | Same as above. |
| `ADMIN_CODE_HASH` | same | Admin login, factor 3 (admin code). | `node deploy/netlify/functions/lib/crypto.js hash 'admincode::YOURCODE'` (code in **upper case**; the server upper-cases what you type). | Same as above. |

Notes on the admin hashes:

- All three must match at once. Changing any of them signs out every admin session.
- The old `h…` format (32-bit `hashPw`) is still accepted, but it can be cracked in seconds. Replace it with the `scrypt$…` output of the commands above (see [SETUP.md](SETUP.md#5-convert-the-admin-hashes-to-scrypt)).
- Include the prefix (`email::`, `adminpw::`, `admincode::`) exactly. Wrap the value in single quotes so the shell does not change it.

## Optional

| Name | Used by | Purpose | Format | If unset |
|---|---|---|---|---|
| `SUPABASE_URL` | `lib/session.js` | Supabase project URL. | `https://<project>.supabase.co`, no trailing path. Anything else is rejected and database calls fail. | `https://vtxuvmtnqlxidnswnunx.supabase.co` (the live project). |
| `LEGACY_CODES` | `lib/legacy-hash.js` (`auth-signup`) | Turns the 151 old access codes on or off. Their hashes are public in git history, so they can be forged. | `off` | The old codes still work, **each one once**. Set `off` once buyers have new codes. |
| `RESET_EMAILS_PER_DAY` | `reset-password` | Site-wide cap on reset emails per day (protects the Resend quota). | Whole number 0–100000. `0` = no reset emails at all. | 80 per day. An invalid value also means 80. When the cap is reached (or the counter cannot be read), no email is sent. |
| `MAPTILER_KEY` | `map-config` | Dark map tiles from MapTiler. | The key from MapTiler → **Account → API keys** (8–128 letters, digits, `-`, `_`; anything else is ignored). **Public by design**: it is in every tile URL. Restrict it to your domain at MapTiler. | Uses `STADIA_API_KEY` if set, otherwise OpenStreetMap tiles with a dark filter. |
| `STADIA_API_KEY` | `map-config` | Dark map tiles from Stadia Maps ("Alidade Smooth Dark"), used only if `MAPTILER_KEY` is not set. | Key from client.stadiamaps.com. Public by design; prefer Stadia's domain-based auth. | OpenStreetMap tiles with a dark filter. |
| `RENTCAST_API_KEY` | `lib/re-estimate.js` (`re-value`, `re-listings`) | Paid real home values and for-sale listings. | Key from RentCast → **API**. Keep it secret. | Free mode: practice listings and values estimated from bundled Census/FHFA data. |
| `RENTCAST_MAX_CALLS_PER_HOUR` | `lib/re-estimate.js` | Site-wide cap on paid RentCast calls per hour (one counter shared by all instances; fails closed). | Digits only: `0` turns paid calls **off**; `1`–`10000` (larger values are capped at 10000). Anything else (`-1`, `5.5`, `abc`) also means **off**. | 40 per hour. Each visitor is also limited (10 value lookups and 15 listing lookups per hour). |
| `ALLOWED_ORIGINS` | `lib/firewall.js` (every function) | Browser origins allowed to call the functions. | Comma-separated origins, e.g. `https://nextgenwealthproject.netlify.app,https://www.example.com`. | Netlify's own `URL`, `DEPLOY_PRIME_URL` and `DEPLOY_URL` (plus `localhost:8888` under `netlify dev`). **If you set it, it replaces that list**, so include every origin, the main site too, or sign-in and saving fail with 403. Requests with no `Origin` header are not affected. |
| `SITE_URL` | `lib/crypto.js`, `lib/geo.js` (helpers no function currently calls) | Public site origin. | `https://nextgenwealthproject.netlify.app` (no trailing slash). Not secret. | No effect today. It does **not** change the firewall allow-list (use `ALLOWED_ORIGINS`). Safe to leave set. |
| `RATE_LIMIT_DB` | `lib/ratelimit.js`, `lib/geo.js` | `off` keeps every rate limit in per-instance memory instead of Supabase. | `off` | Durable limits in Supabase (normal). **Do not set `off` in production**: limits would reset on every cold start. For local development and tests only. |

## Set by Netlify (do not add these yourself)

| Name | Used by | Meaning |
|---|---|---|
| `URL` | `lib/firewall.js`, `lib/geo.js` | The site's main address. Part of the default Origin allow-list. |
| `DEPLOY_PRIME_URL` | `lib/firewall.js`, `lib/geo.js` | Branch / deploy-preview address. Part of the default allow-list. |
| `DEPLOY_URL` | `lib/firewall.js` | This exact deploy's address. Part of the default allow-list. |
| `CONTEXT` | `lib/firewall.js` | `dev` under `netlify dev` adds `http://localhost:8888` and `http://127.0.0.1:8888` to the allow-list. |
| `NETLIFY_DEV` | `lib/firewall.js` | `true` under `netlify dev`; same effect as `CONTEXT=dev`. |

## Build and CI

| Name | Where | Meaning |
|---|---|---|
| `SECRETS_SCAN_OMIT_KEYS` | `deploy/netlify.toml` `[build.environment]` | Tells Netlify's secret scanner that `SITE_URL` and `RESEND_FROM` are public, so their values in the built files do not fail the deploy. |
| `GITHUB_TOKEN`, `GITLEAKS_CONFIG` | `.github/workflows/ci.yml` | Used by the gitleaks secret scan in CI (`GITLEAKS_CONFIG` = `.gitleaks.toml`). Nothing to set. |

There is **no** Supabase public/anon key variable: the browser never talks to the database.

## Running scripts on your computer

`scripts/generate-access-codes.js` reads only `CODE_PEPPER`, and it must be the same value as in Netlify:

```sh
CODE_PEPPER='<same value as Netlify>' node scripts/generate-access-codes.js 10
```

On Windows PowerShell: `$env:CODE_PEPPER='<value>'; node scripts/generate-access-codes.js 10`.
