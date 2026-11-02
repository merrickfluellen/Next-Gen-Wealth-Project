# Security Policy

MoneyQuest is a finance-education web app for teens. Some users are minors, so we take reports seriously and handle them privately.

## Reporting a vulnerability

**Please do not open a public issue, pull request or discussion for security problems.**

Report privately in one of these ways:

1. **GitHub private vulnerability reporting (preferred):** go to this repository's **Security** tab, choose **Report a vulnerability**, and fill in the advisory form. Only the maintainers can see it.
2. If that option is unavailable, contact the maintainer **@merrickfluellen** on GitHub and ask for a private channel. Do not include exploit details in a public message.

Please include:

- what is affected (page, Netlify function, or configuration file) and the impact;
- steps to reproduce or a proof of concept;
- any suggested fix.

What to expect:

- acknowledgement within **7 days**;
- an initial assessment and planned fix timeline within **14 days**;
- credit in the fix notes if you want it.

Please test only against your own account and data, avoid accessing other users' data, and do not run denial-of-service or high-volume automated scans against the live site.

## Supported versions

Only the **latest commit on the default branch** receives security fixes. Fixes are made there and then deployed to the live site (see [docs/SETUP.md](docs/SETUP.md)); older commits and forks are not supported.

| Version                           | Supported |
| --------------------------------- | --------- |
| Latest default branch / live site | Yes       |
| Anything older                    | No        |

## Security model

This is a short, honest summary of how the app is protected and where the limits are.

- **Transport security.** The site is served only over HTTPS by Netlify. HSTS (`max-age` two years, `includeSubDomains`, `preload`) is sent on every page by `deploy/netlify.toml` and on every function response by `lib/firewall.js`.
- **Security headers and CSP.** `deploy/netlify.toml` sets a Content Security Policy, `X-Frame-Options: DENY`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy` and `Cross-Origin-Opener-Policy` on every page. `script-src` is `'self'` only: no third-party script host is trusted. React, ReactDOM, Leaflet and three.js are self-hosted under `deploy/vendor/` (hash-checked in CI, see `deploy/vendor/README.md`) and Tailwind is the prebuilt `deploy/tailwind.css`. The only outside hosts in the CSP are Google Fonts (styles/fonts), the map tile servers (images) and two Overpass API mirrors (`connect-src`). `app.html` and `index.html` are served `no-store`.
- **No browser database access.** The browser never talks to Supabase. All reads and writes go through the Netlify functions (`auth-*`, `progress`, `admin-users`, `reset-password`, `confirm-reset`), which use the secret `SUPA_SERVICE_KEY`. In Supabase every app table has RLS **enabled with no policies** and all privileges revoked from `anon`/`authenticated` (`supabase/001_security.sql` Part B). Never add an "allow" policy for `anon`.
- **Sessions.** User sessions are tokens signed with HMAC-SHA256 (key derived from `SESSION_SECRET` with HKDF), valid 30 days, and bound to the user's current password hash, so a password change, a reset or an account deletion ends every session. Admin sessions are separate 2-hour tokens bound to the current admin credential hashes; admin login needs email, password and admin code together.
- **Cryptography.** `deploy/netlify/functions/lib/crypto.js` uses only Node's built-in `crypto`: AES-256-GCM for password-reset tokens (15-minute expiry, at most 5 guesses per code and 10 per email per day), HMAC-SHA256 for signed tokens and keyed hashes, and salted scrypt for passwords and admin credentials. New access codes are stored only as `HMAC-SHA256(CODE_PEPPER, code)`. Password-reset records store a keyed HMAC of the email (`h1:…`), never the address.
- **Rate limits.** `lib/ratelimit.js` keeps durable counters in Supabase (`public.rl_hit`), shared by every function instance. Keys are the client IP (IPv6 by /64) or the account email. Sign-in, sign-up, reset, account deletion, progress saves and the real-estate/map functions use them. Site-wide budgets (reset e-mails per day, paid RentCast calls per hour, Nominatim 1 request/second) fail closed. Counters are deleted by a daily pg_cron job once their window (at most 1 day) is over.
- **Application firewall.** Every function is wrapped by `deploy/netlify/functions/lib/firewall.js`: allowed methods, an Origin allow-list, body size and JSON checks, a per-IP limit, a filter for common attack patterns and scanner user agents, security headers, and an error handler that never returns stack traces. CI runs its ReDoS self-test.
- **Server-side secrets.** The Supabase service key, signing secrets, `CODE_PEPPER`, admin hashes, and the Resend and RentCast keys live only in Netlify environment variables (see [docs/ENV.md](docs/ENV.md)). The map tile key (`MAPTILER_KEY` / `STADIA_API_KEY`) is public by design because it appears in tile URLs; restrict it to the site's domain at the provider.
- **Privacy by design.** "Delete my data" in the app deletes the account server-side (`auth-delete` → `public.delete_account`). "Find my home" addresses are sent by POST, answered with `no-store`, never logged, and kept only in memory (at most 60 minutes). Under-13 sign-up is blocked before any data is sent.
- **Continuous checks.** GitHub Actions (`.github/workflows/ci.yml`, actions pinned to commit SHAs) syntax-checks the functions and scripts, runs the firewall ReDoS self-test, validates TOML and JSON, checks the vendored files' hashes, rejects external `<script src>` in `deploy/*.html`, checks that `deploy/tailwind.css` is up to date, and runs gitleaks secret scanning on every push and pull request.

### Known limits

- The CSP still allows `'unsafe-inline'` scripts and styles because the pages use large inline scripts and style attributes.
- If Supabase is unreachable, per-client limits fall back to per-instance memory (best effort); the site-wide budgets refuse instead. The price and map-config functions use only the per-instance firewall limit and CDN caching.
- Signing out removes the token from the browser but does not revoke it on the server; it stays valid until it expires (30 days), the password changes, or the account is deleted.
- Accounts that have not signed in since the server-side auth change keep a weak legacy (32-bit) password hash until their next sign-in. The 151 legacy access codes have public hashes and work (once each) until `LEGACY_CODES=off` is set.
- Admin credential hashes may still be in the legacy format; convert them to scrypt (see docs/SETUP.md).
- Security depends on correct configuration outside this repository: Netlify environment variables, the Supabase SQL in `supabase/` (Part A and Part B, pg_cron enabled), and provider-side key restrictions. Report misconfigurations the same way as code bugs.
