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

MoneyQuest is deployed continuously from the default branch to Netlify. Only the **current deployed version (latest commit on the default branch)** receives security fixes; older commits and forks are not supported.

| Version                         | Supported |
| ------------------------------- | --------- |
| Latest default branch / live site | Yes     |
| Anything older                  | No        |

## Security model

This is a short, honest summary of how the app is protected and where the limits are.

- **Transport security.** The site is served only over HTTPS by Netlify, with HSTS so browsers refuse to downgrade to plain HTTP.
- **Security headers.** `deploy/netlify.toml` sets headers for every response, including a Content Security Policy, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` and `Permissions-Policy`. HTML pages and function responses are marked no-store.
- **Server-side secrets.** API keys, the Supabase service-role key and signing secrets live only in Netlify environment variables and are read by the serverless functions in `deploy/netlify/functions/`. They are never shipped to the browser or committed to the repository.
- **Cryptography.** Server-side code in `deploy/netlify/functions/lib/crypto.js` uses Node's built-in `crypto` module: AES-256-GCM for authenticated encryption of sensitive values, and HMAC-SHA256 for signing and verifying tokens.
- **Application firewall.** `deploy/netlify/functions/lib/firewall.js` is shared by the functions and applies request checks before any handler logic runs: rate limiting, allowed HTTP methods, origin checks, and request-body size and format checks.
- **Database access.** The browser talks to Supabase with the *publishable* key, which is public by design. That is only safe if **Supabase Row Level Security (RLS) is enabled on every table** with policies that restrict each user to their own rows. Anyone deploying this project must turn RLS on and review policies; without it, the publishable key would allow reading or changing other users' data.
- **Continuous checks.** GitHub Actions (`.github/workflows/ci.yml`) syntax-checks the functions, validates configuration files and runs gitleaks secret scanning on every push and pull request.

### Known limits

- Rate limiting in serverless functions is best effort: instances do not share memory, so limits apply per instance rather than globally.
- The CSP still allows `'unsafe-inline'` scripts and styles because the pages use inline code.
- Security depends on correct configuration outside this repository (Netlify environment variables, Supabase RLS policies). Report misconfigurations the same way as code bugs.
