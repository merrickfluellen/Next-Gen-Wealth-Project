# MoneyQuest

MoneyQuest (Money Quest by InvestEd Pro) is a money-education game for kids and teens: a walkable 3D "Money City" with lessons (Junior Quest for ages 6–11, Pro Quest for teens), and simulated stocks, crypto, bonds, banking, jobs, real estate and companies. Everything is a simulation for learning. No real money is involved.

Live site: <https://nextgenwealthproject.netlify.app> (the app is `/app.html`).

## How it is built

- **`deploy/`** is the whole website, deployed to Netlify as-is (no build step for the app):
  - `index.html` (home page), `app.html` (the entire app: React via `React.createElement`, no JSX), `privacy.html`, `terms.html`;
  - `vendor/`: self-hosted React, ReactDOM, Leaflet and three.js (see [`deploy/vendor/README.md`](deploy/vendor/README.md)); `tailwind.css`: prebuilt styles;
  - `netlify/functions/`: Node serverless functions for sign-up/sign-in, saving progress, password reset, admin, account deletion, market prices and the real-US-map features, with shared code in `netlify/functions/lib/`;
  - `netlify.toml`: publish settings, redirects and security headers (CSP, HSTS).
- **`supabase/`**: SQL to set up and lock down the database. The browser never talks to the database; only the functions do, with the service key.
- **`scripts/generate-access-codes.js`**: makes new single-use access codes.
- **`package.json`**: build tooling only (`npm run build:css` rebuilds `deploy/tailwind.css`).

## Documentation

- [docs/SETUP.md](docs/SETUP.md): step-by-step deployment (Netlify, environment variables, Supabase rollout, access codes, provider dashboards, smoke test).
- [docs/ENV.md](docs/ENV.md): every environment variable, what it does and how to generate it.
- [supabase/README.md](supabase/README.md): the database SQL in detail (Part A, Part B, account deletion, retention).
- [SECURITY.md](SECURITY.md): how to report a vulnerability, and the security model.
- [Privacy Policy](deploy/privacy.html) and [Terms of Use](deploy/terms.html) (published at `/privacy.html` and `/terms.html`).

## Local development

```sh
npm ci                     # build tooling (Tailwind) and vendored library sources
npm run build:css          # after changing class names in deploy/*.html; commit deploy/tailwind.css
cd deploy && npx netlify-cli dev   # uses deploy/netlify.toml; serves the site + functions on http://localhost:8888
```

Functions need the environment variables from [docs/ENV.md](docs/ENV.md) (put them in a git-ignored `deploy/.env`, or link the Netlify site). Set `RATE_LIMIT_DB=off` to keep rate limits in memory while testing.

## License

This is **not** open-source software. It is released under the [MoneyQuest Source-Available License, Version 1.2](LICENSE). The LICENSE file is what counts; this is only a summary.

- **Free for non-commercial use.** You may use, modify, and share MoneyQuest for personal learning, and for teaching in schools, libraries, clubs, or nonprofit programs where no one is charged for access.
- **No making money from it without signed permission.** You may not make commercial use of MoneyQuest itself (even unmodified, e.g. hosting it with ads) or of any work that uses more than **5%** of it, unless the author gives you signed written permission (co-signed by a parent or guardian while the author is under 18). Silence, donations, or merged pull requests are not permission.
- **5% or less?** You may use it commercially, as long as you give credit and follow the rest of the license. Images, audio, video, and fonts made by the author (including ones embedded in code) are never allowed for commercial use without signed permission.
- **"Commercial" is broad.** It includes selling, subscriptions, ads, sponsorships, affiliate links, selling user data, charging fees for a course or tutoring built on it, using it to promote a paid product, internal use by a for-profit company, and training commercial AI models on it. Nonprofits charging fees are covered too. Viewing or forking on GitHub, search indexing, reviews or news that quote it, and private security reports are not commercial use.
- **How 5% is measured.** On the original files, not on your work, by lines, by non-whitespace characters, by the lesson and quiz text alone, or by any single large file (if *any* of these is over 5%, it counts). Reformatting, minifying, translating, paraphrasing, or AI regeneration of copied material does not help. Everything you and companies you control (or that control you) use commercially is added together.
- **Not claimed.** Ideas, facts, game mechanics as such, and public-domain data (including the U.S. government data in `deploy/netlify/functions/lib/re-data.json`) are not claimed. Third-party files (such as those in `deploy/vendor/`) keep their own licenses. Fair use is not limited.
- **Credit is required.** Keep the LICENSE file and copyright notice, show "Based on MoneyQuest by merrickfluellen (https://github.com/merrickfluellen), used under the MoneyQuest Source-Available License." where users can see it, and say if you changed it.
- **No names or logos.** The names "MoneyQuest" and "InvestEd Pro" may not be used to brand your work.
- **No warranty.** It is provided as-is and is for education only, not financial advice.
- **Breaking the license ends your permission.** Most violations can be fixed (cured); unpermitted commercial use over 5% can only be fixed with signed permission.
- **Contributions.** By sending a pull request or other contribution, you let the author use and relicense it, including commercially.
- **Earlier versions.** Version 1.2 replaces Versions 1.0 and 1.1 for every commit of this repository, including commits that came with an older license file or none, for any copy obtained from November 2, 2026 on.

To ask for commercial permission, contact [@merrickfluellen](https://github.com/merrickfluellen).

*Not legal advice. This license was drafted without a lawyer; have a lawyer review it, and consider registering the copyright with the U.S. Copyright Office.*

Copyright (c) 2026 merrickfluellen. All rights reserved except as granted in the [LICENSE](LICENSE).
