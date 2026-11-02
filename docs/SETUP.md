# Deploying MoneyQuest (step by step)

This guide is for the site owner. Do the steps in order. Each step says where to click. If something looks different in a dashboard, look for the same words nearby; providers rename menus now and then.

You will need: the Netlify site, the Supabase project, a Resend account, Node.js 18 or newer on your computer (for a few commands), and a password manager to save secrets.

Related docs: [ENV.md](ENV.md) (every environment variable), [../supabase/README.md](../supabase/README.md) (the database SQL in detail), [../SECURITY.md](../SECURITY.md).

---

## 0. Read this first: which repository is live

**The live site (nextgenwealthproject.netlify.app) currently deploys from a different repository, `merrickfluellen/investedpro`.** Nothing in this repository (`Next-Gen-Wealth-Project`) reaches the live site until you deploy it. Pick one:

- **Option A (recommended): point Netlify at this repository.**
  Netlify → your site → **Site configuration → Build & deploy → Continuous deployment → Repository → Manage repository → Link to a different repository** → choose `merrickfluellen/Next-Gen-Wealth-Project`, branch = the default branch. Then set the build settings in step 1.
- **Option B: copy the folder over.** Replace the `deploy/` folder in `investedpro` with this repository's `deploy/` folder (delete the old one first, so removed files such as `validate-code.js` really go away), commit and push there.

Do **not** use Netlify's drag-and-drop upload for this version: it does not build the server functions, and the app cannot sign anyone in without them. Use Git (A or B) or the Netlify CLI (`cd deploy && npx netlify-cli deploy --prod`).

Before the first deploy of this version, do steps 2 and 3 (environment variables and SQL Part A). The new app signs people in only through the new functions, and they need both.

---

## 1. Netlify build settings

Netlify → your site → **Site configuration → Build & deploy → Build settings → Configure**:

| Setting | Value |
|---|---|
| Base directory | `deploy` |
| Build command | *(empty)* |
| Publish directory | *(leave empty; `deploy/netlify.toml` sets it to `.` = the `deploy` folder)* |
| Functions directory | *(leave empty; `deploy/netlify.toml` sets `netlify/functions`)* |

There is no build step: the HTML, `tailwind.css` and `vendor/` libraries are committed ready to serve. The functions use only Node's built-in modules (no `npm install` on Netlify). They need Node 18 or newer, which is Netlify's default.

`deploy/netlify.toml` also blocks the function source files and itself from being downloaded, and sets the security headers (CSP, HSTS). Do not add header rules for `/.netlify/functions/*`.

---

## 2. Environment variables

Netlify → your site → **Site configuration → Environment variables → Add a variable**. Full details, defaults and what goes wrong without each one: [ENV.md](ENV.md).

Make the secrets on your computer:

```sh
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
```

Run it once for each secret. Save every value in your password manager **before** pasting it into Netlify.

| Variable | What to put |
|---|---|
| `SUPA_SERVICE_KEY` | Supabase → **Project Settings → API Keys** → `service_role` / secret key |
| `SESSION_SECRET` | a new random value (at least 32 characters). If one is already set, check its length: shorter than 32 now breaks sign-in. Changing it signs everyone out once. |
| `CODE_PEPPER` | a new random value (at least 32 characters). You need the same value later to make access codes. |
| `RESEND_API_KEY` | Resend → **API Keys** (sending access only) |
| `RESEND_FROM` | an address on your verified Resend domain, e.g. `no-reply@yourdomain.com` (see step 7) |
| `ADMIN_EMAIL_HASH`, `ADMIN_PW_HASH`, `ADMIN_CODE_HASH` | scrypt hashes (step 5) |
| Optional | `MAPTILER_KEY` or `STADIA_API_KEY`, `RENTCAST_API_KEY` + `RENTCAST_MAX_CALLS_PER_HOUR`, `RESET_EMAILS_PER_DAY`, `LEGACY_CODES` (step 4) |

Do **not** set `ALLOWED_ORIGINS` unless you add a custom domain (it replaces the default list), and never set `RATE_LIMIT_DB=off` on the live site.

After changing variables: **Deploys → Trigger deploy → Deploy site**.

---

## 3. Supabase database rollout

The SQL is in `supabase/`. Full explanations: [supabase/README.md](../supabase/README.md). Open Supabase → left sidebar **SQL Editor → New query** for each step.

**3.1 Enable pg_cron (once).** Supabase → **Database → Extensions** → search `pg_cron` → enable. Part A uses it to delete password-reset records after 2 days and expired rate-limit counters every day. Without it nothing is ever deleted, and the Privacy Policy's retention promises are not true.

**3.2 Check the `progress` columns.** The app saves into these columns. A missing one means that part of the game is saved only on the device. Safe to run more than once:

```sql
alter table public.progress add column if not exists money_quest jsonb;
alter table public.progress add column if not exists real_estate jsonb;
alter table public.progress add column if not exists economy     jsonb;
alter table public.progress add column if not exists world       jsonb;
```

<details><summary>Starting with an empty Supabase project? Create the two base tables first.</summary>

```sql
create table if not exists public.users (
  id bigint generated always as identity primary key,
  email text not null, name text, pw_hash text,
  free_access boolean not null default false,
  created_at timestamptz not null default now()
);
create table if not exists public.progress (
  id bigint generated always as identity primary key,
  email text not null,
  lesson_notes jsonb, portfolio jsonb, completed_lessons jsonb,
  sim_days numeric, sim_target numeric,
  money_quest jsonb, real_estate jsonb, economy jsonb, world jsonb,
  updated_at timestamptz default now()
);
```
</details>

**3.3 Run Part A.** Paste `supabase/001_security.sql` from the top **down to, but not including,** the `PART B — LOCKDOWN` banner → **Run**. It is safe while the old site is live, and safe to run again. It adds the access-code tables, password-reset table, the rate limiter (`rl_hit`), atomic sign-up, account deletion, the consent columns (`age_band`, `consent_version`, `consent_at`) and the daily clean-up jobs.
- The last result lists duplicate emails. If there are any, fix them first ([Duplicates](../supabase/README.md#duplicates)).
- If you see a WARNING about pg_cron, go back to 3.1 and run Part A again.

**3.4 Deploy** this version of `deploy/` (step 0) with the variables from step 2.

**3.5 Test** with the smoke test (step 9), at least: sign up with a new test code, sign in, play, reload, sign in on a second browser, reset a password.

**3.6 Run Part B.** Paste the rest of `001_security.sql`, from the `PART B — LOCKDOWN` banner to the end → **Run**. It locks the database so only the functions (service key) can reach it. The last result table must show **`ok = true` on every row**; see supabase/README.md if not. After Part B an *old* copy of the app can no longer sign in, which is the point.

**3.7 Optional: clean old saved home addresses.** Run `supabase/002_scrub_home_addresses.sql` once. Older app versions saved a student's real "Find my home" address in the cloud; this removes it from accounts that have not opened the new app. To also clean addresses of homes that were already sold, set `v_aggressive := true` near the top first (see its comments). Recommended, because the Privacy Policy says old saved homes are cleaned.

**3.8 Check the clean-up jobs:**

```sql
select jobname, schedule from cron.job;   -- expect mq-purge-password-resets and mq-purge-rate-counters
```

---

## 4. New access codes, then turn the old ones off

Each code makes exactly one account, ever. On your computer, in this repository's folder:

```sh
CODE_PEPPER='<the same value as in Netlify>' node scripts/generate-access-codes.js 50
CODE_PEPPER='<the same value as in Netlify>' node scripts/generate-access-codes.js 5 --free --note "teacher comps"
```

(Windows PowerShell: `$env:CODE_PEPPER='<value>'; node scripts/generate-access-codes.js 50`.)

1. The script prints the codes (like `K7PM-WX3R-9QHT`). Save them now; they are not stored anywhere else.
2. It also prints an `insert into public.access_codes …` statement. Paste it into **SQL Editor → New query → Run**.
3. Test one code (`generate-access-codes.js 1 --free --note "rollout test"`) by signing up.

The 151 old codes have public hashes, so anyone could forge them. Once buyers and teachers have new codes: add `LEGACY_CODES` = `off` in Netlify and redeploy. Old accounts keep working; only unused old codes stop.

To cancel unused codes: `update public.access_codes set disabled = true where note = 'teacher comps';`

---

## 5. Convert the admin hashes to scrypt

The old admin hashes (starting with `h`) are only 32 bits and can be cracked quickly. On your computer, in this repository's folder:

```sh
node deploy/netlify/functions/lib/crypto.js hash 'email::you@example.com'      # your admin email, lower case
node deploy/netlify/functions/lib/crypto.js hash 'adminpw::YourAdminPassword'  # a long, new password
node deploy/netlify/functions/lib/crypto.js hash 'admincode::YOURADMINCODE'    # admin code, UPPER CASE
```

Each prints a line starting with `scrypt$`. Put them into `ADMIN_EMAIL_HASH`, `ADMIN_PW_HASH` and `ADMIN_CODE_HASH` in Netlify (replace the old values), redeploy, then sign in to the admin dashboard to check. Keep the single quotes in the commands. Clear your terminal history afterwards if others use the computer.

---

## 6. Rebuild `tailwind.css` (only after changing class names)

The styles are prebuilt into `deploy/tailwind.css`. After you add or change Tailwind class names in `deploy/*.html`:

```sh
npm ci
npm run build:css
```

Commit the changed `deploy/tailwind.css`. CI fails if it is out of date. Class names built from pieces (`'bg-' + color`) are not detected; write full class names.

To upgrade a library in `deploy/vendor/`, follow [deploy/vendor/README.md](../deploy/vendor/README.md) (new versioned folder, update hashes).

---

## 7. Provider dashboards (limits and alerts)

Each of these stops a leaked key or a traffic spike from costing money.

- **Resend:** **Domains → Add domain**, add the DNS records it shows, wait for "Verified", then set `RESEND_FROM` to an address on that domain. Without this, reset emails reach only you. Use an API key with sending access only (limit it to that domain if offered). Keep `RESET_EMAILS_PER_DAY` (default 80) below your plan's daily sending limit, and turn on usage notifications if your plan has them.
- **RentCast** (only if `RENTCAST_API_KEY` is set): choose a plan without automatic overage charges, or set a hard usage limit if the dashboard offers one. In Netlify, `RENTCAST_MAX_CALLS_PER_HOUR` caps paid calls site-wide (default 40/hour; `0` turns them off).
- **MapTiler** (if `MAPTILER_KEY` is set): **Account → API keys** → your key → **Allowed HTTP origins** = `nextgenwealthproject.netlify.app` (add any custom domain). Use a key made only for this site. The key is visible in tile URLs, so the origin lock is the protection.
- **Stadia Maps** (if used): in the client dashboard, add `nextgenwealthproject.netlify.app` to your property's domains (domain-based auth). If that works, you can leave `STADIA_API_KEY` unset.
- **Supabase:** **Organization → Billing**: keep the **spend cap** on (paid plans). Check **Database → Extensions → pg_cron** is enabled. In **Project Settings → API**, turn off automatic exposure of new tables if offered.
- **Netlify:** **Team → Billing / Usage**: watch function invocations and bandwidth, and turn on usage notifications if your plan has them. Check **Logs → Functions** after deploys for lines like `*** DATABASE NOT MIGRATED ***` or `rl_hit failed`.

---

## 8. Owner to-dos outside the code

- **Mailing address in the Privacy Policy.** `deploy/privacy.html` section 13 shows "TODO: owner to add a mailing address". COPPA requires the operator's contact details for parents. Replace it with a real mailing address or PO box, and confirm the privacy email address is the one you want parents to use.
- If you change the Terms or Privacy Policy in a meaningful way, update the effective date and bump `CONSENT_VERSION` in **both** `deploy/app.html` and `deploy/netlify/functions/lib/session.js` (they must match, or sign-up fails).

---

## 9. Smoke test after every deploy

Use a private/incognito window. Replace `SITE` with `https://nextgenwealthproject.netlify.app`.

**Pages and headers**
- [ ] `SITE/`, `SITE/app.html`, `SITE/privacy.html` and `SITE/terms.html` load. Browser console (F12) shows no red errors and no "Content Security Policy" messages.
- [ ] `curl -sI SITE/app.html` shows `strict-transport-security`, `content-security-policy` and `cache-control: no-cache, no-store`.
- [ ] `SITE/netlify.toml` and `SITE/netlify/functions/auth-login.js` give 404.

**Accounts**
- [ ] Sign up: pick "12 or younger" → sign-up is blocked, and the Network tab shows no request was sent.
- [ ] Sign up (in another browser profile) with a test code, age 13–17, tick the box → account created. In Supabase: `select email, age_band, consent_version, consent_at from public.users order by created_at desc limit 1;` shows `13-17`, `2026-11-02` and a time.
- [ ] Using the same code again → "already used".
- [ ] Sign out, sign in again; progress is still there. Sign in on a second browser; progress matches.
- [ ] Forgot password → email arrives from your `RESEND_FROM` address → code works → the second browser is signed out when it reloads (a password change ends every session).
- [ ] `select count(*) from public.rate_counters;` is above 0 (durable rate limits work). Netlify function logs show no `rl_hit failed`.

**Game features**
- [ ] City → map loads tiles; a city search works.
- [ ] Pro track: "Find my home" returns an estimate; the map moves near, not onto, the house.
- [ ] Stock and crypto prices load (`SITE/.netlify/functions/get-prices` returns JSON).
- [ ] Me page: Feedback button shows on Pro, not on Junior.

**Admin and deletion**
- [ ] Admin login with the scrypt credentials works; the Users list loads.
- [ ] On the test account: Me → **Delete my data** → "Your account and data were deleted." Signing in with it now fails, and `select * from public.users where email = '<test email>';` returns no rows.

**Database lockdown (after Part B)**
- [ ] The Part B verification table shows `ok = true` on every row.
- [ ] `select jobname from cron.job;` lists the two `mq-purge-…` jobs.
