# Supabase security setup

Until now the app signed people in, checked access codes and saved progress **in the browser**, using
the public Supabase key. Anyone could read every password hash, sign in as anyone, and overwrite
anyone's progress. The fix moves all of that into Netlify functions that use the secret
**service role key**, and then locks the tables so the public key can't touch them.

New functions (in `deploy/netlify/functions/`): `auth-signup`, `auth-login`, `auth-session`,
`progress`, `admin-users`, `auth-delete`. `reset-password` and `confirm-reset` use `public.password_resets` (created in Part A).

Files:

| File | What | When |
|---|---|---|
| `001_security.sql` Part A | Additive: access codes, redemptions, password resets, **rate limiter** (`rate_counters` + `rl_hit`), **atomic signup** (`create_user_with_code`), **account deletion** (`delete_account`), consent columns on `users`, daily cleanup (pg_cron), closed default privileges | Any time; re-run whenever the file changes |
| `001_security.sql` Part B | Lockdown: RLS deny-all, unique email indexes, revoke anon on tables/views/sequences, JSON size limits, verification | After the new app is live |
| `002_scrub_home_addresses.sql` | Optional one-time privacy clean-up of old saved home addresses | Any time after Part A |

Database functions (all `SECURITY DEFINER`, callable **only** with the service key — `anon`/`authenticated` get permission denied):

| Function | Returns | Used by |
|---|---|---|
| `rl_hit(p_key text, p_window_sec int, p_max int)` | new count (int) in the current fixed window; stops counting at `p_max + 1` | `lib/ratelimit.js` |
| `create_user_with_code(p_email, p_name, p_pw_hash, p_code_hash, p_source, p_free, p_age_band, p_consent_version)` | `'ok'` / `'code_used'` / `'account_exists'` / `'code_invalid'`; all-or-nothing | `auth-signup` |
| `delete_account(p_email text)` | jsonb counts | `auth-delete` (the app's "Delete my data" button); you, in the SQL editor |

## 1. Set the Netlify environment variables

Netlify → your site → **Site configuration → Environment variables → Add a variable**.

| Variable | Value | Notes |
|---|---|---|
| `SUPA_SERVICE_KEY` | Supabase → **Project Settings → API Keys** → the `service_role` / secret key | Probably already set (password reset uses it). Never put it in app.html. |
| `SESSION_SECRET` | already set — **must be at least 32 characters**. New value: `node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"` | Signs sign-in, admin and reset tokens. A shorter value is now **rejected**: sign-in, sign-up, admin and reset all fail with "unavailable" until it is fixed. Check its length before deploying. Changing it signs everyone out. |
| `CODE_PEPPER` | a new random value, at least 32 characters: `node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"` | Secret key for new access codes. Keep a copy in your password manager: you need the same value to generate codes. Changing it kills every unused new code. Shorter values are ignored, and then every new code is rejected. |
| `LEGACY_CODES` | leave unset for now; set to `off` later | While unset, the 151 old codes still work, **each one once**. Their hashes are public and can be forged, so turn them off once you've sold/handed out new codes. |
| `SUPABASE_URL` | optional | Defaults to `https://vtxuvmtnqlxidnswnunx.supabase.co`. |

These are only the variables this SQL rollout depends on. The full list (Resend, admin hashes, map and RentCast keys, limits) is in [docs/ENV.md](../docs/ENV.md); the whole deployment is in [docs/SETUP.md](../docs/SETUP.md).

After changing variables, redeploy (**Deploys → Trigger deploy → Deploy site**).

## 2. Rollout order (important)

Running Part B of the SQL turns off the old way the app talks to the database. Do the steps in this order:

1. **Enable pg_cron** (once): Supabase → **Database → Extensions** → search `pg_cron` → enable.
   Part A then schedules two daily clean-up jobs (password-reset rows older than 2 days, expired
   rate-limit counters). Without it Part A prints a WARNING and nothing is ever deleted.
2. **Run SQL Part A** (safe at any time; the current app keeps working).
   Supabase → left sidebar **SQL Editor** → **New query** → paste everything in
   `001_security.sql` from the top **down to (not including) the "PART B — LOCKDOWN" banner** → **Run**.
   - Part A must be live **before** functions that use the new database functions are deployed
     (`rl_hit`, `create_user_with_code`). Until it is, the rate limiter falls back to per-instance
     memory, and global budgets (paid map lookups, reset e-mails) **refuse** (fail closed).
   - The last result table lists duplicate emails. If it shows any rows, see *Duplicates* below.
   - Already ran an older Part A? Just run the new Part A again: every statement is idempotent.
3. **Set the env vars** from step 1 and deploy (functions and app.html ship together from `deploy/`,
   so steps 3 and 4 are one deploy in practice).
4. **Check the new app** on the live site: sign up with a test code
   (`generate-access-codes.js 1 --free --note "rollout test"` — every code works once, ever), sign in,
   make progress, reload, sign in on a second browser.
5. **Run SQL Part B** — paste the rest of `001_security.sql` (from the "PART B — LOCKDOWN" banner to the end) → **Run**.
   - The final result table must show **`ok = true` on every row**. It lists every table, view,
     sequence and function in `public` that `anon` or `authenticated` can reach. A row with `ok = false`
     is reachable with the public key: revoke it (`revoke all on public.<name> from anon, authenticated;`)
     or ask before leaving it.
   - Notices like `locked dependent view …` mean a view over the user tables was found and closed.
   - `… stays NOT VALID …` means some old progress rows are bigger than the 400 KB JSON limit.
     New saves are still checked. Trim those rows, then run the `validate constraint` line from the notice.
6. **Optional privacy clean-up**: run `002_scrub_home_addresses.sql` (see the comments at its top).
7. Generate new codes (below), then set `LEGACY_CODES=off` and redeploy.
8. Optional: in Supabase → **Authentication → Policies**, confirm every table shows "RLS enabled" with
   **no policies**. "No policies" is correct: only the functions (service role) may read them.
   Also check: `select * from pg_publication_tables where pubname = 'supabase_realtime';` should list
   none of the app tables, and **Project Settings → API**: turn off "automatically expose new tables" if offered.

### Rollback

**Fix forward.** The current app.html never uses the public key, so re-opening the tables does not help
it. Only if you must put back an *old* app.html (one that talks to Supabase from the browser), run:

```sql
alter table public.users    disable row level security;
alter table public.progress disable row level security;
grant select, insert, update on public.users, public.progress to anon;
grant usage on all sequences in schema public to anon;
```

That reopens the original hole (anyone can read every password hash), so undo it as soon as you can by
running Part B again. Disabling RLS alone does nothing: Part B also revoked the grants.

Part A objects can stay in place under an old app (nothing uses them). To remove them anyway:

```sql
select cron.unschedule('mq-purge-password-resets'); select cron.unschedule('mq-purge-rate-counters');
drop function if exists public.create_user_with_code(text, text, text, text, text, boolean, text, text);
drop function if exists public.delete_account(text);
drop function if exists public.rl_hit(text, int, int);
drop type if exists public.signup_status;
drop table if exists public.rate_counters;
```

(Keep `access_codes`, `code_redemptions` and `password_resets`: deleting `code_redemptions` re-enables every used code.)

## Deleting an account (parent requests, "delete my data")

Signed-in users delete their own account with **Delete my data** on the Me/Profile page (`auth-delete`
calls the function below). For a parent's request by email, run it yourself:

```sql
select public.delete_account('child@example.com');
```

It deletes the `users` and `progress` rows and the rate-limit counters keyed by that email, and blanks
the email in `code_redemptions` but **keeps the code hash** — so the code cannot be used again.
`password_resets` rows (and the reset rate-limit counters) store only a keyed hash of the email
(`h1:…`), so they are not matched by email; they hold no address and are deleted by the daily job
within 2 days. Do **not** delete `code_redemptions` rows by hand: that makes the code redeemable again.

## Retention

- `password_resets`: deleted after 2 days (pg_cron job `mq-purge-password-resets`, 03:17 UTC daily).
- `rate_counters`: deleted once their window is over (job `mq-purge-rate-counters`, 03:27 UTC daily).
- See the jobs: `select jobname, schedule, command from cron.job;` and runs: `select * from cron.job_run_details order by start_time desc limit 20;`

## Future tables and functions

Part A turns off Supabase's default "grant everything to anon/authenticated" for **new** tables,
sequences and functions in `public` (created by `postgres`), and PUBLIC's default EXECUTE on new
functions. A new table therefore starts closed; enable RLS on it and grant `service_role` what it
needs. A new function needs `grant execute on function … to service_role;`.

## 3. New access codes

```
CODE_PEPPER='<same value as Netlify>' node scripts/generate-access-codes.js 50
CODE_PEPPER='<same value as Netlify>' node scripts/generate-access-codes.js 5 --free --note "teacher comps"
```

The script prints the codes (like `K7PM-WX3R-9QHT`) and an `insert into public.access_codes …` statement.
Save the codes, then paste the SQL into **SQL Editor → New query → Run**. The database only stores a
keyed hash, so a database leak does not leak codes. Each code can create exactly one account
(`code_redemptions` remembers every redeemed code, old and new).

To cancel an unused code you no longer trust: `update public.access_codes set disabled = true where note = '…';`
To see who redeemed what: `select * from public.code_redemptions order by redeemed_at desc;`

## Duplicates

`UNIQUE(email)` can't be added while two rows share an email. List them:

```sql
select * from public.users
 where lower(btrim(email)) in (select lower(btrim(email)) from public.users group by 1 having count(*) > 1)
 order by lower(btrim(email)), created_at;
```

The **oldest** row is normally the real account (a later duplicate may have been planted through the
old open table). Delete the others by their `id` (or `ctid` if there is no id column), e.g.
`delete from public.users where id = 123;`. Do the same for `progress` (keep the row with the most
progress / latest `updated_at`). Then run Part B again.

## Existing passwords

Old accounts have a weak 32-bit password hash. The first time each user signs in through the new
`auth-login`, the function checks the old hash and silently replaces it with a strong scrypt hash.
Accounts that never sign in keep the weak hash; with the tables locked it is no longer readable, but
you can force everyone to reset later if you want (e.g. after a few months, clear `pw_hash` for rows that
don't start with `scrypt$`; those users then use "Forgot password").
