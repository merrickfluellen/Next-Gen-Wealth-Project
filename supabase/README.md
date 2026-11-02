# Supabase security setup

Until now the app signed people in, checked access codes and saved progress **in the browser**, using
the public Supabase key. Anyone could read every password hash, sign in as anyone, and overwrite
anyone's progress. The fix moves all of that into Netlify functions that use the secret
**service role key**, and then locks the tables so the public key can't touch them.

New functions (in `deploy/netlify/functions/`): `auth-signup`, `auth-login`, `auth-session`,
`progress`, `admin-users`.

## 1. Set the Netlify environment variables

Netlify → your site → **Site configuration → Environment variables → Add a variable**.

| Variable | Value | Notes |
|---|---|---|
| `SUPA_SERVICE_KEY` | Supabase → **Project Settings → API Keys** → the `service_role` / secret key | Probably already set (password reset uses it). Never put it in app.html. |
| `SESSION_SECRET` | already set | Signs sign-in tokens (and admin tokens). Changing it signs everyone out. |
| `CODE_PEPPER` | a new random value, at least 32 characters: `node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"` | Secret key for new access codes. Keep a copy in your password manager: you need the same value to generate codes. Changing it kills every unused new code. |
| `LEGACY_CODES` | leave unset for now; set to `off` later | While unset, the 151 old codes still work, **each one once**. Their hashes are public and can be forged, so turn them off once you've sold/handed out new codes. |
| `SUPABASE_URL` | optional | Defaults to `https://vtxuvmtnqlxidnswnunx.supabase.co`. |

After changing variables, redeploy (**Deploys → Trigger deploy → Deploy site**).

## 2. Rollout order (important)

Running Part B of the SQL turns off the old way the app talks to the database. Do the steps in this order:

1. **Run SQL Part A** (safe at any time; the current app keeps working).
   Supabase → left sidebar **SQL Editor** → **New query** → paste everything in
   `001_security.sql` from the top **down to (not including) the "PART B — LOCKDOWN" banner** → **Run**.
   - The last result table lists duplicate emails. If it shows any rows, see *Duplicates* below.
2. **Set the env vars** from step 1 and deploy the new functions.
3. **Deploy the new app.html** that signs in through `/.netlify/functions/auth-login` etc.
   Check on the live site: sign up with a test code, sign in, make progress, reload, sign in on a second browser.
4. **Run SQL Part B** — paste the rest of `001_security.sql` (from the "PART B — LOCKDOWN" banner to the end) → **Run**.
   The final result table must show `rls = true` and `anon_select = false`, `anon_update = false` for all four tables.
5. Generate new codes (below), then set `LEGACY_CODES=off` and redeploy.
6. Optional but recommended: in Supabase → **Authentication → Policies**, confirm `users` and `progress`
   show "RLS enabled" with **no policies**. "No policies" is correct: only the functions (service role) may read them.

If something goes wrong after step 4, you can temporarily undo the lockdown with
`alter table public.users disable row level security; alter table public.progress disable row level security;`
— but that reopens the hole, so fix forward instead where you can.

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
