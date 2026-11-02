-- ════════════════════════════════════════════════════════════════════════════
-- 001_security.sql — lock down users/progress and add server-side access codes.
-- Read supabase/README.md first: PART A is safe at any time; PART B BREAKS the
-- old browser client and must only run after the new app.html is live.
-- Every statement is idempotent (safe to run again).
-- ════════════════════════════════════════════════════════════════════════════


-- ════════════════════════════════════════════════════════════════════════════
-- PART A — additive. Safe to run now; the old client keeps working.
-- ════════════════════════════════════════════════════════════════════════════

-- A1. New access codes (only HMAC-SHA256(CODE_PEPPER, code) is stored).
create table if not exists public.access_codes (
  code_hash  text primary key check (code_hash ~ '^[0-9a-f]{64}$'),
  free       boolean not null default false,
  disabled   boolean not null default false,
  note       text,
  created_at timestamptz not null default now()
);

-- A2. One row per redeemed code (v2 and legacy). UNIQUE(code_hash) = each code works once, ever.
create table if not exists public.code_redemptions (
  id          bigint generated always as identity primary key,
  code_hash   text not null,
  email       text not null,
  source      text,
  redeemed_at timestamptz not null default now()
);
create unique index if not exists code_redemptions_code_hash_key on public.code_redemptions (code_hash);

-- A3. Server-only: RLS on with NO policies (deny all), and no privileges for the public roles.
alter table public.access_codes     enable row level security;
alter table public.code_redemptions enable row level security;
revoke all on table public.access_codes     from anon, authenticated, public;
revoke all on table public.code_redemptions from anon, authenticated, public;
grant  all on table public.access_codes     to service_role;
grant  all on table public.code_redemptions to service_role;

-- A4. pw_hash must hold scrypt strings (~110 chars). Widen it if it is a short varchar/char.
do $$
declare t text; n int;
begin
  select data_type, character_maximum_length into t, n
    from information_schema.columns
   where table_schema = 'public' and table_name = 'users' and column_name = 'pw_hash';
  if t is null then
    raise notice 'users.pw_hash not found — check the users table';
  elsif t in ('character varying', 'character') and (n is null or n < 255) then
    execute 'alter table public.users alter column pw_hash type text';
    raise notice 'users.pw_hash widened to text';
  end if;
end $$;

-- A5. Look for duplicate / non-normalised emails BEFORE running Part B.
--     Both queries should return no rows. If they do, see "Duplicates" in README.md.
select 'users' as tbl, lower(btrim(email)) as email, count(*) as n
  from public.users where email is not null group by 1, 2 having count(*) > 1
union all
select 'progress', lower(btrim(email)), count(*)
  from public.progress where email is not null group by 1, 2 having count(*) > 1;


-- ════════════════════════════════════════════════════════════════════════════
-- PART B — LOCKDOWN. Run ONLY after the new functions + new app.html are live.
-- After this, the old app.html can no longer sign in or save (that is the point).
-- ════════════════════════════════════════════════════════════════════════════

-- B1. Stop if duplicates remain (resolve them first — see README.md "Duplicates").
do $$
begin
  if exists (select 1 from public.users where email is not null group by lower(btrim(email)) having count(*) > 1) then
    raise exception 'users has duplicate emails — resolve them first (README.md, "Duplicates")';
  end if;
  if exists (select 1 from public.progress where email is not null group by lower(btrim(email)) having count(*) > 1) then
    raise exception 'progress has duplicate emails — resolve them first (README.md, "Duplicates")';
  end if;
end $$;

-- B2. Normalise stored emails (the app always sends trim+lowercase).
update public.users    set email = lower(btrim(email)) where email <> lower(btrim(email));
update public.progress set email = lower(btrim(email)) where email <> lower(btrim(email));

-- B3. One account and one progress row per email, and emails must be normalised.
create unique index if not exists users_email_lower_key    on public.users    (lower(email));
create unique index if not exists progress_email_lower_key on public.progress (lower(email));
do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'users_email_normalised') then
    alter table public.users add constraint users_email_normalised
      check (email = lower(btrim(email)));
  end if;
  if not exists (select 1 from pg_constraint where conname = 'progress_email_normalised') then
    alter table public.progress add constraint progress_email_normalised
      check (email = lower(btrim(email)));
  end if;
end $$;

-- B4. Deny-all for the public key: RLS on, every existing policy dropped (an old
--     "allow all" policy would otherwise keep the tables open), privileges revoked.
--     Only the service role (used by the Netlify functions) can touch these tables.
alter table public.users    enable row level security;
alter table public.progress enable row level security;
do $$
declare p record;
begin
  for p in select policyname, tablename from pg_policies
            where schemaname = 'public' and tablename in ('users', 'progress') loop
    execute format('drop policy if exists %I on public.%I', p.policyname, p.tablename);
  end loop;
end $$;
revoke all on table public.users    from anon, authenticated, public;
revoke all on table public.progress from anon, authenticated, public;
grant  all on table public.users    to service_role;
grant  all on table public.progress to service_role;

-- B5. Optional size guard on progress JSON (matches the 256 KB per-column cap in progress.js).
--     Uncomment if you want the database to enforce it too.
-- alter table public.progress add constraint progress_json_size check (
--   coalesce(pg_column_size(lesson_notes), 0) < 300000 and coalesce(pg_column_size(portfolio), 0) < 300000
-- );

-- B6. Verify: both lines should say rls = true, anon_select = false, anon_update = false.
select c.relname as tbl, c.relrowsecurity as rls,
       has_table_privilege('anon', c.oid, 'select') as anon_select,
       has_table_privilege('anon', c.oid, 'update') as anon_update
  from pg_class c join pg_namespace n on n.oid = c.relnamespace
 where n.nspname = 'public' and c.relname in ('users', 'progress', 'access_codes', 'code_redemptions');
