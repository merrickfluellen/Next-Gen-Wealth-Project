-- ════════════════════════════════════════════════════════════════════════════
-- 001_security.sql — lock down users/progress and add server-side access codes.
-- Read supabase/README.md first: PART A is safe at any time; PART B BREAKS the
-- old browser client and must only run after the new app.html is live.
-- Every statement is idempotent (safe to run again): re-run the whole of Part A
-- (and later Part B) whenever this file changes.
-- Optional one-time privacy scrub of old saved home addresses: 002_scrub_home_addresses.sql.
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

-- A4b. Password reset tracking (durable 5-guess limit and per-email cap).
--      Server-only: RLS on, no anon/authenticated access.
create table if not exists public.password_resets (
  id text primary key,
  email text not null,
  attempts int not null default 0,
  used boolean not null default false,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);
create index if not exists password_resets_email_created
  on public.password_resets (email, created_at desc);
alter table public.password_resets enable row level security;
revoke all on table public.password_resets from anon, authenticated, public;
grant all on table public.password_resets to service_role;
-- Cleanup of rows older than 2 days is scheduled in A11 (pg_cron).

-- A6. Durable rate limiting (lib/ratelimit.js). One row per (key, fixed window).
--     Written ONLY through public.rl_hit() below; no role but service_role can even read it.
create table if not exists public.rate_counters (
  key          text        not null check (char_length(key) between 1 and 600),
  window_start timestamptz not null,
  window_sec   int         not null check (window_sec between 1 and 2678400),
  count        int         not null default 0,
  expires_at   timestamptz not null,
  primary key (key, window_start)
);
create index if not exists rate_counters_expires_at on public.rate_counters (expires_at);
alter table public.rate_counters enable row level security;
revoke all on table public.rate_counters from anon, authenticated, public;
grant  all on table public.rate_counters to service_role;

-- rl_hit(key, window_sec, max) → the new count in the current window (epoch-aligned fixed window).
-- Atomic (single INSERT … ON CONFLICT). Once the count is past p_max it stops writing and returns
-- p_max + 1, so a flood of rejected requests costs no row updates.
create or replace function public.rl_hit(p_key text, p_window_sec int, p_max int)
returns int
language plpgsql
security definer
set search_path = ''
as $fn$
declare
  v_start timestamptz;
  v_count int;
begin
  if p_key is null or char_length(p_key) not between 1 and 600 then
    raise exception 'rl_hit: bad key' using errcode = '22023';
  end if;
  if p_window_sec is null or p_window_sec not between 1 and 2678400 then
    raise exception 'rl_hit: bad window' using errcode = '22023';
  end if;
  if p_max is null or p_max not between 0 and 1000000000 then
    raise exception 'rl_hit: bad max' using errcode = '22023';
  end if;
  v_start := pg_catalog.to_timestamp(pg_catalog.floor(extract(epoch from pg_catalog.now()) / p_window_sec) * p_window_sec);
  insert into public.rate_counters as rc (key, window_start, window_sec, count, expires_at)
       values (p_key, v_start, p_window_sec, 1, v_start + pg_catalog.make_interval(secs => p_window_sec))
  on conflict (key, window_start) do update
       set count = rc.count + 1
     where rc.count <= p_max
  returning rc.count into v_count;
  return coalesce(v_count, p_max + 1);
end
$fn$;
revoke all     on function public.rl_hit(text, int, int) from public, anon, authenticated;
grant  execute on function public.rl_hit(text, int, int) to service_role;

-- A7. Consent record on users (auth-signup stores what the signup form sends).
--     Allowed age bands must match lib/session.js AGE_BANDS; under-13 is never stored.
alter table public.users add column if not exists age_band        text;
alter table public.users add column if not exists consent_version text;
alter table public.users add column if not exists consent_at      timestamptz;
do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'users_age_band_check' and conrelid = 'public.users'::regclass) then
    alter table public.users add constraint users_age_band_check
      check (age_band is null or age_band in ('13-17', '18+'));
  end if;
  if not exists (select 1 from pg_constraint where conname = 'users_consent_version_check' and conrelid = 'public.users'::regclass) then
    alter table public.users add constraint users_consent_version_check
      check (consent_version is null or char_length(consent_version) between 1 and 64);
  end if;
end $$;

-- A8. code_redemptions.email may be NULL: delete_account() anonymises the row but keeps code_hash,
--     so a redeemed code stays burned after the account is deleted.
alter table public.code_redemptions alter column email drop not null;

-- A9. Atomic signup: claim the code, create the user and reset the progress row in ONE transaction.
--     Returns 'ok' | 'code_used' | 'account_exists' | 'code_invalid' (v2 code missing/disabled).
--     Bad input raises SQLSTATE 22023 (PostgREST: HTTP 400). Nothing is written unless 'ok'.
do $$
begin
  if not exists (select 1 from pg_type t join pg_namespace n on n.oid = t.typnamespace
                  where n.nspname = 'public' and t.typname = 'signup_status') then
    create type public.signup_status as enum ('ok', 'code_used', 'account_exists', 'code_invalid');
  end if;
end $$;

create or replace function public.create_user_with_code(
  p_email           text,
  p_name            text,
  p_pw_hash         text,
  p_code_hash       text,
  p_source          text,
  p_free            boolean,
  p_age_band        text,
  p_consent_version text
)
returns public.signup_status
language plpgsql
security definer
set search_path = ''
as $fn$
declare
  v_email text := pg_catalog.lower(pg_catalog.btrim(p_email));
  v_free  boolean := coalesce(p_free, false);
  v_row   record;
  v_tbl   text;
begin
  if p_email is null or p_email <> v_email or char_length(v_email) not between 3 and 254
     or pg_catalog.strpos(v_email, '@') < 2 then
    raise exception 'create_user_with_code: email must be trimmed + lowercase' using errcode = '22023';
  end if;
  if p_name is null or char_length(pg_catalog.btrim(p_name)) not between 1 and 80 then
    raise exception 'create_user_with_code: bad name' using errcode = '22023';
  end if;
  if p_pw_hash is null or p_pw_hash not like 'scrypt$%' or char_length(p_pw_hash) > 255 then
    raise exception 'create_user_with_code: pw_hash must be a scrypt hash' using errcode = '22023';
  end if;
  if p_code_hash is null or char_length(p_code_hash) not between 1 and 200 then
    raise exception 'create_user_with_code: bad code hash' using errcode = '22023';
  end if;
  if p_age_band is null or p_age_band not in ('13-17', '18+') then
    raise exception 'create_user_with_code: bad age band' using errcode = '22023';
  end if;
  if p_consent_version is null or char_length(p_consent_version) not between 1 and 64 then
    raise exception 'create_user_with_code: bad consent version' using errcode = '22023';
  end if;

  -- Serialise signups for the same email (works even before Part B adds the unique indexes).
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('mq-signup:' || v_email, 0));

  -- v2 codes: re-check inside the transaction (the code may have been disabled meanwhile).
  if p_code_hash like 'v2:%' then
    select ac.free into v_row from public.access_codes ac
     where ac.code_hash = pg_catalog.substr(p_code_hash, 4) and not ac.disabled;
    if not found then return 'code_invalid'; end if;
    v_free := coalesce(v_row.free, false);
  end if;

  if exists (select 1 from public.code_redemptions where code_hash = p_code_hash) then
    return 'code_used';
  end if;
  if exists (select 1 from public.users u where u.email = v_email or pg_catalog.lower(u.email) = v_email) then
    return 'account_exists';
  end if;

  begin
    insert into public.code_redemptions (code_hash, email, source) values (p_code_hash, v_email, p_source);
    insert into public.users (email, name, pw_hash, free_access, age_band, consent_version, consent_at)
         values (v_email, p_name, p_pw_hash, v_free, p_age_band, p_consent_version, pg_catalog.now());
  exception when unique_violation then
    -- the savepoint of this block undoes BOTH inserts
    get stacked diagnostics v_tbl = table_name;
    if v_tbl = 'code_redemptions' then return 'code_used'; end if;
    return 'account_exists';
  end;

  -- A progress row for a brand-new email can only be an orphan (e.g. planted through the old open
  -- table), so it is replaced, never inherited.
  delete from public.progress p where p.email = v_email or pg_catalog.lower(pg_catalog.btrim(p.email)) = v_email;
  insert into public.progress (email, portfolio) values (v_email, '{"cash":0,"investments":[],"debt":0}');
  return 'ok';
end
$fn$;
revoke all     on function public.create_user_with_code(text, text, text, text, text, boolean, text, text) from public, anon, authenticated;
grant  execute on function public.create_user_with_code(text, text, text, text, text, boolean, text, text) to service_role;

-- A10. Account deletion (parent/COPPA requests, "delete my account"). Usage in the SQL editor:
--        select public.delete_account('child@example.com');
--      Deletes users, progress and password_resets rows and rate-limit counters keyed by the email,
--      and NULLs the email in code_redemptions (code_hash is KEPT, so the code stays burned).
--      Returns counts, e.g. {"users":1,"progress":1,"password_resets":0,"code_redemptions":1,"rate_counters":0}.
create or replace function public.delete_account(p_email text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $fn$
declare
  v   text := pg_catalog.lower(pg_catalog.btrim(p_email));
  vl  text;
  n_u int; n_p int; n_r int; n_c int; n_k int;
begin
  if v is null or char_length(v) not between 3 and 320 then
    raise exception 'delete_account: email required' using errcode = '22023';
  end if;
  vl := pg_catalog.replace(pg_catalog.replace(pg_catalog.replace(v, '\', '\\'), '%', '\%'), '_', '\_');
  delete from public.progress        where pg_catalog.lower(pg_catalog.btrim(email)) = v;  get diagnostics n_p = row_count;
  delete from public.password_resets where pg_catalog.lower(pg_catalog.btrim(email)) = v;  get diagnostics n_r = row_count;
  update public.code_redemptions set email = null
                                     where pg_catalog.lower(pg_catalog.btrim(email)) = v;  get diagnostics n_c = row_count;
  delete from public.users           where pg_catalog.lower(pg_catalog.btrim(email)) = v;  get diagnostics n_u = row_count;
  -- lib/ratelimit.js keys are "<bucket>|<window>|<key>"; email keys end in "|email" or ":email"
  delete from public.rate_counters   where key like '%|' || vl or key like '%:' || vl;     get diagnostics n_k = row_count;
  return pg_catalog.jsonb_build_object('users', n_u, 'progress', n_p, 'password_resets', n_r,
                                       'code_redemptions', n_c, 'rate_counters', n_k);
end
$fn$;
revoke all     on function public.delete_account(text) from public, anon, authenticated;
grant  execute on function public.delete_account(text) to service_role;

-- A11. Retention: daily cleanup with pg_cron (Supabase → Database → Extensions → pg_cron → Enable,
--      then run Part A again). password_resets rows are kept 2 days; rate counters until their window ends.
do $$
begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    if exists (select 1 from cron.job where jobname = 'mq-purge-password-resets') then
      perform cron.unschedule('mq-purge-password-resets');
    end if;
    if exists (select 1 from cron.job where jobname = 'mq-purge-rate-counters') then
      perform cron.unschedule('mq-purge-rate-counters');
    end if;
    perform cron.schedule('mq-purge-password-resets', '17 3 * * *',
      $job$delete from public.password_resets where created_at < now() - interval '2 days'$job$);
    perform cron.schedule('mq-purge-rate-counters', '27 3 * * *',
      $job$delete from public.rate_counters where expires_at < now() or window_start < now() - interval '32 days'$job$);
    raise notice 'pg_cron: scheduled mq-purge-password-resets and mq-purge-rate-counters (daily)';
  else
    raise warning 'pg_cron is NOT enabled, so old password_resets / rate_counters rows are never deleted. '
      'Enable it (Database → Extensions → pg_cron) and run Part A again, or run these two statements daily: '
      'delete from public.password_resets where created_at < now() - interval ''2 days''; '
      'delete from public.rate_counters where expires_at < now();';
  end if;
end $$;

-- A12. Future objects: Supabase grants anon/authenticated full rights on every NEW table, sequence and
--      function in public by default. Turn that off so the next migration is closed unless granted.
--      (Only affects objects created later by these roles; existing grants are handled in Part B.)
do $$
declare r text;
begin
  foreach r in array array['postgres', 'supabase_admin'] loop
    if exists (select 1 from pg_roles where rolname = r) then
      begin
        execute format('alter default privileges for role %I in schema public revoke all on tables from anon, authenticated', r);
        execute format('alter default privileges for role %I in schema public revoke all on sequences from anon, authenticated', r);
        execute format('alter default privileges for role %I in schema public revoke execute on functions from anon, authenticated, public', r);
        -- PUBLIC's EXECUTE on new functions is a GLOBAL default that a per-schema rule cannot remove,
        -- and anon inherits PUBLIC. Grant EXECUTE explicitly (e.g. to service_role) on new functions.
        execute format('alter default privileges for role %I revoke execute on functions from public', r);
        raise notice 'default privileges in public tightened for objects created by %', r;
      exception when insufficient_privilege then
        raise notice 'could not change default privileges of role % (not a member — that is fine for supabase_admin)', r;
      end;
    end if;
  end loop;
end $$;

-- A99. Look for duplicate / non-normalised emails BEFORE running Part B.
--      Both queries should return no rows. If they do, see "Duplicates" in README.md.
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
-- Plain indexes: every function query is `email=eq.<normalised email>`, which can't use lower(email).
-- (With the CHECK below, email is always normalised, so these are equivalent to the lower() ones.)
create unique index if not exists users_email_key          on public.users    (email);
create unique index if not exists progress_email_key       on public.progress (email);
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

-- B4b. Sequences (identity columns): anon could call nextval() and read the signup counter.
--      (Done here, not in Part A: the old client needs them to insert rows.)
revoke all on all sequences in schema public from anon, authenticated, public;

-- B4c. Views / materialized views built on the locked tables (directly or through other views).
--      A view owned by postgres bypasses RLS and is auto-granted to anon, so it would leak the
--      table. Revoke the public roles and make views run with the caller's rights.
do $$
declare r record;
begin
  for r in
    with recursive locked(oid) as (
      select c.oid from pg_class c join pg_namespace n on n.oid = c.relnamespace
       where n.nspname = 'public'
         and c.relname in ('users', 'progress', 'access_codes', 'code_redemptions', 'password_resets', 'rate_counters')
    ), deps(oid) as (
      select distinct w.ev_class from pg_depend d join pg_rewrite w on w.oid = d.objid
       where d.classid = 'pg_rewrite'::regclass and d.refobjid in (select oid from locked)
      union
      select w.ev_class from pg_depend d join pg_rewrite w on w.oid = d.objid
        join deps on d.refobjid = deps.oid
       where d.classid = 'pg_rewrite'::regclass
    )
    select c.oid::regclass as obj, c.relkind
      from deps join pg_class c on c.oid = deps.oid
     where c.relkind in ('v', 'm') and c.oid not in (select oid from locked)
  loop
    execute format('revoke all on %s from anon, authenticated, public', r.obj);
    if r.relkind = 'v' then
      begin
        execute format('alter view %s set (security_invoker = true)', r.obj);
      exception when others then
        raise notice 'could not set security_invoker on % (PostgreSQL < 15?): %', r.obj, sqlerrm;
      end;
    end if;
    raise notice 'locked dependent view %', r.obj;
  end loop;
end $$;

-- B5. Size guard on every progress JSON column. octet_length(col::text) measures the stored text form,
--     so it also catches number-exponent blow-ups (1e300 is stored as 301 digits); pg_column_size would
--     measure the compressed size and miss them. 400 000 bytes leaves room above progress.js's 256 KB cap
--     for jsonb's added spacing. Added NOT VALID (instant; new writes are checked), then validated:
--     if old rows are too big the constraint stays NOT VALID and a notice says so — trim those rows, then
--     `alter table public.progress validate constraint <name>;`.
do $$
declare c text; k text; n bigint;
begin
  foreach c in array array['lesson_notes', 'portfolio', 'completed_lessons', 'money_quest', 'real_estate', 'economy', 'world'] loop
    continue when not exists (select 1 from information_schema.columns
                               where table_schema = 'public' and table_name = 'progress' and column_name = c);
    k := 'progress_' || c || '_size';
    if not exists (select 1 from pg_constraint where conname = k and conrelid = 'public.progress'::regclass) then
      execute format('alter table public.progress add constraint %I check (%I is null or octet_length(%I::text) <= 400000) not valid', k, c, c);
    end if;
    begin
      execute format('alter table public.progress validate constraint %I', k);
    exception when check_violation then
      execute format('select count(*) from public.progress where octet_length(%I::text) > 400000', c) into n;
      raise notice '% row(s) have % larger than 400000 bytes; % stays NOT VALID until they are trimmed', n, c, k;
    end;
  end loop;
end $$;

-- B6. Verify. EVERY row must have ok = true. Covers all tables, views, materialized views and
--     sequences in public (anon AND authenticated, any privilege) plus every function in public
--     that anon/authenticated can execute. A row with ok = false is something the public key can reach.
select kind, name, rls, anon, authenticated,
       (not anon and not authenticated and (rls is distinct from false)) as ok
  from (
    select case c.relkind when 'r' then 'table' when 'p' then 'table' when 'v' then 'view'
                          when 'm' then 'matview' when 'S' then 'sequence' when 'f' then 'foreign table' end as kind,
           c.oid::regclass::text as name,
           case when c.relkind in ('r', 'p') then c.relrowsecurity end as rls,
           case when c.relkind = 'S'
                then has_sequence_privilege('anon', c.oid, 'usage,select,update')
                else has_table_privilege('anon', c.oid, 'select,insert,update,delete,truncate,references,trigger') end as anon,
           case when c.relkind = 'S'
                then has_sequence_privilege('authenticated', c.oid, 'usage,select,update')
                else has_table_privilege('authenticated', c.oid, 'select,insert,update,delete,truncate,references,trigger') end as authenticated
      from pg_class c join pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'public' and c.relkind in ('r', 'p', 'v', 'm', 'S', 'f')
    union all
    select 'function', p.oid::regprocedure::text, null,
           has_function_privilege('anon', p.oid, 'execute'),
           has_function_privilege('authenticated', p.oid, 'execute')
      from pg_proc p
     where p.pronamespace = 'public'::regnamespace
       and (has_function_privilege('anon', p.oid, 'execute') or has_function_privilege('authenticated', p.oid, 'execute')
            or p.proname in ('rl_hit', 'create_user_with_code', 'delete_account'))
  ) v
 order by ok, kind, name;
