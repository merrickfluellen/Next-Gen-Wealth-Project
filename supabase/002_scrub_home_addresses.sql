-- ════════════════════════════════════════════════════════════════════════════
-- 002_scrub_home_addresses.sql — OPTIONAL, ONE-TIME privacy clean-up.
--
-- Older app versions saved a student's real "Find my home" result in the cloud: street address,
-- ZIP, census tract and exact coordinates, inside progress.real_estate, and copied the address
-- into progress.economy (money ledger labels, bank notices, phone texts, deal calculator).
-- The current app never saves these, and cleans a device when it opens, but rows of students who
-- never open the new version keep them. This script cleans those rows on the server.
--
-- What it does, per progress row (same rules as the app's reScrubHome / reMigrateLocalHomes):
--   real_estate.myProps entries with isHome / ownerOccupied:
--     • removes zip, geo, tract, census/postal fields; rounds lat/lng to 0.01° (~1 km)
--     • for homes that came from "Find my home" (homeLookup / confidence / explain):
--       address → 'My home', id → a fresh 'home_…' id (lookup ids can encode the address;
--       reTenants keys follow the new id)
--   economy: every address (and old id) collected above is replaced in the whole column
--     ('My home' / the new id).
--   Changed columns get savedAt = now, so the clean cloud copy replaces older copies on devices.
--
-- STEP 2 (off by default): addresses of homes that were already SOLD are no longer in
-- real_estate, so step 1 cannot know them. Set v_aggressive := true below to also rewrite the
-- old-version ledger/notice templates and the deal-calculator address in economy for EVERY row
-- ("Mortgage + taxes + insurance · <address>" → "… · a property", etc.). This also renames
-- fictional game properties in those old labels; it changes nothing else.
--
-- Safe to run more than once (a clean row is left unchanged). Runs in one transaction; rows whose
-- JSON can't be rewritten are skipped with a NOTICE. Take a backup first if you want an undo:
--   create table public.progress_backup_scrub as select * from public.progress;   -- drop it afterwards!
--   (a backup holds the addresses you are removing: delete it once you have checked the result)
-- ════════════════════════════════════════════════════════════════════════════

do $scrub$
declare
  v_aggressive constant boolean := false;   -- STEP 2: set to true to also clean sold-home leftovers

  r          record;
  re         jsonb;
  props      jsonb;
  tenants    jsonb;
  p          jsonb;
  new_props  jsonb;
  addrs      text[];
  id_old     text[];
  id_new     text[];
  is_lookup  boolean;
  nid        text;
  econ_txt   text;
  econ_new   jsonb;
  re_changed boolean;
  ec_changed boolean;
  a          text;
  i          int;
  n_rows     int := 0;
  n_skip     int := 0;
  now_ms     bigint := (extract(epoch from clock_timestamp()) * 1000)::bigint;
  truthy     constant text[] := array['true', '1', 'yes'];
begin
  for r in
    select ctid, email, real_estate::jsonb as real_estate, economy::jsonb as economy
      from public.progress
     where real_estate is not null or (v_aggressive and economy is not null)
  loop
    begin
      re := r.real_estate; addrs := '{}'; id_old := '{}'; id_new := '{}';
      re_changed := false; ec_changed := false;

      -- ── step 1: real_estate homes ───────────────────────────────────────────
      if re is not null and jsonb_typeof(re) = 'object' and jsonb_typeof(re -> 'myProps') = 'array' then
        props := re -> 'myProps';
        tenants := case when jsonb_typeof(re -> 'reTenants') = 'object' then re -> 'reTenants' else '{}'::jsonb end;
        new_props := '[]'::jsonb;
        for p in select value from jsonb_array_elements(props) loop
          if jsonb_typeof(p) = 'object'
             and (lower(coalesce(p ->> 'isHome', '')) = any (truthy) or lower(coalesce(p ->> 'ownerOccupied', '')) = any (truthy)) then
            is_lookup := lower(coalesce(p ->> 'homeLookup', '')) = any (truthy) or p ? 'confidence' or p ? 'explain';
            p := p - 'zip' - 'zipCode' - 'zipcode' - 'postalCode' - 'postal_code' - 'geo' - 'tract'
                   - 'censusTract' - 'census_tract' - 'county' - 'fips' - 'geoid' - 'block' - 'blockGroup';
            if jsonb_typeof(p -> 'lat') = 'number' then p := jsonb_set(p, '{lat}', to_jsonb(round((p ->> 'lat')::numeric, 2))); end if;
            if jsonb_typeof(p -> 'lng') = 'number' then p := jsonb_set(p, '{lng}', to_jsonb(round((p ->> 'lng')::numeric, 2))); end if;
            if jsonb_typeof(p -> 'lon') = 'number' then p := jsonb_set(p, '{lon}', to_jsonb(round((p ->> 'lon')::numeric, 2))); end if;
            if is_lookup then
              a := p ->> 'address';
              if a is not null and a <> 'My home' and char_length(btrim(a)) >= 5 then addrs := addrs || a; end if;
              p := jsonb_set(p, '{address}', '"My home"') || '{"homeLookup": true}'::jsonb;
              if coalesce(p ->> 'id', '') !~ '^home_' then
                nid := 'home_' || substr(md5(random()::text || clock_timestamp()::text), 1, 12);
                if p ->> 'id' is not null then
                  if tenants ? (p ->> 'id') then
                    tenants := (tenants - (p ->> 'id')) || jsonb_build_object(nid, tenants -> (p ->> 'id'));
                  end if;
                  if char_length(p ->> 'id') >= 5 then id_old := id_old || (p ->> 'id'); id_new := id_new || nid; end if;
                end if;
                p := jsonb_set(p, '{id}', to_jsonb(nid), true);
              end if;
            end if;
          end if;
          new_props := new_props || jsonb_build_array(p);
        end loop;
        if new_props is distinct from props or tenants is distinct from coalesce(re -> 'reTenants', '{}'::jsonb) then
          re := jsonb_set(jsonb_set(re, '{myProps}', new_props), '{reTenants}', tenants, true)
                || jsonb_build_object('savedAt', now_ms);
          re_changed := true;
        end if;
      end if;

      -- ── economy: replace the collected addresses / ids ──────────────────────
      econ_new := r.economy;
      if r.economy is not null and (cardinality(addrs) > 0 or cardinality(id_old) > 0 or v_aggressive) then
        econ_txt := r.economy::text;
        foreach a in array addrs loop
          -- the JSON-escaped form (as it appears in the text) and, for strings nested inside JSON
          -- strings (economy.extras.*), the twice-escaped form
          econ_txt := replace(econ_txt, substr(to_jsonb(a)::text, 2, char_length(to_jsonb(a)::text) - 2), 'My home');
          econ_txt := replace(econ_txt,
            substr(to_jsonb(substr(to_jsonb(a)::text, 2, char_length(to_jsonb(a)::text) - 2))::text, 2,
                   char_length(to_jsonb(substr(to_jsonb(a)::text, 2, char_length(to_jsonb(a)::text) - 2))::text) - 2),
            'My home');
        end loop;
        for i in 1 .. coalesce(cardinality(id_old), 0) loop
          econ_txt := replace(econ_txt, substr(to_jsonb(id_old[i])::text, 2, char_length(to_jsonb(id_old[i])::text) - 2), id_new[i]);
        end loop;

        -- ── step 2 (optional): old-version templates that embedded any property's address ──
        if v_aggressive then
          econ_txt := regexp_replace(econ_txt, '(Mortgage \+ taxes \+ insurance · )[^"\\]{1,200}', '\1a property', 'g');
          econ_txt := regexp_replace(econ_txt, '(Property taxes \+ insurance · )[^"\\]{1,200}', '\1a property', 'g');
          econ_txt := regexp_replace(econ_txt, '(Mortgage \+ taxes · |Property taxes · |Mortgage · )[^"\\]{1,200}', '\1a property', 'g');
          econ_txt := regexp_replace(econ_txt, '(mortgage payments? on )[^"\\(]{1,200}( \()', '\1a property\2', 'g');
          econ_txt := regexp_replace(econ_txt, '(mortgage payments on )[^"\\.]{1,200}(\.)', '\1a property\2', 'g');
          econ_txt := regexp_replace(econ_txt, '(property taxes/insurance on )[^"\\.]{1,200}(\.)', '\1a property\2', 'g');
          -- deal calculator (economy.extras.dealCalc is a JSON string, so its quotes appear as \")
          econ_txt := regexp_replace(econ_txt, '(\\"address\\":\s*\\")[^"\\]{1,200}(\\")', '\1\2', 'g');
        end if;

        if econ_txt <> r.economy::text then
          econ_new := econ_txt::jsonb;   -- throws on a broken rewrite → row skipped below
          if jsonb_typeof(econ_new) = 'object' then econ_new := econ_new || jsonb_build_object('savedAt', now_ms); end if;
          ec_changed := true;
        end if;
      end if;

      if re_changed or ec_changed then
        update public.progress
           set real_estate = case when re_changed then re else real_estate end,
               economy     = case when ec_changed then econ_new else economy end
         where ctid = r.ctid;
        n_rows := n_rows + 1;
      end if;
    exception when others then
      n_skip := n_skip + 1;
      raise notice 'skipped progress row % (%): %', r.ctid, left(coalesce(r.email, ''), 3) || '…', sqlerrm;
    end;
  end loop;
  raise notice 'home-address scrub: % row(s) changed, % skipped (aggressive step 2: %)', n_rows, n_skip, v_aggressive;
end
$scrub$;

-- Check: should return 0 for both counts (step 1 targets). Any saved home still carrying a ZIP,
-- census data, unrounded coordinates or a street address:
select count(*) filter (where p ? 'zip' or p ? 'geo' or p ? 'tract') as homes_with_zip_or_tract,
       count(*) filter (where (jsonb_typeof(p -> 'lat') = 'number' and (p ->> 'lat')::numeric <> round((p ->> 'lat')::numeric, 2))
                           or (jsonb_typeof(p -> 'lng') = 'number' and (p ->> 'lng')::numeric <> round((p ->> 'lng')::numeric, 2))) as homes_with_exact_coords,
       count(*) filter (where (p ? 'homeLookup' or p ? 'confidence' or p ? 'explain') and coalesce(p ->> 'address', '') <> 'My home') as lookups_with_address
  from public.progress, jsonb_array_elements(case when jsonb_typeof(real_estate::jsonb -> 'myProps') = 'array'
                                                  then real_estate::jsonb -> 'myProps' else '[]'::jsonb end) as e(p)
 where jsonb_typeof(p) = 'object' and (p ->> 'isHome' in ('true', '1') or p ->> 'ownerOccupied' in ('true', '1'));
