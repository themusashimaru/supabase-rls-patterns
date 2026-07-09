-- ============================================================================
-- RLS audit: run this against any Supabase/Postgres project.
-- Every query returning rows is a finding. Wire it into CI or run it before
-- each deploy; the most common Supabase incident is a new table where RLS
-- was simply forgotten.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Exposed tables with RLS disabled (the big one)
--    Behind the anon key, each of these is a public read/write API.
-- ----------------------------------------------------------------------------
select n.nspname as schema, c.relname as table_name,
       'RLS DISABLED on exposed table' as finding
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind = 'r'
  and n.nspname = 'public'
  and not c.relrowsecurity;

-- ----------------------------------------------------------------------------
-- 2. RLS enabled but ZERO policies
--    Deny-all: often intentional for service-role-only tables, but verify
--    each one is deliberate rather than half-finished.
-- ----------------------------------------------------------------------------
select c.relname as table_name,
       'RLS on, no policies (deny-all: confirm intentional)' as finding
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind = 'r'
  and n.nspname = 'public'
  and c.relrowsecurity
  and not exists (
    select 1 from pg_policies p
    where p.schemaname = 'public' and p.tablename = c.relname
  );

-- ----------------------------------------------------------------------------
-- 3. Wide-open policies
--    Permissive policies OR together; a single using(true) defeats every
--    other policy on that verb. Each row here should be documented public data.
-- ----------------------------------------------------------------------------
select tablename, policyname, cmd,
       'using(true) policy: ORs over everything else' as finding
from pg_policies
where schemaname = 'public'
  and qual = 'true';

-- ----------------------------------------------------------------------------
-- 4. Verb coverage matrix
--    Not findings per se: a map of which verbs each table has decided.
--    A missing verb is denied, which is often correct; just make sure each
--    blank is a decision, not an accident.
-- ----------------------------------------------------------------------------
select tablename,
       count(*) filter (where cmd = 'SELECT') > 0 as has_select,
       count(*) filter (where cmd = 'INSERT') > 0 as has_insert,
       count(*) filter (where cmd = 'UPDATE') > 0 as has_update,
       count(*) filter (where cmd = 'DELETE') > 0 as has_delete,
       count(*) filter (where cmd = 'ALL')    > 0 as has_all
from pg_policies
where schemaname = 'public'
group by tablename
order by tablename;

-- ----------------------------------------------------------------------------
-- 5. security definer functions without a pinned search_path
--    Each of these resolves names via the CALLER's search_path: an injection
--    vector, and the classic cause of auth triggers breaking signups.
--    (See patterns/03-security-definer-rpcs.sql.)
-- ----------------------------------------------------------------------------
select n.nspname as schema, p.proname as function_name,
       'security definer without set search_path' as finding
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where p.prosecdef
  and n.nspname not in ('pg_catalog', 'information_schema', 'extensions',
                        'graphql', 'graphql_public', 'pgsodium', 'vault',
                        'storage', 'auth', 'realtime', 'supabase_functions')
  and (p.proconfig is null
       or not exists (
         select 1 from unnest(p.proconfig) cfg where cfg like 'search_path=%'
       ));
