-- ============================================================================
-- 05. Gotchas: the ways RLS silently fails in production
-- None of these error. They just quietly expose data until someone looks.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. The backup table
-- ----------------------------------------------------------------------------
-- Someone (possibly you at 2 a.m., possibly your AI assistant) makes a safety
-- copy before a risky migration:
--
--     create table public.orders_backup as select * from public.orders;
--
-- CREATE TABLE AS does not copy RLS. The copy has RLS DISABLED and sits in
-- the exposed public schema: your entire orders history, readable via the
-- anon key. If you must snapshot into public, lock it down at creation:

-- create table public.orders_backup as select * from public.orders;
alter table public.orders_backup enable row level security;
revoke all on public.orders_backup from anon, authenticated;
-- (No policies + RLS on = nobody but service role reads it. Correct for a backup.)

-- Better: keep snapshots out of exposed schemas entirely.
-- create schema if not exists archive;  -- not in the API's exposed schemas
-- create table archive.orders_2026_07 as select * from public.orders;

-- ----------------------------------------------------------------------------
-- 2. The missing verb
-- ----------------------------------------------------------------------------
-- "RLS is enabled and there's a policy" is not the same as "all four verbs
-- are decided." Audit which verbs each policy covers:

select schemaname, tablename, policyname, cmd, roles
from pg_policies
where schemaname = 'public'
order by tablename, cmd;

-- And find exposed tables with RLS off entirely (the big one):

select n.nspname as schema, c.relname as table
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind = 'r'
  and n.nspname = 'public'
  and not c.relrowsecurity;

-- Run that second query in CI or as a pre-deploy check. A new table with
-- RLS forgotten is the single most common Supabase security incident.

-- ----------------------------------------------------------------------------
-- 3. Views run with the OWNER's rights (by default)
-- ----------------------------------------------------------------------------
-- A view created by postgres over an RLS-protected table BYPASSES the
-- table's RLS for anyone who can select from the view. Postgres 15+ fix:

-- create view public.order_summaries
--   with (security_invoker = true)      -- <- makes the CALLER's RLS apply
--   as select id, tenant_id, total from public.orders;

-- If you're on an older Postgres or the view must aggregate across rows the
-- caller can't see, treat the view like a service-role surface: revoke it
-- from anon/authenticated and expose the data through a security definer
-- RPC that does its own checks.

-- ----------------------------------------------------------------------------
-- 4. "It works in the SQL editor" proves nothing
-- ----------------------------------------------------------------------------
-- The dashboard SQL editor runs as postgres, which bypasses RLS. Every
-- policy looks fine from there. Test like the enemy instead:
--   * anon key, logged out: can you read anything?
--   * user A's JWT: can you read user B's rows by ID?
-- You can simulate a user inside SQL for quick checks:

-- begin;
-- set local role authenticated;
-- set local request.jwt.claims = '{"sub":"<user-a-uuid>","role":"authenticated"}';
-- select * from public.orders;   -- what user A actually sees
-- rollback;

-- ----------------------------------------------------------------------------
-- 5. Permissive policies OR together
-- ----------------------------------------------------------------------------
-- Multiple permissive policies on the same verb are combined with OR. A
-- forgotten "temporary" debug policy:
--
--     create policy "debug open" on public.orders for select using (true);
--
-- ...silently defeats every carefully-written policy beside it, because
-- anything OR true is true. Grep your schema for "using (true)" and make
-- sure each one is a deliberate, documented decision about public data.
