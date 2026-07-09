-- ============================================================================
-- 01. Ownership and multi-tenant isolation
-- The two policy shapes that cover 80% of application tables.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- A. Per-user ownership: users see and manage only their own rows
-- ----------------------------------------------------------------------------

create table public.notes (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null default auth.uid() references auth.users (id),
  body       text not null,
  created_at timestamptz not null default now()
);

alter table public.notes enable row level security;

-- Performance idiom: wrap auth.uid() in a scalar subquery. Postgres then
-- evaluates it ONCE per statement instead of once per row, which matters
-- enormously on large tables. Same result, order-of-magnitude faster scans.
create policy "notes: owners select"
  on public.notes for select
  using ((select auth.uid()) = user_id);

create policy "notes: owners insert"
  on public.notes for insert
  with check ((select auth.uid()) = user_id);
  -- with check guards the NEW row: without it, a user could insert rows
  -- attributed to someone else.

create policy "notes: owners update"
  on public.notes for update
  using ((select auth.uid()) = user_id)         -- which rows they may target
  with check ((select auth.uid()) = user_id);   -- what the row may become
  -- Both clauses. using-only lets an owner UPDATE the row to belong to
  -- another user (user_id reassignment), which is a quiet data-integrity hole.

create policy "notes: owners delete"
  on public.notes for delete
  using ((select auth.uid()) = user_id);

-- ----------------------------------------------------------------------------
-- B. Multi-tenant isolation: users belong to a tenant (store, org, team)
--    and see only their tenant's rows
-- ----------------------------------------------------------------------------

create table public.memberships (
  user_id   uuid not null references auth.users (id),
  tenant_id uuid not null,
  role      text not null default 'member',
  primary key (user_id, tenant_id)
);

alter table public.memberships enable row level security;

create policy "memberships: read own"
  on public.memberships for select
  using ((select auth.uid()) = user_id);
-- Membership writes should go through a security definer RPC or the service
-- role (see 03): letting users insert their own memberships is self-service
-- privilege escalation.

create table public.orders (
  id         uuid primary key default gen_random_uuid(),
  tenant_id  uuid not null,
  total      numeric(12,2) not null,
  created_at timestamptz not null default now()
);

alter table public.orders enable row level security;

-- A helper keeps tenant checks consistent across every table and gives the
-- planner one stable expression to cache.
-- SECURITY INVOKER + a SELECT on memberships works because the caller may
-- read their own memberships (policy above).
create or replace function public.is_member_of(t uuid)
returns boolean
language sql
stable
as $$
  select exists (
    select 1 from public.memberships
    where user_id = (select auth.uid()) and tenant_id = t
  );
$$;

create policy "orders: tenant members select"
  on public.orders for select
  using (public.is_member_of(tenant_id));

create policy "orders: tenant members insert"
  on public.orders for insert
  with check (public.is_member_of(tenant_id));

-- Repeat for update/delete as your product requires; leaving a verb without
-- a policy means that verb is denied, which is often exactly right (e.g.
-- orders that can be created and read but never deleted by clients).
