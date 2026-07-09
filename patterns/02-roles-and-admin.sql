-- ============================================================================
-- 02. Roles and admin gates
-- A role flag in your database is only security if the DATABASE enforces it.
-- An isAdmin boolean in React state is a UI hint an attacker doesn't use.
-- ============================================================================

-- Roles live on a profiles table keyed to auth.users.
create table public.profiles (
  id   uuid primary key references auth.users (id),
  role text not null default 'member'   -- 'member' | 'manager' | 'admin'
);

alter table public.profiles enable row level security;

create policy "profiles: read own"
  on public.profiles for select
  using ((select auth.uid()) = id);

-- CRITICAL: there is no INSERT or UPDATE policy on profiles for regular
-- users, and that is deliberate. If users can update their own profile row
-- and the row contains `role`, you have built self-service admin. Role
-- changes go through a security definer RPC (03) or the service role only.
-- If users need to edit display_name etc., either split those columns into
-- a separate table or add an UPDATE policy whose WITH CHECK pins the role:
--   with check ((select auth.uid()) = id and role = (select p.role from public.profiles p where p.id = (select auth.uid())))

-- Role-check helper. SECURITY DEFINER so it can read profiles regardless of
-- the caller's policies; STABLE so the planner caches it per statement.
create or replace function public.app_role()
returns text
language sql
stable
security definer
set search_path = public
as $$
  select role from public.profiles where id = (select auth.uid());
$$;

-- Example: expense reports. Members see their own; managers and admins see
-- all of them; only admins may delete.
create table public.expenses (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null default auth.uid(),
  amount     numeric(12,2) not null,
  created_at timestamptz not null default now()
);

alter table public.expenses enable row level security;

create policy "expenses: own or elevated select"
  on public.expenses for select
  using (
    (select auth.uid()) = user_id
    or public.app_role() in ('manager', 'admin')
  );

create policy "expenses: members insert own"
  on public.expenses for insert
  with check ((select auth.uid()) = user_id);

create policy "expenses: admin delete"
  on public.expenses for delete
  using (public.app_role() = 'admin');

-- Note what is absent: no UPDATE policy, so nobody edits an expense after
-- filing through the client API. Corrections happen through an audited RPC.
-- Denial-by-omission is a feature of RLS; use it on purpose and document it.
