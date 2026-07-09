-- ============================================================================
-- 03. Security definer RPCs: controlled bypass
-- Some operations legitimately cross RLS boundaries: assigning a document
-- number from a shared sequence, voiding an invoice the clerk can't see,
-- promoting a user. The wrong answer is loosening table policies. The right
-- answer is a narrow function that does ONE privileged thing with its own
-- authorization check inside.
-- ============================================================================

-- Example: void an invoice. Clerks can't update invoices directly (no UPDATE
-- policy on the table), but managers may void through this audited gate.
create or replace function public.void_invoice(p_invoice_id uuid, p_reason text)
returns void
language plpgsql
security definer                 -- runs with the function OWNER's privileges,
set search_path = public         -- bypassing the caller's RLS. See warning below.
as $$
declare
  v_role text;
begin
  -- The function must do its own authorization: security definer means the
  -- table policies no longer protect you inside this body.
  select role into v_role from public.profiles where id = auth.uid();
  if v_role not in ('manager', 'admin') then
    raise exception 'not authorized to void invoices';
  end if;

  update public.invoices
     set status = 'void',
         voided_by = auth.uid(),
         voided_at = now(),
         void_reason = p_reason
   where id = p_invoice_id
     and status <> 'void';

  if not found then
    raise exception 'invoice not found or already void';
  end if;
end;
$$;

-- Client-side callers reach this via supabase.rpc('void_invoice', {...}).
-- Lock down who may even call it:
revoke execute on function public.void_invoice(uuid, text) from anon;
grant  execute on function public.void_invoice(uuid, text) to authenticated;

-- ============================================================================
-- THE search_path WARNING (a production outage in three lines)
-- ============================================================================
-- Every security definer function MUST pin its search_path. Without it, the
-- function resolves unqualified names using the CALLER's search_path, which
-- an attacker can influence, and which breaks in a second, sneakier way:
--
-- Functions called by triggers on auth.users (the classic handle_new_user()
-- that copies signups into public.profiles) execute with a search_path that
-- does NOT include public. The insert silently targets the wrong place, the
-- trigger errors, and every new signup fails with an opaque 500 from
-- /auth/v1/signup. The fix is one line on the function:
--
--     set search_path = public
--
-- If signups mysteriously 500 and the auth logs blame a trigger, check this
-- first. Symptom to grep for: "function handle_new_user" + "does not exist"
-- or "relation profiles does not exist".

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public          -- <- the line that keeps signups working
as $$
begin
  insert into public.profiles (id, role)
  values (new.id, 'member')
  on conflict (id) do nothing;    -- idempotent: retries and backfills are safe
  return new;
end;
$$;

-- create trigger on_auth_user_created
--   after insert on auth.users
--   for each row execute function public.handle_new_user();
