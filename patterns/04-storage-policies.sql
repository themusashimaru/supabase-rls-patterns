-- ============================================================================
-- 04. Storage policies
-- Supabase Storage authorizes through RLS policies on storage.objects.
-- A "private" bucket with no policies isn't private-with-rules, it's
-- inaccessible; a public bucket ignores policies for reads entirely.
-- Decide per bucket, then write policies for exactly the access you mean.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- A. Per-user folders: each user reads/writes only under their own prefix
--    Convention: objects are stored at {user_id}/filename
-- ----------------------------------------------------------------------------

-- insert into storage.buckets (id, name, public) values ('user-files', 'user-files', false);

create policy "user-files: own folder read"
  on storage.objects for select
  using (
    bucket_id = 'user-files'
    and (select auth.uid())::text = (storage.foldername(name))[1]
  );

create policy "user-files: own folder write"
  on storage.objects for insert
  with check (
    bucket_id = 'user-files'
    and (select auth.uid())::text = (storage.foldername(name))[1]
  );

create policy "user-files: own folder delete"
  on storage.objects for delete
  using (
    bucket_id = 'user-files'
    and (select auth.uid())::text = (storage.foldername(name))[1]
  );

-- storage.foldername(name) splits the object path; element [1] is the top
-- folder. The path is client-chosen at upload time, which is exactly why the
-- WITH CHECK matters: without it a user uploads into someone else's folder.

-- ----------------------------------------------------------------------------
-- B. Role-gated documents: staff upload, managers read everything
--    (e.g. receipts, count sheets, internal docs)
-- ----------------------------------------------------------------------------

-- insert into storage.buckets (id, name, public) values ('documents', 'documents', false);

create policy "documents: staff upload"
  on storage.objects for insert
  with check (
    bucket_id = 'documents'
    and public.current_role() in ('member', 'manager', 'admin')  -- from 02
  );

create policy "documents: elevated read"
  on storage.objects for select
  using (
    bucket_id = 'documents'
    and public.current_role() in ('manager', 'admin')
  );

-- No update policy: documents are immutable once uploaded (re-upload under a
-- new name instead). No delete policy for clients: deletions go through a
-- security definer RPC or the service role so there's an audit trail.

-- ----------------------------------------------------------------------------
-- Gotchas
-- ----------------------------------------------------------------------------
-- 1. Public buckets serve reads to ANYONE with the URL regardless of these
--    policies. Never put private documents in a public bucket "temporarily."
-- 2. Signed URLs bypass read policies by design (that's their purpose) and
--    live until expiry. Short TTLs for sensitive files; a signed URL in a
--    shared Slack channel is an access grant to the whole channel.
-- 3. Policies filter by bucket_id. Forgetting that clause writes a policy
--    spanning EVERY bucket, which is rarely what you meant.
