# Supabase RLS Patterns

Row Level Security policies that survive production, with comments explaining the *why*. Extracted from multi-store retail and SaaS systems where RLS is the actual security boundary, not decoration.

RLS is the best feature of building on Postgres and the easiest one to get subtly wrong. These patterns cover the shapes that come up in real apps, plus the gotchas that only show up after you ship.

## The patterns

| File | Covers |
|---|---|
| `patterns/01-owner-and-tenant.sql` | Per-user ownership, multi-tenant isolation by store/org, the `(select auth.uid())` performance idiom |
| `patterns/02-roles-and-admin.sql` | Role gates from a profiles table, why client-side role checks are theater, admin-only verbs |
| `patterns/03-security-definer-rpcs.sql` | Controlled RLS bypass with `security definer` functions, and the `search_path` bug that breaks auth triggers |
| `patterns/04-storage-policies.sql` | Bucket policies: per-user folders, role-gated documents |
| `patterns/05-gotchas.sql` | Backup tables, missing-verb policies, views, and other ways RLS silently fails |
| `audit/rls-audit.sql` | Five queries that turn the gotchas into a pre-deploy check: RLS-off tables, policy-less tables, `using(true)` holes, verb coverage, definer functions missing `search_path`. Every returned row is a finding; wire it into CI |

## Ground rules that prevent most RLS incidents

1. **RLS on every table in exposed schemas, no exceptions.** A table without RLS behind the anon key is a public API. This includes `_backup`, `_old`, and `temp_` tables created at 2 a.m.
2. **Policies per verb.** Enabling RLS with only a SELECT policy means INSERT/UPDATE/DELETE are simply blocked (or worse, permitted by a later careless policy). Decide all four verbs explicitly for every table.
3. **`auth.uid()` can be null.** Anonymous requests don't fail policies that compare against null; they just return no rows on SELECT, but a sloppy `using (true)` fallback exposes everything. Never write `using (true)` on an exposed table unless the data is genuinely public.
4. **The service role bypasses RLS entirely.** That's its job. It must exist only in server code, never with a `NEXT_PUBLIC_` prefix, and ideally only in the few places that truly need bypass.
5. **Test policies as the enemy.** The Supabase SQL editor runs as postgres and bypasses RLS, which makes everything look fine. Test with the anon key from an incognito tab, and as user A trying to read user B's rows.

## License

MIT
