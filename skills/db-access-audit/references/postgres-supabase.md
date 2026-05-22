# Platform Reference — PostgreSQL / Supabase

Load this reference when the target is PostgreSQL, Supabase, or a Postgres-compatible engine (Neon, RDS for Postgres, Cloud SQL for Postgres, Timescale, etc.). It supplies the concrete inventory queries, row-level mechanics, bypass paths, test harness, and remediation SQL that the agnostic workflow refers to.

Mechanism map:

| Universal concept | PostgreSQL/Supabase mechanism |
|---|---|
| Subjects | `auth.users`, app membership tables, database login roles, service accounts |
| Roles | database roles + `anon`/`authenticated`/`service_role`; app roles in membership tables/JWT |
| Privileges | `GRANT`/`REVOKE` on tables, columns, sequences, functions, schemas |
| Row/document controls | Row-Level Security (RLS) policies |
| Privileged routines | `SECURITY DEFINER` functions / RPC |
| Bypass paths | table owner, `BYPASSRLS`, `SECURITY DEFINER`, views, `service_role`, broad default privileges |

---

## 1. Inventory queries

### 1.1 Tables and RLS status

```sql
select
  n.nspname as schema_name,
  c.relname as table_name,
  c.relkind,
  c.relrowsecurity as rls_enabled,
  c.relforcerowsecurity as force_rls,
  pg_get_userbyid(c.relowner) as owner
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r', 'p')
  and n.nspname not in ('pg_catalog', 'information_schema')
order by n.nspname, c.relname;
```

A missing-RLS finding is only **Critical** if the table is actually reachable: in an exposed schema **and** carrying a grant to a client role (`anon`/`authenticated`) **and** the Data API on. Cross-check §1.3 grants before rating.

### 1.2 RLS policies

```sql
select
  schemaname, tablename, policyname,
  permissive, roles, cmd,
  qual as using_expression,
  with_check as with_check_expression
from pg_policies
order by schemaname, tablename, policyname;
```

**Read the combination semantics correctly — assess the combined effect per command + role, never one policy in isolation:**

- **PERMISSIVE policies OR-combine.** A row is allowed if *any* permissive policy matches; adding one can only **widen** access. A broad permissive policy (`using (true)`) next to scoped ones makes the scoped ones dead weight.
- **RESTRICTIVE policies AND-combine** (`permissive = 'RESTRICTIVE'`); they only **narrow**, and do nothing alone — a permissive policy must grant access first.
- **`roles` includes `public`** — `pg_policies` shows it as `{public}` (the underlying `pg_policy.polroles` stores it as `{0}`). It means the policy applies to **every role, including `anon`**. Red flag unless intentional.
- **Interpret NULL `qual` / `with_check` per command — NULL does not mean "unrestricted":**
  - `qual` (USING) filters which existing rows are visible/affected. It is **NULL for INSERT** policies (INSERT has no USING). A literal `using (true)` shows as `true`, not NULL — so NULL `qual` is not the same as `using (true)`.
  - `with_check` constrains new/modified rows. It is **NULL for SELECT and DELETE** (no check phase). For **ALL and UPDATE policies**, if `with_check` is omitted Postgres reuses the `USING` expression as the check; for an **INSERT-only policy**, there is no `USING` expression, so a missing `WITH CHECK` means no row-value check from that policy. Resolve the effective check before judging.
- **RLS on + no policy = deny-all** for non-owners (owner still bypasses unless `FORCE` — see §2.1).

### 1.3 Grants — table, then column

```sql
select table_schema, table_name, grantee, privilege_type
from information_schema.table_privileges
where table_schema not in ('pg_catalog', 'information_schema')
order by table_schema, table_name, grantee, privilege_type;
```

Table-level RLS does **not** constrain columns. PostgREST/Data API honour column grants, so correct RLS can still leak a sensitive column (token, secret, `is_admin`, `role`, billing, PII) via a column `GRANT`:

```sql
select table_schema, table_name, column_name, grantee, privilege_type
from information_schema.column_privileges
where table_schema not in ('pg_catalog', 'information_schema')
order by table_schema, table_name, grantee, column_name;
```

### 1.4 Usage, function, and default privileges

```sql
select * from information_schema.usage_privileges
order by object_schema, object_name, grantee;

-- Function EXECUTE grants via aclexplode(proacl). Grantee OID 0 = PUBLIC.
-- Do NOT use has_function_privilege('public', ...): PUBLIC is a pseudo-role,
-- not a pg_roles entry, and that call is unreliable / errors in some environments.
select
  n.nspname as schema_name,
  p.proname as function_name,
  pg_get_function_identity_arguments(p.oid) as args,
  pg_get_userbyid(p.proowner) as owner,
  p.prosecdef as security_definer,
  p.proconfig as config,
  coalesce(pg_get_userbyid(nullif(a.grantee, 0)), 'PUBLIC') as grantee,
  a.privilege_type
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
left join lateral aclexplode(p.proacl) a on true
where n.nspname not in ('pg_catalog', 'information_schema')
order by n.nspname, p.proname, grantee;

select * from pg_default_acl;
```

> **Critical gotcha — a NULL `proacl` is not "no access".** When `proacl` is NULL the function carries the *default* privileges, and the built-in default for functions is `EXECUTE` to **PUBLIC**. So `aclexplode(NULL)` returns no rows even though PUBLIC can execute. Treat a NULL `proacl` as "PUBLIC may EXECUTE unless a `REVOKE` or `ALTER DEFAULT PRIVILEGES` removed it" — check `pg_default_acl` (above) and any migration that revokes default function execute. `information_schema.routine_privileges` is an alternative cross-check for explicit grants.

### 1.5 Roles and inheritance

```sql
select rolname, rolsuper, rolcreaterole, rolcreatedb,
       rolcanlogin, rolreplication, rolbypassrls, rolinherit
from pg_roles
order by rolname;

select parent.rolname as parent_role, member.rolname as member_role, am.admin_option
from pg_auth_members am
join pg_roles parent on parent.oid = am.roleid
join pg_roles member on member.oid = am.member
order by parent.rolname, member.rolname;
```

Flag: unexpected `SUPERUSER`/`BYPASSRLS`; login roles with broad inherited privileges; service roles used by user-facing components; generic shared roles without accountability.

---

## 2. RLS checks

### 2.1 Coverage and owner bypass

For every exposed/sensitive table: RLS enabled? at least one policy for intended access? command-specific where needed? assigned to explicit roles? distinguishes anon vs authenticated? tested as non-owner? should `FORCE ROW LEVEL SECURITY` be set?

> **Owner bypass:** RLS does not apply to the table owner unless `FORCE ROW LEVEL SECURITY` is set. Supabase dashboard tables are often owned by `postgres`, and `SECURITY DEFINER` functions owned by `postgres` run with the owner's bypass. The API roles (`anon`, `authenticated`) are not owners — so this matters for migrations, owner-run queries, and definer functions, and is why testing from the SQL editor as owner proves nothing.

### 2.2 SELECT

Acceptable predicates:

```sql
(select auth.uid()) = user_id                          -- owner-only

exists (select 1 from organization_members m            -- tenant membership
        where m.organization_id = target_table.organization_id
          and m.user_id = (select auth.uid()))

exists (select 1 from organization_members m            -- role within tenant
        where m.organization_id = target_table.organization_id
          and m.user_id = (select auth.uid())
          and m.role in ('owner','admin','manager'))
```

Flag: `using (true)` on non-public tables; a broad permissive policy co-existing with narrow ones (OR wins); auth-only checks without ownership/scope; reliance on mutable user metadata; missing tenant joins; policies on PUBLIC (`{public}` in `pg_policies`) where only `authenticated` should apply.

### 2.3 INSERT — must use `WITH CHECK`

```sql
with check ((select auth.uid()) = user_id)              -- own profile only

with check (exists (select 1 from organization_members m
                    where m.organization_id = target_table.organization_id
                      and m.user_id = (select auth.uid())
                      and m.role in ('owner','admin','editor')))
```

Flag: insert rows for another user/tenant; set `role='admin'`/`owner_id`/`tenant_id`/approval fields directly; `WITH CHECK` missing or weaker than intended; self-join as tenant admin.

### 2.4 UPDATE — needs both `USING` and `WITH CHECK`

```sql
using (exists (select 1 from organization_members m
               where m.organization_id = target_table.organization_id
                 and m.user_id = (select auth.uid())
                 and m.role in ('owner','admin','editor')))
with check (exists (select 1 from organization_members m
                    where m.organization_id = target_table.organization_id
                      and m.user_id = (select auth.uid())
                      and m.role in ('owner','admin','editor')))
```

Flag: change `user_id` to another user; move row to another tenant via `tenant_id`; escalate role/status/approval; `WITH CHECK` absent. Recommend constraints/triggers when ownership columns must be immutable.

### 2.5 DELETE

Delete should be narrower than read/update. Flag: any authenticated user deletes tenant data; non-admins delete audit/history rows; cascades crossing scope. Prefer soft-delete + audit columns for sensitive domains; test cross-tenant delete attempts.

### 2.6 Views

Flag: privileged-owner views that bypass underlying RLS; views exposing sensitive columns; views granted to `anon`/`authenticated` without equivalent filtering; internal views in exposed schemas. PG 15+: `create view v with (security_invoker = true) as ...`. Otherwise revoke client access or move to an unexposed schema.

### 2.7 Functions / RPC

RLS does not protect function execution. Flag: `EXECUTE` to `PUBLIC`/`anon`/`authenticated` unnecessarily; `SECURITY DEFINER` doing privileged work without internal auth checks; missing safe `search_path`; user-controlled IDs operating cross-tenant; secrets exposed.

```sql
create or replace function public.safe_function(...)
returns ... language plpgsql
security definer
set search_path = public, pg_temp
as $$ begin
  -- explicit auth and scope checks here
end; $$;

revoke all on function public.safe_function(...) from public;
grant execute on function public.safe_function(...) to authenticated;
```

### 2.8 Default privileges and drift

Flag: new objects in exposed schemas auto-granting to `anon`/`authenticated`/`PUBLIC`; no migration template enforcing RLS; no CI check for tables without RLS. Recommend revoking broad default privileges, RLS-with-each-table migrations, CI failing on exposed tables lacking RLS.

### 2.9 Performance

Policy predicates should use indexed columns; membership lookups indexed; avoid expensive repeated functions and broad joins; test at realistic tenant sizes.

```sql
create index if not exists idx_table_user_id on target_table(user_id);
create index if not exists idx_table_org_id on target_table(organization_id);
create index if not exists idx_members_user_org on organization_members(user_id, organization_id);
create index if not exists idx_members_org_user_role on organization_members(organization_id, user_id, role);
```

---

## 3. Supabase-specific checks

### 3.1 Built-in roles

| Role | Expected use | Risk |
|---|---|---|
| `anon` | unauthenticated public access | Public data exposure |
| `authenticated` | signed-in user access | Cross-user/cross-tenant exposure |
| `service_role` | trusted server-side elevated access | Bypasses RLS |
| `postgres` | admin/owner | Invalid RLS testing if used as ordinary user |
| `authenticator` | PostgREST role switching | Should stay tightly scoped |

### 3.2 Keys

- Publishable/anon key appears only where expected.
- Secret/service keys never appear in frontend, mobile, browser, public repos, logs, screenshots, chat, or client bundles.
- Server-side service-role use performs explicit authorization before querying.
- Admin scripts/jobs isolated and audited.

### 3.3 Data API

Every exposed table has intentional grants; every exposed sensitive/user/tenant table has RLS; internal tables moved out of exposed schemas or grants revoked; Data API disabled if unused; consider a custom API schema for clearer boundaries.

### 3.4 JWT claims

Prefer `(select auth.uid())`; use `auth.jwt()` carefully; **do not trust mutable `raw_user_meta_data` for authorization** — prefer `raw_app_meta_data` or DB membership tables; confirm claim staleness doesn't delay revocation; verify how role claims are set, updated, revoked, refreshed.

### 3.5 Storage

Audit `storage.objects` policies; bucket- and path-level controls; prevent reading/writing others' paths; prevent overwrite/delete outside scope; public buckets hold only intentionally public data.

```sql
bucket_id = 'avatars'
and (select auth.uid())::text = (storage.foldername(name))[1]
```

### 3.6 Realtime

Identify tables in publications; confirm RLS protects subscriptions; sensitive tables not broadcast broadly; understand delete/update payload exposure.

---

## 4. Opt-in behavioral test harness

PostgREST derives identity from the `role` and `request.jwt.claims` settings. With explicit human opt-in for behavioral read tests, impersonate inside a transaction that is always rolled back (see the agnostic `testing.md` for personas/operations/reporting):

```sql
begin;
  set local role authenticated;
  set local request.jwt.claims = '{"sub":"11111111-1111-1111-1111-111111111111","role":"authenticated"}';
  select * from public.target_table;          -- can this persona see these rows?
rollback;                                       -- nothing persists
```

Anonymous: `set local role anon; set local request.jwt.claims = '{"role":"anon"}';`

Rules: `set local` + `rollback` mandatory, never `commit`; live SELECT tests require explicit behavioral-read opt-in; write-shaped tests require a separate explicit human go-ahead (SKILL.md §2); the connecting role must be able to `SET ROLE` to `anon`/`authenticated` (a pure read-only metadata role usually cannot — then hand the SQL to a human); never test as `postgres`/owner/`service_role`/`BYPASSRLS` as if an ordinary user.

---

## 5. Remediation SQL playbook

Recommendations for the report only — **do not execute** (SKILL.md §2).

```sql
-- Enable / force RLS
alter table public.target_table enable row level security;
alter table public.target_table force row level security;

-- Revoke broad client grants; grant only what's needed (incl. column scope)
revoke all on table public.target_table from anon, authenticated;
grant select on table public.target_table to authenticated;
revoke select on table public.target_table from authenticated;
grant select (id, name, created_at) on table public.target_table to authenticated;

-- Move internal objects to a private schema
create schema if not exists internal;
alter table public.internal_table set schema internal;
revoke all on schema internal from anon, authenticated, public;
```

Owner-only policies:

```sql
create policy "read own"  on public.t for select to authenticated using ((select auth.uid()) = user_id);
create policy "insert own" on public.t for insert to authenticated with check ((select auth.uid()) = user_id);
create policy "update own" on public.t for update to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
```

Tenant-scoped policy:

```sql
create policy "members read org" on public.t for select to authenticated
using (exists (select 1 from public.organization_members m
               where m.organization_id = t.organization_id
                 and m.user_id = (select auth.uid())));
```

Role-management table (no self-escalation):

```sql
create policy "only owners manage members" on public.organization_members for all to authenticated
using (exists (select 1 from public.organization_members self
               where self.organization_id = organization_members.organization_id
                 and self.user_id = (select auth.uid()) and self.role = 'owner'))
with check (exists (select 1 from public.organization_members self
               where self.organization_id = organization_members.organization_id
                 and self.user_id = (select auth.uid()) and self.role = 'owner'));
```

Lock down functions:

```sql
revoke all on function public.admin_function(...) from public, anon, authenticated;
grant execute on function public.admin_function(...) to service_role;
```

Protect dangerous columns (`user_id`, `owner_id`, `tenant_id`, `organization_id`, `role`, `is_admin`, `status`, `approved_by`, `billing_plan`, `deleted_at`): use `WITH CHECK` policies, column-level privileges, triggers, server-side admin-only functions, or separate tables for privileged state.
