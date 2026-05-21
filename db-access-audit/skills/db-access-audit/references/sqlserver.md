# Platform Reference — Microsoft SQL Server

Load this reference when the target is Microsoft SQL Server (on-prem or Azure SQL).

SQL Server has **native row-level security** (`CREATE SECURITY POLICY` + predicate functions) and a two-tier principal model (server-level *logins* and database-level *users*). Its distinctive bypass paths are **ownership chaining**, `EXECUTE AS` impersonation, and `TRUSTWORTHY`/cross-database chaining.

Mechanism map:

| Universal concept | SQL Server mechanism |
|---|---|
| Subjects | server *logins* (`sys.server_principals`) → database *users* (`sys.database_principals`) |
| Roles | fixed/user server roles + fixed/user database roles |
| Privileges | `GRANT` / `DENY` / `REVOKE` (DENY wins) on securables |
| Row controls | RLS: `CREATE SECURITY POLICY` with FILTER/BLOCK predicate functions |
| Privileged routines | modules with `EXECUTE AS`; module signing via certificates |
| Bypass paths | ownership chaining, cross-DB chaining, `TRUSTWORTHY ON`, `IMPERSONATE`, `guest` |

---

## 1. Inventory queries

### 1.1 Principals

```sql
-- server logins
select name, type_desc, is_disabled, create_date
from sys.server_principals
where type in ('S','U','G','C','K')      -- SQL/Windows/group/cert/key logins
order by name;

-- database users (run per database)
select dp.name, dp.type_desc, dp.authentication_type_desc,
       sp.name as mapped_login
from sys.database_principals dp
left join sys.server_principals sp on dp.sid = sp.sid
where dp.type in ('S','U','G','C','K','E','X')
order by dp.name;
```

### 1.2 Role membership

```sql
-- server role membership (e.g. who is in sysadmin)
select rp.name as server_role, mp.name as member
from sys.server_role_members rm
join sys.server_principals rp on rp.principal_id = rm.role_principal_id
join sys.server_principals mp on mp.principal_id = rm.member_principal_id
order by rp.name, mp.name;

-- database role membership (per database)
select rp.name as db_role, mp.name as member
from sys.database_role_members rm
join sys.database_principals rp on rp.principal_id = rm.role_principal_id
join sys.database_principals mp on mp.principal_id = rm.member_principal_id
order by rp.name, mp.name;
```

### 1.3 Permissions (GRANT / DENY)

```sql
-- database-level permissions; DENY (state_desc='DENY') overrides GRANT
select pr.name as principal, perm.class_desc, perm.permission_name,
       perm.state_desc,
       object_name(perm.major_id) as object_name
from sys.database_permissions perm
join sys.database_principals pr on pr.principal_id = perm.grantee_principal_id
order by pr.name, perm.class_desc;

-- server-level permissions (CONTROL SERVER, IMPERSONATE, ALTER ANY LOGIN, ...)
select pr.name as principal, perm.permission_name, perm.state_desc
from sys.server_permissions perm
join sys.server_principals pr on pr.principal_id = perm.grantee_principal_id
order by pr.name;
```

### 1.4 Row-Level Security

```sql
select sp.name as policy_name, sp.is_enabled, sp.is_schema_bound,
       object_schema_name(spr.target_object_id) + '.' +
       object_name(spr.target_object_id) as target_table,
       spr.predicate_type_desc,           -- FILTER / BLOCK
       object_name(spr.predicate_definition_id) as predicate_function
from sys.security_policies sp
join sys.security_predicates spr on sp.object_id = spr.object_id
order by policy_name;
```

Flag: tables with sensitive/tenant data and **no** security policy; policies that are `is_enabled = 0`; FILTER-only predicates where a BLOCK predicate is also needed to stop cross-tenant writes; predicate functions that key off something spoofable.

### 1.5 Impersonation modules and chaining

```sql
-- modules that run as someone else (EXECUTE AS OWNER/SELF/'user')
select object_schema_name(m.object_id) + '.' + object_name(m.object_id) as module,
       dp.name as executes_as
from sys.sql_modules m
left join sys.database_principals dp on m.execute_as_principal_id = dp.principal_id
where m.execute_as_principal_id is not null;

-- database-level elevation switches
select name, is_trustworthy_on, is_db_chaining_on, owner_sid
from sys.databases
order by name;

-- guest access (should normally lack CONNECT in user databases)
select dp.name, perm.permission_name, perm.state_desc
from sys.database_principals dp
join sys.database_permissions perm on perm.grantee_principal_id = dp.principal_id
where dp.name = 'guest';
```

---

## 2. Authorization checks

### 2.1 Dangerous principals and roles

Flag membership/holders of:

- `sysadmin` server role — full control; bypasses all permission checks.
- `securityadmin` — can grant itself `sysadmin`-equivalent (effectively sysadmin).
- `CONTROL SERVER`, `ALTER ANY LOGIN`, `ALTER ANY SERVER ROLE` — server takeover.
- `db_owner`, `db_securityadmin` on application databases for non-admin principals.
- `IMPERSONATE` on high-privilege users (lets a low-priv principal become them).
- The fixed `public` role granted meaningful permissions (every user inherits `public`).
- `db_datareader` / `db_datawriter` granted to app users that should be scoped narrower.

### 2.2 GRANT / DENY precedence

`DENY` overrides `GRANT` at the same or lower scope. When reconstructing effective access, resolve DENY first. Use `sys.fn_my_permissions` / `HAS_PERMS_BY_NAME`, or test via impersonation (§3), rather than reasoning from GRANTs alone.

### 2.3 Ownership chaining (key bypass path)

When a module/view and the objects it references share the **same owner**, SQL Server skips permission checks on the referenced objects — the caller needs permission only on the entry-point object. This is intended for encapsulation but is a bypass path:

- Flag views/procedures owned by a high-privilege principal that read sensitive base tables, granted to low-privilege users — the users reach data they have no direct permission on.
- **Cross-database ownership chaining** (`is_db_chaining_on = 1`) extends this across databases — flag it unless explicitly required.
- `TRUSTWORTHY ON` (`is_trustworthy_on = 1`) combined with a `db_owner` owned by a high-priv login enables privilege elevation to the server — a well-known escalation. Flag `TRUSTWORTHY ON` on any non-system database.

### 2.4 EXECUTE AS / module signing

`EXECUTE AS OWNER/SELF/'user'` runs a module under another principal's context — the SQL Server analogue of `SECURITY DEFINER`. Flag modules executing as a high-privilege principal that perform privileged work callable by low-privilege users without internal authorization checks. Prefer **module signing** (sign the module with a certificate and grant the certificate-derived principal the needed permission) over `EXECUTE AS`/`TRUSTWORTHY` for controlled elevation.

### 2.5 Column protection

Check column-level `GRANT`/`DENY`, Dynamic Data Masking (`sys.masked_columns` — note masking is a display feature, not an access control, and is bypassable with `UNMASK`), and Always Encrypted for sensitive columns. Flag sensitive columns readable by app/reporting principals that shouldn't see them.

---

## 3. Read-only-safe test harness

SQL Server supports impersonation that reverts cleanly — the analogue of the Postgres rollback harness:

```sql
execute as user = 'app_user';      -- adopt the persona's context
  select * from dbo.orders;        -- subject to that user's permissions + RLS
revert;                            -- restore original context
```

For write-shaped tests, wrap in a transaction and roll back (and get explicit human go-ahead per SKILL.md §2):

```sql
begin tran;
execute as user = 'app_user';
  update dbo.orders set tenant_id = 999 where id = 1;   -- should this be blocked?
revert;
rollback tran;                     -- nothing persists
```

Rules: `EXECUTE AS` requires `IMPERSONATE` on the target user; SELECT tests under impersonation are within the read-only mandate; always `REVERT`; never test as `sa`/`sysadmin`/`db_owner` as if an ordinary user. If `IMPERSONATE` is not available, derive answers from `HAS_PERMS_BY_NAME`/`sys.fn_my_permissions` and report as **derived from metadata**.

---

## 4. Remediation patterns

Recommendations for the report only — **do not execute** (SKILL.md §2).

```sql
-- Remove excessive role membership / server permissions
alter server role sysadmin drop member [AppLogin];
revoke impersonate on user::[HighPrivUser] to [AppUser];

-- Least-privilege database role instead of db_datareader/db_owner
create role app_reader;
grant select on schema::app to app_reader;
alter role app_reader add member [AppUser];

-- Turn off elevation switches
alter database AppDb set trustworthy off;
alter database AppDb set db_chaining off;

-- Remove guest connectivity in user databases
revoke connect from guest;

-- Enable Row-Level Security
create function security.fn_tenant_predicate(@tenant_id int)
returns table with schemabinding as
return select 1 as ok
       where @tenant_id = cast(session_context(N'tenant_id') as int);

create security policy security.tenant_filter
add filter predicate security.fn_tenant_predicate(tenant_id) on dbo.orders,
add block  predicate security.fn_tenant_predicate(tenant_id) on dbo.orders
with (state = on);

-- Prefer module signing over EXECUTE AS / TRUSTWORTHY for controlled elevation
```

Also recommend: resolve effective access with DENY precedence in mind; review ownership chains; restrict `IMPERSONATE`; keep `public` role permissions empty on app databases; rotate/disable stale logins.
