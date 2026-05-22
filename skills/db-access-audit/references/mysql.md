# Platform Reference — MySQL / MariaDB

Load this reference when the target is MySQL or MariaDB.

**Critical difference from PostgreSQL: there is no native row-level security.** Row/document-level isolation must be emulated with filtering views, definer-rights stored programs, or the application layer. Audit those mechanisms instead of policies — and treat "row isolation enforced only in app code" as a finding, since any direct connection bypasses it.

Mechanism map:

| Universal concept | MySQL/MariaDB mechanism |
|---|---|
| Subjects | accounts as `user@host` (`mysql.user`) |
| Roles | roles (MySQL 8.0+/MariaDB 10.0.5+); `GRANT role TO user` |
| Privileges | global / database / table / column / routine / proxy privileges |
| Row controls | **emulated** — filtering views, definer procedures, app layer |
| Privileged routines | `SQL SECURITY DEFINER` views and routines |
| Bypass paths | definer-rights views/routines, `FILE`, `GRANT OPTION`, wildcard-host accounts, `mysql.*` access |

---

## 1. Inventory queries

### 1.1 Accounts (subjects)

```sql
select user, host, account_locked, password_expired,
       plugin, password_last_changed
from mysql.user
order by user, host;
```

Flag: anonymous accounts (`user = ''`); accounts with `host = '%'` (connect from anywhere); `password_expired = 'N'` stale accounts; weak/empty auth plugins; locked-but-still-granted accounts.

### 1.2 Roles and grants (MySQL 8.0+)

```sql
-- role-to-user / role-to-role edges
select from_user, from_host, to_user, to_host, with_admin_option
from mysql.role_edges
order by to_user, to_host;

-- default roles activated at login
select user, host, default_role_user, default_role_host
from mysql.default_roles;

-- mandatory roles / auto-activation (server variables)
show variables like 'mandatory_roles';
show variables like 'activate_all_roles_on_login';

-- effective grants for a principal
show grants for 'app_user'@'%';
show grants for 'app_user'@'%' using 'app_role';   -- include a role's privileges
```

If `activate_all_roles_on_login = OFF` and an account has no default role set, granted roles are inactive until `SET ROLE` — verify the app actually activates the roles it relies on.

### 1.3 Privileges by scope

```sql
-- global (server-wide) privileges
select * from information_schema.user_privileges order by grantee;

-- database-level
select * from information_schema.schema_privileges order by grantee, table_schema;

-- table-level
select * from information_schema.table_privileges order by grantee, table_schema, table_name;

-- column-level (the easy-to-miss leak path)
select * from information_schema.column_privileges order by grantee, table_schema, table_name, column_name;
```

### 1.4 Definer-rights views and routines (bypass paths)

```sql
-- views: SECURITY_TYPE = DEFINER runs with the definer's privileges
select table_schema, table_name, definer, security_type
from information_schema.views
order by table_schema, table_name;

-- stored procedures/functions: same DEFINER semantics
select routine_schema, routine_name, routine_type, definer, security_type
from information_schema.routines
order by routine_schema, routine_name;
```

---

## 2. Authorization checks

### 2.1 Dangerous global privileges

A privilege granted `ON *.*` is server-wide. Flag any client/app account holding:

- `SUPER` / `SYSTEM_USER` / `SET_USER_ID` — broad admin, can set arbitrary `DEFINER`.
- `GRANT OPTION` — self-escalation (can grant itself more).
- `FILE` — read/write server files (`LOAD DATA`, `INTO OUTFILE`); data exfiltration and, combined with others, RCE-adjacent.
- `PROCESS` — see all sessions' queries (may leak secrets in SQL text).
- `CREATE USER`, `RELOAD`, `SHUTDOWN`, `REPLICATION SLAVE/CLIENT`.
- `ALL PRIVILEGES ON *.*` or `WITH GRANT OPTION`.
- Any privilege on the `mysql` system database.

The application connection account should hold only the database/table/column privileges it needs on the application schema — never global privileges.

### 2.2 Definer vs invoker

`SQL SECURITY DEFINER` (the default for routines, and the model for views) executes with the definer's privileges, not the caller's. This is MySQL's analogue of `SECURITY DEFINER` and the main privilege-bypass path:

- Flag definer-rights views/routines owned by a high-privilege account (e.g. `root@localhost`) that are callable by low-privilege app accounts and perform privileged reads/writes without internal authorization checks.
- Prefer `SQL SECURITY INVOKER` where the caller should be constrained by their own privileges.
- Flag routines/views whose `DEFINER` account no longer exists or is over-privileged.

### 2.3 Emulated row isolation

Since there is no RLS, verify how (and whether) per-tenant/per-user row isolation is actually enforced:

- **Filtering views** — e.g. a view with `WHERE created_by = CURRENT_USER()` or `WHERE tenant_id = (current session var)`, with table access revoked and only the view granted. Check the view's `WHERE` actually scopes rows and that the base table is not directly grantable.
- **Definer stored procedures** as the only data path, with `SELECT`/`INSERT`/`UPDATE`/`DELETE` revoked on base tables.
- **Per-tenant database/account separation** (a database or account per tenant).
- **App-layer only** — if isolation lives solely in application code and the DB account can read the whole table, that is a finding: any leaked credential, SQL injection, or direct connection bypasses it.

### 2.4 Roles and least privilege

Flag: privileges granted directly to many users instead of via roles; over-broad roles; `mandatory_roles` granting unexpected access; accounts whose effective privileges (account + active roles) exceed their function.

---

## 3. Test approach

MySQL has no per-user impersonation equivalent to Postgres `SET ROLE <user>` or SQL Server `EXECUTE AS USER`. To verify enforcement:

- Connect (in a non-production environment) as the actual low-privilege application account and attempt the persona/operation matrix from `testing.md` directly.
- `SET ROLE` can activate/deactivate granted roles within a session to test role-gated access: `SET ROLE NONE;` then `SET ROLE 'app_role';`.
- For privilege questions without a live low-priv connection, derive the answer from `SHOW GRANTS` + view/routine `SECURITY_TYPE` and report it as **derived from metadata**, not executed.
- Never test using `root` or an account with global privileges as if it were an ordinary user.

---

## 4. Remediation patterns

Recommendations for the report only — **do not execute** (SKILL.md §2).

```sql
-- Remove dangerous global privileges from an app account
revoke super, file, process, grant option on *.* from 'app_user'@'%';

-- Grant least privilege on the application schema only (column-scoped where needed)
grant select, insert, update on appdb.* to 'app_user'@'%';
grant select (id, name, created_at) on appdb.customers to 'reporting'@'%';

-- Remove anonymous and wildcard-host accounts
drop user ''@'localhost';
drop user 'app_user'@'%';            -- recreate scoped to specific hosts

-- Prefer invoker security so callers are bound by their own privileges
alter view appdb.tenant_orders sql security invoker;
-- (routines: recreate with SQL SECURITY INVOKER)

-- Enforce row isolation via a filtering view + revoked base table
revoke all on appdb.orders from 'app_user'@'%';
create view appdb.my_orders as
  select * from appdb.orders where tenant_id = /* session/connection tenant */ ;
grant select on appdb.my_orders to 'app_user'@'%';
```

Also recommend: use roles instead of per-user grants; set explicit default roles; rotate/lock stale accounts; restrict `host` to known sources; move privileged operations behind definer routines with internal authorization checks.
