# Phase 4 — RBAC Audit Checks

Apply every check below.

---

## 4.1 Least privilege

Verify each role has only the permissions required for its business function.

Flag:

- The anonymous/public role can read non-public data.
- Client-facing roles have blanket read/write on sensitive resources.
- Application users can change role, tenant, owner, billing, status, approval, or security fields without constraints.
- Client-facing roles can execute administrative routines/functions.
- Roles have permissions "because previous users had them."
- Permissions exist but are unused.

Severity guidance:

- Anonymous write or broad sensitive read: **Critical**
- Cross-tenant read/write: **Critical**
- Authenticated global write on sensitive resources: **High**
- Excessive internal role permission: **Medium/High depending on blast radius**

---

## 4.2 Separation of users, roles, and permissions

Verify that:

- Users are not directly granted many object-level permissions when a role abstraction should exist.
- Roles are bundles of permissions, not hard-coded job titles that cause role sprawl.
- Users may hold multiple small roles without creating monolithic "super roles."
- Permission definitions are understandable and auditable.

Flag:

- Bloated roles.
- One-off custom roles without expiry.
- Role names like `AP_Role_01` or `misc_admin`.
- Permissions duplicated across many roles without design rationale.

---

## 4.3 Scoped roles, not global roles

Verify role assignments include scope where needed:

- organization_id
- tenant_id
- workspace_id
- project_id
- department_id
- region
- environment
- resource owner

Flag:

- Global `admin` where admin should be tenant/workspace-scoped.
- Role membership table has `user_id, role` but no scope column in a multi-tenant system.
- Policies check role only, not role + tenant/workspace membership.
- Users can access data across organizations because role name matches.

---

## 4.4 Separation of duties

Identify conflicting permissions.

Common conflict pairs:

| Permission A | Permission B | Risk |
|---|---|---|
| Create payment | Approve payment | Fraud |
| Create purchase order | Approve purchase order | Fraud/error |
| Create user | Grant admin role | Privilege escalation |
| Modify audit logs | Investigate audit logs | Evidence tampering |
| Generate encryption key | Decrypt sensitive data | Key misuse |
| Deploy code | Approve production release | Change-control bypass |
| Create vendor | Approve vendor payment | Fraud |
| Export sensitive data | Disable audit/DLP | Data exfiltration |

Report whether the system enforces:

- Static Separation of Duties: conflicting roles cannot be assigned to the same subject.
- Dynamic Separation of Duties: conflicting roles cannot be active in the same session or transaction.
- Approval workflow or MFA for risky operations.

---

## 4.5 Exceptions and temporary access

Check whether temporary elevated access has:

- Approval trail
- Expiration
- Scope
- Reason
- Reviewer
- Automatic revocation
- Audit logs

Flag permanent exceptions as security debt.

---

## 4.6 Lifecycle automation

Assess whether access changes are tied to:

- onboarding
- offboarding
- department/team changes
- HR identity source
- user deactivation
- tenant membership removal
- periodic recertification

Flag orphaned users, inactive admins, and stale service accounts.

---

## 4.7 Dangerous privileged-credential usage

Across platforms, confirm:

- **Where admin/service credentials are used** — Postgres `service_role`/secret keys, MySQL accounts with global privileges, SQL Server `sysadmin`/`db_owner` logins, the Firebase Admin SDK, AWS admin IAM roles.
- They are **never** present in frontend/mobile/client code, public repos, logs, or screenshots.
- Privileged/bypass calls run **server-side only** and perform an explicit authorization check *before* querying.
- **Bypass-capable principals** are rare and justified — Postgres `BYPASSRLS` and table owners; SQL Server `sysadmin`/ownership chaining/`TRUSTWORTHY`; MySQL definer-rights routines; the Firebase Admin SDK (bypasses rules); IAM policies with `*` actions/resources.
- Admin/privileged roles are not used for ordinary application queries.

See the platform reference for the concrete credentials, catalogs, and bypass paths.
