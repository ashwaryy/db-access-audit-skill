# Phase 2 — Classify Data and Resources

Classify every table, collection, or resource into one of these categories:

| Category | Examples | Expected Control |
|---|---|---|
| Public reference | countries, public categories | May allow anonymous read, rarely write |
| Authenticated global | feature flags visible to all users | Authenticated read, admin write |
| User-owned | profiles, personal settings | Owner-only policies |
| Tenant-scoped | org projects, workspace records | Membership/role/scope policies |
| Sensitive regulated | PHI, financial, identity, customer secrets | Strict RLS, MFA/approval outside DB, audit logs |
| Admin-only | billing admin, platform config | No client grants; server/admin only |
| Internal system | queues, sync state, audit logs | Unexposed schema, no client grants |
| Join/membership | user_roles, memberships, invitations | Carefully protected; no self-escalation |

If a sensitive or tenant-scoped table has broad grants or weak RLS, escalate severity.

---

# Phase 3 — Reconstruct the Intended RBAC Model

Build these matrices.

## 3.1 User/subject → role matrix

| Subject Type | Source Table/Provider | Assigned Roles | Scope | Assignment Rule | Expiry |
|---|---|---|---|---|---|

Examples:

- `auth.users` → `organization_members.role`
- service account → database role
- API job → service role
- admin user → app admin table
- workspace member → workspace role

## 3.2 Role → permission matrix

| Role | Scope | Resource | Action | Allowed? | Source |
|---|---|---|---|---:|---|

Actions should be explicit:

- read/list/view
- create
- update own
- update tenant
- delete own
- delete tenant
- approve
- export
- invite/manage users
- change roles
- execute RPC
- administer billing
- bypass RLS

## 3.3 Role hierarchy and inheritance

Document inherited privileges and confirm whether inheritance is intentional.

Flag role hierarchy risk when:

- A junior role inherits senior/admin permissions.
- A support/admin role inherits destructive permissions.
- Inheritance crosses tenant or environment boundaries.
- The hierarchy is undocumented.
- The database role hierarchy conflicts with application roles.

Recommended model:

```text
user -> role -> scope -> permission
```

A user may be `admin` in one organization and `member` or no role in another.
