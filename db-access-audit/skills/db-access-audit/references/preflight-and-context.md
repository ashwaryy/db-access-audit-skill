# Pre-Flight and Context Gathering

Work through these steps **before running a single query**. Each step only activates if the previous one left questions unanswered. The goal is to minimise interruptions to the human while building enough context to audit accurately.

This step shapes every subsequent judgment call: what counts as a finding, how severe it is, and what the correct remediation looks like.

---

## Identify the platform, then load its reference

This core workflow is platform-neutral. The concrete queries, mechanisms, and remediation live in **platform references** — a key job of pre-flight is to identify the target so you can load the matching one:

| Platform | Reference to load |
|---|---|
| PostgreSQL, Supabase, Neon, RDS/Cloud SQL for Postgres | `references/postgres-supabase.md` |
| MySQL, MariaDB | `references/mysql.md` |
| Microsoft SQL Server, Azure SQL | `references/sqlserver.md` |
| Firestore, MongoDB, DynamoDB | `references/nosql.md` |

The *principles* — least privilege, subject/role/permission separation, scoped roles, row/document-level isolation, separation of duties — transfer to any access-control system, but the queries and metadata catalogues do not. For a platform without a dedicated reference, map each concept to its equivalent before auditing:

| Engine | Row-level mechanism | Object/privilege model | Notes |
|---|---|---|---|
| MySQL / MariaDB | No native RLS — emulate with views, stored procedures, or app-layer filters | `GRANT`/`REVOKE`, column privileges | Audit views + definer-rights procedures instead of policies |
| SQL Server | `CREATE SECURITY POLICY` + inline table-valued predicate functions | schema/role grants | Predicate functions are the RLS analogue |
| Oracle | Virtual Private Database (VPD) / Oracle Label Security | roles, system/object privileges | Policy functions attached via `DBMS_RLS` |
| Document DBs (Mongo, Firestore, DynamoDB) | Collection/security rules, IAM conditions | IAM policies, database roles | Authorization lives in rules files / IAM, not SQL |

For non-PostgreSQL engines, state explicitly in the report that the concrete checks were adapted, and flag any area where the equivalent could not be inspected.

---

## Step 1 — Read context files

Look for the following files in the repository root, `docs/`, or any top-level directory. Read every one you find.

| Priority | Files to look for |
|---|---|
| Highest | `CLAUDE.md`, `AGENT.md`, `AGENTS.md` |
| High | `README.md`, `README.rst`, `README.txt` |
| Medium | `docs/spec.md`, `docs/architecture.md`, `docs/schema.md`, any file with "spec", "arch", "design", or "schema" in the name |
| Lower | `package.json`, `pyproject.toml`, `Cargo.toml` (for project name, description, dependencies that hint at the stack) |

For each file you read, extract answers to the context questions in Step 3 and mark them as **[from file: filename]**. Note what is still unanswered.

If all eight questions are answered with reasonable confidence, skip Steps 2 and 3 and go directly to Step 4.

---

## Step 2 — Explore the repository

If context files left gaps, explore the codebase to answer the remaining questions. Do not ask the human yet.

Look for:

- **Tenancy model** — search for column names like `tenant_id`, `organization_id`, `workspace_id`, `account_id`, or `owner_id` in migration files, ORM models, or schema definitions. Their presence strongly implies multi-tenancy or scoped ownership.
- **User types and auth provider** — look for auth configuration files, environment variable names (e.g. `SUPABASE_URL`, `AUTH0_DOMAIN`, `NEXTAUTH_URL`), or imports of auth libraries.
- **Role/permission model** — search for files named `roles`, `permissions`, `rbac`, `acl`, or `policies`. Look for enums, constants, or seed data that defines role names.
- **Sensitive data** — look at migration filenames and table names for patterns like `payment`, `invoice`, `health`, `medical`, `ssn`, `pii`, `gdpr`, `kyc`, `billing`.
- **Platform** — check `supabase/` directory, `.supabase/`, `prisma/schema.prisma`, `drizzle.config.ts`, or similar for the database platform and connection details.
- **Migrations** — read `supabase/migrations/` or equivalent to understand schema history and see if RLS/grants have been explicitly managed.

Mark every answer derived from code exploration as **[inferred from repo]**.

---

## Step 3 — Ask the human only for what remains

If any of the following questions are still unanswered after Steps 1 and 2, ask the human. Present only unanswered questions — do not ask about things you already know. Ask one question per message and wait for the answer before asking the next unresolved question. If the host supports native selectable options, use them for fixed-choice questions; otherwise use numbered choices. If the human answers multiple pending questions at once, record all supplied answers and continue with the next unresolved question. If the human explicitly declines to answer or asks you to proceed, continue and flag the assumption in the report as **Inferred — not confirmed by human**.

```
Context Questions (ask only unanswered ones)
─────────────────────────────────────────────
Q1. Tenancy model
    Single-tenant (one org, internal users only), multi-tenant
    (many orgs sharing one database), or user-owned data
    (each row belongs to one individual)?
    Fixed-choice prompt:
    1. Single-tenant
    2. Multi-tenant
    3. User-owned data
    4. Not sure / infer from repo

Q2. User types
    Who are the users? (internal staff, external customers, both,
    anonymous public, API clients, service accounts)

Q3. Roles and permissions
    Does the app have named roles (admin, member, viewer…)?
    Are they stored in the database or in external claims (JWT, IAM)?

Q4. Sensitive data
    Financial records, PII, health data, or other regulated data?
    Which tables or domains?

Q5. Authentication provider
    Supabase Auth, Auth0, custom JWT, IAM, session cookies, API keys?

Q6. Platform and target environment
    Database platform (Supabase, plain PostgreSQL, Neon, RDS…)?
    Which environment to audit — local, staging, or production?
    If platform is already known, only ask the environment:
    1. Local
    2. Staging
    3. Production
    4. Other / not sure

Q7. Known concerns
    Any specific areas of worry, recent auth-touching changes,
    or past incidents?
    Ask as a single open-ended question:
    Any known concerns, recent auth/RLS changes, or past incidents you want prioritized?

Q8. Out of scope
    Any tables, schemas, or areas to explicitly skip?
    Ask as a single open-ended question:
    Any tables, schemas, or areas explicitly out of scope?
```

---

## Step 4 — Confirm database access

The audit starts with **metadata-only read access**: schema/collection definitions, structures, row/document-level controls (RLS policies, security rules, IAM policies), grants/permissions, roles, role bindings, and function/procedure definitions. No write access is needed.

Do not read live application rows/documents by default. Behavioral tests are opt-in:

- **Metadata-only tests** such as rules emulators, IAM policy simulators, permission catalog checks, and static grant/rule analysis can be run without extra approval.
- **Behavioral read tests** that may query live tables/collections or return real rows/documents require explicit human opt-in.
- **Write-shaped tests** (`INSERT`/`UPDATE`/`DELETE`/put/delete), even inside rollback-capable harnesses, require a separate explicit human opt-in.

First, check whether a connection is already available (e.g. an MCP server is already configured and responding). If it is, confirm silently and proceed — do not ask for something you already have.

If no connection is available, identify the database type from the context gathered in Steps 1–3, then ask the human to provide access using the most appropriate path below. Prefer native selectable options when the host supports them; otherwise use a numbered list. Do not silently downgrade to repository-only artifacts just because no live connection is visible.

### Access tiers — choose the highest tier available

| Tier | Method | Completeness | Notes |
|---|---|---|---|
| 1 | Live connection via MCP tool | Full | Real-time metadata; highest confidence |
| 2 | Live connection via native CLI or SDK | Full | Same quality; requires a shell |
| 3 | Exported schema / schema dump | High | Misses live role state and runtime ACL values |
| 4 | ORM model files or migration history | Medium | Cannot inspect live grants or dynamic policies |
| 5 | Application code only | Low | Authorization intent only; no enforcement verified |

### How to provide a Tier 1 or 2 connection

Ask the human to set up a **read-only** connection scoped to authorization metadata only — the exact method depends on the platform (see the matching platform reference for specifics):

- **Relational (Postgres/Supabase, MySQL, SQL Server):** a dedicated read-only user/role with access to metadata catalogs (`information_schema`, `pg_catalog`, `mysql.*` system tables, `sys.*` catalog views) and no access to application data; a connection string or MCP server config. An MCP server for the platform is the preferred path.
- **Firestore:** the deployed rules file(s) plus read access to IAM bindings; or the Firebase project via read-only credentials.
- **MongoDB:** a read-only account (`read`/`readAnyDatabase`) able to run `usersInfo`/`rolesInfo`.
- **DynamoDB:** read-only IAM access to inspect IAM roles/policies (`iam:Get*`, `iam:List*`) and table metadata; IAM Access Analyzer / policy simulator access.

**Do not share superuser credentials, admin/service keys, root keys, or any credential with write access.** A read-only role or a scoped metadata token is sufficient and preferred. If a behavioral test harness needs a narrowly-scoped capability — e.g. the ability to `SET ROLE` / `EXECUTE AS`, or use the rules emulator / IAM simulator — request it separately and follow the opt-in rules above.

For the access gate, use this fixed-choice prompt:

```text
Can you provide authorization metadata for this audit?
1. Read-only metadata access (recommended)
2. Migration files or schema export
3. Proceed with local artifacts only
```

### If live access is not possible — Tier 3 or 4 fallback

Ask the human to provide one or more of:

- A schema dump or export (schema only, no data rows)
- ORM model files (`schema.prisma`, `models.py`, `schema.rb`, etc.)
- Migration files in chronological order

Only use a Tier 3/4/5 fallback after the human declines live access, cannot provide live access, or explicitly asks you to proceed with local artifacts only.

State clearly in the report's Scope section which tier of access was used and how that limits the confidence of each finding category. If no access of any kind is possible, mark all findings as **Needs Verification — no live access**.

---

## Step 5 — Ask about the output format

Ask once, briefly, unless the human already specified the format. Prefer native selectable options when the host supports them; otherwise use a numbered list:

```text
Preferred report format?
1. Interactive HTML (recommended) — single file, opens in a browser, sidebar navigation, collapsible findings, severity colour-coding, code blocks, remediation roadmap.
2. Markdown (.md) — plain text, suitable for committing to a repo or pasting into a wiki.
```

Default: Interactive HTML if you do not choose or ask me to proceed.

Record the chosen or explicitly defaulted format and apply it when producing the final report. Do not infer Markdown merely because the conversation UI supports Markdown.

---

## Phase 0 — Establish Context

Collect and report:

- Database engine and version.
- Platform: Supabase, plain PostgreSQL, Neon, RDS, Cloud SQL, etc.
- Exposed schemas or API schemas.
- Authentication provider: Supabase Auth, custom JWT, OAuth, IAM, application sessions, service accounts.
- Application role model, if documented.
- Tenant model: single-tenant, multi-tenant, user-owned data, organization/workspace model.
- Environments audited: local, staging, production, branch database.
- Access method: schema dump, migrations, MCP, direct SQL, ORM metadata, dashboard export.

Cross-reference the answers from Step 2 with what you observe in the schema. Note any discrepancies between what the human described and what the database actually implements.

If the intended authorization model is unavailable, infer it from schema and code, then mark inferred assumptions clearly.
