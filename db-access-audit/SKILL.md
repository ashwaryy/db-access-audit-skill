# db-access-audit

An AI agent skill for auditing database authorization — Role-Based Access Control (RBAC), privileges, and row/document-level isolation — across platforms: PostgreSQL/Supabase, MySQL, SQL Server, and NoSQL (Firestore, MongoDB, DynamoDB). A platform-neutral core workflow loads a platform-specific reference once the target is known. The agent inspects your schema, policies/rules/IAM, grants, roles, and privileged routines as they actually exist — not as they are intended to exist — and produces a structured report with severity-rated findings, evidence, exploit scenarios, and exact remediation.

Invoke this skill directly to begin a guided audit of your database authorization model. In Claude Code, use `/db-access-audit`.
