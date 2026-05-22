# Phase 6 — Test Authorization Behaviour

Do not rely only on reading policies/rules/grants when the human has authorized behavior checks. Metadata proves *intent*; execution proves *enforcement*. Build a test matrix for every audit, and mark whether each test was executed, derived from metadata, or provided for human execution.

---

## 6.0 Use the safest available harness — see the platform reference

Each platform offers a way to verify behaviour as a given persona. Some methods are metadata-only; others query live data but leave no persistent changes. Load the matching platform reference for the concrete recipe:

| Platform | Harness |
|---|---|
| PostgreSQL / Supabase | transaction + `set local role` + `set local request.jwt.claims` + `rollback`; live `SELECT` tests need opt-in |
| SQL Server | `execute as user = '...'` ... `revert`; live `SELECT` tests need opt-in; wrap writes in `begin tran ... rollback` |
| MySQL | connect as the actual low-privilege account in non-prod; `SET ROLE` to toggle granted roles |
| Firestore | rules unit-test SDK / emulator, offline, no production data |
| MongoDB | authenticate as the application account in non-prod and attempt the matrix |
| DynamoDB | `aws iam simulate-principal-policy`, evaluates allow/deny without real data calls |

Rules that apply to every harness:

1. **Metadata-only harnesses** can be run under the default audit mandate because they do not touch live application rows/documents.
2. **Behavioral read tests against live data require explicit human opt-in** because they may read real rows/documents, even though they have no persistent side effects.
3. **Write-shaped tests (insert/update/delete/put spoofing) require a separate explicit human opt-in** (SKILL.md §2), even when wrapped in a rollback — they are write-shaped statements.
4. **Never test as a superuser, owner, admin, or bypass-capable principal as if it were an ordinary user** — those bypass the controls and produce false passes. Use them only to *confirm* bypass behaviour deliberately.
5. If approval or harness access is unavailable, derive the answer from metadata and mark the row **Derived from metadata / Provided for human execution**, not executed.

---

## 6.1 Required test personas

At minimum:

| Persona | Expected Access |
|---|---|
| Anonymous / unauthenticated | Public-only |
| Authenticated user A | Own data only |
| Authenticated user B | Own data only |
| Same-tenant member | Tenant-scoped data according to role |
| Cross-tenant user | No access |
| Tenant admin | Scoped admin only |
| Platform admin | Admin operations only through trusted path |
| Service account / job | Minimum server-side access |
| Suspended / deactivated user | No access |
| User with removed membership | No access |

---

## 6.2 Required test operations

For each sensitive table/collection:

- Read own record
- Read other user's record, same tenant
- Read another tenant's record
- Create own / scope-valid record
- Create with spoofed owner/`user_id`/`tenant_id`
- Update an allowed field
- Update owner/tenant/role/status field (escalation attempt)
- Delete an allowed record
- Delete another user's / tenant's record
- Execute an exposed privileged routine/function with own ID
- Execute an exposed privileged routine/function with another user's / tenant's ID

---

## 6.3 Test reporting

For every test case, report:

| Test ID | Persona | Operation | Expected | Actual | Pass/Fail | Evidence |
|---|---|---|---|---|---|---|

If tests cannot be run (no live access, or the harness is unavailable), provide the exact statements/commands a human should run — using the platform reference's harness — and mark each row **Provided for human execution**.
