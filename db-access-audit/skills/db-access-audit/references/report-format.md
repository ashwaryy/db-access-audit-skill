# Required Final Report Format

Apply the format the human chose in Pre-Flight Step 5 (Interactive HTML by default, or Markdown). Scale the depth to the project — a small single-tenant app does not need every sub-table populated; a multi-tenant platform does. The column headings below are platform-neutral; adapt the labels to the target (e.g. "USING/WITH CHECK" for Postgres, "rule condition" for Firestore, "IAM condition" for DynamoDB, "FILTER/BLOCK predicate" for SQL Server).

```markdown
# Database Access Audit Report

## 1. Executive Summary
- Overall risk rating:
- Most important risks:
- Strong controls observed:
- Immediate recommended actions:

## 2. Scope and Access
- Database/platform:
- Environment:
- Access method (and tier):
- Schemas/namespaces inspected:
- Objects inspected:
- Objects not inspected:
- Assumptions:

## 3. Authorization Model Summary
### 3.1 Subjects
### 3.2 Roles
### 3.3 Permissions
### 3.4 Scopes / Tenants
### 3.5 Role Hierarchy
### 3.6 Separation of Duties Rules

## 4. Inventory
### 4.1 Resources and Row/Document-Control Coverage
| Schema/Namespace | Object | Data Category | Exposed? | Row/Doc Control? | Rules/Policies? | Risk |
|---|---|---|---:|---:|---:|---|

### 4.2 Access Control Matrix
| Object | Operation | Policy/Rule/Grant | Principals | Read filter | Write validation | Assessment |
|---|---|---|---|---|---|---|

### 4.3 Grants / Permissions / IAM Matrix
| Object | Type | Grantee/Principal | Privileges/Actions | Assessment |
|---|---|---|---|---|

### 4.4 Privileged Routines
| Routine | Runs As (definer/EXECUTE AS/Admin) | Callable By | Performs Privileged Work? | Assessment |
|---|---|---|---:|---|

### 4.5 Role Membership
| Role | Members/Inherits | Dangerous Attributes | Assessment |
|---|---|---|---|

## 5. Findings
### Finding DBA-001: [Title]
- Severity:
- Category:
- Affected objects:
- Evidence:
- Why this matters:
- Exploit scenario:
- Recommended remediation:
- Example fix (SQL/rule/IAM/migration):
- Validation steps:
- Owner:
- Priority:

## 6. Remediation Roadmap
### Immediate: 0–48 hours
### Short term: 1–2 weeks
### Medium term: 1–2 months
### Long term governance

## 7. Validation Test Plan
| Test | Persona | Action | Expected Result | How to Run |
|---|---|---|---|---|

## 8. Queries / Commands Executed / Evidence Collected
List every query/command/tool call used for audit evidence.

## 9. Residual Risks and Open Questions
```

---

## Quality bar — verify before finalizing

- Every critical/sensitive resource has an explicit access assessment.
- Every client-facing role has its object privileges reviewed.
- Every row/document-level control has an operation, principal, read-filter, and write-validation assessment — evaluated as the *combined* effect of all applicable policies/rules, not one at a time.
- Every client-facing role has column/field-level exposure reviewed for sensitive-data leaks.
- Every routine exposed to client/low-privilege principals is reviewed, and every privileged/bypass routine (definer / `EXECUTE AS` / Admin SDK) is reviewed.
- Every bypass-capable principal (superuser, owner, `BYPASSRLS`, `sysadmin`, ownership chaining, Admin SDK, IAM `*`) is reviewed.
- Every finding includes evidence and remediation.
- The report distinguishes confirmed findings from assumptions.
- The report includes negative tests, not only happy-path tests.
- The remediation plan is prioritized by exploitability and blast radius.
