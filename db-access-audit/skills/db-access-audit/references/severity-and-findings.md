# Finding Severity Rubric

Use this rubric consistently.

## Critical

Use when exploitation can cause immediate major data breach or privilege escalation.

Examples:

- Anonymous/public access to sensitive data.
- Cross-tenant read/write/delete.
- Client/public exposure of an admin or service credential.
- User can grant self admin.
- Row/document-level isolation absent on an exposed sensitive resource with broad access.
- Privileged routine (definer / `EXECUTE AS` / Admin SDK) allows unauthenticated privileged action.

## High

Use when exploitation is serious but requires authentication, a specific role, or non-trivial preconditions.

Examples:

- Any authenticated user can update sensitive records.
- Weak row/document control permits same-tenant overreach.
- Admin routine executable by all authenticated users.
- Role/membership store can be manipulated by non-admins.
- Missing write-side validation (e.g. `WITH CHECK`, rule/`request.resource` checks, IAM conditions) allows ownership/tenant spoofing.

## Medium

Use for meaningful control weaknesses with limited direct exploitability.

Examples:

- Overbroad internal grants.
- Missing access recertification.
- Unscoped admin roles in low-sensitivity areas.
- Temporary exceptions without expiry.
- Weak audit trail for permission changes.

## Low

Use for hygiene issues with limited immediate risk.

Examples:

- Inconsistent role naming.
- Redundant policies.
- Unused roles.
- Missing documentation.
- Non-sensitive reference table policy could be clearer.

## Informational

Use for observations, architecture notes, or improvement opportunities.

---

# Common Findings Library

Use these as standard finding titles when applicable. Phrasing is platform-neutral; cite the platform-specific mechanism in the finding body.

1. **Row/document-level isolation disabled or absent on an exposed sensitive resource**
2. **Broad anonymous/public access to non-public data**
3. **Client-facing role has excessive privileges on a sensitive resource**
4. **Row/document control allows cross-tenant access**
5. **Missing write-side validation allows tenant/owner spoofing** (absent Postgres `WITH CHECK`, unvalidated Firestore `request.resource.data`, missing DynamoDB `LeadingKeys` condition)
6. **Role/membership store permits self-escalation**
7. **Client-callable privileged routine bypasses authorization** (Postgres `SECURITY DEFINER`, SQL Server `EXECUTE AS`/ownership chaining, MySQL definer routine, Firebase Admin SDK path)
8. **Admin/service credential exposed outside the trusted server**
9. **View/aggregation bypasses underlying row/document controls**
10. **Default privileges or default-allow rules expose future objects**
11. **Unscoped global admin role creates excessive blast radius**
12. **No separation of duties for high-risk workflow**
13. **Temporary elevated access lacks expiry**
14. **Stale users/service accounts retain access**
15. **Audit logs insufficient for authorization incident response**
16. **Control relies on mutable/spoofable identity metadata**
17. **Membership/predicate lookup lacks supporting indexes**
18. **Overlapping/bloated roles cause audit ambiguity**
19. **No validation tests for negative authorization cases**
20. **Internal objects placed on an externally-exposed surface**
21. **Sensitive column/field exposed to a client role despite row/document control**
22. **Broad permissive policy/rule overrides narrower ones (additive/OR semantics)**
