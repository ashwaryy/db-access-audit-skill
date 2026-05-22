# Platform Reference — NoSQL (Firestore, MongoDB, DynamoDB)

Load this reference when the target is a document or key-value store. Authorization here lives in **security rules**, **database roles**, or **IAM policies** — not SQL grants and RLS. The universal workflow still applies: inventory subjects/roles/privileges, find the row/document-level control, identify privileged bypass paths.

These three are distinct systems — use the section that matches the target.

---

## 1. Google Cloud Firestore

Authorization is enforced by **Security Rules** (`firestore.rules`) for client SDKs. The Admin SDK and server-side access **bypass rules entirely** — the analogue of a `service_role` key.

### What to inspect

- The deployed `firestore.rules` file (and `storage.rules` if Firebase Storage is used).
- Whether server code uses the Admin SDK (rules bypassed) and whether that path has its own authorization.

### Checks and red flags

```javascript
// ❌ Fully open — anyone on the internet can read/write
match /{document=**} { allow read, write: if true; }

// ❌ "Authenticated" is not "authorized" — any signed-in user reaches every doc
match /orders/{id} { allow read, write: if request.auth != null; }

// ✅ Ownership-scoped read; validated write
match /orders/{id} {
  allow read:  if request.auth.uid == resource.data.ownerId;
  allow create: if request.auth.uid == request.resource.data.ownerId;
  allow update, delete: if request.auth.uid == resource.data.ownerId;
}
```

Flag:

- Default-allow or `if true` anywhere.
- `if request.auth != null` on non-public collections (authenticated ≠ owner/tenant).
- Missing ownership/tenant predicate (`request.auth.uid == resource.data.ownerId`, or a membership lookup via `get()/exists()`).
- Writes not validated against `request.resource.data` — lets a user set `ownerId`, `role`, `isAdmin`, tenant fields, or status to arbitrary values (the document-store equivalent of a missing `WITH CHECK`).
- A broad recursive wildcard `match /{document=**}` whose `allow` is wider than the specific collection rules beneath it (rules are additive/OR — a broader allow grants access).
- Rules trusting custom claims (`request.auth.token.*`) without verifying how those claims are set and revoked, and their staleness window.
- Sensitive data reachable because rules gate the collection but not subcollections, or vice versa.
- Server/Admin SDK paths performing privileged writes with no internal authorization check.

### Test approach

Use the Firebase **Rules emulator / unit test SDK** (`@firebase/rules-unit-testing`) to assert allow/deny per persona offline — no production data touched. Run the persona/operation matrix from `testing.md` (owner, other user, cross-tenant, anonymous, removed-member).

---

## 2. MongoDB

Authorization is **role-based access control**. First confirm authentication is even enabled — an open instance (`security.authorization` not `enabled`, or bound to a public interface) is the most severe and common finding.

### Inventory

```javascript
// is auth enforced?
db.adminCommand({ getParameter: 1, authenticationMechanisms: 1 });
// (and confirm the server was started with --auth / security.authorization: enabled)

// users and their roles (run per database; admin DB holds cluster-wide users)
db.getSiblingDB("admin").runCommand({ usersInfo: 1, showPrivileges: true });
db.runCommand({ usersInfo: 1, showPrivileges: true });

// custom roles and the privileges (actions on resources) they bundle
db.runCommand({ rolesInfo: 1, showPrivileges: true, showBuiltinRoles: false });
```

### Checks and red flags

- **No authentication enabled / network-exposed instance.** Critical.
- Users with `root`, `__system`, `dbOwner`, `userAdminAnyDatabase`, `readWriteAnyDatabase`, or `clusterAdmin` that are not genuine administrators.
- Custom roles granting `anyAction` on `anyResource`, or `{ resource: { db: "", collection: "" } }` (all databases/collections).
- The application account holding `readWrite` on databases it doesn't use, or write where read suffices.
- No per-collection scoping in multi-tenant designs (one role reads every tenant's collection).
- Reliance on app-layer filtering only: MongoDB has no row-level rules, so document isolation must come from per-collection/per-database separation, query-time filters the client cannot remove, or **views with `$redact`/`$match`** exposing only permitted documents/fields (grant access to the view, not the base collection).
- Field-level sensitivity: consider Client-Side Field Level Encryption for secrets; flag sensitive fields readable by broad roles.
- Atlas: if **App Services / Realm rules** are used, audit those rules like Firestore (role-based document filters and field rules); check API keys and rule "default rule" permissiveness.

### Test approach

Authenticate (in non-production) as the application user and attempt the persona/operation matrix directly; `usersInfo`/`rolesInfo` give the metadata-derived answer when a live low-priv connection isn't available. Never test as `root`.

---

## 3. Amazon DynamoDB

DynamoDB has **no database-native users** — all access is through **AWS IAM**. The audit is an IAM-policy audit focused on DynamoDB actions, resource scoping, and the condition keys that provide item- and attribute-level isolation.

### Inventory

```bash
# roles and their policies (the subjects)
aws iam list-roles
aws iam list-role-policies --role-name AppRole
aws iam get-role-policy --role-name AppRole --policy-name AppDynamoAccess
aws iam list-attached-role-policies --role-name AppRole
aws iam get-policy-version --policy-arn <arn> --version-id <v>

# IAM Access Analyzer surfaces overly broad / external access
aws accessanalyzer list-findings --analyzer-arn <arn>
```

### Checks and red flags

```jsonc
// ❌ Over-broad: every DynamoDB action on every table
{ "Effect": "Allow", "Action": "dynamodb:*", "Resource": "*" }

// ✅ Item-level (row) isolation: caller only touches items whose
//    partition key equals their identity
{
  "Effect": "Allow",
  "Action": ["dynamodb:GetItem","dynamodb:Query","dynamodb:PutItem","dynamodb:UpdateItem"],
  "Resource": "arn:aws:dynamodb:*:*:table/Orders",
  "Condition": {
    "ForAllValues:StringEquals": {
      "dynamodb:LeadingKeys": ["${cognito-identity.amazonaws.com:sub}"]
    }
  }
}
```

Flag:

- `Action: dynamodb:*` or `Resource: "*"` on application roles.
- Multi-tenant / per-user tables **without** a `dynamodb:LeadingKeys` condition tying access to the caller's identity — the item-level (row) isolation control. Its absence means any holder of the role reads every tenant's items.
- Missing `dynamodb:Attributes` + `dynamodb:Select` conditions where attribute-level (column) restriction is intended — sensitive attributes otherwise returned.
- Broad `dynamodb:Scan` permission (reads the whole table, ignoring partition-key scoping).
- Wildcard principals or cross-account `Resource`/trust without conditions.
- Stream / export / backup actions (`dynamodb:GetRecords`, `ExportTableToPointInTime`) granted broadly — a bulk-exfiltration path around item-level conditions.
- Long-lived IAM user access keys instead of role assumption; missing rotation.

### Test approach

Use `aws iam simulate-principal-policy` / `simulate-custom-policy` to evaluate allow/deny for specific actions, resources, and condition context (e.g. a given `LeadingKeys` value) without making real data calls — the read-only-safe equivalent for IAM. Run the persona matrix as simulated principals.

```bash
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::<acct>:role/AppRole \
  --action-names dynamodb:GetItem dynamodb:Scan \
  --resource-arns arn:aws:dynamodb:*:*:table/Orders
```

---

## 4. Remediation patterns (all NoSQL)

Recommendations for the report only — **do not execute** (SKILL.md §2).

- **Firestore:** default-deny baseline (`match /{document=**} { allow read, write: if false; }`), explicit ownership/tenant predicates per collection, validate `request.resource.data` on writes, unit-test rules in CI with the emulator, keep Admin SDK usage server-side with its own authorization.
- **MongoDB:** enable authentication and bind to private networks; replace broad built-in roles with least-privilege custom roles scoped per database/collection; expose `$redact`/`$match` views instead of base collections; rotate credentials; use field-level encryption for secrets.
- **DynamoDB:** scope IAM to specific table ARNs and actions; add `dynamodb:LeadingKeys` for item-level isolation and `dynamodb:Attributes` for attribute-level; remove blanket `Scan`; prefer short-lived role assumption over static keys; run IAM Access Analyzer in CI.
