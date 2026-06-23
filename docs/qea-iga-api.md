# QEA (IGA) Change-Request HTTP API Guide

This guide explains how to drive TideCloak's **QEA (Quorum Enforced Authorization)**
governance layer over its HTTP endpoints. QEA is the product name; the API paths and
internal code use the legacy `iga` prefix, so throughout this document the endpoint
paths read `/iga/...` even though the feature is branded QEA.

All resource classes referenced here live in the `iga-core` Maven module
(`org.tidecloak.iga.rest.*`):

- `IgaAdminResource` (`@Path("iga")`): the change-request lifecycle plus several
  side registers (authorizers, role policies, server certs, licensing).
- `IgaTveBundleResource` (`@Path("iga-tve")`): the diagnostic TVE-bundle export.
- `TideAdminCompatResource` (`@Path("tide-admin")`): the IGA on/off toggle and the
  governed `DISABLE_IGA` capture path.

---

## 1. Overview: the capture-then-veto model

When QEA (IGA) is enabled on a realm, a privileged admin action does NOT apply
immediately. The mutating model call is intercepted, written as a PENDING **change
request (CR)** on a fresh transaction (so it survives the rollback of the request
that triggered it), the original request transaction is rolled back, and the caller
receives **HTTP 202 Accepted** with the new CR id. The change only takes effect once
an admin has **authorized** the CR up to its required threshold and then **committed**
it, at which point the change is *replayed* for real against the model and an
attestation is stamped onto the target entity or relationship row.

So the flow is: privileged action captured (202 + CR id), then authorize (one approval
per admin, gated by approver role), then commit (threshold gate, then replay). Turning
QEA off is itself a governed action and is captured the same way (see
`DISABLE_IGA` below).

The `master` realm is always exempt: QEA never captures there, and the master realm
admin is the escape hatch for disabling QEA on any realm.

---

## 2. Authentication and base path

Every endpoint in this guide first calls `auth.realm().requireManageRealm()` (a couple
of read-only listing endpoints use `requireViewRealm`, and comment delete additionally
allows the comment author). In practice you need an **admin access token with
`manage-realm`** on the target realm, sent as a normal bearer token.

The base path is the standard Keycloak admin REST realm path with the resource prefix
appended:

```
/admin/realms/{realm}/iga/...        (IgaAdminResource)
/admin/realms/{realm}/iga-tve/...    (IgaTveBundleResource)
/admin/realms/{realm}/tide-admin/... (TideAdminCompatResource)
```

To get a token, do a normal client-credentials or password grant against the realm
that holds your admin user (commonly `master`) and use the resulting access token. The
examples below assume an environment variable `$TOKEN` holds that bearer token and
`$KC` holds the base URL (for example `http://localhost:8080`), with `$REALM` the
target realm.

---

## 3. The change-request lifecycle

The CR representation (returned by list, get, authorize, commit, and the PUT/comment
endpoints) carries these fields (built in `IgaAdminResource.toRepresentation`):

| Field | Meaning |
|---|---|
| `id` | CR id (also the `ENTITY_ID` segment used in URLs) |
| `realmId` | owning realm id |
| `entityType` | `USER` / `ROLE` / `GROUP` / `CLIENT` / `CLIENT_SCOPE` / `ORGANIZATION` / edge types / `REALM` / `BATCH` |
| `entityId` | target entity id (edges use a synthetic deterministic id) |
| `actionType` | the governed action (see section 4) |
| `status` | `PENDING` / `APPROVED` / `DENIED` / `CANCELLED` |
| `requestedBy`, `createdAt`, `resolvedAt`, `resolvedBy` | provenance |
| `rows` | the parsed `ROWS_JSON` payload that the replay applies |
| `authorizationCount`, `authorizers[]` | how many distinct admins have approved, and who |
| `threshold` | required number of approvals (resolved exactly as the commit gate computes it) |
| `readyToCommit` | true when PENDING and `authorizationCount >= threshold` |
| `requiredApproverRoles`, `scopeMode` | which roles may approve, and whether `any` or `all` of them is required |
| `dependsOn`, `blocked`, `blockedReason` | prerequisite CRs and whether they hold this one back |
| `relatedPolicyCrId` | informational auto-bundle hint linking a tide-realm-admin grant to its pending `REGEN_ADMIN_POLICY` CR (multiAdmin only) |

### 3.1 List pending CRs

`GET /iga/change-requests?status={STATUS}`
(`IgaAdminResource.listChangeRequests`)

Returns a JSON array of CR representations. `status` defaults to `PENDING`; pass any
other status (`APPROVED`, `DENIED`, `CANCELLED`) to list resolved CRs. Listing PENDING
also runs an idempotent best-effort ensure of the multiAdmin threshold-policy CR (a
no-op on non-multiAdmin realms).

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "$KC/admin/realms/$REALM/iga/change-requests?status=PENDING"
```

Response: `200 OK` with the array.

### 3.2 Get a single CR

`GET /iga/change-requests/{id}` (`getChangeRequest`)

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "$KC/admin/realms/$REALM/iga/change-requests/$CR_ID"
```

Response: `200 OK` with the CR representation, or `404 Not Found` if the id is unknown
or belongs to another realm.

### 3.3 Authorize (sign) a CR

`POST /iga/change-requests/{id}/authorize` (`authorize`)

Records ONE approval (a "doken" toward threshold) by the calling admin. It enforces the
approver-role gate, dedups so the same admin cannot sign twice, and does NOT commit even
once the threshold is reached. The request body is optional; the historical
`{"approval": "..."}` field is vestigial (the simple attestor overwrites it with the
admin username).

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{}' \
  "$KC/admin/realms/$REALM/iga/change-requests/$CR_ID/authorize"
```

Responses:
- `200 OK` with the updated CR representation (approval recorded).
- `403 Forbidden` if the admin lacks a required approver role.
- `409 Conflict` if the CR is not PENDING, or if this admin already signed it.
- `404 Not Found` if the id is unknown.

ADOPT_* CRs are uniquely resumable: an `ADOPT_*` CR sitting in `CANCELLED` is flipped
back to PENDING by authorize (and by commit) so the adoption can be completed on a later
admin pass.

### 3.4 Bulk authorize

`POST /iga/change-requests/bulk-authorize` (`bulkAuthorize`)

An operator one-shot to drain a large set of PENDING CRs (typically the toggle-on ADOPT
closure). It authorizes and commits each candidate using the SAME per-CR gate as the
single-CR endpoints.

Request body fields:
- `actionTypeIn`: required (unless `crIdIn` is given) non-empty list of action-type
  strings to select.
- `crIdIn`: optional explicit list of CR ids; when present and non-empty it takes
  precedence over `actionTypeIn` (eligibility decided per CR).
- `olderThan`: optional epoch-millis upper bound on `createdAt`.
- `limit`: optional, default 100, hard max 1000.

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"actionTypeIn":["ADOPT_USER","ADOPT_ROLE"],"limit":500}' \
  "$KC/admin/realms/$REALM/iga/change-requests/bulk-authorize"
```

Responses:
- `200 OK` with `{results:[...], summary:{total, committed, rejected, skipped, ...}}`.
  IMPORTANT: the HTTP 200 means the bulk endpoint ran; individual CRs may still be
  `REJECTED` (for example `FORBIDDEN_APPROVER_ROLE`, `THRESHOLD_NOT_MET`,
  `ENTITY_VANISHED`, `DEPENDENCY_NOT_MET`) or `SKIPPED` (`ALREADY_RESOLVED`). Read the
  per-CR `results` array, not just the status code.
- `400 Bad Request` on a malformed body / bad `limit`.
- `429 Too Many Requests` if another bulk-authorize is already running for this realm
  (a per-realm cluster mutex). The body carries the realm name.

`REGEN_ADMIN_POLICY` CRs are always sorted to commit last so they do not bump the
threshold and strand still-pending grants.

### 3.5 The two-phase multiAdmin enclave approval model

For multiAdmin-mode (Tide) realms there is a two-phase ceremony that produces a real
signed approval (a "doken") from the admin's browser enclave, instead of the single
username-only `authorize` signature. It is multiAdmin-only; firstAdmin / Tideless /
simple realms get `409 Conflict` (`NOT_MULTI_ADMIN`) so the caller falls back to the
single-phase `authorize` flow.

Phase 1: `GET /iga/change-requests/{id}/approval-model` (`getApprovalModel`)

Builds and returns the per-CR `Policy:1` `ModelRequest` for the admin's enclave to
approve.

Response `200 OK`:
```json
{ "changeRequestId": "...", "actionType": "...",
  "requiresApprovalPopup": true, "requestModel": "<base64 serialized ModelRequest>" }
```
Other responses: `404` (unknown CR), `409` (CR not PENDING, or `NOT_MULTI_ADMIN`,
or `NOT_TIDE_ATTESTOR`), `500` (`APPROVAL_MODEL_BUILD_FAILED`).

Phase 2: `POST /iga/change-requests/{id}/approval-model` (`submitApprovalModel`)

Accepts the doken-embedded serialized model back from the enclave, persists it on the
CR carrier, and records the approving admin toward threshold (dedup once per admin).

Body: `{"requestModel": "<base64 doken-embedded ModelRequest>"}`.

Response `200 OK`:
```json
{ "changeRequestId":"...", "recorded":true, "authCount":N,
  "threshold":M, "readyForCommit": <bool> }
```
Other responses: `400` (missing `requestModel`, or `APPROVAL_MODEL_INVALID`),
`403` (`FORBIDDEN_APPROVER_ROLE`), `404`, `409` (not PENDING / not multiAdmin / not
tide attestor).

How it differs from `authorize`: the simple `authorize` records the admin's username as
the approval; the two-phase model collects a cryptographic doken carrier and counts it
toward threshold. In both cases the real signing over the collected carrier happens at
commit time. Commit is still the gate that enforces threshold and applies the change.

### 3.6 Commit a CR

`POST /iga/change-requests/{id}/commit` (`commit`)

Re-checks the approver-role gate, the dependency gate, the threshold, then runs
`combineFinal` and replays the change (applying it to the model and stamping the
attestation). On success the CR flips to `APPROVED`.

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  "$KC/admin/realms/$REALM/iga/change-requests/$CR_ID/commit"
```

Responses:
- `200 OK` with the updated (now `APPROVED`) CR representation.
- `403 Forbidden` if the committing admin lacks a required approver role.
- `409 Conflict` if the CR is not PENDING.
- `412 Precondition Failed`, several variants:
  - `{error:"Need N more signature(s)", threshold, authCount}`: under threshold.
  - `{error:"DEPENDENCY_NOT_MET", message, dependsOn}`: a prerequisite CR is not yet
    APPROVED.
  - `{error:"PENDING_ADMIN_GRANTS", ...}`: a `REGEN_ADMIN_POLICY` CR cannot commit
    while the tide-realm-admin grant CRs it covers are still pending (commit those
    first).
- `404 Not Found` with `{error:"ENTITY_VANISHED", entityType, entityId, realmId}` if an
  ADOPT target was deleted out-of-band during commit (the CR stays PENDING).

### 3.7 Deny

`POST /iga/change-requests/{id}/deny` (`deny`)

Sets the CR `STATUS=DENIED`. Returns `204 No Content`, or `404` if unknown.

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  "$KC/admin/realms/$REALM/iga/change-requests/$CR_ID/deny"
```

There is no separate "cancel" endpoint on this resource: ADOPT CRs are cancelled in bulk
by the toggle-off path, and a manual operator deny is the way to terminate any other CR.

### 3.8 Edit a CR's rows

`PUT /iga/change-requests/{id}` (`updateChangeRequest`)

Replaces the CR's `rows` payload and DELETES all existing authorizations (so the CR must
be re-signed). Body: `{"rows": [ ... ]}`. Returns `200 OK` with the updated
representation, `400` if `rows` is missing, `404` if unknown.

### 3.9 Comments

- `GET /iga/change-requests/{id}/comments` (`listComments`): `200 OK` with the comment
  array.
- `POST /iga/change-requests/{id}/comments` (`addComment`): body `{"comment":"..."}` or
  `{"body":"..."}`. Returns `201 Created` with the comment. `400` if empty or over 2000
  chars.
- `PUT /iga/change-requests/{id}/comments/{commentId}` (`updateComment`): edit your own
  comment. `403` if you are not the author.
- `DELETE /iga/change-requests/{id}/comments/{commentId}` (`deleteComment`): the comment
  author OR a realm admin may delete. `204 No Content` on success, `403` otherwise.

### 3.10 Manual ADOPT

`POST /iga/adopt` (`createAdopt`)

Creates an `ADOPT_<type>` CR for an existing-but-unattested entity. Body:
`{"entityType":"...","entityId":"..."}`. Returns `201 Created` with
`{changeRequestId, entityType, entityId}`, or `409 Conflict` (`ALREADY_ATTESTED`) if the
target already carries an attestation, or `400` for a missing/invalid field. The
toggle-on scan drives this automatically; the endpoint exists so the round-trip can be
exercised directly.

### 3.11 First-admin sign preview

`POST /iga/change-requests/{id}/first-admin-sign-preview` (`firstAdminSignPreview`)

Resolves a CR to its full signing payload (foreign keys expanded), logs it, and returns
it. No cryptography is performed: this is the documented integration point for the future
Tide signing flow. `200 OK` with the payload, `404` if unknown.

### 3.12 Diagnostic bundle export (per CR)

`GET /iga/change-requests/{id}/diagnostic-bundle` (`diagnosticBundle`)

Returns a READ-ONLY JSON snapshot of a single CR for offline inspection / support. It is
NOT replayed: it faithfully dumps the CR entity plus its authorization rows plus the
effective threshold and approver role the commit gate would apply. The shape is
discriminated by `"diag_kind":"iga_cr_bundle"`:

```json
{ "diag_kind":"iga_cr_bundle", "schema_version":1, "realm_id":"...",
  "cr": { "id":"...", "entity_type":"...", "entity_id":"...", "action_type":"...",
          "status":"...", "requested_by":"...", "created_at":..., "depends_on":[...],
          "rows_json": <parsed>, "request_model": "<base64 carrier|null>" },
  "authorizations": [ { "authorized_by":"...", "approval":"...", "created_at":... } ],
  "threshold": <int>, "approver_role": "<role|null>" }
```

It contains NO private-key material (the `request_model` is the public `Policy:1`
carrier; `approval` dokens are public). `200 OK`, or `404` if the CR is unknown.

### 3.13 TVE-bundle export (diagnostics)

`POST /iga-tve/tve-bundle` (`IgaTveBundleResource.tveBundle`)

A prod-debug producer that emits a Token Validation Engine (TVE) bundle: an unsigned
token plus the attestation-unit envelopes computed from current realm state. Two modes
selected by the `mode` body field:

- `synthesize` (default): build an unsigned access/id token through Keycloak's
  claim-construction pipeline against a transient session (no password needed). Body:
  `{"mode":"synthesize","clientId":"...","userId":"...","scope":"<optional>","tokenType":"access|id"}`.
- `pasted`: accept a customer-supplied compact JWS, strip its signature, derive
  `request{t,c,s,aud}` from the payload, and emit the unsigned form plus the unit
  envelopes. Body: `{"mode":"pasted","token":"<compact JWS>"}`.

Output format is content-negotiated by the `Accept` header: CBOR by default
(`application/cbor`), JSON only when the client sends `Accept: application/json`.

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -H "Accept: application/json" \
  -d '{"mode":"synthesize","clientId":"account","userId":"'"$USER_ID"'"}' \
  "$KC/admin/realms/$REALM/iga-tve/tve-bundle"
```

Responses: `200 OK` with the bundle bytes; `400 Bad Request` with `{error, code}` for
bad input (`MISSING_BODY`, `INVALID_MODE`, `MISSING_PARAMETERS`, `CLIENT_NOT_FOUND`,
`USER_NOT_FOUND`, `INVALID_TOKEN`, etc.); `500` (`INTERNAL`) on an export failure. Error
bodies honour the negotiated format (CBOR or JSON).

---

## 4. Action types

Every CR carries an `actionType` naming the governed action. The full set is the switch
in `IgaReplayDispatcher.doReplay` plus the ADOPT family in `IgaReplayExtension`. The
common ones:

Creates:
- `CREATE_USER`, `CREATE_ROLE`, `CREATE_GROUP`, `CREATE_CLIENT`, `CREATE_CLIENT_SCOPE`,
  `CREATE_ORGANIZATION`: create the named entity from the captured representation.

Relationships (grant / revoke):
- `GRANT_ROLES` / `REVOKE_ROLES`: assign or remove user role mappings.
- `GROUP_GRANT_ROLES` / `GROUP_REVOKE_ROLES`: role mappings on a group.
- `JOIN_GROUPS` / `LEAVE_GROUPS`: user group membership.
- `ADD_COMPOSITE` / `REMOVE_COMPOSITE`: composite-role child links.
- `ASSIGN_SCOPE` / `REMOVE_SCOPE`: client-scope to client assignment.
- `SCOPE_ADD_ROLE` / `SCOPE_REMOVE_ROLE`: roles on a client scope.
- `SCOPE_MAPPING_ADD` / `SCOPE_MAPPING_REMOVE`: scope mappings.
- `REALM_DEFAULT_SCOPE_ADD` / `REALM_DEFAULT_SCOPE_REMOVE`: realm default client scopes.
- `ADD_REALM_DEFAULT_GROUP` / `REMOVE_REALM_DEFAULT_GROUP`: realm default groups.

Protocol mappers:
- `ADD_PROTOCOL_MAPPER` / `UPDATE_PROTOCOL_MAPPER` / `REMOVE_PROTOCOL_MAPPER`.

Attribute writes:
- `SET_*_ATTRIBUTE` / `REMOVE_*_ATTRIBUTE` for `USER` / `CLIENT` / `CLIENT_SCOPE` /
  `GROUP` / `ROLE` / `REALM`.

Realm configuration:
- `SET_REALM_CONFIG`: a typed realm-config field write (enabled, sslRequired,
  registrationAllowed, login flows, and many more).
- `UPDATE_CLIENT_WEB_ORIGINS` / `UPDATE_CLIENT_REDIRECT_URIS`.

Deletes:
- `DELETE_USER`, `DELETE_ROLE`, `DELETE_GROUP`, `DELETE_CLIENT`, `DELETE_CLIENT_SCOPE`,
  `DELETE_ORGANIZATION`.

Organizations:
- `ADD_ORG_MEMBER` / `REMOVE_ORG_MEMBER`, `ORG_INVITE_MEMBER` / `ORG_RESEND_INVITE`,
  `ORG_ADD_IDP` / `ORG_REMOVE_IDP`.

Governance and lifecycle:
- `DISABLE_IGA`: turn QEA off (captured, not applied inline; see section 6 of the toggle
  notes below). It is deliberately not on the firstAdmin auto-commit allow-list, so even
  a firstAdmin must explicitly authorize and commit it.
- `OFFBOARD_REALM`: irreversible realm teardown; requires a minimum number of distinct
  approvers.
- `REGEN_ADMIN_POLICY`: the multiAdmin threshold-policy regeneration CR; must commit
  after the tide-realm-admin grants it covers.
- `REQUEST_SERVER_CERT`, `INSTALL_LICENSE`, `ROTATE_LICENSE`: the workload-cert and
  licensing draft flows.

ADOPT family (retroactive attestation of pre-existing state, emitted by the toggle-on
scan):
- Node: `ADOPT_USER`, `ADOPT_ROLE`, `ADOPT_GROUP`, `ADOPT_CLIENT`, `ADOPT_CLIENT_SCOPE`,
  `ADOPT_ORGANIZATION`, `ADOPT_REALM`.
- Edge: `ADOPT_COMPOSITE_ROLE`, `ADOPT_CLIENT_SCOPE_CLIENT`, `ADOPT_CLIENT_SCOPE_ROLE`,
  `ADOPT_PROTOCOL_MAPPER`, `ADOPT_DEFAULT_CLIENT_SCOPE`, `ADOPT_SCOPE_MAPPING`.

ADOPT_* CRs short-circuit the threshold and approver-role gates (threshold 1, system
bootstrap bypass), and are resumable from CANCELLED.

---

## 5. Threshold, approver, and scope

The required threshold and approver role for a CR are resolved by `IgaScopeResolver`
(read from realm and per-entity attributes) combined with the active attestor's
`getThreshold`. The representation's `threshold`, `requiredApproverRoles`, and
`scopeMode` always mirror exactly what the commit gate enforces.

- Realm attributes: `iga.threshold` (integer, honoured only if at least 1),
  `iga.approverRole` (role name(s), comma-separated), `iga.scopeMode` (`any` or `all`;
  default `any`). `iga.attestor` selects `simple` (Tideless, default) or `tide`.
- Threshold resolution: ADOPT_* short-circuits to 1; otherwise the max per-scope
  threshold wins, then the realm `iga.threshold`, then a default of 1, with a final
  `max(1, resolved)` clamp so the gate can never be disabled.
- Approver resolution: ADOPT_* is a no-op (any manage-realm admin may commit). Otherwise
  if `requiredApproverRoles` is empty any manage-realm admin may sign; with
  `scopeMode=any` the admin needs at least one required role, with `scopeMode=all` every
  required role.
- firstAdmin vs multiAdmin (Tide mode): firstAdmin reports threshold 1 and bypasses the
  approver gate (single-signer onboarding); multiAdmin reports a dynamic floor of
  `0.7 * activeTideAdmins` unless a per-scope override or ADOPT bypass wins.

Gotcha: a per-entity `iga.threshold` is honoured ONLY if the SAME entity also sets
`iga.approverRole`. An entity with just `iga.threshold` contributes nothing and
resolution falls back to the realm threshold / default. If a per-entity threshold seems
ignored, set both attributes on that entity.

---

## 6. Response-code reference

| Status | Meaning in this API |
|---|---|
| `200 OK` | The request succeeded (list/get, an authorize/commit that applied, a successful bulk run). |
| `201 Created` | A new sub-resource was created (manual adopt, a comment). |
| `202 Accepted` | A governed admin action was captured into a CR instead of applying. Body: `{status:"PENDING", changeRequestId, entityType, actionType, message}`; `Location` header points at the CR-get endpoint. Source: `IgaPendingApprovalExceptionMapper`. |
| `204 No Content` | A state change with no body (deny, delete comment, delete side-register entries). |
| `400 Bad Request` | Malformed body / missing required field / bad parameter. |
| `403 Forbidden` | The admin lacks a required approver role for an authorize/commit, or is not the comment author for an edit. Body names the required roles and mode. |
| `404 Not Found` | Unknown CR id (or one belonging to another realm); also `ENTITY_VANISHED` on an ADOPT commit whose target was deleted out-of-band. |
| `409 Conflict` | (a) CR is not in PENDING state; (b) the same admin already signed it; (c) a conflicting CR is already pending for this entity (`PENDING_CHANGE_REQUEST_CONFLICT`, one pending CR per entity, source `IgaConflictExceptionMapper`); (d) manual adopt of an already-attested target (`ALREADY_ATTESTED`); (e) two-phase approval on a non-multiAdmin realm (`NOT_MULTI_ADMIN`); (f) toggle-on `SIDECAR_CAP_EXCEEDED`. |
| `412 Precondition Failed` | A commit gate was not met: under threshold (`Need N more signature(s)`), an unmet dependency (`DEPENDENCY_NOT_MET`), or pending admin grants ahead of a policy CR (`PENDING_ADMIN_GRANTS`). |
| `429 Too Many Requests` | A bulk-authorize is already running for this realm (per-realm cluster mutex). |
| `500 Internal Server Error` | An unexpected failure (for example a TVE-bundle export error, or a two-phase model build failure). |

---

## 7. End-to-end example

This walks a single governed action from capture through commit. Assume `$KC`, `$REALM`,
and `$TOKEN` (a manage-realm admin token) are set.

Step 1: an admin action gets captured. For example, granting a role to a user via the
standard Keycloak admin REST API returns `202` instead of applying:

```bash
curl -i -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '[{"id":"'"$ROLE_ID"'","name":"some-role"}]' \
  "$KC/admin/realms/$REALM/users/$USER_ID/role-mappings/realm"
# HTTP/1.1 202 Accepted
# Location: /admin/realms/<realm>/iga/change-requests/<CR_ID>
# { "status":"PENDING", "changeRequestId":"<CR_ID>",
#   "entityType":"USER", "actionType":"GRANT_ROLES", "message":"..." }
```

Step 2: list the pending CRs (or follow the `Location` header straight to the CR), grab
the id and check `threshold` / `readyToCommit`:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "$KC/admin/realms/$REALM/iga/change-requests?status=PENDING"
```

Step 3: authorize the CR (repeat with distinct admins until `authorizationCount` reaches
`threshold`):

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{}' \
  "$KC/admin/realms/$REALM/iga/change-requests/$CR_ID/authorize"
```

Step 4: commit. The change is replayed and applied for real, the role mapping now exists,
and the CR is `APPROVED`:

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  "$KC/admin/realms/$REALM/iga/change-requests/$CR_ID/commit"
```

If commit returns `412` you are under threshold (get more distinct admins to authorize)
or a prerequisite CR is not yet APPROVED; if `403`, the committing admin lacks a required
approver role.

---

## 8. Realm-level policies and the admin (M0) policy

The change-request lifecycle above is the primary surface of this API. There is a
secondary, smaller side register, the **role-policies** store, that the earlier sections
deliberately left out. This section documents it and, in particular, how an external
application now fetches the realm's admin (M0) policy after the old unauthenticated
endpoint was removed.

> Naming note: the REST path is historically `role-policies` and the table is still
> physically named `IGA_ROLE_POLICY`, but these records are **no longer tied to a role**.
> They are **realm-level named policies** keyed by `(REALM_ID, NAME)`. The old per-role
> keying (`REALM_ID, ROLE_ID`) and the `roleId` field were dropped (see the
> `iga-changelog-2.11.0.xml` migration: add `NAME`, backfill existing rows to
> `tide-realm-admin`, drop the `ROLE_ID` column and its old unique constraint, add the
> `UNIQUE (REALM_ID, NAME)` constraint `UQ_IGA_REALM_POLICY_REALM_NAME`). Wherever older
> notes mention a `role/{roleId}` lookup or a `roleId` field, they are stale.

### 8.1 What realm-level policies are

Policies live in the **`IGA_ROLE_POLICY`** table (entity `IgaRolePolicyEntity`). Each row
is a **realm-level named policy** (a serialized policy blob plus its signature and some
metadata) identified by a `NAME` that is unique within the realm. The name that matters
in practice is the **reserved immutable** name **`tide-realm-admin`** (the constant
`TideAttestor.TIDE_REALM_ADMIN_POLICY_KEY = "tide-realm-admin"`): that row is the realm's
**admin (M0) policy**, a `GenericResourceAccessThresholdRole:1` threshold policy that the
multiAdmin (Tide) signing path uses when producing the real signed approval over an admin
change. The `tide-realm-admin` ROLE still defines WHO approves, but the policy STORAGE no
longer hangs off any role id.

Be precise about its role:

- In **Tideless / simple-attestor** mode (`iga.attestor` unset or `simple`, the default
  and canonical mode) this store is **stored scaffolding**. It is NOT a runtime
  enforcement control. The Tideless commit gate is purely `requireApprover` plus
  threshold (see section 5), and nothing in that gate reads `IGA_ROLE_POLICY`. Do not
  treat `IGA_ROLE_POLICY.THRESHOLD` as a second Tideless threshold source: it is not.
- In **multiAdmin (Tide)** mode the `tide-realm-admin` row is the live M0 admin policy
  the signing path consumes. Internally the attestor reads it via
  `TideAttestor.readM0AdminPolicyBytes(session, realm)`, which looks up the
  `tide-realm-admin` row through the `IgaRolePolicy.findByRealmAndName` named query and
  Base64-decodes the `POLICY` column back to the raw `Policy` bytes. That is the
  canonical in-process accessor for the M0 policy. The M0 writer creates / stores this
  row on the realm at enclave-open / commit time; operators do not create it through the
  add endpoint below.

### 8.2 Auth model: authenticated-only reads, manage-realm writes

The policy endpoints split into two auth tiers (all paths are under
`/admin/realms/{realm}/iga/`):

- **Reads (list / get-by-id / get-by-name)** require only **authentication**. They do
  **not** call `requireManageRealm()`; simply reaching this admin resource already
  requires a valid realm-admin token. There is no role requirement.
- **Writes (add/upsert and the deletes)** are **role-gated to `manage-realm`**: each
  calls `auth.realm().requireManageRealm()` first.

There is **no separate commit endpoint** for policies, and **no endpoint gated on the
`tide-realm-admin` role itself**. The `tide-realm-admin` NAME is enforced as
**immutability** (see 8.4), not as an auth tier.

### 8.3 The policy read endpoints (authenticated-only)

| Method and path | Auth | What it does |
|---|---|---|
| `GET /iga/role-policies` | authenticated-only | List every realm-level policy in the realm. Returns a JSON array of policy representations. |
| `GET /iga/role-policies/{id}` | authenticated-only | Fetch one policy by its row id. `404` if unknown or in another realm. |
| `GET /iga/role-policies/name/{name}` | authenticated-only | Fetch the policy with the given `NAME`. `404` if none. This is the one you use for the admin policy: pass the reserved name `tide-realm-admin`. |

Each returns an `IgaRolePolicyRepresentation` (built by
`IgaAdminResource.toRolePolicyRepresentation`) with these fields:

| Field | Meaning |
|---|---|
| `id` | policy row id |
| `realmId` | owning realm id |
| `name` | the policy's realm-unique name (for the admin policy, `tide-realm-admin`) |
| `policy` | Base64 of the serialized `Policy` bytes |
| `policySig` | signature over the policy (max 512 chars) |
| `contractId` | policy contract / Forseti-contract binding; for the admin policy this is `GenericResourceAccessThresholdRole:1` |
| `approvalType` | approval contract type |
| `executionType` | execution contract type |
| `threshold` | the policy's own threshold value (scaffolding; not the Tideless commit gate) |
| `policyData` | optional auxiliary policy data |
| `createdAt`, `updatedAt` | provenance |

### 8.4 The policy write endpoints (manage-realm)

A policy is normally created / stored on the realm by the M0 writer when it is
created or committed. The **add (upsert) endpoint** exists for the case where creation
happens elsewhere (an external caller that already holds the signed policy bytes). The
write endpoints are role-gated to `manage-realm`.

| Method and path | Auth | What it does |
|---|---|---|
| `POST /iga/role-policies` | manage-realm | Add or upsert a realm-level policy by `name` (upsert keyed on `(realmId, name)`). Body is an `IgaRolePolicyRepresentation`; `name`, `policy`, and `policySig` are required (`policySig` max 512 chars). Returns the stored representation. |
| `DELETE /iga/role-policies/{id}` | manage-realm | Delete a policy by row id. `404` if unknown or in another realm. `204` on success. |
| `DELETE /iga/role-policies/name/{name}` | manage-realm | Delete a policy by `NAME`. `404` if none. `204` on success. |

**Reserved-name immutability.** The reserved `tide-realm-admin` name is owned by the M0
writer. Attempting to add/upsert OR delete a policy bearing that name through any of the
three write endpoints returns **`403 Forbidden`** with an error explaining the name is
reserved. The reads in 8.3 may still fetch the `tide-realm-admin` policy normally; only
the writes refuse it.

### 8.5 Fetching the admin (M0) policy from an external application

There used to be an unauthenticated, non-admin endpoint for the admin policy:
`GET /realms/{realm}/tide-policy-resources/admin-policy` (the `PolicyResourceProvider`,
which now exists only in `tidecloak-iga-extensions-old`). **That endpoint is removed.**
It required no token; the replacement requires a valid (authenticated) realm-admin token
but does **not** require `manage-realm`, because the policy reads are authenticated-only.
An external application now reads the admin policy through the by-name read endpoint,
passing the reserved name `tide-realm-admin` directly (no role-id resolution is needed any
more, since policies are no longer keyed by role):

1. Get an admin token (a normal client-credentials or password grant against the realm
   that holds your admin user, as in section 2). Any authenticated realm-admin token
   works for the read; `manage-realm` is not required.
2. Fetch the policy by its reserved name:
   `GET /admin/realms/{realm}/iga/role-policies/name/tide-realm-admin`.
3. The `policy` field of the response is Base64 of the `Policy` bytes. Deserialize it the
   same way the old client code did: `Policy.from(base64ToBytes(policy))`.

```bash
# 1. $TOKEN is an authenticated realm-admin bearer token; $KC and $REALM as in section 2.

# 2. the admin (M0) policy, fetched directly by its reserved name
curl -s -H "Authorization: Bearer $TOKEN" \
  "$KC/admin/realms/$REALM/iga/role-policies/name/tide-realm-admin"
# -> { "name":"tide-realm-admin",
#      "contractId":"GenericResourceAccessThresholdRole:1",
#      "policy":"<base64 Policy bytes>", "policySig":"...", ... }
```

```java
// 3. deserialize the policy field, exactly as the old client did:
String policyB64 = rolePolicy.getPolicy();      // from the JSON response
Policy adminPolicy = Policy.from(base64ToBytes(policyB64));
```

The M0 admin policy is also reachable through a different surface already documented in
this guide: it is embedded as a segment of the multiAdmin approval-model carrier returned
by `GET /iga/change-requests/{id}/approval-model`. See section 3.5 for that flow rather
than re-deriving it here; use the `role-policies/name/tide-realm-admin` endpoint above when
you want the policy on its own, outside an in-flight approval ceremony.

### 8.6 No unauthenticated public endpoint

There is currently **no** unauthenticated public endpoint for the admin policy. The old
`tide-policy-resources/admin-policy` route is gone, and every replacement path described
above requires at least an authenticated realm-admin token. An external application that
needs the admin policy must hold admin credentials for the target realm.
