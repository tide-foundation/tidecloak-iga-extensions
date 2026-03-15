# TideCloak Change Requests API

Build your own admin management UI using these REST endpoints. All endpoints require an admin bearer token with `manage-users` or `manage-realm` permissions.

**Base URL:** `{keycloak-url}/admin/realms/{realm}`

---

## Quick Start

A typical change request lifecycle:

```
1. User/admin creates a change (role assignment, group change, etc.)
   → A draft is created automatically with status DRAFT/PENDING

2. Admin reviews pending changes
   GET /tide-admin/change-set/counts          ← check what's pending
   GET /tide-admin/change-set/all/requests    ← get all details

3. Admin approves or rejects
   POST /tide-admin/change-set/sign/batch     ← approve (sign)
   POST /tideAdminResources/add-rejection     ← reject

4. If Tide multi-admin is enabled, the sign response returns a signing
   challenge that must be completed with the Tide enclave, then submitted:
   POST /tideAdminResources/add-review        ← submit signed review

5. Once enough approvals are collected, commit the change:
   POST /tide-admin/change-set/commit/batch   ← commit approved changes

6. Or cancel at any time:
   POST /tide-admin/change-set/cancel/batch   ← cancel pending changes
```

---

## Listing Change Requests

### Get counts for all types (lightweight)

```
GET /tide-admin/change-set/counts
```

**Response:**
```json
{
  "users": 3,
  "roles": 1,
  "clients": 0,
  "groups": 2,
  "total": 6
}
```

### Get all change requests (single call)

```
GET /tide-admin/change-set/all/requests
```

**Response:**
```json
{
  "users": [ ...RequestedChanges[] ],
  "roles": [ ...RequestedChanges[] ],
  "clients": [ ...RequestedChanges[] ],
  "groups": [ ...RequestedChanges[] ]
}
```

### Get change requests by type

```
GET /tide-admin/change-set/users/requests
GET /tide-admin/change-set/roles/requests
GET /tide-admin/change-set/clients/requests
GET /tide-admin/change-set/groups/requests
```

Each returns an array of `RequestedChanges` objects.

### Get settings and licensing requests

```
GET /tideAdminResources/change-set/licensing/requests
```

### Get realm policy requests

```
GET /tide-admin/realm-policy
```

Returns policy status (`"none"`, `"pending"`, `"active"`, `"delete_pending"`).

---

## RequestedChanges Object

Every change request item includes:

```typescript
{
  draftRecordId: string;      // Unique ID for this draft — use this for all operations
  changeSetType: string;      // "USER_ROLE", "ROLE", "COMPOSITE_ROLE", "CLIENT",
                               // "GROUP_ROLE", "GROUP_MEMBERSHIP", "GROUP_MOVE", etc.
  actionType: string;         // "CREATE" or "DELETE"
  action: string;             // Human-readable description e.g. "Assign Role to User"
  requestType: string;        // Display category
  status: string;             // "DRAFT", "PENDING", "APPROVED", "DENIED", "ACTIVE"
  deleteStatus: string;       // For deletion requests when status is "ACTIVE"
  clientId: string;           // Affected client (if applicable)

  // Who created this request
  requestedBy: string;        // User ID of the requester
  requestedByUsername: string; // Username of the requester

  // Review summary
  approvalCount: number;      // Number of approvals
  rejectionCount: number;     // Number of rejections
  approvedBy: string[];       // Usernames of approvers
  deniedBy: string[];         // Usernames of deniers
  commentCount: number;       // Number of comments

  // Affected records
  userRecord: [{
    username: string;
    clientId: string;
    proofDetailId: string;
    accessDraft: string;       // JSON string of the proposed access proof
  }];

  // Type-specific fields (extend RequestedChanges)
  role?: string;              // For role change requests
  compositeRole?: string;     // For composite role requests
  groupName?: string;         // For group change requests
  roleName?: string;          // For group-role mapping requests
  userName?: string;          // For group membership requests
}
```

---

## Actions

### Approve (Sign) Change Requests

```
POST /tide-admin/change-set/sign/batch
Content-Type: application/json

{
  "changeSets": [
    {
      "changeSetId": "draft-record-id",
      "changeSetType": "USER_ROLE",
      "actionType": "CREATE",
      "policyRoleId": "optional-role-uuid",
      "dynamicData": ["optional-base64-field"]
    }
  ]
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `changeSetId` | Yes | The `draftRecordId` of the change request |
| `changeSetType` | Yes | Type enum (see ChangeSetType Values below) |
| `actionType` | Yes | `"CREATE"` or `"DELETE"` |
| `policyRoleId` | No | Role ID whose policy to use. Omit to use the default `tide-realm-admin` policy. See [Choosing Which Policy](#choosing-which-policy-is-used-during-approval). |
| `dynamicData` | No | Ordered array of base64-encoded fields for custom Forseti contract input |

**Response (non-Tide mode):** `[]` — approval is recorded directly.

**Response (Tide multi-admin mode):**
```json
[
  {
    "changesetId": "draft-record-id",
    "requiresApprovalPopup": true,
    "changeSetDraftRequests": "base64-encoded-signing-challenge",
    "actionType": "CREATE",
    "changeSetType": "USER_ROLE"
  }
]
```

When `requiresApprovalPopup` is `true`, the client must:
1. Decode the `changeSetDraftRequests` (base64)
2. Present the signing challenge to the Tide enclave for the admin to sign
3. Submit the signed result via `POST /tideAdminResources/add-review`

### Submit Signed Review (Tide mode only)

```
POST /tideAdminResources/add-review
Content-Type: multipart/form-data

changeSetId=draft-record-id
changeSetType=USER_ROLE
actionType=CREATE
requests=base64-encoded-signed-response
```

### Reject Change Requests

```
POST /tideAdminResources/add-rejection
Content-Type: multipart/form-data

changeSetId=draft-record-id
actionType=CREATE
changeSetType=USER_ROLE
```

### Commit Approved Change Requests

Once a change request has enough approvals, commit it to apply the change:

```
POST /tide-admin/change-set/commit/batch
Content-Type: application/json

{
  "changeSets": [
    {
      "changeSetId": "draft-record-id",
      "changeSetType": "USER_ROLE",
      "actionType": "CREATE"
    }
  ]
}
```

### Cancel Change Requests

```
POST /tide-admin/change-set/cancel/batch
Content-Type: application/json

{
  "changeSets": [
    {
      "changeSetId": "draft-record-id",
      "changeSetType": "USER_ROLE",
      "actionType": "CREATE"
    }
  ]
}
```

---

## Activity and Comments

### Get activity for a change request

```
GET /tide-admin/change-set/{draftRecordId}/activity
```

**Response:**
```json
{
  "requestedBy": "user-id",
  "requestedByUsername": "admin",
  "timestamp": 1710500000,
  "approvals": [
    {
      "userId": "user-id",
      "username": "admin2",
      "isApproval": true,
      "timestamp": 1710500100
    }
  ],
  "comments": [
    {
      "id": "comment-uuid",
      "userId": "user-id",
      "username": "admin",
      "comment": "Looks good to me",
      "timestamp": 1710500200
    }
  ]
}
```

### Add a comment

```
POST /tide-admin/change-set/{draftRecordId}/comments
Content-Type: application/json

{
  "comment": "Looks good to me"
}
```

**Response:**
```json
{
  "id": "generated-uuid",
  "userId": "current-admin-id",
  "username": "admin",
  "comment": "Looks good to me",
  "timestamp": 1710500200
}
```

---

## Lookup Endpoints

### Check draft status for a specific user role assignment

```
GET /tide-admin/users/{userId}/roles/{roleId}/draft/status
```

**Response:**
```json
{
  "draftStatus": "PENDING",
  "deleteStatus": null
}
```

### Check draft status for a composite role relationship

```
GET /tide-admin/composite/{parentRoleId}/child/{childRoleId}/draft/status
```

### Get changeset request details by ID or type

```
GET /tide-admin/change-set/requests?id={changesetRequestId}
GET /tide-admin/change-set/requests?type={changeSetType}
```

### Get user context (access proof) for a user+client

```
GET /tide-admin/user-context/{userId}/{clientId}
```

---

## Policy Management

Policies in TideCloak control how roles are governed — who can approve access, what smart contract
logic runs, and how many admins must sign off. There are three layers:

1. **Forseti Contracts** — Reusable smart contract code (the logic)
2. **Policy Templates** — Named configurations that reference a contract with parameters
3. **Role Policies (SSH Policies)** — Attach a policy to a specific role

### How to attach a policy to a role

```
Step 1: Create a Forseti contract (or reuse an existing one)
   PUT /tide-admin/forseti-contracts

Step 2: (Optional) Create a policy template for reuse
   POST /tide-admin/policy-templates

Step 3: Attach the policy to a role
   PUT /tide-admin/ssh-policies

Step 4: (Optional) Initialize the role's signing certificate
   POST /tide-admin/role-policy/{roleId}/init-cert
```

### Forseti Contracts

Forseti contracts are smart contract code that defines approval logic.

**List contracts:**
```
GET /tide-admin/forseti-contracts
```

**Response:**
```json
[
  {
    "id": "contract-uuid",
    "contractHash": "SHA512-HEX-HASH",
    "contractCode": "function approve(context) { ... }",
    "name": "Two-admin approval",
    "timestamp": 1710500000
  }
]
```

**Create or update a contract:**
```
PUT /tide-admin/forseti-contracts
Content-Type: application/json

{
  "contractCode": "function approve(context) { return context.approvals >= 2; }",
  "name": "Two-admin approval"
}
```

**Response:**
```json
{
  "success": true,
  "id": "contract-uuid",
  "contractHash": "SHA512-HEX-HASH"
}
```

### Policy Templates

Templates are named, reusable policy configurations that reference a contract.

**List templates:**
```
GET /tide-admin/policy-templates
```

**Response:**
```json
[
  {
    "id": "template-uuid",
    "name": "Standard 2-of-3 approval",
    "description": "Requires 2 out of 3 admins to approve",
    "contractCode": "function approve(...) { ... }",
    "modelId": "model-id",
    "parameters": { "threshold": "2" },
    "timestamp": 1710500000
  }
]
```

**Create a template:**
```
POST /tide-admin/policy-templates
Content-Type: application/json

{
  "name": "Standard 2-of-3 approval",
  "description": "Requires 2 out of 3 admins to approve",
  "contractCode": "function approve(...) { ... }",
  "modelId": "optional-model-id",
  "parameters": { "threshold": "2" }
}
```

**Update a template:**
```
PUT /tide-admin/policy-templates/{id}
Content-Type: application/json

{
  "id": "template-uuid",
  "name": "Updated name",
  "description": "Updated description",
  "contractCode": "function approve(...) { ... }",
  "parameters": { "threshold": "3" }
}
```

**Delete a template:**
```
DELETE /tide-admin/policy-templates/{id}
```

### Role Policies (SSH Policies) — Attach policy to a role

This is how you actually bind a policy to a specific role. When a user requests
access to a role that has a policy attached, the policy logic governs the approval.

**List all role policies:**
```
GET /tide-admin/ssh-policies
```

**Response:**
```json
[
  {
    "id": "policy-uuid",
    "roleId": "role-uuid",
    "contractId": "contract-uuid",
    "contractHash": "SHA512-HEX-HASH",
    "contractName": "Two-admin approval",
    "contractCode": "function approve(...) { ... }",
    "approvalType": "explicit",
    "executionType": "private",
    "threshold": 2,
    "policyData": "{\"custom\": \"config\"}",
    "timestamp": 1710500000
  }
]
```

**Attach or update a policy on a role:**
```
PUT /tide-admin/ssh-policies
Content-Type: application/json

{
  "roleId": "role-uuid",
  "contractCode": "function approve(context) { return context.approvals >= 2; }",
  "approvalType": "explicit",
  "executionType": "private",
  "threshold": 2,
  "policyData": "{\"custom\": \"config\"}"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `roleId` | Yes | The Keycloak role ID to attach the policy to |
| `contractCode` | No | Smart contract code — auto-creates/reuses a Forseti contract by hash |
| `approvalType` | No | `"explicit"` (requires manual approval) or `"implicit"` (auto-approve). Default: `"implicit"` |
| `executionType` | No | `"private"` or `"public"`. Default: `"private"` |
| `threshold` | No | Number of approvals required. Default: `1` |
| `policyData` | No | Arbitrary JSON string for custom policy configuration |

**Response:**
```json
{
  "success": true,
  "id": "policy-uuid",
  "roleId": "role-uuid"
}
```

**Remove a policy from a role:**
```
DELETE /tide-admin/ssh-policies?roleId={roleId}
```

### List all roles that have policies (with signature status)

```
GET /tide-admin/role-policies
```

**Response:**
```json
[
  {
    "id": "role-draft-uuid",
    "roleId": "role-uuid",
    "roleName": "my-role",
    "clientRole": true,
    "clientId": "my-client",
    "timestamp": 1710500000,
    "hasSig": true,
    "policyDisplay": "serialized-policy-details"
  }
]
```

### Initialize role signing certificate

After attaching a policy, you may need to initialize the role's signing certificate
for the Tide enclave to recognize it:

```
POST /tide-admin/role-policy/{roleId}/init-cert
Content-Type: application/json

{
  "initCert": "base64-encoded-certificate"
}
```

### Realm Policy

A realm-level policy that applies globally. Follows the change request workflow
(create pending → approve → commit).

```
GET  /tide-admin/realm-policy                    ← Get current status
POST /tide-admin/realm-policy/pending            ← Create pending policy
POST /tide-admin/realm-policy/commit             ← Commit pending → active
POST /tide-admin/realm-policy/request-delete     ← Request deletion
POST /tide-admin/realm-policy/commit-delete      ← Commit deletion
DELETE /tide-admin/realm-policy                  ← Delete directly
```

**Create pending realm policy:**
```
POST /tide-admin/realm-policy/pending
Content-Type: application/json

{
  "templateId": "template-uuid",
  "contractCode": "function approve(...) { ... }",
  "paramValues": { "threshold": "2" }
}
```

**Response:**
```json
{
  "success": true,
  "id": "realm-policy-uuid",
  "changesetRequestId": "changeset-uuid",
  "requestModel": "serialized-model",
  "templateName": "Template Name",
  "contractId": "contract-uuid"
}
```

The pending realm policy then goes through the standard change request workflow
(approve → commit) before becoming active.

---

## Choosing Which Policy Is Used During Approval

By default, every change request is signed using the **tide-realm-admin** role's policy.
To use a role-specific policy instead, pass `policyRoleId` in the sign request.

### How it works

When you call the sign (approve) endpoint, the system resolves the policy like this:

```
1. If policyRoleId is provided in the ChangeSetRequest → use that role's policy
2. If policyRoleId is null/blank → fall back to the tide-realm-admin role's policy
```

The "policy" is the `initCert` stored on the `TideRoleDraftEntity` for that role,
which contains the cryptographic policy object used by the Tide enclave.

### Signing with a role-specific policy

Pass `policyRoleId` in your sign request:

```
POST /tide-admin/change-set/sign/batch
Content-Type: application/json

{
  "changeSets": [
    {
      "changeSetId": "draft-record-id",
      "changeSetType": "USER_ROLE",
      "actionType": "CREATE",
      "policyRoleId": "role-uuid-with-custom-policy"
    }
  ]
}
```

The `policyRoleId` should be the ID of a role that has:
1. An SSH policy attached (`PUT /tide-admin/ssh-policies`)
2. An initialized signing certificate (`POST /tide-admin/role-policy/{roleId}/init-cert`)

### Dynamic data for custom contracts

If your Forseti contract expects custom input data, pass it via `dynamicData`:

```json
{
  "changeSets": [
    {
      "changeSetId": "draft-record-id",
      "changeSetType": "USER_ROLE",
      "actionType": "CREATE",
      "policyRoleId": "role-uuid",
      "dynamicData": ["field1-base64", "field2-base64"]
    }
  ]
}
```

The `dynamicData` array is an ordered list of base64-encoded fields that are packed
into raw bytes and passed to the Forseti contract. The contract reads these fields
using `TryReadField()` in order.

### Full end-to-end example: Custom policy on a role

```
# 1. Create a Forseti contract with custom approval logic
PUT /tide-admin/forseti-contracts
{ "contractCode": "function approve(ctx) { ... }", "name": "My Policy" }

# 2. Attach the policy to a role
PUT /tide-admin/ssh-policies
{
  "roleId": "role-uuid",
  "contractCode": "function approve(ctx) { ... }",
  "approvalType": "explicit",
  "threshold": 2
}

# 3. Initialize the role's signing certificate (from Tide enclave)
POST /tide-admin/role-policy/role-uuid/init-cert
{ "initCert": "base64-policy-certificate" }

# 4. Now when approving a change request, specify this role's policy
POST /tide-admin/change-set/sign/batch
{
  "changeSets": [{
    "changeSetId": "draft-id",
    "changeSetType": "USER_ROLE",
    "actionType": "CREATE",
    "policyRoleId": "role-uuid"
  }]
}

# → The enclave uses role-uuid's policy instead of tide-realm-admin
# → requiresApprovalPopup: true means the admin must sign via enclave
# → Submit the signed result via POST /tideAdminResources/add-review
```

### FirstAdmin vs MultiAdmin

The signing behavior depends on how the realm's authorizer is configured:

| Authorizer | `requiresApprovalPopup` | Behavior |
|------------|------------------------|----------|
| **MultiAdmin** | `true` | Requires enclave signing. Returns a challenge that the admin must sign. The policyRoleId determines which policy the enclave enforces. |
| **FirstAdmin** | `false` | Signs immediately with VRK. No enclave popup needed. Used during initial setup before multi-admin is configured. |

---

## ChangeSetType Values

| Value | Description |
|-------|-------------|
| `USER_ROLE` | User-to-role assignment |
| `ROLE` | Role creation/deletion |
| `COMPOSITE_ROLE` | Composite role relationship |
| `CLIENT` | Client changes (full scope, etc.) |
| `GROUP_ROLE` | Group-to-role mapping |
| `GROUP_MEMBERSHIP` | User-to-group membership |
| `GROUP_MOVE` | Group parent change |
| `REALM_LICENSE` | Realm licensing |
| `POLICY` | Realm policy |

## ActionType Values

| Value | Description |
|-------|-------------|
| `CREATE` | Creating/adding something |
| `DELETE` | Removing/deleting something |

## Status Values

| Value | Description |
|-------|-------------|
| `DRAFT` | Just created, not yet submitted for review |
| `PENDING` | Submitted, awaiting approval |
| `APPROVED` | Approved, ready to commit |
| `DENIED` | Rejected by an admin |
| `ACTIVE` | Already committed (check `deleteStatus` for pending deletions) |

---

## Authentication

All endpoints require a valid admin access token:

```
Authorization: Bearer {admin-access-token}
```

Obtain a token via the Keycloak token endpoint:

```
POST {keycloak-url}/realms/{realm}/protocol/openid-connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=password&client_id=admin-cli&username={admin}&password={password}
```

Or use a service account with appropriate roles.

---

## TypeScript Client

If building with TypeScript, you can use the `@keycloak/keycloak-admin-client` package which has typed methods for all endpoints:

```typescript
import KcAdminClient from "@keycloak/keycloak-admin-client";

const client = new KcAdminClient({ baseUrl: "http://localhost:8080" });
await client.auth({ username: "admin", password: "admin", grantType: "password", clientId: "admin-cli" });

// Get counts
const counts = await client.tideUsersExt.getChangeSetCounts();

// Get all requests
const all = await client.tideUsersExt.getAllChangeSetRequests();

// Approve
await client.tideUsersExt.approveDraftChangeSet({
  changeSets: [{ changeSetId: "id", changeSetType: "USER_ROLE", actionType: "CREATE" }]
});

// Commit
await client.tideUsersExt.commitDraftChangeSet({
  changeSets: [{ changeSetId: "id", changeSetType: "USER_ROLE", actionType: "CREATE" }]
});

// Cancel
await client.tideUsersExt.cancelDraftChangeSet({
  changeSets: [{ changeSetId: "id", changeSetType: "USER_ROLE", actionType: "CREATE" }]
});

// Reject
await client.tideAdmin.addRejection(formData);

// Get activity
const activity = await client.tideUsersExt.getChangeSetActivity({ id: "draft-id" });

// Add comment
await client.tideUsersExt.addChangeSetComment({ id: "draft-id", comment: "LGTM" });
```
