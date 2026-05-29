# IGA → TokenValidationEngine Producer — Design

**Status:** Draft for approval (Phase 2). No code written yet.
**Owner module:** `tidecloak-iga-extensions / iga-core`
**Consumer:** ork `TokenValidationEngine`
**Date:** 2026-05-27

---

## 1. Goal

Let IGA emit, for a `(realm, client, user, scope)`, the **attestation-unit envelopes** the
ork `TokenValidationEngine` (TVE) consumes, alongside a **real issued token** and its
**`TokenRequest`** — so a token can be validated against current attested realm state.

This is the *forward* direction of the TVE's own unbuilt `RealmExportAdapter`
(`Ork.Tests/.../GoldenFixture.cs:111-121`, `IsImplemented => false`), whose comment already
names it: *"mirrors, in reverse, the IGA producer that emits envelopes from the live DB."*
It is also the build-side half of the **Tide-network login-row** feature (bundle current
attested state at token-issue).

### End-to-end flow

```
(realm, client, user, scope)
        │
        ├─[A] RealmAttestationExporter (iga-core, Java)  ── List<byte[]> envelopes (JSON)
        │
        └─[B] OIDC token endpoint  ── access/ID token (JWT)  +  TokenRequest{TokenType,ClientId,Scope,RequestedAudience}
                                                │
                            ┌───────────────────┘
                            ▼
        ork: foreach env → AttestationUnitFactory.Create(bytes) → engine.AddAttestedData(unit)
             engine.Validate(token, tokenRequest) → (true,null) | (false, ATTESTATION_INVALID)
```

---

## 2. Key finding — consumption needs ordinary JSON, not JCS, not signatures

This de-risks the whole producer:

- `AttestationUnitFactory.Create(bytes)` does `JsonDocument.Parse` and reads every field
  **by name** — any key order / whitespace is fine (`AttestationUnit.cs:132, 269-329`).
- The C# side **re-derives** the canonical (RFC-8785/JCS) form internally; that form is only
  consumed by `ComputeCanonicalHash`/`CanonicalJson`, which **`Validate` never calls**. The
  engine **trusts the parsed shape and verifies no signature**.
- The reference test producer proves it: `EnvelopeBuilder.ToBytes()` emits plain
  `JsonObject.ToJsonString()` (un-canonicalized) straight into the real factory
  (`EnvelopeBuilder.cs:80-91`).

**Consequence:** the Java producer emits ordinary Jackson JSON with the right fields/values.
**No RFC-8785, no SHA-256, no `sign()`, no JNA on the envelope path.** JCS/signatures matter
*only* when a future Tide-mode adds real signature verification (see §9 Non-goals).

---

## 3. The producer

**Home:** new package `org.tidecloak.iga.producer` in `iga-core`, beside `attestors` / `services`
/ `replay`. Depends only on already-in-module `attestors.TideSetResolver` and
`services.IgaUnsignedRowScanner` — no new cross-module dependency.

**Interface:**

```java
public final class RealmAttestationExporter {
    /** Emit the closure of attestation-unit envelopes for the given request as plain JSON. */
    public List<byte[]> export(KeycloakSession session, RealmModel realm, ExportRequest req);
}

// what we capture that the token can't tell us (mirrors TVE TokenRequest)
public record ExportRequest(String clientId, String userId, String scope /*, TokenType, requestedAudience */) {}
```

Per unit it builds an envelope POJO and serializes with Jackson
`ObjectMapper.writeValueAsBytes(...)`. (Optional `SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS`
for stable fixture diffs — a convenience, not a requirement.)

---

## 4. Envelope contract (what the producer must emit)

### 4.0 Wire encoding — CBOR by default, JSON on opt-in

The bundle is serialized as **CBOR by default**. JSON is emitted only when the client opts in
with `Accept: application/json`.

- Default (`Accept: application/cbor`, `*/*`, missing, anything else) → `Content-Type:
  application/cbor`, body is raw CBOR bytes.
- `Accept: application/json` → `Content-Type: application/json`, body is pretty-printed JSON
  (byte-identical to the prior JSON-only implementation).

CBOR uses Jackson's default encoding (`new ObjectMapper(new CBORFactory())`): map keys as
CBOR text strings, ints as CBOR uints, etc. — so the ork side decodes cleanly with C#
`System.Formats.Cbor`. The bundle data structure (top-level keys `realm_id`, `schema_version`,
`request{t,c,s,aud}`, `token`, `units[{u,t,p}]`) is unchanged; only the encoding differs.

**No gzip.** Bundles are not compressed at the transport or application layer. If a future
profile wants compression, it goes via HTTP `Content-Encoding` (transport-level), not via the
application format. This keeps the producer/consumer wire shape deterministic and avoids a
second framing layer on top of CBOR.

### 4.1 Envelope shape (within the bundle)

Each envelope is an object with **exactly 5 top-level keys** (`AttestationUnit.cs:143-162`):

| Key | Rule |
|---|---|
| `unit_type` | one of the 18 wire strings (snake_case, **case-sensitive**); must match the unit |
| `schema_version` | integer, **exactly `1`** |
| `realm_id` | string, **byte-identical to `payload.realm_id`** |
| `target_id` | string, **equals the unit's payload primary key** |
| `payload` | object (see §5) |

**The 18 `unit_type` strings:** `realm_config`, `client_config`, `client_scope_config`,
`protocol_mapper`, `role_definition`, `group_definition`, `user_identity`,
`user_role_mapping_set`, `user_group_membership_set`, `group_role_mapping_set`,
`role_composite_children_set`, `client_scope_assignment_set`, `client_mapper_set`,
`client_scope_mapper_set`, `scope_role_allowlist_set`, `realm_default_groups_set`,
`organization_definition`, `organization_domain_set`.

**Hard parse rules (reject regardless of canonicalization):**
- **Every declared field MUST be present.** Optional values are sent as explicit JSON `null`,
  **never omitted** (e.g. `user_identity.email`/`first_name`/`last_name`).
- Booleans as JSON `true`/`false` (not strings); ints as JSON numbers (Int32).
- Enums case-sensitive: `parent_type ∈ {client, client_scope}`, group `type ∈ {REALM, ORGANIZATION}`.
- Top-level `group_definition.parent_group_id` of a root group **must be `null`**.
- Arrays may be emitted in any order (the C# parser sorts them on ingest).

The full per-unit payload field list is in §5; `EnvelopeBuilder.cs:118-270` (`UnitPresets`) is a
field-for-field valid example of all 18 the Java side can mirror.

---

## 5. Per-unit source mapping (the producer's read plan)

`target_id` and payload schemas are authoritative from ork (`AttestationUnits/*.cs`). Sources and
owners are from iga-core. **IGA-attested?** = does a per-row/per-set `ATTESTATION` column exist to
confirm "committed".

### Node units

| Unit | target_id | KC/JPA source | IGA-attested? |
|---|---|---|---|
| `realm_config` | realm_id | `RealmModel` config + `RealmAttributeEntity` | via attribute rows (`RealmAttributeEntity.attestation`); no single realm-row column |
| `client_config` | client UUID | `realm.getClientByClientId` → `ClientModel` + `ClientAttributeEntity` | yes (`ClientEntity.attestation`) |
| `client_scope_config` | scope id | `clientScopes().getClientScopeById` + attrs | yes (`ClientScopeEntity.attestation`) |
| `protocol_mapper` | mapper id | `ProtocolMapperEntity` (full `config` map) | yes (`ProtocolMapperEntity.attestation`) |
| `role_definition` | role id | `roles().getRoleById` → `RoleModel.getAttributes` | yes (`RoleEntity.attestation`) |
| `group_definition` | group id | `groups().getGroupById` → `GroupModel` (type=0) + attrs | yes (`GroupEntity.attestation`) |
| `user_identity` | user id | `users().getUserById` → `UserModel` + attrs | yes (`UserEntity.attestation`; federated via `FED_USER_ATTRIBUTE.attestation`) |
| `organization_definition` | org id | `OrganizationProvider.getById` → `OrganizationModel` | yes (`OrganizationEntity.attestation`, ORG.ATTESTATION, iga-changelog-2.4.0); wiring it into the producer payload is follow-up (§9) |

### Set units — enumerate via `TideSetResolver.Linkage.selectMembersJpql()` per owner

| Unit | owner | TideSetResolver linkage / source | IGA-attested? |
|---|---|---|---|
| `user_role_mapping_set` | user | `UserRoleMappingEntity` (owner user, member roleId) | yes |
| `user_group_membership_set` | user | `UserGroupMembershipEntity` | yes |
| `group_role_mapping_set` | group | `GroupRoleMappingEntity` | yes |
| `role_composite_children_set` | parent role | `CompositeRoleEntity` (emit `[]` for non-composite) | yes |
| `client_scope_assignment_set` | client | `ClientScopeClientMappingEntity` (`{client_scope_id, default}`; `service_account` NOT listed) | yes |
| `client_mapper_set` | client | `ProtocolMapperEntity` owned by client | yes |
| `client_scope_mapper_set` | client_scope | `ProtocolMapperEntity` owned by scope | yes |
| `scope_role_allowlist_set` | client **or** client_scope | `ScopeMappingEntity` (parent_type=client) **and** `client_scope_role_mapping` (parent_type=client_scope) — **both fold into this one unit via `parent_type`** | yes |
| `realm_default_groups_set` | realm | KC realm default groups | **no dedicated set in IGA**; rarely needed for steady-state issuance (§9) |

`TideSetResolver.linkageFor(...)` already encodes table/owner/member/rowKeys; the producer reuses
it instead of re-deriving. Protocol-mapper owner duality is handled by
`IgaReplayExtension.resolveProtocolMapperOwner`.

---

## 6. Reuse (don't re-derive the realm walk)

- **`services/IgaUnsignedRowScanner.java`** — realm-scoped JPQL projections for **every** node and
  set/edge table. Invert its `attestation IS NULL` filter (→ `IS NOT NULL`, or read the value) to
  enumerate attested rows. Best single reuse target; also the authoritative inventory of which
  tables carry an `ATTESTATION` column.
- **`services/IgaAdoptScan.java:196`** — canonical deterministic whole-realm walk
  (USER→ROLE→GROUP→CLIENT→CLIENT_SCOPE→ORG→edges), including the required
  `session.getContext().setRealm(realm)` binding and the `JpaConnectionProvider` EntityManager
  idiom.
- **`services/IgaSystemEntityFilter.java`** — `shouldSkip`/`shouldSkipEdge` to omit built-ins
  (the engine fixtures generally should skip built-in clients/scopes/roles, matching its
  `AcceptedGaps`).
- EntityManager: `session.getProvider(JpaConnectionProvider.class).getEntityManager()`.

---

## 7. Live model vs attested rows

Read the **live KC model** as current truth; IGA's invariant is *current attested state == latest
committed*, so a row's live value **is** its attested value iff its `ATTESTATION` column is
**non-null**. The producer therefore:

1. walks live entities (model API or scanner JPQL), and
2. uses `attestation IS NOT NULL` as the "governed/committed" discriminator if it needs to assert
   attested status (the engine itself doesn't check this today, so this matters only for the
   trust-loop/fixture-honesty story).

---

## 8. Token + TokenRequest capture

`TokenRequest(TokenType ∈ {AccessToken, IdToken}, ClientId, Scope, RequestedAudience?)` — none of
these four is reliably recoverable from the token (`ClientId` is taken from the *request*, not the
token's `azp`; `Scope` is the raw requested param; `RequestedAudience` null/empty ⇒ no aud prune).

There is **no clean in-process mint API** from iga-core (`DefaultTokenManager.encode` needs a full
protocol request context). The proven path is the **realm's OIDC token endpoint**:

- user token: ROPC/`password` grant against the realm client (e2e `kc.ts:697/1129`);
- admin token: master `admin-cli` password grant (`kc.ts:15`);
- M2M: `client_credentials` grant.

**DECIDED (2026-05-27): token capture is on the IGA side.** The producer itself obtains the token
by calling the realm's OIDC token endpoint over **HTTP** (not the internal mint API) and captures
the four `TokenRequest` fields (they are just the grant parameters it issues). The producer then
emits a single **bundle** carrying `{envelopes + token + TokenRequest}` and hands it to the ork.
The harness is not in the loop for capture.

Fixture note: a scratch realm defaults to RS256; the captured token's `alg` depends on realm config
(the EdDSA/Tide M2M path has caveats). This is fixture content, not a build coupling.

---

## 9. Minimal vs full unit set, and the closure rule

**Always required (engine throws via `.Single()`/lookup if absent):** `realm_config`,
`client_config` (matching the request's ClientId), `client_scope_assignment_set`, `user_identity`.
Plus a `client_scope_config` for **every** scope named in the assignment set (a referenced-but-absent
scope config throws).

**Conditional — emit the *exact closure* of what the token's claims require, no more, no less:**
- `protocol_mapper` for every id in the resolved client/scope mapper sets;
- `client_mapper_set` / `client_scope_mapper_set` when the client/scope has mappers;
- role/group units (`role_definition`, `user_role_mapping_set`, `role_composite_children_set`,
  `group_definition`, `user_group_membership_set`, `group_role_mapping_set`,
  `scope_role_allowlist_set`) when the token carries role/group claims;
- org units when an `organization` claim or org scope is in play;
- `realm_default_groups_set` only for mid-issuance user-creation flows (not steady-state).

Why exact: a token claim with **no attested source** is rejected, and an **attested non-null claim
suppressed in the token** is rejected (`TokenValidationEngine.cs:301-303, 315-318`). The producer
should build the closure by walking from the requesting client + active scopes + the user's
effective roles/groups — the same graph the engine walks forward.

---

## 10. Gaps, non-goals, open decisions

**Gaps / non-goals (call out honestly):**
- **Organizations are now IGA-attested** (`OrganizationEntity` carries an `ATTESTATION` column as of
  iga-changelog-2.4.0; the org is a first-class node, stamped per-entity on
  CREATE/UPDATE/ADOPT_ORGANIZATION). The producer can emit a consumable `organization_definition`;
  closing it into the trust loop (deriving the org node's attestation into the producer payload) is
  follow-up producer work, not yet wired. `organization_domain_set` is out of TVE scope anyway
  (domains are covered by the org-node attestation, no separate domain set).
- **`realm_default_groups_set`** has no dedicated IGA attestation set; only needed for mid-issuance
  user-creation, not steady-state token validation.
- **Signatures / JCS are deferred.** This design covers *consumption* only. Closing the cross-network
  trust loop (real signatures the verifier checks) waits on Midgard `signClaims()` and a coordinated
  JCS byte-for-byte agreement between the Java producer and the C# verifier — out of scope here.
- **Federated users** (`FED_USER_*`) are a secondary path; first cut targets local users.

**Decisions (locked 2026-05-27):**
1. **Token capture = IGA side.** The producer fetches the token via the OIDC endpoint and ships it
   in the bundle (see §8 and the Bundle format below).
2. **Skip built-ins by default** via `IgaSystemEntityFilter` (matches the engine's `AcceptedGaps`),
   with an opt-in include-system flag.
3. **Output = one compact bundle** (see Bundle format below), with a matching deserializer added on
   the ork side.
4. **First milestone = role-only** token (4-unit floor + role units) to prove the loop green, then
   expand.

**Remaining open fork — transport (how the bundle reaches the ork):**
- (A) **Offline bundle for M1** — producer emits the bundle as bytes/file; the ork side gets a
  deserializer + a test/CLI entry that feeds it to `Validate`. Proves produce→serialize→deserialize
  →validate green with the least moving parts. *(Recommended for role-only M1.)*
- (B) **Live ork endpoint** — a new ork HTTP endpoint receives the bundle, deserializes, runs
  `Validate`, returns the verdict; the IGA producer POSTs to it.
- (C) **Via Midgard JNA** — the eventual Tide-network login-row path (IGA → Midgard → ork). Heaviest;
  premature for M1.

### Bundle format (the agreed interface — to be finalized by the PMs)

One self-describing container, kept small by **hoisting fields shared across all units**:

```jsonc
{
  "realm_id": "...",            // hoisted: every unit shares it
  "schema_version": 1,          // hoisted: always 1
  "request": { "t": "access|id", "c": "<clientId>", "s": "<raw scope>", "aud": ["..."] | null },
  "token": "<compact JWS>",
  "units": [
    { "u": "user_role_mapping_set", "t": "<target_id>", "p": { /* payload, sans realm_id */ } },
    ...
  ]
}
```

The ork deserializer re-expands each unit to the full 5-key envelope
(`{unit_type, schema_version, realm_id, target_id, payload}`) before `AttestationUnitFactory.Create`
— re-injecting the hoisted `realm_id`/`schema_version` and `payload.realm_id`. Bundle MAY be gzipped
on the wire. Exact key names/compaction (and whether to gzip) are for the PMs to pin when they agree
the interface, but the hoist-shared-fields shape is the intent of "serialize in a nice small way."

---

## 11. Suggested phasing (for the eventual implementation, post-approval)

1. **M1 — role-only:** `export()` emits the 4 required units + `client_scope_config` for assigned
   scopes + the role units (`role_definition`, `user_role_mapping_set`, `role_composite_children_set`,
   `scope_role_allowlist_set`) + the `protocol_mapper`s that emit `realm_access`/`resource_access`;
   producer fetches a real token (IGA side) for a user with roles; ship the compact bundle; add the
   ork-side deserializer; validate green end-to-end (transport option A). Built-ins skipped.
2. **M2 — mappers + groups:** add group units + `groups`/attribute/audience mappers; broaden claim
   coverage.
3. **M3 — live transport:** wire transport option B (ork endpoint) so the bundle is sent over the
   wire, not just deserialized in-test; this also unblocks `GoldenFixture`.
4. **M4 — edges:** org units (consumable, un-attested), default-groups, federated users — as needed.

---

## Source map

- **ork (consumer / schemas):** `Ork/Ork/Models/TideRequests/Authorization/TidecloakToken/`
  — `TokenValidationEngine.cs` (engine, `TokenRequest` `:45-47`), `AttestationUnit.cs`
  (envelope/factory `:143-162, :478`), `AttestationUnits/*.cs` (18 payload schemas);
  `Ork.Tests/SigningModels/Authorization/TokenValidation/` — `GoldenFixture.cs` (`RealmExportAdapter`
  `:111-121`), `EnvelopeBuilder.cs` (`UnitPresets` `:118-270`), `Scenario.cs`, `TEST-DATA-CONTRACT.md`.
- **iga-extensions (producer):** `iga-core/.../attestors/TideSetResolver.java` (set linkages),
  `services/IgaUnsignedRowScanner.java` (per-table JPQL + attestation inventory),
  `services/IgaAdoptScan.java` (realm walk), `services/IgaSystemEntityFilter.java` (built-in skip),
  `replay/IgaReplayExtension.java` (`resolveProtocolMapperOwner`, set-sign enumeration).
- **tidecloak-override:** the `ATTESTATION` column definitions; token issuance (`DefaultTokenManager`).
