# RealmAttestationExporter — gap analysis (for test authoring)

**Target:** `iga-core/src/main/java/org/tidecloak/iga/producer/RealmAttestationExporter.java`
**Date:** 2026-06-12
**Method:** cross-read the exporter against `attestation-units.md` (the 18-unit spec + the
"Verification — graph walk at token-issuance time" pseudocode) and the
`keycloak-token-construction` skill (scope resolution, mapper execution, role/audience).

The exporter's own stated contract (file header, lines 54–94) is **EXACT closure**: the ORK
TVE *"rejects any claim with no attested source AND any attested-but-suppressed claim. So the
producer must emit precisely the closure the requested `(client, user, scope)` would issue —
no more, no less."*

That makes **two** failure classes, not one:

- **Under-emission** — a node/edge a real token claim needs is missing → ORK has "no attested
  source" → reject. *(This is the class the latest commit `c63d6bb` fixed.)*
- **Over-emission** — a unit is emitted/attested implying a claim the token does **not** carry →
  ORK sees "attested-but-suppressed" → reject. *(Easy to overlook because "emit more = safer"
  is the wrong intuition here.)*

The reference fix (`c63d6bb`, "fix for groups") is the template for the headline finding:
`perUserUnits` emitted the **membership** edge (`user ∈ admins`, unit 9) and the role
**composition** (unit 11) but not the group→role **binding** edge (`admins → realm-admin`,
unit 10). The token's `aud`/`resource_access` collapsed because the ORK could never bind the
group's role to the user. The fix (lines 241–255) added `group_role_mapping_set` for the
user's plain realm groups **and their ancestors**.

Each finding below is written as: **claim → why → spec/skill anchor → test design
(setup / expected / current) → confidence + falsifier.**

---

## F1 (HIGH) — `group_definition` (unit 6) is never emitted at login for the user's plain (non-org) groups or their ancestors

> **STATUS: FIXED (2026-06-12).** `export()` now emits `group_definition` (unit 6) for every
> plain realm group the user is in **and every ancestor** on its parent chain, in the same
> dedup'd ancestor walk that emits `group_role_mapping_set` (now keyed on
> `walkedPlainGroupIds`). The node is emitted UNCONDITIONALLY (its `GroupEntity.attestation`
> column always exists and is stamped for every group by the toggle-on convergence /
> `ADOPT_GROUP` / `CREATE_GROUP` paths — verified in `TideAttestor`). The test below should now
> assert **presence** (green-bar), not absence.

### Claim
`export()` emits, for the user's plain realm groups, the **membership** (unit 9, via
`perUserUnits`) and now the **binding edges** (unit 10, lines 247–255, incl. ancestors) — but
**not** `group_definition` (unit 6) for those groups. `group_definition` is emitted at login
**only** for `ORGANIZATION`-type backing groups (`emitOrganizationClosure`, line 736). It *is*
emitted for every group by the **convergence** path (`exportRealmMetadata`, lines 549–552), so
the DB column gets stamped — but the **login bundle** never contains it.

### Why this is a gap (two independent triggers)
1. **Ancestor role inheritance (universal — bites with no group mapper at all).** The
   `metadataRoleSeed` comment (lines 909–919) states the ORK enumerates group roles
   *ancestor-inclusively*: *"MapperContext.GrantedRoles → GroupAndAncestors walks
   `parent_group_id` until a top-level group."* `parent_group_id` is a field of
   `group_definition` (unit 6 / spec §6). The fix emits `group_role_mapping_set` for ancestor
   groups (line 252), but the ORK can only *reach* those ancestors by walking
   `group_definition(child).parent_group_id → group_definition(parent).parent_group_id → …`.
   With no `group_definition` in the bundle and only the **direct** group in
   `user_group_membership_set`, the emitted ancestor `group_role_mapping_set` units are
   **orphaned** — the ORK has the edges but no path from the user to them. Result: ancestor
   group roles under-report → the *exact* "collapsing aud" symptom the commit fixed, one level
   up.
2. **`groups` claim (when an `oidc-group-membership-mapper` is configured).** That mapper emits
   the slash-path built by walking `parent_group_id` (spec §6 justification). Its attested
   source is `group_definition` for the user's groups + ancestors. Absent at login → `groups`
   claim has "no attested source" → reject.

This is the **same shape** as `c63d6bb`: the commit added the ancestor *edge* walk but not the
ancestor *node* (`group_definition`) walk, nor did it add ancestors to the membership set. The
org path (`emitOrganizationClosure`) shows the intended pattern — it emits `group_definition`
**and** `group_role_mapping_set` together (lines 736–739). The plain-group path emits only the
latter.

### Spec/skill anchor
- `attestation-units.md` graph walk lines 659–676: for **every** group in
  `user_group_membership_set`, the walk visits `group_definition(G)` **and**
  `group_role_mapping_set(G)`, then pushes `parent_group_id` back onto `groups_to_walk`.
- `attestation-units.md` §6 (`parent_group_id` is the ancestor-role + path driver).

### Test design
Unit test (Mockito, mirror `RealmAttestationExporterMetadataSeedTest` /
`PerUserUnitsDefaultRoleExclusionTest`):
- **Setup:** realm with group `parent` (role `r-parent` via GROUP_ROLE_MAPPING) and child
  `child` (parent = `parent`, role `r-child`). User U is a **direct** member of `child` only.
  Mock `user.getGroupsStream() → [child]`, `child.getParent() → parent`,
  `parent.getParent() → null`, both non-`ORGANIZATION`.
- **Expected (per spec, and post-fix):** emitted units include `group_definition(child)` **and**
  `group_definition(parent)` (plus `group_role_mapping_set(child)`,
  `group_role_mapping_set(parent)`, `user_group_membership_set(U)=[child]`).
- **Regression guard:** assert a `GroupDefinitionUnit` is present for **both** `child` and
  `parent` (the fix walks the full ancestor chain, not just the direct group). Also assert org
  backing groups are **not** double-emitted here (they come from `emitOrganizationClosure`).
- **End-to-end (ground truth):** QA replay — user in a nested group whose **parent** carries a
  role that lands in `aud`/`resource_access`; confirm the ORK rejects / drops the inherited
  role pre-fix.

### Confidence / falsifier
**HIGH** that the asymmetry exists (structural, directly readable). The *consequence* (ORK
reject) is falsified only if the ORK derives the parent chain without `group_definition` AND no
`groups` mapper is in play — but the in-repo `metadataRoleSeed` comment asserts the ORK *does*
walk `parent_group_id`, which lives on `group_definition`. The e2e replay settles it.

---

## F2 (MEDIUM) — `web_origins` `+` wildcard is resolved against the *request* context, so commit-time and login-time bytes can diverge

### Claim
`clientConfig` (lines 1041–1043) resolves the `+` wildcard via
`WebOriginsUtils.resolveValidWebOrigins(session, client)`, which calls
`RedirectUtils.resolveValidRedirects`, which resolves **relative** redirect URIs against
`session.getContext().getUri()` (the current request URI;
`tidecloak/.../RedirectUtils.java:74`). The signature is verified over the **literal** emitted
bytes (no re-canonicalization). The commit/convergence stamp and the login emit run in
**different request contexts**, so a client with a relative redirect URI (or a deployment whose
frontend/host URL differs between the admin action and the user auth) can resolve `web_origins`
to **different** absolute origins at the two times → byte divergence → "Attested unit signature
validation failed" on `client_config`.

### Why this is a gap
The exporter deliberately sorts/normalizes everything else for byte-stability across sessions,
but `web_origins` resolution is **request-context-dependent**, which the per-session
normalization can't fix. Absolute redirect URIs resolve identically (no gap); relative ones
don't.

### Spec/skill anchor
- `attestation-units.md` §2: `web_origins` is read by `AllowedWebOriginsProtocolMapper` →
  `allowed-origins` claim.
- Exporter's own byte-identity doctrine (lines 1022–1040): the attested value must equal the
  token's resolved `allowed-origins`.

### Test design
- **Setup:** client with `web_origins=["+"]` and a **relative** redirect URI (e.g. `/app/*`).
  Resolve `clientConfig(...)` twice under two mocked `KeycloakUriInfo` base URIs (simulating
  admin-context vs auth-context) and `serialize()` both.
- **Expected:** identical bytes. **Current (predicted):** divergent `web_origins` arrays.
- Add a control with an **absolute** redirect URI → bytes must match (proves the trigger is
  relative-URI resolution, not the wildcard per se).

### Confidence / falsifier
**MEDIUM.** Falsified if all clients in the deployment use absolute redirect URIs and a fixed
`frontendUrl` (then resolution is context-free). Worth a guard test regardless.

---

## F3 (MEDIUM) — Default client scopes are emitted without applying `isClientScopePermittedForUser` (`isAllowed`) — over-emission

### Claim
`collectAssignedScopes` (lines 1432–1442) and `resolveActiveScopes` (lines 1186–1199) take
`client.getClientScopes(true/false)` directly and never apply the `isAllowed` /
`isClientScopePermittedForUser` filter. A **default** scope carrying a scope→role mapping the
user does **not** hold is filtered out of the real token (its mappers don't run), but the
exporter still emits its `client_scope_config` + `client_scope_mapper_set` + `protocol_mapper`
units and lists it as active.

### Why this is a gap
Per the EXACT-closure contract, an attested mapper whose claim is absent from the token is an
"attested-but-suppressed" claim → ORK reject. Most stock default scopes (`profile`, `email`,
`roles`, `web-origins`, `basic`, `acr`) have **no** scope→role mappings, so `isAllowed` is
universally true and the gap is dormant — but a realm that role-restricts a *default* scope
trips it.

### Spec/skill anchor
- `scope-resolution.md` STEP 2 (`isAllowed` → `isClientScopePermittedForUser`, DCSC.L252–300):
  scopes with role mappings are filtered by `roles ∩ getDeepUserRoleMappings(user)`.

### Test design
- **Setup:** custom **default** scope `restricted-default` with a scope→role mapping to role
  `R`; user U does **not** hold `R`. Mock `client.getClientScopes(true)` to include it.
- **Expected (per real KC):** `restricted-default`'s mapper units NOT emitted (scope filtered).
- **Current (predicted):** they ARE emitted. Assert presence to red-bar.

### Confidence / falsifier
**MEDIUM.** Falsified if the ORK independently recomputes `isAllowed` and ignores extra emitted
mapper-sets (then it's harmless over-emission). Resolve via ORK-contract check or e2e.

---

## F4 (MEDIUM) — `client_config` / `client_scope_config` emit the **full** attribute map, not the spec's token-affecting allow-list

### Claim
`clientConfig` (line 1053) and `clientScopeConfig` (line 1061) pass
`attributeNameValues(client.getAttributes())` / `scope.getAttributes()` — the **entire**
`CLIENT_ATTRIBUTES` / `CLIENT_SCOPE_ATTRIBUTES` map. The spec (§2, §3) prescribes a **filtered
allow-list** (e.g. `client.use.lightweight.access.token.enabled`,
`client_credentials.use_refresh_token`, `access.token.lifespan`,
`use.lower.case.in.token.response`, `acr.loa.map` for clients;
`include.in.token.scope` for scopes).

### Why this is a gap
Two consequences: (a) **byte-identity / ORK-schema contract** — if the ORK's `ClientConfig` /
`ClientScopeConfig` canonicalizer takes only the allow-listed keys, the producer's full-map
emission diverges → signature failure (this is the same byte-identity hazard the
`attributeNameValues` ordinal-sort comment, lines 1464–1494, exists to prevent — but order
isn't the issue here, *membership* is); (b) **re-attestation churn** — any admin edit to a
non-token attribute (e.g. `pkce.code.challenge.method`, `post.logout.redirect.uris`) changes
the attested bytes and forces re-attestation even though no claim changed.

### Spec/skill anchor
- `attestation-units.md` §2 "Allow-list of token-affecting client attributes" + the "Excluded
  (intentionally)" table; §3 likewise for scopes.

### Test design
- **Setup:** client with both an allow-listed attribute (`access.token.lifespan`) and a
  non-token attribute (`post.logout.redirect.uris`). Serialize `clientConfig`.
- **Expected (per spec):** only allow-listed attributes appear in the unit payload.
- **Current (predicted):** the non-token attribute appears too. Assert presence to red-bar.

### Confidence / falsifier
**MEDIUM** as a *design/contract* finding. Falsified if the ORK's matching C# unit also
canonicalizes the full attribute map (then it's a re-attestation-churn smell, not a correctness
bug). **Action: confirm against the ORK `ClientConfigAttestationUnit` / `ClientScopeConfigAttestationUnit` field list — this is the deciding check.**

---

## F5 (MEDIUM) — `realm_config` includes `organizationsEnabled`, which the spec explicitly excludes

### Claim
`REALM_CONFIG_ATTR_KEYS` (lines 100–101) = `{frontendUrl, acr.loa.map, organizationsEnabled}`.
The spec §1 "Excluded (intentionally)" lists `organizationsEnabled` as **NOT** a claim source
or claim-shape gate (runtime-confirmed on vanilla KC 26.5.5: flipping it leaves the
`organization` claim byte-identical), and warns *"a verifier enforcing it would over-reject a
legitimate token KC would issue."*

### Why this is a gap
Same dual consequence as F4: (a) if the ORK's `RealmConfig` unit canonicalizes only
`{frontendUrl, acr.loa.map}`, the extra key diverges the bytes → signature failure; (b) even if
the ORK carries it (the in-code comment claims the "RealmConfig preset" does), it couples
`realm_config` re-attestation to an admin-visibility toggle that changes no claim. The exporter
comment and the spec are in **direct tension** — exactly the kind of disagreement worth a test.

### Spec/skill anchor
- `attestation-units.md` §1 excluded table, `organizationsEnabled` row (runtime-confirmed).

### Test design
- **Setup:** realm with `organizationsEnabled` set; serialize `realmConfig`.
- **Expected (per spec):** `organizationsEnabled` absent from the attribute list.
- **Current:** present. Assert presence to red-bar. **Then confirm the ORK `RealmConfig` preset
  field list** to decide whether the producer or the spec is authoritative for this fork.

### Confidence / falsifier
**MEDIUM.** Falsified if the ORK preset deliberately carries `organizationsEnabled` (then keep
it but document the divergence from the generic spec).

---

## F6 (LOW) — Dynamic `organization:*` / `organization:<alias>` scope params are not resolved into active scopes

### Claim
`requestedScopeNames` (lines 1201–1211) whitespace-splits the scope param and
`resolveActiveScopes` (line 1194) matches tokens against optional scope **names** by exact
equality. A request `scope=organization:acme` or `organization:*` will not match an optional
scope named `organization`, so its mappers wouldn't be activated by this path. The dedup rule
(drop the static `organization` candidate when a dynamic form is present) is also not modeled.

### Why this is mostly dormant
In stock realms the `organization` client scope is a **default** scope, so it's already active
via `getClientScopes(true)` and its mapper emits regardless. The gap bites only if
`organization` is configured **optional** and requested dynamically.

### Spec/skill anchor
- `scope-resolution.md` STEP 1 L34–48 (`tryResolveDynamicClientScope`); `organizations.md` §3.2/§3.3.

### Test design
- **Setup:** `organization` as an **optional** scope; request `scope=organization:acme`; user a
  member of `acme`.
- **Expected:** the `organization` scope's `oidc-organization-membership-mapper` unit emitted.
- **Current (predicted):** not emitted (name `organization` ≠ token `organization:acme`).

### Confidence / falsifier
**LOW** (narrow config). Falsified if the deployment always keeps `organization` as a default
scope.

---

## F7 (LOW / VERIFY) — `service_account` scope coverage for service-account-enabled clients

### Claim
The fork's `TokenManager.getRequestedClientScopes` (lines 648–686) does **not** special-case
`service_account`; the producer relies entirely on `client.getClientScopes(true/false)`. The
`scope-resolution.md` skill states `service_account` *auto-attaches at runtime* when
`serviceAccountsEnabled=true` and is **not** guaranteed to be in the stored default-scopes list
(`logs-openid-offline-access.log` shows it in the validation set though absent from
`defaultDefaultClientScopes`). If, in this fork, `service_account` is **not** a stored default
scope, the producer omits its `client_scope_config` + mappers (`clientHost`, `clientAddress`,
`client_id` claims) for service-account tokens.

### Test design
- **Setup:** service-account-enabled client; inspect what `client.getClientScopes(true)` returns
  for it in the fork (this is the deciding fact).
- **If `service_account` is absent there:** assert the producer emits no `service_account` units
  → gap. **If present:** covered (close this item).

### Confidence / falsifier
**LOW / needs one fact.** Also gated on whether IGA token validation ever runs for
client-credentials/service-account tokens at all (the `ExportRequest` requires a `userId`;
service accounts have one, but the interactive-login assumption may make this moot).

---

## F8 (LOW) — `client_scope_config` is emitted for **all** optional scopes, including unrequested ones

### Claim
`collectAssignedScopes` (lines 1432–1442) unions `getClientScopes(true)` **and**
`getClientScopes(false)`, and `export()` emits a `client_scope_config` per entry (lines
229–231). Unrequested optional scopes are not in the token's resolved-scope set, so per
"no more, no less" their config shouldn't be in the closure. (The `client_scope_mapper_set` is
correctly limited to active scopes via `resolveActiveScopes`, so this is config-only
over-emission.)

### Why low
`client_scope_config` produces no claim by itself; if the ORK walks only resolved scopes it
ignores the extra. Flagged for completeness as the inverse of the F3 concern and because it
contradicts the stated exact-closure contract.

### Test design
- **Setup:** client with optional scope `addr` not named in the request param.
- **Expected (per contract):** no `client_scope_config(addr)`.
- **Current (predicted):** emitted (it's in `getClientScopes(false)`).

### Confidence / falsifier
**LOW.** Falsified if the ORK ignores configs for unresolved scopes (likely) — then it's a
tidiness issue, not a reject.

---

## Cross-cutting notes for the test author

- **Two existing harness styles to copy:**
  - *Pure-builder / Mockito unit tests* — `RealmAttestationExporterMetadataSeedTest`,
    `PerUserUnitsDefaultRoleExclusionTest`, `ProducerBuilderDeterminismTest`,
    `UserIdentityAttributesStringCoercionTest`. Best for F1, F3, F4, F5, F6, F8 (assert the
    **set of emitted unit types/targets**, or CBOR field membership via the `CBORFactory`
    pattern already used).
  - *Determinism / byte-identity tests* — `ProducerBuilderDeterminismTest` shows the
    serialize-twice-and-compare pattern; reuse it for F2 (two request contexts) and F4/F5
    (payload field membership).
- **`export()` needs a `KeycloakSession` + `EntityManager`.** The set-membership findings (F1)
  can be tested at the granularity of the **builder calls** if you assert against the `out` list
  via a thin seam, but the simplest red-bar for F1 is to drive `export()` with a mocked session
  whose `JpaConnectionProvider` returns a mock `EntityManager` (stub the `SELECT … ORDER BY`
  JPQL to return the seeded ids) — same approach the metadata tests use for the seed queries.
- **Ground-truth for the reject/accept consequence** (F1 especially, and the ORK-schema
  questions in F4/F5/F3) is a **QA e2e replay against the ORK** (`tide-stack` + `tide-playwright`
  skills). The unit tests prove the *structural* asymmetry; the ORK replay proves the *reject*.
- **Priority order to test:** F1 (headline, same class as the shipped fix) → F2 (subtle
  byte-divergence) → F4/F5 (ORK-schema contract, one ORK-side lookup settles both) → F3 → F6/F7/F8.
- **Over-emission is not automatically safe** here (the "attested-but-suppressed" reject rule),
  which is why F3/F8/F4/F5 are correctness-relevant and not just tidiness. Confirm each against
  whether the ORK *recomputes* the relevant resolution or *trusts* the producer's emitted set —
  that single ORK-behaviour fact decides several of them.

---
---

# Part 2 — Composite roles & organizations (second pass, 2026-06-12)

**Scope:** the composite-role closure (`metadataRoleSeed` → `transitiveRoleClosure` →
`role_definition` / `role_composite_children_set` / owner `client_config`) and the
organization closure (`emitOrganizationClosure` + the org stampers in `TideAttestor`).
Template gap: `c63d6bb` ("fix for groups") — a structurally complete-looking emission that
either misses an edge the ORK walks or emits a unit no stamper can sign.

## Verified Keycloak facts all of Part 2 hinges on

These were source-verified in the KC fork at `/home/sam/project/tidecloak` (26.5.x). The test
author should treat them as ground truth but may re-confirm with a one-line QA check each:

| # | Fact | Evidence |
|---|---|---|
| K1 | `user.getGroupsStream()` **never returns ORGANIZATION-type groups.** The filter is hardcoded (not feature-gated): the JPA group queries add `type = Type.REALM.intValue()` and the Infinispan cache adapter filters `Type.REALM.equals(g.getType())`. | `model/jpa/.../JpaRealmProvider.java:609,642`; `model/infinispan/.../cache/infinispan/UserAdapter.java:477` |
| K2 | Therefore `RoleUtils.getDeepUserRoleMappings(user)` — the input to `TokenManager.getAccess` and hence to `realm_access` / `resource_access` / `aud` — **never includes a role mapped to an org backing group.** It consumes `user.getGroupsStream()` unfiltered, and the filtering already happened upstream (K1). | `server-spi/.../RoleUtils.java:190-194` |
| K3 | `GroupMembershipMapper` (the `groups` claim) likewise never emits org backing groups — same `getGroupsStream()` source. | `services/.../GroupMembershipMapper.java:100` |
| K4 | `OrganizationProvider.getByMember(user)` returns **all** orgs whose backing group (`g.type = 1`) the user is in — no `enabled` filter, no membership-type filter. | `organization/jpa/JpaOrganizationProvider.java:460-479`; named query `getGroupsByMember` (`... join GroupEntity g ... where g.type = 1 ...`) |
| K5 | The replay is **all-or-nothing fail-closed**: at login every emitted unit's column is read via `UnitColumnMapping.readStored`; a NULL/stub/wrong-length value throws, naming the unit. There is no skip lane. | `IgaAttestationExporterProvider.exportSignedAccessTokenUnits` (lines 60-87) + `replayOrFailClosed` (95-110) |
| K6 | `group_role_mapping_set`'s sig carrier is the `GroupRoleMappingEntity` **rows** ("any row"); a group with zero role-mapping rows has **no column to read** → `readStored` returns null. Same row-carried design for units 7/8/10. | `UnitColumnMapping.java:37,106-108` (read), `162-163` (stamp) |
| K7 | The ADOPT scanner **excludes org backing groups** (`g.type = 0` predicate) — its own comment routes them to the ORGANIZATION path, which "stamps the ORG row's own attestation". | `IgaUnsignedRowScanner.groups` (`IgaUnsignedRowScanner.java:94-98`) |
| K8 | `stampAdoptOrganization` and `stampOrganizationNode` stamp **only** `organization_definition` (16) + `organization_domain_set` (17) — never the backing group's `GroupEntity.attestation`, never its `GroupRoleMappingEntity` rows. | `TideAttestor.java:4832-4855` (ADOPT), `4585-4608` (CREATE/UPDATE) |
| K9 | ~~`exportRealmMetadata` has no production caller~~ **CORRECTED (2026-06-12):** `IgaToggleOnBackfill` is a production caller — `convergeAfterCommit` (invoked from `IgaAdminResource` commit paths once the ADOPT set drains, firstAdmin+capable gated) runs `backfill()`, whose metadata phase calls `exportRealmMetadata` (`IgaToggleOnBackfill.java:181`) and whose per-user phase calls full `export()` per enabled user × client × maximal-optional-scope (`:204`). **But note for F10:** the metadata phase's all-groups walk uses `realm.getGroupsStream()`, which filters `type=REALM` (K1) — so org backing groups are reached ONLY via the per-user phase (`export()` → `emitOrganizationClosure`), i.e. only for orgs that HAVE members at convergence time, and only pre-flip (the convergence is firstAdmin-gated; post-flip the per-CR carrier is the only signer). | `IgaToggleOnBackfill.java:181,204,316-345`; `IgaAdminResource.java:759,1347` |
| K10 | `UnitColumnMapping.stamp` returning 0 rows is documented as a deliberate no-op **"since the login won't emit that unit either."** That invariant is exactly what the org path violates (F9). | `UnitColumnMapping.java:120-126` |
| K11 | Org member join/leave IS captured at the model layer with no type filter (`IgaUserAdapter.joinGroup`, line 1328+), so the U9 restamp on org join is covered by the normal JOIN_GROUPS CR pipeline — **provided** `JpaOrganizationProvider.addMember` routes through the wrapped user model. One e2e confirmation suffices; not raised as a finding. | `IgaUserAdapter.java:1328-1370` |

---

## F9 (HIGH) — org closure emits `group_role_mapping_set` for the backing group UNCONDITIONALLY — the one place the leaf-gate is missing

> **STATUS: FIXED (2026-06-12).** `emitOrganizationClosure` now leaf-gates the unit exactly
> like the plain-group walk: `groupRoleMappingSet(em, groupId, realmId)` is built first and
> added only when `roleIds()` is non-empty (`added` is incremented only on emission). The
> emission for NON-empty org-group role sets is deliberately retained — removing it entirely
> is F11's call and needs the K2 ground-truth + ORK-contract check first; the leaf-gate is
> correct under either F11 outcome. **Scope boundary:** this fix alone does NOT unbrick
> org-member logins — F10 (no stamper ever signs `GroupEntity.attestation` for the org
> backing group, whose `group_definition` is still emitted here) fail-closes the same logins
> and needs a `TideAttestor`-side fix (stamp `group_definition` — and `group_role_mapping_set`
> when non-empty — in `stampAdoptOrganization` / `stampOrganizationNode`). Test below should
> now green-bar (assert ABSENCE of the empty-set unit, PRESENCE in the non-empty control).

### Claim
`emitOrganizationClosure` adds `groupRoleMappingSet(em, groupId, realmId)` with **no empty
check** ([RealmAttestationExporter.java:762](../iga-core/src/main/java/org/tidecloak/iga/producer/RealmAttestationExporter.java#L762)).
The plain-group path introduced by `c63d6bb` leaf-gates the same unit
(`if (!unit.roleIds().isEmpty())`, line 277) precisely because *"a role-less group has no
GROUP_ROLE_MAPPING row to carry the per-set sig, so emitting it empty would dangle a
column-less unit that fail-closes the login"* (lines 262-264). Org backing groups are hidden
from every admin group API and **normally have zero role-mapping rows** — so for essentially
every org member, the login closure contains an empty `group_role_mapping_set` whose column
read is structurally NULL.

### Why this is a gap
The full reject chain is confirmed in-repo (K5 + K6 + K10): empty set → no
`GroupRoleMappingEntity` row → `readStored` null → `replayOrFailClosed` throws → **every
member of any organization fail-closes at login**. This is the *same bug class* `c63d6bb`
fixed, sitting one method below the fix, on the org side of the explicit split ("Org-backing
groups are handled by emitOrganizationClosure — skip them here so the split is explicit").

### Test design
Pure-builder/Mockito (copy `RealmAttestationExporterMetadataClosureTest` style — it already
mocks `OrganizationProvider`):
- **Setup:** user U member of org `acme` (mock `orgProvider.getByMember(U)` → `[acme]`); JPQL
  stub: `OrganizationEntity.groupId` → `g-org`; `GroupRoleMappingEntity ... WHERE group.id =
  'g-org'` → **empty list**; `realm.getGroupById("g-org")` → org-type group mock.
- **Expected (per the c63d6bb doctrine):** `export()` output contains NO
  `GROUP_ROLE_MAPPING_SET` unit with target `g-org`.
- **Current (predicted):** it contains one with an empty `roleIds()` → red-bar.
- **Control:** give `g-org` one role row → unit IS emitted (and see F11 for what must then
  also be in the closure).

### Confidence / falsifier
**HIGH** — purely in-repo, every link in the chain read directly. Falsified only if some
upstream caller filters empty units before `exportSignedAccessTokenUnits` (none found), or if
org membership never coexists with IGA login replay in practice.

---

## F10 (HIGH) — the backing group's `group_definition` is emitted at every org member's login, but NO stamper ever signs `GroupEntity.attestation` for an ORGANIZATION-type group

> **STATUS: FIXED (2026-06-12).** `TideAttestor` now treats the org node as the stamp OWNER of
> its backing group's units, via one shared helper `orgBackingGroupUnits(realm, em, orgId)` —
> `group_definition` always + `group_role_mapping_set` leaf-gated (exactly the post-F9 login
> emission) — wired into all three org lanes:
> 1. **`enumerateLiveCrUnits` `CREATE_ORGANIZATION`/`UPDATE_ORGANIZATION`** — the backing-group
>    units are framed with the node, so the multiAdmin carrier signs them and the distribution
>    stamps them (framing == distribution by construction; post-flip this is the only signer).
> 2. **`stampOrganizationNode`** (firstAdmin live lane) — signs each backing-group unit with the
>    same real per-commit `signProducerEnvelope` + `UnitColumnMapping.stamp` (no convergence
>    reliance, per the ADOPT_REALM doctrine comment).
> 3. **`stampAdoptOrganization`** (ADOPT lane) — stub-stamps them like the node units; the
>    toggle-on convergence upgrades member-surfaced units to real sigs.
>
> Also corrected K9 (see table): the convergence backfill IS a production path and its per-user
> `export()` phase already real-stamped backing groups of **member-bearing** orgs pre-flip — the
> live holes were (a) orgs created post-flip (carrier framed only unit 16) and (b) memberless
> orgs whose first member arrives post-flip. The fix closes (a) outright and (b) for any org
> whose CREATE/UPDATE/ADOPT CR commits after this change.
>
> **Documented residual (accepted, test-pinnable):** an org adopted pre-flip with NO members,
> never touched by another org CR, whose FIRST member joins post-flip — the JOIN_GROUPS edge CR
> frames only `user_group_membership_set`, so the backing group's column still holds the
> ADOPT-time stub → that member's login fail-closes until any UPDATE_ORGANIZATION /
> ORG-family CR commits. Closing it would mean the JOIN_GROUPS framing detecting org-type
> targets and framing the backing-group units too — deliberately out of the minimum delta;
> pin with an e2e if org usage post-flip matters.

### Claim
`emitOrganizationClosure` emits `group_definition(backing)` (line 760) and the uniform read
replays it from `GroupEntity.attestation` (K5, `UnitColumnMapping` GROUP_DEFINITION). But
every path that stamps that column excludes org backing groups:
- `CREATE_GROUP` / `SET_GROUP_ATTRIBUTE` stampers — fire only for admin group-API CRs; org
  backing groups are created internally by `JpaOrganizationProvider.createOrganizationGroup`
  and are invisible to that API.
- `ADOPT_GROUP` — the scanner's `g.type = 0` predicate skips them **by design** (K7), routing
  them to the ORGANIZATION path…
- …but `stampAdoptOrganization` / `stampOrganizationNode` stamp **only** units 16 + 17 (K8).
- The convergence (`exportRealmMetadata`) would also miss them (`realm.getGroupsStream()`
  filters to REALM type per K1) — and it has no production caller anyway (K9).

So even with F9 fixed, an org member's login emits `group_definition(g-org)` → column NULL →
fail-close.

### Why this is a gap
The org-side stamp set and the org-side login emission set have **diverged**: login emits
{16, 17, group_definition, group_role_mapping_set}; the ADOPT/CREATE org stampers sign {16,
17}. The whole Design-B premise (K10, "routing BOTH the stamp and the login read through the
producer … so they cannot drift") holds per-unit-type but was never checked per-*closure* for
the org family. Note the engine genuinely needs this unit: `group_definition.type =
ORGANIZATION` is the gate in the engine's WALK.group_to_org (exporter comment lines 683-690;
spec §6 `type` row).

### Test design
Two layers:
1. **Stamp/emit parity (the structural red-bar).** Drive `emitOrganizationClosure` (via
   `export()` with the F9 setup, backing group non-empty or post-F9-fix) and collect the unit
   `(type, targetId)` pairs. Then enumerate what `stampAdoptOrganization` would stamp for the
   same org (it calls `organizationDefinition` + `organizationDomainSet` only — assert by
   reading the method, or refactor it to return the framed units like `enumerateLiveCrUnits`
   does and assert set-equality). **Expected:** stamped-set ⊇ login-emitted org-closure set.
   **Current:** `GROUP_DEFINITION` (and `GROUP_ROLE_MAPPING_SET` when non-empty) missing.
2. **e2e (ground truth):** realm with one org + one member, IGA on, ADOPT_ORGANIZATION
   committed; member logs in → predict fail-close naming `group_definition` target `g-org`
   (or `group_role_mapping_set` first, per F9, whichever unit order hits first).

### Confidence / falsifier
**HIGH** on the structural divergence (all stampers read). Falsified if some path I did not
find stamps `GroupEntity.attestation` for type-1 groups (the deciding grep:
`UPDATE GroupEntity` sites + `UnitColumnMapping.stamp(GROUP_DEFINITION)` callers — I found
only `stampGroupDefinition` (CREATE_GROUP family, `TideAttestor.java:~4560`) and
`stampAdoptGroup` (`TideAttestor.java:4777-4791`), both unreachable for org groups).

---

## F11 (HIGH, semantic) — org-group role mappings: the exporter's premise contradicts real KC token construction, and the metadata seed cannot resolve the roles it implies

### Claim
The org closure emits `group_role_mapping_set` for the backing group *"so any role inherited
through the org group has an attested source"* (lines 687-689). Per K1+K2 that premise is
**false in real Keycloak**: roles mapped to an ORGANIZATION-type group are *never* in the
user's effective role set, never reach `realm_access` / `resource_access` / `aud`, in any
realm, regardless of feature flags. Two consequences, one for each possible ORK behaviour:

- **(a) If the ORK folds org-group roles into GrantedRoles** (it has every input to do so: U9
  carries the org membership row — raw JPQL, no type filter; `group_definition.type` is
  attested; the U10 edge is emitted), the ORK derives roles **the real token does not carry**
  → exact-closure reject ("attested-but-suppressed"), for any deployment that ever attaches a
  role to an org backing group (partial import, direct DB, future KC features).
- **(b) Even granting the fold,** the role ids in the org U10 edge have **no
  `role_definition` / `role_composite_children_set` / owner `client_config`** in the closure:
  `metadataRoleSeed` clause (ii) walks `user.getGroupsStream()`
  ([RealmAttestationExporter.java:944-950](../iga-core/src/main/java/org/tidecloak/iga/producer/RealmAttestationExporter.java#L944-L950)),
  which never returns org groups (K1). A **composite** role mapped to the org group is the
  worst case: unresolvable AND unexpandable — the exact "(a2) group-inherited composites"
  failure the seed-widening comment says it fixed, resurrected on the org side.

### Why this is a gap
Whichever way the ORK behaves, the current emission is wrong: fold → (a)+(b) bugs; no-fold →
the U10 edge is pure over-emission whose only effect is F9's fail-close. The KC-faithful fix
is to **not emit U10 for ORGANIZATION-type groups at all** and ensure the ORK's GrantedRoles
skips type-ORGANIZATION groups; the alternative (seed org-group roles into
`metadataRoleSeed`) would make the ORK *diverge further* from real tokens.

**Spec bug to flag upstream:** `attestation-units.md`'s graph walk folds
`group_role_mapping_set(G).role_ids` into `roles_to_walk` for **all** visited groups,
including org-backed ones (walk lines 695-696). Per K1/K2 that over-approximates KC 26.5.5 —
the walk should exclude `type = ORGANIZATION` groups from the role fold (their U10 is not a
claim source), or document why over-walking is harmless for the signing service but NOT for
an exact-claim TVE.

### Test design
1. **Producer-level (red-bar for (b)):** org backing group `g-org` carries composite role
   `org-comp` (child `org-child`, a client role of client `other`). User U member of the org,
   no other grants. **Assert (per current emission intent):** closure contains
   `role_definition(org-comp)`, `role_composite_children_set(org-comp) = [org-child]`,
   `role_definition(org-child)`, `client_config(other)`. **Current (predicted):** none
   present, while `group_role_mapping_set(g-org) = [org-comp]` IS emitted — the dangling-edge
   red-bar. (If the team chooses the KC-faithful fix instead, invert the test: assert the U10
   edge itself is absent.)
2. **KC ground truth (settles the fix direction):** QA replay — map a role to an org backing
   group directly in DB ([[tide-postgres]]), mint a real token for a member; **assert the
   role is NOT in `realm_access`/`resource_access`** (K2 predicts absent). This single fact
   decides whether the ORK must skip org groups in GrantedRoles.
3. **ORK contract check:** read the TVE's GrantedRoles / GroupAndAncestors for a
   `group_definition.type == ORGANIZATION` filter. (Deciding fact for (a).)

### Confidence / falsifier
**HIGH** that the asymmetry + missing metadata exist (in-repo + fork-verified). The
*severity* of (a) is falsified if the ORK already skips type-ORGANIZATION groups when folding
group roles — then only (b)-as-over-emission and F9 remain. Falsified for (b) if
`metadataRoleSeed` gains an org-group walk (it has none today).

---

## F12 (MEDIUM) — orphaned org-group membership edges when the OrganizationProvider is unavailable but membership rows persist

### Claim
`perUserUnits` emits `user_group_membership_set` from **raw JPQL with no group-type filter**
(line 783), so it always lists org backing-group ids. The only emitter of those groups'
`group_definition` is `emitOrganizationClosure`, which **no-ops entirely** when
`session.getProvider(OrganizationProvider.class)` throws or returns null (lines 707-717) —
i.e. when the ORGANIZATION feature is disabled at deploy after orgs were used. The plain-group
walk skips them by type (line 271). Result: U9 references group ids with **no
`group_definition` in the closure** — the same "orphaned edge" shape as F1, org-flavoured.

### Why this is reachable
Disabling organizations does **not** delete `ORG` / `KEYCLOAK_GROUP(type=1)` /
`USER_GROUP_MEMBERSHIP` rows (spec §1 `organizationsEnabled` row documents the rows
surviving; K1 shows the type filter is not feature-gated, so the membership rows stay live
for the JPQL). Any realm that used orgs and then turned the feature off ships orphaned U9
edges at every former member's login.

### Test design
- **Setup:** `session.getProvider(OrganizationProvider.class)` → null. U9 JPQL stub returns
  `[g-org]`; `user.getGroupsStream()` → empty (K1-faithful mock).
- **Assert (closure-integrity invariant, reusable beyond this finding):** *every* group id
  appearing in an emitted `user_group_membership_set` has a matching `GROUP_DEFINITION` unit
  in the same export. **Current (predicted):** violated for `g-org` → red-bar.
- This invariant assert is cheap and general — recommend adding it as a standing property
  check over `export()` output in all new tests (it would also have caught pre-F1 ancestors).

### Confidence / falsifier
**MEDIUM.** Falsified if the ORK ignores membership entries whose group_definition is absent
(skip-not-reject) — an ORK-contract fact. Even then the U9 *bytes* still verify (sig is over
the raw set), so this would be benign — but per the exact-closure doctrine stated in the file
header, dangling references are rejects.

---

## F13 (MEDIUM, security/design) — the leaf-gate makes "all composite children deleted" indistinguishable from "never composite", defeating the spec's anti-deletion guarantee at the empty boundary

### Claim
`emitRoleCompositeChildrenSet` (lines 611-620) skips the unit when `childRoleIds` is empty —
necessary under the rows-carry-the-sig design (K6: the sig lives on `CompositeRoleEntity`
rows). But spec §11's note exists for the opposite reason: *"A non-composite role still gets
an attestation here, with `child_role_ids = []`. That way the signing service can prove the
role is non-composite (vs. unattested)."* The linkage-set design principle ("hashing the
entire set defeats the cherry-pick attack: **deleting a row breaks the hash** just as adding
one does") fails exactly at the last-row boundary:

- **Delete ONE of two children (ungoverned, e.g. direct DB):** remaining row carries the old
  sig over the old 2-element set; producer emits the new 1-element set; Ed25519 verify over
  the literal bytes fails → **detected** (as a hard login outage until re-attested).
- **Delete the LAST child:** the sig carrier rows vanish AND the unit drops out of the
  closure (leaf-gate) → login succeeds, the composite's grants silently shrink, **no veto
  trace, no detection**. The same boundary exists for `group_role_mapping_set` (last role
  unmapped from a group), `user_role_mapping_set` (last direct grant), and
  `user_group_membership_set` (last membership).

Governed flows restamp at commit, so the exposure is the **ungoverned-mutation** channel —
which is precisely the channel the attestation chain exists to detect.

### Why this matters for composite roles specifically
Deleting all children of `tide-realm-admin`-style composites is a *privilege-stripping*
attack with a clean audit profile: the next login simply issues a smaller token. The
asymmetry (1-of-2 → outage; 2-of-2 → silence) is the test-pinnable signature of the gap.

### Test design
1. **Builder-level boundary pin (cheap, do first):** role with children `[a,b]` → unit
   emitted with both ids; children `[a]` → emitted; children `[]` → NOT emitted. Documents
   the boundary explicitly (today it's only implied).
2. **Replay-level:** `replayOrFailClosed` is static/package-private — feed it (unitFor 1-child
   set, stored = sig-over-2-child-set bytes) → reject path; then show the 0-child case never
   reaches replay at all. Together these prove the detect/silent asymmetry without an ORK.
3. **e2e (ground truth, QA):** DB-delete one-of-two composite children → login fail-closes;
   DB-delete the last child → login succeeds and the token lacks the role, with nothing in
   the CR/veto history. ([[tide-postgres]] + [[tide-stack]].)

### Confidence / falsifier
**HIGH** that the asymmetry exists (forced by the column design); **MEDIUM** that it is
*actionable* — closing it needs a parent-anchored sig (e.g. an `emptyCompositeAttestation` on
`RoleEntity`, or folding "is-composite + child-count" into `role_definition`'s payload), a
design decision for the ORK/threat-model owners. The test's value is pinning the boundary so
the decision is made consciously, not by omission.

---

## F14 (LOW / ORK-contract) — static `organization` scope with multi-org membership: real KC emits NO claim; the closure offers the engine N orgs

### Claim
Per the token-construction skill (invariant 13a, `organizations.md`): with the **unqualified**
static `scope=organization`, KC emits the `organization` claim **only when the user is a
member of exactly one org** — multi-membership produces a null write and the claim is absent
from the wire. The producer (correctly, per closure rules) emits `organization_definition` +
`organization_domain_set` for **every** member org (K4: `getByMember` doesn't filter). If the
engine's `ResolveMemberAliases` emits all enabled member aliases without modelling the
exactly-one rule (and the `multivalued` mapper-config branch), it will **expect** a claim a
legitimate multi-org token does not carry → false reject.

### Test design
- **e2e or ORK-unit:** user member of `acme` + `globex`, both enabled, stock `organization`
  default scope (`multivalued=true` mapper). Real token: NO `organization` claim (verify
  first against live KC — invariant 13a). Run the TVE over the closure → must accept.
- Also pin the inverse single-membership case (claim = `["acme"]`) as the control.

### Confidence / falsifier
**LOW-MEDIUM** — producer-side emission is correct either way; this is purely whether the
engine mirrors KC's single-membership rule and the `multivalued=false` index-0 quirk (spec
unit 17 `enabled` row documents the latter as a known cross-unit dependency). One ORK-side
source read (`Mappers/Organization*ClaimMapper.cs`) settles it.

---

## Part 2 cross-cutting notes for the test author

- **Dead-code signal, keep as guard:** the `type == ORGANIZATION → continue` in the plain
  walk (line 271) can never fire (K1: `getGroupsStream()` pre-filters). Harmless, but it
  encodes the same false premise as F11 — worth a comment-level fix alongside whichever F11
  direction is chosen. Do NOT delete the guard (it future-proofs against KC changing K1).
- **Priority order:** F9 → F10 (same fixture, two asserts; together they predict *every org
  member's login fail-closes today* — the headline e2e is one QA replay with one org + one
  member) → F11 (decides the U10-for-org-groups design; run the K2 ground-truth check first)
  → F12 (one standing closure-integrity property test) → F13 (boundary pin + security
  decision) → F14 (ORK-contract).
- **Single deciding ORK fact for F11/F12/F14:** whether the TVE's group walk / GrantedRoles /
  ResolveMemberAliases filter on `group_definition.type` and model the static-scope
  single-membership rule. One read of the ORK's `MapperContext.GrantedRoles` +
  `Organization*ClaimMapper` answers all three.
- **Fixture reuse:** all of F9-F12 share one Mockito fixture: realm + org `acme` (+ optional
  `globex`), backing group `g-org` (type ORGANIZATION, JPQL-stubbed
  `OrganizationEntity.groupId`), member user U, request client with empty scope param. The
  existing `RealmAttestationExporterMetadataClosureTest` already shows the
  `OrganizationProvider` mocking pattern to copy.
- **Stamp-side parity harness (F10):** consider extracting the per-CR stamped-unit framing
  (`stampAdoptOrganization` etc.) to return the framed units (as `enumerateLiveCrUnits`
  does) so "login-emitted set ⊆ stamped set" becomes a directly assertable property per
  entity family — that property test would have caught F9, F10, and the original `c63d6bb`
  gap mechanically.

---
---

# Part 3 — Scopes & protocol mappers (third pass, 2026-06-12)

**Scope:** the scope/mapper unit families end-to-end — exporter emission
(`collectAssignedScopes` / `resolveActiveScopes` / `emitAllActiveMappers` /
`jwtRelevantMapperIds`), the client/scope/mapper CR lanes (`IgaClientAdapter` /
`IgaClientScopeAdapter` capture → `enumerateLiveCrUnits` framing →
`stampProducerUnitColumns` / ADOPT stampers), and the ORK engine's mapper contract
(`ClaimMapperRegistry`). Cross-read against `keycloak-token-construction`
(scope-resolution.md, mapper-set-assembly.md, SKILL.md invariants) and
`attestation-units.md` §§2–4, 12–15. Line numbers refer to the **current working tree**
(post-F1/F9/F10 fixes, uncommitted).

Template gap is still `c63d6bb`: a closure that the login emits but no stamper owns (or
vice versa). Part 3 found the same shape THREE more times in the scope/mapper family
(F15, F16, F17), plus a capture-surface hole (F18) and four exporter-vs-KC-pipeline
divergences (F19–F22).

## Verified facts Part 3 hinges on (continuing the K-series)

| # | Fact | Evidence |
|---|---|---|
| K12 | The login emits a `protocol_mapper` unit (3) for EVERY JWT-relevant mapper on the request client and on every ACTIVE scope, and replays its sig from `ProtocolMapperEntity.attestation`. | `RealmAttestationExporter.emitAllActiveMappers` (L1264-1298); `UnitColumnMapping` read L88-89 / stamp L146-147 |
| K13 | Framing == distribution == `enumerateLiveCrUnits`, for every action type. `buildAllCrUnits` (phase-1 carrier AND commit distribution) funnels through the one enumerator (L3855-3866); index-0 edge units exist only for the 7 edge actions (`isProducerEnvelopeSignedAction`, L3715-3731 — no client/scope/mapper action is among them). **Anything absent from the `enumerateLiveCrUnits` switch is signed NOWHERE on the live (post-flip) lanes.** | `TideAttestor.java:3715-3731, 3855-3866, 3889-4023` |
| K14 | `ADD_PROTOCOL_MAPPER` / `UPDATE_PROTOCOL_MAPPER` / `REMOVE_PROTOCOL_MAPPER` frame ONLY the parent's mapper-set unit (12/13) — never the `protocol_mapper` node (3). Same on the firstAdmin live lane (`stampMapperSet`, L4332-4333 → L4684-4701: writes `clientMapperSetAttestation` / `clientScopeMapperSetAttestation` only). The ONLY paths that write a real per-unit envelope sig to `ProtocolMapperEntity.attestation`: `ADOPT_PROTOCOL_MAPPER` (L4915-4925, toggle-on lane) and the pre-flip convergence backfill. The dispatcher's replay writes to that column too (`IgaReplayDispatcher` L1249-1263, L2124-2146, L682-709) but with the LEGACY linkage-set canonical sig (`table=protocol_mapper\nowner=…\nmembers=…`) or the node-row sig — NOT a sig over the `protocol_mapper` unit envelope the login emits. | `TideAttestor.java:3981-3991, 4332-4333, 4684-4701, 4915-4925`; `IgaReplayDispatcher.java:1249-1263` |
| K15 | The ORK engine REJECTS any mapper-set member whose factory id has no registered handler: *"Handlers only derive — they never reject. An unsupported factory is the engine's concern (no registered handler → the engine's single Reject)."* The registry is an ALLOW-LIST of exactly 15 factory ids: address, allowed-origins, audience, audience-resolve, full-name, group-membership, hardcoded-claim, hardcoded-role, organization-membership, usermodel-attribute, usermodel-client-role, usermodel-property, usermodel-realm-role, **usermodel-role-name**, usersessionmodel-note. | `ork/.../Mappers/IClaimMapperHandler.cs:13-15, 47-72` |
| K16 | The ORK registers the RoleNameMapper handler under **`oidc-usermodel-role-name-mapper`**, but KC 26.5.5's `RoleNameMapper.PROVIDER_ID` is **`oidc-role-name-mapper`** (fork-verified). The real factory id resolves to NO handler. | `ork/.../Mappers/RoleNameMapper.cs:19`; `tidecloak/services/.../mappers/RoleNameMapper.java:66` |
| K17 | KC's mapper-set assembly applies TWO filters the exporter does not: (a) `m.getProtocol() == client.getProtocol()` and an empty set when the client's protocol is null (DCSC.L312-326); (b) `ProtocolMapperUtils.isEnabled` — drop any mapper whose factory is not registered on the server (PMU.L177-179). The exporter's only filter is the 5-entry `JWT_BODY_IRRELEVANT_FACTORIES` deny-list (L148-153, L1308-1318). | `mapper-set-assembly.md` Algorithm + "Inputs that quietly change the set"; `RealmAttestationExporter.java:148-153, 1264-1318` |
| K18 | The real login path passes the token's **`scope` CLAIM** as the producer's scope param: `DefaultTokenManager` L251 `String scope = accessToken.getScope()` → L260 `exportSignedAccessTokenUnits(realm, clientId, userId, scope)`. The scope claim is `DCSC.getScopeString()` — allowed scopes filtered by `isIncludeInTokenScope()`, the client filtered out, `openid` re-attached (DCSC.L188-212, skill invariant 2). The debug bundle's pasted mode does the same (`IgaTveBundleResource.java:435,473`). | fork `DefaultTokenManager.java:251,260`; `scope-resolution.md` L106-128 |
| K19 | The inline-mode (post-create) capture surface for clients is ONLY: `setAttribute`, `removeAttribute`, `add/update/removeProtocolMapper`, `add/deleteScopeMapping`, `setWebOrigins`, `setRedirectUris` (`IgaClientAdapter` override list). For client scopes ONLY: `setAttribute`, `removeAttribute`, `add/update/removeProtocolMapper`, `add/deleteScopeMapping`; `setName` / `setProtocol` pass straight through to super in inline mode (`IgaClientScopeAdapter.java:433-462` — the capture branch fires only in `captureMode`, i.e. mid-create). NO interception of `ClientModel.setFullScopeAllowed` / `setClientId` / `setProtocol` / `setServiceAccountsEnabled` exists anywhere in iga-core (grep-verified). | `IgaClientAdapter.java` overrides; `IgaClientScopeAdapter.java:433-462` |
| K20 | `REMOVE_CLIENT_ATTRIBUTE` (`IgaClientAdapter.java:472`) and `REMOVE_CLIENT_SCOPE_ATTRIBUTE` (`IgaClientScopeAdapter.java:545`) are captured CR action types that appear in NEITHER the `enumerateLiveCrUnits` switch (only `CREATE_CLIENT`/`SET_CLIENT_ATTRIBUTE`/`UPDATE_CLIENT_WEB_ORIGINS`/`UPDATE_CLIENT_REDIRECT_URIS` and `CREATE_CLIENT_SCOPE`/`SET_CLIENT_SCOPE_ATTRIBUTE`) NOR the `stampProducerUnitColumns` switch. The in-code `REMOVE_REALM_ATTRIBUTE` comment (L4006-4012) documents the exact consequence for the realm analog they already fixed: *"the CR framed 0 units → the carrier fell back to canonicalForRegularCr's non-CBOR canonical, which the ORK rejects as 'envelope must be a CBOR map'"*. | `TideAttestor.java:3905-3914, 4006-4013, 4315-4319` |
| K21 | `ADOPT_CLIENT` stamps FOUR client-family units (client_config, client_scope_assignment_set, client_mapper_set, scope_role_allowlist_set/client — L4848-4866); `ADOPT_CLIENT_SCOPE` stamps THREE (config, mapper-set, allowlist — L4869-4886). The live `CREATE_CLIENT` framing emits ONE (client_config, L3905-3909); `CREATE_CLIENT_SCOPE` ONE (config, L3910-3914). The login always emits the request client's assignment set (L226-231) and its allowlist EVEN WHEN EMPTY (L349-355). New clients get the realm's default scopes attached at creation, so the assignment set is non-trivial from birth. | `TideAttestor.java`, `RealmAttestationExporter.java` cited lines |
| K22 | The four derived-set columns (`client_scope_assignment_set` 11, `client_mapper_set` 12, `client_scope_mapper_set` 13, `scope_role_allowlist_set` 14) live on the PARENT entity (`ClientEntity`/`ClientScopeEntity` dedicated columns) — NOT on child rows. Unlike the row-carried sets (7/8/9/10), an EMPTY set is stampable and replayable; no leaf-gate is structurally required for them. | `UnitColumnMapping.java:39-42, 80-87, 112-113, 138-145, 166-167, 176-192` |
| K23 | Stock-realm coverage is closed: every mapper factory attached to the stock default/optional scopes is either in the producer's 5-entry deny-list (acr, sub, session-state, amr, nonce) or in the ORK's 15-entry registry (incl. `oidc-usersessionmodel-note-mapper` for `basic`'s `auth_time` and `service_account`'s client_id/clientHost/clientAddress). The mines are all NON-stock additions (F19/F20). | K15 registry list vs KC 26.5.5 stock scope mappers |

---

## F15 (HIGH) — `ADD_PROTOCOL_MAPPER` / `UPDATE_PROTOCOL_MAPPER` never sign the `protocol_mapper` NODE unit; post-flip, adding or editing a mapper fail-closes every login that activates its parent

### Claim
The mapper CR family frames ONLY the parent's mapper-set unit (K14): `enumerateLiveCrUnits`
L3981-3991 builds `clientMapperSet` / `clientScopeMapperSet`; `stampMapperSet` mirrors it on
the firstAdmin lane. Nothing on the live lanes ever produces a VVK sig over the
`protocol_mapper` unit envelope (the bytes `emitAllActiveMappers` emits at login). The only
node signers are `ADOPT_PROTOCOL_MAPPER` (toggle-on) and the pre-flip convergence. So
post-flip:

- **ADD:** the new `ProtocolMapperEntity` row's `attestation` column holds either NULL or
  the dispatcher's legacy linkage-canonical sig (K14) — never a sig over the unit envelope.
  `replayOrFailClosed` then either fail-closes locally (NULL/stub/wrong-length) or ships a
  64-byte sig over the WRONG bytes, which the ORK's literal-bytes Ed25519 verify rejects.
- **UPDATE:** the unit payload changes (config list — e.g. `claim.name`,
  `access.token.claim`), but only the (unchanged-membership!) mapper-set is re-signed; the
  node column keeps the OLD sig over the OLD config bytes → ORK verify fails.
- **REMOVE is the correct half:** the node row (and its column) vanishes, the login stops
  emitting the unit, and the set is re-signed — no gap.

Blast radius: a mapper added to a DEFAULT scope (e.g. `profile`) enters the active closure
of **every user × every client** at the next login. This is `attestation-units.md` §4's
trigger implemented backwards — the spec says add/edit re-attests the node *"(also requires
re-attesting the parent's mapper-set)"*; the code re-attests the set and skips the node.

### Spec/skill anchor
- `attestation-units.md` §4 (trigger: "add or delete a mapper … edit any mapper config key").
- K5 (all-or-nothing replay), K12, K13, K14.

### Test design
1. **Frame-parity unit test (red-bar):** build an `ADD_PROTOCOL_MAPPER` CR (rowsJson with
   `CLIENT_SCOPE_ID` + mapper row), drive `enumerateLiveCrUnits` against a mocked post-change
   model where the scope has the new mapper. **Expected (per spec):** framed units contain a
   `ProtocolMapperUnit` with `target_id == mapperId` AND the `ClientScopeMapperSetUnit`.
   **Current:** set unit only. Repeat for `UPDATE_PROTOCOL_MAPPER` (config-edit) and for the
   client-parent variant (`CLIENT_UUID`).
2. **Login/stamp parity property (the harness Part 2 recommends):** for the same fixture,
   assert (login-emitted units whose target is the mapper) ⊆ (framed units). Catches F15,
   F16, F17 mechanically.
3. **e2e (ground truth):** post-flip realm → admin adds a `oidc-usermodel-attribute-mapper`
   to the `profile` scope via a governed CR → commit → ANY user login: predict fail-close
   naming `protocol_mapper` target `<new-mapper-id>`.

### Fix shape (for the implementing agent)
Mirror the F10 pattern: in `enumerateLiveCrUnits` frame
`RealmAttestationExporter.protocolMapperUnitById(session, realm, mapperId)` alongside the
set for ADD/UPDATE (the helper already exists, built for ADOPT — L1368-1402); add the same
node stamp to `stampMapperSet`. Skip the node for REMOVE. Respect the
`JWT_BODY_IRRELEVANT_FACTORIES` filter: a filtered factory's node must NOT be framed (the
login won't emit it), but the SET membership already excludes it via
`jwtRelevantMapperIds` — keep both sides on the shared helper.

### Confidence / falsifier
**HIGH** — every link read in-repo (K12-K14). Falsified only if some post-flip path
re-runs the convergence backfill (none found; the F10 fix comments assert "post-flip these
CRs are the ONLY signer"), or if an ADOPT scan re-runs post-flip and re-adopts unsigned
mapper rows (check `IgaAdoptScan` invocation gating — worth one confirmation read).

---

## F16 (HIGH) — `CREATE_CLIENT` (and `CREATE_CLIENT_SCOPE` with inline mappers) frames a fraction of the closure the login emits for that entity

### Claim
The login's per-request-client emission is: `client_config` + `client_scope_assignment_set`
(always, L226-231) + `scope_role_allowlist_set`/client (always, EVEN EMPTY, L349-355) +
`client_mapper_set` & per-mapper `protocol_mapper` units (when the client owns JWT-relevant
mappers). `ADOPT_CLIENT` stamps exactly that family (K21). The live `CREATE_CLIENT` CR
frames ONLY `client_config` (L3905-3909) — there is no `perClientUnits()` analog of the
`perUserUnits` "COMPLETE BY CONSTRUCTION" derivation the CREATE_USER carrier got
(L3929-3950). A client created post-flip has `clientScopeAssignmentAttestation` and
`scopeRoleAllowlistAttestation` NULL → the FIRST login with `azp = <new client>` fail-closes
on `client_scope_assignment_set` (new clients get default scopes attached at creation, so
the set is emitted and non-trivial — K21).

Same shape one level down: `CREATE_CLIENT_SCOPE` frames only `client_scope_config`. For a
scope created empty via the admin console this is complete (mapper-set and allowlist are
empty → not emitted at login; mappers later arrive as `ADD_PROTOCOL_MAPPER` CRs → F15's
problem). But a scope (or client) created WITH INLINE MAPPERS — partial import, programmatic
`ClientRepresentation.protocolMappers` (the dispatcher explicitly replays nested mappers,
`IgaReplayDispatcher.java:682-709`) — leaves `client_scope_mapper_set`/`client_mapper_set`
AND every nested `protocol_mapper` node unsigned-or-wrong-bytes (the dispatcher's
`signNestedChildSet` writes the LEGACY canonical, not unit envelopes — K14).

### Spec/skill anchor
- `attestation-units.md` graph walk lines 636-642: `client_config`,
  `client_scope_assignment_set`, `client_mapper_set`, `scope_role_allowlist_set("client")`
  are ALL visited for the request client on every issuance.
- The `perUserUnits` doctrine (exporter L400-437): per-entity closures must be derived from
  ONE producer method so carrier and login cannot drift. Clients never got this treatment.

### Test design
1. **Frame-parity (red-bar):** `CREATE_CLIENT` CR, post-change model = client with the
   stock default scopes attached, no dedicated mappers. **Expected:** framed ⊇
   {client_config, client_scope_assignment_set, scope_role_allowlist_set(client)}.
   **Current:** {client_config}. Variant: rep with one inline mapper → expected additionally
   {client_mapper_set, protocol_mapper(m)}.
2. **e2e:** post-flip, create+commit a new public client, log a user in via it → predict
   fail-close naming `client_scope_assignment_set` target `<client uuid>`.

### Fix shape
Extract `perClientUnits(session, client, realmId)` (config + assignment set + allowlist +
leaf-gated mapper-set + JWT-relevant mapper nodes) into `RealmAttestationExporter`; call it
from `export()`, the `CREATE_CLIENT` framing, AND `stampAdoptClient` so the three can never
drift (the exact `perUserUnits` move). Same for a `perClientScopeUnits` used by
`CREATE_CLIENT_SCOPE` framing + `stampAdoptClientScope`.

### Confidence / falsifier
**HIGH** for the structural framing≠login divergence. The *consequence* depends on
`UnitColumnMapping.readStored` finding NULL — falsified only if some other CR family
incidentally stamps the new client's derived-set columns before its first login
(`ASSIGN_SCOPE` would fix the assignment set IF an admin happens to toggle a scope; nothing
fixes the allowlist column until a `SCOPE_MAPPING_ADD`). The e2e settles it.

---

## F17 (HIGH) — `REMOVE_CLIENT_ATTRIBUTE` / `REMOVE_CLIENT_SCOPE_ATTRIBUTE` are captured but framed NOWHERE — the already-fixed `REMOVE_REALM_ATTRIBUTE` bug, alive on both config families

### Claim
Both action types create CRs (K20) whose commit must re-sign the parent's config unit (the
post-change attribute list shrank — `client_config`/`client_scope_config` payload bytes
change). Neither appears in `enumerateLiveCrUnits` nor `stampProducerUnitColumns`. The
realm family hit this EXACT bug and fixed it by adding `REMOVE_REALM_ATTRIBUTE` to both
switches, leaving a comment describing the failure (K20). Consequences, by lane:
- **multiAdmin real-signing:** 0 framed units → the phase-1 carrier falls back to the
  non-CBOR canonical → ORK rejects the COMMIT itself ("envelope must be a CBOR map") — the
  veto pipeline wedges for that CR.
- **any lane where the commit survives:** the config column keeps the sig over the OLD
  attribute list → next login emitting that client/scope's config unit fails the ORK
  literal-bytes verify → fail-close.

Note the token relevance: removing `include.in.token.scope` from a scope (changes the
`scope` claim per skill invariant 2 — absent defaults to TRUE), or removing
`client.use.lightweight.access.token.enabled` / `access.token.lifespan` from a client, are
precisely the edits this CR family carries.

### Test design
1. **Switch-membership unit test (cheap, red-bar):** assert
   `enumerateLiveCrUnits(cr(REMOVE_CLIENT_ATTRIBUTE, CLIENT_UUID=c))` contains a
   `ClientConfigUnit(c)`; same for `REMOVE_CLIENT_SCOPE_ATTRIBUTE` → `ClientScopeConfigUnit`.
2. **Action-coverage property test (standing guard):** for every action type the adapters
   can emit (grep-derived constant list), `enumerateLiveCrUnits` must return ≥1 unit OR the
   action must be in `isProducerEnvelopeSignedAction` OR in an explicit no-producer-unit
   allowlist (REQUEST_SERVER_CERT, licensing, ORG membership edges, …). This pins F17 and
   catches any future captured-but-unframed action mechanically.

### Confidence / falsifier
**HIGH** — switch membership is directly readable; the failure mode is documented in-repo
for the realm analog. Falsified only if the attribute-removal CRs are dead code (the admin
console always sends full-rep updates → `setAttribute` with null? — check
`RepresentationToModel.updateClient`'s attribute diffing; even then partial-update API
callers reach `removeAttribute`).

---

## F18 (HIGH, governance + availability) — the capture surface ≠ the attested-payload surface: `fullScopeAllowed`, `clientId`, client `protocol`, `serviceAccountsEnabled`, scope `name`, scope `protocol` mutate UNGOVERNED and brick the attested bytes

### Claim
The `client_config` payload commits to `client_id`, `protocol`, `full_scope_allowed`,
`service_accounts_enabled` (+ origins/attrs); `client_scope_config` commits to `name`,
`protocol` (+attrs). The capture surface (K19) intercepts NONE of the model mutators for
those six fields — `setFullScopeAllowed`, `setClientId`, `setProtocol`,
`setServiceAccountsEnabled` on clients are not overridden at all, and the scope adapter's
`setName`/`setProtocol` capture only fires in `captureMode` (create), passing straight
through in inline mode (L434-462). Two independent consequences:

1. **Governance bypass (the IGA threat model's headline case).** Flipping
   `full_scope_allowed` on a client widens `realm_access`/`resource_access`/`aud` for every
   token it issues (skill invariant 6) — with NO change request, NO quorum, NO veto trace.
   Renaming a scope changes the `scope` claim literal (spec §3 trigger). Renaming a client
   changes `azp`/`aud`/`resource_access` keys (spec §2). These are exactly the
   "claim-shape gate" edits the 18-unit spec exists to gate.
2. **Attestation divergence → brick.** The login-emitted `client_config` /
   `client_scope_config` bytes change immediately, but no CR exists to restamp the column —
   the stored sig is permanently stale until some UNRELATED config CR (e.g. a cosmetic
   `SET_CLIENT_ATTRIBUTE`) happens to re-frame the unit. Every login via that client (or
   with that scope active) fail-closes in the interim.

### Test design
1. **Surface-parity test (the durable guard):** enumerate the fields each unit builder
   reads (`clientConfig`: getClientId, getProtocol, isFullScopeAllowed,
   isServiceAccountsEnabled, getWebOrigins(+redirects), getAttributes;
   `clientScopeConfig`: getName, getProtocol, getAttributes) and assert each has a
   corresponding intercepted mutator in the IGA adapter (reflectively: the adapter class
   declares an override). Red-bars on all six today; pins any future payload extension.
2. **Behavioural red-bar (per field):** with IGA active (inline mode),
   `client.setFullScopeAllowed(false)` → assert an `IgaChangeRequestEntity` was created
   (currently: none, write commits directly).
3. **e2e:** flip full-scope in the admin console on a committed realm → no CR appears AND
   the next login via that client fail-closes on `client_config` (ORK sig mismatch) — the
   double symptom (silent governance bypass + availability break) is the test signature.

### Confidence / falsifier
**HIGH** on the capture-surface fact (override list read; grep over iga-core found no other
interception). **Caveat for the test author:** confirm the admin REST update path
(`ClientResource.update` → `RepresentationToModel.updateClient`) actually reaches these
setters through the IGA adapter (i.e. the wrapped model is what the resource mutates) — if
some fork-side seam intercepts whole-rep client updates upstream (none found in iga-core;
check `tidecloak-override`), the governance half collapses and only the
divergence half (still a bug, lower severity) remains.

---

## F19 (MEDIUM-HIGH) — no mapper-protocol filter: a `protocol≠openid-connect` mapper (or a null-protocol client) is emitted/listed though KC never runs it

### Claim
KC folds into the mapper set only mappers with `m.getProtocol() == client.getProtocol()`,
and produces ZERO mappers when the client's protocol is null (K17a). The exporter emits
every non-deny-listed mapper of the client + active scopes and lists it in the set
membership (`emitAllActiveMappers`, `jwtRelevantMapperIds` — factory filter only). A SAML
mapper attached to an OIDC client/scope (the admin mapper API accepts any
`ProtocolMapperRepresentation.protocol`; partial imports do this) is therefore attested as
running:
- if its factory is outside the ORK registry (every `saml-*` factory is) → engine Reject at
  handler resolution (K15) → **false reject of a token KC mints fine**;
- if (hypothetically) registered → the engine derives a claim the token doesn't carry →
  attested-but-suppressed reject.

The spec carries `protocol` in unit 4's payload precisely as this gate (§4: "Flipping to
`saml` silently drops the mapper from the OIDC set") — the producer attests the field but
does not apply the gate.

### Test design
- **Unit (red-bar):** active scope with mappers `[m1(protocol=openid-connect),
  m2(protocol=saml)]` → assert `jwtRelevantMapperIds` excludes m2 AND no
  `ProtocolMapperUnit(m2)` is emitted AND the `client_scope_mapper_set` payload lists only
  m1. **Current:** m2 emitted + listed.
- **Edge:** `client.getProtocol() == null` → KC emits zero mappers (DCSC.L312-315);
  exporter currently emits all.
- **Byte-coupling warning:** `jwtRelevantMapperIds` is shared by the login AND the
  CR/ADOPT stampers — apply the protocol filter inside the shared helper (it needs the
  client's protocol as a parameter for client-owned mappers; scope mappers gate on the
  REQUEST client's protocol, which the realm-metadata path doesn't know — for
  `exportRealmMetadata`, gate on `protocol == "openid-connect"` and document the
  restriction). Changing only one side diverges sign-time vs login bytes (the F2-class
  hazard).

### Confidence / falsifier
**HIGH** that the filter is absent (direct read); **MEDIUM** severity (requires a
cross-protocol mapper to exist — partial imports and API misuse make this reachable, stock
realms don't hit it). Falsified if the ORK independently drops protocol-mismatched members
when walking mapper-sets — check `TokenValidationEngine` stage 5 for a protocol gate (one
read decides).

---

## F20 (MEDIUM) — factory-coverage contract: deny-list (producer, 5 ids) vs allow-list (engine, 15 ids) leaves every other factory a false-reject mine; plus the ORK registers RoleNameMapper under a WRONG id

### Claim
Two complementary halves:

**(a) Producer doesn't model `ProtocolMapperUtils.isEnabled` (K17b).** A stored mapper
whose factory is NOT registered on the KC server (undeployed extension, feature-gated
factory) is silently dropped by KC — no claim, valid token. The exporter emits it (not in
the deny-list) → ORK has no handler → Reject (K15). Same shape for KC built-ins that ARE
registered server-side but missing from BOTH the producer deny-list and the ORK registry —
the mapper RUNS in KC and the ORK can't derive it, so the engine rejects either way (here
rejecting is arguably fail-closed-correct, but it means deployments using these mappers
cannot log in AT ALL, which is a product decision to make consciously):
`oidc-role-name-mapper`, `oidc-sha256-pairwise-sub-mapper` (pairwise `sub`!),
`oidc-claims-param-token-mapper`, `oidc-claims-param-value-idtoken-mapper`,
`oidc-script-based-protocol-mapper` (fork-verified PROVIDER_IDs). Stock realms are safe
(K23); any of these one admin action away is not.

**(b) The ORK's RoleNameMapper id is a typo (K16).** `RoleNameMapper.cs` claims factory
`oidc-usermodel-role-name-mapper`; KC's id is `oidc-role-name-mapper`. The handler exists
but is unreachable; the skill's invariant-14 routing (role-injection class) was implemented
against a factory id that never occurs. Consequence: any realm with a role-name mapper →
producer emits the unit (correct id) → registry miss → engine Reject at every affected
login. Fix is ORK-side (one string); pin from this repo with a fixture emitting the real id.

### Test design
- **(a) red-bar unit:** active scope with a mapper whose factory id is
  `com.example.custom-mapper` (simulate unregistered: it IS unregistered in any test KC
  session) → per KC the closure must exclude it; exporter currently emits it. Implementing
  the filter: `session.getKeycloakSessionFactory().getProviderFactory(ProtocolMapper.class,
  factoryId) != null` — the EXACT check PMU uses; share it sign-side.
- **(a) contract table test:** assert
  `(KC 26.5.5 built-in OIDC factory ids) ⊆ (JWT_BODY_IRRELEVANT_FACTORIES ∪ ork registry ids)`
  — fails today on the five ids above; the failing set IS the documented mine list. Keep the
  ork id list as a checked-in fixture so registry drift re-red-bars.
- **(b) ork-side:** unit fixture `protocol_mapper` with `protocol_mapper:
  "oidc-role-name-mapper"` → `ClaimMapperRegistry.TryResolve` must succeed (currently
  false).

### Confidence / falsifier
**HIGH** on (b) — two PROVIDER_ID strings read side by side. **MEDIUM** on (a)'s severity
(non-stock configs only). (a) is falsified as a *false-reject* only if the engine treats
unknown factories as skip-not-reject — IClaimMapperHandler.cs L13-15 says the opposite
explicitly.

---

## F21 (MEDIUM) — the producer's "requested scope" is the token's `scope` CLAIM, so an applied optional scope with `include.in.token.scope=false` is invisible to the closure

### Claim
`resolveActiveScopes` matches optional-scope NAMES against whitespace tokens of
`req.scope()` (L1229-1254). But the value fed in at login is `accessToken.getScope()` — the
POST-filter claim (K18), not the request param. A **custom optional scope** with
`include.in.token.scope=false` that the client requested: KC applies it (its mappers RUN,
their claims are in the token) but its name is ABSENT from the `scope` claim → the producer
never activates it → its `client_scope_mapper_set` + `protocol_mapper` units are missing
from the closure → ORK: "no attested source" → **false reject**. Stock optional scopes all
have `include.in.token.scope=true` (or absent→true), so this is dormant until a realm adds
a claim-bearing, scope-hidden optional scope — a documented KC pattern for internal claims.

Inverse direction is safe: default scopes with `include=false` (roles, web-origins, basic,
acr, service_account) are activated via `getClientScopes(true)` regardless of the param.
Also fold in the F6 extension: a dynamic `organization:<alias>` entry in the scope claim
won't name-match the `organization` scope either (same matching code path).

### Test design
- **Unit (red-bar):** optional scope `internal-claims` (`include.in.token.scope=false`, one
  usermodel-attribute mapper), `req.scope() = "openid profile email"` (what the claim would
  carry after KC filtered the name out). **Expected (to match the real token):** the
  mapper's unit IS emitted. **Current:** not emitted.
- **Provenance pin (fork-side, one-line):** assert `DefaultTokenManager` passes the
  client-session `scope` NOTE (the original request param) — or change the producer to take
  the param from the clientSession and document that the claim is NOT a faithful proxy.
  Decide the fix direction first: passing the raw param is strictly more faithful (KC's own
  scope resolution starts from it); re-deriving "applied scopes" from the claim is lossy by
  design (skill invariant 2).

### Confidence / falsifier
**HIGH** on the provenance fact (K18, read in the fork). **MEDIUM** severity (custom-config
gated). Falsified if the ORK engine itself resolves active scopes from the assignment-set
units rather than trusting the bundle's scope string — in that case the producer's
under-emission still breaks the bundle (missing mapper units), so only the *mechanism*
changes, not the verdict.

---

## F22 (MEDIUM, security/design) — empty scope-level role allowlists are skipped at login though their column always exists: deleting the LAST allowlist row silently flips a restricted scope to UNIVERSAL

### Claim
`export()` emits the per-scope `scope_role_allowlist_set` only when non-empty (L356-363),
unlike the client-level one ("emitted explicitly even when empty", L349-355). The stated
leaf-gate rationale (rows carry the sig) does NOT apply here: unit 14's sig lives on the
ALWAYS-PRESENT parent column `ClientScopeEntity.scopeRoleAllowlistAttestation` (K22), and
`stampAdoptClientScope` already stamps it even when empty. The skip recreates F13's
deletion-blindness at a strictly worse boundary, because for allowlists the empty state is
a GRANT: `isClientScopePermittedForUser` returns TRUE for an empty mapping set
(scope-resolution.md L63 — "no role mappings → universal"). Ungoverned deletion (direct DB)
of a restricted scope's last `CLIENT_SCOPE_ROLE_MAPPING` row therefore (a) widens the scope
to every user, and (b) drops the unit from the login closure entirely — no stale-sig
detection, no veto trace. The spec calls this out verbatim (§15: *"Always emit the empty
array explicitly so the signing service can verify 'no allowlist entries' was the attested
intent, not a missing attestation"*).

### Why the asymmetry exists (and the fix dependency)
Emitting the empty unit today would fail-close logins on scopes whose allowlist column was
never stamped — i.e. it is MASKED by, and must be fixed together with, the
`CREATE_CLIENT_SCOPE` framing gap (F16's scope half: frame the allowlist at scope-create,
as `stampAdoptClientScope` already does at adopt). Sequence the fix: (1) frame allowlist in
CREATE_CLIENT_SCOPE, (2) flip L356-363 to unconditional emission, (3) e2e a stale realm
(scopes created between the two changes need a re-stamp pass or the SCOPE_ADD_ROLE family
to touch them).

### Test design
1. **Boundary pin (builder level):** restricted scope with roles `[r1]` → unit emitted;
   delete to `[]` → **expected (per spec §15): still emitted with empty `role_ids`**;
   current: skipped. Client-level control: already always-emitted (assert to pin the
   asymmetry).
2. **Security e2e (the headline):** scope `restricted` with allowlist `[admin-only]`,
   default-attached to a client; user WITHOUT the role logs in → scope filtered (F3
   territory), token lacks its claims. DB-delete the allowlist row ([[tide-postgres]]) →
   same user logs in → KC now applies the scope (universal); assert (a) no CR/veto trace
   exists, (b) the login SUCCEEDS pre-fix (the silent-widening proof), (c) post-fix the
   ORK rejects on allowlist-set divergence until re-attested.

### Confidence / falsifier
**HIGH** on the structural asymmetry + the universal-when-empty KC fact (skill-anchored).
**MEDIUM** on exploitability (needs the ungoverned-mutation channel — but that is the
channel the chain exists to detect, same argument as F13). Falsified if the ORK
re-derives allowlist presence from `client_scope_config` and rejects absent-but-expected
allowlist units — check the engine's unit-14 handling (one read).

---

## Part 3 cross-cutting notes for the test author

- **One harness kills four findings.** The "framed-set ⊇ login-emitted-set per entity
  family" property recommended in Part 2 catches F15, F16, F17 (and would have caught
  c63d6bb/F9/F10). Build it FIRST: for each CR action type, run `enumerateLiveCrUnits`
  over a post-change mock and assert every login-emitted unit targeting the CR's entity is
  framed. The action-coverage table (F17 test 2) is its cheap static companion.
- **Byte-coupling discipline for any exporter filter change (F19/F20/F21/F22):** every
  emission-shape change must land in the SHARED `public static` builders
  (`jwtRelevantMapperIds`, `clientMapperSet`, `clientScopeMapperSet`, …) so the CR/ADOPT
  stampers and the login keep emitting identical bytes — fixing the login side alone
  converts a false-reject into a sig-mismatch brick (the F2 class).
- **Priority order:** F15 (headline; same class as c63d6bb, hits DEFAULT-scope mapper edits)
  → F17 (two-line fix, documented failure mode) → F16 (perClientUnits refactor) → F18
  (governance hole — decide capture vs. document-as-unguarded per field) → F21 (provenance,
  needs a fork-side decision) → F19/F20 (closure-faithfulness; includes the ork
  `oidc-role-name-mapper` id fix) → F22 (security boundary, sequenced after F16-scope).
- **Single deciding ORK read for F19/F21/F22:** does `TokenValidationEngine` stage 3-5
  re-derive active scopes / apply a mapper-protocol gate / demand allowlist units for
  role-mapped scopes, or does it trust the producer's emitted sets verbatim? One pass over
  `TokenValidationEngine.cs` (stages 3, 5, 8) answers all three; record the answer next to
  K15.
- **Fixture reuse:** F15/F16/F17 share one Mockito fixture (client + default scopes +
  one custom scope + one mapper, post-change model mocks); F19/F20/F21 share the
  scope-with-mappers fixture varying only factory id / protocol / include.in.token.scope.
  The existing `RealmAttestationExporterMetadataSeedTest` mocking pattern carries over
  unchanged.
