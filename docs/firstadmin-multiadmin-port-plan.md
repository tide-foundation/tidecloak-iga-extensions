# FirstAdmin / MultiAdmin Port — Design + Migration Plan

**Status:** Draft for approval (Phase 2). No code written yet.
**Owner module:** `tidecloak-iga-extensions / iga-core`
**Date:** 2026-06-01
**Branch (planning):** `iga-tve-producer-m1`

---

## 1. Goal

Port the legacy two-mode authorizer semantics — `FirstAdmin` (single-signer
bootstrap that signs the realm's initial `tide-realm-admin` policy) and
`MultiAdmin` (T-of-N threshold signer for everyday CRs) — onto the **current
`TideAttestor` SPI** as a single class with a mode branch, replacing the
obsolete user-context signing path with the new row/unit envelope shape used
by the rest of `iga-core` and the IGA→TVE producer.

Authority for the legacy semantics:
- `tidecloak-iga-extensions-old/.../authorizer/FirstAdmin.java:37-168`
- `tidecloak-iga-extensions-old/.../authorizer/MultiAdmin.java:42-546`
- `tidecloak-iga-extensions-old/.../authorizer/AuthorizerFactory.java:6-42`
- `tidecloak-iga-extensions-old/.../utils/IGAUtils.java:23-129`

Current home (the receiver of the port):
- `tidecloak-iga-extensions/iga-core/.../attestors/TideAttestor.java:51-380`
- `tidecloak-iga-extensions/iga-core/.../attestors/IgaAttestor.java:19-72` (SPI)
- `tidecloak-iga-extensions/iga-core/.../entities/IgaAuthorizerEntity.java:34-78`

The port is scoped to **`TideAttestor` only** — no new factory id, no new SPI
type, no separate `FirstAdminAttestor` / `MultiAdminAttestor` class. The
attestor itself decides which branch to run per call by reading a new `mode`
field on the realm's `IgaAuthorizerEntity` row.

---

## 2. Background: legacy vs current

The table below contrasts the legacy two-class design with the current
single-attestor codebase. Every legacy reference is anchored to a file:line so
the contract is auditable.

| Aspect | Legacy (old extensions) | Current (`iga-core`) |
|---|---|---|
| Pluggable surface | `AuthorizerFactory.getCommitter("firstAdmin"\|"multiAdmin")` (`.../authorizer/AuthorizerFactory.java:10-12, 38-41`) | Keycloak SPI: `IgaAttestor` resolved by realm attribute `iga.attestor`, default `simple` (`IgaAttestors.java:21-35`) |
| Mode storage | `AuthorizerEntity.type` column (`.../entities/AuthorizerEntity.java:30`), values `"firstAdmin"` / `"multiAdmin"` (constants in `Constants.java:11-12`) | `IgaAuthorizerEntity.type` (`IgaAuthorizerEntity.java:46-47`) used as a free-text registration tag (no mode semantics today) |
| Payload to sign — bootstrap | `IGAUtils.signInitialTideAdmin` builds a `UserContextSignRequest("VRK:1")` over a Midgard `Policy` + a list of `UserContext`s; returns a list of base64 signatures terminated by the **policy signature** (`.../utils/IGAUtils.java:26-84`) | `TideAttestor.combineFinal` builds a deterministic canonical byte string over per-(table,owner) sets or per-entity NODE state and signs via `sign(byte[])` (`TideAttestor.java:115-136, 153-232`) |
| Payload to sign — steady-state | `IGAUtils.signContextsWithVrk` per-context loop + `MultiAdmin.commitWithAuthorizer` invokes `Midgard.SignModel(settings, req)` on each `UserContext` (`.../utils/IGAUtils.java:86-128`, `.../authorizer/MultiAdmin.java:386-446`) | Same `TideAttestor.combineFinal` set/node canonical + single `sign(byte[])` swap-point (`TideAttestor.java:115-136, 305-358`) |
| Per-admin dedup | `MultiAdmin` rejects a second signature from the same admin in `signWithAuthorizer` (`.../authorizer/MultiAdmin.java:66-78`); `FirstAdmin` has no dedup (it commits in one call) | `IgaAdminResource.authorize` rejects duplicate username/userId on the CR (`IgaAdminResource.java:259-278`); `TideAttestor.record` itself stores admin's username in `partialSig` (`TideAttestor.java:82-101`) |
| Threshold source | Hard `System.getenv("THRESHOLD_T")` / `THRESHOLD_N` at sign/commit time (`MultiAdmin.java:125-126, 366-371`; `IGAUtils.java:35-39, 94-98`), plus a stored `tideThreshold` role-attribute with a `0.7 × numberOfAdmins` stale-cap fallback (`ChangesetRequestAdapter.java:104-116`; `BasicIGAUtils.java:762-765`) | **Tideless:** `IgaScopeResolver.resolveThreshold` reads per-scope-entity `iga.threshold` then realm attribute `iga.threshold`, defaulting to 1 (`IgaScopeResolver.java:283-311`) — **unchanged**. **Tide-mode (this port):** `TideAttestor.getThreshold` multiAdmin branch computes `Math.max(1, (int)(0.7 × activeTideRealmAdmins))` live (§3.5–3.7); firstAdmin returns 1. No stored value, no env, no `iga.threshold_t`/`_n`. |
| Threshold T/N representation | Two ints (`Threshold_T` + `Threshold_N` on `SignRequestSettingsMidgard`) + stored `tideThreshold` | Single integer. No `N`: in Tide-mode multiAdmin it is the dynamic `floor(0.7 × activeTideRealmAdmins)` (min 1) recomputed per quorum check (the "N" of admins is implicit and live); in Tideless it is the static `iga.threshold` integer. |
| VRK accessor | `componentModel.getConfig().getFirst("clientSecret")` + Jackson-deserialize to `SecretKeys`, then `secretKeys.activeVrk`; component lookup via `realm.getComponentsStream().filter(x -> "tide-vendor-key".equals(x.getProviderId()))` (`MultiAdmin.java:373-383, 474-484`; `IGAUtils.java:32-49`) | **Not present.** `TideAttestor.sign(byte[])` produces a dummy SHA-256 stub: `"TIDE-DUMMY-v1:" + base64(sha256(canonical))` (`TideAttestor.java:351-358`) |
| Transition trigger | `FirstAdmin.commitWithAuthorizer` flips `authorizer.setType("multiAdmin")` when the CR is a `TideUserRoleMappingDraftEntity` assigning `Constants.TIDE_REALM_ADMIN` (`FirstAdmin.java:109-116`); `MultiAdmin.commitWithAuthorizer` does the same for `isAuthorityAssignment` (`MultiAdmin.java:455-460`) | **Not present.** No mode flip exists; `IgaAuthorizerEntity.type` is set at create time and never re-written. |
| Default authorizer for new realms | Bootstrapped as `firstAdmin` by the legacy realm-init flow (legacy startup creates the row with `type=Constants.TIDE_INITIAL_AUTHORIZER`) | `IgaAuthorizerEntity` is only created by an explicit `POST /iga/authorizers` (endpoint `IgaAdminResource.java:1054-1095`; row insert `IgaAuthorizerService.create` → `em.persist` at `IgaAuthorizerService.java:24-37`) — no auto-bootstrap on toggle-on. `type` is taken verbatim from the request (`IgaAdminResource.java:1087-1092`), not derived |
| User-context regeneration on transition | `FirstAdmin.regenerateDefaultUserContexts` re-emits all client drafts to remove pre-transition contexts (`FirstAdmin.java:121-158`) | N/A — user contexts have been removed entirely (CR rows are the new shape) |
| `Midgard.SignModel` dependency | Hard-required at compile and runtime (legacy `pom.xml:106-112`) | Currently absent; `TideAttestor.sign` is a SHA-256 stub with the comment "TODO: replace with Midgard signClaims() — single crypto swap-point" (`TideAttestor.java:349`) |

---

## 3. Design — the two-mode `TideAttestor`

### 3.1 Single class, mode read per call

A new field `mode` is added to `IgaAuthorizerEntity` (column + getter/setter; see §4). The attestor reads it on every call via a small helper:

```java
private String resolveMode(KeycloakSession session, RealmModel realm) {
    EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
    IgaAuthorizerEntity row = em.createNamedQuery("IgaAuthorizer.findByRealm", IgaAuthorizerEntity.class)
            .setParameter("realmId", realm.getId())
            .getResultStream().findFirst().orElse(null);

    // A row exists: its mode column is authoritative.
    if (row != null && row.getMode() != null) {
        return row.getMode();
    }

    // NO row exists. This is the DEFAULT state for every realm today — the
    // iga_authorizer entity is dormant (0 rows live; §9.1). The no-row branch
    // is decided by the realm's Tide-vs-Tideless discriminator: the
    // `iga.attestor` attribute (IgaAttestors.java:21-35), the SAME attribute
    // §Q4/D9 already hinge on.
    String attestor = realm.getAttribute("iga.attestor");          // IgaAttestors.java:22
    if ("tide".equals(attestor)) {
        // Tide realm that has not yet bootstrapped its admin policy → firstAdmin.
        // (The first Tide-mode record() will lazily materialise this row seeded
        // mode="firstAdmin" — §9; until then resolveMode reports firstAdmin so
        // the bootstrap branch runs.)
        return "firstAdmin";
    }
    // Tideless / simple / attribute absent → no-op. The authorizer entity is
    // irrelevant to Tideless; SimpleNameAttestor never consults it and never
    // calls resolveMode. This branch is unreachable from SimpleNameAttestor; it
    // exists only so a stray call on a non-Tide realm does not fabricate a mode.
    return null;
}
```

**Decision 1 — RESOLVED `session:2026-06-01 with user`.** When there is **no**
`IgaAuthorizerEntity` row for the realm (the dormant-entity default — `iga_authorizer`
holds **0 rows** in the live demo DB despite active IGA usage, 13 authorizations
across 9 CRs; §9.1), `resolveMode` returns:

- **`firstAdmin`** when `iga.attestor == "tide"` — the realm is a Tide realm that
  has not yet bootstrapped its `tide-realm-admin` policy. The bootstrap branch
  (§6) runs and the row is lazily seeded `mode="firstAdmin"` on the first
  Tide-mode `record()` (§9).
- **no-op (`null`)** otherwise (simple / Tideless / attribute absent). The
  authorizer entity is irrelevant to Tideless; `SimpleNameAttestor` does not
  consult it and never calls `resolveMode`, so this branch is reached only by a
  defensive stray call — it deliberately does **not** invent a `firstAdmin` /
  `multiAdmin` mode for a non-Tide realm.

This **supersedes** the earlier draft default-when-missing of `"multiAdmin"`. The
old "no row → multiAdmin" rule was wrong for the only realms that ever reach this
attestor: a `tide`-attestor realm with no authorizer row is one that has **not yet
bootstrapped**, so it must enter `firstAdmin`, not steady-state `multiAdmin`. The
`defaultValue="multiAdmin"` migration column (§4.2) is unaffected — it governs the
mode of rows that **already exist**, not the no-row case Decision 1 covers; the two
do not collide because a Tide realm's row is created (lazily, §9) seeded
`firstAdmin`, while any pre-existing operator-created row keeps the column default.
The discriminator is `IgaAttestors.java:21-35` (`iga.attestor` selects `tide` vs
`simple`), cross-referenced by §Q4/D9.

### 3.2 `record(KeycloakSession, IgaChangeRequestEntity, UserModel, String)`

**Lazy-seed precondition (Decision 2, §9.3).** Before branching, `record` runs the
lazy firstAdmin seed: if the realm has **no** `IgaAuthorizerEntity` row **and**
`iga.attestor == "tide"`, it creates one seeded `mode="firstAdmin"` via
`IgaAuthorizerService.create()` (`IgaAuthorizerService.java:34`). This is the
**only** place the first row is ever born (no eager toggle-on / realm-init seed).
After this step the row always exists for a Tide realm, so the subsequent
`resolveMode` reads the column. See §9.3 for the full sketch + the no-`tide-vendor-key`
skip.

Then branch by mode:

| Mode | Behaviour |
|---|---|
| `firstAdmin` | No dedup (legacy `FirstAdmin` never enforced it — it ran the full sign+commit in one call). Persist exactly one `IgaAuthorizationEntity` (the bootstrap admin) and immediately return; the per-CR endpoint then proceeds to commit. |
| `multiAdmin` | **Unchanged** from today's `TideAttestor.record` (`TideAttestor.java:82-101`): enforce `IgaScopeResolver.requireApprover`, persist `partialSig = admin.getUsername()`. Dedup is enforced one layer up in `IgaAdminResource.authorize` (`IgaAdminResource.java:259-278`). |

In **both** modes the persisted shape is the same — `IgaAuthorizationEntity` with `partialSig = admin.getUsername()` — so the existing `combineFinal(... authorizations)` accumulator works unchanged.

### 3.3 `combineFinal(KeycloakSession, IgaChangeRequestEntity, List<IgaAuthorizationEntity>)`

This is the only method whose **payload shape** differs by mode:

| Mode | Canonical payload built | Crypto called | Result string |
|---|---|---|---|
| `firstAdmin` & CR is tide-realm-admin policy | Per §6.2: the realm's `tide-realm-admin` `IgaRolePolicyEntity.policy` value (verbatim, base64-decoded if needed) | `sign(canonical)` — VRK signing via the ported VRK signing call (§5), which routes **Midgard → ORK network** (NOT a local key op; see §5.1, §3.4) | A single base64 signature, prefixed `TIDE-FIRSTADMIN-v1:` so it is unmistakably the bootstrap shape (mirrors the existing `TIDE-DUMMY-v1:` prefix at `TideAttestor.java:56`). Also written back to `IgaRolePolicyEntity.policySig` in the same transaction — see §7. |
| `firstAdmin` & CR is any other type | Per §6.3: the **exact same canonical bytes** today's `TideAttestor.combineFinal` produces (the set canonical via `canonicalizeLinkageSet` at `TideAttestor.java:153-208` or NODE canonical via `canonicalizeNode` at `TideAttestor.java:215-232`) | `sign(canonical)` — VRK signing via the Midgard → ORK call (§5), **not** a local key op | `TIDE-FIRSTADMIN-v1:<base64>`. The replay dispatcher's stamp path (`IgaReplayDispatcher.replay`) treats this string opaquely. |
| `multiAdmin` (any CR) | Unchanged from today: per-(table,owner) set canonical OR per-entity NODE canonical (`TideAttestor.java:115-136, 153-232`) | `sign(canonical)` — the **same** single swap-point as today (`TideAttestor.java:351-358`); future Midgard `signClaims()` integration lands here uniformly for both modes — already tracked under [[project-iga-tve-producer]] | `TIDE-DUMMY-v1:<base64>` today; eventually `<midgard-sig>` when the swap is real. |

### 3.4 `sign(byte[])`

The `firstAdmin` branch signs **with the VRK** (`secretKeys.activeVrk`, read
via the accessor in §5) — this is the bootstrap case where **one admin** (the
1-of-1 ADMIN quorum) authorizes the sign. **The VRK signing itself is NOT a
local key operation.** The VRK is sharded across the ORK network via threshold
cryptography, so even single-admin firstAdmin signing routes **Midgard → ORK
network** and requires the ORKs to be reachable (user-confirmed 2026-06-01; see
§5.1 for the network boundary inside Midgard's native core). In legacy this was
`Midgard.SignWithVrk(req.GetDataToAuthorize(), settings.VendorRotatingPrivateKey)`
at `IGAUtils.java:57-59, 113-115` — and the surrounding `SignRequestSettingsMidgard`
carries `HomeOrkUrl`/`VVKId` (`IGAUtils.java:44, 43`), the ORK endpoint the
native Midgard core dials.

The `multiAdmin` branch uses the **enclave threshold-signing path** — today the
SHA-256 stub at `TideAttestor.java:351-358`, in the future the real
`Midgard.SignModel` call. The Midgard swap-point is the single `sign(byte[])`
method as it is today. **Both** modes ultimately go Midgard → ORK; firstAdmin
does **not** by-pass the network. The distinction between the modes is **not**
local-vs-network — it is (a) ADMIN-quorum semantics (firstAdmin = 1; multiAdmin
= dynamic `floor(0.7 × activeAdmins)`) and (b) which key / signing ceremony
(VRK sign vs enclave threshold sign). Consequently firstAdmin signing carries
the **same ORK-reachability / M2M dependency** as multiAdmin: if the ORKs are
unreachable, firstAdmin fails the same way multiAdmin does (see §6 and §12 Q3).

Implementation shape:

```java
private String sign(KeycloakSession session, RealmModel realm, String mode, byte[] canonical) {
    if ("firstAdmin".equals(mode)) {
        VrkSignSettings settings = VrkAccessor.readVrkSignSettings(session, realm); // §5: activeVrk + HomeOrkUrl + VVKId + payerPublic + obfGVVK
        byte[] sig = VrkAccessor.signWithVrk(canonical, settings);   // §5: Midgard.SignWithVrk -> native core -> ORK network (NOT local)
        return "TIDE-FIRSTADMIN-v1:" + Base64.getEncoder().encodeToString(sig);
    }
    // multiAdmin: today's dummy; swap-point for Midgard.signClaims()
    try {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(canonical);
        return DUMMY_SIG_PREFIX + Base64.getEncoder().encodeToString(digest);
    } catch (NoSuchAlgorithmException e) {
        throw new RuntimeException("SHA-256 unavailable for TideAttestor dummy signing", e);
    }
}
```

The reusable `signSet(KeycloakSession, String, String, Collection<String>)`
helper at `TideAttestor.java:305-308` already centralises the canonical-set
shape used by `IgaReplayDispatcher` for nested-child fan-out; the mode
branch goes here too (it must produce the same byte-string the dispatcher
later writes into every fanned-out row's ATTESTATION column).

### 3.5 `getThreshold(KeycloakSession, RealmModel, IgaChangeRequestEntity)`

`getThreshold` is the `IgaAttestor` SPI method (`IgaAttestor.java:55`); the
`tide` attestor already has `session` + `realm` + `cr` in scope, so it has
everything it needs to count admins with no extra plumbing. Today
`TideAttestor.getThreshold` (`TideAttestor.java:104-106`) just delegates to
`IgaScopeResolver.resolveThreshold`; the port branches it by mode **inside
`TideAttestor`** (NOT inside the shared `IgaScopeResolver` — that resolver is
the **Tideless** path and its realm `iga.threshold` default must stay static;
see §8 and §12 Q8):

```java
@Override
public int getThreshold(KeycloakSession session, RealmModel realm, IgaChangeRequestEntity cr) {
    // firstAdmin is single-signer onboarding: ALWAYS 1, unconditionally — it
    // does not consult per-scope overrides, the realm attribute, or the admin
    // count (§3.5 invariant; legacy FirstAdmin reads no threshold at all).
    if ("firstAdmin".equals(resolveMode(session, realm))) {
        return 1;
    }
    // multiAdmin: a per-scope iga.threshold (set WITH iga.approverRole on the
    // same entity) or an ADOPT_* short-circuit still wins via the shared path;
    // only the realm-level default flips from static iga.threshold to the
    // dynamic 0.7 floor.
    IgaScopeResolver.ResolvedScope scope = IgaScopeResolver.resolve(session, realm, cr);
    if (scope != null && !scope.thresholds.isEmpty()) {
        return IgaScopeResolver.resolveThreshold(session, realm, scope, cr);     // per-scope override wins
    }
    if (cr != null && IgaReplayExtension.isAdoptAction(cr.getActionType())) {
        return 1;                                                               // ADOPT bypass wins
    }
    return Math.max(1, (int) (0.7 * countActiveTideRealmAdmins(realm, session))); // §3.6 / §3.7
}
```

| Mode | Returns |
|---|---|
| `firstAdmin` | **Constant `1`, unconditionally.** The whole point of the bootstrap mode is single-signer onboarding (`FirstAdmin.commitWithAuthorizer` at `FirstAdmin.java:102-119` proceeds straight to commit with no `THRESHOLD_T` check; only `MultiAdmin` reads it). The firstAdmin branch in the sketch above returns a literal `1` **before** consulting `IgaScopeResolver`, the realm attribute, or the dynamic active-admin count — none of them apply in firstAdmin mode. |
| `multiAdmin` | **Dynamically computed at quorum-check time** as `Math.max(1, (int)(0.7 * activeTideRealmAdmins))` — see §3.6. NOT stored on any entity or realm attribute. A per-scope-entity `iga.threshold` override (when set together with `iga.approverRole` on the same entity — the same-entity coupling rule, `IgaScopeResolver` collectors `:483/493/501`) still wins over the dynamic floor, as does the ADOPT_* bypass; the dynamic compute is the **realm-level default**, replacing the static realm `iga.threshold` attribute / `1` that the Tideless path keeps. The branch lives **in `TideAttestor`, not in `IgaScopeResolver`** (the shared resolver stays Tideless-static). |

**Consistency with the no-row case (§3.1, Decision 1).** The `getThreshold`
sketch reads the mode via the **same `resolveMode`** as §3.1, so the no-`IgaAuthorizerEntity`-row
default flows through here unchanged: on a `tide` realm with no authorizer row,
`resolveMode` returns `"firstAdmin"`, so `getThreshold` returns the constant `1`
(the bootstrap quorum) — exactly what a not-yet-bootstrapped Tide realm needs.
`resolveMode`'s `null` return (non-Tide / Tideless) cannot reach this method in
practice, because `getThreshold` here is the **`tide` attestor's** override and a
Tideless realm resolves to `SimpleNameAttestor` (whose own `getThreshold` keeps
the static `IgaScopeResolver` path); the defensive `"firstAdmin".equals(null)` ==
`false` simply means a stray non-Tide call would fall through to the multiAdmin
branch rather than returning `1`. §3.1 and §3.5 therefore agree: **no row +
`tide` ⇒ firstAdmin ⇒ threshold 1**; **row present ⇒ its `mode` column**.

### 3.6 Dynamic threshold (multiAdmin) — `0.7 * activeTideRealmAdmins`

Replaces the legacy stored-on-role `tideThreshold` attribute. There is **no
realm attribute** for the multiAdmin threshold — no `iga.threshold_t`, no
`iga.threshold_n`, no per-user `tideThreshold`. Computed **on every quorum
check**, never persisted:

```java
// Computed at the moment quorum is checked. NOT stored.
int activeAdmins = countActiveTideRealmAdmins(realm, session);
int threshold = Math.max(1, (int) (0.7 * activeAdmins));
```

- The `(int)` cast truncates (floor); `Math.max(1, …)` is the minimum-of-one
  floor (the quorum can never be zero).

Legacy reference sites — the **exact** formula already exists in old code:

- `tidecloak-iga-extensions-old/tidecloak-iga-provider/src/main/java/org/tidecloak/base/iga/TideRequests/TideRoleRequests.java:128` — the **primary** site, `int threshold = Math.max(1, (int) (thresholdPercentage * (numberOfActiveAdmins + numberOfAdditionalAdmins)));`, called with `thresholdPercentage = 0.7` from `ChangeSetProcessor.java:329`.
- `tidecloak-iga-extensions-old/tidecloak-iga-provider/src/main/java/org/tidecloak/base/iga/interfaces/ChangesetRequestAdapter.java:104-115` — two more instances inside `getChangeSetStatus()` (one as the IGA-enabled-but-no-component path at `:104`, one as the stale-cap fallback at `:115`).
- `tidecloak-iga-extensions-old/tidecloak-iga-provider/src/main/java/org/tidecloak/base/iga/utils/BasicIGAUtils.java:764` — the stale-cap fallback `threshold = Math.max(1, (int) (0.7 * numberOfAdmins))` in `processDraftRejections()`.

**Port simplification:** legacy used a stored `tideThreshold` role-attribute
(`ChangesetRequestAdapter.parseThreshold` at `:184-194`, written as
`tideThreshold` on the `tide-realm-admin` role) as the **primary** source,
with the `0.7 * numberOfAdmins` formula only as a **stale-cap fallback** when
the stored value exceeded the live admin count (`ChangesetRequestAdapter.java:111-116`,
`BasicIGAUtils.java:762-765`). That braiding meant the threshold could drift
from reality between writes. The new port **drops the stored mode entirely** —
the formula is always computed live, so staleness is structurally impossible
and there is no stored-threshold value to migrate. We deliberately did **NOT**
introduce a stored T/N realm attribute (no `iga.threshold_t` / `iga.threshold_n`).
See §11 D3 for the audit-trail decision row.

**Where it lands:** inside `TideAttestor.getThreshold` (the multiAdmin branch
of the sketch in §3.5), **not** inside `IgaScopeResolver.resolveThresholdInternal`
(`IgaScopeResolver.java:292-311`). The shared resolver remains the **Tideless**
static path (realm `iga.threshold` attribute → per-scope max → 1, per
`docs/IGA.md` §"Configuring thresholds"); only the `tide` attestor's
realm-level default flips to the dynamic 0.7 floor. The per-scope-entity
`iga.threshold` override (set together with `iga.approverRole` — the same-entity
coupling rule) and the ADOPT_* short-circuit still win, because the sketch
consults `resolveThreshold` first and only falls through to the dynamic floor
when no scoped/ADOPT value applies. See §12 Q8 for why this split is
load-bearing.

#### 3.6.1 Worked examples

| `activeTideRealmAdmins` | `(int)(0.7 × n)` | `Math.max(1, …)` |
|---|---|---|
| 1 | 0 | **1** |
| 2 | 1 | **1** |
| 3 | 2 | **2** |
| 4 | 2 | **2** |
| 5 | 3 | **3** |
| 10 | 7 | **7** |
| 100 | 70 | **70** |

### 3.7 Counting active tide-realm-admins

The "active tide-realm-admin" predicate (verbatim from spec):

> User holds the `tide-realm-admin` role AND is enabled AND has a committed Tide identity (not a pending CR).

The three sub-predicates and how each is checked in iga-core. Note this is
**stricter** than legacy's `numberOfActiveAdmins` (legacy
`ChangesetRequestAdapter.getNumberOfActiveAdmins` at `:196-207` filtered role
members only by the existence of an `ACTIVE` `TideUserRoleMappingDraftEntity`,
and did not gate on `isEnabled()`):

| Sub-predicate | Check | Source / call site |
|---|---|---|
| **Role: holds `tide-realm-admin`** | Resolve the role via `realm.getClientByClientId("realm-management").getRole("tide-realm-admin")`, then iterate members via `session.users().getRoleMembersStream(realm, role)`. The `getRoleMembersStream` pattern is already in use at `iga-core/.../rest/TideAdminCompatResource.java:754, 767` for `manage-realm` / approver-role coverage counting. | `session.users().getRoleMembersStream(RealmModel, RoleModel)` |
| **Enabled** | `user.isEnabled()` on each returned `UserModel`. | Standard KC `UserModel`. |
| **Committed Tide identity (NOT a pending CR)** | **Found.** The canonical "committed" signal in current iga-core is the **`ATTESTATION` column being non-null on the `USER_ROLE_MAPPING` row** for `(user, tide-realm-admin)`. A role grant only stamps that column at replay/commit (the skill's "relationship CRs stamp the linkage row `USER_ROLE_MAPPING(uid,rid)`"); a still-PENDING `GRANT_ROLES` CR applies **nothing** (the scratch row is rolled back), so the linkage row either does not exist or has `attestation IS NULL`. The inverse query — unsigned/pending rows — is `IgaUnsignedRowScanner.userRoleMappings` at `IgaUnsignedRowScanner.java:541-547` (`SELECT urm.user.id, urm.roleId FROM UserRoleMappingEntity urm WHERE urm.user.realmId = ?1 AND urm.attestation IS NULL`). The committed check is therefore: a `UserRoleMappingEntity` exists for `(u.getId(), tideRoleId)` with `attestation IS NOT NULL`. This single signal collapses BOTH the "committed Tide identity" and "not a pending CR" sub-predicates: a committed (stamped) grant is exactly a non-pending one. iga-core has **no** separate per-user `tideUserKey` / `tideEnrolled` / `TIDE_USER` attribute (verified via grep on 2026-06-01) — the ATTESTATION-on-the-grant-edge is the authoritative committed marker. |

Reference helper sketch:

```java
private static int countActiveTideRealmAdmins(RealmModel realm, KeycloakSession session) {
    ClientModel rm = realm.getClientByClientId("realm-management");
    if (rm == null) return 0;
    RoleModel tideAdmin = rm.getRole("tide-realm-admin");
    if (tideAdmin == null) return 0;

    // (user id, role id) pairs whose USER_ROLE_MAPPING.attestation IS NOT NULL
    // — the committed/stamped tide-realm-admin grants. Inverse of
    // IgaUnsignedRowScanner.userRoleMappings (IgaUnsignedRowScanner.java:541-547).
    Set<String> committedAdminUserIds = committedTideAdminUserIds(session, realm, tideAdmin.getId());

    return (int) session.users().getRoleMembersStream(realm, tideAdmin)
            .filter(UserModel::isEnabled)
            .filter(u -> committedAdminUserIds.contains(u.getId()))  // committed grant only (not PENDING)
            .count();
}

// SELECT urm.user.id FROM UserRoleMappingEntity urm
//   WHERE urm.user.realmId = :realmId AND urm.roleId = :roleId
//     AND urm.attestation IS NOT NULL
```

### 3.8 `isSetSigned()` — unchanged

Returns `true` for the `tide` factory regardless of mode (`TideAttestor.java:71-74`). Both `firstAdmin` and `multiAdmin` produce the same set/node canonical shape — only the **signing algorithm** changes, not the per-row fan-out semantics that `IgaReplayDispatcher` reads off this flag (`IgaReplayDispatcher.java:158-166, 1191`).

---

## 4. Schema migration

### 4.1 Migration mechanism in iga-core

iga-core uses **Liquibase XML changelogs** under `iga-core/src/main/resources/META-INF/`:
- Master changelog (the include list) is `iga-changelog-master.xml`; it is a pure
  aggregating `<include>` list of 16 per-version files (`1.0.0`→`2.4.0`), no
  changeSets of its own (`iga-changelog-master.xml:7-22`).
- Per-version files are named `iga-changelog-<semver>.xml`; the most recent is `iga-changelog-2.4.0.xml` (which added the ORG ATTESTATION column for the producer roadmap — see `iga-changelog-2.4.0.xml:32-36`).
- **VERIFIED 2026-06-01 — the changelog path is returned by the *provider*, NOT
  the *factory*.** `IgaJpaEntityProviderFactory` (`IgaJpaEntityProviderFactory.java`)
  is a thin factory with only `create/getId/init/postInit/close` — it has **no**
  changelog method. The path comes from `IgaJpaEntityProvider.getChangelogLocation()`
  which returns the master changelog literal `"META-INF/iga-changelog-master.xml"`
  (`IgaJpaEntityProvider.java:36-38`); `IgaJpaEntityProvider.getEntities()` also
  lists `IgaAuthorizerEntity.class` among the 10 registered entities
  (`IgaJpaEntityProvider.java:20-32`). Keycloak's standard `JpaUpdaterProvider`
  loads that master changelog and runs each included file's changeSets.

The migration pattern for adding a column is well-trodden (compare
`iga-changelog-2.3.1.xml:29-33` for the `SCOPE_MAPPING.ATTESTATION` add and
`iga-changelog-2.4.0.xml:32-36` for `ORG.ATTESTATION`).

**Concrete mechanism to add the `mode` column (VERIFIED).** Two coordinated
edits, both in iga-core, plus one registration line:
1. **New versioned changelog file** `iga-changelog-2.5.0.xml` (§4.2) containing
   the `<addColumn tableName="IGA_AUTHORIZER">` changeSet. It is a **new file**,
   not an appended changeSet on an existing file — every prior column add follows
   the one-file-per-version convention (2.3.0/2.3.1/2.4.0 each got their own file).
2. **Register it in the master `<include>` list** by appending
   `<include file="META-INF/iga-changelog-2.5.0.xml"/>` after the 2.4.0 include
   line in `iga-changelog-master.xml:22`. This registration is **mandatory** — the master
   is a literal include list (no glob), so an unincluded file is never run.
3. **The JPA `@Column`** on `IgaAuthorizerEntity` (§4.3, `IgaAuthorizerEntity.java`).
   The Liquibase column add (edit 1+2) and the JPA `@Column` (edit 3) are the two
   coordinated schema edits; `IgaJpaEntityProvider.java` needs **no** edit (the
   entity is already registered there and the changelog path is already the master).

### 4.2 New changelog: `iga-changelog-2.5.0.xml`

Create file `iga-core/src/main/resources/META-INF/iga-changelog-2.5.0.xml`:

```xml
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<databaseChangeLog xmlns="http://www.liquibase.org/xml/ns/dbchangelog"
                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                   xsi:schemaLocation="http://www.liquibase.org/xml/ns/dbchangelog
                   http://www.liquibase.org/xml/ns/dbchangelog/dbchangelog-3.1.xsd">

    <!--
      2.5.0: Add a MODE column to IGA_AUTHORIZER.

      Two values today: "firstAdmin" (single-signer bootstrap) and
      "multiAdmin" (T-of-N steady-state). Default for existing rows is
      "multiAdmin" so existing realms do NOT retro-trigger the bootstrap
      signing path on next CR commit (see firstadmin-multiadmin-port-plan.md
      §9 for the rollout justification).
    -->

    <changeSet id="iga-2.5.0-1" author="tidecloak-iga">
        <addColumn tableName="IGA_AUTHORIZER">
            <column name="MODE" type="VARCHAR(32)" defaultValue="multiAdmin">
                <constraints nullable="false"/>
            </column>
        </addColumn>
    </changeSet>

</databaseChangeLog>
```

And add the include to `iga-changelog-master.xml`:

```xml
<include file="META-INF/iga-changelog-2.5.0.xml"/>
```

`defaultValue="multiAdmin"` + `nullable="false"` is the rollout-safe choice:
existing rows backfill to `multiAdmin` (no retro-bootstrap on the next
commit); new rows can opt into `firstAdmin` via §9's bootstrap path.

### 4.3 JPA entity diff (`IgaAuthorizerEntity`)

Add field + accessor; namedQuery additions optional. Diff against `IgaAuthorizerEntity.java:34-78`:

```java
@Column(name = "MODE", length = 32, nullable = false)
private String mode = "multiAdmin";

public String getMode() { return mode; }
public void setMode(String mode) { this.mode = mode; }
```

The Java-side default (`= "multiAdmin"`) mirrors the SQL-side
`defaultValue` so an entity built via `new IgaAuthorizerEntity()` without an
explicit `setMode` call is well-defined.

No new `@NamedQuery` is strictly required — the new field is read off the
existing `IgaAuthorizer.findByRealm` result (`IgaAuthorizerEntity.java:14-16`).
A convenience query `IgaAuthorizer.findByRealmAndMode` would mirror the
existing `findByRealmAndType` (`IgaAuthorizerEntity.java:21-24`) and is
trivial to add later if call sites need it; not needed by this design.

---

## 5. VRK plumbing port

**Framing correction (2026-06-01).** This is **not** "port a local key
accessor." The VRK is sharded across the ORK network; signing with it is a
**network operation** that routes Midgard → ORK. So the plumbing to port is the
**VRK signing call together with the ORK-network configuration it needs** — the
`tide-vendor-key` component supplies not just the key bytes (`activeVrk`) but
the ORK endpoint (`systemHomeOrk` → `settings.HomeOrkUrl`), the VVK id
(`vvkId` → `settings.VVKId`), the payer public (`payerPublic`), and the
obfuscated vendor key (`obfGVVK`). The accessor must read **all** of these, not
just the private-key bytes, because `Midgard.SignWithVrk` ultimately dials the
ORKs through the native core (§5.1 below).

### 5.1 Legacy accessor + where the network boundary actually is

There is **no single legacy "VRK accessor" class**. The access pattern is
**inlined** at multiple call sites with the same shape (component lookup +
JSON deserialize + field read). Canonical seven-step sequence, lifted from
`MultiAdmin.java:474-484` + `MultiAdmin.java:90-95`:

```java
// 1. Locate the realm's tide-vendor-key component.
ComponentModel componentModel = realm.getComponentsStream()
        .filter(x -> "tide-vendor-key".equals(x.getProviderId()))
        .findFirst()
        .orElse(null);
if (componentModel == null) {
    throw new BadRequestException("There is no tide-vendor-key component set up for this realm, " + realm.getName());
}

// 2. Pull its config map.
MultivaluedHashMap<String, String> config = componentModel.getConfig();

// 3. Deserialize clientSecret blob to SecretKeys.
String currentSecretKeys = config.getFirst("clientSecret");
SecretKeys secretKeys = new ObjectMapper().readValue(currentSecretKeys, SecretKeys.class);

// 4. The active VRK is the base64/hex private key.
String vrkPrivateKey = secretKeys.activeVrk;
```

`SecretKeys` has four fields (`SecretKeys.java:6-16`):
- `activeVrk` — the active VRK private key (what we sign with),
- `pendingVrk` — pre-rotation key,
- `VZK` — vendor zero key,
- `history` — past keys.

`Midgard.SignWithVrk(payload, vrk)` is the signing call (`IGAUtils.java:57-59, 113-115`); legacy depends on the optional `org.tide:MidgardJava` maven artifact under the `tide-iga` profile (`tidecloak-iga-extensions-old/tidecloak-iga-provider/pom.xml:103-131`).

**Where the ORK network boundary is — verified 2026-06-01.** The Java
signature `Midgard.SignWithVrk(String msg, String vrk)` (`Midgard.java:160-167`)
looks like a pure local key sign — it takes only the message and the private-key
string and returns signature bytes. **That appearance is an indirection.**
`SignWithVrk` delegates to the JNA binding `Interface.sign_with_vrk(msg, vrk)`
(`MidgardInterface.java:14`), which crosses into Midgard's **native C# core**
(`MidgardCore.so`/`.dll`). Per the Midgard project architecture, the native core
delegates to Flow classes that use **HTTP clients to ORK nodes**
(`Midgard/Core/Clients/NodeClient`, `NetworkClient`; `Midgard/Core/Flows/.../Network`).
The VRK is sharded across the ORK network via threshold crypto, so the actual
sign happens **on the ORK network**, not on the bytes of `activeVrk` alone. The
ORK endpoint the native core dials comes from `settings.HomeOrkUrl`
(`= keyProviderConfig.getFirst("systemHomeOrk")`, `IGAUtils.java:44, 102`) and
`settings.VVKId` (`IGAUtils.java:43, 101`).

**Net: the network boundary is *inside* Midgard's native core, not visible in
the Java `SignWithVrk` signature.** The Java call site passes key + config and
gets bytes back, but a reachable ORK network is required for the call to
succeed. This is exactly the indirection that made the earlier "firstAdmin is
local" reading plausible — the Java surface hides it. (See §12 Q3, RESOLVED.)

### 5.2 Target landing site in iga-core

A new package `org.tidecloak.iga.crypto` holding two files:

```
iga-core/src/main/java/org/tidecloak/iga/crypto/
    SecretKeys.java       // ported verbatim from shared-models (4 public fields,
                          //   activeVrk/pendingVrk/VZK/history)
    VrkAccessor.java      // static helpers: readVrkSignSettings(session, realm)
                          //                 signWithVrk(payload, settings)
```

`VrkAccessor.readVrkSignSettings(KeycloakSession, RealmModel)` runs steps 1-3
of §6.1 and returns **the full ORK-signing settings bundle**, not just key
bytes: `activeVrk` (the private key) **plus** the ORK-network config the native
Midgard core needs — `HomeOrkUrl` (from component `systemHomeOrk`), `VVKId`
(from `vvkId`), `PayerPublicKey` (from `payerPublic`), `ObfuscatedVendorPublicKey`
(from `obfGVVK`). This mirrors legacy's `SignRequestSettingsMidgard` build at
`IGAUtils.java:42-49`. `VrkAccessor.signWithVrk(payload, settings)` delegates to
`Midgard.SignWithVrk(payload, settings.activeVrk)` — which, as established in
§5.1, **dials the ORK network** inside the native core; the call therefore needs
the ORKs reachable and the `HomeOrkUrl`/`VVKId` correctly populated, NOT merely
a valid private key. (Bundling the ORK config in `readVrkSignSettings` rather
than passing raw `byte[] vrk` is the surgically-correct shape: it makes the
network dependency explicit at the call site instead of hiding it behind a
key-bytes parameter.)

Why `crypto/` rather than a `vrk/` subpackage: the next consumer of the VRK
plumbing — the future Midgard `signClaims()` swap that replaces the
multiAdmin SHA-256 stub at `TideAttestor.java:351-358` — also lives in the
same conceptual space (signing primitives backed by realm-scoped key
material **and the same ORK network**). One subpackage for both keeps the
import surface small.

### 5.3 Dependency surface to add to `iga-core/pom.xml`

The current `iga-core/pom.xml:26-101` declares **no Midgard / Tide
dependency**. Adding the VRK signing path needs:

```xml
<!-- Midgard Java client — provides Midgard.SignWithVrk + Midgard.SignModel +
     SignRequestSettingsMidgard. Optional and provided so non-Tide deployments
     still build cleanly without the artifact on the local maven cache.

     The legacy pom guarded this behind a `tide-iga` profile
     (tidecloak-iga-extensions-old/tidecloak-iga-provider/pom.xml:103-131);
     iga-core has no need for that split today — the multiAdmin path is the
     same crypto target, and the optional flag plus provided scope keep the
     classpath behaviour the same. -->
<dependency>
    <groupId>org.tide</groupId>
    <artifactId>MidgardJava</artifactId>
    <version>1.0-SNAPSHOT</version>
    <optional>true</optional>
    <scope>provided</scope>
</dependency>
```

If the build fleet doesn't have `MidgardJava` available, `VrkAccessor`
methods are wired to throw `UnsupportedOperationException("Midgard not on classpath")` and the firstAdmin branch hard-fails on use — that is acceptable: firstAdmin signing **requires** Midgard **and a reachable ORK network**, while the rest of `iga-core` today (multiAdmin's SHA-256 stub path, the producer, the replay dispatcher) does not depend on Midgard *yet*. Note this is a **build-time / classpath** axis only; it is **orthogonal** to the **runtime** ORK-reachability dependency. Even with `MidgardJava` on the classpath, firstAdmin signing still fails at runtime if the ORKs are down (the same M2M-503 failure mode as multiAdmin once its `sign()` is wired to Midgard — see §6.5 and §12 Q3). Do not read "multiAdmin's stub doesn't need Midgard" as "multiAdmin avoids the ORK network": that is only true while it is a stub; the moment the `sign(byte[])` swap-point lands `Midgard.signClaims()`, multiAdmin too requires reachable ORKs.

### 5.4 Test seam

Because firstAdmin signing is a **Midgard → ORK network** call (§5.1), a unit
test cannot exercise it green without **either** a reachable ORK network **or**
a test-double that stands in for the Midgard→ORK round-trip. The seam: expose a
package-private `VrkAccessor.installTestOverride(BiFunction<byte[], VrkSignSettings, byte[]> signer)`
that the test calls to swap in a deterministic stub (e.g. HMAC-SHA-256 over
`"TEST-VRK"`) **in place of the Midgard→ORK call**. This is a Midgard/ORK
test-double, not "signing without a key" — it stubs the network boundary
identified in §5.1. Production paths never call `installTestOverride`. This
mirrors the existing dummy-prefix pattern (`DUMMY_SIG_PREFIX` at `TideAttestor.java:56`) that already lets tests assert on signature byte-shape without a live ORK network. (See §10 for which scenarios need this stub vs which can stub `sign()` wholesale.)

---

## 6. firstAdmin signing branch

### 6.1 What legacy `IGAUtils.signInitialTideAdmin` does

Reference: `IGAUtils.java:26-84`. The full sequence:

1. Read `clientSecret` from the `tide-vendor-key` component config; deserialize to `SecretKeys` (`IGAUtils.java:32-34`).
2. Read T/N from `System.getenv("THRESHOLD_T" / "THRESHOLD_N")` (`IGAUtils.java:35-40`). **In the port there is no T/N read at all: firstAdmin returns constant 1 (§3.5), and multiAdmin computes its threshold dynamically (§3.6) from the active-tide-realm-admin count (§3.7). No `System.getenv`, no stored `tideThreshold`, no realm attribute for the multiAdmin threshold.**
3. Build `SignRequestSettingsMidgard` with the seven realm-component fields: `vvkId`, `systemHomeOrk`, `payerPublic`, `obfGVVK`, `activeVrk` (the `secretKeys.activeVrk` from step 1), `Threshold_T`, `Threshold_N` (`IGAUtils.java:42-49`).
4. Build a `UserContextSignRequest("VRK:1")` and load `draft` + the user-context array onto it (`IGAUtils.java:51-55`).
5. `SetAuthorization(Midgard.SignWithVrk(req.GetDataToAuthorize(), settings.VendorRotatingPrivateKey))` — this is the **first** VRK signature and the bootstrap key step (`IGAUtils.java:57-59`). **This is a Midgard → ORK network call** (§5.1): `settings` was built with `HomeOrkUrl`/`VVKId` at step 3, and the native core dials those ORKs; it is not a local sign over `VendorRotatingPrivateKey` bytes.
6. Set the `Authorizer` + `AuthorizerCertificate` on the request from the `AuthorizerEntity` row (`IGAUtils.java:61-62`).
7. Call `Midgard.SignModel(settings, req)` → `SignatureResponse` holding one signature per user-context (`IGAUtils.java:64-70`).
8. Build a **second** request `PolicySignRequest(policy.ToBytes(), "VRK:1")`, run the same VRK-authorize + Midgard.SignModel cycle, and append its signature **last** to the returned list (`IGAUtils.java:72-80`).

What the port keeps **verbatim**: steps 1, 3, 5 — the realm-component VRK lookup, the threshold settings, the `Midgard.SignWithVrk` call shape.

What the port **adapts**: steps 4, 7, 8 — there is no more `UserContextSignRequest` because user contexts are gone. Instead:

- The "rows/units" CR case uses the **same canonical-bytes shape** the current `TideAttestor` already produces (`canonicalizeLinkageSet` / `canonicalizeNode` at `TideAttestor.java:153-232`). Sign those bytes directly with `Midgard.SignWithVrk(canonical, activeVrk)`. **No** `UserContextSignRequest` wrapper.
- The "tide-realm-admin policy" CR case (§6.2) replaces step 8: the policy payload is the role-policy bytes stored on `IgaRolePolicyEntity.policy` (`IgaRolePolicyEntity.java:50-51`), and the resulting signature is written back to `IgaRolePolicyEntity.policySig` (`IgaRolePolicyEntity.java:53-54`).

What the port **drops**: step 7's per-user-context loop. There are no per-context signatures because there are no user contexts.

### 6.1a CR→signing-payload resolution — reuse `IgaFirstAdminSignPreviewService`

**Decision 3 — RESOLVED `session:2026-06-01 with user`. Reuse the existing
payload builder; do NOT build a second one.** `iga-core` already contains a
service that resolves a CR to its full signing payload with all foreign keys
expanded to full entity data, and logs it — `IgaFirstAdminSignPreviewService`
(`IgaFirstAdminSignPreviewService.java:42-519`). It is explicitly the FirstAdmin
signing-flow prototype (class javadoc + the file-header `TODO: when
Midgard.signClaims() is ready, replace logger.info call with the real sign +
persist signature flow`, `IgaFirstAdminSignPreviewService.java:3-6`) — i.e. it
was written to become exactly this branch's payload stage. It performs **no
cryptography today** (it logs the resolved payload; the Midgard call is the TODO).

**What its payload builder actually produces + signature.** The public entry is
`Map<String,Object> buildAndLog(String changeRequestId)`
(`IgaFirstAdminSignPreviewService.java:78`), which looks the CR up by id, guards
the realm, then delegates to the **private** assembler
`Map<String,Object> build(IgaChangeRequestEntity cr)`
(`IgaFirstAdminSignPreviewService.java:97-110`). `build()` returns a
`LinkedHashMap` with the FK-expanded sections:
- `changeRequest` — the CR header + parsed `rows` (`:99, :112-124`),
- `subject` — the resolved subject entity (USER/GROUP/ROLE/CLIENT) (`:100, :130-141`),
- `subjectState` — for USER CRs, the user's current realm/client roles + groups +
  effective-role expansion (`:101-103, :241-292`),
- `resolvedRows` — **per-row FK expansion**, e.g. `GRANT_ROLES`/`REVOKE_ROLES`
  rows expanded to the full user + role (with composites) + that role's policy
  (`:104-105, :311-379`),
- `rolePolicies` — every `IgaRolePolicyEntity` reachable from the CR's roles,
  including `policy`, `policySig`, `threshold`, and the linked Forseti contract
  (`:106, :385-437`),
- `authorizers` — the realm's `IgaAuthorizerEntity` rows (`:107, :443-454`),
- `existingAuthorizations` — the `IgaAuthorizationEntity` records already recorded
  against the CR (`:108, :456-470`).

**How §6 wires it.** TideAttestor's firstAdmin branch calls the preview service
for **CR→signing-payload resolution** instead of re-deriving FK expansion
locally:
1. TideAttestor (or `combineFinal`) constructs/obtains an
   `IgaFirstAdminSignPreviewService` for `(em, session, realm, …services)` and
   calls its payload builder for the CR — see the extraction note below.
2. The builder returns the FK-expanded `Map<String,Object>` (the attested
   rows/units payload). TideAttestor canonicalises **that** and feeds the bytes to
   the VRK sign (§5 / §3.4) — the **Midgard → ORK VRK sign is bolted on inside
   TideAttestor** (it is a network op per the corrected §5/§6/Q3, **not** done by
   the preview service, which has no crypto). The preview service's
   `log.infof("[FirstAdmin sign preview] …")` (`:86`) is the placeholder the real
   sign+persist replaces — i.e. the `TODO` at `:3-6` is discharged by routing the
   builder's output into TideAttestor's `sign(byte[])` rather than into a log line.

**Extraction note (small refactor the implementation performs).** The payload
logic is currently `private` and welded to the logging entry point
(`build(...)` at `:97` is private; the only public door is `buildAndLog(...)` at
`:78`, which *also* logs). To reuse it cleanly **without** logging on every
production sign, the implementation should **extract the payload assembly into a
reusable public method** — e.g. promote `build(IgaChangeRequestEntity)` to public
(or add `Map<String,Object> buildPayload(String changeRequestId)` that does the
find+guard of `buildAndLog` minus the `log.infof`), and have `buildAndLog` call
it. This avoids **two parallel payload builders that can drift** — the whole point
of Decision 3. The signing branch calls the extracted method; the existing
`/sign-preview` debug endpoint keeps calling `buildAndLog`.

**Which payload kind goes through which builder — see §6.2/§6.3.** The two
firstAdmin-era payload kinds are routed as follows: the **tide-realm-admin POLICY
CR** signs the policy bytes directly (§6.2 — *not* the preview builder's map;
see the reconciliation in §6.2), while **every other firstAdmin-era CR** (the
attested rows/units) is resolved through this preview-service payload builder
(§6.3). Both then sign via the same VRK → Midgard → ORK path inside TideAttestor.

### 6.2 Tide-realm-admin policy payload

The role-policy storage is `IgaRolePolicyEntity` (`IgaRolePolicyEntity.java:38-112`):

- `policy` — `@Column(name = "POLICY", columnDefinition = "TEXT", nullable = false)` (`IgaRolePolicyEntity.java:50-51`).
- `policySig` — `@Column(name = "POLICY_SIG", length = 512, nullable = false)` (`IgaRolePolicyEntity.java:53-54`).

The payload to sign for the bootstrap CR is the **`policy` column value
verbatim, as UTF-8** — VERIFIED, the legacy base64-decode does **NOT** apply.

**Byte-shape resolution (VERIFIED 2026-06-01).** Legacy treated the stored value
as a base64-encoded Midgard `Policy` blob and decoded it before signing
(`FirstAdmin.java:56-57`: `Policy.From(Base64.getDecoder().decode(tideRoleEntity.getInitCert()))`),
because legacy itself **stored** `policy.ToBytes()` base64 on `initCert`
(`TideRoleRequests.java:171-176, 232-235`). **New-world iga-core does NOT
base64-encode on the way in**, so there is nothing to decode:
- **Column shape.** `policy` is `@Column(name = "POLICY", columnDefinition = "TEXT", nullable = false)`,
  a plain `String` with **no JPA `@Convert`/converter** (`IgaRolePolicyEntity.java:50-51`;
  the entity declares zero converters).
- **Ingest is verbatim.** `POST /iga/role-policies` (`IgaAdminResource.upsertRolePolicy`,
  `@Path("role-policies")` at `IgaAdminResource.java:1154-1155`) only null/blank-checks
  `policy` (`:1171-1175`) and passes `rep.getPolicy()` straight through
  (`:1187-1190`) to `IgaRolePolicyService.upsert`, which does
  `entity.setPolicy(policy)` with **no** base64/JSON/transform
  (`IgaRolePolicyService.java:35, 52`). The stored string is byte-for-byte what
  the caller POSTed.
- **No decode anywhere.** Grep on 2026-06-01: iga-core has **no** `Base64.decode`
  of the role policy — the only two `Base64` sites are a JWT-segment decode in
  `IgaTveBundleResource.java:428` and signature *encoding* in `TideAttestor`,
  neither touching `IgaRolePolicyEntity.policy`. The firstAdmin sign-preview
  prototype likewise reads `policy.getPolicy()` as an opaque string
  (`IgaFirstAdminSignPreviewService.java:413`).

**Conclusion (CONFIRMED): sign the UTF-8 bytes of the stored `policy` string
verbatim** — `Midgard.SignWithVrk(policy.getBytes(StandardCharsets.UTF_8), activeVrk)`.
The legacy `Base64.getDecoder().decode(...)` step is **dropped** (it existed only
to undo legacy's own base64 store, which iga-core does not perform). The shape
contract is "whatever the caller stored as `policy`, those same bytes go into
Midgard.SignWithVrk." If a future caller chooses to store base64 there, that is
the caller's convention and the signer still treats it opaquely — the signer does
not impose or assume an encoding.

**Routing vs the preview-service builder (§6.1a).** This is the **first** of the
two firstAdmin payload kinds and it does **not** go through
`IgaFirstAdminSignPreviewService`'s FK-expansion map: for the tide-realm-admin
**POLICY** CR the payload is the **policy bytes themselves**
(`IgaRolePolicyEntity.policy.getBytes(UTF_8)`), signed verbatim as concluded
above. The preview builder is the right tool for resolving *CR row state* into an
attested payload (§6.3) — but the bootstrap policy sign is signing a *governance
parameter* (the policy body), not the CR's relational rows, so it bypasses the
map builder and signs the stored `policy` column directly. (The preview builder
*does* surface this same `policy`/`policySig` in its `rolePolicies` section at
`IgaFirstAdminSignPreviewService.java:413-414`, but as **context**, not as the
byte string fed to the signer.) Both kinds still terminate on the same VRK →
Midgard → ORK sign inside TideAttestor (§5/§3.4).

Detection signal — "this CR is the tide-realm-admin policy CR" — is covered in §7.1.

### 6.3 Non-policy CR canonical

Already what today's attestor produces. The port adds **nothing new** to the
canonical shape for the non-policy firstAdmin path — it just routes through
the **real** `Midgard.SignWithVrk` rather than the SHA-256 stub. The
dispatcher's per-row / set-fan-out semantics (`IgaReplayDispatcher.replay`
gated on `isSetSigned()` at `IgaReplayDispatcher.java:158-166`) need no
change because the signature **string** is opaque to them — only its
provenance (which `sign(byte[])` produced it) changes.

**This is the *second* firstAdmin payload kind (Decision 3 / §6.1a) — the
attested rows/units.** CR→payload resolution for these non-policy firstAdmin CRs
runs through the **reused** `IgaFirstAdminSignPreviewService` payload builder
(the extracted `build(IgaChangeRequestEntity)` / `buildPayload(...)` method,
§6.1a) — *not* a second, parallel resolver inside TideAttestor. The builder's
FK-expanded map IS the rows/units payload; TideAttestor canonicalises it (the
same set/node canonical the attestor already emits, `canonicalizeLinkageSet` /
`canonicalizeNode` at `TideAttestor.java:153-232`) and signs the bytes with the
**real** `Midgard.SignWithVrk` (§5/§3.4). So §6.3's "nothing new in the canonical
shape" still holds — the novelty is *where the resolved payload comes from* (the
shared preview builder, per Decision 3) and *which signer* runs it (VRK → ORK, not
the stub), never the canonical byte layout.

### 6.4 Return shape

Legacy `IGAUtils.signInitialTideAdmin` returns `List<String>` (`IGAUtils.java:26`) with one entry per user-context plus a trailing entry for the policy. **In the port that list collapses to a single string** because there is only one canonical to sign per CR (no per-context fan-out).

The persisted-signature shape:

- For a non-policy CR: the returned `TIDE-FIRSTADMIN-v1:<base64>` string lands in the `ATTESTATION` column of the affected entity / set rows, exactly the way today's `TIDE-DUMMY-v1:...` does via the dispatcher (e.g. `IgaReplayDispatcher.java:182, 326, 419`).
- For the tide-realm-admin policy CR: the signature lands in `IgaRolePolicyEntity.policySig` (`IgaRolePolicyEntity.java:53-54`). **In addition** the same string is written to the CR's `ATTESTATION` slot via the dispatcher's normal stamp — the policy CR is a CR like any other and gets stamped as such.

The `TIDE-FIRSTADMIN-v1:` prefix is mandatory: it lets the future signature-verifier distinguish a single-signer (1-of-1 admin quorum) VRK signature (firstAdmin bootstrap) from a multiAdmin enclave-threshold signature without parsing the body. (The prefix marks the **quorum + ceremony**, not "local vs network" — both signatures come back from the ORK network.)

### 6.5 Failure mode when the ORKs are unreachable

Because firstAdmin signing is a Midgard → ORK call (§5.1, §3.4), it has the
**same ORK-reachability failure mode as multiAdmin** will once multiAdmin's
`sign(byte[])` is wired to Midgard. If the ORK network is unreachable,
`Midgard.SignWithVrk` fails (returns null / throws inside the native core), and
`combineFinal` cannot produce a signature — the CR commit fails. This is the
**same M2M-503 / "Midgard signing unavailable" path** that the pending
`Midgard.signClaims()` blocker introduces for multiAdmin (§12 Q3). firstAdmin is
**not** a way to commit CRs while the ORKs are down. The port should surface
this as a clean error (propagate a 503-class failure to the commit endpoint),
mirroring whatever the multiAdmin swap-point will do — the two modes should
share one ORK-unreachable error path, since they share the same dependency.

### 7.1 Detecting "this is the tide-realm-admin policy CR"

The most reliable signal — and the one legacy used — is **the role assignment itself**: a `GRANT_ROLES` CR whose row carries the realm-management client's `tide-realm-admin` role id.

Legacy detection: `FirstAdmin.isAssigningTideRealmAdminRole` (`FirstAdmin.java:160-167`):

```java
RoleModel tideRole = session.getContext().getRealm()
    .getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID)
    .getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
return tideUserRoleMappingDraftEntity.getRoleId().equals(tideRole.getId());
```

Port-side detection runs against the live KC model + the CR's parsed rows:

```java
private static boolean isTideRealmAdminAssignment(KeycloakSession session, RealmModel realm,
                                                   IgaChangeRequestEntity cr) {
    if (!"GRANT_ROLES".equals(cr.getActionType())) return false;
    ClientModel realmMgmt = realm.getClientByClientId("realm-management");
    if (realmMgmt == null) return false;
    RoleModel tideRole = realmMgmt.getRole("tide-realm-admin");
    if (tideRole == null) return false;
    for (Map<String, Object> row : parseRows(cr.getRowsJson())) {
        if (tideRole.getId().equals(str(row, "ROLE_ID"))) return true;
    }
    return false;
}
```

(`GRANT_ROLES` rows carry `USER_ID` + `ROLE_ID` per `IgaReplayDispatcher.java:181-184`.)

**Alternative detection signal — role-policy upsert.** Today's REST
`POST /iga/role-policies` (`IgaAdminResource.java:1154-1198`) bypasses the CR
machinery entirely (it directly persists a row). If a future change captures
role-policy upserts as their own CRs, the detection would switch to
`actionType == "UPSERT_ROLE_POLICY"` with the CR's `entityId == tideRoleId`.
For now the only signal that flips the realm into multiAdmin mode is the
**role assignment** itself, matching legacy exactly.

The string constant `"tide-realm-admin"` should be lifted into a constants
class (e.g. `org.tidecloak.iga.crypto.IgaConstants`) when the VRK package
lands; the legacy `Constants.TIDE_REALM_ADMIN` (`Constants.java:6`) is the source of truth.

### 7.2 Where the flip happens

End of `TideAttestor.combineFinal`, **after** the signature succeeds but
**before** returning the string to the caller (so the dispatcher's CR-status
flip and the ATTESTATION write happen in the same JPA transaction as the
mode flip):

```java
@Override
public String combineFinal(KeycloakSession session, IgaChangeRequestEntity cr,
                           List<IgaAuthorizationEntity> authorizations) {
    RealmModel realm = session.realms().getRealm(cr.getRealmId());
    String mode = resolveMode(session, realm);   // §3.1: "firstAdmin" (row or no-row tide) | "multiAdmin" | null (non-tide, unreachable here)

    // Constant-first equals() so a null mode (the §3.1 non-tide no-op return,
    // which combineFinal never actually sees because the tide attestor is only
    // resolved for iga.attestor=="tide") cannot NPE.
    byte[] canonical = ("firstAdmin".equals(mode) && isTideRealmAdminAssignment(session, realm, cr))
            ? readPolicyBytes(session, realm)
            : canonicalForRegularCr(session, cr);

    String sig = sign(session, realm, mode, canonical);

    // Idempotency + transition (firstAdmin only)
    if ("firstAdmin".equals(mode)) {
        if (isTideRealmAdminAssignment(session, realm, cr)) {
            writeBackPolicySig(session, realm, sig);
            flipModeToMultiAdmin(session, realm);
        }
    }
    return sig;
}
```

**This sketch is the *first* policy sign, not the only one.** The
`writeBackPolicySig` + `flipModeToMultiAdmin` branch above fires **once**, on the
firstAdmin→multiAdmin bootstrap. Every **subsequent** membership change in
multiAdmin mode re-writes the **same** `IgaRolePolicyEntity.policy`/`.policySig`
columns under the *new* threshold — the regeneration cycle is specified in
**§7a** (trigger events, who signs, idempotency, ORK-failure). Read §7's
"first policy sign" as "the **first of many**": this bootstrap is sign #1; §7a
governs signs #2…n. The multiAdmin branch of `combineFinal` does **not** flip
mode (it is already multiAdmin) but **does** invoke the §7a regen-on-membership-
change side-effect when the committing CR moves `floor(0.7 × activeAdmins)`.

**Reconciliation with the lazy seed (Decision 2, §9.3).** `flipModeToMultiAdmin`
writes the `mode` **column** of the realm's `IgaAuthorizerEntity` row — so by the
time the flip runs, **the row must exist**. It always does: the lazy seed runs in
`TideAttestor.record()` (§9.3), which fires on **every** admin authorization for
the CR, strictly **before** `combineFinal` (and therefore before the flip) is
reached at commit. So the sequence for a brand-new Tide realm whose first
governed action is the tide-realm-admin policy CR is, in order: (1) first
`record()` → no row + `iga.attestor=="tide"` → **lazily seed the row
`mode="firstAdmin"`** (D12); (2) threshold check via `getThreshold` reads
`firstAdmin` → quorum 1 (§3.5); (3) `combineFinal` signs the policy bytes (§6.2),
**writes `policySig`**, and **flips the seeded row's `mode` column to
`multiAdmin`** (§7.2) — all in one JPA transaction (§7.3). The lazy seed
(firstAdmin) and the transition trigger (firstAdmin→multiAdmin) are therefore
**not** in conflict: the seed *establishes* the firstAdmin state the transition
then *consumes*. If the realm's first post-port CR is **not** the tide-realm-admin
policy CR, the row is seeded `firstAdmin`, that CR signs under the firstAdmin
branch with **no** flip, and the flip waits for the eventual tide-realm-admin
policy CR — unchanged §7 semantics.

### 7.3 Atomicity

Both the ATTESTATION write and the mode flip happen inside Keycloak's
**caller-owned JPA transaction** that wraps `IgaAdminResource.commit` (see
the surrounding `commit` body at `IgaAdminResource.java:300-392` — every JPA
write inside `replay` participates in that same transaction). Because
`IgaAuthorizerEntity.mode` is a regular column on a managed entity, calling
`em.find(IgaAuthorizerEntity.class, id).setMode("multiAdmin")` inside
`combineFinal` is atomically committed with the dispatcher's ATTESTATION
write. There is no need for a separate transaction or a `runJobInTransaction`
shim (which `TideAdminCompatResource.toggleIga` uses at
`TideAdminCompatResource.java:106-115` for an explicitly-separated scan; that
pattern would be **wrong** here because we *want* the flip to roll back if
the replay fails).

### 7.4 Idempotency

The two cases to spec:

1. **Already in `multiAdmin` mode but `record` is being called.** No flip
   needed; `record` just runs the multiAdmin branch (today's exact path).
2. **Already in `multiAdmin` mode but a firstAdmin-style CR (tide-realm-admin
   assignment) arrives.** This is the unusual case — a legitimate `multiAdmin`
   realm assigning the realm-admin role to another admin. **Treat as a
   regular `GRANT_ROLES` CR.** No special detection on the multiAdmin side:
   the tide-realm-admin role becomes "just another role" once the bootstrap
   has happened. Log nothing; let the dispatcher stamp it the normal way.
   No re-flip.

The **rejection / hard-error** case the prompt asks about — "what if a
firstAdmin-style CR arrives when we're already in multiAdmin mode" — is
specifically about **the bootstrap shape itself** (sign-the-policy-payload).
Spec: if the call site ever explicitly asks for the bootstrap branch when
mode is `multiAdmin`, throw `IllegalStateException("firstAdmin signing
attempted in multiAdmin mode")` and log a `WARN`. In practice this branch
is unreachable from `combineFinal` because the bootstrap-detection check is
gated on `"firstAdmin".equals(mode)` — but the explicit guard is a cheap
correctness floor.

---

## 7a. Threshold-change policy regeneration (multiAdmin steady state)

**Requirement (user-stated 2026-06-01).** Because the multiAdmin threshold is
`floor(0.7 × activeTideRealmAdmins)` (min 1), **any change to the active
tide-realm-admin set changes the threshold**, and when the threshold changes a
**new admin policy** (encoding the new threshold + the new admin set) must be
**generated and re-signed**. The admin policy is therefore a **regenerated /
versioned artifact**, not a static one-time thing. §7 covers the *first* policy
sign (the firstAdmin→multiAdmin bootstrap trigger); this section covers **every
subsequent** policy sign — the regen+re-sign cycle that fires whenever the
admin set moves.

This is **not** a new invention — legacy already did exactly this. See the
legacy trace in §7a.0 for the file:line anchors; the new-world mapping follows.

### 7a.0 Legacy precedent (what we are porting)

Legacy regenerated + re-signed the `tide-realm-admin` role policy through
`TideRoleRequests.createRolePolicyDraft(session, recordId, 0.7, additionalAdmins, role)`
(`tidecloak-iga-extensions-old/.../TideRequests/TideRoleRequests.java:103-200`).
The full traced flow:

1. **Threshold recompute site.** `TideRoleRequests.java:124-128`:
   `numberOfActiveAdmins = users.size()` (count of `ACTIVE`
   `TideUserRoleMappingDraftEntity` for the role) and then
   `int threshold = Math.max(1, (int)(thresholdPercentage * (numberOfActiveAdmins + numberOfAdditionalAdmins)))`
   with `thresholdPercentage = 0.7`. This is the same `0.7` floor formula §3.6
   ports; the **only** legacy difference is the `+ numberOfAdditionalAdmins`
   addend (see step 3).

2. **Policy artifact built.** `TideRoleRequests.java:144-148`: a Midgard
   `Policy("GenericResourceAccessThresholdRole:1", "any", vvkId,
   ApprovalType.EXPLICIT, ExecutionType.PUBLIC, params)` where
   `params = { threshold: <computed>, role: "tide-realm-admin", resource:
   "realm-management" }`. So the artifact **carries the threshold int + the
   role name + the resource (client) name**, keyed to the realm's `vvkId`.
   It is base64-encoded (`policy.ToBytes()`) and stored as a `PolicyDraftEntity`
   (`TideRoleRequests.java:171-176`, `changesetRequestId = recordId + "policy"`),
   plus a `ChangesetRequestEntity` of `ChangeSetType.POLICY`
   (`TideRoleRequests.java:189-195`). The committed signed copy lives on
   `TideRoleDraftEntity.initCert` / `.initCertSig`
   (`TideRoleRequests.java:232-235`, `commitRolePolicy`).

3. **`additionalAdmins` = the pending net delta.** It is **not** a separate
   admin list — it is an int that pre-applies the in-flight membership change
   so the policy is signed for the admin count it will have **after** this CR
   commits. Computed at `ChangeSetProcessor.java:304`:
   `int additionalAdmins = pendingChangeRequest.getActionType() == ActionType.CREATE ? 1 : -1`.
   Call sites: `+1` for a grant draft (`UserRoleProcessor.java:155, 247`),
   `-1` for a revoke draft (`UserRoleProcessor.java:289`), and for **bulk**
   approvals the net of the batch (`UserRoleProcessor.java:623`,
   `combineChangeRequests` passes `netChange = (+1 per add) + (-1 per delete)`
   with `forceCreate=true`). So `numberOfActiveAdmins` is the *currently
   committed* count and `additionalAdmins` is the *pending* delta about to
   land — together they are the post-commit count the new threshold is built
   for.

4. **Trigger events (callers of `createRolePolicyDraft`).** Grep-confirmed
   (whole legacy provider): only three classes invoke it —
   `TideRoleRequests`, `ChangeSetProcessor`, `UserRoleProcessor`. The events:
   - **Grant draft of `tide-realm-admin`** (`UserRoleProcessor.handleCreateRequest:247`,
     gated on `role == TIDE_REALM_ADMIN` **and** authorizer `type == "multiAdmin"`).
   - **Revoke draft of `tide-realm-admin`** (`UserRoleProcessor.handleDeleteRequest:289`,
     same gate, `additionalAdmins = -1`).
   - **Post-commit recompute of *other* pending authority CRs**
     (`ChangeSetProcessor.updateOtherAuthorityRequests:329`): when one admin
     grant/revoke commits, every *other* still-pending tide-realm-admin CR has
     its policy draft **deleted and recreated** at the new admin count
     (`ChangeSetProcessor.java:309-329`), because the denominator just moved.
   - **Bulk merge** (`UserRoleProcessor.combineChangeRequests:623`): N
     simultaneous authority assignments collapse to **one** shared policy with
     the net delta (see §7a.4).
   - **Recreation loop on commit** (`UserRoleProcessor.commit:155`): after a
     tide-realm-admin assignment commits, pending non-batch authority requests
     are re-drafted at the new count.

   **Note — NOT triggered by user enable/disable or delete.** Grep for
   `setEnabled`/`isEnabled` in the legacy provider returns only an unrelated
   `approveFullScope(…, boolean isEnabled)` param and the `toggleIGA` realm
   flag — **no** disable/enable hook calls `createRolePolicyDraft`. Worse,
   legacy's `getNumberOfActiveAdmins` (`ChangesetRequestAdapter.java:196-205`)
   filters role members **only** by the presence of an `ACTIVE`
   `TideUserRoleMappingDraftEntity` and **does not gate on `isEnabled()`** — so
   legacy's count never reacted to enable/disable at all. The new port's
   active-admin predicate (§3.7) is **stricter** (adds `isEnabled()` + committed
   stamp), which is why disable/enable/delete now logically *should* move the
   count — see §7a.1 for how the new world detects those events that legacy
   ignored.

5. **Who signs the regenerated policy — the chicken-and-egg answer.**
   **RESOLVED from legacy: the new policy is signed under the CURRENT
   (pre-change) admin set's authority, via the VRK, and the new threshold only
   takes effect for *subsequent* CRs.** Evidence:
   - The policy draft is VRK-signed at draft-creation time inside
     `createRolePolicyDraft` itself —
     `Midgard.SignWithVrk(pSignReq.GetDataToAuthorize(), signedSettings.VendorRotatingPrivateKey)`
     (`TideRoleRequests.java:179-182`) — i.e. it is authorized by the **VRK**,
     not by a fresh T-of-N quorum gathered at the *new* threshold.
   - At **commit**, `MultiAdmin.commitWithAuthorizer` signs the POLICY model
     with `Midgard.SignModel(settings, pReq)` where `settings.Threshold_T/_N`
     come from the **current** env/quorum (`MultiAdmin.java:366-383, 427`), and
     it **defers** the policy commit until after the user-context signs
     (`MultiAdmin.java:429-438`) precisely **"because committing the policy now
     would update the ORK threshold mid-batch, causing subsequent UC signs to
     fail"** (`MultiAdmin.java:429-431`). That comment is the smoking gun: the
     new threshold becomes live on the ORK **only after** the current batch
     finishes signing under the **old** threshold.
   - i.e. legacy **bootstraps the new threshold under the existing admin set's
     quorum + the VRK**, then the new threshold governs the next CR. There is
     **no** circular "need the new quorum to authorize its own creation".

   The CR carrying the membership change and the regenerated POLICY CR are
   approved **together** (the membership CR is what the admins authorize; the
   POLICY draft rides along, VRK-authorized, and is committed last). So the
   admins who sign are the **old** set at the **old** threshold; the policy they
   thereby install declares the **new** threshold for everyone after them.

### 7a.1 Trigger events (new world)

The concrete events that change `activeTideRealmAdmins` (§3.7) and therefore
the dynamic threshold. For each: whether it is naturally caught at **CR-commit
time** (the seam legacy used and the natural seam here, since these are
themselves IGA-governed actions) or needs a separate watch.

| Event | Effect on count | Detected at CR-commit? |
|---|---|---|
| tide-realm-admin **GRANTED** (committed) | +1 | **Yes.** A `GRANT_ROLES` CR that stamps the `USER_ROLE_MAPPING(uid, tideRoleId)` row — exactly the §3.7 committed signal. Same seam legacy used (`UserRoleProcessor.java:247`). |
| tide-realm-admin **REVOKED** (committed) | −1 | **Yes.** A `REVOKE_ROLES` CR that clears/removes the stamped linkage row. Legacy `-1` path (`UserRoleProcessor.java:289`). |
| tide-realm-admin user **DISABLED** | −1 (drops out: §3.7 requires `isEnabled()`) | **Depends.** A user enable/disable is **not** an IGA-governed CR today (it is a plain `UserModel.setEnabled(false)`). Legacy **ignored** this entirely (its count had no `isEnabled()` gate — §7a.0 step 4). Since the new predicate **does** gate on enabled, this needs either (a) a separate watch (UserModel event listener) or (b) acceptance that the threshold for *enable/disable* only re-materialises lazily on the next quorum check (see §7a.4 / §7a.6). **Recommended: (b) lazy** — `getThreshold` is computed live on every quorum check (§3.6), so a disabled admin already drops out of the **gate** immediately; the open question is only whether we also **regenerate + re-sign the stored policy artifact** at that instant. See §7a.6. |
| tide-realm-admin user **RE-ENABLED** | +1 | **Depends** — symmetric to disable. |
| tide-realm-admin user's Tide identity **newly committed** (was pending) | +1 | **Yes.** This *is* the grant-commit: the §3.7 signal is the `attestation IS NOT NULL` stamp, which only lands when the previously-PENDING `GRANT_ROLES` CR commits. So "pending → committed" is the same commit-time seam as GRANT. |
| tide-realm-admin user **DELETED** | −1 | **Depends.** A full user delete is not an IGA CR today (like disable). Same (a)/(b) choice; recommended lazy. The stamped linkage row is removed by the delete cascade, so the live `getThreshold` count drops immediately even without a policy regen. |

**Seam summary.** GRANT / REVOKE / pending→committed are **commit-time** events
(the natural seam — they are governed CRs and the regen rides the commit, as
in legacy). DISABLE / RE-ENABLE / DELETE are **not** governed CRs and were
**not** handled by legacy at all; the new stricter predicate means they *do*
move the live threshold (the gate self-corrects on next quorum check), and the
only decision is whether they also eagerly regenerate the **stored signed
policy artifact** — flagged in §7a.6 and §12 Q9.

### 7a.2 What gets regenerated

A new **admin policy artifact** encoding `{ threshold: floor(0.7 × newCount),
role: "tide-realm-admin", resource: "realm-management" }` — the same field set
legacy's `Policy` carried (§7a.0 step 2), recomputed at the new count.

New-world shape — reconciling with "user-contexts are gone, rows/units replaced
them":

- The policy is a **distinct signed artifact**, *not* an attested unit. The
  row/unit ATTESTATION envelopes (§3.3, §6.3) sign *CR row state*; the admin
  policy signs a *governance parameter* (the live threshold + admin scope). They
  are different things and legacy kept them separate too (the POLICY changeset
  is its own `ChangeSetType.POLICY`, distinct from the USER_ROLE changeset).
- In iga-core the artifact is the **`IgaRolePolicyEntity`** for the
  `tide-realm-admin` role: `policy` (the encoded threshold+role+resource) +
  `policySig` (the VRK signature) — the **same** entity §6.2 already uses for
  the first (bootstrap) sign. **Regeneration = re-writing `policy` with the new
  threshold and re-writing `policySig` with a fresh VRK signature over it.** No
  new table, no new entity; the bootstrap path (§6.2/§7.2) and the regen path
  write the **same two columns**, differing only in *when* (first commit vs
  every subsequent membership-changing commit) and *what threshold* the
  `policy` body encodes.
- It is therefore **not** a brand-new CR *type*. The cleanest port is: the
  membership-changing CR (GRANT/REVOKE of tide-realm-admin) carries the policy
  regen as a side-effect at commit (mirroring legacy, where the POLICY draft is
  created alongside the USER_ROLE draft and committed in the same flow). If a
  future change captures role-policy upserts as their own CRs (the
  `UPSERT_ROLE_POLICY` alternative noted in §7.1), the regen would become its
  own CR; for this port it rides the membership CR's commit.

**Versioning.** Each regen overwrites `policy`/`policySig` in place (legacy
overwrote `initCert`/`initCertSig` likewise — `TideRoleRequests.java:232-235`).
There is no explicit epoch/version column today. If an audit trail of
historical thresholds is wanted, that is a **new** column (e.g.
`IgaRolePolicyEntity.version` or an append-only policy-history table) and is
called out as a decision in §11 D10 / §12 Q9 — legacy had **no** such history
(it mutated in place), so not adding one matches legacy; adding one is a
deliberate enhancement.

### 7a.3 Who signs the regenerated policy

**Legacy answer (from §7a.0 step 5, RESOLVED): the CURRENT (pre-change) admin
set signs, via the VRK, under the OLD threshold; the NEW threshold takes effect
for subsequent CRs.** The regenerated policy is VRK-authorized at draft time
(`TideRoleRequests.java:179-182`) and the membership CR it rides is approved by
the existing quorum at the existing threshold; the new threshold only goes live
on the ORK *after* that commit (`MultiAdmin.java:429-431`).

**Recommended new-world behaviour (mirror legacy):**
- The regenerated `IgaRolePolicyEntity.policy` is signed via the **VRK signing
  path** (§5 / §3.4) — `sign(byte[])` over the new policy bytes, routing
  Midgard → ORK (NOT local; §5.1). This is the **same** signing primitive the
  bootstrap (firstAdmin) policy sign uses (§6.2). The continuity is exact: first
  sign and every regen both go VRK → Midgard → ORK.
- The **authorizing quorum** for the membership CR that carries the regen is the
  **current/old** multiAdmin threshold (`floor(0.7 × currentCommittedCount)`),
  computed by `getThreshold` (§3.5) at the moment that CR is checked — i.e.
  *before* the new member is counted. After commit, the next `getThreshold` call
  sees the new count and returns the new threshold. **This is the OLD-threshold
  quorum installing the NEW threshold**, exactly as legacy.

**Decision flagged for the user (§12 Q9, the OLD-vs-NEW quorum question):**
legacy settles it as **OLD quorum signs, NEW threshold takes effect next** — and
that is the recommended port behaviour. The only residual user call is whether
the *new* world should instead require the **new** (post-change) threshold's
quorum to ratify the regenerated policy (a stricter, non-legacy choice that
would mean, e.g., adding the 4th admin needs the 3-of-… quorum that only exists
*after* the add — a bootstrap/circularity the legacy design deliberately avoided
by using the VRK). **Recommendation: keep the legacy semantics** (OLD quorum +
VRK installs NEW threshold); flag the alternative only so the user can veto.

### 7a.4 Idempotency / churn control

If several admins are added in quick succession, do we regenerate N times or
batch?

**Legacy behaviour (discoverable):**
- **Per single committed membership CR → exactly one regen.** Each grant/revoke
  draft creates one policy draft at its own count (`UserRoleProcessor.java:247/289`).
- **Built-in dedup: `IsEqualTo` short-circuit.** `createRolePolicyDraft`
  compares the freshly-built policy bytes against the currently-committed
  `initCert` and **returns early without creating a draft if the threshold is
  unchanged** (`TideRoleRequests.java:163-168`,
  `if(!forceCreate && currentPolicy.IsEqualTo(policy.ToBytes())) return;`). So
  e.g. going from 2→3 active admins is `(int)(0.7×2)=1 → (int)(0.7×3)=2` — a
  real change, regen happens; but 3→4 is `2 → 2` — **no** change, **no** regen.
  The floor formula means most single adds **don't** move the threshold, and
  legacy skips the regen in exactly those cases.
- **Bulk = one batched regen.** `combineChangeRequests` collapses N
  simultaneous authority assignments into **one** shared policy with the net
  delta and `forceCreate=true` (`UserRoleProcessor.java:599-627`), and stores
  `batchAuthorityIds` so the post-commit recompute **skips** the batch-mates
  (`ChangeSetProcessor.java:272-285`, `UserRoleProcessor.java:126-135`) to avoid
  nuking their already-signed shared policy.

**Recommended new-world default:** **regenerate on each committed
membership-changing CR, gated by the same "threshold actually changed" check.**
Concretely:
1. Compute `newThreshold = floor(0.7 × newCommittedCount)` at the commit.
2. Read the current `IgaRolePolicyEntity.policy` threshold; **if equal, skip**
   the regen (port of the `IsEqualTo` short-circuit — this is the primary churn
   control and it falls out of the floor formula for free).
3. Only when the threshold differs, rewrite `policy` + re-sign `policySig`.

Because each committed CR is already a discrete governed event, per-CR regen
(with the no-change skip) is the natural and sufficient default; an explicit
batch mechanism is only needed if iga-core grows a bulk-approve path
analogous to legacy's `combineChangeRequests` (not in scope for this port —
note it as a follow-up if bulk approve lands). See §11 D10.

### 7a.5 Interaction with the firstAdmin→multiAdmin transition (§7)

Make the continuity explicit:

- **The transition (§7) is the *first* policy sign.** During firstAdmin
  bootstrap, the tide-realm-admin policy CR is signed (VRK) and
  `IgaRolePolicyEntity.policySig` is written for the first time, and the mode
  flips to multiAdmin (§7.2). At that instant the policy encodes whatever
  threshold the bootstrap establishes (with one admin just onboarded, the
  multiAdmin floor is typically `floor(0.7×1)=1`).
- **Threshold-change regen (this section) is *every subsequent* policy sign.**
  Once in multiAdmin mode, each membership change that moves
  `floor(0.7 × activeAdmins)` rewrites the **same** `policy`/`policySig` columns
  under the OLD quorum + VRK (§7a.3).
- So §7's framing of "the first policy sign" should be read as "the **first of
  many**" — the bootstrap is sign #1; regens are signs #2…n. The signing
  primitive (VRK → Midgard → ORK) and the target columns
  (`IgaRolePolicyEntity.policy`/`.policySig`) are **identical** across all of
  them; only the trigger (bootstrap transition vs membership-change commit) and
  the encoded threshold differ. (§7's text is cross-referenced to this section;
  see the note added at the end of §7.2.)

### 7a.6 Failure mode — ORKs unreachable during a membership-change commit

Policy regeneration re-signs via VRK → Midgard → ORK (§7a.3, §5.1, §3.4) — it is
**NOT** a local key op. So if the ORKs are unreachable when an admin-set change
commits, the **re-sign fails** the same way any other Midgard → ORK sign fails
(§6.5, §12 Q3 — the M2M-503 path).

The intended behaviour — and the open question:

- **The membership CR and its policy regen share one commit transaction**
  (mirroring §7.3 atomicity and legacy, where the USER_ROLE commit and the
  deferred POLICY commit are in the same `commitWithAuthorizer` flow,
  `MultiAdmin.java:429-461`). Therefore **if the policy re-sign fails, the whole
  commit fails and rolls back** — the membership change does **not** half-apply.
  This is the recommended intended behaviour: **fail-closed and atomic**. You
  cannot end up with the new admin committed but the threshold still on the old
  policy (or vice-versa).
- **Consequence for disable/enable/delete (the non-CR events, §7a.1):** because
  those are not governed CRs, there is no commit transaction to roll back. The
  **live `getThreshold` gate already self-corrects** (it recomputes off the live
  count every quorum check — §3.6 — so a disabled admin stops counting toward
  the gate immediately, ORKs or no ORKs). The only thing that *cannot* happen
  without ORKs is **eagerly re-signing the stored policy artifact** to match. So
  the stored `policy`/`policySig` can lag the live count for disable/enable/
  delete until the next ORK-backed regen. **Open question (§12 Q9):** is that
  lag acceptable (the gate is correct; only the signed artifact is stale), or
  must disable/enable/delete also be promoted to ORK-backed governed events that
  fail-closed when ORKs are down? **Recommendation:** accept the lag — the
  authorization gate (`getThreshold`) is always live and correct; the signed
  policy artifact is a *published* record that can be lazily reconciled. Flag
  for user confirmation.

### 7a.7 §3 / getThreshold consistency

The threshold the regenerated **policy artifact encodes** and the threshold
`getThreshold()` **returns** must agree — **both derive from the identical
`countActiveTideRealmAdmins` (§3.7)** and the identical
`Math.max(1, (int)(0.7 × n))` floor (§3.6). No drift is structurally possible
because there is **one** counting function and **one** formula; the policy regen
calls the same `countActiveTideRealmAdmins` at commit that `getThreshold` calls
at quorum-check. (This is the new-world improvement over legacy, where the
*gate* read a stored `tideThreshold` role-attribute with a stale-cap fallback
while the *policy* was rebuilt from the live count — two sources that could
diverge between writes; §3.6 "Port simplification". The port collapses them to
one live source, so the §7a regen and the §3.5 gate cannot disagree.)

---

## 8. multiAdmin path (no-op port; just verify)

Today's `TideAttestor` **is** the multiAdmin path. The locked surface:

- `record` — `TideAttestor.java:82-101` (per-admin auth record, identical to `SimpleNameAttestor.record` at `SimpleNameAttestor.java:46-69`).
- `combineFinal` — `TideAttestor.java:115-136` (calls `canonicalizeLinkageSet` at `:153-208` or `canonicalizeNode` at `:215-232`).
- `sign(byte[])` — `TideAttestor.java:351-358` (the SHA-256 stub with the comment "TODO: replace with Midgard signClaims()" at `:349`).

After the port, this path **does not change byte-for-byte** in behaviour
except for the **threshold source**: `TideAttestor.getThreshold` in multiAdmin
mode is now **dynamically computed** as `Math.max(1, (int)(0.7 * activeTideRealmAdmins))`
at quorum-check time (§3.5 sketch, §3.6, §3.7) — replacing today's plain
delegation to `IgaScopeResolver.resolveThreshold` (`TideAttestor.java:104-106`).
The branch lives **inside `TideAttestor`**, not inside the shared resolver:
`getThreshold` still calls `IgaScopeResolver.resolveThreshold` first so the
per-scope-entity `iga.threshold` override (set with `iga.approverRole` on the
same entity) and the ADOPT_* short-circuit keep top priority
(`IgaScopeResolver.java:283-311`); only the **realm-level default** — which in
the shared resolver is the static realm `iga.threshold` attribute or `1` — is
overridden by the dynamic 0.7 floor for the `tide` attestor. The shared
resolver is untouched, so the **Tideless** static `iga.threshold` story
(`docs/IGA.md` §"Configuring thresholds") is preserved exactly (§12 Q8). That
is the only behavioural delta on the multiAdmin code path.

The Midgard `signClaims()` swap-point is unchanged: still the
single `sign(byte[])` method (`TideAttestor.java:351`), still tracked under
[[project-iga-tve-producer]] (the same producer roadmap as the IGA→TVE
producer-design doc).

**The contrast between the two modes is NOT local-vs-network.** Both firstAdmin
and multiAdmin sign by going Midgard → ORK (§3.4, §5.1); both share the same
ORK-reachability dependency at the `sign(byte[])` swap-point. The real
differences are exactly two:
- **Admin quorum:** firstAdmin = 1 (one admin authorizes); multiAdmin =
  dynamic `floor(0.7 × activeTideRealmAdmins)`.
- **Key / signing ceremony:** firstAdmin = VRK signing (`Midgard.SignWithVrk`);
  multiAdmin = enclave threshold signing (future `Midgard.SignModel` /
  `signClaims`), today the SHA-256 stub.
Both ceremonies terminate on the ORK network. (See §12 Q3.)

`getThreshold` in firstAdmin mode returns **constant `1`** and does NOT
consult the dynamic active-admin count (§3.5). That `1` is the **admin
quorum**, not a statement that the sign is local — the single authorizing
admin's sign still routes to the ORKs.

---

## 9. Rollout / migration for existing realms

### 9.1 Today's state of `IGA_AUTHORIZER`

Best-effort answer: in dev/staging today, **`IgaAuthorizerEntity` rows are
only created by an explicit `POST /iga/authorizers`** (endpoint
`IgaAdminResource.createAuthorizer`, `@POST @Path("authorizers")` at
`IgaAdminResource.java:1054-1095`; the actual row insert is
`IgaAuthorizerService.create(...)` → `em.persist(entity); em.flush()` at
`IgaAuthorizerService.java:24-37`, with `new IgaAuthorizerEntity()` at `:26` and
`persist` at `:34`). The seed sets `type`, `providerId`, `authorizer`,
`authorizerCertificate` **verbatim from the request body** (`IgaAdminResource.java:1087-1092`)
— there is **no** default/derivation of `type`; the caller supplies whatever
string it wants (it does **not** auto-write `"tide"` vs `"simple"` — `type` is
free-text, per §Q5 and the Background table). There is no auto-seed on realm
creation, no auto-seed on toggle-on (the `toggleIga` handler at
`TideAdminCompatResource.java:74-277` does **not** touch `IgaAuthorizerEntity`),
and the only test paths that create authorizer rows do so via the REST endpoint.

**Entity-existence — VERIFIED (load-bearing for the whole port):**
`IgaAuthorizerEntity` **EXISTS** in current iga-core
(`entities/IgaAuthorizerEntity.java:34`, `@Table(name = "IGA_AUTHORIZER")` at
`:11`, registered in `IgaJpaEntityProvider.getEntities()` at
`IgaJpaEntityProvider.java:24`). Its current columns are `ID, REALM_ID,
PROVIDER_ID, TYPE, AUTHORIZER, AUTHORIZER_CERTIFICATE, CREATED_AT`
(`IgaAuthorizerEntity.java:36-56`) — there is **no `MODE` column today**, so the
§4 `mode` addition is a genuine `ALTER`/new-column on an existing table, exactly
as §4.2/§4.3 describe (not a new-entity decision).

**Live-DB fact (the 0-row reality).** In the live demo DB, `iga_authorizer`
holds **0 rows** despite active IGA usage — **13 authorizations across 9 change
requests**. The entity is **dormant**: "no authorizer row" is the **DEFAULT
state for every realm today**, not an edge case. The whole rollout therefore has
to make sense for a realm whose `iga_authorizer` is empty — which is exactly what
Decision 1 (§3.1, no-row → `firstAdmin` for `tide`) and Decision 2 (lazy seed,
below) are built around.

**For already-IGA-on realms — retroactive seed is NO LONGER an open decision; it
is closed by the lazy-seed design (Decision 2 / §9.3).** There is **nothing to
retroactively seed**: the authorizer row is created **lazily, on the first
Tide-mode `TideAttestor.record()`** (§9.3), seeded `mode="firstAdmin"`. So an
existing already-on Tide realm — which today has **0** rows (the live-DB fact
above) — simply gets its row materialised on its **next Tide CR** after the port
lands, with no backfill job, no migration, no operator `POST`. Until that first
record(), `resolveMode` already reports `firstAdmin` for it (Decision 1), so the
realm behaves correctly even in the window before the row exists. This
**self-heals** and **fits the 0-row reality** exactly.

In prod (Tide-enabled deployment): unknown — no current Tide deployment is
running iga-core yet, so the populated state is "fresh + small". The migration
default-value rule handles this trivially.

### 9.2 Default mode for existing rows: `"multiAdmin"`

**Scope note.** This section is about the rare realm that **already has** an
`IgaAuthorizerEntity` row (operator-created via `POST /iga/authorizers`) — *not*
the common no-row realm. The no-row case is governed by Decision 1 (§3.1: no row
+ `tide` ⇒ `firstAdmin`) and the row is seeded `firstAdmin` lazily by Decision 2
(§9.3). The two are complementary and do not collide: the `defaultValue` here
only ever applies to a row that was **already inserted** before the `MODE` column
existed; a lazily-seeded row is inserted **with** `mode="firstAdmin"` and never
sees this backfill default.

The migration's `defaultValue="multiAdmin"` (`iga-changelog-2.5.0.xml`,
§4.2) backfills every **pre-existing** row to multiAdmin mode. **Justification:**

- An existing row was created via `POST /iga/authorizers` before this port
  landed — i.e. by an operator who already accepted the multi-signer model
  (the legacy bootstrap path wasn't even exposed via the new REST surface).
- Backfilling to `firstAdmin` would mean the **next** CR commit on that realm
  fires the bootstrap branch — runs `Midgard.SignWithVrk` against the realm's
  active VRK, signs the tide-realm-admin policy CR (if the next CR happens to
  be one), and flips back to multiAdmin. That is wrong: the realm should
  start in the steady-state mode it was already operating in.
- `multiAdmin` is also the **safer default** if anything goes wrong with the
  flip detection — the worst case is "this CR runs through the SHA-256 stub
  exactly the way it did before this port", which is the existing observable
  behaviour.

### 9.3 Where the first authorizer row is created — lazily, on first `record()`

**Decision 2 — RESOLVED `session:2026-06-01 with user`. The first
`IgaAuthorizerEntity` row is created LAZILY, on the first Tide-mode
`TideAttestor.record()`, seeded `mode = "firstAdmin"`.** No eager seed on IGA
toggle-on; no mandatory admin `POST /iga/authorizers`; no realm-init bootstrap.

**Rationale:** self-healing, zero migration, and it fits the 0-row live reality
(§9.1 — `iga_authorizer` is empty for every realm today). The row **materialises
the first time a Tide realm processes a governed action through the tide
attestor** — i.e. the first moment it is actually needed — instead of being
pre-provisioned speculatively.

**Mechanism.** At the top of `TideAttestor.record(...)`, before recording the
authorization:

```java
// Lazy firstAdmin seed (Decision 2). Runs only on the tide attestor's path.
RealmModel realm = session.realms().getRealm(cr.getRealmId());
boolean hasRow = !authorizerService.listByRealm(realm.getId()).isEmpty();   // IgaAuthorizerService.java:42
if (!hasRow && "tide".equals(realm.getAttribute("iga.attestor"))) {         // IgaAttestors.java:22
    // Seed exactly one row, mode="firstAdmin", via the existing persist path.
    authorizerService.create(realm.getId(), providerId, /*type*/ "firstAdmin",
                             authorizer, authorizerCertificate);             // IgaAuthorizerService.java:24-37 (em.persist at :34)
    // NOTE: create() must also set MODE="firstAdmin" — see the create()-signature
    // note below; the §4 mode column is what carries the firstAdmin marker.
}
// ... then proceed with the normal record() body.
```

The persist itself is the **existing** `IgaAuthorizerService.create()` path —
`new IgaAuthorizerEntity()` → `em.persist(entity); em.flush()` at
`IgaAuthorizerService.java:24-37` (persist at `:34`). The §4 entity diff already
gives the row a Java-side `mode = "multiAdmin"` default and the SQL
`defaultValue="multiAdmin"`; the lazy seed must **override** that to
`mode="firstAdmin"`. Two equivalent ways, implementer's choice: (i) add a `mode`
parameter to `create(...)` (extending the current
`create(realmId, providerId, type, authorizer, authorizerCertificate)` signature
at `IgaAuthorizerService.java:24`), or (ii) call `create(...)` then
`entity.setMode("firstAdmin")` before the flush. Either way the seeded row's
**MODE column is `firstAdmin`** so the very next `resolveMode` (§3.1) reads it
from the column rather than re-deriving the no-row default.

**VRK-material fields.** The seed still needs `providerId` / `authorizer` /
`authorizerCertificate` from the realm's `tide-vendor-key` component (the VRK
material — see §5; this component is not yet read anywhere in iga-core, grep
2026-06-01). If the realm has **no** `tide-vendor-key` component, **skip the
seed** and let `resolveMode`'s no-row branch keep reporting `firstAdmin`
(Decision 1) — firstAdmin signing has no VRK to sign with yet anyway, so a
row with empty VRK fields buys nothing. Log an INFO line ("no tide-vendor-key
component; deferring firstAdmin authorizer seed"). **Framing note (§Q4):** a
missing `tide-vendor-key` component means "VRK not provisioned," **not** "this
is a Tideless realm." The Tide-vs-Tideless discriminator is `iga.attestor ==
"tide"` (`IgaAttestors.java:21-35`), not component presence; the lazy seed runs
only inside the `iga.attestor = tide` path (the tide attestor's `record`), so
the component check is purely a VRK-availability precondition, not a mode/Tide
switch.

**Why not eager (toggle-on / realm-init / mandatory POST).** Three rejected
alternatives and why the lazy approach wins:
- **Seed on `toggleIga` OFF→ON** would couple bootstrap to the toggle handler
  (`TideAdminCompatResource.java:74-277`), which does not touch
  `IgaAuthorizerEntity` today and would then need the VRK-component read added to
  a path that has nothing else to do with signing. It also misses **already-on**
  realms (the OFF→ON edge never fires again for them).
- **Mandatory `POST /iga/authorizers`** would reintroduce a manual operator step
  the live 0-row reality shows nobody performs.
- **Retroactive/migration backfill** is unnecessary precisely because the lazy
  seed self-heals on the next CR (see §9.4).

### 9.4 Already-IGA-enabled realms upgrading to this port — no backfill needed

A realm that already has `isIGAEnabled=true` **before** this port lands needs
**no special handling and no backfill**. Such a realm has **0**
`IgaAuthorizerEntity` rows today (§9.1 live-DB fact); after the port:
- Until its next Tide CR, `resolveMode` reports `firstAdmin` via the no-row
  branch (Decision 1, §3.1) — so the realm is already in the correct bootstrap
  state with no row present.
- On its **next Tide-mode `record()`**, the lazy seed (§9.3) materialises the
  row `mode="firstAdmin"`. From then on the column is authoritative.

So **the "retroactive seed" open item is CLOSED**: there is nothing to
retroactively seed because the first post-port Tide CR seeds the row itself. The
firstAdmin→multiAdmin transition (§7) then flips the freshly-seeded row to
`multiAdmin` the moment the realm signs its `tide-realm-admin` policy CR — which
is the same first bootstrap moment, so an already-on realm that immediately
processes a tide-realm-admin assignment seeds-then-flips in one governed
sequence. (If the realm's first post-port CR is *not* a tide-realm-admin policy
CR, the row is seeded `firstAdmin`, that CR is signed under the firstAdmin
branch, and the flip waits for the eventual tide-realm-admin policy CR — exactly
the §7 trigger, unchanged.)

---

## 10. Tests

The following scenarios should be added (enumerate only — no test code in
this doc):

**ORK-dependency note for the signing tests.** firstAdmin signing is a
Midgard → ORK network call (§5.1, §3.4, §12 Q3), so any test that asserts on a
**real** firstAdmin signature byte-string needs **either** a reachable ORK
network **or** the Midgard test-double from §5.4 (`installTestOverride`, which
stubs the Midgard → ORK round-trip). You **cannot** unit-test firstAdmin signing
green without stubbing the Midgard → ORK call. **What CAN be tested without ORKs**
(by stubbing `sign()` / installing the override, no live network): the
mode-branch selection, the transition trigger + atomic mode-flip (§7), and the
dynamic threshold count (§3.5–3.7) — these are pure JPA/count logic and do not
touch the network. Scenarios 1, 2 and 7 below assert on real signature bytes and
therefore require the §5.4 stub (or live ORKs); scenarios 3, 4, 5 exercise
threshold/mode/transition logic and run with `sign()` stubbed. (The
`TIDE-DUMMY-v1:` stub assertions in scenario 3 are the **multiAdmin** stub, which
is still a SHA-256 no-op today and needs no ORK.)

1. **firstAdmin signs a row/unit CR (non-policy).** *(Needs the §5.4 Midgard
   stub or live ORKs — firstAdmin signing is a Midgard → ORK call.)* Seed the realm with
   `IgaAuthorizerEntity.mode = "firstAdmin"`. Author a `GRANT_ROLES` CR
   that does **not** assign `tide-realm-admin`. Authorize + commit. Assert:
   the affected `USER_ROLE_MAPPING` row's `attestation` is
   `TIDE-FIRSTADMIN-v1:<base64>`; `IgaAuthorizerEntity.mode` is **still**
   `"firstAdmin"`; `IgaRolePolicyEntity.policySig` is untouched.

2. **firstAdmin signs the tide-realm-admin policy CR — atomic flip.**
   *(Signing assertion needs the §5.4 Midgard stub or live ORKs; the mode-flip
   + rollback assertions can run with `sign()` stubbed.)*
   Seed `mode = "firstAdmin"`. Author a `GRANT_ROLES` CR that assigns
   the realm-management `tide-realm-admin` role to a user. Authorize +
   commit. Assert: the `USER_ROLE_MAPPING` row's `attestation` is
   `TIDE-FIRSTADMIN-v1:<base64>`; `IgaRolePolicyEntity.policySig` for the
   tide-realm-admin role is the **same** signature; `IgaAuthorizerEntity.mode`
   is now `"multiAdmin"`; all three writes are in the same JPA transaction
   (rollback test: throw inside the dispatcher after stamp; assert mode
   has not flipped).

3. **multiAdmin path — dynamic threshold gates commit.** Seed
   `mode = "multiAdmin"` and provision **5** active tide-realm-admins (role +
   enabled + committed/stamped `tide-realm-admin` USER_ROLE_MAPPING). Dynamic
   threshold = `Math.max(1, (int)(0.7 × 5)) = 3`. Author any non-policy CR.
   Two admins record; assert commit returns `412 PRECONDITION_FAILED` with
   `{"threshold":3, "authCount":2}` (matching `IgaAdminResource.java:346-354`).
   Third admin records; commit succeeds. Assert `ATTESTATION` is
   `TIDE-DUMMY-v1:<base64>` (stub) and three entries exist in
   `IGA_AUTHORIZATION` for the CR. (No `iga.threshold_t` realm attribute is set
   anywhere — the `3` comes purely from the live admin count.)

   **Dedup clarification.** Dedup today is **per-CR per-admin** (see
   `IgaAdminResource.java:259-278`) — the same admin cannot sign the same CR
   twice. Across CRs the same admin can sign any number of CRs. This stays
   the same after the port.

4. **Idempotency — firstAdmin-shape policy CR while in multiAdmin mode.**
   Seed `mode = "multiAdmin"`. Author a `GRANT_ROLES` CR assigning
   `tide-realm-admin`. Authorize + commit. Assert: signature lands as
   `TIDE-DUMMY-v1:...` (the multiAdmin stub, not the firstAdmin VRK path);
   no mode flip happens; no policy-sig write happens. The role grant is
   treated as a regular grant.

5. **Dynamic threshold (multiAdmin) — `getThreshold` boundary + liveness.**
   All in `mode = "multiAdmin"`, no `iga.threshold` realm attribute set,
   no per-scope override unless noted. "Active admin" = role + enabled +
   committed (stamped) `tide-realm-admin` USER_ROLE_MAPPING (§3.7).
   - **Boundary table.** Provision N active admins and assert
     `getThreshold` returns the floor of `0.7 × N`, min 1:
     N=1 → **1**; N=3 → **2**; N=5 → **3**; N=10 → **7**. (Also spot-check
     N=2 → 1, N=4 → 2, N=100 → 70 per §3.6.1.)
   - **Recompute on add — proves dynamic, not stored.** Provision 3 active
     admins (threshold 2). Author a CR. Between draft and commit, commit a
     **4th** active tide-realm-admin grant (role + enabled + stamped). Re-read
     `getThreshold`; assert it is still **2** (`(int)(0.7×4)=2`); now add a
     **5th**; assert `getThreshold` recomputes to **3**. No stored value was
     touched.
   - **Disabled admin drops out.** Provision 5 active admins (threshold 3).
     Disable one (`user.setEnabled(false)`); assert `getThreshold` drops to
     **2** (`(int)(0.7×4)=2`) — the disabled user no longer counts toward the
     denominator.
   - **Pending tide-realm-admin does NOT count.** Provision 4 committed active
     admins (threshold 2). Author a `GRANT_ROLES` CR assigning `tide-realm-admin`
     to a 5th user but **leave it PENDING** (do not commit). Assert
     `getThreshold` is still **2** — the pending grant has no stamped
     USER_ROLE_MAPPING row (`attestation IS NULL`), so the 5th user is excluded
     from the denominator. Commit the CR; assert `getThreshold` now recomputes
     to **3**.
   - **Per-scope override still wins (multiAdmin).** Provision 5 active admins
     (dynamic floor 3) AND set `iga.threshold = 7` **with** `iga.approverRole`
     on the affected role (same-entity coupling). Assert `getThreshold` returns
     **7** (per-scope override beats the dynamic floor — §3.5 sketch consults
     `resolveThreshold` first).
   - **firstAdmin ignores the count.** In **firstAdmin** mode with 10 active
     admins, assert `getThreshold` returns **1** (firstAdmin never consults the
     dynamic count — §3.5).
   - **Tideless unaffected (regression guard).** With `iga.attestor` unset
     (`simple`) and realm `iga.threshold = 5`, assert `getThreshold` returns
     **5** — the dynamic 0.7 formula is `tide`-attestor-only and the shared
     `IgaScopeResolver` static path is untouched (§12 Q8).

6. **Lazy firstAdmin seed on first `record()` (Decision 2, §9.3).** Start a
   `tide`-attestor realm (`iga.attestor = "tide"`) with a `tide-vendor-key`
   component and **zero** `IgaAuthorizerEntity` rows (the live-DB default). Before
   any CR, assert `resolveMode` reports `"firstAdmin"` via the no-row branch
   (Decision 1) and `IgaAuthorizerService.listByRealm` is empty. Author a CR and
   have an admin `record` on it; assert **exactly one** `IgaAuthorizerEntity` row
   now exists with `mode = "firstAdmin"`, `providerId = <tide-vendor-key id>`, and
   the VRK `authorizer`/`authorizerCertificate` fields populated from the
   component. Have a **second** admin `record` on another CR; assert **no second
   row** is created (the `!hasRow` guard skips re-seeding) and `resolveMode` now
   reads `firstAdmin` from the **column**. Variant — **no `tide-vendor-key`
   component**: assert the seed is **skipped** (still 0 rows), one INFO log line
   is emitted, and `resolveMode` keeps reporting `firstAdmin` from the no-row
   branch. Variant — **Tideless** (`iga.attestor` unset): assert `record` runs the
   `SimpleNameAttestor` path and **never** seeds an `IgaAuthorizerEntity` (the
   tide attestor's lazy-seed code is not on the Tideless path).

7. **VRK accessor test seam (Midgard → ORK stub).** Install a deterministic
   `installTestOverride` stub **in place of the Midgard → ORK call** (§5.4);
   assert the firstAdmin signature is the stub's output (HMAC-SHA-256 over a
   known canonical) and the prefix is `TIDE-FIRSTADMIN-v1:`. This test exists
   precisely **because** firstAdmin signing is a network call — the override is
   how the signing path is exercised without a live ORK network. (Asserting the
   stub is *installed and used* also documents that the production path is a
   real Midgard → ORK round-trip.)

8. **Threshold-change policy regen — admin added moves the threshold (§7a).**
   *(Signature assertion needs the §5.4 Midgard stub or live ORKs; the
   recompute + skip assertions run with `sign()` stubbed.)* Seed
   `mode = "multiAdmin"` with **2** committed active tide-realm-admins (policy
   threshold `floor(0.7×2)=1`). Commit a `GRANT_ROLES` CR adding a **3rd**
   active admin. Assert: a **new** `IgaRolePolicyEntity.policy` is written whose
   encoded threshold is now **2** (`floor(0.7×3)`), `policySig` is a fresh
   `TIDE-...`/VRK signature over the new bytes, and `getThreshold` for the next
   CR returns **2** — agreeing with the policy (§7a.7 no-drift). The signing
   quorum for the membership CR was the **old** threshold (1), and the new
   threshold (2) only governs the *next* CR (§7a.3 OLD-signs-NEW-takes-effect).

9. **Threshold-change policy regen — admin disabled lowers the threshold (§7a.1).**
   Seed `mode = "multiAdmin"` with **5** committed active admins (policy
   threshold `floor(0.7×5)=3`). `setEnabled(false)` on one. Assert the **live**
   `getThreshold` immediately drops to **2** (`floor(0.7×4)`) — the gate
   self-corrects off the live count with no CR (§7a.6). Per the §7a.6/§12 Q9
   recommendation (accept lag), assert the stored `IgaRolePolicyEntity.policy`
   may still encode **3** until the next ORK-backed regen; if the user chooses
   the stricter "eager re-sign on disable" option instead, assert the policy is
   rewritten to **2** synchronously (this branch is gated on the Q9 decision).

10. **No-change skip — successive adds that don't move the floor (§7a.4).**
    Seed `mode = "multiAdmin"` with **3** committed active admins (threshold 2).
    Commit a grant for a **4th** (`floor(0.7×4)=2` — unchanged). Assert **no**
    new `policySig` is written (the `IsEqualTo` short-circuit, ported from
    `TideRoleRequests.java:163-168` — threshold did not change). Then commit a
    **5th** (`floor(0.7×5)=3` — changed); assert the policy **is** regenerated
    with threshold 3. This proves per-CR regen is gated by an actual threshold
    delta, not by every membership touch.

11. **Rapid successive adds — N regens vs 1 (per the §7a.4 idempotency decision).**
    With the recommended default (per-committed-CR regen + no-change skip): add
    3 admins via 3 separate committed CRs starting from N=2; assert the policy is
    regenerated only on the CRs where the floor actually moves (2→1 stays, 3→2
    moves, 4→2 stays, 5→3 moves — so **2** regens across the 3 adds, not 3).
    *(If a future bulk-approve path lands — out of scope, §7a.4 — the batched
    variant would instead produce **1** regen at the net count; assert that only
    under the bulk path.)*

12. **Policy regen when ORKs are down — defined fail-closed (§7a.6).** Seed
    `mode = "multiAdmin"`, 2 active admins. With the Midgard → ORK call stubbed
    to **fail** (or no override installed and no live ORKs), commit a
    `GRANT_ROLES` CR adding a 3rd admin (which *would* move the threshold 1→2 and
    so trigger a regen). Assert the **whole commit rolls back atomically**
    (§7a.6): the 3rd admin's `USER_ROLE_MAPPING` is **not** stamped, the policy
    is **not** rewritten, and a 503-class error surfaces (the same ORK-unreachable
    path as scenarios touching firstAdmin signing, §6.5 / §12 Q3). Contrast: a
    `setEnabled(false)` on an admin with ORKs down does **not** roll anything back
    (no CR) — assert `getThreshold` still drops live while the stored policy lags
    (§7a.6 recommendation).

---

## 11. Decisions baked in (audit trail)

All thirteen constraints below were locked in `session:2026-06-01 with user`
(the planning session that produced this doc) and are not up for re-litigation
during the implementation phase.

- **D1. One class, two modes.** Extend `TideAttestor`; do not add a separate
  `FirstAdminAttestor` / `MultiAdminAttestor` class. Rationale: the SPI and
  realm-attribute (`iga.attestor=tide`) resolution already pick the attestor
  per realm — adding a second factory id would mean operators have to flip
  realm attributes mid-bootstrap, which is the exact ergonomic pain the
  legacy two-class design caused.

- **D2. Mode field on `IgaAuthorizerEntity`.** New `mode VARCHAR(32) NOT NULL
  DEFAULT 'multiAdmin'` column added via a new Liquibase changelog
  `iga-changelog-2.5.0.xml`. Two values today (`firstAdmin`, `multiAdmin`).

- **D3. Threshold for multiAdmin: dynamically computed at quorum-check
  time** as `Math.max(1, (int)(0.7 * activeTideRealmAdmins))` (§3.5 sketch,
  §3.6, §3.7). Three sub-decisions, all confirmed `session:2026-06-01 with user`:
  - **Algorithm** = `floor(0.7 × activeTideRealmAdmins)`, minimum 1. The
    `0.7` literal and the `Math.max(1, (int) …)` shape are lifted verbatim
    from legacy `TideRoleRequests.java:128` (primary, called with `0.7` from
    `ChangeSetProcessor.java:329`), `ChangesetRequestAdapter.java:104-115`,
    and `BasicIGAUtils.java:764`. Worked examples in §3.6.1.
  - **Storage** = **always dynamic, NOT stored.** Legacy stored a
    `tideThreshold` role-attribute (`ChangesetRequestAdapter.parseThreshold`
    at `:184-194`) as the primary source with the `0.7 × numberOfAdmins`
    formula as a **stale-cap fallback** (`ChangesetRequestAdapter.java:111-116`;
    `BasicIGAUtils.java:762-765`). The port drops the stored mode entirely to
    remove staleness as a failure class. **No** `iga.threshold_t` /
    `iga.threshold_n` realm attribute, **no** `System.getenv`, **no** per-user
    or per-role `tideThreshold` write, **no** stored column. Nothing to migrate.
  - **Active definition** = a user who **simultaneously** (1) holds the
    `tide-realm-admin` realm-management role, (2) is enabled (`UserModel.isEnabled()`),
    and (3) has a **committed** Tide identity — operationalised as a
    `tide-realm-admin` `USER_ROLE_MAPPING` row with `attestation IS NOT NULL`
    (the inverse of `IgaUnsignedRowScanner.userRoleMappings`,
    `IgaUnsignedRowScanner.java:541-547`). A PENDING (uncommitted) grant has
    no stamped row and does not count. This is **stricter** than legacy's
    `numberOfActiveAdmins` (`ChangesetRequestAdapter.java:196-207`), which did
    not gate on `isEnabled()`.

  firstAdmin mode returns constant `1` and ignores the dynamic count. The
  dynamic branch lives in `TideAttestor.getThreshold`, **not** in the shared
  `IgaScopeResolver` (which stays Tideless-static — see D9 / §12 Q8).

- **D4. Port VRK plumbing into iga-core — it is a NETWORK signing call, not a
  local key accessor.** A new `org.tidecloak.iga.crypto` package with
  `VrkAccessor` + `SecretKeys`. The legacy accessor is **inline** at every call
  site (no central class to port verbatim) — the port creates the central class
  the legacy never had. The accessor reads the **full ORK-signing settings**
  (`activeVrk` + `HomeOrkUrl`/`systemHomeOrk` + `VVKId` + `payerPublic` +
  `obfGVVK`), not just the private key, because `Midgard.SignWithVrk` routes
  **Midgard → ORK network** (the VRK is sharded across the ORKs; user-confirmed
  2026-06-01 — §5.1, §12 Q3). Add `org.tide:MidgardJava` as an
  `optional`/`provided` dep on `iga-core/pom.xml`. **firstAdmin signing is
  therefore Midgard/ORK-blocked on the same swap-point as multiAdmin** — it is
  NOT a local-crypto path that ships independently of the Midgard → ORK
  integration.

- **D5. firstAdmin signs two payload shapes.** (a) The realm's
  `tide-realm-admin` policy bytes (stored on `IgaRolePolicyEntity.policy`),
  signed with VRK and written back to `IgaRolePolicyEntity.policySig` +
  stamped on the CR — **this is the transition trigger**. (b) Any other
  CR's standard row/unit canonical (the same shape today's `combineFinal`
  produces), signed with VRK and stamped on the affected rows. The legacy
  `signContextsWithVrk` per-user-context loop is **dropped**.

- **D6. multiAdmin path already exists; do not touch its public surface.**
  Today's `TideAttestor` IS multiAdmin. The port adds a mode branch around
  it, not a rewrite of it. The Midgard `signClaims()` swap-point remains the
  single `sign(byte[])` method.

- **D7. Transition is internal to `TideAttestor`.** No new
  `/transition` REST endpoint, no admin manual trigger. The flip happens
  inside `combineFinal` on successful signature of the tide-realm-admin
  policy CR while in firstAdmin mode — same JPA transaction as the
  ATTESTATION write.

- **D8. Skip the legacy port for obsolete user-context plumbing.**
  `regenerateDefaultUserContexts` (`FirstAdmin.java:121-158`),
  `signContextsWithVrk` per-context loop (`IGAUtils.java:86-128`), and
  the legacy draft entities used solely for user-context state
  (`TideClientDraftEntity` and friends) are **not ported**. The CR row +
  set/unit envelope shape supersedes them.

- **D9. The dynamic 0.7 threshold is `tide`-attestor-only; Tideless stays
  static.** The dynamic floor lives in `TideAttestor.getThreshold`'s
  multiAdmin branch, **never** in the shared `IgaScopeResolver`. The Tideless
  path (`SimpleNameAttestor`, `iga.attestor` unset/`simple`) keeps its
  attribute-driven static threshold: realm `iga.threshold` → per-scope max →
  1 (`IgaScopeResolver.resolveThresholdInternal`, `IgaScopeResolver.java:292-311`;
  `docs/IGA.md` §"Configuring thresholds"). Both `getThreshold` paths still
  call `IgaScopeResolver.resolveThreshold` first so the per-scope-entity
  `iga.threshold` override (with same-entity `iga.approverRole`) and the
  ADOPT_* short-circuit keep priority; only the `tide` attestor's realm-level
  **default** differs. This split is load-bearing — collapsing the formula
  into the shared resolver would silently change every Tideless realm's
  realm-default threshold from its configured `iga.threshold` to `0.7 × admins`.

- **D10. The admin policy is a regenerated/versioned artifact, re-signed on
  every threshold-changing membership commit (§7a).** Because the multiAdmin
  threshold is `floor(0.7 × activeTideRealmAdmins)`, any committed change to the
  active tide-realm-admin set that moves the floor regenerates the
  `tide-realm-admin` `IgaRolePolicyEntity.policy` (new threshold + role +
  resource) and re-signs `policySig` via VRK → Midgard → ORK. Sub-decisions:
  - **Regen cadence = per committed membership-changing CR, gated by a
    "threshold actually changed" skip** (port of legacy's `IsEqualTo`
    short-circuit, `TideRoleRequests.java:163-168`). Most single adds don't move
    the floor and are skipped; only real changes re-sign. An explicit batch
    mechanism is deferred until/unless a bulk-approve path lands (§7a.4).
  - **Same artifact as the bootstrap sign.** Regen rewrites the **same two
    columns** (`policy`/`policySig`) the firstAdmin bootstrap (§6.2/§7.2) wrote;
    no new table/CR type. The §7 "first policy sign" is the first of many; §7a
    is signs #2…n.
  - **In-place overwrite, no history column** (matches legacy, which mutated
    `initCert`/`initCertSig` in place). An append-only policy-history / epoch
    column is a deliberate *enhancement*, not required by this port — see §12 Q9.
  - Confirmed against legacy `session:2026-06-01 with user` requirement; the
    legacy mechanism is `createRolePolicyDraft` (§7a.0).

- **D11. Mode resolution when no authorizer row exists (Decision 1, §3.1).**
  `resolveMode(session, realm)` with **no** `IgaAuthorizerEntity` row returns
  **`firstAdmin`** when `iga.attestor == "tide"` (the realm is a Tide realm that
  has not bootstrapped its admin policy), and **no-op (`null`)** otherwise
  (simple / Tideless / attribute absent — `SimpleNameAttestor` never consults the
  authorizer entity). When a row **does** exist, its `mode` column is returned.
  **Supersedes** the earlier "no row ⇒ multiAdmin" default. The discriminator is
  the realm attribute `iga.attestor` (`IgaAttestors.java:21-35`), the same one
  §Q4/D9 hinge on. This is the **default** state, not an edge case — `iga_authorizer`
  has **0 rows** in the live demo DB (§9.1). Confirmed `session:2026-06-01 with
  user`. (§3.1 sketch + §3.5 consistency note.)

- **D12. The first authorizer row is created lazily, on first Tide-mode
  `record()`, seeded `firstAdmin` (Decision 2, §9.3).** No eager seed on IGA
  toggle-on, no mandatory `POST /iga/authorizers`, no realm-init bootstrap.
  `TideAttestor.record()` checks for the row; if absent **and** `iga.attestor ==
  "tide"`, it creates one with `mode="firstAdmin"` via the existing
  `IgaAuthorizerService.create()` persist path (`IgaAuthorizerService.java:34`)
  before recording. Self-healing, zero migration, fits the 0-row live reality.
  **Closes the "retroactive seed" open item** — there is nothing to retroactively
  seed; an already-on Tide realm gets its row on its **next** Tide CR, no
  backfill (§9.4). If the realm has no `tide-vendor-key` component the seed is
  deferred and the no-row branch (D11) keeps reporting `firstAdmin`. Confirmed
  `session:2026-06-01 with user`.

- **D13. Reuse `IgaFirstAdminSignPreviewService` for CR→signing-payload
  resolution (Decision 3, §6.1a).** The existing prototype already resolves a CR
  to its full FK-expanded signing payload and logs it, with **no crypto**
  (`IgaFirstAdminSignPreviewService.java:42-519`; TODO `Midgard.signClaims()` at
  `:3-6`). TideAttestor's firstAdmin branch **reuses its payload builder** — the
  `build(IgaChangeRequestEntity)` assembler (`:97`, reached via `buildAndLog` at
  `:78`) — extracted to a reusable public method (small refactor) so there are
  **not two parallel payload builders that can drift**. TideAttestor then performs
  the Midgard → ORK VRK sign itself (the sign is a network op, not done by the
  preview service — corrected §5/§6/Q3). Routing: the **tide-realm-admin POLICY
  CR** signs `policy.getBytes(UTF_8)` verbatim (§6.2, bypassing the map builder);
  **all other firstAdmin-era CRs** (attested rows/units) resolve through the
  reused builder (§6.3). Confirmed `session:2026-06-01 with user`.

---

## 12. Open questions / risks

These should be answered (or explicitly accepted as risks) before
implementation begins.

- **Q1. Legacy postgres dead data.** The legacy
  `ChangesetRequestEntity`, `AccessProofDetailEntity`,
  `TideRoleDraftEntity`, `TideUserRoleMappingDraftEntity` rows (under
  `tidecloak-iga-extensions-old/tide-jpa-providers/src/main/java/org/tidecloak/jpa/entities/`)
  may exist as **live data** in a Tide-deployed Postgres. The port has no
  migration plan for them. Decisions needed:
  (a) Are any production realms running the legacy iga-provider today, or
  is the legacy code only on dev/staging?
  (b) If (a) is yes, do we migrate the legacy rows to the new schema, or
  do we accept that legacy realms cannot upgrade in-place and must be
  re-bootstrapped?

- **Q2. UI awareness of the transition.** Does `admin-ui-next` need a visible
  signal that the realm has flipped from firstAdmin → multiAdmin? Today
  there is no UI surface that reads `IgaAuthorizerEntity.type` or the new
  `mode`. Options:
  (a) Add a `GET /iga/authorizers/state` endpoint that returns
  `{mode: "firstAdmin"|"multiAdmin"}` and have the UI poll it.
  (b) Surface the mode in the existing `GET /iga/authorizers/{id}` response
  (`IgaAdminResource.java:1041-1052`) and let the UI infer transitions from
  the change.
  Decision: out of scope for this plan; flag to the admin-ui-next PM after
  this port lands.

- **Q3. Is `Midgard.SignWithVrk` (firstAdmin signing) a local op? — RESOLVED:
  NO, it goes to the ORKs.** The firstAdmin branch uses `Midgard.SignWithVrk`
  (`IGAUtils.java:57-59, 113-115`), and the multiAdmin branch will use
  `Midgard.SignModel` / `signClaims`. The earlier draft claimed `SignWithVrk` was
  a "synchronous local call (no ORK round-trip)" — **that was wrong.**
  **User-confirmed 2026-06-01:** the VRK is sharded across the ORK network via
  threshold cryptography, so `Midgard.SignWithVrk` makes a **network call to the
  ORKs**, even for single-admin firstAdmin signing. Code evidence: the Java
  `Midgard.SignWithVrk(String msg, String vrk)` (`Midgard.java:160-167`) *looks*
  local — it takes only message + key string — but it delegates to the JNA
  binding `sign_with_vrk` (`MidgardInterface.java:14`) into Midgard's **native C#
  core**, whose Flow/Client layer holds **HTTP clients to ORK nodes**
  (`Midgard/Core/Clients/NodeClient`,`NetworkClient`). **The network boundary is
  inside Midgard's native core, not visible in the Java `SignWithVrk`
  signature** — which is exactly the indirection that made the "local" reading
  plausible. The ORK endpoint is supplied via `settings.HomeOrkUrl`
  (`= systemHomeOrk`) / `settings.VVKId` from the `tide-vendor-key` component
  (`IGAUtils.java:43-44, 101-102`).

  **Consequence — firstAdmin is NOT a way to sidestep the Midgard/ORK
  dependency.** firstAdmin signing is **blocked on the same Midgard → ORK
  integration as multiAdmin.** The pending `Midgard.signClaims()` /
  "M2M 503 → signed" blocker that gates multiAdmin's `TideAttestor.sign()`
  swap-point **also gates firstAdmin signing**. The port **can** land the
  mode-branching, the transition trigger, and the dynamic-threshold logic
  without ORKs (those are pure JPA/count logic, testable by stubbing `sign()` —
  §10), but **end-to-end firstAdmin signing cannot be green until the
  Midgard → ORK VRK-signing call is wired** — the same swap-point story as
  multiAdmin's `TideAttestor.sign()`. The shared risks are now **two**: (1) the
  build-time `MidgardJava` artifact availability (§5.3), and (2) the runtime
  ORK-reachability / M2M signing path — and **both** apply to **both** modes.

- **Q4. VRK-component availability gate — NOT the Tide-vs-Tideless
  discriminator (CORRECTED 2026-06-01).** An earlier draft treated the presence
  of a `tide-vendor-key` component as *the* signal that distinguishes a Tide
  realm from a Tideless realm. **That is factually wrong, and `tide-vendor-key`
  does not appear anywhere in iga-core at all** (grep 2026-06-01: zero matches in
  `iga-core/src/main/java`; the component name lives only in `tidecloak-idp-extensions`
  / the key provider and the old extensions). **The canonical Tide-vs-Tideless
  discriminator in current iga-core is the realm attribute `iga.attestor`**:
  `IgaAttestors.resolveAttestor` reads `realm.getAttribute("iga.attestor")` and
  selects the `tide` attestor (`TideAttestor.ID = "tide"`,
  `TideAttestor.java:53`) when it equals `"tide"`, otherwise falls back to the
  default `simple` attestor (`SimpleNameAttestor.ID = "simple"`) — see
  `IgaAttestors.java:21-35`. That same attribute is the Tideless/Tide boundary
  the threshold split (§Q8, D9) already hinges on (`IgaScopeResolver.java:50`).
  So:
  - **"Is this a Tide realm?"** ⇒ `iga.attestor == "tide"` (the attestor SPI
    resolution), **not** the presence of a `tide-vendor-key` component.
  - **"Can firstAdmin actually sign?"** is a *separate, narrower* question — it
    needs VRK key material + ORK config. In legacy that material came from the
    `tide-vendor-key` component (`MultiAdmin.java:474-484`), and the §5 VRK port
    re-introduces that component read into iga-core (where it does not yet exist).
    The firstAdmin branch therefore hard-requires that component **as a
    VRK-availability precondition** (no VRK = no signature), but its absence means
    "this Tide realm is not yet VRK-provisioned," **not** "this is a Tideless
    realm." A genuinely Tideless realm is identified by `iga.attestor != "tide"`
    and never reaches the firstAdmin branch in the first place (it resolves to
    `SimpleNameAttestor`).
  Decision (unchanged in substance): firstAdmin signing remains gated on VRK
  component availability; the bootstrap seed (§9.3) is skipped when the VRK
  material is absent. The **correction** is only in *naming the discriminator* —
  `iga.attestor`, not `tide-vendor-key` — so the doc does not mislead the
  implementer into using component-presence as the mode/Tide switch.

- **Q5. `IgaAuthorizerEntity.type` vs new `mode` redundancy.** The existing
  `type` column (`IgaAuthorizerEntity.java:46-47`) is documented as
  free-text. After this port, `type` and `mode` could in principle hold
  different values. Recommendation: **leave `type` alone** (no semantic
  change) and let `mode` be the single source of truth for the
  firstAdmin/multiAdmin distinction. A future cleanup can collapse them
  once the new shape is proven.

- **Q6. Concurrent CRs across the transition.** What happens if two CRs
  are committed nearly simultaneously while still in firstAdmin mode and
  one of them is the tide-realm-admin policy CR? Atomicity (§7.3)
  protects the **per-CR** state, but two concurrent commits could both
  read `mode = "firstAdmin"`, both sign with VRK, and both flip the mode.
  The flip is idempotent (`setMode("multiAdmin")` is a no-op if already
  multiAdmin) and the per-CR signing is correct in both cases, so the
  worst outcome is **one redundant `setMode` call**. Accept as a non-issue;
  document in the implementation that the flip is naturally idempotent.

- **Q7. "Committed Tide identity" signal — RESOLVED.** The active-admin
  count's third sub-predicate (§3.7) needs a "committed (not pending) Tide
  identity" signal. **Found in current iga-core:** a `tide-realm-admin`
  `USER_ROLE_MAPPING` row with `attestation IS NOT NULL` — the inverse of the
  unsigned-row scan `IgaUnsignedRowScanner.userRoleMappings`
  (`IgaUnsignedRowScanner.java:541-547`). A PENDING `GRANT_ROLES` CR stamps
  nothing (its scratch row is rolled back), so a committed grant is exactly a
  stamped one; this one signal subsumes both "committed Tide identity" and
  "not a pending CR". **Residual risk:** this treats a *committed role grant*
  as the Tide-identity proof. If a future requirement distinguishes "committed
  role grant" from "completed Tide enrollment ceremony" (a separate
  per-user-key signal that today lives outside iga-core, in
  `tidecloak-idp-extensions` / the key provider), the predicate would need a
  second conjunct. For this port the stamped-grant signal is the canonical,
  in-module check and is what the count uses. iga-core has **no** per-user
  `tideUserKey` / `tideEnrolled` / `TIDE_USER` attribute (grep-verified
  2026-06-01).

- **Q8. Tideless `iga.threshold` (singular) vs Tide dynamic 0.7 — kept
  distinct.** The **existing Tideless flow** uses the realm attribute
  `iga.threshold` (singular) as its static realm-default threshold, resolved
  in `IgaScopeResolver.resolveThresholdInternal` (`IgaScopeResolver.java:292-311`,
  attribute key `ATTR_THRESHOLD = "iga.threshold"` at `:50`; documented in
  `docs/IGA.md` §"Configuring thresholds" / §"Modes: Tideless vs Tide"). The
  dynamic 0.7 formula is **Tide-mode-only** and lives in
  `TideAttestor.getThreshold` (§3.5, D9). These must not be conflated:
  - Tideless realm (`iga.attestor` unset/`simple`): keeps static realm
    `iga.threshold` → per-scope max → 1. Unchanged.
  - Tide realm (`iga.attestor = tide`), multiAdmin mode: realm-level default
    becomes `Math.max(1, (int)(0.7 × activeTideRealmAdmins))`; per-scope
    `iga.threshold` (with same-entity `iga.approverRole`) and ADOPT_* bypass
    still win. firstAdmin mode → constant 1.

  No risk to the Tideless story as long as the dynamic branch is not pushed
  down into the shared resolver (the D9 invariant). Verified against
  `IgaScopeResolver.java:50, 292-311` and `docs/IGA.md` (lines 16-18, 165-205,
  275-363) on 2026-06-01.

- **Q9. Threshold-change policy regeneration — quorum + lazy-vs-eager + history
  (§7a).** The dynamic threshold makes the admin policy a regenerated/re-signed
  artifact (§7a, D10). Three residual decisions:
  - **(a) OLD-vs-NEW-threshold quorum — RESOLVED from legacy, recommend keep.**
    Legacy signs the regenerated policy under the **current/old** admin set's
    quorum + the **VRK**, and the **new** threshold takes effect only for
    *subsequent* CRs (§7a.0 step 5 / §7a.3: VRK-authorized draft at
    `TideRoleRequests.java:179-182`; deferred policy commit "would update the ORK
    threshold mid-batch" at `MultiAdmin.java:429-431`). **Recommendation: port
    the legacy semantics** (OLD quorum + VRK installs NEW threshold) — it avoids
    the circular "need the post-add quorum to authorize the add". The only thing
    to confirm with the user: whether to instead require the **new** (post-change)
    threshold's quorum to ratify the regenerated policy (stricter, non-legacy).
    **User call requested.**
  - **(b) Disable/enable/delete — lazy gate vs eager re-sign.** GRANT/REVOKE are
    governed CRs and regen at commit (fail-closed, atomic — §7a.6). DISABLE /
    RE-ENABLE / DELETE are **not** CRs today and legacy ignored them in its count
    entirely (§7a.0 step 4). The new stricter predicate (§3.7) means they **do**
    move the live `getThreshold` gate (which self-corrects on the next quorum
    check). **Open: do we also eagerly re-sign the stored `policy`/`policySig`
    when an admin is disabled/deleted (requires ORKs reachable, can't be
    transactional with a non-CR event), or accept that the *signed artifact*
    lags the *live gate* until the next ORK-backed regen?** **Recommendation:
    accept the lag** — the authorization gate is always live and correct; the
    signed policy is a published record reconciled lazily. **User call
    requested.**
  - **(c) Policy history/epoch.** Legacy overwrote the policy in place with no
    version trail (§7a.2, D10). If an audit history of past thresholds is
    required, add an epoch column or append-only policy-history table (new
    schema, beyond the §4 `MODE` add). **Recommendation: match legacy (no
    history) for this port; flag as enhancement.**

  **Contradiction this introduces with existing plan content:** §7's framing of
  the transition as "the first policy sign" / "first sign only" is now too
  narrow — the transition is the **first of many** signs (bootstrap = sign #1;
  §7a regens = signs #2…n, same `policy`/`policySig` columns, same VRK → ORK
  primitive). §7.2 has been annotated and §7a.5 makes the continuity explicit,
  but reviewers used to the "one-time bootstrap sign" mental model should note
  the softening. No other existing content is contradicted — the dynamic-0.7
  formula (§3.6), VRK-via-ORK boundary (§5.1), schema (§4), and the
  firstAdmin→multiAdmin transition (§7) are all preserved and reused, not
  changed.

- **Q10. Mode resolution when no `IgaAuthorizerEntity` row exists — RESOLVED
  `session:2026-06-01 with user`.** (Was: implicitly "no row ⇒ multiAdmin", the
  earlier §3.1 default — flipped.) **Decision:** `resolveMode(session, realm)`
  with no row returns **`firstAdmin`** when `iga.attestor == "tide"` (Tide realm,
  admin policy not yet bootstrapped) and **no-op (`null`)** otherwise (simple /
  Tideless / attribute absent — `SimpleNameAttestor` never consults the authorizer
  entity); a present row yields its `mode` column. This is the **default** case,
  not an edge case — `iga_authorizer` holds **0 rows** in the live demo DB despite
  13 authorizations across 9 CRs (§9.1). Discriminator: `iga.attestor`
  (`IgaAttestors.java:21-35`), the same attribute §Q4/D9 hinge on. See §3.1 sketch
  + §3.5 consistency note + D11.

- **Q11. Where the first authorizer row is created — RESOLVED `session:2026-06-01
  with user`.** (Was: §9.1 "retroactive seed is a DESIGN DECISION, left for the
  user" + §9.3 two landing-site options (a)/(b) — all closed.) **Decision:**
  **lazily, on the first Tide-mode `TideAttestor.record()`, seeded
  `mode="firstAdmin"`** via the existing `IgaAuthorizerService.create()` persist
  path (`IgaAuthorizerService.java:34`). No eager toggle-on seed, no mandatory
  `POST /iga/authorizers`, no realm-init bootstrap, **no retroactive/backfill
  seed** — there is nothing to retroactively seed because the first post-port Tide
  CR materialises the row (already-on realms self-heal on their next Tide CR,
  §9.4). If no `tide-vendor-key` component, the seed defers and the Q10 no-row
  branch keeps reporting `firstAdmin`. See §9.3 + D12.

- **Q12. Which payload builder the firstAdmin branch uses — RESOLVED
  `session:2026-06-01 with user`.** **Decision:** **reuse the existing
  `IgaFirstAdminSignPreviewService` payload builder** (`build(IgaChangeRequestEntity)`
  at `IgaFirstAdminSignPreviewService.java:97`, reached via `buildAndLog` at
  `:78`) for CR→signing-payload resolution, extracted to a reusable public method
  (small refactor) so there are **not two parallel payload builders that can
  drift**. TideAttestor performs the Midgard → ORK VRK sign itself (network op,
  not the preview service's job — it has no crypto; TODO at `:3-6`). The
  tide-realm-admin POLICY CR signs `policy.getBytes(UTF_8)` verbatim (§6.2,
  bypassing the map builder); all other firstAdmin-era CRs route through the
  reused builder (§6.3). See §6.1a + D13.

---

## Source map

- **Legacy (port-from):**
  - `tidecloak-iga-extensions-old/tidecloak-iga-provider/src/main/java/org/tidecloak/tide/iga/authorizer/FirstAdmin.java:37-168` — bootstrap signer.
  - `tidecloak-iga-extensions-old/tidecloak-iga-provider/src/main/java/org/tidecloak/tide/iga/authorizer/MultiAdmin.java:42-546` — steady-state T-of-N signer.
  - `tidecloak-iga-extensions-old/tidecloak-iga-provider/src/main/java/org/tidecloak/tide/iga/authorizer/Authorizer.java:13-17` — legacy interface.
  - `tidecloak-iga-extensions-old/tidecloak-iga-provider/src/main/java/org/tidecloak/tide/iga/authorizer/AuthorizerFactory.java:6-42` — legacy factory.
  - `tidecloak-iga-extensions-old/tidecloak-iga-provider/src/main/java/org/tidecloak/tide/iga/utils/IGAUtils.java:23-129` — `signInitialTideAdmin` + `signContextsWithVrk`.
  - `tidecloak-iga-extensions-old/tide-jpa-providers/src/main/java/org/tidecloak/jpa/entities/AuthorizerEntity.java:19-81` — legacy AUTHORIZER table.
  - `tidecloak-iga-extensions-old/shared-models/src/main/java/org/tidecloak/shared/Constants.java:6-13` — `TIDE_REALM_ADMIN`, `TIDE_INITIAL_AUTHORIZER`, `TIDE_MULTI_ADMIN_AUTHORIZER`.
  - `tidecloak-iga-extensions-old/shared-models/src/main/java/org/tidecloak/shared/models/SecretKeys.java:6-16` — `activeVrk` shape.

- **Current (port-into):**
  - `tidecloak-iga-extensions/iga-core/src/main/java/org/tidecloak/iga/attestors/TideAttestor.java:51-380` — the receiver of the mode branch.
  - `tidecloak-iga-extensions/iga-core/src/main/java/org/tidecloak/iga/attestors/IgaAttestor.java:19-72` — SPI surface (unchanged by the port).
  - `tidecloak-iga-extensions/iga-core/src/main/java/org/tidecloak/iga/attestors/IgaScopeResolver.java:50, 283-311` — threshold/approver realm attributes; the **Tideless static** `iga.threshold` resolution that stays UNCHANGED (the Tide-mode dynamic 0.7 floor lands in `TideAttestor.getThreshold`, not here — §3.5, D9).
  - `tidecloak-iga-extensions/iga-core/src/main/java/org/tidecloak/iga/attestors/TideAttestor.java:104-106` — today's plain `getThreshold` delegation; gets the mode branch + dynamic 0.7 floor (§3.5).
  - `tidecloak-iga-extensions/iga-core/src/main/java/org/tidecloak/iga/services/IgaUnsignedRowScanner.java:541-547` — `userRoleMappings` unsigned-row query; its inverse (`attestation IS NOT NULL`) is the "committed Tide identity" signal for the active-admin count (§3.7, §12 Q7).
  - `tidecloak-iga-extensions/iga-core/src/main/java/org/tidecloak/iga/attestors/IgaAttestors.java:21-35` — attestor resolver.
  - `tidecloak-iga-extensions/iga-core/src/main/java/org/tidecloak/iga/attestors/SimpleNameAttestor.java:29-103` — reference for "simple" attestor (unchanged by the port).
  - `tidecloak-iga-extensions/iga-core/src/main/java/org/tidecloak/iga/entities/IgaAuthorizerEntity.java:34-78` — gets new `mode` column.
  - `tidecloak-iga-extensions/iga-core/src/main/java/org/tidecloak/iga/entities/IgaRolePolicyEntity.java:38-112` — `policy` + `policySig` columns (signed by the firstAdmin branch).
  - `tidecloak-iga-extensions/iga-core/src/main/java/org/tidecloak/iga/entities/IgaChangeRequestEntity.java:35-72` — CR row, `actionType` + `entityType` + `entityId` (read by the transition detector).
  - `tidecloak-iga-extensions/iga-core/src/main/java/org/tidecloak/iga/providers/IgaAuthorizerService.java:13-78` — authorizer CRUD (the bootstrap seed extends it).
  - `tidecloak-iga-extensions/iga-core/src/main/java/org/tidecloak/iga/providers/IgaFirstAdminSignPreviewService.java:42-519` — payload-resolution prototype that already showed which entities the firstAdmin branch needs to read.
  - `tidecloak-iga-extensions/iga-core/src/main/java/org/tidecloak/iga/rest/IgaAdminResource.java:259-392, 1054-1096` — `authorize` / `commit` per-CR endpoints + `POST /iga/authorizers`.
  - `tidecloak-iga-extensions/iga-core/src/main/java/org/tidecloak/iga/rest/TideAdminCompatResource.java:74-277` — `toggle-iga` handler (where the firstAdmin seed should land per §9.3).
  - `tidecloak-iga-extensions/iga-core/src/main/java/org/tidecloak/iga/replay/IgaReplayDispatcher.java:130-278` — dispatcher entrypoint + per-action stamp UPDATEs (unchanged by the port).
  - `tidecloak-iga-extensions/iga-core/src/main/resources/META-INF/iga-changelog-master.xml:1-24` — master changelog (new include lands here).
  - `tidecloak-iga-extensions/iga-core/src/main/resources/META-INF/iga-changelog-2.4.0.xml:32-37` — reference for the column-add pattern this port mirrors.
  - `tidecloak-iga-extensions/iga-core/pom.xml:26-101` — dependency list (gets the optional Midgard dep added).

- **Reference (related current docs):**
  - `tidecloak-iga-extensions/docs/IGA.md:165-205, 280-330` — Tideless vs Tide modes; existing threshold/approver attribute family.
  - `tidecloak-iga-extensions/docs/iga-tve-producer-design.md:1-340` — sibling design doc; the firstAdmin branch consumes the **same** 18 envelope shape this producer emits (referenced by §6.3 of this plan).
