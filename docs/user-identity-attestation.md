# `user_identity` Attestation: Self-Reg & Admin-Invite

How `iga-core` signs and stamps the `user_identity` attestation unit for newly-onboarded
users, and the invariants that keep ORK token-time verification passing. Read this before
touching self-registration, `link-tide-account`, or the invite/attestation flow in this
module — it captures hard-won gotchas that are not obvious from the code alone.

All file/line references below are verified against the tree as of the
`agent/selfreg-attestation-signing` branch.

---

## 1. The two SPI entry points

The cross-module contract lives in the `IgaSystemProvisionerProvider` SPI
(`iga-core/src/main/java/org/tidecloak/iga/providers/IgaSystemProvisionerProvider.java`),
implemented by `DefaultIgaSystemProvisionerProvider`. `tidecloak-idp-extensions` resolves
it via `session.getProvider(IgaSystemProvisionerProvider.class)` and calls it **without a
Maven dependency on `iga-core`** (SPI-only coupling). The two relevant methods:

| Method | Caller / flow | What it does |
|---|---|---|
| `signAndStampUserIdentity(realm, userId, tideAuthDataJson, settingsSignedBlob, settingsSigB64)` | self-reg / link, IGA-on | Re-signs the **full current** `user_identity` envelope via the gVRK ceremony, stamps the sig onto `UserEntity.attestation`. |
| `signAndStampInvitableUserIdentity(realm, userId, userPublic, tideAuthDataJson, settingsSignedBlob, settingsSigB64)` | admin-invite (`LinkTideAccount` required action), self-reg-OFF | Two-copy invite ceremony (Unit A pre-link + Unit B post-link). |

Note the **extra `userPublic` param** on the invite method — it is the **tideUserKey**
string. The invite method writes the link attributes itself rather than relying on the
caller having written them.

Both delegate to static methods on `TideAttestor`:
- `signAndStampUserIdentity` → `TideAttestor.signUserIdentityWithGVrk(...)`
  (`TideAttestor.java`, currently ~line 2743).
- `signAndStampInvitableUserIdentity` → `TideAttestor.signInvitableUserIdentityWithGVrk(...)`
  (`TideAttestor.java`, currently ~line 2912).

---

## 2. The invite ceremony — exact order, and WHY

`TideAttestor.signInvitableUserIdentityWithGVrk` performs a **REORDER ceremony**. The
step order is load-bearing; do not rearrange it:

1. **READ the stored Unit A signature FIRST** (before any write). It is read straight from
   `UserEntity.attestation` via JPQL (`SELECT e.attestation FROM UserEntity e WHERE e.id = :id`).
   This is the VVK signature the admin's CREATE_USER stamp left behind. Shape is
   `TIDE-FIRSTADMIN-v1:` + base64(64-byte sig) — validated for prefix and 64-byte length,
   fail-closed otherwise.
2. **Recompute Unit A UNFILTERED while the row is still PRE-LINK** —
   `RealmAttestationExporter.userIdentity(user, realm.getId()).serialize()`, taken **before**
   `vuid`/`tideUserKey` are written. Because the row is still in its pre-link state, this byte-
   matches the bytes the stored sig was made over. The shipped value is
   `unlinkedSignedUnitA = unitA ‖ storedSig` (concatenation), which the ORK VVK-verifies.
3. **Parse `tideAuthDataJson`** (`AuthRequest` String + base64 `BlindSig`) and derive the
   authenticated vuid (`AuthRequest.User`) — see §5. Done before the write so the injected
   vuid is the Tide vuid, not the KC id.
4. **Write the link attributes**: `user.setSingleAttribute("vuid", authVuid)` and
   `user.setSingleAttribute("tideUserKey", userPublic)` — same KC API `LinkTideAccount` uses.
5. **Recompute Unit B UNFILTERED (POST-link)** — the same `userIdentity(...)` export, now
   including `vuid`/`tideUserKey`.
6. **ORK signs Unit B** via the gVRK ceremony (`signInvitableUserIdentityUnitWithGVrk` →
   `SetInviteData(unlinkedSignedUnitA, tideUserKey, unitB)`).
7. **OVERWRITE `UserEntity.attestation`** with `TIDE-FIRSTADMIN-v1:` + base64(Unit B sig), so
   the token-time exporter (which recomputes the FULL unit == Unit B) replays correctly.

The whole thing is **fail-closed**: any missing material, a missing/short stored Unit A sig,
a parse failure, or a signing failure throws — an invitable `user_identity` must never be
stamped with a fake or partial signature.

---

## 3. No sidecar table — by design

Unit A is reconstructed from (recompute of the pre-link row) + (the pre-existing
`UserEntity.attestation` column). A dedicated `IGA_SIGNED_USER_IDENTITY` table was tried and
**removed**. Do **not** reintroduce a table to cache prior signed envelopes — the
recompute-plus-`attestation`-column approach IS the design. (Confirmed: no
`IGA_SIGNED_USER_IDENTITY` reference remains in `iga-core/src`.)

---

## 4. The byte-equality invariant (the #1 cause of ORK invite rejections)

The invite-time Unit A recompute must be **byte-identical** to whatever the stored admin
signature was made over. The same `RealmAttestationExporter.userIdentity(...)` recompute is
used at **token time**, so the stored `attestation` sig must always verify against it.

Key facts:
- The ORK verifies the **literal CBOR bytes verbatim** (Ed25519/VVK) — there is **no C#-side
  re-canonicalization that would paper over field drift**. Any difference between the
  CREATE_USER stamp bytes and the invite/token recompute bytes breaks the signature.
- User attributes are emitted **sorted by name (ordinal)** but with each attribute's
  `values[]` left in **stored order** — see `RealmAttestationExporter.userAttributeNameValues`
  (`RealmAttestationExporter.java` ~line 1508). This mirrors the ORK canonicalizer
  (`AttestationUnit.GetNameValuesList`, ordinal sort by name, values kept stored-order).
  `userIdentity(...)` itself (~line 1048) emits id/username/email/emailVerified/firstName/
  lastName + the sorted attribute list.

**Known drift sources and how they are neutralised:**

- **`email_verified` flipping false→true** when the user clicks the invite/link action.
  Suppressed *at source* in `tidecloak-override`'s `ExecuteActionsActionTokenHandler` for the
  `link-tide-account-action` (cross-repo — not in this module). If invite verification starts
  failing, check that suppression first.
- **`vuid` / `tideUserKey`** — written only AFTER Unit A is captured (step 4 above), so they
  never pollute Unit A. They are present in Unit B (and at token time), which is what the
  overwritten sig in step 7 covers.

---

## 5. The vuid binding gotcha (recently fixed — do not regress)

On the **invite path**, the injected `vuid` attribute MUST be the **authenticated Tide vuid**,
read as `org.midgard.models.AuthRequest.From(authData.AuthRequest).User` — **NOT** the KC
`userId`.

Why: the ORK's identity-binding check requires Unit B's injected `vuid` to equal the
`AuthRequest.User` it parses from the *same* `AuthRequest`. The string is injected verbatim
(no re-encoding) so the equality holds by construction.

- **Self-reg** gets away with using `userId` only because there the KC user is created with
  `id == vuid`.
- An **admin-invited** user has a **random KC UUID**, so injecting `userId` as the vuid fails
  the ORK check. This was the recently-fixed bug.

Note: only the `vuid` **attribute** carries the Tide vuid. The unit's `user_id` / `target_id`
remain the KC id (that comes from `user.getId()` inside `userIdentity(...)`).

---

## 6. IGA-off behaviour

These SPI methods must **never** be called for a realm where IGA is disabled. Enablement is
`"true".equalsIgnoreCase(realm.getAttribute("isIGAEnabled"))`.

- `tidecloak-idp-extensions` gates the calls at the call site.
- `DefaultIgaSystemProvisionerProvider` adds a **defensive guard** — both signAndStamp methods
  throw `IllegalStateException` if the realm is IGA-disabled.

When IGA is off there is **no attestation ceremony at all**: idp sets `vuid`/`tideUserKey`
directly and no `user_identity` signature is produced.

---

## Quick reference (constants & paths)

- `TideAttestor.FIRSTADMIN_SIG_PREFIX = "TIDE-FIRSTADMIN-v1:"` — the stored sig prefix.
- `TideAttestor.TIDE_VENDOR_KEY_PROVIDER_ID = "tide-vendor-key"` — the realm component
  carrying the VRK config used to build the sign settings.
- SPI: `org.tidecloak.iga.providers.IgaSystemProvisionerProvider` /
  `DefaultIgaSystemProvisionerProvider`.
- Ceremony: `org.tidecloak.iga.attestors.TideAttestor` (`signUserIdentityWithGVrk`,
  `signInvitableUserIdentityWithGVrk`).
- Recompute: `org.tidecloak.iga.producer.RealmAttestationExporter#userIdentity`.
