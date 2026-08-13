# Server identity — workload & realm certificates

How a workload gets an mTLS client certificate, and how a realm gets its TLS server certificate
plus root CA. Read this before touching `ServerCertSigner`, `ResourceIdentityAttestations`,
`ServerIdentityResourceProvider`, `IgaRealmCertService`, or the `REQUEST_*_CERT` replay branches.

Tidecloak never builds a certificate. It submits CSRs; the ORK cohort constructs every
TBSCertificate and threshold-signs it with the gVVK, returning the TBS bytes alongside the
signatures, which this module pairs back together and validates before storing.

## The two flows

| | Client (workload) | Realm |
|---|---|---|
| Action type | `REQUEST_SERVER_CERT` | `REQUEST_REALM_CERT` |
| CR entity | `CLIENT` / clientId | `REALM` / realmId |
| Sidecar | `IGA_SERVER_CERT_DRAFT` (per client+keypair) | `IGA_REALM_CERT` (per realm, one row per issuance) |
| Filed by | `POST /realms/{r}/tide-server-identity/request` (CSR body + single-use enrolment token) | `ensureRealmCertRequested`, as a side effect of the FIRST client enrolment in the realm |
| Carrier builder | `ServerCertSigner.buildApprovalModel` | `ServerCertSigner.buildRealmApprovalModel` |
| Commit | `IgaReplayDispatcher.replayRequestServerCert` → `issue` | `replayRequestRealmCert` → `issueRealm` |
| Yields | one leaf | realm server certificate **and** root CA (inseparable) |
| Key owner | the workload (CSR arrives from outside) | Tidecloak (`IgaRealmCertService.CreateRealmCertificateSigningRequest`) |

The realm pair is realm-scoped, so it is requested ONCE and shared. Client requests are chained to
it with `dependsOn` when it is not yet issued — a leaf committed before its anchor exists cannot
complete a handshake. `findPending` returns an in-flight realm CR so every client enrolling during
the approval window chains to the SAME prerequisite rather than filing duplicates.

## ORK contract — the expensive-to-re-derive parts

Authority: `Midgard/Java/.../RequestExtensions/ResourceIdentitySignRequest.java` and
`ork/.../TidecloakToken/ResourceIdentitySignRequest.cs`. **Check both before changing framing —
they have changed under us more than once.**

### Two modes, one request

`SetResourceIdentityRequest` (client leaf) and `SetTidecloakRealmRequest` (realm pair) are
INDEPENDENT optional sub-requests; at least one must be set. This module drives them separately —
asking for both on every enrolment would re-issue Tidecloak's own TLS certificate each time a
workload enrolled. The realm attestation is required in BOTH modes: the ORK reads the realm name
from it before it looks at what was requested.

### Draft slots are fixed; response slots are COMPACTED

Draft: realm attestation, resource request, realm request — always written, an unrequested
certificate is a present-but-zero-length slot.

The response is not. `PrepareDatasToSign` appends a slot only for what was actually requested:

```
client mode -> [0] resource
realm mode  -> [0] realm server certificate, [1] root CA
(both)      -> [0] resource, [1] realm server cert, [2] root CA
```

Reading a fixed index across modes silently mismatches. Hence `CLIENT_MODE_SLOT_*` /
`REALM_MODE_SLOT_*` rather than one shared set.

### Subject naming — three different strings

| Thing | Value |
|---|---|
| Client CSR subject | `CN=client_<clientId>` — the HUMAN clientId, checked literally against attested `client_config.ClientId` |
| Realm CSR subject | `CN=realm_<realmName>` — **no `_ca` suffix** |
| Issuer of both | `CN=realm_<realmName>_ca` — the root CA, built by the ORK |
| Client cert SAN | `urn:tide:client:<ClientIdUuid>` — the client's internal **UUID**, from the attestation, not the CSR |

So the CN carries the clientId and the SAN carries the UUID. Enrolment resolves the client with
`getClientByClientId`; a consumer matching on the SAN must use `getClientById`.

### Keys, serials, lifetimes

- **Both CSRs must carry a named-curve P-256 subject key** — resource and realm alike. Enforced in
  `CertificationRequestParser.parseAndVerify`, so it applies to all three callers (public enrolment,
  admin-filed request, and the realm CSR this module generates) and cannot be half-applied. Explicit
  curve parameters are refused even when they describe P-256.
- Issued certificates are always Ed25519-signed (the gVVK), whatever the subject key — X.509 keeps
  subject-key and signature algorithms independent.
- Client/realm serials are generated here before approval opens, so admins approve a fixed
  identity. The **root CA serial is derived by the cohort** from the gVVK SPKI and must not be sent.
- Lifetimes: client leaf **1 month**; realm server certificate and root CA **20 years**.
  `IssuedCertificateValidator` has a separate ceiling per type (21y allows for leap days).

### frontendUrl

The realm server certificate's SAN dNSName — the only thing a TLS client checks (RFC 6125). The ORK
takes it from the request, else from `realm_config.FrontendUrl`, and refuses if neither has one.
`resolveRealmFrontendUrl` prefers the attested value (gVVK-signed) and returns null; it only falls
back to this node's `UrlType.FRONTEND` base URI when the realm has no `frontendUrl` attribute. Must
be absolute http(s) with a **DNS host** — an IP literal is rejected.

### Timestamp lives in dynamic data

The certificate `NotBefore` is stamped at SEND time (`stampCertificateTimestamp`), as 8 bytes
little-endian unix seconds in `DynamicData` — NOT in the draft. `GetDataToAuthorize()` hashes only
the draft and expiry, so dynamic data is outside what dokens cover. This is what lets a carrier
built at approval time survive an approval window longer than the ORK's 5-minute clock tolerance.

## Authorization — two different things, two different packs

The single most confusable part of this code. **Getting these backwards produces "This authorizer
has not allowed the model X to be authorized".**

| | What it authorizes | Pack | Model the ORK sees |
|---|---|---|---|
| **Creation auth** — `initializeCreationAuth` → `ModelRequest.InitializeTideRequestWithVrk` | the vendor CREATING a carrier that admins will later doken | **MAIN gVRK** (`gVRK` / `gVRKCertificate`) | outer `TideRequestInitialization:1` |
| **Approval auth**, firstAdmin — `authorizeWithVrk` | the change itself; the VRK IS the approver | **firstAdmin pack** (`authorizer` / `authorizerCertificate`), burned at the multiAdmin flip | `ResourceIdentity:1` |
| **Approval auth**, multiAdmin | the change itself, by admin doken quorum | dokens validated against the M0 Policy | `Policy:1` |

`InitializeTideRequestWithVrk` **throws unless `AuthFlow == "Policy:1"`** — it exists only to mint a
creation authorization for a carrier that will accumulate dokens. A VRK-authorized request has no
such two-step: it is authorized and signed in one pass.

`new ResourceIdentitySignRequest(usePolicy)` picks the flow: `true` → `Policy:1`, `false` →
`GVRK:1`. `authorizedByDokenQuorum` derives it from `TideAttestor.isMultiAdminMode`, and the Policy
is attached only when `usePolicy`.

Both authorization paths sign over `GetDataToAuthorize()` = `SHA512(draft) + expiry`, so they must
run **after** every `Set*` that shapes either. Keep them last in the builders.

### Carrier lifecycle differs by mode

- **multiAdmin** — two-phase enclave. Phase 1 builds the carrier and **must persist it**
  (`cr.setRequestModel` + flush) or the accumulation short-circuit can never fire and every approver
  rebuilds from zero, yielding a 1-doken request the ORK rejects. Phase 2 overwrites it with the
  doken-embedded model.
- **firstAdmin** — no ceremony persists anything. `resolveCarrier` builds the carrier at COMMIT and
  signs immediately, mirroring `TideAttestor.sign`'s firstAdmin branch.

`resolveCarrier` fails closed for multiAdmin when the carrier is blank — that means the quorum
ceremony never ran.

## Attestations — where the gVVK signatures come from

`ResourceIdentity:1` requires `realm_config` and `client_config` as `unit ‖ 64-byte gVVK signature`.
Tidecloak never holds the gVVK, so it cannot sign these — **but it does not need to.**

Every producer unit is already signed through the real VVK→Midgard→ORK ceremony at CR commit and
stamped into that unit's column: `realm_config` → `RealmEntity.realmConfigAttestation`,
`client_config` → `ClientEntity.attestation` (see `UnitColumnMapping`). `ResourceIdentityAttestations`
rebuilds the unit, reads its column via `UnitColumnMapping.readStored`, and pairs them through
`IgaAttestationExporterProvider.replayOrFailClosed` — the same all-or-nothing contract the login
export obeys. A missing column, a firstAdmin stub, or a wrong-length signature throws.

Consequence: a realm whose `realm_config` column was never stamped cannot request certificates until
the toggle-on backfill covers it. Also — the envelope is rebuilt from LIVE state and paired with a
STORED signature, so if realm config changed since the last stamp the ORK rejects it at commit with
"Realm Attestation signature failed". A local Ed25519 verify against the realm gVVK at build time
would catch that earlier; not implemented.

## Reading certificates back out

| Endpoint | Auth | Returns |
|---|---|---|
| `GET .../tide-server-identity/status?fingerprint=` | none | the workload's leaf + `trustBundle` (root CA), **released together or not at all**; status stays `DRAFT` until both exist |
| `GET .../tide-server-identity/realmCertificate` | none | PEM bundle: realm server certificate then root CA (fullchain order), 404 unless both are committed |
| `GET .../tide-server-identity/crl` | none | revoked drafts |

All are public by design: a root CA is a trust anchor meant to be distributed, and a server
certificate is presented in the clear in every handshake. **The realm private key is NOT served by
any of these and must never be added to them** — they are unauthenticated, and the certificate lives
20 years.

Responses are PEM (standard base64 inside armour). Note the persisted `CSR` / `PUBLIC_KEY` columns
are **base64url without padding** — different alphabet, do not cross the decoders.

## Known gaps

- **Renewal** — `IgaRealmCert.findCurrent` has no expiry predicate, so an aged-out realm row still
  reads as current and `ensureRealmCertRequested` never re-files. Low impact at 20 years, real if
  lifetimes shorten.
- **No tests** anywhere on these paths. The slot indices, CN strings, timestamp encoding, dependsOn
  chain and envelope‖sig concatenation are all unpinned.
- `IgaRealmCertService.revoke` / `findById` / `deleteById` have no callers — there is currently no
  way to invalidate a realm certificate.
- `deleteByRealm` named queries are unwired for every IGA sidecar, `IGA_REALM_CERT` included.
- A failed enrolment (403 on the token consume) leaves its CRs committed — returning a Response does
  not roll back the Keycloak transaction.
- Realm **private key** export (for an nginx front) is deliberately unimplemented.
