# tidecloak-iga-extensions (`iga-core`)

TideCloak IGA (Identity Governance & Administration) core module. Java / Maven.

## Build / run constraints
- Do **not** build, package, or inspect jars in this repo as part of agent work — the user
  runs all build tests. Make source changes only.

## Where to start for common tasks

- **Self-registration / `link-tide-account` / admin-invite `user_identity` attestation** —
  read [`docs/user-identity-attestation.md`](docs/user-identity-attestation.md) FIRST. It
  documents the two SPI entry points (`IgaSystemProvisionerProvider.signAndStampUserIdentity`
  and `signAndStampInvitableUserIdentity`), the invite ceremony order in
  `TideAttestor.signInvitableUserIdentityWithGVrk`, the byte-equality invariant that keeps ORK
  verification passing, the `vuid` binding gotcha, and the IGA-off bypass. These contain
  non-obvious gotchas (e.g. why there is no sidecar table, why the invite vuid is
  `AuthRequest.User` not the KC `userId`) that are expensive to re-derive.

- **Workload / realm certificates (`REQUEST_SERVER_CERT`, `REQUEST_REALM_CERT`, mTLS)** — read
  [`docs/server-identity-certificates.md`](docs/server-identity-certificates.md) FIRST. It documents
  the `ResourceIdentity:1` ORK contract (draft slots are fixed but RESPONSE slots are compacted
  per mode; `CN=client_<clientId>` vs `CN=realm_<name>` vs the `_ca` issuer; the SAN carries the
  client UUID, not the clientId), the two DIFFERENT authorizations and which authorizer pack each
  needs (creation-auth = MAIN gVRK + `Policy:1` only; approval = firstAdmin pack + `GVRK:1`, or
  dokens + `Policy:1`), why the carrier must be persisted in phase 1, and where the gVVK-signed
  attestations actually come from (the producer attestation columns — this module never signs them).
  Getting the authorizer packs or the response slots wrong produces ORK errors that read as
  unrelated, and re-deriving any of it means reading two other repos.

## Other docs
- `docs/IGA.md`, `docs/EXTENDING-IGA.md` — general IGA architecture & extension guide.
- `docs/tideless-iga-walkthrough.md` — Tideless-mode IGA walkthrough.
