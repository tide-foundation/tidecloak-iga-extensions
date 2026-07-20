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

## Other docs
- `docs/IGA.md`, `docs/EXTENDING-IGA.md` — general IGA architecture & extension guide.
- `docs/tideless-iga-walkthrough.md` — Tideless-mode IGA walkthrough.
