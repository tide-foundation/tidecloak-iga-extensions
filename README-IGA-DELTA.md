
# IGA delta (drafting without bulky processors)

## What this adds
- **UserContextDraftService**: stage & commit drafts (per user per client), plus automatic rebase of other open drafts.
- **UserContextBuilder**: builds access-token-like payload (without dynamic fields) and attaches `AuthorizerPolicy` linkages from role attributes.
- **UserContextDeltaUtils**: shallow, JWT-friendly merges.
- **Liquibase**: adds `DEFAULT_USER_CONTEXT` to `ACCESS_PROOF_DETAIL` to store baseline alongside the transactional draft.

## How to wire
1. **Entity**: add getters/setters for `defaultUserContext` in `AccessProofDetailEntity`.
2. **Liquibase**: include `iga-002-add-default-user-context.xml` in your master changelog.
3. **Replace old processor calls**:
   - Stage: `new UserContextDraftService(session).stageDraftForAction(realm, action, type, rep)`
   - Commit: `new UserContextDraftService(session).commit(changeSetId, type, adminSigOrId)`
4. **Admin approvals**: keep using your existing `AdminAuthorizationEntity` + `ChangesetRequestEntity` flow.

## Notes
- `defaultUserContext` **is the active baseline snapshot** used to rebase pending drafts when another request is approved first.
- `UserContextBuilder` reads role attributes `tide.ap`, `tide.ap.auth`, `tide.ap.sign` to include AuthorizerPolicy references in the context.
