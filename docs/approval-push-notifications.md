# Approval push notifications

Tells a realm's approvers, on their phone, that a change request is waiting.

## Why the trigger is here and not in the ORKs

A change request is born in TideCloak's database and nowhere else. The ORKs never
observe its creation, so they cannot notice it — they could only be *told*, which
puts TideCloak back in the path. The trigger is unavoidably TideCloak's.

That is not a new single point of failure. If TideCloak is unreachable there are no
change requests being created and no `/approve` endpoint to call, so notifications
failing alongside it costs nothing that was not already lost.

Redundancy belongs on the delivery side: a device registers its subscription with
every node it knows (`Notifications.subscribeToPush` in the authenticator takes a
*list*), any node that is up can send, and the browser collapses duplicates on the
shared notification tag.

## The messages carry no payload — deliberately

A push message may carry an encrypted body (RFC 8291). These do not.

**Disclosure.** A push message travels through a push service chosen by the browser
— Google's for Chrome, Mozilla's for Firefox, Apple's for Safari. None is ours, and
none was selected by the vendor. Even encrypted, the existence, timing and frequency
of messages is visible to that service. Putting realm names or change-request ids in
the body would hand a third party a running commentary on a vendor's governance
activity. An empty message tells it only that *something* happened.

**Blast radius.** RFC 8291 is ECDH + HKDF + AES-GCM, and any subtle error produces
messages that fail silently at the browser. Omitting it removes that failure mode and
leaves `IgaWebPushSender` with one job: sign a JWT and POST.

The cost is a generic notification — "approvals pending", not "realm a1 needs you".
The service worker treats an empty push as a prompt to open the app at
`/?approvals=1`, which lists the realms that admin uses and loads the real change
requests over the authenticated connection. Detail arrives over the channel that is
already trusted, rather than the one that is not.

This is why `POST iga/push/subscriptions` stores only the `endpoint` and ignores the
`p256dh`/`auth` keys: without payloads there is nothing to encrypt to.

## Pieces

| Concern | Where |
|---|---|
| Subscription row (realm + user + endpoint) | `entities/IgaPushSubscriptionEntity` |
| Storage, upsert, delete-on-410 | `providers/IgaPushSubscriptionService` |
| Per-realm VAPID key pair | `services/IgaVapidKeys` |
| VAPID JWT + POST (RFC 8030/8292) | `services/IgaWebPushSender` |
| Recipient resolution + fan-out | `services/IgaApprovalNotifier` |
| REST (`iga/push/vapid-key`, `iga/push/subscriptions`) | `rest/IgaAdminResource` |
| Schema | `META-INF/iga-changelog-2.12.0.xml` |

## Two things that will bite

**The notification fires after commit, not at create.** `IgaApprovalNotifier` enlists
via `enlistAfterCompletion`, so a rolled-back change request announces nothing. An
admin who opens the app to find nothing there learns to ignore the notification.

**`session.getContext().setRealm(realm)` before any user lookup.** `getRoleMembersStream`
reads `session.getContext().getRealm()` and throws *"Session not bound to a realm"*
without it — the same trap documented at `IgaAdminResource.ensureThresholdPolicyCrForEnclave`.

## Endpoints are not `requireManageRealm`

Every push endpoint is scoped to the *calling* admin: it reads the user id from the
authenticated session and can only add or remove that user's own devices. Demanding
`manage-realm` would lock out `tide-realm-admin` holders — who do not get
`manage-realm` implicitly, and who are exactly the people expected to approve.

## Turning it off

Set the realm attribute `iga.push.disabled=true`. `iga.push.subject` overrides the
RFC 8292 `sub` claim (default `mailto:admin@tide.org`).

## VAPID keys live in a table, not a realm attribute

Two strings keyed by realm look exactly like a `realm.setAttribute` job. That does not
work here, and fails in a way worth remembering: **realm attributes are governed
state**. Under IGA the write is captured as a `SET_REALM_ATTRIBUTE` change request
instead of being applied, so

- the generated pair is handed to the caller and then forgotten,
- the realm accumulates a change request nobody asked for, and
- the next call fails outright against that now-pending CR.

The rule this illustrates: operational data that no approval depends on must not enter
the approval pipeline. VAPID keys authenticate the *sender*, protect no governance
decision, and holding one only lets you push to endpoints you already know — so they
belong in `IGA_PUSH_VAPID`, where writes simply apply. That also keeps the private key
out of the realm representation, which anyone who can view the realm can read.

Keys are generated on first subscribe and never rotated in place: the public half is
baked into every subscription a browser has already made.
