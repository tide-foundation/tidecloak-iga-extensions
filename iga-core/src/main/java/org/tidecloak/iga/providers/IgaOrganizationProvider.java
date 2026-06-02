package org.tidecloak.iga.providers;

import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OrganizationModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.cache.infinispan.organization.InfinispanOrganizationProvider;
import org.keycloak.models.utils.KeycloakModelUtils;

import jakarta.persistence.EntityManager;
import java.util.List;
import java.util.Map;

/**
 * Extends Keycloak 26.5.5's {@link InfinispanOrganizationProvider} (the cache
 * layer that itself wraps {@code JpaOrganizationProvider}) to intercept
 * Organization mutations through the IGA approval workflow when IGA is enabled,
 * mirroring exactly how {@link IgaRealmProvider} intercepts client/group/role
 * creation.
 *
 * <h2>Why wrap the cache layer</h2>
 * Unlike Realm/User/Client/Group/Role caching — which lives under SEPARATE
 * {@code *CacheProviderFactory} SPI types so the cache always layers ON TOP of
 * IGA naturally — KC's organization caching sits ON the same
 * {@code OrganizationProviderFactory} SPI as JPA
 * ({@code InfinispanOrganizationProviderFactory.order()==10},
 * {@link InfinispanOrganizationProvider}).
 * With IGA at {@code order()==20} we MUST be selected over Infinispan, so when
 * we extended {@code JpaOrganizationProvider} the entire Infinispan cache layer
 * was bypassed: cache invalidations registered by KC's own listeners
 * (e.g. {@code IdentityProviderUpdatedEvent} via
 * {@code InfinispanOrganizationProviderFactory.postInit}) flowed into a
 * cache that nothing read from, and reads after an IGA-mediated mutation could
 * return stale {@code CachedOrganization}/{@code CachedOrganizationIds}/
 * {@code CachedCount} entries until per-org explicit invalidations were sent
 * by the workaround in
 * {@code TideAdminCompatResource.evictRealmCache}.
 *
 * <p>Now {@code IgaOrganizationProvider extends InfinispanOrganizationProvider}
 * the layering becomes: IGA (top) → Infinispan cache (middle, via super calls)
 * → JPA (bottom, resolved lazily by Infinispan via
 * {@code session.getProvider(OrganizationProvider.class, "jpa")} —
 * {@link InfinispanOrganizationProvider#getDelegate()}). KC's
 * {@code JpaOrganizationProviderFactory} is registered at id {@code "jpa"}
 * so the SPI
 * lookup resolves regardless of which factory is the default.</p>
 *
 * <p>Behaviour: cache invalidations fired by Infinispan's own listeners now
 * flow through the chain naturally (KC's
 * {@code IdentityProviderUpdatedEvent}/{@code IdentityProviderRemovedEvent}
 * listeners call {@code registerOrganizationInvalidation} on the
 * {@code session.getProvider(OrganizationProvider.class, "infinispan")}
 * lookup — see "Factory presence" below — and that instance and ours share
 * the same {@code RealmCacheSession}). Reads after IGA-mediated writes return
 * fresh data without the per-org explicit eviction loop in
 * {@code evictRealmCache} for the steady-state case. The eviction loop is still
 * required for the IGA OFF→ON / ON→OFF toggle transition: entries cached BEFORE
 * the toggle flipped hold a snapshot that the architectural fix cannot reach
 * (the fix only governs future loads). The {@code evictRealmCache} comment on
 * the toggle path documents this explicitly — do not remove that loop.</p>
 *
 * <h2>Factory presence</h2>
 * KC's {@code DefaultKeycloakSessionFactory#initializeProviders} runs
 * {@code postInit} on EVERY registered factory regardless of which one is
 * selected as the default. The Infinispan factory's {@code postInit} (id/user-
 * removed event listeners) therefore still registers when the IGA factory wins
 * {@code order()==20}. The listeners call
 * {@code session.getProvider(OrganizationProvider.class, "infinispan")} which
 * resolves to a fresh {@link InfinispanOrganizationProvider} (KC's
 * {@code InfinispanOrganizationProviderFactory} is still in the SPI registry
 * at id {@code "infinispan"} via META-INF/services). That instance and ours
 * share the same {@code RealmCacheSession} in the current
 * {@code KeycloakSession}, so its
 * {@code realmCache.registerInvalidation(cacheKeyOrgId(realm, id))} drops
 * exactly the entries our subsequent {@code super.getById}/{@code
 * super.getByDomainName} reads would have returned stale — completing the
 * invalidation chain.</h2>
 *
 * <p>{@link InfinispanOrganizationProvider} is non-{@code final} and exposes a
 * public single-arg constructor {@code (KeycloakSession)}, so extension is feasible
 * — no fallback to composition required.</p>
 *
 * <h2>Intercepted operations</h2>
 * <ul>
 *   <li>{@code create(id, name, alias)} — POST {realm}/organizations
 *       (KC's REST resource calls the 2-arg default {@code create(name, alias)}
 *       which forwards to {@code create(null, name, alias)} on the
 *       OrganizationProvider SPI — the 3-arg id-bearing overload is the one
 *       method KC actually dispatches to). →
 *       {@code CREATE_ORGANIZATION} (full {@code OrganizationRepresentation}
 *       captured by the JAX-RS filter as {@code REP_JSON}). The
 *       {@code redirectUrl} field is NOT a {@code create()} argument in the
 *       OrganizationProvider SPI — it is applied later via
 *       {@code OrganizationModel.setRedirectUrl} inside
 *       {@code RepresentationToModel.toModel(rep, model)}, captured by
 *       {@link IgaOrganizationModel} as part of the full-rep terminal seam.</li>
 *   <li>{@code remove(org)} — DELETE {realm}/organizations/{id}
 *       → {@code DELETE_ORGANIZATION}.</li>
 *   <li>{@code addMember(org, user)} / {@code addManagedMember(org, user)}
 *       — POST {realm}/organizations/{id}/members → {@code ADD_ORG_MEMBER}.</li>
 *   <li>{@code removeMember(org, user)} — DELETE
 *       {realm}/organizations/{id}/members/{member-id}
 *       → {@code REMOVE_ORG_MEMBER}.</li>
 *   <li>{@code addIdentityProvider(org, idp)} — POST
 *       {realm}/organizations/{id}/identity-providers
 *       → {@code ORG_ADD_IDP}.</li>
 *   <li>{@code removeIdentityProvider(org, idp)} — DELETE
 *       {realm}/organizations/{id}/identity-providers/{alias}
 *       → {@code ORG_REMOVE_IDP}.</li>
 * </ul>
 *
 * <p>Organization <b>update</b> (PUT {realm}/organizations/{id}) flows through
 * {@code RepresentationToModel.toModel(rep, OrganizationModel)} which calls
 * setters on the model returned by {@link #getById(String)}. We wrap that model
 * in {@link IgaOrganizationModel} so update (incl. domain changes, which KC
 * 26.5.5 manages only through {@code OrganizationModel.setDomains} as part of
 * org update — there is no standalone domain endpoint) is intercepted as
 * {@code UPDATE_ORGANIZATION}.</p>
 *
 * <p>Member <b>invitations</b> (POST {realm}/organizations/{id}/members/
 * invite-user and .../invite-existing-user → {@code ORG_INVITE_MEMBER}) are
 * intercepted at the {@code InvitationManager} SPI seam: {@link
 * #getInvitationManager()} returns an {@link IgaInvitationManager} whose
 * {@code create(...)} throws {@code IgaPendingApprovalException} BEFORE KC's
 * {@code OrganizationInvitationResource.sendInvitation} persists the invitation
 * entity / serializes the action token / sends the e-mail. The real
 * invitation (token + e-mail) is performed at commit time by replay. See
 * {@link IgaInvitationManager} for the full ordering proof and governance
 * model.</p>
 *
 * <h2>IGA_REPLAY_ACTIVE guard</h2>
 * {@link #isIgaActive()} returns {@code false} when the session attribute
 * {@code IGA_REPLAY_ACTIVE} equals {@code "true"} — set by
 * {@code IgaReplayDispatcher.replay(...)} — so replay rebuilds pass straight
 * through to {@code super} without re-interception, exactly like every other
 * Iga* provider.
 */
public class IgaOrganizationProvider extends InfinispanOrganizationProvider {

    private final KeycloakSession igaSession;

    public IgaOrganizationProvider(KeycloakSession session) {
        // super constructs the Infinispan layer, which lazily resolves its
        // delegate via session.getProvider(OrganizationProvider.class, "jpa")
        // (InfinispanOrganizationProvider.getDelegate:73-79) — i.e. KC's
        // JpaOrganizationProviderFactory at id "jpa". Wraps invitationManager
        // through InfinispanInvitationManager(getDelegate().getInvitationManager())
        // eagerly in the super constructor (line 56).
        super(session);
        this.igaSession = session;
    }

    private IgaChangeRequestService getService() {
        EntityManager em = igaSession.getProvider(JpaConnectionProvider.class).getEntityManager();
        return new IgaChangeRequestService(em, igaSession);
    }

    private RealmModel realm() {
        return igaSession.getContext().getRealm();
    }

    private boolean isIgaActive() {
        RealmModel realm = realm();
        if (realm == null) return false;
        IgaChangeRequestService service = getService();
        if (!service.isIgaEnabled(realm)) return false;
        Object replay = igaSession.getAttribute("IGA_REPLAY_ACTIVE");
        return !"true".equals(replay);
    }

    /**
     * Persist the change request in a SEPARATE Keycloak session/transaction so
     * it survives the rollback caused by the pending-approval exception we
     * throw afterwards, then throw to interrupt the original write flow.
     * Identical mechanism to {@link IgaRealmProvider}'s recordAndThrow.
     */
    private void recordAndThrow(RealmModel realm, String entityType, String entityId,
                                String actionType, List<Map<String, Object>> rows) {
        String[] crIdHolder = new String[1];
        KeycloakModelUtils.runJobInTransaction(igaSession.getKeycloakSessionFactory(), newSession -> {
            RealmModel newRealm = newSession.realms().getRealm(realm.getId());
            EntityManager newEm = newSession.getProvider(JpaConnectionProvider.class).getEntityManager();
            IgaChangeRequestService newService = new IgaChangeRequestService(newEm, newSession);
            crIdHolder[0] = newService.create(newRealm, entityType, entityId, actionType, rows, null).getId();
        });
        throw new IgaPendingApprovalException(crIdHolder[0], entityType, actionType);
    }

    // -------------------------------------------------------------------------
    // CREATE ORGANIZATION
    // -------------------------------------------------------------------------

    /**
     * The id-bearing create overload IS the OrganizationProvider SPI method
     * KC dispatches to. The default 2-arg {@code create(name, alias)} forwards
     * to {@code create(null, name, alias)} (see
     * {@link org.keycloak.organization.OrganizationProvider#create(String, String)}
     * default body), and KC's REST path
     * ({@code OrganizationsResource.create}) calls the 2-arg flavour. So
     * intercepting here covers BOTH the REST POST and replay's explicit
     * 2-arg call ({@code IgaReplayDispatcher.replayCreateOrganization}). The
     * previously-defined 3-arg {@code create(name, alias, redirectUrl)} did
     * NOT match any SPI method — it overrode nothing and the interception was
     * therefore unreachable.
     */
    @Override
    public OrganizationModel create(String id, String name, String alias) {
        if (isIgaActive()) {
            // Model-layer accumulate-then-veto, identical mechanism to
            // IgaRealmProvider.addClient/createGroup. Create the REAL (scratch)
            // org via super so Keycloak's OrganizationsResource.create can apply
            // the COMPLETE incoming OrganizationRepresentation via
            // RepresentationToModel.toModel(rep, model) to a genuine
            // OrganizationAdapter. The IgaOrganizationModel is returned in
            // create-capture mode: every per-setter call falls through to the
            // real model, and the LAST setter KC's toModel makes —
            // OrganizationModel.setDomains() (RepresentationToModel.toModel line
            // 1736, KC 26.5.5) — is the terminal seam where the now-complete
            // model is snapshotted to an OrganizationRepresentation, the
            // CREATE_ORGANIZATION change request (with full REP_JSON) is written
            // in a separate transaction, the REQUEST transaction is marked
            // rollback-only and IgaPendingApprovalException is thrown (→ 202).
            // The scratch org is discarded by the request-tx rollback. See
            // IgaOrganizationModel#setDomains and the IgaClientAdapter
            // lifecycle proof.
            OrganizationModel base = super.create(id, name, alias);
            if (base == null) return null;
            return new IgaOrganizationModel(igaSession, base, this, /*captureCreate=*/ true);
        }
        return super.create(id, name, alias);
    }

    // -------------------------------------------------------------------------
    // ORGANIZATION lookup — wrap so toModel(...) update setters are intercepted
    // -------------------------------------------------------------------------

    @Override
    public OrganizationModel getById(String id) {
        OrganizationModel base = super.getById(id);
        if (base == null) return null;
        return new IgaOrganizationModel(igaSession, base, this);
    }

    @Override
    public OrganizationModel getByDomainName(String domain) {
        OrganizationModel base = super.getByDomainName(domain);
        if (base == null) return null;
        return new IgaOrganizationModel(igaSession, base, this);
    }

    boolean igaActive() {
        return isIgaActive();
    }

    /**
     * Expose the wrapping {@link KeycloakSession} to peers in this package
     * (specifically {@link IgaInvitationManager}, which needs the request URI
     * to discriminate the resend path from a fresh invite). Package-private
     * to keep the surface intentionally small; not part of the public org SPI.
     */
    KeycloakSession session() {
        return igaSession;
    }

    // -------------------------------------------------------------------------
    // DELETE ORGANIZATION
    // -------------------------------------------------------------------------

    @Override
    public boolean remove(OrganizationModel organization) {
        if (isIgaActive() && organization != null) {
            RealmModel realm = realm();
            Map<String, Object> row = new java.util.LinkedHashMap<>();
            row.put("ORG_ID", organization.getId());
            row.put("REALM_ID", realm.getId());
            recordAndThrow(realm, "ORGANIZATION", organization.getId(),
                    "DELETE_ORGANIZATION", List.of(row));
            return false; // unreachable
        }
        return super.remove(organization);
    }

    // -------------------------------------------------------------------------
    // MEMBERS
    // -------------------------------------------------------------------------

    @Override
    public boolean addMember(OrganizationModel organization, UserModel user) {
        if (isIgaActive() && organization != null && user != null) {
            recordMember(organization, user, "ADD_ORG_MEMBER");
            return false; // unreachable
        }
        return super.addMember(organization, user);
    }

    @Override
    public boolean addManagedMember(OrganizationModel organization, UserModel user) {
        if (isIgaActive() && organization != null && user != null) {
            recordMember(organization, user, "ADD_ORG_MEMBER");
            return false; // unreachable
        }
        return super.addManagedMember(organization, user);
    }

    @Override
    public boolean removeMember(OrganizationModel organization, UserModel user) {
        if (isIgaActive() && organization != null && user != null) {
            recordMember(organization, user, "REMOVE_ORG_MEMBER");
            return false; // unreachable
        }
        return super.removeMember(organization, user);
    }

    private void recordMember(OrganizationModel organization, UserModel user, String action) {
        RealmModel realm = realm();
        Map<String, Object> row = new java.util.LinkedHashMap<>();
        row.put("ORG_ID", organization.getId());
        row.put("USER_ID", user.getId());
        row.put("REALM_ID", realm.getId());
        recordAndThrow(realm, "ORGANIZATION", organization.getId(), action, List.of(row));
    }

    // -------------------------------------------------------------------------
    // MEMBER INVITATION (SPI seam: InvitationManager.create)
    //
    // POST {realm}/organizations/{id}/members/invite-user and
    // .../invite-existing-user → OrganizationInvitationResource.sendInvitation,
    // whose FIRST persisting side-effect is invitationManager.create(...). By
    // returning an IgaInvitationManager from getInvitationManager() we throw
    // IgaPendingApprovalException inside that create(), strictly before the
    // invitation entity is persisted and therefore before the action token is
    // serialized and the e-mail is sent. The real invite (token + e-mail) is
    // performed at commit time by IgaReplayDispatcher.replay, which runs under
    // IGA_REPLAY_ACTIVE so getInvitationManager() still returns the wrapper but
    // isIgaActive() is false → create() passes straight through to KC's
    // JpaInvitationManager and KC's own OrganizationInvitationResource logic.
    // -------------------------------------------------------------------------

    @Override
    public org.keycloak.organization.InvitationManager getInvitationManager() {
        return new IgaInvitationManager(super.getInvitationManager(), this, igaSession);
    }

    /**
     * Record an {@code ORG_INVITE_MEMBER} change request and throw to interrupt
     * the invitation flow before any token/e-mail. Convenience wrapper that
     * pins the action type to {@code ORG_INVITE_MEMBER}; see the action-type
     * overload below for the canonical body and rationale.
     */
    void recordOrgInvite(String orgId, String email, String firstName, String lastName) {
        recordOrgInvite(orgId, email, firstName, lastName, "ORG_INVITE_MEMBER");
    }

    /**
     * Record an org-invite-style change request ({@code ORG_INVITE_MEMBER} or
     * {@code ORG_RESEND_INVITE}) and throw to interrupt the invitation flow
     * before any token/e-mail. Scoped/keyed by the target organization
     * ({@code ORG_ID}) exactly like ADD_/REMOVE_ORG_MEMBER so
     * {@code IgaScopeResolver.collectOrganizationScope} resolves
     * {@code iga.approverRole}/{@code iga.threshold} off the org. The invitee
     * identity travels as plain row keys (no REP_JSON — the invite endpoints
     * are form-encoded, not a JSON representation the capture filter handles)
     * so replay can reconstruct the exact KC invite call. Both action types
     * carry the same row shape and replay through the same
     * {@code replayOrgInviteMember} body (a faithful transcription of KC's
     * {@code sendInvitation}), so a resend's replay mints a fresh token + sends
     * a fresh e-mail exactly like the original invite — the action type is the
     * audit-/scope-relevant distinction.
     */
    void recordOrgInvite(String orgId, String email, String firstName, String lastName,
                         String actionType) {
        recordOrgInvite(orgId, email, firstName, lastName, actionType, null);
    }

    /**
     * Record an org-invite-style change request, optionally carrying the id of
     * an invitation row that should be removed at replay time (RESEND only).
     *
     * <p>For {@code ORG_RESEND_INVITE}, KC's
     * {@code OrganizationInvitationResource.resendInvitation} now defers the
     * {@code invitationManager.remove(id)} of the original until AFTER
     * {@code sendInvitation} returns synchronously (so a denied resend preserves
     * the original row). That means at IGA-capture time the original invitation
     * row is STILL present. If replay later calls
     * {@code invitationManager.create(org, email, firstName, lastName)} with the
     * same {@code (organization_id, email)} pair, the
     * {@code UK_ORG_INVITATION_EMAIL} unique constraint (jpa-changelog-26.5.0.xml
     * line 231-233) is violated and the commit transaction aborts with
     * SQLState 23505 (translated by KC into HTTP 409 on the {@code /commit}
     * call). To avoid that without weakening deny semantics, the seam captures
     * the original invitation id here; {@link IgaReplayDispatcher
     * #replayOrgInviteMember} removes that row before re-creating.</p>
     *
     * <p>Deny path: replay never runs, so the original is left intact —
     * exactly the contract phase7a-resend-deny-preserves-original.spec.ts
     * relies on.</p>
     */
    void recordOrgInvite(String orgId, String email, String firstName, String lastName,
                         String actionType, String originalInvitationId) {
        RealmModel realm = realm();
        Map<String, Object> row = new java.util.LinkedHashMap<>();
        row.put("ORG_ID", orgId);
        if (email != null) row.put("INVITE_EMAIL", email);
        if (firstName != null) row.put("INVITE_FIRST_NAME", firstName);
        if (lastName != null) row.put("INVITE_LAST_NAME", lastName);
        if (originalInvitationId != null) {
            row.put("ORIGINAL_INVITATION_ID", originalInvitationId);
        }
        row.put("REALM_ID", realm.getId());
        recordAndThrow(realm, "ORGANIZATION", orgId, actionType, List.of(row));
    }

    // -------------------------------------------------------------------------
    // IDENTITY PROVIDER LINK
    // -------------------------------------------------------------------------

    @Override
    public boolean addIdentityProvider(OrganizationModel organization, IdentityProviderModel idp) {
        if (isIgaActive() && organization != null && idp != null) {
            recordIdp(organization, idp, "ORG_ADD_IDP");
            return false; // unreachable
        }
        return super.addIdentityProvider(organization, idp);
    }

    @Override
    public boolean removeIdentityProvider(OrganizationModel organization, IdentityProviderModel idp) {
        if (isIgaActive() && organization != null && idp != null) {
            recordIdp(organization, idp, "ORG_REMOVE_IDP");
            return false; // unreachable
        }
        return super.removeIdentityProvider(organization, idp);
    }

    private void recordIdp(OrganizationModel organization, IdentityProviderModel idp, String action) {
        RealmModel realm = realm();
        Map<String, Object> row = new java.util.LinkedHashMap<>();
        row.put("ORG_ID", organization.getId());
        row.put("IDP_ALIAS", idp.getAlias());
        row.put("REALM_ID", realm.getId());
        recordAndThrow(realm, "ORGANIZATION", organization.getId(), action, List.of(row));
    }
}
