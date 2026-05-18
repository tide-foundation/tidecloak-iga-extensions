package org.tidecloak.iga.providers;

import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OrganizationModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.organization.jpa.JpaOrganizationProvider;

import jakarta.persistence.EntityManager;
import java.util.List;
import java.util.Map;

/**
 * Extends Keycloak 26.5.5's {@link JpaOrganizationProvider} to intercept
 * Organization mutations through the IGA approval workflow when IGA is enabled,
 * mirroring exactly how {@link IgaRealmProvider} intercepts client/group/role
 * creation.
 *
 * <h2>Intercepted operations</h2>
 * <ul>
 *   <li>{@code create(name, alias[, redirectUrl])} — POST {realm}/organizations
 *       → {@code CREATE_ORGANIZATION} (full {@code OrganizationRepresentation}
 *       captured by the JAX-RS filter as {@code REP_JSON}).</li>
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
 * <p>Invitations ({@code POST .../members} with an email, and
 * {@code POST .../invitations}) are intentionally NOT intercepted here — see
 * the report; they create action tokens and send email at request time and
 * need a dedicated replay design, flagged as a follow-up.</p>
 *
 * <h2>IGA_REPLAY_ACTIVE guard</h2>
 * {@link #isIgaActive()} returns {@code false} when the session attribute
 * {@code IGA_REPLAY_ACTIVE} equals {@code "true"} — set by
 * {@code IgaReplayDispatcher.replay(...)} — so replay rebuilds pass straight
 * through to {@code super} without re-interception, exactly like every other
 * Iga* provider.
 */
public class IgaOrganizationProvider extends JpaOrganizationProvider {

    private final KeycloakSession igaSession;

    public IgaOrganizationProvider(KeycloakSession session) {
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

    @Override
    public OrganizationModel create(String name, String alias, String redirectUrl) {
        if (isIgaActive()) {
            RealmModel realm = realm();
            // The org id is generated inside JpaOrganizationProvider.create and
            // cannot be pinned through the SPI (mirrors role/group: no
            // id-bearing create). The CR is keyed by org NAME; replay records
            // the generated id. Full OrganizationRepresentation captured by the
            // JAX-RS filter is folded in as REP_JSON so replay rebuilds
            // enabled/description/redirectUrl/attributes/domains via Keycloak's
            // own RepresentationToModel.toModel — the exact builder
            // OrganizationsResource.create uses.
            Map<String, Object> row = new java.util.LinkedHashMap<>();
            row.put("ORG_NAME", name);
            if (alias != null) row.put("ORG_ALIAS", alias);
            if (redirectUrl != null) row.put("ORG_REDIRECT_URL", redirectUrl);
            row.put("REALM_ID", realm.getId());
            String repJson = org.tidecloak.iga.rest.IgaRepresentationCaptureFilter
                    .pendingRepJson(igaSession,
                            org.tidecloak.iga.rest.IgaRepresentationCaptureFilter.TYPE_ORGANIZATION);
            if (repJson != null) {
                row.put("REP_JSON", repJson);
            }
            recordAndThrow(realm, "ORGANIZATION", name, "CREATE_ORGANIZATION", List.of(row));
            return null; // unreachable
        }
        return super.create(name, alias, redirectUrl);
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

    /** Used by {@link IgaOrganizationModel} to record an UPDATE_ORGANIZATION CR. */
    void recordOrgUpdate(String orgId, List<Map<String, Object>> rows) {
        RealmModel realm = realm();
        recordAndThrow(realm, "ORGANIZATION", orgId, "UPDATE_ORGANIZATION", rows);
    }

    boolean igaActive() {
        return isIgaActive();
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
