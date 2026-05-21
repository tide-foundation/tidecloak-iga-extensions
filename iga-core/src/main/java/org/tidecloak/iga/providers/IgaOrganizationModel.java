package org.tidecloak.iga.providers;

import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OrganizationDomainModel;
import org.keycloak.models.OrganizationModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.OrganizationRepresentation;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.persistence.EntityManager;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * Decorating {@link OrganizationModel} that intercepts organization create AND
 * update mutations through the IGA approval workflow using the SAME model-layer
 * accumulate-then-veto mechanism as {@link IgaClientAdapter} /
 * {@link IgaGroupAdapter}.
 *
 * <h2>Two modes</h2>
 * <ul>
 *   <li><b>Update mode</b> ({@code captureCreate == false}, the default):
 *       {@code OrganizationResource.update} (PUT .../organizations/{id}) applies
 *       the incoming {@link OrganizationRepresentation} by calling
 *       {@code RepresentationToModel.toModel(rep, model)} on the model returned
 *       by {@code IgaOrganizationProvider.getById}. This decorator passes every
 *       setter straight through to the real model (so the FULL representation is
 *       applied to a genuine scratch {@code OrganizationAdapter}) and intercepts
 *       only at the terminal seam {@link #setDomains} —
 *       {@code RepresentationToModel.toModel} (KC 26.5.5,
 *       {@code org.keycloak.models.utils.RepresentationToModel:1729}) calls
 *       {@code model.setDomains(...)} as its FINAL, unconditional setter (line
 *       1736) AFTER setName/setAlias/setEnabled/setRedirectUrl/setDescription/
 *       setAttributes. There snapshot → CR(REP_JSON) in a separate tx →
 *       request-tx rollback-only → {@code IgaPendingApprovalException}.</li>
 *   <li><b>Create-capture mode</b> ({@code captureCreate == true}): wraps a
 *       <em>scratch</em> {@code OrganizationModel} that
 *       {@code IgaOrganizationProvider.create} just persisted via
 *       {@code super.create}. {@code OrganizationsResource.create} (POST
 *       .../organizations) calls {@code provider.create(name, alias)} then the
 *       SAME {@code RepresentationToModel.toModel(rep, model)} (KC 26.5.5
 *       {@code OrganizationsResource:114-115}), so the identical terminal seam
 *       {@link #setDomains} applies — it just writes a {@code CREATE_ORGANIZATION}
 *       CR instead of {@code UPDATE_ORGANIZATION}, and the scratch org is
 *       discarded by the request-tx rollback exactly like a captured client.</li>
 * </ul>
 *
 * <p>{@code IgaReplayDispatcher.replayCreateOrganization} does
 * {@code orgs.create(name,alias)} then {@code RepresentationToModel.toModel(rep,
 * model)}, and {@code replayUpdateOrganization} does
 * {@code RepresentationToModel.toModel(rep, getById(orgId))} — both consume
 * exactly the {@link OrganizationRepresentation} produced here by
 * {@link ModelToRepresentation#toRepresentation(OrganizationModel, boolean)}
 * (called with {@code briefRepresentation=false} so attributes are included).
 * Replay runs under {@code IGA_REPLAY_ACTIVE} so the wrapped setters pass
 * straight through.</p>
 *
 * <p>All read accessors delegate straight to the wrapped model so normal GETs
 * and replay are unaffected.</p>
 */
public class IgaOrganizationModel implements OrganizationModel {

    private static final Logger log = Logger.getLogger(IgaOrganizationModel.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final KeycloakSession session;
    private final OrganizationModel delegate;
    private final IgaOrganizationProvider provider;

    /**
     * When true this decorator wraps a scratch org mid-{@code create} and the
     * terminal seam {@link #setDomains} writes a CREATE_ORGANIZATION CR; when
     * false it wraps the getById model for the update path and writes
     * UPDATE_ORGANIZATION. In BOTH cases per-setter interception is bypassed so
     * RepresentationToModel.toModel applies the full representation.
     */
    private final boolean captureCreate;

    public IgaOrganizationModel(KeycloakSession session, OrganizationModel delegate,
                                IgaOrganizationProvider provider) {
        this(session, delegate, provider, false);
    }

    public IgaOrganizationModel(KeycloakSession session, OrganizationModel delegate,
                                IgaOrganizationProvider provider, boolean captureCreate) {
        this.session = session;
        this.delegate = delegate;
        this.provider = provider;
        this.captureCreate = captureCreate;
    }

    /**
     * Terminal seam for CREATE_ORGANIZATION / UPDATE_ORGANIZATION.
     *
     * <p>{@code RepresentationToModel.toModel(rep, model)} (KC 26.5.5,
     * {@code org.keycloak.models.utils.RepresentationToModel:1729}) ends with
     * {@code model.setDomains(...)} (line 1736) — the FINAL, unconditional
     * setter, AFTER setName/setAlias/setEnabled/setRedirectUrl/setDescription/
     * setAttributes (lines 1733-1735). Both the create
     * ({@code OrganizationsResource.create:114-115}) and update
     * ({@code OrganizationResource.update}) admin paths run that exact builder,
     * so when this fires every admin-supplied org field (including the just
     * supplied {@code domains} argument) is the desired final state. We snapshot
     * the model into an {@link OrganizationRepresentation} with Keycloak's own
     * {@link ModelToRepresentation#toRepresentation(OrganizationModel, boolean)}
     * ({@code briefRepresentation=false} → attributes included), overlay the
     * {@code domains} argument (not yet written to the model since we throw
     * before {@code super.setDomains}), write the CR with full {@code REP_JSON}
     * in a SEPARATE transaction, mark the REQUEST tx rollback-only and throw
     * {@link IgaPendingApprovalException}. Lifecycle/discard proof identical to
     * {@link IgaClientAdapter#updateClient}.</p>
     */
    @Override
    public void setDomains(java.util.Set<OrganizationDomainModel> domains) {
        if (!intercept()) {
            delegate.setDomains(domains);
            return;
        }

        String orgId = delegate.getId();
        OrganizationRepresentation rep = ModelToRepresentation.toRepresentation(delegate, false);
        rep.setId(orgId);
        // The terminal seam fires BEFORE super.setDomains, so the model's
        // domains have NOT been written (create: none yet; update: still the
        // OLD set). ModelToRepresentation.toRepresentation populated rep's
        // domains from that stale model state via addDomain; replace it with
        // the admin-supplied argument so REP_JSON carries the desired FINAL
        // domains exactly as replay's RepresentationToModel.toModel applies
        // them (OrganizationRepresentation has no setDomains — clear the live
        // set then re-add, matching addDomain's own backing collection).
        if (rep.getDomains() != null) {
            rep.getDomains().clear();
        }
        if (domains != null) {
            for (OrganizationDomainModel d : domains) {
                if (d != null && d.getName() != null && !d.getName().isBlank()) {
                    org.keycloak.representations.idm.OrganizationDomainRepresentation dr =
                            new org.keycloak.representations.idm.OrganizationDomainRepresentation();
                    dr.setName(d.getName());
                    dr.setVerified(d.isVerified());
                    rep.addDomain(dr);
                }
            }
        }

        String action = captureCreate ? "CREATE_ORGANIZATION" : "UPDATE_ORGANIZATION";

        String repJson;
        try {
            repJson = MAPPER.writeValueAsString(rep);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new RuntimeException(
                    "IGA capture " + action + ": failed to serialize captured "
                    + "OrganizationRepresentation for org=" + delegate.getName(), e);
        }

        int attrs = rep.getAttributes() == null ? 0 : rep.getAttributes().size();
        int doms = domains == null ? 0 : domains.size();
        log.infof("IGA capture %s: full-rep path for org=%s (id=%s, attributes=%d, domains=%d, "
                + "%d chars) captured at the model-layer terminal seam "
                + "(RepresentationToModel.toModel#setDomains); CR written in a separate tx, "
                + "request tx marked rollback-only so the scratch org state is discarded "
                + "(zero rows persisted at draft); full config will replay on commit",
                action, delegate.getName(), orgId, attrs, doms, repJson.length());

        // rowsJson contract: CREATE consumed by replayCreateOrganization
        // (ORG_NAME/ORG_ALIAS/REP_JSON), UPDATE by replayUpdateOrganization
        // (ORG_ID/REP_JSON). We supply all keys so both replays resolve.
        Map<String, Object> row = new java.util.LinkedHashMap<>();
        row.put("ORG_ID", orgId);
        row.put("ORG_NAME", delegate.getName());
        if (delegate.getAlias() != null) row.put("ORG_ALIAS", delegate.getAlias());
        if (delegate.getRedirectUrl() != null) row.put("ORG_REDIRECT_URL", delegate.getRedirectUrl());
        row.put("REALM_ID", realmId());
        row.put("REP_JSON", repJson);

        String[] crIdHolder = new String[1];
        String entityKey = captureCreate ? delegate.getName() : orgId;
        KeycloakModelUtils.runJobInTransaction(session.getKeycloakSessionFactory(), newSession -> {
            RealmModel newRealm = newSession.realms().getRealm(realmId());
            EntityManager newEm = newSession.getProvider(JpaConnectionProvider.class).getEntityManager();
            IgaChangeRequestService newService = new IgaChangeRequestService(newEm, newSession);
            crIdHolder[0] = newService.create(newRealm, "ORGANIZATION", entityKey,
                    action, List.of(row), null).getId();
        });

        session.getTransactionManager().setRollbackOnly();

        throw new IgaPendingApprovalException(crIdHolder[0], "ORGANIZATION", action);
    }

    private String realmId() {
        RealmModel realm = session.getContext().getRealm();
        return realm != null ? realm.getId() : null;
    }

    private boolean intercept() {
        // captureCreate adapters are only ever built when IGA is active and not
        // replaying (IgaOrganizationProvider.create gated by isIgaActive()).
        // Update-mode adapters re-check via the provider so replay
        // (IGA_REPLAY_ACTIVE) and non-IGA realms pass straight through.
        if (captureCreate) return true;
        return provider.igaActive();
    }

    // ---- intercepted setters: pass through to the real model so
    // RepresentationToModel.toModel builds the COMPLETE representation; only
    // setDomains (the terminal seam, above) intercepts. ----

    @Override
    public void setName(String name) {
        delegate.setName(name);
    }

    @Override
    public void setAlias(String alias) {
        delegate.setAlias(alias);
    }

    @Override
    public void setEnabled(boolean enabled) {
        delegate.setEnabled(enabled);
    }

    @Override
    public void setDescription(String description) {
        delegate.setDescription(description);
    }

    @Override
    public void setRedirectUrl(String redirectUrl) {
        delegate.setRedirectUrl(redirectUrl);
    }

    @Override
    public void setAttributes(Map<String, List<String>> attributes) {
        delegate.setAttributes(attributes);
    }

    // ---- pure delegation (reads + identity) ----

    @Override
    public String getId() {
        return delegate.getId();
    }

    @Override
    public String getName() {
        return delegate.getName();
    }

    @Override
    public String getAlias() {
        return delegate.getAlias();
    }

    @Override
    public boolean isEnabled() {
        return delegate.isEnabled();
    }

    @Override
    public String getDescription() {
        return delegate.getDescription();
    }

    @Override
    public String getRedirectUrl() {
        return delegate.getRedirectUrl();
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        return delegate.getAttributes();
    }

    @Override
    public Stream<OrganizationDomainModel> getDomains() {
        return delegate.getDomains();
    }

    @Override
    public Stream<IdentityProviderModel> getIdentityProviders() {
        return delegate.getIdentityProviders();
    }

    @Override
    public boolean isManaged(UserModel user) {
        return delegate.isManaged(user);
    }

    @Override
    public boolean isMember(UserModel user) {
        return delegate.isMember(user);
    }

    // ---- equality/hash by org id ----
    //
    // KC's JpaOrganizationProvider.getMemberById (KC 26.5.5,
    // {@code JpaOrganizationProvider.java:444-457}) probes membership with
    // {@code getByMember(user).anyMatch(organization::equals)}. The
    // {@code organization} argument on the inbound REST call is the
    // {@link IgaOrganizationModel} returned by {@code getById}; the stream
    // entries are ALSO {@link IgaOrganizationModel} instances built fresh per
    // call by {@code IgaOrganizationProvider.getByMember}. Two distinct wrapper
    // objects for the same underlying org → {@code Object.equals} (identity)
    // returns false → {@code anyMatch} returns false → {@code getMemberById}
    // returns null → {@code OrganizationMemberResource.getMember} throws
    // {@code NotFoundException} and the admin REST call (e.g. DELETE
    // .../members/{id}, GET .../members/{id}) responds with HTTP 404 — which
    // breaks every {@code REMOVE_ORG_MEMBER}-style flow.
    //
    // Mirror KC's own pattern (model/jpa OrganizationAdapter.java:252-263):
    // any two {@link OrganizationModel} instances with the same {@code getId()}
    // are equal, hash on the id alone. Identical contract — symmetric across
    // mixed (wrapped vs raw) comparisons used by KC's own anyMatch.
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof OrganizationModel)) return false;

        OrganizationModel that = (OrganizationModel) o;
        return that.getId().equals(getId());
    }

    @Override
    public int hashCode() {
        return getId().hashCode();
    }
}
