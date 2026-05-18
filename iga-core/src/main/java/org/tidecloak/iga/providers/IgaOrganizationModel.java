package org.tidecloak.iga.providers;

import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OrganizationDomainModel;
import org.keycloak.models.OrganizationModel;
import org.keycloak.models.UserModel;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * Decorating {@link OrganizationModel} that intercepts organization-update
 * mutations through the IGA approval workflow, mirroring how
 * {@code IgaRealmAdapter} intercepts realm-attribute writes.
 *
 * <p>Keycloak's {@code OrganizationResource.update(PUT .../organizations/{id})}
 * applies the incoming {@code OrganizationRepresentation} by calling
 * {@code RepresentationToModel.toModel(rep, model)}, which in turn calls
 * {@code setName/setAlias/setEnabled/setRedirectUrl/setDescription/
 * setAttributes/setDomains} on the model returned by
 * {@code OrganizationProvider.getById}. We wrap that model here so the FIRST
 * mutating call records an {@code UPDATE_ORGANIZATION} change request (carrying
 * the full {@code OrganizationRepresentation} the JAX-RS filter captured as
 * {@code REP_JSON}) and throws {@code IgaPendingApprovalException} → HTTP 202,
 * before any partial mutation is persisted. Domain changes are part of the same
 * representation ({@code setDomains}) so they are covered transparently — KC
 * 26.5.5 has no standalone organization-domain endpoint.</p>
 *
 * <p>All read accessors delegate straight to the wrapped model so normal GETs
 * and replay (where {@code IgaOrganizationProvider.igaActive()} is false under
 * {@code IGA_REPLAY_ACTIVE}) are unaffected. Setters delegate to the wrapped
 * model when IGA is inactive so non-IGA realms and replay behave exactly like
 * stock Keycloak.</p>
 */
public class IgaOrganizationModel implements OrganizationModel {

    private final KeycloakSession session;
    private final OrganizationModel delegate;
    private final IgaOrganizationProvider provider;

    public IgaOrganizationModel(KeycloakSession session, OrganizationModel delegate,
                                IgaOrganizationProvider provider) {
        this.session = session;
        this.delegate = delegate;
        this.provider = provider;
    }

    /**
     * Record an UPDATE_ORGANIZATION change request and throw to interrupt the
     * write. The full desired state travels as REP_JSON (captured by the
     * JAX-RS filter on PUT .../organizations/{id}); replay rebuilds it via
     * Keycloak's own {@code RepresentationToModel.toModel} — the exact builder
     * {@code OrganizationResource.update} uses.
     */
    private void recordUpdateAndThrow() {
        Map<String, Object> row = new java.util.LinkedHashMap<>();
        row.put("ORG_ID", delegate.getId());
        String repJson = org.tidecloak.iga.rest.IgaRepresentationCaptureFilter
                .pendingRepJson(session,
                        org.tidecloak.iga.rest.IgaRepresentationCaptureFilter.TYPE_ORGANIZATION);
        if (repJson != null) {
            row.put("REP_JSON", repJson);
        }
        provider.recordOrgUpdate(delegate.getId(), List.of(row));
    }

    private boolean intercept() {
        return provider.igaActive();
    }

    // ---- intercepted mutators (the toModel update path) ----

    @Override
    public void setName(String name) {
        if (intercept()) { recordUpdateAndThrow(); return; }
        delegate.setName(name);
    }

    @Override
    public void setAlias(String alias) {
        if (intercept()) { recordUpdateAndThrow(); return; }
        delegate.setAlias(alias);
    }

    @Override
    public void setEnabled(boolean enabled) {
        if (intercept()) { recordUpdateAndThrow(); return; }
        delegate.setEnabled(enabled);
    }

    @Override
    public void setDescription(String description) {
        if (intercept()) { recordUpdateAndThrow(); return; }
        delegate.setDescription(description);
    }

    @Override
    public void setRedirectUrl(String redirectUrl) {
        if (intercept()) { recordUpdateAndThrow(); return; }
        delegate.setRedirectUrl(redirectUrl);
    }

    @Override
    public void setAttributes(Map<String, List<String>> attributes) {
        if (intercept()) { recordUpdateAndThrow(); return; }
        delegate.setAttributes(attributes);
    }

    @Override
    public void setDomains(java.util.Set<OrganizationDomainModel> domains) {
        if (intercept()) { recordUpdateAndThrow(); return; }
        delegate.setDomains(domains);
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
}
