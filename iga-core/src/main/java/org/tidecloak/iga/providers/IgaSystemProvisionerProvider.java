package org.tidecloak.iga.providers;

import org.keycloak.models.RealmModel;
import org.keycloak.provider.Provider;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.tidecloak.iga.services.IgaSystemProvisioner.TideUhoEnqueueResult;
import org.tidecloak.iga.services.IgaSystemProvisioner.TideUhoRemovalResult;

/**
 * Keycloak SPI provider exposing the {@code tide-claims} scope auto-provisioning
 * enqueue so out-of-module callers (notably {@code tidecloak-idp-extensions}'
 * server-start hook) can drive it WITHOUT a Maven dependency on {@code iga-core}.
 *
 * <p>Resolve and call it as:
 * <pre>{@code
 * TideUhoEnqueueResult r = session
 *     .getProvider(IgaSystemProvisionerProvider.class)
 *     .enqueueTideClaimsScopeProvisioning(realm, scopeRep, "system");
 * }</pre>
 *
 * <p>The default factory id is {@code "default"} (single registered
 * implementation, selected automatically when no id is given).
 *
 * @see org.tidecloak.iga.services.IgaSystemProvisioner
 */
public interface IgaSystemProvisionerProvider extends Provider {

    /**
     * State-aware, idempotent enqueue of the tide-claims scope provisioning
     * chain (CREATE_CLIENT_SCOPE + REALM_DEFAULT_SCOPE_ADD + per-client
     * ASSIGN_SCOPE) for {@code realm}. Safe to call repeatedly. See
     * {@link org.tidecloak.iga.services.IgaSystemProvisioner#enqueueTideClaimsScopeProvisioning}.
     *
     * @param realm       the IGA-enabled target realm (caller checks enablement)
     * @param scopeRep    the {@code tide-claims} client scope representation,
     *                    including its inline {@code t.uho} protocol mapper
     * @param requestedBy the {@code REQUESTED_BY} stamp (e.g. {@code "system"})
     * @return a {@link TideUhoEnqueueResult} describing which CRs were filed
     */
    TideUhoEnqueueResult enqueueTideClaimsScopeProvisioning(
            RealmModel realm, ClientScopeRepresentation scopeRep, String requestedBy);

    /**
     * State-aware, idempotent enqueue of the tide-claims scope <em>teardown</em>
     * (a single governed {@code DELETE_CLIENT_SCOPE} CR) for {@code realm} — the
     * counterpart of {@link #enqueueTideClaimsScopeProvisioning}, invoked when a
     * realm is offboarded to local {@code /crypto} signing so the attested
     * {@code t.uho} mapper does not linger. Safe to call repeatedly. See
     * {@link org.tidecloak.iga.services.IgaSystemProvisioner#enqueueTideClaimsScopeRemoval}.
     *
     * <p>A SINGLE removal CR is sufficient: Keycloak's
     * {@code removeClientScope(realm, id)} cascade removes the realm-default, all
     * per-client attachments, the role-mapping allow-list, and the nested
     * {@code t.uho} protocol mapper in one operation — no reverse-ordered detach
     * CRs are needed.
     *
     * @param realm       the IGA-enabled target realm (caller checks enablement)
     * @param requestedBy the {@code REQUESTED_BY} stamp (e.g. {@code "system"})
     * @return a {@link TideUhoRemovalResult} describing whether a CR was filed
     *         (or that there was nothing to do)
     */
    TideUhoRemovalResult enqueueTideClaimsScopeRemoval(RealmModel realm, String requestedBy);
}
