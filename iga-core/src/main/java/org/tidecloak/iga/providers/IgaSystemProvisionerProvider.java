package org.tidecloak.iga.providers;

import org.keycloak.models.RealmModel;
import org.keycloak.provider.Provider;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.tidecloak.iga.services.IgaSystemProvisioner.TideUhoEnqueueResult;

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
}
