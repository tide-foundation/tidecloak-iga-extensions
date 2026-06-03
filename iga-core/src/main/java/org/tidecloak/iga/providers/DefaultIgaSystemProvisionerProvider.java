package org.tidecloak.iga.providers;

import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.tidecloak.iga.services.IgaSystemProvisioner;
import org.tidecloak.iga.services.IgaSystemProvisioner.TideUhoEnqueueResult;
import org.tidecloak.iga.services.IgaSystemProvisioner.TideUhoRemovalResult;

import jakarta.persistence.EntityManager;

/**
 * Default {@link IgaSystemProvisionerProvider} — a thin per-session wrapper that
 * delegates to {@link IgaSystemProvisioner}, sourcing the request-scoped
 * {@link EntityManager} from the session's {@link JpaConnectionProvider} (same
 * idiom as the rest of {@code iga-core}).
 */
public class DefaultIgaSystemProvisionerProvider implements IgaSystemProvisionerProvider {

    private final KeycloakSession session;

    public DefaultIgaSystemProvisionerProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public TideUhoEnqueueResult enqueueTideClaimsScopeProvisioning(
            RealmModel realm, ClientScopeRepresentation scopeRep, String requestedBy) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        return new IgaSystemProvisioner(session, em)
                .enqueueTideClaimsScopeProvisioning(realm, scopeRep, requestedBy);
    }

    @Override
    public TideUhoRemovalResult enqueueTideClaimsScopeRemoval(RealmModel realm, String requestedBy) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        return new IgaSystemProvisioner(session, em)
                .enqueueTideClaimsScopeRemoval(realm, requestedBy);
    }

    @Override
    public void close() {
        // no-op: the EntityManager is owned by the JpaConnectionProvider.
    }
}
