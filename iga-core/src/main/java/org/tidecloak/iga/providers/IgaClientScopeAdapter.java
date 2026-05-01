package org.tidecloak.iga.providers;

import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.jpa.ClientScopeAdapter;
import org.keycloak.models.jpa.entities.ClientScopeEntity;

import jakarta.persistence.EntityManager;
import java.util.List;
import java.util.Map;

/**
 * Wraps ClientScopeAdapter and intercepts scope mapping operations for IGA.
 */
public class IgaClientScopeAdapter extends ClientScopeAdapter {

    private final KeycloakSession igaSession;

    public IgaClientScopeAdapter(RealmModel realm, EntityManager em, KeycloakSession session, ClientScopeEntity clientScopeEntity) {
        super(realm, em, session, clientScopeEntity);
        this.igaSession = session;
    }

    private IgaChangeRequestService getService() {
        EntityManager em = igaSession.getProvider(JpaConnectionProvider.class).getEntityManager();
        return new IgaChangeRequestService(em, igaSession);
    }

    private boolean isIgaActive() {
        IgaChangeRequestService service = getService();
        if (!service.isIgaEnabled(realm)) return false;
        Object replay = igaSession.getAttribute("IGA_REPLAY_ACTIVE");
        return !"true".equals(replay);
    }

    @Override
    public void addScopeMapping(RoleModel role) {
        if (!isIgaActive()) {
            super.addScopeMapping(role);
            return;
        }
        IgaChangeRequestService service = getService();
        String scopeId = getId();
        service.create(realm, "CLIENT", scopeId, "SCOPE_ADD_ROLE",
                List.of(Map.of("SCOPE_ID", scopeId, "ROLE_ID", role.getId())),
                null);
    }

    @Override
    public void deleteScopeMapping(RoleModel role) {
        if (!isIgaActive()) {
            super.deleteScopeMapping(role);
            return;
        }
        IgaChangeRequestService service = getService();
        String scopeId = getId();
        service.create(realm, "CLIENT", scopeId, "SCOPE_REMOVE_ROLE",
                List.of(Map.of("SCOPE_ID", scopeId, "ROLE_ID", role.getId())),
                null);
    }
}
