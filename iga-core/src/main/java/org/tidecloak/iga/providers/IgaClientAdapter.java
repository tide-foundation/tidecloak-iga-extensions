package org.tidecloak.iga.providers;

import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.jpa.ClientAdapter;
import org.keycloak.models.jpa.entities.ClientEntity;

import jakarta.persistence.EntityManager;
import java.util.List;
import java.util.Map;

/**
 * Wraps ClientAdapter and intercepts scope/mapper operations for IGA.
 */
public class IgaClientAdapter extends ClientAdapter {

    private final KeycloakSession igaSession;

    public IgaClientAdapter(RealmModel realm, EntityManager em, KeycloakSession session, ClientEntity clientEntity) {
        super(realm, em, session, clientEntity);
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
    public void addClientScope(ClientScopeModel scope, boolean defaultScope) {
        if (!isIgaActive()) {
            super.addClientScope(scope, defaultScope);
            return;
        }
        IgaChangeRequestService service = getService();
        String clientId = getId();
        service.create(realm, "CLIENT", clientId, "ASSIGN_SCOPE",
                List.of(Map.of(
                        "CLIENT_ID", clientId,
                        "SCOPE_ID", scope.getId(),
                        "DEFAULT_SCOPE", defaultScope
                )),
                null);
    }

    @Override
    public void removeClientScope(ClientScopeModel scope) {
        if (!isIgaActive()) {
            super.removeClientScope(scope);
            return;
        }
        IgaChangeRequestService service = getService();
        String clientId = getId();
        service.create(realm, "CLIENT", clientId, "REMOVE_SCOPE",
                List.of(Map.of("CLIENT_ID", clientId, "SCOPE_ID", scope.getId())),
                null);
    }

    @Override
    public ProtocolMapperModel addProtocolMapper(ProtocolMapperModel model) {
        if (!isIgaActive()) {
            return super.addProtocolMapper(model);
        }
        IgaChangeRequestService service = getService();
        String clientId = getId();
        String mapperId = model.getId() != null ? model.getId() : java.util.UUID.randomUUID().toString();
        service.create(realm, "CLIENT", clientId, "ADD_PROTOCOL_MAPPER",
                List.of(Map.of(
                        "ID", mapperId,
                        "NAME", model.getName(),
                        "PROTOCOL", model.getProtocol(),
                        "PROTOCOL_MAPPER_NAME", model.getProtocolMapper(),
                        "CLIENT_ID", clientId
                )),
                null);
        // Return a stub model with the assigned id
        model.setId(mapperId);
        return model;
    }
}
