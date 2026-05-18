package org.tidecloak.iga.providers;

import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.jpa.ClientAdapter;
import org.keycloak.models.jpa.entities.ClientEntity;

import jakarta.persistence.EntityManager;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
        // getId() returns the client's UUID primary key — NOT the human
        // clientId. rowsJson contract: CLIENT_UUID = uuid, CLIENT_ID = human.
        String clientUuid = getId();
        service.create(realm, "CLIENT", clientUuid, "ASSIGN_SCOPE",
                List.of(Map.of(
                        "CLIENT_UUID", clientUuid,
                        "CLIENT_ID", getClientId(),
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
        String clientUuid = getId();
        service.create(realm, "CLIENT", clientUuid, "REMOVE_SCOPE",
                List.of(Map.of(
                        "CLIENT_UUID", clientUuid,
                        "CLIENT_ID", getClientId(),
                        "SCOPE_ID", scope.getId())),
                null);
    }

    // -------------------------------------------------------------------------
    // Attribute interception (CLIENT_ATTRIBUTES).
    //
    // Same one-pending-CR-per-entity rule as the rest of the inline-pattern
    // operations: admins must drain a client's pending CR before issuing
    // another one for that client.
    // -------------------------------------------------------------------------

    @Override
    public void setAttribute(String name, String value) {
        if (!isIgaActive()) {
            super.setAttribute(name, value);
            return;
        }
        IgaChangeRequestService service = getService();
        String clientUuid = getId();
        checkNoPendingCr(service, clientUuid);
        Map<String, Object> row = new HashMap<>();
        row.put("CLIENT_UUID", clientUuid);
        row.put("CLIENT_ID", getClientId());
        row.put("NAME", name);
        row.put("VALUE", value);
        service.create(realm, "CLIENT", clientUuid, "SET_CLIENT_ATTRIBUTE",
                List.of(row), null);
    }

    @Override
    public void removeAttribute(String name) {
        if (!isIgaActive()) {
            super.removeAttribute(name);
            return;
        }
        IgaChangeRequestService service = getService();
        String clientUuid = getId();
        checkNoPendingCr(service, clientUuid);
        Map<String, Object> row = new HashMap<>();
        row.put("CLIENT_UUID", clientUuid);
        row.put("CLIENT_ID", getClientId());
        row.put("NAME", name);
        service.create(realm, "CLIENT", clientUuid, "REMOVE_CLIENT_ATTRIBUTE",
                List.of(row), null);
    }

    private void checkNoPendingCr(IgaChangeRequestService service, String clientUuid) {
        var existing = service.findPending(realm.getId(), "CLIENT", clientUuid);
        if (existing != null) {
            throw new IgaConflictException(existing.getId());
        }
    }

    @Override
    public ProtocolMapperModel addProtocolMapper(ProtocolMapperModel model) {
        if (!isIgaActive()) {
            return super.addProtocolMapper(model);
        }
        IgaChangeRequestService service = getService();
        String clientUuid = getId();
        String mapperId = model.getId() != null ? model.getId() : java.util.UUID.randomUUID().toString();
        service.create(realm, "CLIENT", clientUuid, "ADD_PROTOCOL_MAPPER",
                List.of(Map.of(
                        "ID", mapperId,
                        "NAME", model.getName(),
                        "PROTOCOL", model.getProtocol(),
                        "PROTOCOL_MAPPER_NAME", model.getProtocolMapper(),
                        "CLIENT_UUID", clientUuid,
                        "CLIENT_ID", getClientId()
                )),
                null);
        // Return a stub model with the assigned id
        model.setId(mapperId);
        return model;
    }

    @Override
    public void updateProtocolMapper(ProtocolMapperModel mapping) {
        if (!isIgaActive()) {
            super.updateProtocolMapper(mapping);
            return;
        }
        IgaChangeRequestService service = getService();
        String clientUuid = getId();
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("ID", mapping.getId());
        row.put("NAME", mapping.getName());
        row.put("PROTOCOL", mapping.getProtocol());
        row.put("PROTOCOL_MAPPER_NAME", mapping.getProtocolMapper());
        row.put("CLIENT_UUID", clientUuid);
        row.put("CLIENT_ID", getClientId());
        if (mapping.getConfig() != null) {
            row.put("config", new LinkedHashMap<>(mapping.getConfig()));
        }
        service.create(realm, "CLIENT", clientUuid, "UPDATE_PROTOCOL_MAPPER",
                List.of(row), null);
    }

    @Override
    public void removeProtocolMapper(ProtocolMapperModel mapping) {
        if (!isIgaActive()) {
            super.removeProtocolMapper(mapping);
            return;
        }
        IgaChangeRequestService service = getService();
        String clientUuid = getId();
        Map<String, Object> row = new HashMap<>();
        row.put("ID", mapping.getId());
        row.put("CLIENT_UUID", clientUuid);
        row.put("CLIENT_ID", getClientId());
        service.create(realm, "CLIENT", clientUuid, "REMOVE_PROTOCOL_MAPPER",
                List.of(row), null);
    }

    // -------------------------------------------------------------------------
    // Web origins / redirect URIs — full set replacement.
    //
    // The CLIENT_WEB_ORIGINS and CLIENT_REDIRECT_URIS tables are list-collection
    // tables and have no entity class for per-row attestation. Coverage is
    // provided by the change request snapshot in rows_json; on replay we apply
    // the full set.
    // -------------------------------------------------------------------------

    @Override
    public void setWebOrigins(Set<String> webOrigins) {
        if (!isIgaActive()) {
            super.setWebOrigins(webOrigins);
            return;
        }
        IgaChangeRequestService service = getService();
        String clientUuid = getId();
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("CLIENT_UUID", clientUuid);
        row.put("CLIENT_ID", getClientId());
        row.put("values", webOrigins == null ? new ArrayList<String>() : new ArrayList<>(webOrigins));
        service.create(realm, "CLIENT", clientUuid, "UPDATE_CLIENT_WEB_ORIGINS",
                List.of(row), null);
    }

    @Override
    public void setRedirectUris(Set<String> redirectUris) {
        if (!isIgaActive()) {
            super.setRedirectUris(redirectUris);
            return;
        }
        IgaChangeRequestService service = getService();
        String clientUuid = getId();
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("CLIENT_UUID", clientUuid);
        row.put("CLIENT_ID", getClientId());
        row.put("values", redirectUris == null ? new ArrayList<String>() : new ArrayList<>(redirectUris));
        service.create(realm, "CLIENT", clientUuid, "UPDATE_CLIENT_REDIRECT_URIS",
                List.of(row), null);
    }
}
