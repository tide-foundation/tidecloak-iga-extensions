package org.tidecloak.iga.providers;

import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.jpa.ClientScopeAdapter;
import org.keycloak.models.jpa.entities.ClientScopeEntity;

import jakarta.persistence.EntityManager;
import java.util.HashMap;
import java.util.LinkedHashMap;
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

    // -------------------------------------------------------------------------
    // Attribute interception (CLIENT_SCOPE_ATTRIBUTES).
    //
    // Note: client scope CRs reuse the entityType "CLIENT_SCOPE" for the
    // pending-CR check so we do not collide with same-id-but-different-entity
    // rows (the `findPending` query filters by entity type).
    // -------------------------------------------------------------------------

    @Override
    public void setAttribute(String name, String value) {
        if (!isIgaActive()) {
            super.setAttribute(name, value);
            return;
        }
        IgaChangeRequestService service = getService();
        String scopeId = getId();
        checkNoPendingCr(service, scopeId);
        Map<String, Object> row = new HashMap<>();
        row.put("SCOPE_ID", scopeId);
        row.put("NAME", name);
        row.put("VALUE", value);
        service.create(realm, "CLIENT_SCOPE", scopeId, "SET_CLIENT_SCOPE_ATTRIBUTE",
                List.of(row), null);
    }

    @Override
    public void removeAttribute(String name) {
        if (!isIgaActive()) {
            super.removeAttribute(name);
            return;
        }
        IgaChangeRequestService service = getService();
        String scopeId = getId();
        checkNoPendingCr(service, scopeId);
        Map<String, Object> row = new HashMap<>();
        row.put("SCOPE_ID", scopeId);
        row.put("NAME", name);
        service.create(realm, "CLIENT_SCOPE", scopeId, "REMOVE_CLIENT_SCOPE_ATTRIBUTE",
                List.of(row), null);
    }

    private void checkNoPendingCr(IgaChangeRequestService service, String scopeId) {
        var existing = service.findPending(realm.getId(), "CLIENT_SCOPE", scopeId);
        if (existing != null) {
            throw new IgaConflictException(existing.getId());
        }
    }

    // -------------------------------------------------------------------------
    // Protocol mappers on a CLIENT_SCOPE.
    //
    // Mirrors IgaClientAdapter, but the parent entity_type is "CLIENT_SCOPE"
    // so IgaScopeResolver can resolve scope rules against the parent scope
    // attributes when one is configured.
    // -------------------------------------------------------------------------

    @Override
    public ProtocolMapperModel addProtocolMapper(ProtocolMapperModel model) {
        if (!isIgaActive()) {
            return super.addProtocolMapper(model);
        }
        IgaChangeRequestService service = getService();
        String scopeId = getId();
        String mapperId = model.getId() != null ? model.getId() : java.util.UUID.randomUUID().toString();
        service.create(realm, "CLIENT_SCOPE", scopeId, "ADD_PROTOCOL_MAPPER",
                List.of(Map.of(
                        "ID", mapperId,
                        "NAME", model.getName(),
                        "PROTOCOL", model.getProtocol(),
                        "PROTOCOL_MAPPER_NAME", model.getProtocolMapper(),
                        "CLIENT_SCOPE_ID", scopeId
                )),
                null);
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
        String scopeId = getId();
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("ID", mapping.getId());
        row.put("NAME", mapping.getName());
        row.put("PROTOCOL", mapping.getProtocol());
        row.put("PROTOCOL_MAPPER_NAME", mapping.getProtocolMapper());
        row.put("CLIENT_SCOPE_ID", scopeId);
        if (mapping.getConfig() != null) {
            row.put("config", new LinkedHashMap<>(mapping.getConfig()));
        }
        service.create(realm, "CLIENT_SCOPE", scopeId, "UPDATE_PROTOCOL_MAPPER",
                List.of(row), null);
    }

    @Override
    public void removeProtocolMapper(ProtocolMapperModel mapping) {
        if (!isIgaActive()) {
            super.removeProtocolMapper(mapping);
            return;
        }
        IgaChangeRequestService service = getService();
        String scopeId = getId();
        Map<String, Object> row = new HashMap<>();
        row.put("ID", mapping.getId());
        row.put("CLIENT_SCOPE_ID", scopeId);
        service.create(realm, "CLIENT_SCOPE", scopeId, "REMOVE_PROTOCOL_MAPPER",
                List.of(row), null);
    }
}
