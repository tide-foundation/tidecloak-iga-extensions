package org.tidecloak.iga.providers;

import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.jpa.RoleAdapter;
import org.keycloak.models.jpa.entities.RoleEntity;

import jakarta.persistence.EntityManager;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Wraps RoleAdapter and intercepts composite role operations for IGA.
 */
public class IgaRoleAdapter extends RoleAdapter {

    private final KeycloakSession session;

    public IgaRoleAdapter(KeycloakSession session, RealmModel realm, EntityManager em, RoleEntity role) {
        super(session, realm, em, role);
        this.session = session;
    }

    private IgaChangeRequestService getService() {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        return new IgaChangeRequestService(em, session);
    }

    private boolean isIgaActive() {
        IgaChangeRequestService service = getService();
        if (!service.isIgaEnabled(realm)) return false;
        Object replay = session.getAttribute("IGA_REPLAY_ACTIVE");
        return !"true".equals(replay);
    }

    @Override
    public void addCompositeRole(RoleModel role) {
        if (!isIgaActive()) {
            super.addCompositeRole(role);
            return;
        }
        IgaChangeRequestService service = getService();
        String roleId = getId();
        service.create(realm, "ROLE", roleId, "ADD_COMPOSITE",
                List.of(Map.of("COMPOSITE", roleId, "CHILD_ROLE", role.getId())),
                null);
    }

    @Override
    public void removeCompositeRole(RoleModel role) {
        if (!isIgaActive()) {
            super.removeCompositeRole(role);
            return;
        }
        IgaChangeRequestService service = getService();
        String roleId = getId();
        service.create(realm, "ROLE", roleId, "REMOVE_COMPOSITE",
                List.of(Map.of("COMPOSITE", roleId, "CHILD_ROLE", role.getId())),
                null);
    }

    // -------------------------------------------------------------------------
    // Attribute interception (ROLE_ATTRIBUTE).
    //
    // One-pending-CR-per-entity rule applies; concurrent attribute writes on
    // the same role while a CR is pending throw IgaConflictException (409).
    // -------------------------------------------------------------------------

    @Override
    public void setSingleAttribute(String name, String value) {
        if (!isIgaActive()) {
            super.setSingleAttribute(name, value);
            return;
        }
        IgaChangeRequestService service = getService();
        String roleId = getId();
        checkNoPendingCr(service, roleId);
        Map<String, Object> row = new HashMap<>();
        row.put("ROLE_ID", roleId);
        row.put("NAME", name);
        row.put("VALUE", value);
        service.create(realm, "ROLE", roleId, "SET_ROLE_ATTRIBUTE",
                List.of(row), null);
    }

    @Override
    public void setAttribute(String name, List<String> values) {
        if (!isIgaActive()) {
            super.setAttribute(name, values);
            return;
        }
        IgaChangeRequestService service = getService();
        String roleId = getId();
        checkNoPendingCr(service, roleId);
        List<Map<String, Object>> rows = new ArrayList<>();
        if (values != null) {
            for (String v : values) {
                Map<String, Object> row = new HashMap<>();
                row.put("ROLE_ID", roleId);
                row.put("NAME", name);
                row.put("VALUE", v);
                rows.add(row);
            }
        }
        if (rows.isEmpty()) {
            Map<String, Object> row = new HashMap<>();
            row.put("ROLE_ID", roleId);
            row.put("NAME", name);
            row.put("VALUE", null);
            rows.add(row);
        }
        service.create(realm, "ROLE", roleId, "SET_ROLE_ATTRIBUTE", rows, null);
    }

    @Override
    public void removeAttribute(String name) {
        if (!isIgaActive()) {
            super.removeAttribute(name);
            return;
        }
        IgaChangeRequestService service = getService();
        String roleId = getId();
        checkNoPendingCr(service, roleId);
        Map<String, Object> row = new HashMap<>();
        row.put("ROLE_ID", roleId);
        row.put("NAME", name);
        service.create(realm, "ROLE", roleId, "REMOVE_ROLE_ATTRIBUTE",
                List.of(row), null);
    }

    private void checkNoPendingCr(IgaChangeRequestService service, String roleId) {
        var existing = service.findPending(realm.getId(), "ROLE", roleId);
        if (existing != null) {
            throw new IgaConflictException(existing.getId());
        }
    }
}
