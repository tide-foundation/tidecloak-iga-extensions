package org.tidecloak.iga.providers;

import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.jpa.GroupAdapter;
import org.keycloak.models.jpa.entities.GroupEntity;

import jakarta.persistence.EntityManager;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Wraps GroupAdapter and intercepts role mapping operations for IGA.
 */
public class IgaGroupAdapter extends GroupAdapter {

    private final KeycloakSession session;

    public IgaGroupAdapter(KeycloakSession session, RealmModel realm, EntityManager em, GroupEntity group) {
        super(session, realm, em, group);
        this.session = session;
    }

    private IgaChangeRequestService getService() {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        return new IgaChangeRequestService(em, session);
    }

    private boolean isIgaActive(RealmModel realm) {
        IgaChangeRequestService service = getService();
        if (!service.isIgaEnabled(realm)) return false;
        Object replay = session.getAttribute("IGA_REPLAY_ACTIVE");
        return !"true".equals(replay);
    }

    @Override
    public void grantRole(RoleModel role) {
        if (!isIgaActive(realm)) {
            super.grantRole(role);
            return;
        }
        IgaChangeRequestService service = getService();
        String groupId = getId();
        service.create(realm, "GROUP", groupId, "GROUP_GRANT_ROLES",
                List.of(Map.of("GROUP", groupId, "ROLE", role.getId())),
                null);
    }

    @Override
    public void deleteRoleMapping(RoleModel role) {
        if (!isIgaActive(realm)) {
            super.deleteRoleMapping(role);
            return;
        }
        IgaChangeRequestService service = getService();
        String groupId = getId();
        service.create(realm, "GROUP", groupId, "GROUP_REVOKE_ROLES",
                List.of(Map.of("GROUP", groupId, "ROLE", role.getId())),
                null);
    }

    // -------------------------------------------------------------------------
    // Attribute interception (GROUP_ATTRIBUTE).
    //
    // The one-pending-CR-per-entity rule applies; consecutive attribute writes
    // on the same group while a CR is pending throw IgaConflictException (409).
    // -------------------------------------------------------------------------

    @Override
    public void setSingleAttribute(String name, String value) {
        if (!isIgaActive(realm)) {
            super.setSingleAttribute(name, value);
            return;
        }
        IgaChangeRequestService service = getService();
        String groupId = getId();
        checkNoPendingCr(service, groupId);
        Map<String, Object> row = new HashMap<>();
        row.put("GROUP_ID", groupId);
        row.put("NAME", name);
        row.put("VALUE", value);
        service.create(realm, "GROUP", groupId, "SET_GROUP_ATTRIBUTE",
                List.of(row), null);
    }

    @Override
    public void setAttribute(String name, List<String> values) {
        if (!isIgaActive(realm)) {
            super.setAttribute(name, values);
            return;
        }
        IgaChangeRequestService service = getService();
        String groupId = getId();
        checkNoPendingCr(service, groupId);
        List<Map<String, Object>> rows = new ArrayList<>();
        if (values != null) {
            for (String v : values) {
                Map<String, Object> row = new HashMap<>();
                row.put("GROUP_ID", groupId);
                row.put("NAME", name);
                row.put("VALUE", v);
                rows.add(row);
            }
        }
        if (rows.isEmpty()) {
            Map<String, Object> row = new HashMap<>();
            row.put("GROUP_ID", groupId);
            row.put("NAME", name);
            row.put("VALUE", null);
            rows.add(row);
        }
        service.create(realm, "GROUP", groupId, "SET_GROUP_ATTRIBUTE", rows, null);
    }

    @Override
    public void removeAttribute(String name) {
        if (!isIgaActive(realm)) {
            super.removeAttribute(name);
            return;
        }
        IgaChangeRequestService service = getService();
        String groupId = getId();
        checkNoPendingCr(service, groupId);
        Map<String, Object> row = new HashMap<>();
        row.put("GROUP_ID", groupId);
        row.put("NAME", name);
        service.create(realm, "GROUP", groupId, "REMOVE_GROUP_ATTRIBUTE",
                List.of(row), null);
    }

    private void checkNoPendingCr(IgaChangeRequestService service, String groupId) {
        var existing = service.findPending(realm.getId(), "GROUP", groupId);
        if (existing != null) {
            throw new IgaConflictException(existing.getId());
        }
    }
}
