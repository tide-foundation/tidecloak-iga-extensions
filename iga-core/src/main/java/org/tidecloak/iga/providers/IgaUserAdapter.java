package org.tidecloak.iga.providers;

import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.jpa.UserAdapter;
import org.keycloak.models.jpa.entities.UserEntity;

import jakarta.persistence.EntityManager;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Wraps UserAdapter and intercepts mutating operations to route through IGA
 * when IGA is enabled and no replay is active.
 */
public class IgaUserAdapter extends UserAdapter {

    // UserAdapter.session is private, so we keep our own reference
    private final KeycloakSession igaSession;

    public IgaUserAdapter(KeycloakSession session, RealmModel realm, EntityManager em, UserEntity user) {
        super(session, realm, em, user);
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
    public void grantRole(RoleModel role) {
        if (!isIgaActive()) {
            super.grantRole(role);
            return;
        }
        IgaChangeRequestService service = getService();
        String userId = getId();
        checkNoPendingCr(service, userId);
        String requestedBy = getCurrentUserId();
        service.create(realm, "USER", userId, "GRANT_ROLES",
                List.of(Map.of("USER_ID", userId, "ROLE_ID", role.getId())),
                requestedBy);
    }

    @Override
    public void deleteRoleMapping(RoleModel role) {
        if (!isIgaActive()) {
            super.deleteRoleMapping(role);
            return;
        }
        IgaChangeRequestService service = getService();
        String userId = getId();
        checkNoPendingCr(service, userId);
        String requestedBy = getCurrentUserId();
        service.create(realm, "USER", userId, "REVOKE_ROLES",
                List.of(Map.of("USER_ID", userId, "ROLE_ID", role.getId())),
                requestedBy);
    }

    @Override
    public void joinGroup(GroupModel group) {
        if (!isIgaActive()) {
            super.joinGroup(group);
            return;
        }
        IgaChangeRequestService service = getService();
        String userId = getId();
        checkNoPendingCr(service, userId);
        String requestedBy = getCurrentUserId();
        service.create(realm, "USER", userId, "JOIN_GROUPS",
                List.of(Map.of("USER", userId, "GROUP", group.getId())),
                requestedBy);
    }

    @Override
    public void leaveGroup(GroupModel group) {
        if (!isIgaActive()) {
            super.leaveGroup(group);
            return;
        }
        IgaChangeRequestService service = getService();
        String userId = getId();
        checkNoPendingCr(service, userId);
        String requestedBy = getCurrentUserId();
        service.create(realm, "USER", userId, "LEAVE_GROUPS",
                List.of(Map.of("USER", userId, "GROUP", group.getId())),
                requestedBy);
    }

    // -------------------------------------------------------------------------
    // Attribute interception (USER_ATTRIBUTE)
    //
    // KNOWN LIMITATION: the existing one-pending-CR-per-entity rule means that
    // if an admin sets attribute A on user U, then tries to set attribute B on
    // the same user before the first CR is approved/denied, the second attempt
    // returns 409 IgaConflictException. Admins must drain the existing pending
    // CR (approve or deny) before issuing a new one for the same entity.
    // -------------------------------------------------------------------------

    @Override
    public void setSingleAttribute(String name, String value) {
        if (!isIgaActive()) {
            super.setSingleAttribute(name, value);
            return;
        }
        IgaChangeRequestService service = getService();
        String userId = getId();
        checkNoPendingCr(service, userId);
        Map<String, Object> row = new HashMap<>();
        row.put("USER_ID", userId);
        row.put("NAME", name);
        row.put("VALUE", value);
        service.create(realm, "USER", userId, "SET_USER_ATTRIBUTE",
                List.of(row), getCurrentUserId());
    }

    @Override
    public void setAttribute(String name, List<String> values) {
        if (!isIgaActive()) {
            super.setAttribute(name, values);
            return;
        }
        IgaChangeRequestService service = getService();
        String userId = getId();
        checkNoPendingCr(service, userId);
        // Multi-value: emit one row per value so replay can persist each one.
        List<Map<String, Object>> rows = new ArrayList<>();
        if (values != null) {
            for (String v : values) {
                Map<String, Object> row = new HashMap<>();
                row.put("USER_ID", userId);
                row.put("NAME", name);
                row.put("VALUE", v);
                rows.add(row);
            }
        }
        if (rows.isEmpty()) {
            // Empty values means "remove all" — represent as a single null-value
            // row so replay can detect it as a clear.
            Map<String, Object> row = new HashMap<>();
            row.put("USER_ID", userId);
            row.put("NAME", name);
            row.put("VALUE", null);
            rows.add(row);
        }
        service.create(realm, "USER", userId, "SET_USER_ATTRIBUTE", rows, getCurrentUserId());
    }

    @Override
    public void removeAttribute(String name) {
        if (!isIgaActive()) {
            super.removeAttribute(name);
            return;
        }
        IgaChangeRequestService service = getService();
        String userId = getId();
        checkNoPendingCr(service, userId);
        Map<String, Object> row = new HashMap<>();
        row.put("USER_ID", userId);
        row.put("NAME", name);
        service.create(realm, "USER", userId, "REMOVE_USER_ATTRIBUTE",
                List.of(row), getCurrentUserId());
    }

    private void checkNoPendingCr(IgaChangeRequestService service, String userId) {
        var existing = service.findPending(realm.getId(), "USER", userId);
        if (existing != null) {
            throw new IgaConflictException(existing.getId());
        }
    }

    private String getCurrentUserId() {
        try {
            var auth = igaSession.getContext().getAuthenticationSession();
            if (auth != null) {
                return auth.getAuthenticatedUser() != null
                        ? auth.getAuthenticatedUser().getId()
                        : null;
            }
        } catch (Exception ignored) {
        }
        return null;
    }
}
