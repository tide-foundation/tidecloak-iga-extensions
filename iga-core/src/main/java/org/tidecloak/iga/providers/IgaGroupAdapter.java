package org.tidecloak.iga.providers;

import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.jpa.GroupAdapter;
import org.keycloak.models.jpa.entities.GroupEntity;

import jakarta.persistence.EntityManager;
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
}
