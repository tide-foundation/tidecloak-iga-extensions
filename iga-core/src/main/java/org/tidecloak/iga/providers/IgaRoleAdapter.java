package org.tidecloak.iga.providers;

import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.jpa.RoleAdapter;
import org.keycloak.models.jpa.entities.RoleEntity;

import jakarta.persistence.EntityManager;
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
}
