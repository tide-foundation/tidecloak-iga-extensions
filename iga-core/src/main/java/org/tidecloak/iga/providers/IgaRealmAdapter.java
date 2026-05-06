package org.tidecloak.iga.providers;

import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.jpa.RealmAdapter;
import org.keycloak.models.jpa.entities.RealmEntity;

import jakarta.persistence.EntityManager;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Wraps RealmAdapter and intercepts realm-attribute writes (REALM_ATTRIBUTE
 * table) for the IGA approval workflow.
 *
 * <h3>Bootstrap: enabling IGA</h3>
 * When IGA is OFF and an admin sets the realm attribute {@code isIGAEnabled =
 * true}, {@code isIgaActive(this)} returns {@code false} at the moment of the
 * write so the call is passed straight through to {@code super.setAttribute}.
 * IGA only "engages" on the next write, after the attribute has been
 * persisted.
 *
 * <h3>Disable: turning IGA off</h3>
 * Once IGA is ON, an admin trying to set {@code isIGAEnabled = false} goes
 * through the normal change-request flow — disabling IGA requires admin
 * approval just like any other privileged realm-attribute write.
 *
 * <h3>Conflict rule</h3>
 * The existing one-pending-CR-per-entity rule applies: while a realm-attribute
 * CR is pending, attempting to set or remove ANY realm attribute on the same
 * realm fails with 409. Admins must approve or deny the existing CR first.
 */
public class IgaRealmAdapter extends RealmAdapter {

    private final KeycloakSession igaSession;

    public IgaRealmAdapter(KeycloakSession session, EntityManager em, RealmEntity realm) {
        super(session, em, realm);
        this.igaSession = session;
    }

    private IgaChangeRequestService getService() {
        EntityManager em = igaSession.getProvider(JpaConnectionProvider.class).getEntityManager();
        return new IgaChangeRequestService(em, igaSession);
    }

    private boolean isIgaActive() {
        IgaChangeRequestService service = getService();
        // isIgaEnabled checks the very attribute being mutated; this means
        // an admin enabling IGA for the first time falls into the !active
        // branch and the write is applied directly.
        if (!service.isIgaEnabled(this)) return false;
        Object replay = igaSession.getAttribute("IGA_REPLAY_ACTIVE");
        return !"true".equals(replay);
    }

    @Override
    public void setAttribute(String name, String value) {
        if (!isIgaActive()) {
            super.setAttribute(name, value);
            return;
        }
        IgaChangeRequestService service = getService();
        String realmId = getId();
        checkNoPendingCr(service, realmId);
        Map<String, Object> row = new HashMap<>();
        row.put("REALM_ID", realmId);
        row.put("NAME", name);
        row.put("VALUE", value);
        service.create(this, "REALM", realmId, "SET_REALM_ATTRIBUTE",
                List.of(row), null);
    }

    @Override
    public void removeAttribute(String name) {
        if (!isIgaActive()) {
            super.removeAttribute(name);
            return;
        }
        IgaChangeRequestService service = getService();
        String realmId = getId();
        checkNoPendingCr(service, realmId);
        Map<String, Object> row = new HashMap<>();
        row.put("REALM_ID", realmId);
        row.put("NAME", name);
        service.create(this, "REALM", realmId, "REMOVE_REALM_ATTRIBUTE",
                List.of(row), null);
    }

    private void checkNoPendingCr(IgaChangeRequestService service, String realmId) {
        var existing = service.findPending(realmId, "REALM", realmId);
        if (existing != null) {
            throw new IgaConflictException(existing.getId());
        }
    }
}
