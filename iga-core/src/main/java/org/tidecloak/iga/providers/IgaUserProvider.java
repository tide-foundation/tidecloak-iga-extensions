package org.tidecloak.iga.providers;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.jpa.JpaUserProvider;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;

import jakarta.persistence.EntityManager;
import java.util.List;
import java.util.Map;

/**
 * Extends JpaUserProvider to intercept user mutations through IGA when enabled.
 * JpaUserProvider.session is private, so we maintain our own reference as igaSession.
 */
public class IgaUserProvider extends JpaUserProvider {

    // JpaUserProvider.session is private; store our own copy
    private final KeycloakSession igaSession;

    public IgaUserProvider(KeycloakSession session, EntityManager em) {
        super(session, em);
        this.igaSession = session;
    }

    private IgaChangeRequestService getService() {
        return new IgaChangeRequestService(em, igaSession);
    }

    @Override
    public UserModel addUser(RealmModel realm, String username) {
        IgaChangeRequestService service = getService();
        if (!service.isIgaEnabled(realm)) {
            return super.addUser(realm, username);
        }
        // Check if replay is active
        Object replay = igaSession.getAttribute("IGA_REPLAY_ACTIVE");
        if ("true".equals(replay)) {
            return super.addUser(realm, username);
        }

        String generatedId = KeycloakModelUtils.generateId();
        String requestedBy = getCurrentUserId();
        service.create(realm, "USER", generatedId, "CREATE_USER",
                List.of(Map.of(
                        "ID", generatedId,
                        "USERNAME", username.toLowerCase(),
                        "REALM_ID", realm.getId(),
                        "CREATED_TIMESTAMP", System.currentTimeMillis(),
                        "EMAIL_VERIFIED", false,
                        "ENABLED", true
                )),
                requestedBy);

        // Return a stub user backed by a transient UserEntity
        UserEntity stub = new UserEntity();
        stub.setId(generatedId);
        stub.setUsername(username.toLowerCase());
        stub.setRealmId(realm.getId());
        stub.setCreatedTimestamp(System.currentTimeMillis());
        stub.setEmailVerified(false);
        stub.setEnabled(true);
        return new IgaUserAdapter(igaSession, realm, em, stub);
    }

    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        UserModel base = super.getUserById(realm, id);
        if (base == null) return null;
        if (base instanceof org.keycloak.models.jpa.UserAdapter) {
            UserEntity entity = ((org.keycloak.models.jpa.UserAdapter) base).getEntity();
            return new IgaUserAdapter(igaSession, realm, em, entity);
        }
        return base;
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        UserModel base = super.getUserByUsername(realm, username);
        if (base == null) return null;
        if (base instanceof org.keycloak.models.jpa.UserAdapter) {
            UserEntity entity = ((org.keycloak.models.jpa.UserAdapter) base).getEntity();
            return new IgaUserAdapter(igaSession, realm, em, entity);
        }
        return base;
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        UserModel base = super.getUserByEmail(realm, email);
        if (base == null) return null;
        if (base instanceof org.keycloak.models.jpa.UserAdapter) {
            UserEntity entity = ((org.keycloak.models.jpa.UserAdapter) base).getEntity();
            return new IgaUserAdapter(igaSession, realm, em, entity);
        }
        return base;
    }

    private String getCurrentUserId() {
        try {
            var auth = igaSession.getContext().getAuthenticationSession();
            if (auth != null && auth.getAuthenticatedUser() != null) {
                return auth.getAuthenticatedUser().getId();
            }
        } catch (Exception ignored) {
        }
        return null;
    }
}
