package org.tidecloak.iga.providers;

import org.keycloak.connections.jpa.JpaConnectionProvider;
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
        Object replay = igaSession.getAttribute("IGA_REPLAY_ACTIVE");
        if (service.isIgaEnabled(realm) && !"true".equals(replay)) {
            String userId = KeycloakModelUtils.generateId();
            // Read the captured UserRepresentation off the REQUEST session
            // BEFORE entering the separate-transaction lambda (the new session
            // does not carry the JAX-RS filter's attribute). The filter stashed
            // the full POST {realm}/users body so replay can rebuild enabled,
            // email, names, attributes, required actions, credentials, role
            // mappings, groups, service-account link — not just id+username.
            String repJson = org.tidecloak.iga.rest.IgaRepresentationCaptureFilter
                    .pendingRepJson(igaSession,
                            org.tidecloak.iga.rest.IgaRepresentationCaptureFilter.TYPE_USER);
            String[] crIdHolder = new String[1];
            KeycloakModelUtils.runJobInTransaction(igaSession.getKeycloakSessionFactory(), newSession -> {
                RealmModel newRealm = newSession.realms().getRealm(realm.getId());
                EntityManager newEm = newSession.getProvider(JpaConnectionProvider.class).getEntityManager();
                IgaChangeRequestService newService = new IgaChangeRequestService(newEm, newSession);
                Map<String, Object> row = new java.util.LinkedHashMap<>();
                row.put("ID", userId);
                row.put("USERNAME", username.toLowerCase());
                row.put("REALM_ID", realm.getId());
                if (repJson != null) {
                    row.put("REP_JSON", repJson);
                }
                crIdHolder[0] = newService.create(newRealm, "USER", userId, "CREATE_USER",
                        List.of(row),
                        getCurrentUserId()).getId();
            });
            throw new org.tidecloak.iga.providers.IgaPendingApprovalException(crIdHolder[0], "USER", "CREATE_USER");
        }
        UserModel base = super.addUser(realm, username);
        if (base == null) return null;
        if (base instanceof org.keycloak.models.jpa.UserAdapter) {
            UserEntity entity = ((org.keycloak.models.jpa.UserAdapter) base).getEntity();
            return new IgaUserAdapter(igaSession, realm, em, entity);
        }
        return base;
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
