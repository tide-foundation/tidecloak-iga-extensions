package org.tidecloak.base.iga.ChangeSetCommitter;

import jakarta.persistence.EntityManager;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.cache.UserCache;          // <-- needed in newer KC
import org.keycloak.services.resources.admin.AdminAuth;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;

/**
 * Minimal committer now that ChangeSetProcessors are gone.
 *
 * NOTE:
 *  - The signing flow now writes signatures directly to AccessProofDetailEntity before this committer runs.
 *  - Commit here is reduced to cache-busting and returning 200 so the pipeline continues.
 *  - If/when we add per-type DB transitions, do them here based on changeSet.getType().
 */
public class BasicIGACommitter implements ChangeSetCommitter {

    @Override
    public Response commit(ChangeSetRequest changeSet,
                           EntityManager em,
                           KeycloakSession session,
                           RealmModel realm,
                           Object draftEntity,
                           AdminAuth auth) throws Exception {

        // If you add per-type state transitions, switch on changeSet.getType() here.

        // Clear user cache so fresh user contexts are rebuilt next token/session hit.
        UserCache userCache = session.getProvider(UserCache.class);
        if (userCache != null) {
            userCache.clear();
        }

        return Response.ok("Change set approved and committed").build();
    }
}
