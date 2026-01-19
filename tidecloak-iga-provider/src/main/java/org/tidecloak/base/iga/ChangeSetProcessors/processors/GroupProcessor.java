package org.tidecloak.base.iga.ChangeSetProcessors.processors;

import jakarta.persistence.EntityManager;
import org.keycloak.models.*;
import org.keycloak.representations.AccessToken;
import org.keycloak.models.utils.RoleUtils;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessor;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.base.iga.ChangeSetProcessors.utils.UserContextUtils;
import org.tidecloak.base.iga.interfaces.TideUserAdapter;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.drafting.TideGroupDraftEntity;
import org.tidecloak.shared.enums.ActionType;

import java.util.HashMap;
import java.util.Set;
import java.util.stream.Collectors;

import static org.tidecloak.base.iga.ChangeSetProcessors.utils.ChangeRequestUtils.getChangeSetRequestFromEntity;

public class GroupProcessor implements ChangeSetProcessor<TideGroupDraftEntity> {

    @Override
    public AccessToken transformUserContext(AccessToken token,
                                            KeycloakSession session,
                                            TideGroupDraftEntity entity,
                                            UserModel user,
                                            ClientModel client) {
        RealmModel realm = session.getContext().getRealm();

        // init token parts
        if (token.getRealmAccess() == null) token.setRealmAccess(new AccessToken.Access());
        if (token.getResourceAccess() == null) token.setResourceAccess(new HashMap<>());

        ChangeSetRequest change = getChangeSetRequestFromEntity(session, entity);

        // Recompute effective roles for the user (includes group mappings)
        UserContextUtils u = new UserContextUtils();
        Set<RoleModel> activeRoles = u.getDeepUserRoleMappings(user, session, realm, org.tidecloak.shared.enums.DraftStatus.ACTIVE);

        // If this is a DELETE of this group, try to remove roles contributed by this group from the preview.
        if (change.getActionType() == ActionType.DELETE && entity.getId() != null) {
            GroupModel grp = realm.getGroupById(entity.getId());
            if (grp != null) {
                Set<RoleModel> grpRoles = RoleUtils.expandCompositeRolesStream(grp.getRoleMappingsStream())
                        .collect(Collectors.toSet());
                activeRoles.removeAll(grpRoles);
            }
        }

        // Derive in-scope roles for client (respecting FSA and client scopes via existing util)
        Set<RoleModel> allowed = UserContextUtils.getAccess(
                activeRoles,
                client,
                client.getClientScopes(true).values().stream(),
                client.isFullScopeAllowed()
        );

        // Apply to token
        token.setRealmAccess(null);
        token.setResourceAccess(new HashMap<>());
        allowed.forEach(r -> UserContextUtils.addRoleToAccessToken(token, r));
        u.normalizeAccessToken(token, client.isFullScopeAllowed());

        return token;
    }

    @Override
    public void handleCreateRequest(KeycloakSession session, TideGroupDraftEntity entity, EntityManager em, Runnable callback) throws Exception {

    }

    @Override
    public void handleDeleteRequest(KeycloakSession session, TideGroupDraftEntity entity, EntityManager em, Runnable callback) throws Exception {

    }

    @Override
    public void updateAffectedUserContextDrafts(KeycloakSession session, AccessProofDetailEntity userContextDraft, Set<RoleModel> uniqRoles, ClientModel client, TideUserAdapter user, EntityManager em) throws Exception {

    }

    @Override
    public RoleModel getRoleRequestFromEntity(KeycloakSession session, RealmModel realm, TideGroupDraftEntity entity) {
        return null;
    }
}
