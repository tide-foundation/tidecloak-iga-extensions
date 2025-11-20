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
import org.tidecloak.jpa.entities.drafting.TideUserGroupMembershipEntity;
import org.tidecloak.shared.enums.ActionType;

import java.util.HashMap;
import java.util.Set;
import java.util.stream.Collectors;

import static org.tidecloak.base.iga.ChangeSetProcessors.utils.ChangeRequestUtils.getChangeSetRequestFromEntity;

public class UserGroupMembershipProcessor implements ChangeSetProcessor<TideUserGroupMembershipEntity> {

    @Override
    public AccessToken transformUserContext(AccessToken token,
                                            KeycloakSession session,
                                            TideUserGroupMembershipEntity entity,
                                            UserModel user,
                                            ClientModel client) {
        RealmModel realm = session.getContext().getRealm();
        if (token.getRealmAccess() == null) token.setRealmAccess(new AccessToken.Access());
        if (token.getResourceAccess() == null) token.setResourceAccess(new HashMap<>());

        ChangeSetRequest change = getChangeSetRequestFromEntity(session, entity);

        UserContextUtils u = new UserContextUtils();
        Set<RoleModel> effective = u.getDeepUserRoleMappings(user, session, realm, org.tidecloak.shared.enums.DraftStatus.ACTIVE);

        GroupModel group = realm.getGroupById(entity.getGroupId());
        if (group != null) {
            Set<RoleModel> groupRoles = RoleUtils.expandCompositeRolesStream(group.getRoleMappingsStream())
                    .collect(Collectors.toSet());
            if (change.getActionType() == ActionType.CREATE) {
                effective.addAll(groupRoles);
            } else if (change.getActionType() == ActionType.DELETE) {
                effective.removeAll(groupRoles);
            }
        }

        Set<RoleModel> allowed = UserContextUtils.getAccess(
                effective,
                client,
                client.getClientScopes(true).values().stream(),
                client.isFullScopeAllowed()
        );

        token.setRealmAccess(null);
        token.setResourceAccess(new HashMap<>());
        allowed.forEach(r -> UserContextUtils.addRoleToAccessToken(token, r));
        u.normalizeAccessToken(token, client.isFullScopeAllowed());
        return token;
    }

    @Override
    public void handleCreateRequest(KeycloakSession session, TideUserGroupMembershipEntity entity, EntityManager em, Runnable callback) throws Exception {

    }

    @Override
    public void handleDeleteRequest(KeycloakSession session, TideUserGroupMembershipEntity entity, EntityManager em, Runnable callback) throws Exception {

    }

    @Override
    public void updateAffectedUserContextDrafts(KeycloakSession session, AccessProofDetailEntity userContextDraft, Set<RoleModel> uniqRoles, ClientModel client, TideUserAdapter user, EntityManager em) throws Exception {

    }

    @Override
    public RoleModel getRoleRequestFromEntity(KeycloakSession session, RealmModel realm, TideUserGroupMembershipEntity entity) {
        return null;
    }
}
