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
import org.tidecloak.jpa.entities.drafting.TideGroupRoleMappingEntity;
import org.tidecloak.shared.enums.ActionType;

import java.util.HashMap;
import java.util.Set;
import java.util.stream.Collectors;

import static org.tidecloak.base.iga.ChangeSetProcessors.utils.ChangeRequestUtils.getChangeSetRequestFromEntity;

public class GroupRoleProcessor implements ChangeSetProcessor<TideGroupRoleMappingEntity> {

    @Override
    public AccessToken transformUserContext(AccessToken token,
                                            KeycloakSession session,
                                            TideGroupRoleMappingEntity entity,
                                            UserModel user,
                                            ClientModel client) {
        RealmModel realm = session.getContext().getRealm();
        if (token.getRealmAccess() == null) token.setRealmAccess(new AccessToken.Access());
        if (token.getResourceAccess() == null) token.setResourceAccess(new HashMap<>());

        ChangeSetRequest change = getChangeSetRequestFromEntity(session, entity);

        UserContextUtils u = new UserContextUtils();
        Set<RoleModel> effective = u.getDeepUserRoleMappings(user, session, realm, org.tidecloak.shared.enums.DraftStatus.ACTIVE);

        GroupModel group = realm.getGroupById(entity.getGroup().getId());
        RoleModel mappedRole = realm.getRoleById(entity.getRoleId());
        if (group != null && mappedRole != null) {
            // Build the group's current role set and apply the delta
            Set<RoleModel> groupRoles = RoleUtils.expandCompositeRolesStream(group.getRoleMappingsStream())
                    .collect(Collectors.toSet());
            if (change.getActionType() == ActionType.CREATE) {
                groupRoles.add(mappedRole);
                effective.add(mappedRole);
            } else if (change.getActionType() == ActionType.DELETE) {
                groupRoles.remove(mappedRole);
                effective.remove(mappedRole);
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
    public void handleCreateRequest(KeycloakSession session, TideGroupRoleMappingEntity entity, EntityManager em, Runnable callback) throws Exception {

    }

    @Override
    public void handleDeleteRequest(KeycloakSession session, TideGroupRoleMappingEntity entity, EntityManager em, Runnable callback) throws Exception {

    }

    @Override
    public void updateAffectedUserContextDrafts(KeycloakSession session, AccessProofDetailEntity userContextDraft, Set<RoleModel> uniqRoles, ClientModel client, TideUserAdapter user, EntityManager em) throws Exception {

    }

    @Override
    public RoleModel getRoleRequestFromEntity(KeycloakSession session, RealmModel realm, TideGroupRoleMappingEntity entity) {
        return null;
    }
}
