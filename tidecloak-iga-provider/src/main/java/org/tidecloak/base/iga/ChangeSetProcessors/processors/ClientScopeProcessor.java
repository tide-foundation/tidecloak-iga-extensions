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
import org.tidecloak.jpa.entities.drafting.TideClientScopeMappingDraftEntity;

import java.util.HashMap;
import java.util.Set;
import java.util.stream.Collectors;

import static org.tidecloak.base.iga.ChangeSetProcessors.utils.ChangeRequestUtils.getChangeSetRequestFromEntity;

public class ClientScopeProcessor implements ChangeSetProcessor<TideClientScopeMappingDraftEntity> {

    @Override
    public AccessToken transformUserContext(AccessToken token,
                                            KeycloakSession session,
                                            TideClientScopeMappingDraftEntity entity,
                                            UserModel user,
                                            ClientModel client) {
        RealmModel realm = session.getContext().getRealm();
        if (token.getRealmAccess() == null) token.setRealmAccess(new AccessToken.Access());
        if (token.getResourceAccess() == null) token.setResourceAccess(new HashMap<>());

        ChangeSetRequest change = getChangeSetRequestFromEntity(session, entity);

        UserContextUtils u = new UserContextUtils();
        Set<RoleModel> effective = u.getDeepUserRoleMappings(user, session, realm, org.tidecloak.shared.enums.DraftStatus.ACTIVE);

        ClientModel targetClient = realm.getClientById(entity.getClientId());
        ClientScopeModel scope = realm.getClientScopeById(entity.getClientScopeId());
        if (targetClient != null && scope != null) {
            Set<RoleModel> scopeRoles = RoleUtils.expandCompositeRolesStream(scope.getScopeMappingsStream())
                    .collect(Collectors.toSet());

            if (change.getActionType() == org.tidecloak.shared.enums.ActionType.CREATE) {
                effective.addAll(scopeRoles);
            } else if (change.getActionType() == org.tidecloak.shared.enums.ActionType.DELETE) {
                effective.removeAll(scopeRoles);
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
    public void handleCreateRequest(KeycloakSession session, TideClientScopeMappingDraftEntity entity, EntityManager em, Runnable callback) throws Exception {

    }

    @Override
    public void handleDeleteRequest(KeycloakSession session, TideClientScopeMappingDraftEntity entity, EntityManager em, Runnable callback) throws Exception {

    }

    @Override
    public void updateAffectedUserContextDrafts(KeycloakSession session, AccessProofDetailEntity userContextDraft, Set<RoleModel> uniqRoles, ClientModel client, TideUserAdapter user, EntityManager em) throws Exception {

    }

    @Override
    public RoleModel getRoleRequestFromEntity(KeycloakSession session, RealmModel realm, TideClientScopeMappingDraftEntity entity) {
        return null;
    }
}
