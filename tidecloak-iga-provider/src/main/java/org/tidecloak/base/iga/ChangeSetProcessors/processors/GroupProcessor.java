package org.tidecloak.base.iga.ChangeSetProcessors.processors;

import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.representations.AccessToken;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessor;
import org.tidecloak.jpa.entities.ChangeRequestKey;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.base.iga.ChangeSetProcessors.utils.GroupUtils;
import org.tidecloak.base.iga.ChangeSetProcessors.utils.UserContextUtils;
import org.tidecloak.base.iga.interfaces.TideClientAdapter;
import org.tidecloak.base.iga.interfaces.TideUserAdapter;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.drafting.TideGroupDraftEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;

import java.util.*;
import java.util.stream.Collectors;

import static org.tidecloak.base.iga.ChangeSetProcessors.utils.ChangeRequestUtils.getChangeSetRequestFromEntity;

public class GroupProcessor implements ChangeSetProcessor<TideGroupDraftEntity> {

    protected static final Logger logger = Logger.getLogger(GroupProcessor.class);

    @Override
    public AccessToken transformUserContext(AccessToken token,
                                            KeycloakSession session,
                                            TideGroupDraftEntity entity,
                                            UserModel user,
                                            ClientModel client) {
        RealmModel realm = session.getContext().getRealm();

        if (token.getRealmAccess() == null) token.setRealmAccess(new AccessToken.Access());
        if (token.getResourceAccess() == null) token.setResourceAccess(new HashMap<>());

        ChangeSetRequest change = getChangeSetRequestFromEntity(session, entity);

        UserContextUtils u = new UserContextUtils();
        Set<RoleModel> activeRoles = u.getDeepUserRoleMappings(user, session, realm, DraftStatus.ACTIVE);

        // If deleting this group, remove roles contributed by it
        if (change.getActionType() == ActionType.DELETE && entity.getId() != null) {
            GroupModel grp = realm.getGroupById(entity.getId());
            if (grp != null) {
                Set<RoleModel> grpRoles = RoleUtils.expandCompositeRolesStream(grp.getRoleMappingsStream())
                        .collect(Collectors.toSet());
                activeRoles.removeAll(grpRoles);
            }
        }

        Set<RoleModel> allowed = UserContextUtils.getAccess(
                activeRoles,
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
    public void request(KeycloakSession session, TideGroupDraftEntity entity, EntityManager em,
                        ActionType action, Runnable callback, ChangeSetType changeSetType) {
        try {
            switch (action) {
                case CREATE:
                    handleCreateRequest(session, entity, em, callback);
                    break;
                case DELETE:
                    handleDeleteRequest(session, entity, em, callback);
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported action: " + action);
            }
            ChangeSetProcessor.super.createChangeRequestEntity(em, entity.getChangeRequestId(), changeSetType);
        } catch (Exception e) {
            throw new RuntimeException("Failed to process GROUP request", e);
        }
    }

    @Override
    public void handleCreateRequest(KeycloakSession session, TideGroupDraftEntity entity, EntityManager em, Runnable callback) throws Exception {
        // Group creation doesn't affect user contexts until roles/members are assigned
        String changeSetId = KeycloakModelUtils.generateId();
        entity.setChangeRequestId(changeSetId);
        em.flush();
    }

    @Override
    public void handleDeleteRequest(KeycloakSession session, TideGroupDraftEntity entity, EntityManager em, Runnable callback) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        String changeSetId = KeycloakModelUtils.generateId();
        entity.setChangeRequestId(changeSetId);
        entity.setAction(ActionType.DELETE);

        GroupModel group = realm.getGroupById(entity.getId());
        if (group == null) {
            em.flush();
            return;
        }

        // All members of this group and its subgroups will have their tokens affected
        List<UserModel> groupMembers = GroupUtils.getAllGroupMembersRecursive(session, realm, group);

        if (groupMembers.isEmpty()) {
            em.flush();
            return;
        }

        // Get all full-scope clients
        List<ClientModel> clientList = session.clients().getClientsStream(realm)
                .map(client -> new TideClientAdapter(realm, em, session, em.find(ClientEntity.class, client.getId())))
                .filter(TideClientAdapter::isFullScopeAllowed)
                .collect(Collectors.toList());

        clientList.removeIf(c -> c.getClientId().equalsIgnoreCase(org.keycloak.models.Constants.BROKER_SERVICE_CLIENT_ID));

        // Also add clients for group's client roles
        group.getRoleMappingsStream().forEach(role -> {
            if (role.isClientRole()) {
                ClientModel roleClient = realm.getClientById(role.getContainerId());
                if (roleClient != null && !clientList.contains(roleClient)) {
                    clientList.add(roleClient);
                }
            }
        });

        for (ClientModel client : clientList) {
            for (UserModel user : groupMembers) {
                ChangeSetProcessor.super.generateAndSaveTransformedUserContextDraft(
                        session, em, realm, client, user,
                        new ChangeRequestKey(entity.getId(), changeSetId),
                        ChangeSetType.GROUP, entity);
            }
        }

        em.flush();
    }

    @Override
    public void updateAffectedUserContextDrafts(KeycloakSession session, AccessProofDetailEntity userContextDraft,
                                                 Set<RoleModel> uniqRoles, ClientModel client, TideUserAdapter user,
                                                 EntityManager em) throws Exception {
    }

    @Override
    public RoleModel getRoleRequestFromEntity(KeycloakSession session, RealmModel realm, TideGroupDraftEntity entity) {
        return null;
    }
}
