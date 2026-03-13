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
import org.tidecloak.base.iga.ChangeSetProcessors.utils.TideEntityUtils;
import org.tidecloak.base.iga.ChangeSetProcessors.utils.UserContextUtils;
import org.tidecloak.base.iga.interfaces.TideClientAdapter;
import org.tidecloak.base.iga.interfaces.TideUserAdapter;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.drafting.TideUserGroupMembershipEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;

import java.util.*;
import java.util.stream.Collectors;

import org.keycloak.models.cache.CacheRealmProvider;
import org.keycloak.models.cache.UserCache;

import static org.tidecloak.base.iga.ChangeSetProcessors.utils.ChangeRequestUtils.getChangeSetRequestFromEntity;

public class UserGroupMembershipProcessor implements ChangeSetProcessor<TideUserGroupMembershipEntity> {

    protected static final Logger logger = Logger.getLogger(UserGroupMembershipProcessor.class);

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
        Set<RoleModel> effective = u.getDeepUserRoleMappings(user, session, realm, DraftStatus.ACTIVE);

        GroupModel group = realm.getGroupById(entity.getGroupId());
        if (group != null) {
            // Collect roles from this group AND all parent groups (group hierarchy inheritance)
            Set<RoleModel> groupRoles = new HashSet<>();
            collectGroupRolesWithParents(group, groupRoles);
            groupRoles = RoleUtils.expandCompositeRolesStream(groupRoles.stream())
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
    public void cancel(KeycloakSession session, TideUserGroupMembershipEntity entity, EntityManager em, ActionType actionType) {
        // Remove access proof drafts
        List<AccessProofDetailEntity> accessProofDetailEntities = UserContextUtils.getUserContextDrafts(em, entity.getId());
        accessProofDetailEntities.forEach(em::remove);

        // Remove the draft entity itself
        em.remove(entity);
        em.flush();

        // Remove the changeset request entity
        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class,
                new ChangesetRequestEntity.Key(entity.getId(), ChangeSetType.USER_GROUP_MEMBERSHIP));
        if (changesetRequestEntity != null) {
            em.remove(changesetRequestEntity);
            em.flush();
        }
    }

    @Override
    public void commit(KeycloakSession session, ChangeSetRequest change, TideUserGroupMembershipEntity entity,
                       EntityManager em, Runnable commitCallback) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        logger.infof("USER_GROUP_MEMBERSHIP commit called. changeSetId=%s, actionType=%s, entityId=%s",
                change.getChangeSetId(), change.getActionType(), entity.getId());

        Runnable callback = () -> {
            logger.infof("USER_GROUP_MEMBERSHIP commit callback executing for changeSetId=%s", change.getChangeSetId());
            List<TideUserGroupMembershipEntity> entities = em.createNamedQuery("GetUserGroupMembershipDraftEntityByRequestId", TideUserGroupMembershipEntity.class)
                    .setParameter("requestId", change.getChangeSetId()).getResultList();
            logger.infof("USER_GROUP_MEMBERSHIP commit callback found %d entities for changeSetId=%s", entities.size(), change.getChangeSetId());
            commitUserGroupMembershipChangeRequest(session, realm, entities, change);
        };

        ChangeSetProcessor.super.commit(session, change, entity, em, callback);
    }

    private void commitUserGroupMembershipChangeRequest(KeycloakSession session, RealmModel realm,
                                                         List<TideUserGroupMembershipEntity> entities, ChangeSetRequest change) {
        EntityManager em = session.getProvider(org.keycloak.connections.jpa.JpaConnectionProvider.class).getEntityManager();
        entities.forEach(entity -> {
            logger.infof("Processing entity id=%s, currentDraftStatus=%s, groupId=%s, userId=%s",
                    entity.getId(), entity.getDraftStatus(), entity.getGroupId(),
                    entity.getUser() != null ? entity.getUser().getId() : "null");

            GroupModel group = realm.getGroupById(entity.getGroupId());
            if (entity.getUser() == null || group == null) {
                logger.warnf("USER_GROUP_MEMBERSHIP commit skipping entity %s: user=%s, group=%s",
                        entity.getId(), entity.getUser(), group);
                return;
            }

            if (entity.getDraftStatus().equals(DraftStatus.ACTIVE)) {
                logger.infof("Entity %s already ACTIVE, skipping", entity.getId());
                return;
            }
            entity.setDraftStatus(DraftStatus.ACTIVE);
            logger.infof("Set entity %s draftStatus to ACTIVE", entity.getId());

            // Construct TideUserAdapter directly to bypass cache wrapper and ensure
            // applyJoinGroup/applyLeaveGroup are called (not joinGroup which creates a new draft)
            TideUserAdapter tideUser = TideEntityUtils.toTideUserAdapter(entity.getUser(), session, realm);

            if (change.getActionType() == ActionType.CREATE) {
                logger.infof("Applying joinGroup for user=%s, group=%s", tideUser.getId(), group.getId());
                tideUser.applyJoinGroup(group);
            } else if (change.getActionType() == ActionType.DELETE) {
                logger.infof("Applying leaveGroup for user=%s, group=%s", tideUser.getId(), group.getId());
                tideUser.applyLeaveGroup(group);
            }
            em.flush();
            logger.infof("Entity %s committed and flushed. New draftStatus=%s", entity.getId(), entity.getDraftStatus());
        });

        // Evict caches so subsequent requests see the committed changes
        CacheRealmProvider cacheRealmProvider = session.getProvider(CacheRealmProvider.class);
        if (cacheRealmProvider != null) cacheRealmProvider.clear();
        UserCache userCache = session.getProvider(UserCache.class);
        if (userCache != null) userCache.clear();
    }

    @Override
    public void request(KeycloakSession session, TideUserGroupMembershipEntity entity, EntityManager em,
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
            throw new RuntimeException("Failed to process USER_GROUP_MEMBERSHIP request", e);
        }
    }

    @Override
    public void handleCreateRequest(KeycloakSession session, TideUserGroupMembershipEntity entity, EntityManager em, Runnable callback) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        String changeSetId = KeycloakModelUtils.generateId();
        entity.setChangeRequestId(changeSetId);

        UserModel user = session.users().getUserById(realm, entity.getUser().getId());
        GroupModel group = realm.getGroupById(entity.getGroupId());
        if (user == null || group == null) {
            throw new IllegalArgumentException("User or group not found");
        }

        // Get all full-scope clients
        List<ClientModel> clientList = session.clients().getClientsStream(realm)
                .map(client -> new TideClientAdapter(realm, em, session, em.find(ClientEntity.class, client.getId())))
                .filter(TideClientAdapter::isFullScopeAllowed)
                .collect(Collectors.toList());

        clientList.removeIf(c -> c.getClientId().equalsIgnoreCase(org.keycloak.models.Constants.BROKER_SERVICE_CLIENT_ID));

        // Also add clients for group's client roles (including parent groups)
        addClientRolesFromGroupHierarchy(group, realm, clientList);

        for (ClientModel client : clientList) {
            ChangeSetProcessor.super.generateAndSaveTransformedUserContextDraft(
                    session, em, realm, client, user,
                    new ChangeRequestKey(entity.getId(), changeSetId),
                    ChangeSetType.USER_GROUP_MEMBERSHIP, entity);
        }

        em.flush();
    }

    @Override
    public void handleDeleteRequest(KeycloakSession session, TideUserGroupMembershipEntity entity, EntityManager em, Runnable callback) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        String changeSetId = KeycloakModelUtils.generateId();
        entity.setChangeRequestId(changeSetId);
        entity.setAction(ActionType.DELETE);

        UserModel user = session.users().getUserById(realm, entity.getUser().getId());
        GroupModel group = realm.getGroupById(entity.getGroupId());
        if (user == null || group == null) {
            throw new IllegalArgumentException("User or group not found");
        }

        List<ClientModel> clientList = session.clients().getClientsStream(realm)
                .map(client -> new TideClientAdapter(realm, em, session, em.find(ClientEntity.class, client.getId())))
                .filter(TideClientAdapter::isFullScopeAllowed)
                .collect(Collectors.toList());

        clientList.removeIf(c -> c.getClientId().equalsIgnoreCase(org.keycloak.models.Constants.BROKER_SERVICE_CLIENT_ID));

        // Also add clients for group's client roles (including parent groups)
        addClientRolesFromGroupHierarchy(group, realm, clientList);

        for (ClientModel client : clientList) {
            ChangeSetProcessor.super.generateAndSaveTransformedUserContextDraft(
                    session, em, realm, client, user,
                    new ChangeRequestKey(entity.getId(), changeSetId),
                    ChangeSetType.USER_GROUP_MEMBERSHIP, entity);
        }

        em.flush();
    }

    @Override
    public void updateAffectedUserContextDrafts(KeycloakSession session, AccessProofDetailEntity userContextDraft,
                                                 Set<RoleModel> uniqRoles, ClientModel client, TideUserAdapter user,
                                                 EntityManager em) throws Exception {
    }

    /**
     * Recursively adds client models for any client roles found in the group and its parents.
     */
    private void addClientRolesFromGroupHierarchy(GroupModel group, RealmModel realm, List<ClientModel> clientList) {
        group.getRoleMappingsStream().forEach(role -> {
            if (role.isClientRole()) {
                ClientModel roleClient = realm.getClientById(role.getContainerId());
                if (roleClient != null && !clientList.contains(roleClient)) {
                    clientList.add(roleClient);
                }
            }
        });
        if (group.getParentId() != null) {
            addClientRolesFromGroupHierarchy(group.getParent(), realm, clientList);
        }
    }

    /**
     * Recursively collects roles from a group and all its parent groups.
     * In Keycloak, a child group inherits roles from its parent groups.
     */
    private void collectGroupRolesWithParents(GroupModel group, Set<RoleModel> roles) {
        roles.addAll(group.getRoleMappingsStream().collect(Collectors.toSet()));
        if (group.getParentId() != null) {
            collectGroupRolesWithParents(group.getParent(), roles);
        }
    }

    @Override
    public RoleModel getRoleRequestFromEntity(KeycloakSession session, RealmModel realm, TideUserGroupMembershipEntity entity) {
        return null;
    }
}
