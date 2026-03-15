package org.tidecloak.base.iga.ChangeSetProcessors.processors;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.models.*;
import org.keycloak.models.cache.CacheRealmProvider;
import org.keycloak.models.cache.UserCache;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.representations.AccessToken;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessor;
import org.tidecloak.base.iga.ChangeSetProcessors.keys.UserClientKey;
import org.tidecloak.jpa.entities.ChangeRequestKey;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.base.iga.ChangeSetProcessors.utils.GroupUtils;
import org.tidecloak.base.iga.ChangeSetProcessors.utils.TideEntityUtils;
import org.tidecloak.base.iga.ChangeSetProcessors.utils.UserContextUtils;
import org.tidecloak.base.iga.interfaces.TideClientAdapter;
import org.tidecloak.base.iga.interfaces.TideRealmProvider;
import org.tidecloak.base.iga.interfaces.TideUserAdapter;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.drafting.TideGroupMoveDraftEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;

import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.tidecloak.base.iga.ChangeSetProcessors.utils.ChangeRequestUtils.getChangeSetRequestFromEntity;

public class GroupMoveProcessor implements ChangeSetProcessor<TideGroupMoveDraftEntity> {

    protected static final Logger logger = Logger.getLogger(GroupMoveProcessor.class);

    @Override
    public AccessToken transformUserContext(AccessToken token,
                                            KeycloakSession session,
                                            TideGroupMoveDraftEntity entity,
                                            UserModel user,
                                            ClientModel client) {
        RealmModel realm = session.getContext().getRealm();
        if (token.getRealmAccess() == null) token.setRealmAccess(new AccessToken.Access());
        if (token.getResourceAccess() == null) token.setResourceAccess(new HashMap<>());

        UserContextUtils u = new UserContextUtils();
        Set<RoleModel> effective = u.getDeepUserRoleMappings(user, session, realm, DraftStatus.ACTIVE);

        // Compute roles inherited from old parent hierarchy
        Set<RoleModel> oldParentRoles = new HashSet<>();
        if (entity.getOldParentId() != null) {
            GroupModel oldParent = realm.getGroupById(entity.getOldParentId());
            if (oldParent != null) {
                collectGroupRolesWithParents(oldParent, oldParentRoles);
                oldParentRoles = RoleUtils.expandCompositeRolesStream(oldParentRoles.stream())
                        .collect(Collectors.toSet());
            }
        }

        // Compute roles inherited from new parent hierarchy
        Set<RoleModel> newParentRoles = new HashSet<>();
        if (entity.getNewParentId() != null) {
            GroupModel newParent = realm.getGroupById(entity.getNewParentId());
            if (newParent != null) {
                collectGroupRolesWithParents(newParent, newParentRoles);
                newParentRoles = RoleUtils.expandCompositeRolesStream(newParentRoles.stream())
                        .collect(Collectors.toSet());
            }
        }

        // Apply the diff: remove old inherited roles, add new inherited roles
        Set<RoleModel> rolesToRemove = new HashSet<>(oldParentRoles);
        rolesToRemove.removeAll(newParentRoles);
        Set<RoleModel> rolesToAdd = new HashSet<>(newParentRoles);
        rolesToAdd.removeAll(oldParentRoles);

        effective.removeAll(rolesToRemove);
        effective.addAll(rolesToAdd);

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
    public void cancel(KeycloakSession session, TideGroupMoveDraftEntity entity, EntityManager em, ActionType actionType) {
        // Remove access proof drafts
        List<AccessProofDetailEntity> accessProofDetailEntities = UserContextUtils.getUserContextDrafts(em, entity.getId());
        accessProofDetailEntities.forEach(em::remove);

        // Remove the draft entity itself
        em.remove(entity);
        em.flush();

        // Remove the changeset request entity
        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class,
                new ChangesetRequestEntity.Key(entity.getId(), ChangeSetType.GROUP_MOVE));
        if (changesetRequestEntity != null) {
            em.remove(changesetRequestEntity);
            em.flush();
        }
    }

    @Override
    public void commit(KeycloakSession session, ChangeSetRequest change, TideGroupMoveDraftEntity entity,
                       EntityManager em, Runnable commitCallback) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        logger.infof("GROUP_MOVE commit called. changeSetId=%s, entityId=%s",
                change.getChangeSetId(), entity.getId());

        Runnable callback = () -> {
            List<TideGroupMoveDraftEntity> entities = em.createNamedQuery("GetGroupMoveDraftEntityByRequestId", TideGroupMoveDraftEntity.class)
                    .setParameter("requestId", change.getChangeSetId()).getResultList();
            commitGroupMoveChangeRequest(session, realm, entities);
        };

        ChangeSetProcessor.super.commit(session, change, entity, em, callback);
    }

    private void commitGroupMoveChangeRequest(KeycloakSession session, RealmModel realm, List<TideGroupMoveDraftEntity> entities) {
        EntityManager em = session.getProvider(org.keycloak.connections.jpa.JpaConnectionProvider.class).getEntityManager();
        entities.forEach(entity -> {
            if (entity.getDraftStatus().equals(DraftStatus.ACTIVE)) {
                return;
            }
            entity.setDraftStatus(DraftStatus.ACTIVE);

            GroupModel group = realm.getGroupById(entity.getGroupId());
            if (group == null) {
                logger.warnf("GROUP_MOVE commit skipping entity %s: group not found", entity.getId());
                return;
            }

            GroupModel newParent = entity.getNewParentId() != null ? realm.getGroupById(entity.getNewParentId()) : null;

            // Apply the move directly via the realm provider's super.moveGroup
            TideRealmProvider realmProvider = (TideRealmProvider) session.getProvider(org.keycloak.models.GroupProvider.class);
            realmProvider.applyMoveGroup(realm, group, newParent);

            em.flush();
        });

        // Evict caches so subsequent requests see the committed changes
        CacheRealmProvider cacheRealmProvider = session.getProvider(CacheRealmProvider.class);
        if (cacheRealmProvider != null) cacheRealmProvider.clear();
        UserCache userCache = session.getProvider(UserCache.class);
        if (userCache != null) userCache.clear();
    }

    @Override
    public void request(KeycloakSession session, TideGroupMoveDraftEntity entity, EntityManager em,
                        ActionType action, Runnable callback, ChangeSetType changeSetType) {
        try {
            handleCreateRequest(session, entity, em, callback);
            if (!DraftStatus.ACTIVE.equals(entity.getDraftStatus())) {
                ChangeSetProcessor.super.createChangeRequestEntity(em, entity.getChangeRequestId(), changeSetType);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to process GROUP_MOVE request", e);
        }
    }

    @Override
    public void handleCreateRequest(KeycloakSession session, TideGroupMoveDraftEntity entity, EntityManager em, Runnable callback) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        String changeSetId = KeycloakModelUtils.generateId();
        entity.setChangeRequestId(changeSetId);

        GroupModel group = realm.getGroupById(entity.getGroupId());
        if (group == null) {
            throw new IllegalArgumentException("Group not found");
        }

        // Find all users in this group and all subgroups recursively
        List<UserModel> groupMembers = GroupUtils.getAllGroupMembersRecursive(session, realm, group);

        if (groupMembers.isEmpty()) {
            // No users affected — immediate commit
            entity.setDraftStatus(DraftStatus.ACTIVE);
            GroupModel newParent = entity.getNewParentId() != null ? realm.getGroupById(entity.getNewParentId()) : null;
            TideRealmProvider realmProvider = (TideRealmProvider) session.getProvider(GroupProvider.class);
            realmProvider.applyMoveGroup(realm, group, newParent);
            em.flush();
            return;
        }

        // Get all full-scope clients + clients for roles in old/new parent hierarchies
        List<ClientModel> clientList = session.clients().getClientsStream(realm)
                .map(client -> new TideClientAdapter(realm, em, session, em.find(ClientEntity.class, client.getId())))
                .filter(TideClientAdapter::isFullScopeAllowed)
                .collect(Collectors.toList());

        clientList.removeIf(c -> c.getClientId().equalsIgnoreCase(org.keycloak.models.Constants.BROKER_SERVICE_CLIENT_ID));

        // Add clients for roles in old and new parent hierarchies
        addClientRolesFromParentHierarchy(entity.getOldParentId(), realm, clientList);
        addClientRolesFromParentHierarchy(entity.getNewParentId(), realm, clientList);

        clientList = clientList.stream().distinct().collect(Collectors.toList());

        for (ClientModel client : clientList) {
            for (UserModel user : groupMembers) {
                ChangeSetProcessor.super.generateAndSaveTransformedUserContextDraft(
                        session, em, realm, client, user,
                        new ChangeRequestKey(entity.getId(), changeSetId),
                        ChangeSetType.GROUP_MOVE, entity);
            }
        }

        em.flush();
    }

    @Override
    public List<ChangesetRequestEntity> combineChangeRequests(
            KeycloakSession session,
            List<TideGroupMoveDraftEntity> entities,
            EntityManager em) throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        RealmModel realm = session.getContext().getRealm();

        Map<UserClientKey, List<AccessProofDetailEntity>> rawMap =
                ChangeSetProcessor.super.groupChangeRequests(entities, em);

        Map<String, Map<String, List<AccessProofDetailEntity>>> byUserClient =
                rawMap.entrySet().stream()
                        .flatMap(e -> e.getValue().stream()
                                .map(proof -> Map.entry(e.getKey(), proof)))
                        .collect(Collectors.groupingBy(
                                e -> e.getKey().getUserId(),
                                Collectors.groupingBy(
                                        e -> e.getKey().getClientId(),
                                        Collectors.mapping(Map.Entry::getValue, Collectors.toList())
                                )));

        List<String> userIds = new ArrayList<>(byUserClient.keySet());
        Map<String, UserEntity> userById = em.createQuery(
                        "SELECT u FROM UserEntity u WHERE u.id IN :ids", UserEntity.class)
                .setParameter("ids", userIds)
                .getResultList().stream()
                .collect(Collectors.toMap(UserEntity::getId, Function.identity()));

        Set<String> clientIds = byUserClient.values().stream()
                .flatMap(m -> m.keySet().stream())
                .collect(Collectors.toSet());
        Map<String, ClientModel> clientById = clientIds.stream()
                .map(cid -> Map.entry(cid, realm.getClientById(cid)))
                .filter(e -> e.getValue() != null)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        List<ChangesetRequestEntity> results = new ArrayList<>();

        for (var userEntry : byUserClient.entrySet()) {
            String userId = userEntry.getKey();
            UserEntity ue = userById.get(userId);
            UserModel um = session.users().getUserById(realm, userId);

            // Short-circuit: if this user has only 1 proof total, no combining needed
            long totalProofs = userEntry.getValue().values().stream()
                    .mapToLong(List::size)
                    .sum();
            if (totalProofs <= 1) {
                userEntry.getValue().values().stream()
                        .flatMap(List::stream)
                        .findFirst()
                        .ifPresent(proof -> {
                            List<ChangesetRequestEntity> existing = em.createNamedQuery(
                                            "getAllChangeRequestsByRecordId", ChangesetRequestEntity.class)
                                    .setParameter("changesetRequestId", proof.getChangeRequestKey().getChangeRequestId())
                                    .getResultList();
                            results.addAll(existing);
                        });
                continue;
            }

            String combinedRequestId = KeycloakModelUtils.generateId();

            List<AccessProofDetailEntity> toRemoveProofs = new ArrayList<>();
            List<ChangesetRequestEntity> toRemoveRequests = new ArrayList<>();

            for (var clientEntry : userEntry.getValue().entrySet()) {
                ClientModel cm = clientById.get(clientEntry.getKey());
                AtomicReference<String> mappingId = new AtomicReference<>();
                if (cm == null) continue;
                String combinedProofDraft = null;

                for (var proof : clientEntry.getValue()) {
                    mappingId.set(proof.getChangeRequestKey().getMappingId());
                    TideGroupMoveDraftEntity draft = (TideGroupMoveDraftEntity) BasicIGAUtils.fetchDraftRecordEntity(em, ChangeSetType.GROUP_MOVE, proof.getChangeRequestKey().getMappingId());
                    if (draft == null) {
                        throw new IllegalStateException("Missing draft for request " + proof.getChangeRequestKey().getMappingId());
                    }
                    draft.setChangeRequestId(combinedRequestId);
                    em.persist(draft);

                    if (combinedProofDraft == null) {
                        combinedProofDraft = proof.getProofDraft();
                    }
                    AccessToken token = objectMapper.readValue(combinedProofDraft, AccessToken.class);
                    combinedProofDraft = combinedTransformedUserContext(session, realm, cm, um, "openId", draft, token);

                    toRemoveProofs.add(proof);
                    toRemoveRequests.addAll(em.createNamedQuery("getAllChangeRequestsByRecordId", ChangesetRequestEntity.class)
                            .setParameter("changesetRequestId", proof.getChangeRequestKey().getChangeRequestId())
                            .getResultList());
                }

                ChangeSetProcessor.super.saveUserContextDraft(session, em, realm, cm, ue, new ChangeRequestKey(mappingId.get(), combinedRequestId), ChangeSetType.GROUP_MOVE, combinedProofDraft);
            }

            toRemoveProofs.forEach(em::remove);
            toRemoveRequests.forEach(em::remove);

            List<ChangesetRequestEntity> created = em.createNamedQuery("getAllChangeRequestsByRecordId", ChangesetRequestEntity.class)
                    .setParameter("changesetRequestId", combinedRequestId)
                    .getResultList();
            results.addAll(created);
        }

        em.flush();
        return results;
    }

    @Override
    public void handleDeleteRequest(KeycloakSession session, TideGroupMoveDraftEntity entity, EntityManager em, Runnable callback) throws Exception {
        throw new UnsupportedOperationException("Delete is not supported for GROUP_MOVE. Use cancel instead.");
    }

    @Override
    public void updateAffectedUserContextDrafts(KeycloakSession session, AccessProofDetailEntity userContextDraft,
                                                 Set<RoleModel> uniqRoles, ClientModel client, TideUserAdapter user,
                                                 EntityManager em) throws Exception {
    }

    @Override
    public RoleModel getRoleRequestFromEntity(KeycloakSession session, RealmModel realm, TideGroupMoveDraftEntity entity) {
        return null;
    }

    /**
     * Recursively collects roles from a group and all its parent groups.
     */
    private void collectGroupRolesWithParents(GroupModel group, Set<RoleModel> roles) {
        roles.addAll(group.getRoleMappingsStream().collect(Collectors.toSet()));
        if (group.getParentId() != null) {
            collectGroupRolesWithParents(group.getParent(), roles);
        }
    }

    /**
     * Adds client models for any client roles found in the parent hierarchy.
     */
    private void addClientRolesFromParentHierarchy(String parentId, RealmModel realm, List<ClientModel> clientList) {
        if (parentId == null) return;
        GroupModel parent = realm.getGroupById(parentId);
        if (parent == null) return;
        addClientRolesFromGroupHierarchy(parent, realm, clientList);
    }

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
}
