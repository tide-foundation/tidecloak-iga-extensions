package org.tidecloak.base.iga.ChangeSetProcessors.processors;

import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.representations.AccessToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessor;
import org.tidecloak.base.iga.ChangeSetProcessors.keys.UserClientKey;
import org.tidecloak.jpa.entities.ChangeRequestKey;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.base.iga.ChangeSetProcessors.utils.ClientUtils;
import org.tidecloak.base.iga.ChangeSetProcessors.utils.GroupUtils;
import org.tidecloak.base.iga.ChangeSetProcessors.utils.TideEntityUtils;
import org.tidecloak.base.iga.ChangeSetProcessors.utils.UserContextUtils;
import org.tidecloak.base.iga.interfaces.TideGroupAdapter;
import org.tidecloak.base.iga.interfaces.TideUserAdapter;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.drafting.TideGroupRoleMappingEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;

import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.keycloak.models.cache.CacheRealmProvider;
import org.keycloak.models.cache.UserCache;

import static org.tidecloak.base.iga.ChangeSetProcessors.utils.ChangeRequestUtils.getChangeSetRequestFromEntity;

public class GroupRoleProcessor implements ChangeSetProcessor<TideGroupRoleMappingEntity> {

    protected static final Logger logger = Logger.getLogger(GroupRoleProcessor.class);

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
        Set<RoleModel> effective = u.getDeepUserRoleMappings(user, session, realm, DraftStatus.ACTIVE);

        GroupModel group = realm.getGroupById(entity.getGroup().getId());
        RoleModel mappedRole = realm.getRoleById(entity.getRoleId());
        if (group != null && mappedRole != null) {
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
    public void cancel(KeycloakSession session, TideGroupRoleMappingEntity entity, EntityManager em, ActionType actionType) {
        RealmModel realm = session.getContext().getRealm();

        // Remove access proof drafts
        List<AccessProofDetailEntity> accessProofDetailEntities = UserContextUtils.getUserContextDrafts(em, entity.getId());
        accessProofDetailEntities.forEach(em::remove);

        // Remove the draft entity itself
        em.remove(entity);
        em.flush();

        // Remove the changeset request entity
        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class,
                new ChangesetRequestEntity.Key(entity.getId(), ChangeSetType.GROUP_ROLE));
        if (changesetRequestEntity != null) {
            em.remove(changesetRequestEntity);
            em.flush();
        }
    }

    @Override
    public void commit(KeycloakSession session, ChangeSetRequest change, TideGroupRoleMappingEntity entity,
                       EntityManager em, Runnable commitCallback) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        logger.infof("GROUP_ROLE commit called. changeSetId=%s, actionType=%s, entityId=%s",
                change.getChangeSetId(), change.getActionType(), entity.getId());

        Runnable callback = () -> {
            logger.infof("GROUP_ROLE commit callback executing for changeSetId=%s", change.getChangeSetId());
            List<TideGroupRoleMappingEntity> entities = em.createNamedQuery("GetGroupRoleDraftEntityByRequestId", TideGroupRoleMappingEntity.class)
                    .setParameter("requestId", change.getChangeSetId()).getResultList();
            logger.infof("GROUP_ROLE commit callback found %d entities for changeSetId=%s", entities.size(), change.getChangeSetId());
            commitGroupRoleChangeRequest(session, realm, entities, change);
        };

        ChangeSetProcessor.super.commit(session, change, entity, em, callback);
    }

    private void commitGroupRoleChangeRequest(KeycloakSession session, RealmModel realm, List<TideGroupRoleMappingEntity> entities, ChangeSetRequest change) {
        EntityManager em = session.getProvider(org.keycloak.connections.jpa.JpaConnectionProvider.class).getEntityManager();
        entities.forEach(entity -> {
            logger.infof("Processing entity id=%s, currentDraftStatus=%s, roleId=%s, groupId=%s",
                    entity.getId(), entity.getDraftStatus(), entity.getRoleId(),
                    entity.getGroup() != null ? entity.getGroup().getId() : "null");

            RoleModel role = realm.getRoleById(entity.getRoleId());
            if (entity.getGroup() == null || role == null) {
                logger.warnf("GROUP_ROLE commit skipping entity %s: group=%s, role=%s",
                        entity.getId(), entity.getGroup(), role);
                return;
            }

            if (entity.getDraftStatus().equals(DraftStatus.ACTIVE)) {
                logger.infof("Entity %s already ACTIVE, skipping", entity.getId());
                return;
            }
            entity.setDraftStatus(DraftStatus.ACTIVE);
            logger.infof("Set entity %s draftStatus to ACTIVE", entity.getId());

            // Construct TideGroupAdapter directly to bypass cache wrapper and ensure
            // applyGrantRole/applyDeleteRoleMapping are called (not grantRole which creates a new draft)
            TideGroupAdapter tideGroup = new TideGroupAdapter(realm, em, entity.getGroup(), session);

            if (change.getActionType() == ActionType.CREATE) {
                logger.infof("Applying grantRole for group=%s, role=%s", tideGroup.getId(), role.getId());
                tideGroup.applyGrantRole(role);
            } else if (change.getActionType() == ActionType.DELETE) {
                logger.infof("Applying deleteRoleMapping for group=%s, role=%s", tideGroup.getId(), role.getId());
                tideGroup.applyDeleteRoleMapping(role);
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
    public void request(KeycloakSession session, TideGroupRoleMappingEntity entity, EntityManager em,
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
            // Skip creating changeset request entity if already immediately committed (no affected users)
            if (!DraftStatus.ACTIVE.equals(entity.getDraftStatus())) {
                ChangeSetProcessor.super.createChangeRequestEntity(em, entity.getChangeRequestId(), changeSetType);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to process GROUP_ROLE request", e);
        }
    }

    @Override
    public List<ChangesetRequestEntity> combineChangeRequests(
            KeycloakSession session,
            List<TideGroupRoleMappingEntity> entities,
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
                    TideGroupRoleMappingEntity draft = (TideGroupRoleMappingEntity) BasicIGAUtils.fetchDraftRecordEntity(em, ChangeSetType.GROUP_ROLE, proof.getChangeRequestKey().getMappingId());
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

                ChangeSetProcessor.super.saveUserContextDraft(session, em, realm, cm, ue, new ChangeRequestKey(mappingId.get(), combinedRequestId), ChangeSetType.GROUP_ROLE, combinedProofDraft);
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
    public void handleCreateRequest(KeycloakSession session, TideGroupRoleMappingEntity entity, EntityManager em, Runnable callback) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        String changeSetId = KeycloakModelUtils.generateId();
        entity.setChangeRequestId(changeSetId);

        GroupModel group = realm.getGroupById(entity.getGroup().getId());
        RoleModel role = realm.getRoleById(entity.getRoleId());
        if (group == null || role == null) {
            throw new IllegalArgumentException("Group or role not found");
        }

        // Find all users in this group and all subgroups recursively
        List<UserModel> groupMembers = GroupUtils.getAllGroupMembersRecursive(session, realm, group);

        if (groupMembers.isEmpty()) {
            // No users affected — immediate commit: set ACTIVE and apply to base table
            entity.setDraftStatus(DraftStatus.ACTIVE);
            TideGroupAdapter tideGroup = new TideGroupAdapter(realm, em, entity.getGroup(), session);
            tideGroup.applyGrantRole(role);
            em.flush();
            return;
        }

        // Find affected clients for this role
        List<ClientModel> clientList = ClientUtils.getUniqueClientList(session, realm, role, em);

        // Generate user context drafts for each user on each affected client
        for (ClientModel client : clientList) {
            for (UserModel user : groupMembers) {
                ChangeSetProcessor.super.generateAndSaveTransformedUserContextDraft(
                        session, em, realm, client, user,
                        new ChangeRequestKey(entity.getId(), changeSetId),
                        ChangeSetType.GROUP_ROLE, entity);
            }
        }

        em.flush();
    }

    @Override
    public void handleDeleteRequest(KeycloakSession session, TideGroupRoleMappingEntity entity, EntityManager em, Runnable callback) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        String changeSetId = KeycloakModelUtils.generateId();
        entity.setChangeRequestId(changeSetId);
        entity.setAction(ActionType.DELETE);

        GroupModel group = realm.getGroupById(entity.getGroup().getId());
        RoleModel role = realm.getRoleById(entity.getRoleId());
        if (group == null || role == null) {
            throw new IllegalArgumentException("Group or role not found");
        }

        // Recursively collect members from group and all subgroups
        List<UserModel> groupMembers = GroupUtils.getAllGroupMembersRecursive(session, realm, group);

        if (groupMembers.isEmpty()) {
            // No users affected — immediate commit: set ACTIVE and apply to base table
            entity.setDraftStatus(DraftStatus.ACTIVE);
            TideGroupAdapter tideGroup = new TideGroupAdapter(realm, em, entity.getGroup(), session);
            tideGroup.applyDeleteRoleMapping(role);
            em.flush();
            return;
        }

        List<ClientModel> clientList = ClientUtils.getUniqueClientList(session, realm, role, em);

        for (ClientModel client : clientList) {
            for (UserModel user : groupMembers) {
                ChangeSetProcessor.super.generateAndSaveTransformedUserContextDraft(
                        session, em, realm, client, user,
                        new ChangeRequestKey(entity.getId(), changeSetId),
                        ChangeSetType.GROUP_ROLE, entity);
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
    public RoleModel getRoleRequestFromEntity(KeycloakSession session, RealmModel realm, TideGroupRoleMappingEntity entity) {
        return realm.getRoleById(entity.getRoleId());
    }
}
