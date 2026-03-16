package org.tidecloak.base.iga.ChangeSetProcessors.processors;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.models.*;
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
import org.tidecloak.base.iga.ChangeSetProcessors.utils.UserContextUtils;
import org.tidecloak.base.iga.interfaces.TideClientAdapter;
import org.tidecloak.base.iga.interfaces.TideUserAdapter;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.drafting.TideGroupDraftEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;

import org.tidecloak.base.iga.interfaces.TideRealmProvider;

import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
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
    public void cancel(KeycloakSession session, TideGroupDraftEntity entity, EntityManager em, ActionType actionType) {
        List<AccessProofDetailEntity> pendingChanges = em.createNamedQuery("getProofDetailsForDraftByChangeSetTypeAndId", AccessProofDetailEntity.class)
                .setParameter("recordId", entity.getChangeRequestId())
                .setParameter("changesetType", ChangeSetType.GROUP)
                .getResultList();
        pendingChanges.forEach(em::remove);

        if (actionType == ActionType.DELETE) {
            entity.setAction(ActionType.CREATE);
            entity.setDraftStatus(DraftStatus.ACTIVE);
        }
        em.flush();

        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(entity.getChangeRequestId(), ChangeSetType.GROUP));
        if (changesetRequestEntity != null) {
            em.remove(changesetRequestEntity);
            em.flush();
        }
    }

    @Override
    public void commit(KeycloakSession session, ChangeSetRequest change, TideGroupDraftEntity entity, EntityManager em, Runnable commitCallback) throws Exception {
        RealmModel realm = session.getContext().getRealm();

        Runnable callback = () -> {
            try {
                List<TideGroupDraftEntity> entities = em.createNamedQuery("GetGroupDraftEntityByRequestId", TideGroupDraftEntity.class)
                        .setParameter("requestId", change.getChangeSetId()).getResultList();
                commitGroupChangeRequest(session, realm, entities, change, em);
            } catch (Exception e) {
                throw new RuntimeException("Error during commit callback", e);
            }
        };

        ChangeSetProcessor.super.commit(session, change, entity, em, callback);
    }

    private void commitGroupChangeRequest(KeycloakSession session, RealmModel realm, List<TideGroupDraftEntity> entities, ChangeSetRequest change, EntityManager em) {
        entities.forEach(entity -> {
            if (change.getActionType() == ActionType.CREATE) {
                if (entity.getDraftStatus() == DraftStatus.ACTIVE) return;
                if (entity.getDraftStatus() != DraftStatus.APPROVED) {
                    throw new RuntimeException("Draft record has not been approved by all admins.");
                }
                entity.setDraftStatus(DraftStatus.ACTIVE);
            } else if (change.getActionType() == ActionType.DELETE) {
                if (entity.getDraftStatus() != DraftStatus.APPROVED) {
                    throw new RuntimeException("Deletion has not been approved by all admins.");
                }
                entity.setDraftStatus(DraftStatus.ACTIVE);
                GroupModel group = realm.getGroupById(entity.getId());
                if (group != null) {
                    TideRealmProvider realmProvider = (TideRealmProvider) session.getProvider(RealmProvider.class);
                    realmProvider.applyRemoveGroup(realm, group);
                }
                em.remove(entity);
            }
        });
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
            ChangeSetProcessor.super.createChangeRequestEntity(session, em, entity.getChangeRequestId(), changeSetType);
        } catch (Exception e) {
            throw new RuntimeException("Failed to process GROUP request", e);
        }
    }

    @Override
    public List<ChangesetRequestEntity> combineChangeRequests(
            KeycloakSession session,
            List<TideGroupDraftEntity> entities,
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
                    TideGroupDraftEntity draft = (TideGroupDraftEntity) BasicIGAUtils.fetchDraftRecordEntity(em, ChangeSetType.GROUP, proof.getChangeRequestKey().getMappingId());
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

                ChangeSetProcessor.super.saveUserContextDraft(session, em, realm, cm, ue, new ChangeRequestKey(mappingId.get(), combinedRequestId), ChangeSetType.GROUP, combinedProofDraft);
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
