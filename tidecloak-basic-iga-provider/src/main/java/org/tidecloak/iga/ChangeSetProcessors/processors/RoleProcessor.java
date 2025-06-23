package org.tidecloak.iga.ChangeSetProcessors.processors;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.AccessToken;
import org.tidecloak.iga.ChangeSetProcessors.ChangeSetProcessor;
import org.tidecloak.iga.ChangeSetProcessors.keys.UserClientKey;
import org.tidecloak.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.iga.ChangeSetProcessors.utils.TideEntityUtils;
import org.tidecloak.iga.ChangeSetProcessors.utils.UserContextUtils;
import org.tidecloak.iga.utils.BasicIGAUtils;
import org.tidecloak.jpa.entities.ChangeRequestKey;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.drafting.TideRoleDraftEntity;
import org.tidecloak.iga.interfaces.TideUserAdapter;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.tidecloak.iga.ChangeSetProcessors.utils.ChangeRequestUtils.getChangeSetRequestFromEntity;
import static org.tidecloak.iga.ChangeSetProcessors.utils.ClientUtils.getUniqueClientList;
import static org.tidecloak.iga.ChangeSetProcessors.utils.UserContextUtils.addRoleToAccessToken;
import static org.tidecloak.iga.ChangeSetProcessors.utils.UserContextUtils.removeRoleFromAccessToken;

public class RoleProcessor implements ChangeSetProcessor<TideRoleDraftEntity> {

    protected static final Logger logger = Logger.getLogger(RoleProcessor.class);

    @Override
    public void cancel(KeycloakSession session, TideRoleDraftEntity entity, EntityManager em, ActionType actionType){
        List<AccessProofDetailEntity> pendingChanges = em.createNamedQuery("getProofDetailsForDraftByChangeSetTypeAndId", AccessProofDetailEntity.class)
                .setParameter("recordId", entity.getChangeRequestId())
                .setParameter("changesetType", ChangeSetType.ROLE)
                .getResultList();
        pendingChanges.forEach(em::remove);

        List<TideRoleDraftEntity> pendingDrafts = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class)
                .setParameter("role", entity.getRole())
                .getResultList();

        pendingDrafts.forEach(d -> {
            d.setDeleteStatus(DraftStatus.NULL);
        });
        em.flush();

        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(entity.getChangeRequestId(), ChangeSetType.ROLE));
        if(changesetRequestEntity != null){
            em.remove(changesetRequestEntity);
            em.flush();
        }
    }

    @Override
    public void commit(KeycloakSession session, ChangeSetRequest change, TideRoleDraftEntity entity, EntityManager em, Runnable commitCallback) throws Exception {
        logger.debug(String.format(
                "Starting workflow: COMMIT. Processor: %s, Action: %s, Entity ID: %s, Change Request ID: %s",
                this.getClass().getSimpleName(),
                change.getActionType(),
                entity.getId(),
                entity.getChangeRequestId()
        ));

        RealmModel realm = session.getContext().getRealm();

        Runnable callback = () -> {
            try {
                List<TideRoleDraftEntity> entities = em.createNamedQuery("GetRoleDraftEntityByRequestId", TideRoleDraftEntity.class)
                        .setParameter("requestId", change.getChangeSetId()).getResultList();
                commitRoleChangeRequest(realm, entities, change, em);
            } catch (Exception e) {
                throw new RuntimeException("Error during commit callback", e);
            }
        };

        ChangeSetProcessor.super.commit(session, change, entity, em, callback);

        // Log successful completion
        logger.debug(String.format(
                "Successfully processed workflow: COMMIT. Processor: %s, Mapping ID: %s, Change Request ID: %s",
                this.getClass().getSimpleName(),
                entity.getId(),
                entity.getChangeRequestId()
        ));
    }

    @Override
    public void request(KeycloakSession session, TideRoleDraftEntity entity, EntityManager em, ActionType action, Runnable callback, ChangeSetType changeSetType) {
        try {
            // Log the start of the request with detailed context
            logger.debug(String.format(
                    "Starting workflow: REQUEST. Processor: %s, Action: %s, Entity ID: %s, Change Request ID: %s",
                    this.getClass().getSimpleName(),
                    action,
                    entity.getId(),
                    entity.getChangeRequestId()
            ));
            switch (action) {
                case CREATE:
                    logger.debug(String.format("Initiating CREATE action for Mapping ID: %s in workflow: REQUEST. Change Request ID: %s", entity.getId(), entity.getChangeRequestId()));
                    handleCreateRequest(session, entity, em, callback);
                    ChangeSetProcessor.super.createChangeRequestEntity(em, entity.getChangeRequestId(), changeSetType);
                    break;
                case DELETE:
                    logger.debug(String.format("Initiating DELETE action for Mapping ID: %s in workflow: REQUEST. Change Request ID: %s", entity.getId(), entity.getChangeRequestId()));
                    handleDeleteRequest(session, entity, em, callback);
                    ChangeSetProcessor.super.createChangeRequestEntity(em, entity.getChangeRequestId(), changeSetType);
                    break;
                default:
                    logger.warn(String.format("Unsupported action type: %s for Mapping ID: %s in workflow: REQUEST. Change Request ID: %s", action, entity.getId(), entity.getChangeRequestId()));
                    throw new IllegalArgumentException("Unsupported action: " + action);
            }

            // Log successful completion
            logger.debug(String.format(
                    "Successfully processed workflow: REQUEST. Processor: %s, Mapping ID: %s, Change Request ID: %s",
                    this.getClass().getSimpleName(),
                    entity.getId(),
                    entity.getChangeRequestId()
            ));

        } catch (Exception e) {
            logger.error(String.format(
                    "Error in workflow: REQUEST. Processor: %s, Mapping ID: %s, Change Request ID: %s, Action: %s. Error: %s",
                    this.getClass().getSimpleName(),
                    entity.getId(),
                    entity.getChangeRequestId(),
                    action,
                    e.getMessage()
            ), e);
            throw new RuntimeException("Failed to process ROLE request", e);
        }
    }

    @Override
    public void handleCreateRequest(KeycloakSession session, TideRoleDraftEntity entity, EntityManager em, Runnable callback) throws Exception {
        throw new Exception("ROLE creation not yet implementated");
    }

    @Override
    public void handleDeleteRequest(KeycloakSession session, TideRoleDraftEntity entity, EntityManager em, Runnable callback) throws Exception {
        entity.setChangeRequestId(KeycloakModelUtils.generateId());
        RealmModel realm = session.getContext().getRealm();
        RoleModel role = realm.getRoleById(entity.getRole().getId());
        List<UserModel> users = session.users().searchForUserStream(realm, new HashMap<>()).filter(u -> u.hasRole(role)).toList();
        if(users.isEmpty()){
            return;
        }
        entity.setAction(ActionType.DELETE);

        List<ClientModel> clientList = getUniqueClientList(session, realm, role);
        clientList.forEach(client -> {
            users.forEach(user -> {
                UserModel wrappedUser = TideEntityUtils.wrapUserModel(user, session, realm);
                try {
                    ChangeSetProcessor.super.generateAndSaveTransformedUserContextDraft(session, em, realm, client, wrappedUser, new ChangeRequestKey(entity.getId(), entity.getChangeRequestId()), ChangeSetType.ROLE, entity);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
        });

    }

    @Override
    public void updateAffectedUserContextDrafts(KeycloakSession session, AccessProofDetailEntity affectedUserContextDraft, Set<RoleModel> uniqRoles, ClientModel client, TideUserAdapter user, EntityManager em) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        TideRoleDraftEntity affectedRoleEntity = em.find(TideRoleDraftEntity.class, affectedUserContextDraft.getChangeRequestKey().getMappingId());
        if (affectedRoleEntity == null || (affectedRoleEntity.getDraftStatus() == DraftStatus.ACTIVE && (affectedRoleEntity.getDeleteStatus() == null || affectedRoleEntity.getDeleteStatus().equals(DraftStatus.NULL))))
        {
            return;
        }
        ChangeSetRequest affectedChangeRequest = getChangeSetRequestFromEntity(session, affectedRoleEntity);
        if(affectedChangeRequest.getActionType() == ActionType.DELETE) {
            affectedRoleEntity.setDeleteStatus(DraftStatus.DRAFT);
        }else if (affectedChangeRequest.getActionType() == ActionType.CREATE) {
            affectedRoleEntity.setDraftStatus(DraftStatus.DRAFT);
        }

        String userContextDraft = ChangeSetProcessor.super.generateTransformedUserContext(session, realm, client, user, "openid", affectedRoleEntity);
        affectedUserContextDraft.setProofDraft(userContextDraft);
    }

    @Override
    public RoleModel getRoleRequestFromEntity(KeycloakSession session,  RealmModel realm,TideRoleDraftEntity entity) {
        return realm.getRoleById(entity.getRole().getId());
    }

    @Override
    public AccessToken transformUserContext(AccessToken token, KeycloakSession session, TideRoleDraftEntity entity, UserModel user, ClientModel clientModel){
        RealmModel realm = session.getContext().getRealm();
        RoleModel role = realm.getRoleById(entity.getRole().getId());

        Set<RoleModel> tideRoleModel = Set.of(TideEntityUtils.toTideRoleAdapter(role, session, realm));

        UserContextUtils userContextUtils = new UserContextUtils();
        Set<RoleModel> roleModelSet = userContextUtils.expandActiveCompositeRoles(session, tideRoleModel);

        ChangeSetRequest change = getChangeSetRequestFromEntity(session, entity);
        roleModelSet.forEach(r -> {
            if(change.getActionType().equals(ActionType.CREATE)){
                addRoleToAccessToken(token, r);
            } else if (change.getActionType().equals(ActionType.DELETE)) {
                removeRoleFromAccessToken(token, r);
            }
        });
        userContextUtils.normalizeAccessToken(token, clientModel.isFullScopeAllowed());
        return token;
    }

    @Override
    public List<ChangesetRequestEntity> combineChangeRequests(
            KeycloakSession session,
            List<TideRoleDraftEntity> userRoleEntities,
            EntityManager em) throws IOException, Exception {
        ObjectMapper objectMapper = new ObjectMapper();

        RealmModel realm = session.getContext().getRealm();

        // Group raw AccessProofDetailEntity items by userId and clientId
        Map<UserClientKey, List<AccessProofDetailEntity>> rawMap =
                ChangeSetProcessor.super.groupChangeRequests(userRoleEntities, em);

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

        // Prefetch all UserEntity instances in one query
        List<String> userIds = new ArrayList<>(byUserClient.keySet());
        Map<String, UserEntity> userById = em.createQuery(
                        "SELECT u FROM UserEntity u WHERE u.id IN :ids", UserEntity.class)
                .setParameter("ids", userIds)
                .getResultList().stream()
                .collect(Collectors.toMap(UserEntity::getId, Function.identity()));

        // Cache ClientModel lookups to avoid repeated realm.getClientById() calls
        Set<String> clientIds = byUserClient.values().stream()
                .flatMap(m -> m.keySet().stream())
                .collect(Collectors.toSet());
        Map<String, ClientModel> clientById = clientIds.stream()
                .map(cid -> Map.entry(cid, realm.getClientById(cid)))
                .filter(e -> e.getValue() != null)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        List<ChangesetRequestEntity> results = new ArrayList<>(byUserClient.size());

        // Iterate over each user group to merge proofs and retrieve change requests
        for (var userEntry : byUserClient.entrySet()) {
            String userId = userEntry.getKey();
            UserEntity ue = userById.get(userId);
            UserModel um = session.users().getUserById(realm, userId);

            String combinedRequestId = KeycloakModelUtils.generateId();

            List<AccessProofDetailEntity> toRemoveProofs = new ArrayList<>();
            List<ChangesetRequestEntity> toRemoveRequests = new ArrayList<>();


            // Merge proofs across clients into a single JSON draft
            for (var clientEntry : userEntry.getValue().entrySet()) {
                ClientModel cm = clientById.get(clientEntry.getKey());
                AtomicReference<String> mappingId = new AtomicReference<>();
                AtomicBoolean isFirstRun = new AtomicBoolean();
                isFirstRun.set(true);

                if (cm == null) continue;
                String combinedProofDraft = null;


                for (var proof : clientEntry.getValue()) {
                    mappingId.set(proof.getChangeRequestKey().getMappingId());
                    TideRoleDraftEntity draft = (TideRoleDraftEntity) BasicIGAUtils.fetchDraftRecordEntity(em, ChangeSetType.ROLE, proof.getChangeRequestKey().getMappingId());


                    if (draft == null) {
                        throw new IllegalStateException(
                                "Missing draft for request " + proof.getChangeRequestKey().getMappingId());
                    }

                    draft.setChangeRequestId(combinedRequestId);
                    em.persist(draft);

                    if (combinedProofDraft == null) {
                        combinedProofDraft = proof.getProofDraft();
                    }
                    AccessToken token = objectMapper.readValue(
                            combinedProofDraft, AccessToken.class);
                    combinedProofDraft = combinedTransformedUserContext(
                            session, realm, cm, um, "openId", draft, token);

                    toRemoveProofs.add(proof);
                    toRemoveRequests.addAll(em.createNamedQuery(
                                    "getAllChangeRequestsByRecordId",
                                    ChangesetRequestEntity.class)
                            .setParameter("changesetRequestId", proof.getChangeRequestKey().getChangeRequestId())
                            .getResultList());

                    if(isFirstRun.get()) {
                        isFirstRun.set(false);
                    }
                }

                ChangeSetProcessor.super.saveUserContextDraft(session, em, realm, cm, ue, new ChangeRequestKey(mappingId.get(), combinedRequestId), ChangeSetType.ROLE, combinedProofDraft);

            }

            // Remove outdated proofs and their change-request entities
            toRemoveProofs.forEach(em::remove);
            toRemoveRequests.forEach(em::remove);


            // Retrieve the recreated ChangeRequestEntity(ies) for this combinedRequestId
            List<ChangesetRequestEntity> created = em.createNamedQuery(
                            "getAllChangeRequestsByRecordId", ChangesetRequestEntity.class)
                    .setParameter("changesetRequestId", combinedRequestId)
                    .getResultList();
            results.addAll(created);
        }

        // Flush all pending changes once at the end
        em.flush();

        return results;
    }

    private void commitRoleChangeRequest(RealmModel realm, List<TideRoleDraftEntity> entities, ChangeSetRequest change, EntityManager em) {;

        entities.forEach((entity) -> {
            RoleModel role = realm.getRoleById(entity.getRole().getId());
            if (role == null) return;

            if (change.getActionType() == ActionType.CREATE) {
                if(entity.getDraftStatus().equals(DraftStatus.ACTIVE)) return;
                if(entity.getDraftStatus() != DraftStatus.APPROVED){
                    throw new RuntimeException("Draft record has not been approved by all admins.");
                }
                entity.setDraftStatus(DraftStatus.ACTIVE);

            } else if (change.getActionType() == ActionType.DELETE) {
                if(entity.getDeleteStatus() != DraftStatus.APPROVED && entity.getDeleteStatus() != DraftStatus.ACTIVE ){
                    throw new RuntimeException("Deletion has not been approved by all admins.");
                }
                entity.setDeleteStatus(DraftStatus.ACTIVE);
                realm.removeRole(role);
                cleanupRoleRecords(em, entity);
            }
        });
    }


    private void cleanupRoleRecords(EntityManager em, TideRoleDraftEntity mapping) {
        List<String> recordsToRemove = new ArrayList<>(em.createNamedQuery("getUserRoleMappingDraftsByRole", String.class)
                .setParameter("roleId", mapping.getRole().getId())
                .getResultList());

        em.createNamedQuery("deleteUserRoleMappingDraftsByRole")
                .setParameter("roleId", mapping.getRole().getId())
                .executeUpdate();

        recordsToRemove.addAll(em.createNamedQuery("selectIdsForRemoval", String.class)
                .setParameter("role", mapping.getRole())
                .getResultList());
        recordsToRemove.add(mapping.getId());

        em.createNamedQuery("removeDraftRequestsOnRemovalOfRole")
                .setParameter("role", mapping.getRole())
                .executeUpdate();

        recordsToRemove.forEach(id -> em.createNamedQuery("deleteProofRecords")
                .setParameter("recordId", id)
                .executeUpdate());
    }
}
