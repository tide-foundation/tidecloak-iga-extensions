package org.tidecloak.iga.ChangeSetProcessors.processors;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.AccessToken;
import org.tidecloak.iga.ChangeSetProcessors.ChangeSetProcessor;
import org.tidecloak.iga.ChangeSetProcessors.keys.UserClientKey;
import org.tidecloak.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.iga.ChangeSetProcessors.utils.ChangeRequestUtils;
import org.tidecloak.iga.interfaces.TideUserAdapter;
import org.tidecloak.iga.utils.IGAUtils;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.ChangeRequestKey;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.drafting.TideClientDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.tidecloak.iga.ChangeSetProcessors.utils.UserContextUtils.*;
import static org.tidecloak.iga.ChangeSetProcessors.utils.UserContextUtils.addRoleToAccessToken;


public class ClientProcessor implements ChangeSetProcessor<TideClientDraftEntity> {
    protected static final Logger logger = Logger.getLogger(ClientProcessor.class);

    @Override
    public void cancel(KeycloakSession session, TideClientDraftEntity entity, EntityManager em, ActionType actionType) {
        if(!entity.getFullScopeDisabled().equals(DraftStatus.ACTIVE)){
            entity.setFullScopeDisabled(DraftStatus.NULL);
        }else if (!entity.getFullScopeEnabled().equals(DraftStatus.ACTIVE)){
            entity.setFullScopeEnabled(DraftStatus.NULL);
        }

        // Find any pending changes
        List<AccessProofDetailEntity> pendingChanges = em.createNamedQuery("getProofDetailsForDraftByChangeSetTypeAndId", AccessProofDetailEntity.class)
                .setParameter("recordId", entity.getChangeRequestId())
                .setParameter("changesetType", ChangeSetType.CLIENT)
                .getResultList();

        pendingChanges.forEach(em::remove);
        em.flush();

        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(entity.getChangeRequestId(), ChangeSetType.CLIENT));
        if(changesetRequestEntity != null){
            em.remove(changesetRequestEntity);
            em.flush();
        }

    }

    @Override
    public  void commit(KeycloakSession session, ChangeSetRequest change, TideClientDraftEntity entity, EntityManager em, Runnable commitCallback) throws Exception {
        // Log the start of the request with detailed context
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
                List<TideClientDraftEntity> entities = em.createNamedQuery("GetClientDraftEntityByRequestId", TideClientDraftEntity.class)
                        .setParameter("requestId", change.getChangeSetId()).getResultList();

                commitDefaultUserContext(realm, entities, change);
            } catch (Exception e) {
                throw new RuntimeException("Error during commit callback", e);
            }
        };

        ChangeSetProcessor.super.commit(session, change, entity, em, callback);


        // Log successful completion
        logger.debug(String.format(
                "Successfully processed workflow: COMMIT. Processor: %s, Entity ID: %s, Change Request ID: %s",
                this.getClass().getSimpleName(),
                entity.getId(),
                entity.getChangeRequestId()
        ));
    }

    @Override
    public void request(KeycloakSession session, TideClientDraftEntity entity, EntityManager em, ActionType action, Runnable callback, ChangeSetType changeSetType) {
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
                    logger.debug("Client Processor has no implementation for DELETE.");
                    //ChangeSetProcessor.super.createChangeRequestEntity(em, entity.getChangeRequestId(), changeSetType);
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
            throw new RuntimeException("Failed to process CLIENT request", e);
        }
    }

    @Override
    public void handleCreateRequest(KeycloakSession session, TideClientDraftEntity entity, EntityManager em, Runnable callback) throws Exception {
        entity.setChangeRequestId(KeycloakModelUtils.generateId());
        RealmModel realm = session.realms().getRealm(entity.getClient().getRealmId());
        ClientModel client = realm.getClientById(entity.getClient().getId());
        String defaultFullScopeUserContext = generateRealmDefaultUserContext(session, realm, client, em);
        ChangeSetProcessor.super.saveUserContextDraft(session, em, realm, client, null, new ChangeRequestKey(entity.getId(), entity.getChangeRequestId()), ChangeSetType.CLIENT, defaultFullScopeUserContext);
    }

    @Override
    public void handleDeleteRequest(KeycloakSession session, TideClientDraftEntity entity, EntityManager em, Runnable callback) throws Exception {
        entity.setChangeRequestId(KeycloakModelUtils.generateId());

    }

    @Override
    public void updateAffectedUserContextDrafts(KeycloakSession session, AccessProofDetailEntity userContextDraft, Set<RoleModel> uniqRoles, ClientModel client, TideUserAdapter user, EntityManager em) throws Exception {
        RealmModel realm = session.realms().getRealm(userContextDraft.getRealmId());
        String defaultFullScopeUserContext = generateRealmDefaultUserContext(session, realm, client, em);
        em.remove(userContextDraft);
        this.saveUserContextDraft(session, em, session.getContext().getRealm(), client, null, userContextDraft.getChangeRequestKey(), ChangeSetType.CLIENT, defaultFullScopeUserContext);
    }

    @Override
    public RoleModel getRoleRequestFromEntity(KeycloakSession session, RealmModel realm, TideClientDraftEntity entity) {
        return null;
    }

    private void commitDefaultUserContext(RealmModel realm, List<TideClientDraftEntity> entities, ChangeSetRequest change) {
        entities.forEach(entity -> {
            ClientModel clientModel = realm.getClientByClientId(entity.getClient().getClientId());
            if (clientModel == null) return;

            if (change.getActionType() == ActionType.CREATE) {
                if(entity.getDraftStatus() != DraftStatus.APPROVED){
                    throw new RuntimeException("Draft record has not been approved by all admins.");
                }
                entity.setDraftStatus(DraftStatus.ACTIVE);

            } else if (change.getActionType() == ActionType.DELETE) {
                throw new RuntimeException("CLIENT has no implementation for DELETE");

            }
        });
    }

    @Override
    public List<ChangesetRequestEntity> combineChangeRequests(
            KeycloakSession session,
            List<TideClientDraftEntity> userRoleEntities,
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
                    TideClientDraftEntity draft = (TideClientDraftEntity) IGAUtils.fetchDraftRecordEntity(em, ChangeSetType.CLIENT, proof.getChangeRequestKey().getMappingId());


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

                ChangeSetProcessor.super.saveUserContextDraft(session, em, realm, cm, ue, new ChangeRequestKey(mappingId.get(), combinedRequestId), ChangeSetType.CLIENT, combinedProofDraft);

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

    private String generateRealmDefaultUserContext(KeycloakSession session, RealmModel realm, ClientModel client, EntityManager em) throws Exception {
        List<String> clients = List.of(Constants.ADMIN_CLI_CLIENT_ID, Constants.ADMIN_CONSOLE_CLIENT_ID);
        String id = KeycloakModelUtils.generateId();
        UserModel dummyUser = session.users().addUser(realm, id, id, true, false);
        AccessToken accessToken = ChangeSetProcessor.super.generateAccessToken(session, realm, client, dummyUser);
        if(clients.contains(client.getClientId())){
            accessToken.subject(null);
            session.users().removeUser(realm, dummyUser);
            return ChangeSetProcessor.super.cleanAccessToken(accessToken, List.of("preferred_username", "scope"), client.isFullScopeAllowed());
        } else {
            Set<RoleModel> rolesToAdd = getAllAccess(session, Set.of(realm.getDefaultRole()), client, client.getClientScopes(true).values().stream(), client.isFullScopeAllowed(), null);
            rolesToAdd.forEach(r -> {
                if ( realm.getName().equalsIgnoreCase(Config.getAdminRealm())){
                    addRoleToAccessTokenMasterRealm(accessToken, r, realm, em);
                }
                else{
                    addRoleToAccessToken(accessToken, r);
                }
            });
        }
            accessToken.subject(null);
            session.users().removeUser(realm, dummyUser);
            return ChangeSetProcessor.super.cleanAccessToken(accessToken, List.of("preferred_username", "scope"), client.isFullScopeAllowed());
    }
}
