package org.tidecloak.base.iga.ChangeSetProcessors.processors;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.AccessToken;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessor;
import org.tidecloak.base.iga.ChangeSetProcessors.keys.UserClientKey;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.base.iga.ChangeSetProcessors.utils.TideEntityUtils;
import org.tidecloak.base.iga.ChangeSetProcessors.utils.UserContextUtils;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.jpa.entities.ChangeRequestKey;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.base.iga.interfaces.TideUserAdapter;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.drafting.TideClientDraftEntity;
import org.tidecloak.base.iga.interfaces.TideClientAdapter;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.tidecloak.base.iga.ChangeSetProcessors.utils.ChangeRequestUtils.getChangeSetRequestFromEntity;
import static org.tidecloak.base.iga.ChangeSetProcessors.utils.UserContextUtils.*;

public class ClientFullScopeProcessor implements ChangeSetProcessor<TideClientDraftEntity> {
    protected static final Logger logger = Logger.getLogger(ClientFullScopeProcessor.class);

    @Override
    public void cancel(KeycloakSession session, TideClientDraftEntity entity, EntityManager em, ActionType actionType) {
        if(!entity.getFullScopeDisabled().equals(DraftStatus.ACTIVE)){
            entity.setFullScopeDisabled(DraftStatus.NULL);
        }else if (!entity.getFullScopeEnabled().equals(DraftStatus.ACTIVE)){
            entity.setFullScopeEnabled(DraftStatus.NULL);
        }

        // Find any pending changes
        List<AccessProofDetailEntity> pendingChanges = em.createNamedQuery("getProofDetailsForDraftByChangeSetTypesAndId", AccessProofDetailEntity.class)
                .setParameter("recordId", entity.getId())
                .setParameter("changesetTypes", List.of(ChangeSetType.CLIENT_FULLSCOPE, ChangeSetType.CLIENT_DEFAULT_USER_CONTEXT))
                .getResultList();

        pendingChanges.forEach(em::remove);
        em.flush();

        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(entity.getId(), ChangeSetType.CLIENT_FULLSCOPE));
        if(changesetRequestEntity != null){
            em.remove(changesetRequestEntity);
            em.flush();
        }

    }

    @Override
    public void commit(KeycloakSession session, ChangeSetRequest change, TideClientDraftEntity entity, EntityManager em, Runnable commitCallback) throws Exception {
        logger.debug(String.format(
                "Starting workflow: COMMIT. Processor: %s, Action: %s, Entity ID: %s",
                this.getClass().getSimpleName(),
                change.getActionType(),
                entity.getId()
        ));

        RealmModel realm = session.getContext().getRealm();
        ClientModel client = new TideClientAdapter(realm, em, session, entity.getClient());

        Runnable callback = () -> {
            try {
                List<TideClientDraftEntity> entities = em.createNamedQuery("GetClientDraftEntityByRequestId", TideClientDraftEntity.class)
                        .setParameter("requestId", change.getChangeSetId()).getResultList();

                commitCallback(change, entities, client, em);
                em.flush();

            } catch (Exception e) {
                throw new RuntimeException("Error during commit callback", e);
            }
        };

        ChangeSetProcessor.super.commit(session, change, entity, em, callback);

        // Log successful completion
        logger.debug(String.format(
                "Successfully processed workflow: COMMIT. Processor: %s, Mapping ID: %s",
                this.getClass().getSimpleName(),
                entity.getId()
        ));
    }

    @Override
    public void request(KeycloakSession session, TideClientDraftEntity entity, EntityManager em, ActionType action, Runnable callback, ChangeSetType changeSetType) {
        try {
            // Log the start of the request with detailed context
            logger.debug(String.format(
                    "Starting workflow: REQUEST. Processor: %s, Action: %s, Entity ID: %s",
                    this.getClass().getSimpleName(),
                    action,
                    entity.getId()
            ));
            RealmModel realm = session.realms().getRealm(entity.getClient().getRealmId());
            String igaAttribute = realm.getAttribute("isIGAEnabled");
            boolean isIGAEnabled = igaAttribute != null && igaAttribute.equalsIgnoreCase("true");
            switch (action) {
                case CREATE:
                    logger.debug(String.format("Initiating CREATE (enable) action for Mapping ID: %s in workflow: REQUEST", entity.getId()));
                    handleCreateRequest(session, entity, em, callback);
                    ChangeSetProcessor.super.createChangeRequestEntity(em, entity.getChangeRequestId(), changeSetType);
                    if (!isIGAEnabled){
                        if (entity.getFullScopeEnabled().equals(DraftStatus.ACTIVE)){
                            entity.setFullScopeDisabled(DraftStatus.NULL);
                        }
                        callback.run();
                    }
                    break;
                case DELETE:
                    logger.debug(String.format("Initiating DELETE (disable) action for Mapping ID: %s in workflow: REQUEST", entity.getId()));
                    handleDeleteRequest(session, entity, em, callback);
                    ChangeSetProcessor.super.createChangeRequestEntity(em, entity.getChangeRequestId(), changeSetType);
                    if (!isIGAEnabled){
                        if (entity.getFullScopeDisabled().equals(DraftStatus.ACTIVE)){
                            entity.setFullScopeEnabled(DraftStatus.NULL);
                        }
                        callback.run();
                    }
                    break;
                default:
                    logger.warn(String.format("Unsupported action type: %s for Mapping ID: %s in workflow: REQUEST", action, entity.getId()));
                    throw new IllegalArgumentException("Unsupported action: " + action);
            }


        } catch (Exception e) {
            logger.error(String.format(
                    "Error in workflow: REQUEST. Processor: %s, Mapping ID: %s, Action: %s. Error: %s",
                    this.getClass().getSimpleName(),
                    entity.getId(),
                    action,
                    e.getMessage()
            ), e);
            throw new RuntimeException("Failed to process CLIENT_FULLSCOPE request", e);

        }
    }

    @Override
    public void handleCreateRequest(KeycloakSession session, TideClientDraftEntity entity, EntityManager em, Runnable callback) throws Exception {
        entity.setChangeRequestId(KeycloakModelUtils.generateId());
        RealmModel realm = session.getContext().getRealm();
        ClientModel client = realm.getClientByClientId(entity.getClient().getClientId());
        entity.setFullScopeEnabled(DraftStatus.DRAFT);
        em.persist(entity);
        em.flush();

        // Update Default user context for client aswell
        ChangeSetRequest change = getChangeSetRequestFromEntity(session, entity, ChangeSetType.CLIENT_FULLSCOPE);
        String defaultFullScopeUserContext = generateRealmDefaultUserContext(session, realm, client, em, change);
        ChangeSetProcessor.super.saveUserContextDraft(session, em, realm, client, null, new ChangeRequestKey(entity.getId(), entity.getChangeRequestId()), ChangeSetType.CLIENT_DEFAULT_USER_CONTEXT, defaultFullScopeUserContext);
        em.flush();

        List<UserModel> usersInRealm = session.users().searchForUserStream(realm, new HashMap<>()).toList();
        usersInRealm.forEach(user -> {
            try{
                // Find any pending changes
                List<AccessProofDetailEntity> pendingChanges = em.createNamedQuery("getProofDetailsForDraftByChangeSetTypeAndIdAndUser", AccessProofDetailEntity.class)
                        .setParameter("recordId", entity.getId())
                        .setParameter("changesetType", ChangeSetType.CLIENT_FULLSCOPE)
                        .setParameter("userId", user.getId())
                        .getResultList();

                if(pendingChanges != null && !pendingChanges.isEmpty()){
                    return;
                }

                UserModel wrappedUser = TideEntityUtils.wrapUserModel(user, session, realm);

                ChangeSetProcessor.super.generateAndSaveTransformedUserContextDraft(session, em, realm, client, wrappedUser, new ChangeRequestKey(entity.getId(), entity.getChangeRequestId()),
                        ChangeSetType.CLIENT_FULLSCOPE, entity);

            }
            catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        em.flush();
    }

    @Override
    public void handleDeleteRequest(KeycloakSession session, TideClientDraftEntity entity, EntityManager em, Runnable callback) throws Exception {
        entity.setChangeRequestId(KeycloakModelUtils.generateId());
        RealmModel realm = session.getContext().getRealm();
        ClientModel client = realm.getClientByClientId(entity.getClient().getClientId());
        List<UserModel> usersInRealm = session.users().searchForUserStream(realm, new HashMap<>()).toList();

        if(usersInRealm.isEmpty()){
            if (callback != null) {
                callback.run();
            }
            approveFullScope(entity, false);
            ChangeSetRequest changeSetRequest = getChangeSetRequestFromEntity(session, entity);
            ChangeSetProcessor.super.updateAffectedUserContexts(session, realm, changeSetRequest, entity, em);
            return;
        }

        entity.setFullScopeDisabled(DraftStatus.DRAFT);
        em.merge(entity);
        em.flush();

        // Update Default user context for client aswell
        ChangeSetRequest change = getChangeSetRequestFromEntity(session, entity);
        String defaultFullScopeUserContext = generateRealmDefaultUserContext(session, realm, client, em, change);
        ChangeSetProcessor.super.saveUserContextDraft(session, em, realm, client, null, new ChangeRequestKey(entity.getId(), entity.getChangeRequestId()), ChangeSetType.CLIENT_DEFAULT_USER_CONTEXT, defaultFullScopeUserContext);
        em.flush();

        usersInRealm.forEach(user -> {
            // Find any pending changes
            List<AccessProofDetailEntity> pendingChanges = em.createNamedQuery("getProofDetailsForDraftByChangeSetTypeAndId", AccessProofDetailEntity.class)
                    .setParameter("recordId", entity.getId())
                    .setParameter("changesetType", ChangeSetType.CLIENT_FULLSCOPE)
                    .getResultList();

            if ( pendingChanges != null && !pendingChanges.isEmpty()) {
                return;
            }
            try {
                ChangeSetProcessor.super.generateAndSaveTransformedUserContextDraft(session, em, realm, client, user, new ChangeRequestKey(entity.getId(), entity.getChangeRequestId()), ChangeSetType.CLIENT_FULLSCOPE, entity);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        em.flush();
    }


    @Override
    public void updateAffectedUserContextDrafts(KeycloakSession session, AccessProofDetailEntity affectedUserContextDraft, Set<RoleModel> uniqRoles, ClientModel client, TideUserAdapter user, EntityManager em) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        TideClientDraftEntity affectedClientFullScopeEntity = em.find(TideClientDraftEntity.class, affectedUserContextDraft.getChangeRequestKey().getMappingId());
        if (affectedClientFullScopeEntity == null ||
                isValidStatusPair(affectedClientFullScopeEntity.getFullScopeDisabled(), affectedClientFullScopeEntity.getFullScopeEnabled()) ||
                isValidStatusPair(affectedClientFullScopeEntity.getFullScopeEnabled(), affectedClientFullScopeEntity.getFullScopeDisabled())) {
            return;
        }
        ChangeSetRequest affectedChangeRequest = getChangeSetRequestFromEntity(session, affectedClientFullScopeEntity);

        if(affectedChangeRequest.getActionType() == ActionType.DELETE) {
            affectedClientFullScopeEntity.setFullScopeDisabled(DraftStatus.DRAFT);
        }else if (affectedChangeRequest.getActionType() == ActionType.CREATE) {
            affectedClientFullScopeEntity.setFullScopeEnabled(DraftStatus.DRAFT);
        }

        String userContextDraft = ChangeSetProcessor.super.generateTransformedUserContext(session, realm, client, user, "openid", affectedClientFullScopeEntity);
        affectedUserContextDraft.setProofDraft(userContextDraft);
        em.flush();

    }

    @Override
    public RoleModel getRoleRequestFromEntity(KeycloakSession session, RealmModel realm, TideClientDraftEntity entity) {
        return null;
    }

    @Override
    public AccessToken transformUserContext(AccessToken token, KeycloakSession session, TideClientDraftEntity entity, UserModel user, ClientModel clientModel) {
        RealmModel realm = session.getContext().getRealm();
        ClientModel client = realm.getClientByClientId(entity.getClient().getClientId());

        // Ensure token components are initialized
        if (token.getRealmAccess() == null) {
            token.setRealmAccess(new AccessToken.Access());
        }
        if (token.getResourceAccess() == null) {
            token.setResourceAccess(new HashMap<>());
        }

        UserContextUtils userContextUtils = new UserContextUtils();
        Set<RoleModel> activeRoles = userContextUtils.getDeepUserRoleMappings(user, session, realm, DraftStatus.ACTIVE);

        ChangeSetRequest change = getChangeSetRequestFromEntity(session, entity);
        Set<RoleModel> roleModelSet = UserContextUtils.getAccess(
                activeRoles,
                client,
                client.getClientScopes(true).values().stream(),
                change.getActionType().equals(ActionType.CREATE)
        );

        if (change.getActionType().equals(ActionType.DELETE)) {
            // Clear existing roles if realm access exists
            if (token.getRealmAccess() != null && token.getRealmAccess().getRoles() != null) {
                token.getRealmAccess().getRoles().clear();
            }

            // Clear resource access if it exists
            if (token.getResourceAccess() != null) {
                token.getResourceAccess().clear();
            }
        }

        // Add roles to token
        roleModelSet.forEach(role -> {
            addRoleToAccessToken(token, role);
        });

        // Update token audience
        userContextUtils.normalizeAccessToken(token, client.isFullScopeAllowed());

        return token;
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
                    TideClientDraftEntity draft = (TideClientDraftEntity) BasicIGAUtils.fetchDraftRecordEntity(em, ChangeSetType.CLIENT_FULLSCOPE, proof.getChangeRequestKey().getMappingId());


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

                ChangeSetProcessor.super.saveUserContextDraft(session, em, realm, cm, ue, new ChangeRequestKey(mappingId.get(), combinedRequestId), ChangeSetType.CLIENT_FULLSCOPE, combinedProofDraft);

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

    private void commitCallback(ChangeSetRequest change, List<TideClientDraftEntity> entities, ClientModel clientModel, EntityManager em){
        entities.forEach(entity -> {
            if (change.getActionType() == ActionType.CREATE) {
                if(entity.getFullScopeEnabled() != DraftStatus.APPROVED && entity.getFullScopeEnabled() != DraftStatus.ACTIVE){
                    throw new RuntimeException("Draft record has not been approved by all admins.");
                }
                entity.setFullScopeEnabled(DraftStatus.ACTIVE);
                entity.setFullScopeDisabled(DraftStatus.NULL);
                clientModel.setFullScopeAllowed(true);
            } else if (change.getActionType() == ActionType.DELETE) {
                if(entity.getFullScopeDisabled() != DraftStatus.APPROVED && entity.getFullScopeDisabled() != DraftStatus.ACTIVE){
                    throw new RuntimeException("Deletion has not been approved by all admins.");
                }
                entity.setFullScopeDisabled(DraftStatus.ACTIVE);
                entity.setFullScopeEnabled(DraftStatus.NULL);
                clientModel.setFullScopeAllowed(false);
            }

            ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(change.getChangeSetId(), ChangeSetType.CLIENT));
            if(entity.getDraftStatus().equals(DraftStatus.DRAFT) && changesetRequestEntity != null){
                entity.setDraftStatus(DraftStatus.ACTIVE);
                // Find any pending changes
                List<AccessProofDetailEntity> pendingChanges = em.createNamedQuery("getProofDetailsForDraftByChangeSetTypesAndId", AccessProofDetailEntity.class)
                        .setParameter("recordId", entity.getId())
                        .setParameter("changesetTypes", List.of(ChangeSetType.CLIENT))
                        .getResultList();
                pendingChanges.forEach(em::remove);
                em.remove(changesetRequestEntity);

            }
        });
    }

    private void approveFullScope(TideClientDraftEntity clientFullScopeStatuses, boolean isEnabled) {
        if (isEnabled) {
            clientFullScopeStatuses.setFullScopeDisabled(DraftStatus.NULL);
            clientFullScopeStatuses.setFullScopeEnabled(DraftStatus.ACTIVE);
        } else {
            clientFullScopeStatuses.setFullScopeEnabled(DraftStatus.NULL);
            clientFullScopeStatuses.setFullScopeDisabled(DraftStatus.ACTIVE);
        }

    }

    private boolean isValidStatusPair(DraftStatus activeStatus, DraftStatus inactiveStatus) {
        // Valid if the active status is ACTIVE and the inactive status is null or NULL
        return activeStatus == DraftStatus.ACTIVE &&
                (inactiveStatus == null || inactiveStatus == DraftStatus.NULL);
    }

    private String generateRealmDefaultUserContext(KeycloakSession session, RealmModel realm, ClientModel client, EntityManager em, ChangeSetRequest change) throws Exception {
        List<String> clients = List.of(Constants.ADMIN_CLI_CLIENT_ID, Constants.ADMIN_CONSOLE_CLIENT_ID, Constants.ACCOUNT_CONSOLE_CLIENT_ID);
        String id = KeycloakModelUtils.generateId();
        UserModel dummyUser = session.users().addUser(realm, id, id, true, false);
        AccessToken accessToken = ChangeSetProcessor.super.generateAccessToken(session, realm, client, dummyUser);
        boolean isFullscope = change.getActionType().equals(ActionType.CREATE);
        if(clients.contains(client.getClientId())){
            accessToken.subject(null);
            session.users().removeUser(realm, dummyUser);
            return ChangeSetProcessor.super.cleanAccessToken(accessToken, List.of("preferred_username", "scope"), isFullscope);
        } else {
            Set<RoleModel> rolesToAdd = getAllAccess(session, Set.of(realm.getDefaultRole()), client, client.getClientScopes(true).values().stream(), isFullscope, null);
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
        return ChangeSetProcessor.super.cleanAccessToken(accessToken, List.of("preferred_username", "scope"), isFullscope);
    }
}
