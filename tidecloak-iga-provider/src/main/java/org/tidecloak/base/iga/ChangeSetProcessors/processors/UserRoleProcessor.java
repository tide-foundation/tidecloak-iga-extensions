package org.tidecloak.base.iga.ChangeSetProcessors.processors;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.AccessToken;
import org.tidecloak.jpa.entities.drafting.PolicyDraftEntity;
import org.tidecloak.shared.models.UserContext;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessor;
import org.tidecloak.base.iga.ChangeSetProcessors.keys.UserClientKey;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.base.iga.ChangeSetProcessors.utils.ClientUtils;
import org.tidecloak.base.iga.ChangeSetProcessors.utils.TideEntityUtils;
import org.tidecloak.base.iga.ChangeSetProcessors.utils.UserContextUtils;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.jpa.entities.*;
import org.tidecloak.jpa.entities.drafting.TideRoleDraftEntity;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.base.iga.interfaces.TideRoleAdapter;
import org.tidecloak.base.iga.interfaces.TideUserAdapter;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.shared.enums.ActionType;


import java.io.IOException;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.tidecloak.base.iga.ChangeSetProcessors.utils.ChangeRequestUtils.getChangeSetRequestFromEntity;
import static org.tidecloak.base.iga.ChangeSetProcessors.utils.UserContextUtils.addRoleToAccessToken;
import static org.tidecloak.base.iga.ChangeSetProcessors.utils.UserContextUtils.removeRoleFromAccessToken;
import static org.tidecloak.base.iga.TideRequests.TideRoleRequests.createRolePolicyDraft;

public class UserRoleProcessor implements ChangeSetProcessor<TideUserRoleMappingDraftEntity> {

    protected static final Logger logger = Logger.getLogger(UserRoleProcessor.class);

    @Override
    public void cancel(KeycloakSession session, TideUserRoleMappingDraftEntity entity, EntityManager em, ActionType actionType){
        RealmModel realmModel = session.realms().getRealm(entity.getUser().getRealmId());
        RoleModel role = realmModel.getRoleById(entity.getRoleId());
        TideUserAdapter user = new TideUserAdapter(session, realmModel, em, entity.getUser());
        List<AccessProofDetailEntity> accessProofDetailEntities = UserContextUtils.getUserContextDrafts(em, entity.getId());
        accessProofDetailEntities.forEach(em::remove);

        List<TideUserRoleMappingDraftEntity> pendingDrafts = em.createNamedQuery("getUserRoleAssignmentDraftEntityByStatusNotEqualTo", TideUserRoleMappingDraftEntity.class)
                .setParameter("user", entity.getUser())
                .setParameter("roleId", role.getId())
                .setParameter("draftStatus", DraftStatus.ACTIVE)
                .getResultList();
        user.deleteRoleAndProofRecords(role, pendingDrafts, actionType);
        em.flush();

        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(entity.getId(), ChangeSetType.USER_ROLE));
        if(changesetRequestEntity != null){
            em.remove(changesetRequestEntity);
            em.flush();
        }
    }

    @Override
    public void commit(KeycloakSession session, ChangeSetRequest change, TideUserRoleMappingDraftEntity entity, EntityManager em, Runnable commitCallback) throws Exception {
        logger.debug(String.format(
                "Starting workflow: COMMIT. Processor: %s, Action: %s, Entity ID: %s, Change Request ID: %s",
                this.getClass().getSimpleName(),
                change.getActionType(),
                entity.getId(),
                entity.getChangeRequestId()
        ));

        RealmModel realm = session.getContext().getRealm();
        UserModel user = session.users().getUserById(realm, entity.getUser().getId());

        Runnable callback = () -> {
            try {
                List<TideUserRoleMappingDraftEntity> entities = em.createNamedQuery("GetUserRoleMappingDraftEntityByRequestId", TideUserRoleMappingDraftEntity.class)
                        .setParameter("requestId", change.getChangeSetId()).getResultList();
                commitUserRoleChangeRequest(user, realm, entities, change);
            } catch (Exception e) {
                throw new RuntimeException("Error during commit callback", e);
            }
        };

        ChangeSetProcessor.super.commit(session, change, entity, em, callback);

        // Recreate for tide-admin-realm assignment here
        RoleModel role = realm.getRoleById(entity.getRoleId());

        if(Objects.equals(role.getName(), org.tidecloak.shared.Constants.TIDE_REALM_ADMIN)) {
            ComponentModel componentModel = realm.getComponentsStream()
                    .filter(x -> "tide-vendor-key".equals(x.getProviderId()))  // Use .equals for string comparison
                    .findFirst()
                    .orElse(null);

            if(componentModel == null) {
                throw new Exception("There is no tide-vendor-key component set up for this realm, " + realm.getName());
            }
            List<AuthorizerEntity> realmAuthorizers = em.createNamedQuery("getAuthorizerByProviderId", AuthorizerEntity.class)
                    .setParameter("ID", componentModel.getId()).getResultList();
            if (realmAuthorizers.isEmpty()){
                throw new Exception("Authorizer not found for this realm.");
            }

            List<TideUserRoleMappingDraftEntity> tideAdminRealmRoleRequests = em.createNamedQuery("getUserRoleMappingDraftsByRoleAndStatusNotEqualTo", TideUserRoleMappingDraftEntity.class)
                    .setParameter("roleId", role.getId())
                    .setParameter("draftStatus", DraftStatus.ACTIVE)
                    .getResultList();

            List<ClientModel> clientList = ClientUtils.getUniqueClientList(session, realm, role, em);

            tideAdminRealmRoleRequests.forEach(request -> {
                try {
                    UserModel u = session.users().getUserById(realm, request.getUser().getId());
                    List<ChangesetRequestEntity> changesetRequestEntity = em.createNamedQuery("getAllChangeRequestsByRecordId", ChangesetRequestEntity.class).setParameter("changesetRequestId", request.getChangeRequestId()).getResultList();
                    if(!changesetRequestEntity.isEmpty()) {
                        changesetRequestEntity.forEach(em::remove);
                    }
                    em.flush();
                    List<AccessProofDetailEntity> accessProofs = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                            .setParameter("recordId", request.getId()).getResultList();
                    accessProofs.forEach(p -> {
                        em.remove(p);
                        em.flush();
                    });
                    List<PolicyDraftEntity> policyDraftEntities = em.createNamedQuery("getPolicyByChangeSetId", PolicyDraftEntity.class).setParameter("changesetId", request.getChangeRequestId()).getResultList();
                    if(!policyDraftEntities.isEmpty()){
                        em.remove(policyDraftEntities.get(0));
                        em.flush();
                    }
                    createRolePolicyDraft(session, request.getId(), 0.7, 1, role);
                    processRealmManagementRoleAssignment(session, em, realm, clientList, request, u);

                } catch (Exception e) {
                    throw new RuntimeException(e);
                }

            });
        }

        // Log successful completion
        logger.debug(String.format(
                "Successfully processed workflow: COMMIT. Processor: %s, Mapping ID: %s, Change Requests ID: %s",
                this.getClass().getSimpleName(),
                entity.getId(),
                entity.getChangeRequestId()
        ));
    }

    @Override
    public void request(KeycloakSession session, TideUserRoleMappingDraftEntity entity, EntityManager em, ActionType action, Runnable callback, ChangeSetType changeSetType) {
        try {
            // Log the start of the request with detailed context
            logger.debug(String.format(
                    "Starting workflow: REQUEST. Processor: %s, Action: %s, Entity ID: %s, Change Requests ID: %s",
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
            throw new RuntimeException("Failed to process USER_ROLE request", e);
        }
    }


    @Override
    public void handleCreateRequest(KeycloakSession session, TideUserRoleMappingDraftEntity mapping, EntityManager em, Runnable callback) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        RoleModel role = realm.getRoleById(mapping.getRoleId());
        UserModel userModel = TideEntityUtils.toTideUserAdapter(mapping.getUser(), session, realm);
        String changeSetId = KeycloakModelUtils.generateId();
        mapping.setChangeRequestId(changeSetId);

        if(role.getName().equalsIgnoreCase(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN)) {
            ComponentModel componentModel = realm.getComponentsStream()
                    .filter(x -> "tide-vendor-key".equals(x.getProviderId()))  // Use .equals for string comparison
                    .findFirst()
                    .orElse(null);

            if(componentModel == null) {
                throw new Exception("There is no tide-vendor-key component set up for this realm, " + realm.getName());
            }
            List<AuthorizerEntity> realmAuthorizers = em.createNamedQuery("getAuthorizerByProviderId", AuthorizerEntity.class)
                    .setParameter("ID", componentModel.getId()).getResultList();
            if (realmAuthorizers.isEmpty()){
                throw new Exception("Authorizer not found for this realm.");
            }
            if (realmAuthorizers.get(0).getType().equalsIgnoreCase("multiAdmin")) {
                createRolePolicyDraft(session, changeSetId, 0.7, 1, role);
            }
        }

        Set<RoleModel> roleMappings = Collections.singleton(role);
        List<ClientModel> clientList = ClientUtils.getUniqueClientList(session, realm, role, em);

        if (role.isClientRole() && isRealmManagementClient(role)) {
            processRealmManagementRoleAssignment(session, em, realm, clientList, mapping, userModel);
        } else {
            processRoles(session, em, realm, clientList, roleMappings, mapping, userModel);
        }

        em.flush();
    }

    @Override
    public void handleDeleteRequest(KeycloakSession session, TideUserRoleMappingDraftEntity entity, EntityManager em, Runnable callback) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        RoleEntity roleEntity = em.find(RoleEntity.class, entity.getRoleId());
        RoleModel role = realm.getRoleById(entity.getRoleId());

        UserModel affectedUser = session.users().getUserById(realm, entity.getUser().getId());
        String changeSetId = KeycloakModelUtils.generateId();

        entity.setChangeRequestId(changeSetId);

        if(roleEntity.getName().equalsIgnoreCase(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN)) {
            ComponentModel componentModel = realm.getComponentsStream()
                    .filter(x -> "tide-vendor-key".equals(x.getProviderId()))  // Use .equals for string comparison
                    .findFirst()
                    .orElse(null);

            if(componentModel == null) {
                throw new Exception("There is no tide-vendor-key component set up for this realm, " + realm.getName());
            }
            List<AuthorizerEntity> realmAuthorizers = em.createNamedQuery("getAuthorizerByProviderId", AuthorizerEntity.class)
                    .setParameter("ID", componentModel.getId()).getResultList();
            if (realmAuthorizers.isEmpty()){
                throw new Exception("Authorizer not found for this realm.");
            }
            if (realmAuthorizers.get(0).getType().equalsIgnoreCase("multiAdmin")) {
                createRolePolicyDraft(session, changeSetId, 0.7, -1, role);
            }
        }


        Set<UserModel> users = new TreeSet<>(Comparator.comparing(UserModel::getId));
        users.add(affectedUser);

        RoleModel tideRoleModel = TideEntityUtils.toTideRoleAdapter(roleEntity, session, realm);
        List<TideUserRoleMappingDraftEntity> activeDraftEntities = TideUserAdapter.getActiveDraftEntities(em, entity.getUser(), tideRoleModel);
        if ( activeDraftEntities.isEmpty()){
            return;
        }

        TideUserRoleMappingDraftEntity userRoleMapping = activeDraftEntities.get(0);

        // Check if there is a delete status pending. Only create a delete request if its not yet actioned
        if(userRoleMapping.getDeleteStatus() != null && userRoleMapping.getDeleteStatus().equals(DraftStatus.NULL))
        {
            return;
        }

        // Mark entities as pending delete.
        userRoleMapping.setDeleteStatus(DraftStatus.DRAFT);
        userRoleMapping.setTimestamp(System.currentTimeMillis());

        List<ClientModel> clientList = ClientUtils.getUniqueClientList(session, realm, tideRoleModel, em);

        clientList.forEach(client -> {
            users.forEach(user -> {
                    try {
                        UserEntity u = em.find(UserEntity.class, user.getId());
                        UserModel wrappedUser = TideEntityUtils.toTideUserAdapter(u, session, realm);
                        ChangeSetProcessor.super.generateAndSaveTransformedUserContextDraft(session, em, realm, client, wrappedUser, new ChangeRequestKey(userRoleMapping.getId(), userRoleMapping.getChangeRequestId()),
                            ChangeSetType.USER_ROLE, userRoleMapping);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                });
        });
    }

    @Override
    public RoleModel getRoleRequestFromEntity(KeycloakSession session, RealmModel realm, TideUserRoleMappingDraftEntity entity) {
        return realm.getRoleById(entity.getRoleId());
    }

    @Override
    public void updateAffectedUserContextDrafts(KeycloakSession session, AccessProofDetailEntity affectedUserContextDraft, Set<RoleModel> roles, ClientModel client, TideUserAdapter userChangesMadeTo, EntityManager em) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        TideUserRoleMappingDraftEntity affectedUserRoleEntity = em.find(TideUserRoleMappingDraftEntity.class, affectedUserContextDraft.getChangeRequestKey().getMappingId());
        if (affectedUserRoleEntity == null || !Objects.equals(userChangesMadeTo.getId(), affectedUserRoleEntity.getUser().getId()) || affectedUserRoleEntity.getDraftStatus() == DraftStatus.ACTIVE && (affectedUserRoleEntity.getDeleteStatus() == null || affectedUserRoleEntity.getDeleteStatus().equals(DraftStatus.NULL))){
            return;
        }

        ChangeSetRequest affectedChangeRequest = getChangeSetRequestFromEntity(session, affectedUserRoleEntity);

        if(affectedChangeRequest.getActionType() == ActionType.DELETE) {
            affectedUserRoleEntity.setDeleteStatus(DraftStatus.DRAFT);
        }else if (affectedChangeRequest.getActionType() == ActionType.CREATE) {
            affectedUserRoleEntity.setDraftStatus(DraftStatus.DRAFT);
        }

        String userContextDraft = ChangeSetProcessor.super.generateTransformedUserContext(session, realm, client, userChangesMadeTo, "openId", affectedUserRoleEntity);
        affectedUserContextDraft.setProofDraft(userContextDraft);
    }


    @Override
    public AccessToken transformUserContext(AccessToken token, KeycloakSession session, TideUserRoleMappingDraftEntity entity, UserModel user, ClientModel clientModel){
        RealmModel realm = session.getContext().getRealm();
        RoleModel role = realm.getRoleById(entity.getRoleId());

        Set<RoleModel> tideRoleModel = Set.of(TideEntityUtils.toTideRoleAdapter(role, session, realm));

        UserContextUtils userContextUtils = new UserContextUtils();
        Set<RoleModel> roleModelSet = userContextUtils.expandActiveCompositeRoles(session, tideRoleModel);

        ChangeSetRequest change = getChangeSetRequestFromEntity(session, entity);
        roleModelSet.forEach(r -> {
            if(change.getActionType().equals(ActionType.CREATE)){
                addRoleToAccessToken(token, r);
            } else if (change.getActionType().equals(ActionType.DELETE)) {
                if(Objects.equals(entity.getUser().getId(), user.getId())) {
                    removeRoleFromAccessToken(token, r);
                }
            }
        });
        userContextUtils.normalizeAccessToken(token, clientModel.isFullScopeAllowed());
        return token;
    }

    @Override
    public List<ChangesetRequestEntity> combineChangeRequests(
            KeycloakSession session,
            List<TideUserRoleMappingDraftEntity> userRoleEntities,
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
                    TideUserRoleMappingDraftEntity draft = (TideUserRoleMappingDraftEntity) BasicIGAUtils.fetchDraftRecordEntity(em, ChangeSetType.USER_ROLE, proof.getChangeRequestKey().getMappingId());
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

                ChangeSetProcessor.super.saveUserContextDraft(session, em, realm, cm, ue, new ChangeRequestKey(mappingId.get(), combinedRequestId), ChangeSetType.USER_ROLE, combinedProofDraft);

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

    // Helper Methods
    private void commitUserRoleChangeRequest(UserModel user, RealmModel realm, List<TideUserRoleMappingDraftEntity> entities, ChangeSetRequest change) {

        entities.forEach(entity -> {
            RoleModel role = realm.getRoleById(entity.getRoleId());
            if (role == null) return;

            if (change.getActionType() == ActionType.CREATE) {
                // If already active, then early return
                if(entity.getDraftStatus().equals(DraftStatus.ACTIVE)) return;

                if(!entity.getDraftStatus().equals(DraftStatus.APPROVED)){
                    throw new RuntimeException("Draft record has not been approved by all admins.");
                }
                entity.setDraftStatus(DraftStatus.ACTIVE);

            } else if (change.getActionType() == ActionType.DELETE) {
                if(!entity.getDeleteStatus().equals(DraftStatus.APPROVED) && !entity.getDeleteStatus().equals(DraftStatus.ACTIVE) ){
                    throw new RuntimeException("Deletion has not been approved by all admins.");
                }
                entity.setDeleteStatus(DraftStatus.ACTIVE);
                user.deleteRoleMapping(role);
            }
        });
    }

    private boolean isRealmManagementClient(RoleModel role) {
        return ((ClientModel) role.getContainer()).getClientId().equalsIgnoreCase(Constants.REALM_MANAGEMENT_CLIENT_ID);
    }

    private void processRealmManagementRoleAssignment(KeycloakSession session, EntityManager em, RealmModel realm, List<ClientModel> clientList,
                                                       TideUserRoleMappingDraftEntity entity, UserModel userModel) {
        Set<UserModel> adminUsers = new HashSet<>();
        adminUsers.add(userModel);
        clientList.forEach(client -> {
            try {
                boolean isAdminClient = client.getClientId().equalsIgnoreCase(Constants.ADMIN_CONSOLE_CLIENT_ID) || client.getClientId().equalsIgnoreCase(Constants.ADMIN_CLI_CLIENT_ID);
                adminUsers.forEach(u -> {
                    try {
                        ChangeSetProcessor.super.generateAndSaveTransformedUserContextDraft(session, em, realm, client, u, new ChangeRequestKey(entity.getId() ,entity.getChangeRequestId()),
                                ChangeSetType.USER_ROLE, entity);

                    }catch (Exception e) {
                        throw new RuntimeException("Error processing client: " + client.getClientId(), e);
                    }
                });
            } catch (Exception e) {
                throw new RuntimeException("Error processing client: " + client.getClientId(), e);
            }
        });
    }

    private void processRoles(KeycloakSession session, EntityManager em, RealmModel realm, List<ClientModel> clientList,
                                                  Set<RoleModel> roleMappings, TideUserRoleMappingDraftEntity entity, UserModel userModel) {
        clientList.forEach(client -> {
            try {
                if (isAdminClient(client)) {
                    return;
                }
                ChangeSetProcessor.super.generateAndSaveTransformedUserContextDraft(session, em, realm, client, userModel, new ChangeRequestKey(entity.getId() ,entity.getChangeRequestId()),
                        ChangeSetType.USER_ROLE, entity);
            } catch (Exception e) {
                throw new RuntimeException("Error processing client: " + client.getClientId(), e);
            }
        });
    }

    private boolean isAdminClient(ClientModel client) {
        return client.getClientId().equalsIgnoreCase(Constants.ADMIN_CONSOLE_CLIENT_ID) ||
                client.getClientId().equalsIgnoreCase(Constants.ADMIN_CLI_CLIENT_ID);
    }


    private Set<TideRoleAdapter> wrapRolesAsTideAdapters(Set<RoleModel> roles, KeycloakSession session, RealmModel realm, EntityManager em) {
        return roles.stream()
                .map(r -> new TideRoleAdapter(session, realm, em, em.getReference(RoleEntity.class, r.getId())))
                .collect(Collectors.toSet());
    }

    private Set<RoleModel> expandAllCompositeRoles(Set<TideRoleAdapter> wrappedRoles) {
        Set<RoleModel> compositeRoles = new HashSet<>();
        compositeRoles.addAll(TideEntityUtils.expandCompositeRoles(wrappedRoles, DraftStatus.DRAFT));
        compositeRoles.addAll(TideEntityUtils.expandCompositeRoles(wrappedRoles, DraftStatus.PENDING));
        compositeRoles.addAll(TideEntityUtils.expandCompositeRoles(wrappedRoles, DraftStatus.APPROVED));
        compositeRoles.addAll(TideEntityUtils.expandCompositeRoles(wrappedRoles, DraftStatus.ACTIVE));

        return compositeRoles.stream().filter(Objects::nonNull).collect(Collectors.toSet());
    }

    private List<AccessProofDetailEntity> getUserContextDrafts(EntityManager em, ClientModel client, TideUserRoleMappingDraftEntity entity) {
        UserEntity user = entity.getUser();
        return em.createNamedQuery("getProofDetailsForUserByClient", AccessProofDetailEntity.class)
                .setParameter("user", user)
                .setParameter("clientId", client.getId())
                .getResultList();
    }


    private List<TideUserRoleMappingDraftEntity> getUserRoleMappings(EntityManager em, String changeSetId, ActionType action, RealmModel realm) {
        String queryName = action == ActionType.CREATE ? "getUserRoleMappingsByStatusAndRealmAndRecordId" : "getUserRoleMappingsByDeleteStatusAndRealmAndRecordId";
        return em.createNamedQuery(queryName, TideUserRoleMappingDraftEntity.class)
                .setParameter(action == ActionType.CREATE ? "draftStatus" : "deleteStatus", DraftStatus.APPROVED)
                .setParameter("changesetId", changeSetId)
                .setParameter("realmId", realm.getId())
                .getResultList();
    }

}
