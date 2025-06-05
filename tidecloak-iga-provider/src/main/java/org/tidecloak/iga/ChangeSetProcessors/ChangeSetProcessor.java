package org.tidecloak.iga.ChangeSetProcessors;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.ws.rs.core.Response;
import org.keycloak.common.ClientConnection;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.managers.UserSessionManager;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.midgard.Serialization.JsonSorter;
import org.midgard.models.InitializerCertificateModel.InitializerCertifcate;
import org.midgard.models.RequestExtensions.UserContextSignRequest;
import org.midgard.models.UserContext.UserContext;
import org.tidecloak.iga.ChangeSetProcessors.keys.UserClientKey;
import org.tidecloak.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.keycloak.representations.AccessToken;
import org.tidecloak.iga.ChangeSetProcessors.utils.TideEntityUtils;
import org.tidecloak.iga.ChangeSetProcessors.utils.UserContextUtils;
import org.tidecloak.iga.utils.IGAUtils;
import org.tidecloak.jpa.entities.*;
import org.tidecloak.shared.enums.WorkflowType;
import org.tidecloak.shared.enums.models.WorkflowParams;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.iga.interfaces.TideClientAdapter;
import org.tidecloak.iga.interfaces.TideRoleAdapter;
import org.tidecloak.iga.interfaces.TideUserAdapter;
import org.tidecloak.jpa.entities.drafting.*;
import org.tidecloak.iga.interfaces.ChangesetRequestAdapter;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.tidecloak.shared.enums.ActionType;


import java.net.URI;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiFunction;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.tidecloak.iga.TideRequests.TideRoleRequests.getDraftRoleInitCert;
import static org.tidecloak.iga.ChangeSetProcessors.utils.ChangeRequestUtils.getChangeSetRequestFromEntity;
import static org.tidecloak.iga.ChangeSetProcessors.utils.UserContextUtils.*;

public interface ChangeSetProcessor<T> {

    /**
     * Executes a workflow (e.g., request , approval or commit) for a given change set.
     *
     * @param session   The KeycloakSession for the current context.
     * @param entity   The entity instance being processed.
     * @param em        The EntityManager for database interactions.
     * @param workflow  The type of workflow to execute (e.g. REQUEST, APPROVAL, COMMIT).
     * @param params    Additional parameters specific to the workflow.
     */
    default void executeWorkflow(KeycloakSession session, T entity, EntityManager em, WorkflowType workflow, WorkflowParams params, Runnable callback) throws Exception {
        switch (workflow) {
            case APPROVAL:
                approve(session, getChangeSetRequestFromEntity(session, entity, params.getChangeSetType()), entity, em, params.getDraftStatus(), params.isDelete());
                break;
            case COMMIT:
                commit(session, getChangeSetRequestFromEntity(session, entity, params.getChangeSetType()), entity, em, null);
                break;
            case REQUEST:
                request(session, entity, em, params.getActionType(), callback, params.getChangeSetType());
                break;
            case CANCEL:
                cancel(session, entity, em, params.getActionType());
                break;
            default:
                throw new IllegalArgumentException("Unsupported workflow: " + workflow);
        }
    }

    /**
     * Processes a change request based on the specified action type.
     * This method determines the action to perform (e.g., CREATE or DELETE) and delegates
     * the specific logic to helper methods `handleCreateRequest` and `handleDeleteRequest`.
     *
     * @param session   The Keycloak session for the current context.
     * @param mapping   The entity being processed.
     * @param em        The EntityManager for database interactions.
     * @param action    The type of action to be performed (e.g., CREATE, DELETE).
     * @throws IllegalArgumentException If the action type is not supported.
     */
    default void request(KeycloakSession session, T mapping, EntityManager em, ActionType action, Runnable callback, ChangeSetType changeSetType) throws Exception {
        // Handle action types (CREATE, DELETE)
        switch (action) {
            case CREATE:
                handleCreateRequest(session, mapping, em, callback);
                break;
            case DELETE:
                handleDeleteRequest(session, mapping, em, callback);
                break;
            default:
                throw new IllegalArgumentException("Unsupported action: " + action);
        }
    }

    /**
     * Approves a change request by updating the draft status and applying specific business logic.
     * This method should be overridden by specific processors to define approval behavior.
     *
     * @param session   The Keycloak session for the current context.
     * @param change    The change set request containing details of the change.
     * @param mapping   The entity being processed.
     * @param em        The EntityManager for database interactions.
     * @param status    The new status to be applied to the draft (e.g., ACTIVE, APPROVED).
     * @param isDelete  Indicates whether the approval is for a deletion request.
     * @throws UnsupportedOperationException If the method is not implemented in the specific processor.
     */
    default void approve(KeycloakSession session, ChangeSetRequest change, T mapping, EntityManager em, DraftStatus status, boolean isDelete){
        throw new UnsupportedOperationException("Approve not implemented");

    };

    /**
     * Updates all affected user context drafts triggered by a change request commit.
     * This method performs the following steps:
     * - Retrieves a list of affected clients based on the entity.
     * - Updates any related user contexts for these clients.
     *
     * @param session   The Keycloak session for the current context.
     * @param change    The change set request containing details of the change.
     * @param entity    The entity being processed.
     * @param em        The EntityManager for database interactions.
     * @throws Exception If an error occurs during the update process.
     */
    default void updateAffectedUserContexts(KeycloakSession session, RealmModel realm, ChangeSetRequest change, T entity, EntityManager em) throws Exception {
        if(change.getType().equals(ChangeSetType.CLIENT)){
            return;
        }
        List<ClientModel> affectedClients = getAffectedClients(session, realm, entity, em);
        ChangeSetProcessorFactory processorFactory = new ChangeSetProcessorFactory(); // Initialize the processor factory

        for (ClientModel client : affectedClients) {

            List<AccessProofDetailEntity> userContextDrafts = getUserContextDrafts(em, client)
                    .stream()
                    .filter(proof -> !Objects.equals(proof.getRecordId(), change.getChangeSetId()))
                    .toList();


            for(AccessProofDetailEntity userContextDraft : userContextDrafts) {
                em.lock(userContextDraft, LockModeType.PESSIMISTIC_WRITE);

                if(change.getType().equals(ChangeSetType.USER_ROLE) && (userContextDraft.getChangesetType().equals(ChangeSetType.CLIENT) || userContextDraft.getChangesetType().equals(ChangeSetType.DEFAULT_ROLES) || userContextDraft.getChangesetType().equals(ChangeSetType.CLIENT_DEFAULT_USER_CONTEXT) || userContextDraft.getChangesetType().equals(ChangeSetType.CLIENT_FULLSCOPE))) {
                    continue;
                }

                TideUserAdapter user = null;
                if(entity instanceof  TideUserRoleMappingDraftEntity tideUserRoleMappingDraft) {
                    UserEntity userEntity = tideUserRoleMappingDraft.getUser();
                    user = TideEntityUtils.toTideUserAdapter(userEntity, session, realm);
                } else {
                    UserEntity userEntity = userContextDraft.getUser();
                    user = TideEntityUtils.toTideUserAdapter(userEntity, session, realm);
                }


                Set<RoleModel> roleSet = new HashSet<>();
                roleSet.add(getRoleRequestFromEntity(session, realm, entity));
                var uniqRoles = roleSet.stream().distinct().filter(Objects::nonNull).collect(Collectors.toSet());

                processorFactory.getProcessor(userContextDraft.getChangesetType()).updateAffectedUserContextDrafts(session, userContextDraft, uniqRoles, client, user, em);
                ChangesetRequestEntity changesetRequestEntity = ChangesetRequestAdapter.getChangesetRequestEntity(session, userContextDraft.getRecordId(), userContextDraft.getChangesetType());
                if (changesetRequestEntity != null){
                    changesetRequestEntity.getAdminAuthorizations().clear(); // empty sigs!
                }
            }
        }
        em.flush();

        // Group proofDetails by changeRequestId
        Map<String, List<AccessProofDetailEntity>> groupedProofDetails = getUserContextDraftsForRealm(em, realm.getId()).stream()
                .filter(proof -> !Objects.equals(proof.getRecordId(), change.getChangeSetId()))
                .sorted(Comparator.comparingLong(AccessProofDetailEntity::getCreatedTimestamp).reversed())
                .collect(Collectors.groupingBy(AccessProofDetailEntity::getRecordId));

        // Process each group
        groupedProofDetails.forEach((changeRequestId, details) -> {
            try {
                // Create a list of UserContext for the current changeRequestId
                List<UserContext>  userContexts = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                        .setParameter("recordId", changeRequestId).getResultStream().map(p -> new UserContext(p.getProofDraft())).collect(Collectors.toList());

                if(userContexts.isEmpty()){
                    return;
                }
                AtomicInteger numberOfNormalUserContext = new AtomicInteger();
                userContexts.forEach(x -> {
                    if(x.getInitCertHash() == null) {
                        numberOfNormalUserContext.getAndIncrement();
                    }
                });
                Stream<UserContext> normalUserContext = userContexts.stream().filter(x -> x.getInitCertHash() == null);
                Stream<UserContext> adminContexts = userContexts.stream().filter(x -> x.getInitCertHash() != null);
                List<UserContext> orderedContext = Stream.concat(adminContexts, normalUserContext).toList();

                // Create UserContextSignRequest
                UserContextSignRequest updatedReq = new UserContextSignRequest("Admin:1");
                updatedReq.SetUserContexts(orderedContext.toArray(new UserContext[0]));
                updatedReq.SetNumberOfUserContexts(numberOfNormalUserContext.get());

                ChangeSetType changeSetType;
                if(details.get(0).getChangesetType().equals(ChangeSetType.CLIENT_DEFAULT_USER_CONTEXT)){
                    changeSetType = ChangeSetType.CLIENT_FULLSCOPE;
                }
                else if (details.get(0).getChangesetType().equals(ChangeSetType.DEFAULT_ROLES)) {
                    changeSetType = ChangeSetType.COMPOSITE_ROLE;
                }
                else{
                    changeSetType = details.get(0).getChangesetType();
                }

                ChangesetRequestEntity changesetRequestEntity = ChangesetRequestAdapter.getChangesetRequestEntity(session, changeRequestId, changeSetType);
                if(changesetRequestEntity != null){
                    changesetRequestEntity.setDraftRequest(Base64.getEncoder().encodeToString(updatedReq.GetDraft()));
                }
                em.flush();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    /**
     * Commits a change request by finalizing the draft and applying changes to the database.
     *
     * @param session        The Keycloak session for the current context.
     * @param change         The change set request containing details of the change.
     * @param entity         The entity being processed.
     * @param em             The EntityManager for database interactions.
     * @param commitCallback A Runnable task to execute during the commit process for additional actions.
     * @throws Exception If any error occurs during the commit process.
     */
    default void commit(KeycloakSession session, ChangeSetRequest change, T entity, EntityManager em, Runnable commitCallback) throws Exception {
        String realmId = session.getContext().getRealm().getId();
        ComponentModel componentModel = session.getContext().getRealm().getComponentsStream()
                .filter(x -> "tide-vendor-key".equals(x.getProviderId()))  // Use .equals for string comparison
                .findFirst()
                .orElse(null);


        // Retrieve the user context drafts
        List<AccessProofDetailEntity> userContextDrafts = getUserContextDrafts(em, change.getChangeSetId(), change.getType());

        if (userContextDrafts.isEmpty()) {
            throw new Exception("No user context drafts found for this change set id, " + change.getChangeSetId());
        }

        if(IGAUtils.isIGAEnabled(session.getContext().getRealm()) && componentModel == null){
            commitCallback.run();
            ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(change.getChangeSetId(), change.getType()));
            if (changesetRequestEntity != null) {
                changesetRequestEntity.getAdminAuthorizations().clear();
                em.flush();
            }

            return;
        }

        // Process each user context draft
        for (AccessProofDetailEntity userContextDraft : userContextDrafts) {
            try {
                UserEntity userEntity = userContextDraft.getUser();
                TideUserAdapter affectedUser = TideEntityUtils.toTideUserAdapter(userEntity, session, session.realms().getRealm(userContextDraft.getRealmId()));

                commitUserContextToDatabase(session, userContextDraft, em);
                em.remove(userContextDraft); // This user context draft is committed, so remove it
                em.flush();
            } catch (Exception e) {
                throw new RuntimeException("Error processing user context draft: " + e.getMessage(), e);
            }
        }

        // Execute the commit callback if provided
        if (commitCallback != null) {
            commitCallback.run();
        }
        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(change.getChangeSetId(), change.getType()));
        if (changesetRequestEntity != null) {
            em.remove(changesetRequestEntity);
        }

        // Regenerate for client full scope change request.
        List<ChangesetRequestEntity> clientFullScopeChangeRequests = em.createNamedQuery("getAllChangeRequestsByChangeSetType", ChangesetRequestEntity.class)
                .setParameter("changesetType", ChangeSetType.CLIENT_FULLSCOPE)
                .getResultStream()
                .filter(x -> {
                    TideClientDraftEntity tideClientDraftEntity = em.find(TideClientDraftEntity.class, x.getChangesetRequestId());
                    if (tideClientDraftEntity == null) {
                        em.remove(x); // Remove empty change request
                        return false;
                    }
                    return tideClientDraftEntity.getClient().getRealmId().equalsIgnoreCase(realmId);
                })
                .toList();

        ChangeSetProcessorFactory changeSetProcessorFactory = new ChangeSetProcessorFactory();

        clientFullScopeChangeRequests.forEach(req -> {
            TideClientDraftEntity tideClientDraftEntity = em.find(TideClientDraftEntity.class, req.getChangesetRequestId());

            if (tideClientDraftEntity == null) return; // Skip if draft entity is missing

            ChangeSetRequest c = getChangeSetRequestFromEntity(session, tideClientDraftEntity, ChangeSetType.CLIENT_FULLSCOPE);

            // Remove associated admin authorizations
            req.getAdminAuthorizations().clear();

            // Remove associated proof details
            em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                    .setParameter("recordId", req.getChangesetRequestId())
                    .getResultStream()
                    .forEach(em::remove);

            // Remove the changeset request
            em.remove(req);

            // Process the workflow
            WorkflowParams params = new WorkflowParams(DraftStatus.DRAFT, c.getActionType().equals(ActionType.DELETE), c.getActionType(), ChangeSetType.CLIENT_FULLSCOPE);
            try {
                changeSetProcessorFactory.getProcessor(ChangeSetType.CLIENT_FULLSCOPE)
                        .executeWorkflow(session, tideClientDraftEntity, em, WorkflowType.REQUEST, params, null);
            } catch (Exception e) {
                throw new RuntimeException("Error executing workflow for request ID: " + req.getChangesetRequestId(), e);
            }
        });

        // Flush once after batch processing
        em.flush();

        // Update affected user contexts
        updateAffectedUserContexts(session, session.getContext().getRealm(), change, entity, em);
    }

    /**
     * Cancels a change request and its dependencies.
     *
     * @param session   The Keycloak session for the current context.
     * @param entity   The entity being processed.
     * @param em        The EntityManager for database interactions.
     * @throws IllegalArgumentException If the action type is not supported.
     */
    default void cancel(KeycloakSession session, T entity, EntityManager em, ActionType actionType) throws Exception {
        throw new UnsupportedOperationException("Cancel has no default implementation");
    }

    /**
     * Generates and saves a transformed user context draft for the given user and client models.
     * This method applies entity-specific transformations to the user context.
     *
     * @param session   KeycloakSession object for authentication and context.
     * @param em        EntityManager for database operations.
     * @param realm     RealmModel representing the current realm.
     * @param clientModel ClientModel representing the client.
     * @param userModel UserModel representing the user.
     * @param recordId  Record ID for the change set.
     * @param type      ChangeSetType representing the type of the change set.
     * @param entity    The entity that triggers the transformation.
     * @throws Exception If any error occurs during the generation or saving of the user context draft.
     */
    default void generateAndSaveTransformedUserContextDraft(KeycloakSession session, EntityManager em, RealmModel realm,
                                                            ClientModel clientModel, UserModel userModel, String recordId,
                                                            ChangeSetType type, T entity) throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        objectMapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.PUBLIC_ONLY);

        // Generate a transformed user context using entity-specific logic
        String userContextDraft = this.generateTransformedUserContext(session, realm, clientModel, userModel, "openid", entity);
        UserEntity user = TideEntityUtils.toUserEntity(userModel, em);
        saveUserContextDraft(session, em, realm, clientModel, user, recordId, type, userContextDraft);
    }


    /**
     * Generates and saves a default user context draft for the given user and client models.
     * This method generates a user context in its raw form without any transformations.
     *
     * @param session   KeycloakSession object for authentication and context.
     * @param em        EntityManager for database operations.
     * @param realm     RealmModel representing the current realm.
     * @param clientModel ClientModel representing the client.
     * @param userModel UserModel representing the user.
     * @param recordId  Record ID for the change set.
     * @param type      ChangeSetType representing the type of the change set.
     * @throws Exception If any error occurs during the generation or saving of the user context draft.
     */
    default void generateAndSaveDefaultUserContextDraft(KeycloakSession session, EntityManager em, RealmModel realm,
                                                        ClientModel clientModel, UserModel userModel, String recordId,
                                                        ChangeSetType type) throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        objectMapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.PUBLIC_ONLY);

        // Generate a raw user context without applying entity-specific transformations
        String userContextDraft = this.generateDefaultUserContext(session, realm, clientModel, userModel);

        UserEntity user = TideEntityUtils.toUserEntity(userModel, em);

        saveUserContextDraft(session, em, realm, clientModel, user, recordId, type, userContextDraft);
    }

    /**
     * Retrieves a list of affected clients for the given entity.
     * This includes:
     * - Clients with full scope enabled or draft scope.
     * - Clients associated with the role of the entity.
     * - Additional clients based on composite roles and component logic.
     *
     * @param session The Keycloak session for the current context.
     * @param entity  The entity being processed (e.g., user role, composite role, etc.).
     * @param em      The EntityManager for database interactions.
     * @return A list of unique ClientModel instances that are affected by the changeSetRequest.
     * @throws Exception If an authorizer is not found or other processing errors occur.
     */
    default List<ClientModel> getAffectedClients(KeycloakSession session, RealmModel realm, T entity, EntityManager em) throws Exception {
        Set<ClientModel> affectedClients = new HashSet<>();

        // Add clients with full scope or draft scope
        realm.getClientsStream()
                .map(client -> new TideClientAdapter(realm, em, session, em.getReference(ClientEntity.class, client.getId())))
                .filter(clientModel -> {
                    ClientEntity clientEntity = em.find(ClientEntity.class, clientModel.getId());
                    List<TideClientDraftEntity> scopeDrafts = em.createNamedQuery("getClientFullScopeStatusByFullScopeEnabledStatus", TideClientDraftEntity.class)
                            .setParameter("client", clientEntity)
                            .setParameter("fullScopeEnabled", DraftStatus.DRAFT)
                            .getResultList();
                    return clientModel.isFullScopeAllowed() || (scopeDrafts != null && !scopeDrafts.isEmpty());
                })
                .forEach(affectedClients::add);

        // Add clients based on role-specific logic
        RoleModel role = getRoleRequestFromEntity(session, realm, entity);
        if (role != null) {
            if (role.isClientRole()) {
                ClientModel client = realm.getClientById(role.getContainerId());
                if (client != null) {
                    affectedClients.add(client);
                }
            }

            if (role.isComposite()) {
                RoleEntity roleEntity = em.getReference(RoleEntity.class, role.getId());
                Set<RoleModel> wrappedRoles = Set.of(new TideRoleAdapter(session, realm, em, roleEntity));
                UserContextUtils userContextUtils = new UserContextUtils();
                Set<RoleModel> activeRoles = userContextUtils.expandActiveCompositeRoles(session, wrappedRoles);

                activeRoles.stream()
                        .filter(r -> r.getContainer() instanceof ClientModel)
                        .map(r -> (ClientModel) r.getContainer())
                        .forEach(affectedClients::add);
            }
        }

        // Component logic for admin authorizations
        ComponentModel componentModel = realm.getComponentsStream()
                .filter(component -> "tide-vendor-key".equals(component.getProviderId()))
                .findFirst()
                .orElse(null);

        if (componentModel != null) {
            affectedClients.removeIf(client ->
                    Constants.ADMIN_CONSOLE_CLIENT_ID.equalsIgnoreCase(client.getClientId()) ||
                            Constants.ADMIN_CLI_CLIENT_ID.equalsIgnoreCase(client.getClientId()) ||
                            Constants.REALM_MANAGEMENT_CLIENT_ID.equalsIgnoreCase(client.getClientId())
            );
        }
        affectedClients.removeIf(r -> r.getClientId().equalsIgnoreCase(Constants.BROKER_SERVICE_CLIENT_ID));

        return new ArrayList<>(affectedClients);
    }

    /**
     * Transforms the generated access token with specific processor logic to a user context for the change request.
     *
     * @param token              The initial access token to be transformed.
     * @param session            The Keycloak session for context.
     * @return The transformed access token.
     */
    default AccessToken transformUserContext(
            AccessToken token,
            KeycloakSession session,
            T entity,
            UserModel user,
            ClientModel clientModel

    ) {
        return token;
    }

    default List<AccessProofDetailEntity> combineChangeRequests(
            KeycloakSession session,
            List<T> entity,
            EntityManager em

    ) {
        throw new UnsupportedOperationException("Combine Change Requests has no default implementation");
    }


    /**
     * Generates a user context draft for a specific entity.
     * This method includes claims specific to the user, such as tideUserKey and vuid, and transforms the token
     * using a processor appropriate for the entity type.
     *
     * @param session    The Keycloak session for the current context.
     * @param realm      The realm associated with the operation.
     * @param client     The client model for which the context draft is being generated.
     * @param user       The user model for whom the draft is being generated.
     * @param scopeParam The scope parameter for the access token.
     * @param entity     The entity for which the user context is being generated.
     * @return A serialized JSON string of the user context draft.
     * @throws JsonProcessingException If an error occurs during JSON serialization.
     */

    default String generateTransformedUserContext(KeycloakSession session, RealmModel realm, ClientModel client, UserModel user, String scopeParam, T entity) throws Exception {
        AccessToken token = this.generateAccessToken(session, realm, client, user);
        return this.generateTransformedUserContext(session, realm, client, user, scopeParam, entity, token);
    }

    default String combinedTransformedUserContext(KeycloakSession session, RealmModel realm, ClientModel client, UserModel user, String scopeParam, T entity, AccessToken token) throws Exception {
        return this.generateTransformedUserContext(session, realm, client, user, scopeParam, entity, token);
    }


    default Map<UserClientKey, List<AccessProofDetailEntity>> groupChangeRequests(List<T> entities, EntityManager em ){
        ObjectMapper objectMapper = new ObjectMapper();

        // Get a list of entities
        List<AccessProofDetailEntity> proofs = entities.stream().map(entity -> {
            return IGAUtils.getAccessProofsFromEntity(em, entity);
        }).filter(Objects::nonNull).flatMap(List::stream).toList();

        // group access proofs by user and client
        Map<UserClientKey, List<AccessProofDetailEntity>> grouped =
                proofs.stream().collect(Collectors.groupingBy(
                        proof -> {
                            return new UserClientKey(proof.getUser().getId(), proof.getClientId());

                        }
                ));

        return grouped;

        // combine for each user
        // loop through user + client access proof and combine, update id ??? record id??? and save new proof in a new accessproofentity with this record id and remove the others.
//        grouped.forEach((userClientAccess, accessProofs) -> {
//
//            AtomicReference<String> trackTokenString = new AtomicReference<>("");
//            // generate a new ID
//            accessProofs.forEach(proof -> {
//                try {
//                    T entity =  (T) IGAUtils.fetchDraftRecordEntity(em, proof.getChangesetType(), proof.getRecordId());
//                    AccessToken accessToken = objectMapper.readValue(proof.getProofDraft(), AccessToken.class);
//                    trackTokenString.set(this.generateTransformedUserContext(session, realm, client, user, scopeParam, entity));
//
//                } catch (Exception e) {
//                    throw new RuntimeException(e);
//                }
//            });
//
//        });

        // commit
        // update affected

    }

//    default String combineChangeSets(KeycloakSession session, RealmModel realm, ClientModel client, UserModel user, String scopeParam, T entity, AccessToken token) throws Exception {
//        ObjectMapper objectMapper = new ObjectMapper();
//        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
//        objectMapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.PUBLIC_ONLY);
//        ChangeSetProcessorFactory processorFactory = new ChangeSetProcessorFactory();
//
//        String tideUserKey = user.getFirstAttribute("tideUserKey");
//        String vuid = user.getFirstAttribute("vuid");
//
//        if (tideUserKey != null) {
//            token.getOtherClaims().put("tideuserkey", tideUserKey);
//        }
//        if (vuid != null) {
//            token.getOtherClaims().put("vuid", vuid);
//        }
//
//        ChangeSetRequest changeSetRequest = getChangeSetRequestFromEntity(session, entity);
//        AccessToken userContextToken = processorFactory.getProcessor(changeSetRequest.getType()).combineUserContexts(token, session, entity, user, client);
//
//        boolean isFullScopeAllowed = client.isFullScopeAllowed();
//        if( entity instanceof TideClientDraftEntity) {
//            isFullScopeAllowed = changeSetRequest.getActionType().equals(ActionType.CREATE);
//        }
//
//        return this.cleanAccessToken(userContextToken, null, isFullScopeAllowed);
//
//    }

    default AccessToken transformedToken(AccessToken token, UserModel user) throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        objectMapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.PUBLIC_ONLY);

        String tideUserKey = user.getFirstAttribute("tideUserKey");
        String vuid = user.getFirstAttribute("vuid");

        if (tideUserKey != null) {
            token.getOtherClaims().put("tideuserkey", tideUserKey);
        }
        if (vuid != null) {
            token.getOtherClaims().put("vuid", vuid);
        }

        return token;
    }


    default String generateTransformedUserContext(KeycloakSession session, RealmModel realm, ClientModel client, UserModel user, String scopeParam, T entity, AccessToken token) throws Exception {
        ChangeSetProcessorFactory processorFactory = new ChangeSetProcessorFactory();
        AccessToken accessToken = this.transformedToken(token, user);

        ChangeSetRequest changeSetRequest = getChangeSetRequestFromEntity(session, entity);
        AccessToken userContextToken = processorFactory.getProcessor(changeSetRequest.getType()).transformUserContext(accessToken, session, entity, user, client);

        boolean isFullScopeAllowed = client.isFullScopeAllowed();
        if( entity instanceof TideClientDraftEntity) {
            isFullScopeAllowed = changeSetRequest.getActionType().equals(ActionType.CREATE);
        }

        return this.cleanAccessToken(userContextToken, null, isFullScopeAllowed);

    }

    /**
     * Generates a default user context for a given user and client.
     * This method creates a raw, untransformed AccessToken that includes user-specific claims (e.g., "tideUserKey" and "vuid").
     * The resulting token is serialized into JSON format and represents the base context without entity-specific transformations.
     *
     * @param session The Keycloak session for the current context, providing access to session-related operations.
     * @param realm   The realm associated with the operation, defining the domain of users and clients.
     * @param client  The client model for which the default user context is being generated.
     * @param user    The user model for whom the default user context is being generated.
     * @return A serialized JSON string of the default (raw) user context, ready to be saved or transformed further.
     * @throws JsonProcessingException If an error occurs during the serialization of the user context to JSON.
     */
    default String generateDefaultUserContext(KeycloakSession session, RealmModel realm, ClientModel client, UserModel user) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        objectMapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.PUBLIC_ONLY);

        AccessToken token = this.generateAccessToken(session, realm, client, user);
        String tideUserKey = user.getFirstAttribute("tideUserKey");
        String vuid = user.getFirstAttribute("vuid");

        // Add claims to the token
        if (tideUserKey != null) {
            token.getOtherClaims().put("tideuserkey", tideUserKey);
        }
        if (vuid != null) {
            token.getOtherClaims().put("vuid", vuid);
        }

        return this.cleanAccessToken(token, null, client.isFullScopeAllowed());
    }

    default AccessToken generateAccessToken(KeycloakSession session, RealmModel realm, ClientModel client, UserModel user){
        AccessToken token = sessionAware(session, realm, client, user, "openid", (userSession, clientSessionCtx) -> {
            TokenManager tokenManager = new TokenManager();
            return tokenManager.responseBuilder(realm, client, null, session, userSession, clientSessionCtx)
                    .generateAccessToken().getAccessToken();
        });

        return token;
    }

    default String cleanAccessToken(AccessToken token, List<String> extraKeysToRemove, boolean isFullscope) throws JsonProcessingException {
        UserContextUtils userContextUtils = new UserContextUtils();
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        objectMapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.PUBLIC_ONLY);
        userContextUtils.normalizeAccessToken(token, isFullscope);
        JsonNode draftNode = objectMapper.valueToTree(token);
        return objectMapper.writeValueAsString(cleanProofDraft(draftNode, extraKeysToRemove));

    }

    /**
     * Saves a user context draft to the database.
     * This method creates a draft entity and persists it along with additional metadata, such as the record ID and proof draft.
     *
     * @param session    The Keycloak session for the current context.
     * @param em         The EntityManager for database interactions.
     * @param realm      The realm associated with the operation.
     * @param clientModel The client model for which the draft is being saved.
     * @param user       The user entity associated with the draft.
     * @param recordId   The record ID of the change set.
     * @param type       The type of the change set.
     * @param proofDraft The serialized proof draft as a JSON string.
     * @throws Exception If an error occurs during the save operation.
     */
    default void saveUserContextDraft(KeycloakSession session, EntityManager em, RealmModel realm, ClientModel clientModel, UserEntity user, String recordId, ChangeSetType type, String proofDraft) throws Exception {
        String clientId = clientModel != null ? clientModel.getId() : null;
        AccessProofDetailEntity newDetail = new AccessProofDetailEntity();
        newDetail.setId(KeycloakModelUtils.generateId());
        newDetail.setClientId(clientId);
        newDetail.setUser(user);
        newDetail.setRecordId(recordId);
        newDetail.setProofDraft(proofDraft);
        newDetail.setChangesetType(type);
        newDetail.setRealmId(realm.getId());
        em.persist(newDetail);
        em.flush();


        List<AccessProofDetailEntity> proofDetails = getUserContextDrafts(em, recordId, type);
        proofDetails.sort(Comparator.comparingLong(AccessProofDetailEntity::getCreatedTimestamp).reversed());
        ClientModel realmManagement = session.clients().getClientByClientId(realm, Constants.REALM_MANAGEMENT_CLIENT_ID);
        RoleModel tideRole = realmManagement.getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
        var tideIdp = session.identityProviders().getByAlias("tide");
        boolean hasInitCert;
        boolean isTideAdminRole;
        boolean isUnassignRole;
        UserModel originalUser;

        InitializerCertifcate cert = null;
        byte[] certHash = new byte[0];

        if (type.equals(ChangeSetType.USER_ROLE)) {
            TideUserRoleMappingDraftEntity roleMapping = (TideUserRoleMappingDraftEntity)IGAUtils.fetchDraftRecordEntityByRequestId(em, type, recordId);
            if (roleMapping == null) {
                throw new Exception("Invalid request, no user role mapping draft entity found for this record ID: " + recordId);
            }
            List<TideRoleDraftEntity> tideRoleDraftEntity = em.createNamedQuery("getRoleDraftByRoleId", TideRoleDraftEntity.class)
                    .setParameter("roleId", roleMapping.getRoleId()).getResultList();
            if(tideRoleDraftEntity.isEmpty()){
                throw new Exception("Invalid request, no role draft entity found for this role ID: " + roleMapping.getRoleId());
            }

            isTideAdminRole = tideRole != null && roleMapping.getRoleId().equals(tideRole.getId());

            RoleInitializerCertificateDraftEntity roleInitCert = getDraftRoleInitCert(session, recordId);

            hasInitCert = roleInitCert != null;
            ChangeSetRequest changeSetRequest = getChangeSetRequestFromEntity(session, roleMapping);
            isUnassignRole = changeSetRequest.getActionType().equals(ActionType.DELETE);
            originalUser = session.users().getUserById(realm, roleMapping.getUser().getId());
            ComponentModel componentModel = realm.getComponentsStream()
                    .filter(x -> "tide-vendor-key".equals(x.getProviderId()))  // Use .equals for string comparison
                    .findFirst()
                    .orElse(null);

            if(componentModel != null){
                List<AuthorizerEntity> realmAuthorizers = em.createNamedQuery("getAuthorizerByProviderIdAndTypes", AuthorizerEntity.class)
                        .setParameter("ID", componentModel.getId())
                        .setParameter("types", List.of("firstAdmin", "multiAdmin")).getResultList();

                if (realmAuthorizers.isEmpty()) {
                    throw new Exception("Authorizer not found for this realm.");
                }

                if(isTideAdminRole && realmAuthorizers.get(0).getType().equalsIgnoreCase("firstAdmin") && realmAuthorizers.size() == 1){
                    RoleEntity role = em.getReference(RoleEntity.class, tideRole.getId());

                    TideRoleDraftEntity tideRoleEntity = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class)
                            .setParameter("role", role).getSingleResult();
                    cert = InitializerCertifcate.FromString(tideRoleEntity.getInitCert());
                    certHash = cert.hash();
                }

                else if (hasInitCert) {
                    cert = InitializerCertifcate.FromString(roleInitCert.getInitCert());
                    certHash = cert.hash();
                }
            }
        } else {
            isTideAdminRole = false;
            hasInitCert = false;
            originalUser = null;
            isUnassignRole = false;
        }

        List<UserContext> userContexts = new ArrayList<>();
        UserContextSignRequest req = new UserContextSignRequest("Admin:1");


        InitializerCertifcate finalCert = cert;
        byte[] finalCertHash = certHash;

        proofDetails.forEach(p -> {
            UserContext userContext = new UserContext(p.getProofDraft());
            if (hasInitCert || isTideAdminRole) {
                try {
                    if(!isUnassignRole) {
                        userContext.setThreshold(finalCert.getPayload().getThreshold());
                        userContext.setInitCertHash(finalCertHash);
                    } else if (originalUser != null && !p.getUser().getId().equals(originalUser.getId())) {
                        userContext.setThreshold(finalCert.getPayload().getThreshold());
                        userContext.setInitCertHash(finalCertHash);
                    }
                    else {
                        userContext.setThreshold(0);
                        userContext.setInitCertHash(null);
                    }
                    p.setProofDraft(userContext.ToString());
                    em.flush();

                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
            userContexts.add(userContext);
        });

        AtomicInteger numberOfNormalUserContext = new AtomicInteger();
        userContexts.forEach( uc -> {
            if(uc.getInitCertHash() == null) {
                numberOfNormalUserContext.getAndIncrement();
            }
        });
        req.SetNumberOfUserContexts(numberOfNormalUserContext.get());

        if(hasInitCert || isTideAdminRole) { req.SetInitializationCertificate(finalCert); }

        // filter user contexts, admin contexts first then normal user context
        Stream<UserContext> normalUserContext = userContexts.stream().filter(x -> x.getInitCertHash() == null);
        Stream<UserContext> adminContexts = userContexts.stream().filter(x -> x.getInitCertHash() != null);
        List<UserContext> orderedContext = Stream.concat(adminContexts, normalUserContext).toList();

        req.SetUserContexts(orderedContext.toArray(new UserContext[0]));
        String draft = Base64.getEncoder().encodeToString(req.GetDraft());

        ChangeSetType changeSetType;
        if(type.equals(ChangeSetType.CLIENT_DEFAULT_USER_CONTEXT)){
            changeSetType = ChangeSetType.CLIENT_FULLSCOPE;
        }
        else if (type.equals(ChangeSetType.DEFAULT_ROLES)) {
            changeSetType = ChangeSetType.COMPOSITE_ROLE;
        }
        else{
            changeSetType = type;
        }

        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(recordId, changeSetType));
        if (changesetRequestEntity == null) {
            ChangesetRequestEntity entity = new ChangesetRequestEntity();
            entity.setChangesetRequestId(recordId);
            entity.setDraftRequest(draft);
            entity.setChangesetType(type);
            em.persist(entity);
            em.flush();
        } else {
            changesetRequestEntity.setDraftRequest(draft);
            em.flush();
        }
    }

    default void createChangeRequestEntity(EntityManager em, String recordId, ChangeSetType changeSetType) {
        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(recordId, changeSetType));
        if (changesetRequestEntity == null) {
            ChangesetRequestEntity entity = new ChangesetRequestEntity();
            entity.setChangesetRequestId(recordId);
            entity.setChangesetType(changeSetType);
            em.persist(entity);
            em.flush();
        }
    }


    void handleCreateRequest (KeycloakSession session, T entity, EntityManager em, Runnable callback) throws Exception;
    void handleDeleteRequest (KeycloakSession session, T entity, EntityManager em, Runnable callback) throws Exception;
    void updateAffectedUserContextDrafts(KeycloakSession session, AccessProofDetailEntity userContextDraft, Set<RoleModel> uniqRoles, ClientModel client, TideUserAdapter user, EntityManager em) throws Exception;
    RoleModel getRoleRequestFromEntity(KeycloakSession session, RealmModel realm, T entity);

    // Helper methods

    private void commitUserContextToDatabase(KeycloakSession session, AccessProofDetailEntity userContext, EntityManager em) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        ComponentModel componentModel = realm.getComponentsStream()
                .filter(x -> "tide-vendor-key".equals(x.getProviderId()))  // Use .equals for string comparison
                .findFirst()
                .orElse(null);

        if(componentModel == null) {
            throw new Exception("There is no tide-vendor-key component set up for this realm, " + realm.getName());
        }

        String accessProofSig = userContext.getSignature();
        if(accessProofSig == null || accessProofSig.isEmpty()){
            throw new Exception("Could not find authorization signature for this user context. Request denied.");
        }

        if(userContext.getChangesetType().equals(ChangeSetType.DEFAULT_ROLES) || userContext.getChangesetType().equals(ChangeSetType.CLIENT) || userContext.getChangesetType().equals(ChangeSetType.CLIENT_DEFAULT_USER_CONTEXT)) {
            ClientEntity clientEntity = em.find(ClientEntity.class, userContext.getClientId());
            TideClientDraftEntity defaultUserContext = em.createNamedQuery("getClientFullScopeStatus", TideClientDraftEntity.class).setParameter("client", clientEntity).getSingleResult();
            defaultUserContext.setDefaultUserContext(userContext.getProofDraft());
            defaultUserContext.setDefaultUserContextSig(accessProofSig);
            em.flush();
            return;
        }

        UserClientAccessProofEntity userClientAccess = em.find(UserClientAccessProofEntity.class, new UserClientAccessProofEntity.Key(userContext.getUser(), userContext.getClientId()));

        if (userClientAccess == null){
            UserClientAccessProofEntity newAccess = new UserClientAccessProofEntity();
            newAccess.setUser(userContext.getUser());
            newAccess.setClientId(userContext.getClientId());
            newAccess.setAccessProof(userContext.getProofDraft());
            newAccess.setAccessProofSig(accessProofSig);
            newAccess.setIdProofSig("");
            newAccess.setAccessProofMeta("");
            em.persist(newAccess);

        } else{
            userClientAccess.setAccessProof(userContext.getProofDraft());
            userClientAccess.setAccessProofMeta("");
            userClientAccess.setAccessProofSig(accessProofSig);
            userClientAccess.setIdProofSig("");
            em.merge(userClientAccess);
        }
    }

    private<R> R sessionAware(KeycloakSession session, RealmModel realm, ClientModel client, UserModel user, String scopeParam, BiFunction<UserSessionModel, ClientSessionContext,R> function) {
        session.getContext().setClient(client);
        session.getContext().setRealm(realm);
        AuthenticationSessionModel authSession = null;
        AuthenticationSessionManager authSessionManager = new AuthenticationSessionManager(session);
        URI uri = session.getContext().getUri().getBaseUri();
        ClientConnection clientConnection = session.getContext().getConnection();

        try {
            RootAuthenticationSessionModel rootAuthSession = authSessionManager.createAuthenticationSession(realm, false);
            authSession = rootAuthSession.createAuthenticationSession(client);

            authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
            authSession.setClientNote(OIDCLoginProtocol.ISSUER, Urls.realmIssuer(uri, realm.getName()));
            authSession.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, scopeParam);

            UserSessionModel userSession = new UserSessionManager(session).createUserSession(authSession.getParentSession().getId(), realm, user, user.getUsername(),
                    clientConnection.getRemoteAddr(), "example-auth", false, null, null, UserSessionModel.SessionPersistenceState.TRANSIENT);

            AuthenticationManager.setClientScopesInSession(session, authSession);
            ClientSessionContext clientSessionCtx = TokenManager.attachAuthenticationSession(session, userSession, authSession);

            return function.apply(userSession, clientSessionCtx);

        } finally {
            if (authSession != null) {
                authSessionManager.removeAuthenticationSession(realm, authSession, false);
            }
        }
    }

    private JsonNode cleanProofDraft (JsonNode token, List<String> keysToRemove) throws JsonProcessingException {
        ObjectNode object = (ObjectNode) token;

        // Remove what we don't need
        object.remove("exp");
        object.remove("iat");
        object.remove("jti");
        object.remove("sid");
        object.remove("auth_time");
        object.remove("session_state");
        object.remove("given_name");
        object.remove("family_name");
        object.remove("email_verified");
        object.remove("email_verified");
        object.remove("email");
        object.remove("name");
        object.remove("typ");

        // Removing ACR for now. This changes by the type of authenticate taken. Explicit login is 1 and "remembered" session is 0.
        object.remove("acr");

        if (keysToRemove != null && !keysToRemove.isEmpty()){
            keysToRemove.forEach(object::remove);
        }

        return JsonSorter.parseAndSortArrays(object.toString());
    }

    /**
     * @return filtered set of roles based on Client settings. If client is full scoped returns back everything else remove out of scope roles.
     */
    private static Set<RoleModel> filterClientRoles(Set<RoleModel> roleModels, ClientModel client, Stream<ClientScopeModel> clientScopes, Boolean isFullScopeAllowed) {
        if (!isFullScopeAllowed) {

            // 1 - Client roles of this client itself
            Stream<RoleModel> scopeMappings = client.getRolesStream();

            // 2 - Role mappings of client itself + default client scopes + optional client scopes requested by scope parameter (if applyScopeParam is true)
            Stream<RoleModel> clientScopesMappings;
            clientScopesMappings = clientScopes.flatMap(ScopeContainerModel::getScopeMappingsStream);

            scopeMappings = Stream.concat(scopeMappings, clientScopesMappings);

            // 3 - Expand scope mappings
            scopeMappings = RoleUtils.expandCompositeRolesStream(scopeMappings);

            // Intersection of expanded user roles and expanded scopeMappings
            roleModels.retainAll(scopeMappings.collect(Collectors.toSet()));

        }
        return roleModels;
    }
}
