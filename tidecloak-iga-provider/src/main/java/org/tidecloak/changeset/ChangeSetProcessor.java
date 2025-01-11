package org.tidecloak.changeset;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.util.MultivaluedHashMap;
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
import org.tidecloak.changeset.models.ChangeSetRequest;
import org.keycloak.representations.AccessToken;
import org.tidecloak.changeset.utils.TideEntityUtils;
import org.tidecloak.enums.WorkflowType;
import org.tidecloak.enums.models.WorkflowParams;
import org.tidecloak.enums.ChangeSetType;
import org.tidecloak.enums.DraftStatus;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.AuthorizerEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.UserClientAccessProofEntity;
import org.tidecloak.jpa.entities.drafting.*;
import org.tidecloak.models.ChangesetRequestAdapter;
import org.tidecloak.models.TideUserAdapter;
import org.tidecloak.utils.AccessDetails;
import org.tidecloak.utils.TideRolesUtil;
import org.tidecloak.models.TideClientAdapter;
import org.tidecloak.models.TideRoleAdapter;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.tidecloak.enums.ActionType;


import java.net.URI;
import java.util.*;
import java.util.function.BiFunction;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.tidecloak.TideRequests.TideRoleRequests.tideRealmAdminRole;
import static org.tidecloak.changeset.utils.ChangeRequestUtils.getChangeSetRequestFromEntity;
import static org.tidecloak.changeset.utils.UserContextUtils.getUserContextDrafts;

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
        ChangeSetRequest change = getChangeSetRequestFromEntity(session, entity);

        switch (workflow) {
            case APPROVAL:
                approve(session, change, entity, em, params.getDraftStatus(), params.isDelete());
                break;
            case COMMIT:
                commit(session, change, entity, em, null);
                break;
            case REQUEST:
                request(session, entity, em, params.getActionType(), callback);
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
    default void request(KeycloakSession session, T mapping, EntityManager em, ActionType action, Runnable callback) throws Exception {
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
    default void updateAffectedUserContexts(KeycloakSession session, ChangeSetRequest change, T entity, EntityManager em) throws Exception {
        List<ClientModel> affectedClients = getAffectedClients(session, entity, em);
        RealmModel realm = session.getContext().getRealm();
        ChangeSetProcessorFactory processorFactory = new ChangeSetProcessorFactory(); // Initialize the processor factory

        for (ClientModel client : affectedClients) {

            List<AccessProofDetailEntity> userContextDrafts = getUserContextDrafts(em, client)
                    .stream()
                    .filter(proof -> !Objects.equals(proof.getRecordId(), change.getChangeSetId()))
                    .toList();

            for(AccessProofDetailEntity userContextDraft : userContextDrafts) {
                em.lock(userContextDraft, LockModeType.PESSIMISTIC_WRITE);
                UserEntity userEntity = userContextDraft.getUser();
                TideUserAdapter user = TideEntityUtils.toTideUserAdapter(userEntity, session, realm);

                Set<RoleModel> roleSet = new HashSet<>();
                roleSet.add(getRoleRequestFromEntity(session, entity));
                var uniqRoles = roleSet.stream().distinct().filter(Objects::nonNull).collect(Collectors.toSet());

                processorFactory.getProcessor(userContextDraft.getChangesetType()).updateAffectedUserContextDrafts(session, userContextDraft, uniqRoles, client, user, em);
                ChangesetRequestEntity changesetRequestEntity = ChangesetRequestAdapter.getChangesetRequestEntity(session, userContextDraft.getRecordId());
                if (changesetRequestEntity != null){
                    changesetRequestEntity.setAdminAuthorizations(List.of()); // empty sigs!
                }
            }

            // Group proofDetails by changeRequestId
            Map<String, List<AccessProofDetailEntity>> groupedProofDetails = userContextDrafts.stream()
                    .collect(Collectors.groupingBy(AccessProofDetailEntity::getRecordId));

            // Process each group
            groupedProofDetails.forEach((changeRequestId, details) -> {
                try {
                    // Create a list of UserContext for the current changeRequestId
                    List<UserContext> userContexts = details.stream()
                            .map(p -> new UserContext(p.getProofDraft()))
                            .collect(Collectors.toList());

                    // Create UserContextSignRequest
                    UserContextSignRequest updatedReq = new UserContextSignRequest("Admin:1");
                    updatedReq.SetUserContexts(userContexts.toArray(new UserContext[0]));

                    ChangesetRequestEntity changesetRequestEntity = ChangesetRequestAdapter.getChangesetRequestEntity(session, changeRequestId);
                    changesetRequestEntity.setDraftRequest(Base64.getEncoder().encodeToString(updatedReq.GetDraft()));
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
        }
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
        // Retrieve the user context drafts
        List<AccessProofDetailEntity> userContextDrafts = getUserContextDrafts(em, change.getChangeSetId());

        if (userContextDrafts.isEmpty()) {
            throw new Exception("No user context drafts found for this change set id, " + change.getChangeSetId());
        }

        // Process each user context draft
        for (AccessProofDetailEntity userContextDraft : userContextDrafts) {
            try {
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
            em.flush();
        }

        // Update affected user contexts
        updateAffectedUserContexts(session, change, entity, em);
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
    default List<ClientModel> getAffectedClients(KeycloakSession session, T entity, EntityManager em) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        Set<ClientModel> affectedClients = new HashSet<>();

        // Add clients with full scope or draft scope
        realm.getClientsStream()
                .map(client -> new TideClientAdapter(realm, em, session, em.getReference(ClientEntity.class, client.getId())))
                .filter(clientModel -> {
                    ClientEntity clientEntity = em.find(ClientEntity.class, clientModel.getId());
                    List<TideClientFullScopeStatusDraftEntity> scopeDrafts = em.createNamedQuery("getClientFullScopeStatusByFullScopeEnabledStatus", TideClientFullScopeStatusDraftEntity.class)
                            .setParameter("client", clientEntity)
                            .setParameter("fullScopeEnabled", DraftStatus.DRAFT)
                            .getResultList();
                    return clientModel.isFullScopeAllowed() || (scopeDrafts != null && !scopeDrafts.isEmpty());
                })
                .forEach(affectedClients::add);

        // Add clients based on role-specific logic
        RoleModel role = getRoleRequestFromEntity(session, entity);
        if (role != null) {
            if (role.isClientRole()) {
                ClientModel client = realm.getClientById(role.getContainerId());
                if (client != null) {
                    affectedClients.add(client);
                }
            }

            if (role.isComposite()) {
                RoleEntity roleEntity = em.getReference(RoleEntity.class, role.getId());
                Set<TideRoleAdapter> wrappedRoles = Set.of(new TideRoleAdapter(session, realm, em, roleEntity));
                Set<RoleModel> activeRoles = TideRolesUtil.expandCompositeRoles(wrappedRoles, DraftStatus.ACTIVE);

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
            MultivaluedHashMap<String, String> config = componentModel.getConfig();
            List<AuthorizerEntity> realmAuthorizers = em.createNamedQuery("getAuthorizerByProviderId", AuthorizerEntity.class)
                    .setParameter("ID", componentModel.getId())
                    .getResultList();

            if (realmAuthorizers.isEmpty()) {
                throw new Exception("Authorizer not found for this realm.");
            }

            // Remove specific clients if no "firstAdmin" authorizer exists
            if (realmAuthorizers.stream().noneMatch(authorizer -> "firstAdmin".equalsIgnoreCase(authorizer.getType()))) {
                affectedClients.removeIf(client ->
                        Constants.ADMIN_CONSOLE_CLIENT_ID.equals(client.getClientId()) ||
                                Constants.ADMIN_CLI_CLIENT_ID.equals(client.getClientId())
                );
            }
        }

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
            UserModel user

    ) {
        return token;
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
    default String generateTransformedUserContext(KeycloakSession session, RealmModel realm, ClientModel client, UserModel user, String scopeParam, T entity) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        objectMapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.PUBLIC_ONLY);
        ChangeSetProcessorFactory processorFactory = new ChangeSetProcessorFactory();

        session.getContext().setClient(client);
        AccessToken token = sessionAware(session, realm, client, user, scopeParam, (userSession, clientSessionCtx) -> {
            TokenManager tokenManager = new TokenManager();
            return tokenManager.responseBuilder(realm, client, null, session, userSession, clientSessionCtx)
                    .generateAccessToken().getAccessToken();
        });

        String tideUserKey = user.getFirstAttribute("tideUserKey");
        String vuid = user.getFirstAttribute("vuid");

        if (tideUserKey != null) {
            token.getOtherClaims().put("tideuserkey", tideUserKey);
        }
        if (vuid != null) {
            token.getOtherClaims().put("vuid", vuid);
        }

        ChangeSetRequest changeSetRequest = getChangeSetRequestFromEntity(session, entity);
        AccessToken userContext = processorFactory.getProcessor(changeSetRequest.getType()).transformUserContext(token, session, entity, user);
        JsonNode draftNode = objectMapper.valueToTree(userContext);
        return objectMapper.writeValueAsString(cleanProofDraft(draftNode));
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
        session.getContext().setClient(client);

        AccessToken token = sessionAware(session, realm, client, user, "openid", (userSession, clientSessionCtx) -> {
            TokenManager tokenManager = new TokenManager();
            return tokenManager.responseBuilder(realm, client, null, session, userSession, clientSessionCtx)
                    .generateAccessToken().getAccessToken();
        });

        String tideUserKey = user.getFirstAttribute("tideUserKey");
        String vuid = user.getFirstAttribute("vuid");

        // Add claims to the token
        if (tideUserKey != null) {
            token.getOtherClaims().put("tideuserkey", tideUserKey);
        }
        if (vuid != null) {
            token.getOtherClaims().put("vuid", vuid);
        }

        JsonNode draftNode = objectMapper.valueToTree(token);
        return objectMapper.writeValueAsString(cleanProofDraft(draftNode));
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
    private void saveUserContextDraft(KeycloakSession session, EntityManager em, RealmModel realm, ClientModel clientModel, UserEntity user, String recordId, ChangeSetType type, String proofDraft) throws Exception {
        AccessProofDetailEntity newDetail = new AccessProofDetailEntity();
        newDetail.setId(KeycloakModelUtils.generateId());
        newDetail.setClientId(clientModel.getId());
        newDetail.setUser(user);
        newDetail.setRecordId(recordId);
        newDetail.setProofDraft(proofDraft);
        newDetail.setChangesetType(type);
        em.persist(newDetail);

        List<AccessProofDetailEntity> proofDetails = getUserContextDrafts(em, recordId);
        RoleModel tideRole = session.clients().getClientByClientId(realm, Constants.REALM_MANAGEMENT_CLIENT_ID).getRole(tideRealmAdminRole);

        boolean isAssigningTideAdminRole;
        if (type.equals(ChangeSetType.USER_ROLE)) {
            TideUserRoleMappingDraftEntity roleMapping = em.find(TideUserRoleMappingDraftEntity.class, recordId);
            if (roleMapping == null) {
                throw new Exception("Invalid request, no user role mapping draft entity found for this record ID: " + recordId);
            }
            isAssigningTideAdminRole = roleMapping.getRoleId().equals(tideRole.getId());
        } else {
            isAssigningTideAdminRole = false;
        }

        List<UserContext> userContexts = new ArrayList<>();
        UserContextSignRequest req = new UserContextSignRequest("VRK:1");

        proofDetails.forEach(p -> {
            UserContext userContext = new UserContext(p.getProofDraft());
            if (isAssigningTideAdminRole) {
                try {
                    RoleEntity role = em.getReference(RoleEntity.class, tideRole.getId());
                    TideRoleDraftEntity tideRoleEntity = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class)
                            .setParameter("role", role).getSingleResult();

                    InitializerCertifcate cert = InitializerCertifcate.FromString(tideRoleEntity.getInitCert());
                    userContext.setInitCertHash(cert.hash());
                    p.setProofDraft(userContext.ToString());
                    em.flush();
                    req.SetInitializationCertificate(cert);

                } catch (JsonProcessingException e) {
                    throw new RuntimeException(e);
                }
            }
            userContexts.add(userContext);
        });
        req.SetUserContexts(userContexts.toArray(new UserContext[0]));
        String draft = Base64.getEncoder().encodeToString(req.GetDraft());

        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, recordId);
        if (changesetRequestEntity == null) {
            ChangesetRequestEntity entity = new ChangesetRequestEntity();
            entity.setChangesetRequestId(recordId);
            entity.setAdminAuthorizations(new ArrayList<>());
            entity.setDraftRequest(draft);
            em.persist(entity);
            em.flush();
        } else {
            changesetRequestEntity.setDraftRequest(draft);
            em.flush();
        }
    }


    void handleCreateRequest (KeycloakSession session, T entity, EntityManager em, Runnable callback) throws Exception;
    void handleDeleteRequest (KeycloakSession session, T entity, EntityManager em, Runnable callback) throws Exception;
    void updateAffectedUserContextDrafts(KeycloakSession session, AccessProofDetailEntity userContextDraft, Set<RoleModel> uniqRoles, ClientModel client, TideUserAdapter user, EntityManager em) throws Exception;
    RoleModel getRoleRequestFromEntity(KeycloakSession session, T entity);

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
        UserClientAccessProofEntity userClientAccess = em.find(UserClientAccessProofEntity.class, new UserClientAccessProofEntity.Key(userContext.getUser(), userContext.getClientId()));
        if(accessProofSig == null || accessProofSig.isEmpty()){
            throw new Exception("Could not find authorization signature for this user context. Request denied.");
        }

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
        AuthenticationSessionModel authSession = null;
        AuthenticationSessionManager authSessionManager = new AuthenticationSessionManager(session);
        URI uri = session.getContext().getUri().getBaseUri();
        ClientConnection clientConnection = session.getContext().getConnection();

        try {
            RootAuthenticationSessionModel rootAuthSession = authSessionManager.createAuthenticationSession(realm, false);
            authSession = rootAuthSession.createAuthenticationSession(client);

            authSession.setAuthenticatedUser(user);
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

    private JsonNode cleanProofDraft (JsonNode token) throws JsonProcessingException {
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


    private static AccessDetails sortAccessRoles(Set<RoleModel> roles){
        AccessToken.Access realmAccess = new AccessToken.Access();
        Map<String, AccessToken.Access> clientAccesses = new HashMap<>();

        // Organize roles into realm and client accesses
        for (RoleModel role : roles) {
            if (role.getContainer() instanceof RealmModel) {
                realmAccess.addRole(role.getName());
            } else if (role.getContainer() instanceof ClientModel client) {
                clientAccesses.computeIfAbsent(client.getClientId(), k -> new AccessToken.Access())
                        .addRole(role.getName());
            }
        }
        return new AccessDetails(realmAccess, clientAccesses);
    }

    private static void setTokenClaims(AccessToken token, AccessDetails accessRoles, ActionType actionType) {

        if (actionType == ActionType.DELETE){
            // Handle deletion of realm and client roles
            removeRealmAccess(token, accessRoles.getRealmAccess());
            removeClientAccesses(token, accessRoles.getClientAccesses());
        }else{
            // Add or update realm access in the token
            mergeRealmAccess(token, accessRoles.getRealmAccess());
            // Add or update client accesses in the token
            mergeClientAccesses(token, accessRoles.getClientAccesses());
        }
    }

    private static void removeRealmAccess(AccessToken token, AccessToken.Access realmAccess) {
        if (token.getRealmAccess() != null && realmAccess != null && realmAccess.getRoles() != null) {
            token.getRealmAccess().getRoles().removeAll(realmAccess.getRoles());
        }
    }

    private static void removeClientAccesses(AccessToken token, Map<String, AccessToken.Access> clientAccesses) {
        if (token.getResourceAccess() != null && clientAccesses != null) {
            clientAccesses.forEach((clientKey, access) -> {
                if (access != null && access.getRoles() != null) {
                    AccessToken.Access tokenClientAccess = token.getResourceAccess().get(clientKey);
                    if (tokenClientAccess != null) {
                        tokenClientAccess.getRoles().removeAll(access.getRoles());
                    }
                }
            });
        }
    }
    private static void mergeRealmAccess(AccessToken token, AccessToken.Access realmAccess) {
        if (realmAccess != null && realmAccess.getRoles() != null && !realmAccess.getRoles().isEmpty()) {
            if (token.getRealmAccess() == null) {
                token.setRealmAccess(new AccessToken.Access());
            }
            realmAccess.getRoles().forEach(role -> token.getRealmAccess().addRole(role));
        }
    }

    private static void mergeClientAccesses(AccessToken token, Map<String, AccessToken.Access> clientAccesses) {
        if (clientAccesses != null && !clientAccesses.isEmpty()) {
            // Ensure the resource access map is modifiable
            Map<String, AccessToken.Access> resourceAccess = token.getResourceAccess();
            if (resourceAccess == null || resourceAccess.isEmpty()) {
                resourceAccess = new HashMap<>();
                token.setResourceAccess(resourceAccess);
            }

            Map<String, AccessToken.Access> finalResourceAccess = resourceAccess;
            clientAccesses.forEach((clientKey, access) -> {
                AccessToken.Access tokenClientAccess = finalResourceAccess.computeIfAbsent(clientKey, k -> new AccessToken.Access());
                if (access.getRoles() != null) {
                    access.getRoles().forEach(tokenClientAccess::addRole);
                }
            });
        }
    }
    private static JsonNode removeAccessFromJsonNode(JsonNode originalNode, AccessDetails accessDetails) {
        if (!(originalNode instanceof ObjectNode)) {
            throw new IllegalArgumentException("Expected an ObjectNode for originalNode.");
        }

        ObjectNode modifiedNode = ((ObjectNode) originalNode).deepCopy();

        // Handle realm access removal
        AccessToken.Access realmAccess = accessDetails.getRealmAccess();
        ObjectNode realmAccessNode = (ObjectNode) modifiedNode.get("realm_access");
        if (realmAccessNode != null && realmAccessNode.has("roles")) {
            removeRolesFromArrayNode(realmAccessNode, "roles", realmAccess.getRoles());

            // Check if realm_access node is now empty and remove it
            if (!realmAccessNode.has("roles") || !realmAccessNode.get("roles").elements().hasNext()) {
                modifiedNode.remove("realm_access");
            }
        }

        // Handle client accesses removal
        ObjectNode resourceAccessNode = (ObjectNode) modifiedNode.get("resource_access");
        if (resourceAccessNode != null) {
            // Iterate over each client access to remove roles and potentially the client object
            accessDetails.getClientAccesses().forEach((clientId, access) -> {
                ObjectNode clientNode = (ObjectNode) resourceAccessNode.get(clientId);
                if (clientNode != null && clientNode.has("roles")) {
                    removeRolesFromArrayNode(clientNode, "roles", access.getRoles());

                    // Check if the client node is now empty and remove it from the resource access
                    if (!clientNode.has("roles") || !clientNode.get("roles").elements().hasNext()) {
                        resourceAccessNode.remove(clientId); // Remove the client node if it's empty
                    }
                }
            });

            // Check if resource_access node is now empty and remove it
            if (!resourceAccessNode.fieldNames().hasNext()) {
                modifiedNode.remove("resource_access");
            }
        }

        return modifiedNode;
    }
    private static void removeRolesFromArrayNode(ObjectNode parentNode, String key, Set<String> rolesToRemove) {
        if (parentNode == null || !parentNode.has(key) || rolesToRemove == null || rolesToRemove.isEmpty()) {
            return; // Nothing to remove if input is empty or null or key does not exist
        }

        ArrayNode arrayNode = (ArrayNode) parentNode.get(key);
        ArrayNode resultNode = arrayNode.deepCopy().arrayNode();

        // Filter out roles to remove
        arrayNode.forEach(jsonNode -> {
            if (!rolesToRemove.contains(jsonNode.asText())) {
                resultNode.add(jsonNode);
            }
        });

        // Update the parentNode
        if (!resultNode.isEmpty()) {
            parentNode.set(key, resultNode);
        } else {
            parentNode.remove(key); // Remove the key entirely if no roles are left
        }
    }
}
