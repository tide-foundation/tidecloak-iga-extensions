package org.tidecloak.jpa.utils;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.persistence.EntityManager;
import org.keycloak.common.ClientConnection;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.managers.UserSessionManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.tidecloak.interfaces.ActionType;
import org.tidecloak.interfaces.ChangeSetType;
import org.tidecloak.interfaces.DraftStatus;
import org.tidecloak.jpa.entities.AccessProofDetailDependencyEntity;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.function.BiFunction;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import static org.tidecloak.AdminRealmResource.TideAdminRealmResource.getAccess;
import static org.tidecloak.AdminRealmResource.TideAdminRealmResource.setTokenClaims;

public final class TideAuthzProofUtil {

    private final KeycloakSession session;
    private final RealmModel realm;
    private  final EntityManager em;
    private static final ObjectMapper objectMapper = new ObjectMapper();

    public TideAuthzProofUtil(KeycloakSession session, RealmModel realm, EntityManager em) {
        this.session = session;
        this.realm = realm;
        this.em = em;
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        objectMapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);
    }
    /**
     * @return filtered set of roles based on Client settings. If client is full scoped returns back everything else remove out of scope roles.
     */
    public static Set<RoleModel> filterClientRoles(Set<RoleModel> roleModels, ClientModel client, Stream<ClientScopeModel> clientScopes) {
        if (!client.isFullScopeAllowed()) {

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

    public static AccessDetails sortAccessRoles(Set<RoleModel> roles){
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

    public static void setTokenClaims(AccessToken token, AccessDetails accessRoles, ActionType actionType) {

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

    public void generateAndSaveProofDraft(ClientModel clientModel, UserModel userModel, Set<RoleModel> newRoleMappings, String recordId, ChangeSetType type, ActionType actionType) throws JsonProcessingException {
        // Generate AccessToken based on the client and user information with openid scope
        AccessToken proof = generateAccessToken(clientModel, userModel, "openid");

        // Filter and expand roles based on the provided mappings; only approved roles are considered
        Set<RoleModel> activeRoles = TideRolesUtil.expandCompositeRoles(newRoleMappings, DraftStatus.APPROVED, ActionType.CREATE);
        Set<RoleModel> requestedAccess = filterClientRoles(activeRoles, clientModel, clientModel.getClientScopes(false).values().stream());
        UserEntity user = TideRolesUtil.toUserEntity(userModel, em);
        List<AccessProofDetailEntity> proofDetails = fetchProofDetails(clientModel.getId(), user);
        AccessDetails accessDetails = sortAccessRoles(requestedAccess);

        // Apply the filtered roles to the AccessToken
        setTokenClaims(proof, accessDetails, actionType);

        JsonNode proofDraftNode = objectMapper.valueToTree(proof);



        String proofDraft = processProofDetails(proofDetails, proofDraftNode, recordId, type, em, actionType, accessDetails);

        // Always save the access proof detail
        saveAccessProofDetail(clientModel, user, recordId, type, proofDraft, System.currentTimeMillis());
    }

    private String processProofDetails(List<AccessProofDetailEntity> proofDetails, JsonNode proofDraftNode, String recordId, ChangeSetType type, EntityManager em, ActionType actionType, AccessDetails accessDetails) throws JsonProcessingException {
        if (proofDetails.isEmpty()) {
            handleNewProofDependencies(recordId, type, em);
            return cleanProofDraft(proofDraftNode); // Return clean proof draft without merging
        }
        else {
            AccessProofDetailEntity latestProof = proofDetails.get(0);
            JsonNode latestProofNode = objectMapper.readTree(latestProof.getProofDraft());

            JsonNode draft;
            if (actionType == ActionType.DELETE){
                System.out.println("HELLO WE ARE TRYING TO DELETE");
                draft = removeAccessFromJsonNode(latestProofNode, accessDetails);
            }
            else{
                draft = mergeJsonNodes(latestProofNode, proofDraftNode);
            }


            updateDependencyIfNeeded(latestProof, recordId, type, em);
            return cleanProofDraft(draft); // Return cleaned proof draft
        }
    }

    private void handleNewProofDependencies(String recordId, ChangeSetType type, EntityManager em) {
        AccessProofDetailDependencyEntity dependency = em.find(AccessProofDetailDependencyEntity.class, new AccessProofDetailDependencyEntity.Key(recordId, type));
        if (dependency == null) {
            AccessProofDetailDependencyEntity newDependency = new AccessProofDetailDependencyEntity();
            newDependency.setRecordId(recordId);
            newDependency.setChangesetType(type);
            em.persist(newDependency);
        }
    }

    private void updateDependencyIfNeeded(AccessProofDetailEntity latestProof, String recordId, ChangeSetType type, EntityManager em) {
        AccessProofDetailDependencyEntity dependency = em.find(AccessProofDetailDependencyEntity.class, new AccessProofDetailDependencyEntity.Key(recordId, type));
        if (dependency == null) {
            AccessProofDetailDependencyEntity newDependency = new AccessProofDetailDependencyEntity();
            newDependency.setRecordId(recordId);
            newDependency.setChangesetType(type);
            newDependency.setForkedRecordId(latestProof.getRecordId());
            newDependency.setForkedChangeSetType(latestProof.getChangesetType());
            em.persist(newDependency);
        }
    }

    private void saveAccessProofDetail(ClientModel clientModel, UserEntity user, String recordId, ChangeSetType type, String proofDraft, long timestamp) {
        AccessProofDetailEntity newDetail = new AccessProofDetailEntity();
        newDetail.setId(KeycloakModelUtils.generateId());
        newDetail.setClientId(clientModel.getId());
        newDetail.setUser(user);
        newDetail.setRecordId(recordId);
        newDetail.setProofDraft(proofDraft);
        newDetail.setChangesetType(type);
        newDetail.setCreatedTimestamp(timestamp);
        em.persist(newDetail);
    }

    private List<AccessProofDetailEntity> fetchProofDetails(String clientId, UserEntity user) {
        return em.createNamedQuery("getProofDetailsForUserByClient", AccessProofDetailEntity.class)
                .setParameter("user", user)
                .setParameter("clientId", clientId)
                .getResultList();
    }

    public String generateChangeChecksum(String proofDraft, TideUserRoleMappingDraftEntity draftUserRole) throws JsonProcessingException, NoSuchAlgorithmException {

        TideUserRoleMappingDraftEntity temp = new TideUserRoleMappingDraftEntity();
        temp.setId(draftUserRole.getId());
        temp.setUser(draftUserRole.getUser());
        temp.setRoleId(draftUserRole.getRoleId());
        temp.setAction(draftUserRole.getAction());
        temp.setDraftStatus(draftUserRole.getDraftStatus());

        JsonNode tempNode = objectMapper.valueToTree(temp);
        // Sort draft record
        var sortedTemp = sortJsonNode(tempNode);
        String draftRecord = objectMapper.writeValueAsString(sortedTemp);
        String change = proofDraft.concat(draftRecord);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] changeBytes = digest.digest(
                change.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(changeBytes);
    }

    public AccessToken generateAccessToken(ClientModel client, UserModel user, String scopeParam){
        return sessionAware(client, user, scopeParam, (userSession, clientSessionCtx) -> {
            TokenManager tokenManager = new TokenManager();
            return tokenManager.responseBuilder(realm, client, null, session, userSession, clientSessionCtx)
                    .generateAccessToken().getAccessToken();
        });

    }

    public static JsonNode sortJsonNode(JsonNode jsonNode) {
        if (jsonNode.isObject()) {
            ObjectNode sortedObject = objectMapper.createObjectNode();


            // Sort field names and directly insert into sortedObject
            StreamSupport.stream(Spliterators.spliteratorUnknownSize(jsonNode.fieldNames(), Spliterator.ORDERED), false)
                    .sorted()
                    .forEachOrdered(key -> sortedObject.set(key, sortJsonNode(jsonNode.get(key))));

            return sortedObject;
        } else if (jsonNode.isArray()) {
            ArrayNode arrayNode = objectMapper.createArrayNode();
            // Recursively sort elements of the array and handle string arrays for sorting
            if (!jsonNode.isEmpty() && jsonNode.get(0).isTextual()) {
                List<String> sortedList = StreamSupport.stream(jsonNode.spliterator(), false)
                        .map(JsonNode::asText)
                        .sorted()
                        .toList();
                sortedList.forEach(arrayNode::add);
            } else {
                jsonNode.forEach(item -> arrayNode.add(sortJsonNode(item)));
            }
            return arrayNode;
        } else {
            return jsonNode;
        }
    }

    // This is used to merged previous generate draft tokens with the newly created one.
    public static JsonNode mergeJsonNodes(JsonNode node1, JsonNode node2) {
        if (node1.isObject() && node2.isObject()) {
            ObjectNode mergedNode = ((ObjectNode) node1).deepCopy();
            ObjectNode object2 = (ObjectNode) node2;

            object2.fields().forEachRemaining(entry -> {
                String key = entry.getKey();
                JsonNode value = entry.getValue();

                if (mergedNode.has(key) && mergedNode.get(key).isContainerNode() && value.isContainerNode()) {
                    mergedNode.set(key, mergeJsonNodes(mergedNode.get(key), value));
                } else {
                    mergedNode.set(key, value);
                }
            });

            return mergedNode;
        } else if (node1.isArray() && node2.isArray()) {
            ArrayNode array1 = (ArrayNode) node1;
            ArrayNode array2 = (ArrayNode) node2;
            ArrayNode mergedArray = array1.deepCopy();
            array2.forEach(item -> {
                if (!containsNode(mergedArray, item)) {
                    mergedArray.add(item);
                }
            });
            return mergedArray;
        } else {
            throw new IllegalArgumentException("Both nodes must be either ObjectNodes or ArrayNodes");
        }
    }



    private static boolean containsNode(ArrayNode array, JsonNode item) {
        for (JsonNode node : array) {
            if (node.equals(item)) {
                return true;
            }
        }
        return false;
    }

    public static JsonNode removeAccessFromJsonNode(JsonNode originalNode, AccessDetails accessDetails) {
        if (!(originalNode instanceof ObjectNode)) {
            throw new IllegalArgumentException("Expected an ObjectNode for originalNode.");
        }

        ObjectNode modifiedNode = ((ObjectNode) originalNode).deepCopy();

        // Handle realm access removal
        AccessToken.Access realmAccess = accessDetails.getRealmAccess();
        ObjectNode realmAccessNode = (ObjectNode) modifiedNode.get("realm_access");
        if (realmAccessNode != null && realmAccessNode.has("roles")) {
            removeRolesFromArrayNode(realmAccessNode, "roles", realmAccess.getRoles());
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
                    if (!clientNode.fieldNames().hasNext()) {
                        resourceAccessNode.remove(clientId); // Remove the client node if it's empty
                    }
                }
            });
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
        if (resultNode.size() > 0) {
            parentNode.set(key, resultNode);
        } else {
            parentNode.remove(key); // Remove the key entirely if no roles are left
        }
    }


    private<R> R sessionAware(ClientModel client, UserModel user, String scopeParam, BiFunction<UserSessionModel, ClientSessionContext,R> function) {
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

            AuthenticationManager.setClientScopesInSession(authSession);
            ClientSessionContext clientSessionCtx = TokenManager.attachAuthenticationSession(session, userSession, authSession);

            return function.apply(userSession, clientSessionCtx);

        } finally {
            if (authSession != null) {
                authSessionManager.removeAuthenticationSession(realm, authSession, false);
            }
        }
    }

    private String cleanProofDraft (JsonNode token) {
        try{
            ObjectNode object = (ObjectNode) token;

            // Remove what we don't need
            object.remove("exp");
            object.remove("iat");
            object.remove("jti");
            object.remove("sid");
            object.remove("auth_time");
            object.remove("session_state");
            // Removing ACR for now. This changes by the type of authenticate taken. Explicit login is 1 and "remembered" session is 0.
            object.remove("acr");

            JsonNode sortedJson = sortJsonNode(object);

            return objectMapper.writeValueAsString(sortedJson);
        }
        catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to process token", e);
        }
    }
    private static void mergeRealmAccess(AccessToken token, AccessToken.Access realmAccess) {
        if (realmAccess.getRoles() != null && !realmAccess.getRoles().isEmpty()) {
            if (token.getRealmAccess() == null) {
                token.setRealmAccess(realmAccess);
            } else {
                token.getRealmAccess().getRoles().addAll(realmAccess.getRoles());
            }
        }
    }

    private static void mergeClientAccesses(AccessToken token, Map<String, AccessToken.Access> clientAccesses) {
        clientAccesses.forEach((clientKey, access) -> {
            AccessToken.Access tokenClientAccess = token.getResourceAccess().computeIfAbsent(clientKey, k -> new AccessToken.Access());
            if (access.getRoles() != null) {
                tokenClientAccess.getRoles().addAll(access.getRoles());
            }
        });
    }
    private static void removeRealmAccess(AccessToken token, AccessToken.Access realmAccess) {
        if (token.getRealmAccess() != null && realmAccess.getRoles() != null) {
            token.getRealmAccess().getRoles().removeAll(realmAccess.getRoles());
        }
    }

    private static void removeClientAccesses(AccessToken token, Map<String, AccessToken.Access> clientAccesses) {
        clientAccesses.forEach((clientKey, access) -> {
            if (token.getResourceAccess().containsKey(clientKey) && access.getRoles() != null) {
                token.getResourceAccess().get(clientKey).getRoles().removeAll(access.getRoles());
            }
        });
    }


}

