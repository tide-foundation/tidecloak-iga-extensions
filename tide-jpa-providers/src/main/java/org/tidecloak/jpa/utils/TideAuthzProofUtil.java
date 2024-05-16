package org.tidecloak.jpa.utils;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.persistence.EntityManager;
import org.keycloak.common.ClientConnection;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.RoleEntity;
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
import org.tidecloak.jpa.entities.UserClientAccessProofEntity;
import org.tidecloak.jpa.entities.drafting.TideCompositeRoleMappingDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import twitter4j.v1.User;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.function.BiFunction;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

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
        System.out.println("INSIDE GENERATION");
        Set<RoleModel> requestedAccess = filterClientRoles(activeRoles, clientModel, clientModel.getClientScopes(false).values().stream());
        UserEntity user = TideRolesUtil.toUserEntity(userModel, em);

        AccessDetails accessDetails = sortAccessRoles(requestedAccess);

        // Apply the filtered roles to the AccessToken
        setTokenClaims(proof, accessDetails, actionType);

        JsonNode proofDraftNode = objectMapper.valueToTree(proof);

        if ( actionType == ActionType.DELETE){
            proofDraftNode = removeAccessFromJsonNode(proofDraftNode, accessDetails);
        }

        var proofDraft = cleanProofDraft(proofDraftNode);


        // Always save the access proof detail
        saveAccessProofDetail(clientModel, user, recordId, type, proofDraft, System.currentTimeMillis());
    }

    public List<TideCompositeRoleMappingDraftEntity> findCompositeMappingsByChildRole(RoleEntity composite) {
        return em.createNamedQuery("TideCompositeRoleMappingDraftEntity.findByChildRoleWithDependency", TideCompositeRoleMappingDraftEntity.class)
                .setParameter("composite", composite)
                .getResultList();
    }

    private void updateDependencyIfNeeded(AccessProofDetailEntity latestProof, String recordId, ChangeSetType type, EntityManager em) {
        AccessProofDetailDependencyEntity dependency = em.find(AccessProofDetailDependencyEntity.class, new AccessProofDetailDependencyEntity.Key(recordId, type));
        if (dependency == null && type == latestProof.getChangesetType()) {
            AccessProofDetailDependencyEntity newDependency = new AccessProofDetailDependencyEntity();
            newDependency.setRecordId(recordId);
            newDependency.setChangesetType(type);
            newDependency.setForkedRecordId(latestProof.getRecordId());
            newDependency.setForkedChangeSetType(latestProof.getChangesetType()); // made redundant
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

    public void saveProofToDatabase(String proof, String clientId, UserEntity user) throws NoSuchAlgorithmException, JsonProcessingException {

        System.out.println("ADDING THIS PRROF " + proof);
        // find if proof exists, update if it does else we create a new one for the user
        UserClientAccessProofEntity userClientAccess = em.find(UserClientAccessProofEntity.class, new UserClientAccessProofEntity.Key(user, clientId ));
        String proofChecksum = generateProofChecksum(proof);
        String proofMeta = getProofMeta(proof);

        if (userClientAccess == null){
            System.out.println("NO ACCESS FOUND, ADDING NEW");
            UserClientAccessProofEntity newAccess = new UserClientAccessProofEntity();
            newAccess.setUser(user);
            newAccess.setClientId(clientId);
            newAccess.setAccessProof(proofChecksum);
            newAccess.setAccessProofMeta(proofMeta);
            em.persist(newAccess);
        } else{
            userClientAccess.setAccessProof(proofChecksum);
            userClientAccess.setAccessProofMeta(proofMeta);
        }
    }

    public String generateProofChecksum(String proof) throws NoSuchAlgorithmException {

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] changeBytes = digest.digest(
                proof.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(changeBytes);
    }

    public String getProofMeta(String proofDraft) throws JsonProcessingException, NoSuchAlgorithmException {

        // Generate the meta here
        // Create a root node
        JsonNode jsonNode = objectMapper.readTree(proofDraft);
        ObjectNode object = (ObjectNode) jsonNode;
        ObjectNode rootNode = objectMapper.createObjectNode();
        var jsonProperties = object.properties();
        generateMeta(rootNode, jsonProperties);
        return objectMapper.writeValueAsString(rootNode);
    }


    public AccessToken generateAccessToken(ClientModel client, UserModel user, String scopeParam){
        session.getContext().setClient(client);
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

    public String updateDraftProofDetails(ClientModel clientModel, UserModel userModel, String oldProofDetails) throws JsonProcessingException {
        // Generate the current token
        AccessToken currentProof = generateAccessToken(clientModel, userModel, "openid");

        JsonNode currentProofNode = objectMapper.valueToTree(currentProof);
        JsonNode oldProofNode = objectMapper.readTree(oldProofDetails);

        return cleanProofDraft(mergeJsonNodes(currentProofNode, oldProofNode));


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


    private void generateMeta(ObjectNode rootNode, Set<Map.Entry<String, JsonNode>> json){
        json.forEach(x -> {
            if ( x.getValue().getNodeType() == JsonNodeType.OBJECT ){
                ObjectNode node = rootNode.putObject(x.getKey());
                generateMeta(node, x.getValue().properties());
            }else {
                ObjectNode node = objectMapper.createObjectNode();
                node.put("type", x.getValue().getNodeType().toString());
                rootNode.set(x.getKey(), node);
            }
        });
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
                realmAccess.getRoles().forEach(role -> {
                    token.getRealmAccess().addRole(role);
                });
            }
        }
    }

    private static void mergeClientAccesses(AccessToken token, Map<String, AccessToken.Access> clientAccesses) {
        clientAccesses.forEach((clientKey, access) -> {
            AccessToken.Access tokenClientAccess = token.getResourceAccess().computeIfAbsent(clientKey, k -> new AccessToken.Access());
            if (access.getRoles() != null) {
                access.getRoles().forEach(tokenClientAccess::addRole);
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

