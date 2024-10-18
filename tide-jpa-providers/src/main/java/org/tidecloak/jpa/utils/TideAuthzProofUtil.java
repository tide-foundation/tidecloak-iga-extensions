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
import jakarta.persistence.LockModeType;
import jakarta.persistence.NoResultException;
import org.keycloak.common.ClientConnection;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.ClientEntity;
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
import org.tidecloak.interfaces.DraftChangeSetRequest;
import org.tidecloak.interfaces.DraftStatus;
import org.tidecloak.interfaces.TidecloakChangeSetRequest.TidecloakDraftChangeSetRequest;
import org.tidecloak.jpa.entities.AccessProofDetailDependencyEntity;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.UserClientAccessProofEntity;
import org.tidecloak.jpa.entities.drafting.*;
import org.tidecloak.jpa.models.TideClientAdapter;
import org.tidecloak.jpa.models.TideRoleAdapter;
import org.tidecloak.jpa.models.TideUserAdapter;

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
        objectMapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.PUBLIC_ONLY);
    }
    /**
     * @return filtered set of roles based on Client settings. If client is full scoped returns back everything else remove out of scope roles.
     */
    public static Set<RoleModel> filterClientRoles(Set<RoleModel> roleModels, ClientModel client, Stream<ClientScopeModel> clientScopes, Boolean isFullScopeAllowed) {
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

    public AccessDetails getAccessToRemove (ClientModel clientModel, Set<RoleModel> newRoleMappings, Boolean isFullScopeAllowed) {
        Set<TideRoleAdapter> wrappedRoles = newRoleMappings.stream().map(r -> {
            RoleEntity roleEntity = em.getReference(RoleEntity.class, r.getId());
            return new TideRoleAdapter(session, realm, em, roleEntity);
        }).collect(Collectors.toSet());
        Set<RoleModel> activeRoles = TideRolesUtil.expandCompositeRoles(wrappedRoles, DraftStatus.ACTIVE);
        ClientEntity clientEntity = em.find(ClientEntity.class, clientModel.getId());
        ClientModel wrappedClient = new TideClientAdapter(realm, em, session, clientEntity);
        Set<RoleModel> requestedAccess = filterClientRoles(activeRoles, wrappedClient, clientModel.getClientScopes(false).values().stream(), isFullScopeAllowed);
        return sortAccessRoles(requestedAccess);
    }

    public void generateAndSaveProofDraft(ClientModel clientModel, UserModel userModel, Set<RoleModel> newRoleMappings, String recordId, ChangeSetType type, ActionType actionType, Boolean isFullScopeAllowed) throws JsonProcessingException {
        // Generate AccessToken based on the client and user information with openid scope
        AccessToken proof = generateAccessToken(clientModel, userModel, "openid");
        //TideUserAdapter wrappedUser = new TideUserAdapter(session, realm, em, em.getReference(UserEntity.class, userModel.getId()));
        //Stream<RoleModel> currentRoles = wrappedUser.getRoleMappingsStreamByStatusAndAction(DraftStatus.ACTIVE, ActionType.CREATE);
        //newRoleMappings.addAll(currentRoles.collect(Collectors.toSet()));
        AccessDetails accessDetails = null;
        UserEntity user = TideRolesUtil.toUserEntity(userModel, em);
        // Filter and expand roles based on the provided mappings; only approved roles are considered
        var roleSet = newRoleMappings.stream().distinct().filter(Objects::nonNull).collect(Collectors.toSet());
        if ( roleSet != null && !roleSet.isEmpty()){
            // ensure our roles are TideRoleAdapters
            Set<TideRoleAdapter> wrappedRoles = roleSet.stream().map(roles -> {
                RoleEntity roleEntity = em.getReference(RoleEntity.class, roles.getId());
                return new TideRoleAdapter(session, realm, em, roleEntity);
            }).collect(Collectors.toSet());
            Set<RoleModel> activeRoles = TideRolesUtil.expandCompositeRoles(wrappedRoles, DraftStatus.ACTIVE);
            ClientEntity clientEntity = em.find(ClientEntity.class, clientModel.getId());
            ClientModel wrappedClient = new TideClientAdapter(realm, em, session, clientEntity);
            Set<RoleModel> requestedAccess = filterClientRoles(activeRoles, wrappedClient, clientModel.getClientScopes(false).values().stream(), isFullScopeAllowed);
            accessDetails = sortAccessRoles(requestedAccess);

            // Apply the filtered roles to the AccessToken
            setTokenClaims(proof, accessDetails, actionType);

        }
        JsonNode proofDraftNode = objectMapper.valueToTree(proof);
        if ( actionType == ActionType.DELETE && accessDetails != null){
            proofDraftNode = removeAccessFromJsonNode(proofDraftNode, accessDetails);
        }
        AccessToken accessToken = objectMapper.convertValue(proofDraftNode, AccessToken.class);

        // Get client keys from resource access
        Set<String> clientKeys = accessToken.getResourceAccess().keySet();

        // Filter out the client model name from the client keys
        String[] aud = clientKeys.stream()
                .filter(key -> !Objects.equals(key, clientModel.getName()))
                .toArray(String[]::new);
        // Set the audience in the access token based on the filtered keys
        accessToken.audience(aud.length == 0 ? null : aud);
        // Convert the access token back to a JsonNode
        proofDraftNode = objectMapper.valueToTree(accessToken);
            // Clean the proof draft
        String proofDraft = cleanProofDraft(proofDraftNode);
        // Save the access proof detail
        saveAccessProofDetail(clientModel, user, recordId, type, proofDraft);

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

    private void saveAccessProofDetail(ClientModel clientModel, UserEntity user, String recordId, ChangeSetType type, String proofDraft) {
        AccessProofDetailEntity newDetail = new AccessProofDetailEntity();
        newDetail.setId(KeycloakModelUtils.generateId());
        newDetail.setClientId(clientModel.getId());
        newDetail.setUser(user);
        newDetail.setRecordId(recordId);
        newDetail.setProofDraft(proofDraft);
        newDetail.setChangesetType(type);
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

    public <T> TidecloakDraftChangeSetRequest generateTidecloakDraftChangeSetRequest(EntityManager em, String recordId, T mapping, long timestamp) throws JsonProcessingException {

        // This returns the access proof in descending order by timestamp
        List<String> userAccessDrafts = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                .setParameter("recordId", recordId)
                .getResultStream().map(AccessProofDetailEntity::getProofDraft)
                .toList();

        JsonNode mappingObject = objectMapper.valueToTree(mapping);
        JsonNode sortedMapping = sortJsonNode(mappingObject);
        String draftRecord = objectMapper.writeValueAsString(sortedMapping);

        return new TidecloakDraftChangeSetRequest(draftRecord, timestamp, userAccessDrafts);

    };

    // TODO: SAVING FINAL PROOF HERE
    public void saveProofToDatabase(AccessProofDetailEntity proof) throws NoSuchAlgorithmException, JsonProcessingException {

        // find if proof exists, update if it does else we create a new one for the user
        UserClientAccessProofEntity userClientAccess = em.find(UserClientAccessProofEntity.class, new UserClientAccessProofEntity.Key(proof.getUser(), proof.getClientId()));
//        String proofChecksum = generateProofChecksum(proof.getProofDraft());
        String sig = proof.getSignatures().get(0).getSignature();
        String proofMeta = getProofMeta(proof.getProofDraft());

        System.out.println("COMMITING THIS !!" );
        System.out.println(proof.getProofDraft());


        if (userClientAccess == null){
            UserClientAccessProofEntity newAccess = new UserClientAccessProofEntity();
            newAccess.setUser(proof.getUser());
            newAccess.setClientId(proof.getClientId());
            newAccess.setAccessProof(sig);
            newAccess.setAccessProofMeta(proofMeta);
            em.persist(newAccess);
        } else{
            userClientAccess.setAccessProof(sig);
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
            if (jsonNode != null && !jsonNode.isEmpty() && jsonNode.get(0).isTextual()) {
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

    public String updateDraftProofDetails(ClientModel clientModel, UserModel userModel, String oldProofDetails, Set<RoleModel> newRoleMappings, ActionType actionType, Boolean isFullScopeAllowed) throws JsonProcessingException {
        // Generate the current token
        AccessToken currentProof = generateAccessToken(clientModel, userModel, "openid");
        var rolesSet = newRoleMappings.stream().distinct().filter(Objects::nonNull).collect(Collectors.toSet());
        Set<TideRoleAdapter> wrappedRoles = rolesSet.stream().map(r -> {
            RoleEntity roleEntity = em.getReference(RoleEntity.class, r.getId());
            return new TideRoleAdapter(session, realm, em, roleEntity);
        }).collect(Collectors.toSet());
        Set<RoleModel> activeRoles = TideRolesUtil.expandCompositeRoles(wrappedRoles, DraftStatus.ACTIVE);
        ClientEntity clientEntity = em.find(ClientEntity.class, clientModel.getId());
        ClientModel wrappedClient = new TideClientAdapter(realm, em, session, clientEntity);
        Set<RoleModel> requestedAccess = filterClientRoles(activeRoles, wrappedClient, clientModel.getClientScopes(false).values().stream(), isFullScopeAllowed);

        AccessDetails accessDetails = sortAccessRoles(requestedAccess);

        // Apply the filtered roles to the AccessToken
        setTokenClaims(currentProof, accessDetails, actionType);


        JsonNode currentProofNode = objectMapper.valueToTree(currentProof);
        JsonNode oldProofNode = objectMapper.readTree(oldProofDetails);
        JsonNode merged = mergeJsonNodes(currentProofNode, oldProofNode);

        AccessToken accessToken = objectMapper.convertValue(merged, AccessToken.class);
        Set<String> clientKeys = accessToken.getResourceAccess().keySet();
        String[] aud = Arrays.stream(clientKeys.toArray(String[]::new)).filter(x -> !Objects.equals(x, clientModel.getName())).toArray(String[]::new);
        // Set the audience in the access token based on the filtered keys
        accessToken.audience(aud.length == 0 ? null : aud);
        JsonNode finalToken = objectMapper.valueToTree(accessToken);
        return cleanProofDraft(finalToken);


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

    public String removeAudienceFromToken(String proof) throws JsonProcessingException {
        JsonNode currentProof = objectMapper.readTree(proof);
        AccessToken token = objectMapper.convertValue(currentProof, AccessToken.class);
        token.audience(null);
         return objectMapper.writeValueAsString(sortJsonNode(objectMapper.valueToTree(token)));
    }

    public String removeAccessFromToken(String proof, AccessDetails accessDetails) throws JsonProcessingException {
        JsonNode currentProof = objectMapper.readTree(proof);
        JsonNode removedAccess = removeAccessFromJsonNode(currentProof, accessDetails);
        return cleanProofDraft(removedAccess);
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

    public void checkAndUpdateProofRecords(DraftChangeSetRequest change, Object entity, ChangeSetType changeSetType, EntityManager em) throws NoSuchAlgorithmException, JsonProcessingException {
        List<ClientModel> affectedClients = getAffectedClients(entity, changeSetType, em);
        TideAuthzProofUtil tideAuthzProofUtil = new TideAuthzProofUtil(session, realm, em);

        for (ClientModel client : affectedClients) {
            System.out.println(client.getClientId());
            // Get all draft access proof details for this client.
            List<AccessProofDetailEntity> proofDetails = getProofDetailsByChangeSetType(em, client, entity, changeSetType);
            for (AccessProofDetailEntity proofDetail : proofDetails) {
                System.out.println("Proof id here");
                System.out.println(proofDetail.getId());
                em.lock(proofDetail, LockModeType.PESSIMISTIC_WRITE);
                UserEntity user = proofDetail.getUser();
                UserModel userModel = session.users().getUserById(realm, user.getId());
                UserModel wrappedUser = TideRolesUtil.wrapUserModel(userModel, session, realm);

                //TODO: NEED TO ENSURE ITS COMMITED HERE
                // Check if this draft access proof is for this draft change request
                if (Objects.equals(proofDetail.getRecordId(), change.getChangeSetId())) {
                    System.out.println("apparently commited?!");
                    // If this draft change request is a user role grant, we need to check if it is granting a composite role to the user.
                    if(change.getType() == ChangeSetType.USER_ROLE) {
                        TideUserRoleMappingDraftEntity record = em.find(TideUserRoleMappingDraftEntity.class, proofDetail.getRecordId());
                        RoleEntity roleEntity = em.find(RoleEntity.class, record.getRoleId());
                        List<TideCompositeRoleMappingDraftEntity> compositeRoleDrafts = em.createNamedQuery("getCompositeEntityByParent", TideCompositeRoleMappingDraftEntity.class)
                                .setParameter("composite", roleEntity)
                                .getResultList();
                        TideAuthzProofUtil util = new TideAuthzProofUtil(session, realm, em);

                        // Check all composite role records and see if that have been commited.
                        for(TideCompositeRoleMappingDraftEntity draft : compositeRoleDrafts) {
                            // If a record is still draft or pending, need to create a new access proof detail draft for this user and client.
                            if(draft.getDraftStatus() != DraftStatus.ACTIVE){
                                Set<RoleModel> roles = new HashSet<>();
                                roles.add(realm.getRoleById(draft.getChildRole().getId()));
                                // Create new drafts
                                util.generateAndSaveProofDraft(client, wrappedUser, roles, draft.getId(), ChangeSetType.COMPOSITE_ROLE, ActionType.CREATE, true);
                            }
                        }
                    }

                    // TODO: update this part for multi admin. UNSURE what that looks like after we got threshold signatures, whats the artifact after that? e.g. all 3 admins approve so 3 signatures + admin gCMKAUTH, what happens after???
                    saveProofToDatabase(proofDetail);
                    em.remove(proofDetail); // this proof is commited, so now we remove
                    em.flush();
                    continue;
                }

                Set<RoleModel> roleSet = new HashSet<>();
                ActionType actionType = null;

                if (entity instanceof TideUserRoleMappingDraftEntity) {
                    roleSet.add(TideRolesUtil.wrapRoleModel(realm.getRoleById(((TideUserRoleMappingDraftEntity) entity).getRoleId()), session, realm));
                    actionType = ((TideUserRoleMappingDraftEntity) entity).getAction();
                } else if (entity instanceof TideCompositeRoleMappingDraftEntity) {
                    roleSet.add(TideRolesUtil.wrapRoleModel(realm.getRoleById(((TideCompositeRoleMappingDraftEntity) entity).getChildRole().getId()), session, realm));
                    actionType = ((TideCompositeRoleMappingDraftEntity) entity).getAction();
                } else if (entity instanceof TideRoleDraftEntity) {
                    roleSet.add(TideRolesUtil.wrapRoleModel(realm.getRoleById(((TideRoleDraftEntity) entity).getRole().getId()), session, realm));
                    actionType = ((TideRoleDraftEntity) entity).getAction();
                } else if (entity instanceof TideClientFullScopeStatusDraftEntity) {
                    Set<RoleModel> activeRoles;
                    if (((TideClientFullScopeStatusDraftEntity) entity).getAction() == ActionType.DELETE) {
                        activeRoles = TideRolesUtil.getDeepUserRoleMappings(wrappedUser, session, realm, em, DraftStatus.ACTIVE).stream().filter(role -> {
                            if (role.isClientRole()) {
                                return !Objects.equals(((ClientModel) role.getContainer()).getClientId(), client.getClientId());
                            }
                            return true;
                        }).collect(Collectors.toSet());
                    } else {
                        activeRoles = new HashSet<>(TideRolesUtil.getDeepUserRoleMappings(wrappedUser, session, realm, em, DraftStatus.ACTIVE));
                    }
                    roleSet.addAll(activeRoles);
                }
                var uniqRoles = roleSet.stream().distinct().filter(Objects::nonNull).collect(Collectors.toSet());
                if (proofDetail.getChangesetType() == ChangeSetType.USER_ROLE) {
                    TideUserRoleMappingDraftEntity draftEntity = em.find(TideUserRoleMappingDraftEntity.class, proofDetail.getRecordId());
                    handleUserRoleMappingDraft(draftEntity, proofDetail, change, uniqRoles, actionType, client, tideAuthzProofUtil, wrappedUser, em);
                }
                else if (proofDetail.getChangesetType() == ChangeSetType.COMPOSITE_ROLE) {
                    TideCompositeRoleMappingDraftEntity draftEntity = em.find(TideCompositeRoleMappingDraftEntity.class, proofDetail.getRecordId());
                    handleCompositeRoleMappingDraft(draftEntity, proofDetail, change, uniqRoles, client, tideAuthzProofUtil, wrappedUser, em);
                }
                else if (proofDetail.getChangesetType() == ChangeSetType.ROLE) {
                    TideRoleDraftEntity draftEntity = em.find(TideRoleDraftEntity.class, proofDetail.getRecordId());
                    handleRoleDraft(draftEntity, proofDetail, change, uniqRoles, client, tideAuthzProofUtil, wrappedUser, em);
                }
                else if (proofDetail.getChangesetType() == ChangeSetType.USER) {
                    TideUserDraftEntity draftEntity = em.find(TideUserDraftEntity.class, proofDetail.getRecordId());
                    handleUserDraft(draftEntity, proofDetail, client, tideAuthzProofUtil, wrappedUser);
                }
                else if (proofDetail.getChangesetType() == ChangeSetType.CLIENT) {
                    TideClientFullScopeStatusDraftEntity draftEntity = em.find(TideClientFullScopeStatusDraftEntity.class, proofDetail.getRecordId());
                    handleClientDraft(draftEntity, proofDetail, change, client, tideAuthzProofUtil, wrappedUser, em);
                }
            }
        }
    }

    public static UserClientAccessProofEntity getUserClientAccessProof(KeycloakSession session, UserModel userModel) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        UserEntity user = TideRolesUtil.toUserEntity(userModel, em);

        try {
            return em.createNamedQuery("getAccessProofByUserIdAndClientId", UserClientAccessProofEntity.class)
                    .setParameter("user", user)
                    .setParameter("clientId", session.getContext().getClient().getId())
                    .getSingleResult();
        } catch (NoResultException e) {
            return null;
        }
    }



    private void handleRoleDraft(TideRoleDraftEntity draftEntity, AccessProofDetailEntity proofDetail, DraftChangeSetRequest change, Set<RoleModel> roles, ClientModel client, TideAuthzProofUtil tideAuthzProofUtil, UserModel wrappedUser, EntityManager em) throws JsonProcessingException, NoSuchAlgorithmException {
        if (draftEntity == null || (draftEntity.getDraftStatus() == DraftStatus.ACTIVE && draftEntity.getDeleteStatus() == null)) {
            return;
        }

        if (change.getActionType() == ActionType.DELETE) {
            if (change.getType() == ChangeSetType.CLIENT) {
                TideCompositeRoleMappingDraftEntity compositeRoleMappingDraft = em.find(TideCompositeRoleMappingDraftEntity.class, proofDetail.getRecordId());
                if (compositeRoleMappingDraft != null) {
                    RoleModel childRole = realm.getRoleById(compositeRoleMappingDraft.getChildRole().getId());
                    RoleModel compositeRole = realm.getRoleById(compositeRoleMappingDraft.getComposite().getId());
                    if (childRole.isClientRole() && !Objects.equals(childRole.getContainerId(), client.getId())) {
                        roles.add(childRole);
                    }
                    if (compositeRole.isClientRole() && !Objects.equals(compositeRole.getContainerId(), client.getId())) {

                        roles.add(compositeRole);
                    }
                    roles.remove(compositeRole);
                }
            }
            if (draftEntity.getDraftStatus() == DraftStatus.ACTIVE && draftEntity.getDeleteStatus() != null) {
                draftEntity.setDeleteStatus(DraftStatus.DRAFT);
            } else if (draftEntity.getDraftStatus() == DraftStatus.APPROVED) {
                draftEntity.setDraftStatus(DraftStatus.DRAFT);
            }
            String proof = proofDetail.getProofDraft();
            var uniqRoles = roles.stream().distinct().filter(Objects::nonNull).collect(Collectors.toSet());
            uniqRoles.forEach(test -> System.out.println(test.getName()));
            AccessDetails accessDetails = tideAuthzProofUtil.getAccessToRemove(client, uniqRoles, client.isFullScopeAllowed());
            String updatedProof = tideAuthzProofUtil.removeAccessFromToken(proof, accessDetails);
            String newProof = tideAuthzProofUtil.removeAudienceFromToken(updatedProof);
            proofDetail.setProofDraft(newProof);
            return;
        }
        String proof = proofDetail.getProofDraft();
        if (draftEntity.getDraftStatus() == DraftStatus.ACTIVE && draftEntity.getDeleteStatus() != null) {
            draftEntity.setDeleteStatus(DraftStatus.DRAFT);
            String updatedProof = tideAuthzProofUtil.updateDraftProofDetails(client, wrappedUser, proof, roles, ActionType.CREATE, true);
            var ogRole = new HashSet<RoleModel>();
            ogRole.add(realm.getRoleById(draftEntity.getRole().getId()));
            var uniqRoles = ogRole.stream().distinct().filter(Objects::nonNull).collect(Collectors.toSet());
            AccessDetails accessDetails = tideAuthzProofUtil.getAccessToRemove(client, uniqRoles, client.isFullScopeAllowed());
            String newProof = tideAuthzProofUtil.removeAccessFromToken(updatedProof, accessDetails);
            proofDetail.setProofDraft(newProof);
        } else if (draftEntity.getDraftStatus() == DraftStatus.APPROVED) {
            draftEntity.setDraftStatus(DraftStatus.DRAFT);
            String updatedProof = tideAuthzProofUtil.updateDraftProofDetails(client, wrappedUser, proof, roles, draftEntity.getAction(), true);
            proofDetail.setProofDraft(updatedProof);
        }

    }

    private void handleUserDraft(TideUserDraftEntity draftEntity, AccessProofDetailEntity proofDetail, ClientModel client, TideAuthzProofUtil tideAuthzProofUtil, UserModel wrappedUser) throws JsonProcessingException, NoSuchAlgorithmException {
        if (draftEntity == null || (draftEntity.getDraftStatus() == DraftStatus.ACTIVE && draftEntity.getDeleteStatus() == null)) {
            return;
        }
        if (draftEntity.getDraftStatus() == DraftStatus.ACTIVE && draftEntity.getDeleteStatus() != null) {
            draftEntity.setDeleteStatus(DraftStatus.DRAFT);
        } else if (draftEntity.getDraftStatus() == DraftStatus.APPROVED) {
            draftEntity.setDraftStatus(DraftStatus.DRAFT);
        }
        String proof = proofDetail.getProofDraft();
        Set<RoleModel> roleSet = new HashSet<>();
        String updatedProof = tideAuthzProofUtil.updateDraftProofDetails(client, wrappedUser, proof, roleSet, draftEntity.getAction(), client.isFullScopeAllowed());
        proofDetail.setProofDraft(updatedProof);
    }

    private void handleClientDraft(TideClientFullScopeStatusDraftEntity draftEntity, AccessProofDetailEntity proofDetail, DraftChangeSetRequest change, ClientModel client, TideAuthzProofUtil tideAuthzProofUtil, UserModel wrappedUser, EntityManager em) throws JsonProcessingException, NoSuchAlgorithmException {
        if (draftEntity == null || (draftEntity.getFullScopeEnabled() == DraftStatus.ACTIVE && draftEntity.getFullScopeDisabled() == DraftStatus.NULL)
                || (draftEntity.getFullScopeDisabled() == DraftStatus.ACTIVE && draftEntity.getFullScopeEnabled() == DraftStatus.NULL)) {
            return;
        }

        if (change.getActionType() == ActionType.DELETE) {
            System.out.println("Made it this far!!!");
            if (draftEntity.getFullScopeDisabled() == DraftStatus.ACTIVE && draftEntity.getFullScopeEnabled() == DraftStatus.PENDING) {
                draftEntity.setFullScopeEnabled(DraftStatus.DRAFT);
            }
            em.remove(proofDetail);
            Set<RoleModel> activeRoles = TideRolesUtil.getDeepUserRoleMappings(wrappedUser, session, realm, em, DraftStatus.ACTIVE).stream().filter(role -> {
                if (role.isClientRole()) {
                    return !Objects.equals(((ClientModel) role.getContainer()).getClientId(), client.getClientId());
                }
                return true;
            }).collect(Collectors.toSet());
            tideAuthzProofUtil.generateAndSaveProofDraft(client, wrappedUser, activeRoles, proofDetail.getRecordId(), proofDetail.getChangesetType(), ActionType.CREATE, false);
            em.flush();
//            String proof = proofDetail.getProofDraft();

//
//            Set<RoleModel> roles = TideRolesProtocolMapper.getAccess(activeRoles, client, client.getClientScopes(true).values().stream(), true);
//            var uniqRoles = roles.stream().distinct().filter(Objects::nonNull).collect(Collectors.toSet());
//
//            AccessDetails accessDetails = tideAuthzProofUtil.getAccessToRemove(client, uniqRoles, false);
//            String updatedProof = tideAuthzProofUtil.removeAccessFromToken(proof, accessDetails);
//            String newProof = tideAuthzProofUtil.removeAudienceFromToken(updatedProof);
//            proofDetail.setProofDraft(newProof);
            return;
        }

        draftEntity.setFullScopeEnabled(DraftStatus.DRAFT);
        String proof = proofDetail.getProofDraft();
        Set<RoleModel> roleSet = new HashSet<>();
        String updatedProof = tideAuthzProofUtil.updateDraftProofDetails(client, wrappedUser, proof, roleSet, draftEntity.getAction(), true);
        proofDetail.setProofDraft(updatedProof);
    }


    private List<AccessProofDetailEntity> getProofDetailsByChangeSetType(EntityManager em, ClientModel client, Object entity, ChangeSetType changeSetType) throws JsonProcessingException {
        if (changeSetType == ChangeSetType.USER_ROLE) {
            UserEntity user = ((TideUserRoleMappingDraftEntity) entity).getUser();
            return em.createNamedQuery("getProofDetailsForUserByClient", AccessProofDetailEntity.class)
                    .setParameter("user", user)
                    .setParameter("clientId", client.getId())
                    .getResultList();
        } else if (changeSetType == ChangeSetType.USER) {
            UserEntity user = ((TideUserDraftEntity) entity).getUser();
            return em.createNamedQuery("getProofDetailsForUserByClient", AccessProofDetailEntity.class)
                    .setParameter("user", user)
                    .setParameter("clientId", client.getId())
                    .getResultList();
        } else if (changeSetType == ChangeSetType.COMPOSITE_ROLE || changeSetType == ChangeSetType.ROLE) {
            return em.createNamedQuery("getProofDetailsByClient", AccessProofDetailEntity.class)
                    .setParameter("clientId", client.getId())
                    .getResultList();
        }
        else if (changeSetType == ChangeSetType.CLIENT) {
            if (((TideClientFullScopeStatusDraftEntity) entity).getAction() == ActionType.CREATE) {
                String clientId = ((TideClientFullScopeStatusDraftEntity) entity).getClient().getId();

                List<String> recordIds = em.createNamedQuery("getProofDetailsByClient", AccessProofDetailEntity.class)
                        .setParameter("clientId", clientId)
                        .getResultStream().map(AccessProofDetailEntity::getRecordId).distinct().toList();

                List<AccessProofDetailEntity> proofs = new ArrayList<>();
                proofs.addAll(em.createNamedQuery("getProofDetailsForDraftByChangeSetType", AccessProofDetailEntity.class)
                        .setParameter("changesetType", ChangeSetType.USER_ROLE)
                        .getResultStream().filter(proof -> !recordIds.contains(proof.getRecordId())).toList());

                proofs.addAll(em.createNamedQuery("getProofDetailsForDraftByChangeSetType", AccessProofDetailEntity.class)
                        .setParameter("changesetType", ChangeSetType.COMPOSITE_ROLE)
                        .getResultStream().filter(proof -> !recordIds.contains(proof.getRecordId())).toList());

                proofs.addAll(em.createNamedQuery("getProofDetailsForDraftByChangeSetType", AccessProofDetailEntity.class)
                        .setParameter("changesetType", ChangeSetType.ROLE)
                        .getResultStream().filter(proof -> !recordIds.contains(proof.getRecordId())).toList());

                List<AccessProofDetailEntity> uniqueProofs = proofs.stream()
                        .collect(Collectors.collectingAndThen(
                                Collectors.toMap(
                                        AccessProofDetailEntity::getUser,
                                        e -> e,
                                        (e1, e2) -> e1 // If there are duplicates, keep the first one
                                ),
                                map -> new ArrayList<>(map.values())
                        ));
                for (AccessProofDetailEntity t : uniqueProofs) {

                    if (t.getChangesetType() == ChangeSetType.USER_ROLE) {
                        UserModel user = session.users().getUserById(realm, t.getUser().getId());
                        TideAuthzProofUtil util = new TideAuthzProofUtil(session, realm, em);

                        TideUserRoleMappingDraftEntity role = em.find(TideUserRoleMappingDraftEntity.class, t.getRecordId());
                        Set<RoleModel> roles = new HashSet<>();
                        RoleModel roleModel = realm.getRoleById(role.getRoleId());
                        if (roleModel != null){
                            roles.add(roleModel);
                        }

                        util.generateAndSaveProofDraft(client, user, roles, t.getRecordId(), ChangeSetType.USER_ROLE, ActionType.CREATE, true);

                    } else if ( t.getChangesetType() == ChangeSetType.COMPOSITE_ROLE) {
                        UserModel user = session.users().getUserById(realm, t.getUser().getId());
                        TideAuthzProofUtil util = new TideAuthzProofUtil(session, realm, em);

                        TideCompositeRoleMappingDraftEntity role = em.find(TideCompositeRoleMappingDraftEntity.class, t.getRecordId());
                        Set<RoleModel> roles = new HashSet<>();
                        RoleModel roleModel = realm.getRoleById(role.getChildRole().getId());
                        if (roleModel != null){
                            roles.add(roleModel);
                        }
                        util.generateAndSaveProofDraft(client, user, roles, t.getRecordId(), ChangeSetType.COMPOSITE_ROLE, ActionType.CREATE, true);

                    } else if ( t.getChangesetType() == ChangeSetType.ROLE) {
                        UserModel user = session.users().getUserById(realm, t.getUser().getId());
                        TideAuthzProofUtil util = new TideAuthzProofUtil(session, realm, em);

                        TideRoleDraftEntity role = em.find(TideRoleDraftEntity.class, t.getRecordId());
                        Set<RoleModel> roles = new HashSet<>();
                        RoleModel roleModel = realm.getRoleById(role.getRole().getId());
                        if (roleModel != null){
                            roles.add(roleModel);
                        }
                        util.generateAndSaveProofDraft(client, user, roles, t.getRecordId(), ChangeSetType.ROLE, ActionType.DELETE, true);

                    }

                }
            }
            return em.createNamedQuery("getProofDetailsByClient", AccessProofDetailEntity.class)
                    .setParameter("clientId", client.getId())
                    .getResultList();
        }
        return Collections.emptyList();
    }

    private void handleUserRoleMappingDraft(TideUserRoleMappingDraftEntity draftEntity, AccessProofDetailEntity proofDetail, DraftChangeSetRequest change, Set<RoleModel> roles, ActionType actionType, ClientModel client, TideAuthzProofUtil tideAuthzProofUtil, UserModel wrappedUser, EntityManager em) throws JsonProcessingException, NoSuchAlgorithmException {
        if (draftEntity == null || (draftEntity.getDraftStatus() == DraftStatus.ACTIVE && draftEntity.getDeleteStatus() == null)) {
            return;
        }
        if (change.getType() == ChangeSetType.CLIENT) {
            if (change.getActionType() == ActionType.DELETE) {
                boolean hasCommittedRole = ((TideUserAdapter) wrappedUser).getRoleMappingsStreamByStatusAndAction(DraftStatus.ACTIVE, ActionType.CREATE)
                        .anyMatch(x -> x.isClientRole() && Objects.equals(x.getContainer().getId(), client.getId()));

                if (hasCommittedRole) {
                    String proof = proofDetail.getProofDraft();

                    TideUserRoleMappingDraftEntity userRoleDraft = em.find(TideUserRoleMappingDraftEntity.class, proofDetail.getRecordId());
                    if (userRoleDraft != null) {
                        RoleModel role = realm.getRoleById(userRoleDraft.getRoleId());
                        if(role.isClientRole() && Objects.equals(role.getContainer().getId(), client.getId())) {
                            em.remove(proofDetail);
                            em.flush();
                            return;
                        }
                        roles.add(realm.getRoleById(userRoleDraft.getRoleId()));
                    }
                }
                if (draftEntity.getDraftStatus() == DraftStatus.ACTIVE && draftEntity.getDeleteStatus() != null) {
                    draftEntity.setDeleteStatus(DraftStatus.DRAFT);
                } else if (draftEntity.getDraftStatus() == DraftStatus.APPROVED) {
                    draftEntity.setDraftStatus(DraftStatus.DRAFT);
                }

                System.out.println("CHECKING THE ROLES!!!");
                roles.forEach(xr -> System.out.println(xr.getName()));
                roles.add(realm.getRoleById(draftEntity.getRoleId()));
                // remove and re-add
                em.remove(proofDetail);
                tideAuthzProofUtil.generateAndSaveProofDraft(client, wrappedUser, roles, proofDetail.getRecordId(), proofDetail.getChangesetType(), ActionType.CREATE, false);
                em.flush();
                return;
            }
        }

        String proof = proofDetail.getProofDraft();
        if (draftEntity.getDraftStatus() == DraftStatus.ACTIVE && draftEntity.getDeleteStatus() != null) {
            draftEntity.setDeleteStatus(DraftStatus.DRAFT);
            String updatedProof = tideAuthzProofUtil.updateDraftProofDetails(client, wrappedUser, proof, roles, actionType, true);
            var ogRole = new HashSet<RoleModel>();
            ogRole.add(realm.getRoleById(draftEntity.getRoleId()));
            var uniqRoles = ogRole.stream().distinct().filter(Objects::nonNull).collect(Collectors.toSet());
            AccessDetails accessDetails = tideAuthzProofUtil.getAccessToRemove(client, uniqRoles, client.isFullScopeAllowed());
            String newProof = tideAuthzProofUtil.removeAccessFromToken(updatedProof, accessDetails);
            proofDetail.setProofDraft(newProof);
            return;
        }
        else if (draftEntity.getDraftStatus() != DraftStatus.ACTIVE) {
            roles.add(realm.getRoleById(draftEntity.getRoleId()));
            draftEntity.setDraftStatus(DraftStatus.DRAFT);
            String updatedProof = tideAuthzProofUtil.updateDraftProofDetails(client, wrappedUser, proof, roles, actionType, true);
            proofDetail.setProofDraft(updatedProof);
            return;
        }

    }

    private void handleCompositeRoleMappingDraft(TideCompositeRoleMappingDraftEntity draftEntity, AccessProofDetailEntity proofDetail, DraftChangeSetRequest change, Set<RoleModel> roles, ClientModel client, TideAuthzProofUtil tideAuthzProofUtil, UserModel wrappedUser, EntityManager em) throws JsonProcessingException, NoSuchAlgorithmException {
        if (draftEntity == null || (draftEntity.getDraftStatus() == DraftStatus.ACTIVE && draftEntity.getDeleteStatus() == null)) {
            return;
        }
        if (change.getType() == ChangeSetType.CLIENT) {
            if (change.getActionType() == ActionType.DELETE) {
                TideCompositeRoleMappingDraftEntity compositeRoleMappingDraft = em.find(TideCompositeRoleMappingDraftEntity.class, proofDetail.getRecordId());
                if (compositeRoleMappingDraft != null) {
                    RoleModel childRole = realm.getRoleById(compositeRoleMappingDraft.getChildRole().getId());
                    RoleModel compositeRole = realm.getRoleById(compositeRoleMappingDraft.getComposite().getId());
                    if (childRole.isClientRole() && !Objects.equals(childRole.getContainerId(), client.getId())) {
                        roles.add(childRole);
                    }
                    if (compositeRole.isClientRole() && !Objects.equals(compositeRole.getContainerId(), client.getId())) {
                        roles.add(compositeRole);
                    }
                    // we want to keep the parent role, this is been deleted
                    roles.remove(compositeRole);
                }

                if (draftEntity.getDraftStatus() == DraftStatus.ACTIVE && draftEntity.getDeleteStatus() != null) {
                    draftEntity.setDeleteStatus(DraftStatus.DRAFT);
                } else if (draftEntity.getDraftStatus() == DraftStatus.APPROVED) {
                    draftEntity.setDraftStatus(DraftStatus.DRAFT);
                }
                // remove and re-add
                em.remove(proofDetail);
                roles.add(realm.getRoleById(draftEntity.getComposite().getId()));
                tideAuthzProofUtil.generateAndSaveProofDraft(client, wrappedUser, roles, proofDetail.getRecordId(), proofDetail.getChangesetType(), ActionType.CREATE, false);
                em.flush();
                return;

            }
        }

        String proof = proofDetail.getProofDraft();
        if (draftEntity.getDraftStatus() == DraftStatus.ACTIVE && draftEntity.getDeleteStatus() != null) {
            draftEntity.setDeleteStatus(DraftStatus.DRAFT);
            String updatedProof = tideAuthzProofUtil.updateDraftProofDetails(client, wrappedUser, proof, roles, ActionType.CREATE, true);
            var ogRole = new HashSet<RoleModel>();
            ogRole.add(realm.getRoleById(draftEntity.getChildRole().getId()));
            var uniqRoles = ogRole.stream().distinct().filter(Objects::nonNull).collect(Collectors.toSet());
            AccessDetails accessDetails = tideAuthzProofUtil.getAccessToRemove(client, uniqRoles, client.isFullScopeAllowed());
            String newProof = tideAuthzProofUtil.removeAccessFromToken(updatedProof, accessDetails);
            proofDetail.setProofDraft(newProof);
        } else if (draftEntity.getDraftStatus() == DraftStatus.APPROVED) {
            draftEntity.setDraftStatus(DraftStatus.DRAFT);
            String updatedProof = tideAuthzProofUtil.updateDraftProofDetails(client, wrappedUser, proof, roles, draftEntity.getAction(), true);
            proofDetail.setProofDraft(updatedProof);
        }
    }

    private List<ClientModel> getAffectedClients(Object entity, ChangeSetType changeSetType, EntityManager em) {
        if (changeSetType == ChangeSetType.CLIENT) {
            List<ClientModel> client = new ArrayList<>();
            ClientEntity clientEntity = ((TideClientFullScopeStatusDraftEntity) entity).getClient();
            client.add(realm.getClientById(clientEntity.getId()));
            return client;
        }

        List<ClientModel> affectedClients = realm.getClientsStream()
                .map(client -> new TideClientAdapter(realm, em, session, em.getReference(ClientEntity.class, client.getId())))
                .filter(clientModel -> {
                    ClientEntity clientEntity = em.find(ClientEntity.class, clientModel.getId());
                    List<TideClientFullScopeStatusDraftEntity> scopeDraft = em.createNamedQuery("getClientFullScopeStatusByFullScopeEnabledStatus", TideClientFullScopeStatusDraftEntity.class)
                            .setParameter("client", clientEntity)
                            .setParameter("fullScopeEnabled", DraftStatus.DRAFT)
                            .getResultList();
                    return clientModel.isFullScopeAllowed() || (scopeDraft != null && !scopeDraft.isEmpty());
                }).distinct().collect(Collectors.toList());
        // need to expand role and get child role clients too

        RoleModel roleModel = null;

        if (changeSetType == ChangeSetType.USER_ROLE) {
            roleModel = realm.getRoleById(((TideUserRoleMappingDraftEntity) entity).getRoleId());
            affectedClients.add(realm.getClientById(roleModel.getContainerId()));

        } else if (changeSetType == ChangeSetType.COMPOSITE_ROLE) {
            roleModel = realm.getRoleById(((TideCompositeRoleMappingDraftEntity) entity).getChildRole().getId());
            affectedClients.add(realm.getClientById(roleModel.getContainerId()));
        } else if (changeSetType == ChangeSetType.ROLE) {
            roleModel = realm.getRoleById(((TideRoleDraftEntity) entity).getRole().getId());
            affectedClients.add(realm.getClientById(roleModel.getContainerId()));
        }

        if(roleModel != null && roleModel.isComposite()){
            RoleEntity roleEntity = em.getReference(RoleEntity.class, roleModel.getId());
            Set<TideRoleAdapter> wrappedRoles = new HashSet<>();
            wrappedRoles.add(new TideRoleAdapter(session, realm, em, roleEntity));
            Set<RoleModel> activeRoles = TideRolesUtil.expandCompositeRoles(wrappedRoles, DraftStatus.ACTIVE);
            activeRoles.forEach(x -> {
                if (x.getContainer() instanceof  ClientModel){
                    affectedClients.add((ClientModel) x.getContainer());
                }
            });
        }

        return affectedClients.stream().distinct().collect(Collectors.toList());
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

    private void setAudience(AccessToken token, ClientModel clientModel, Set<RoleModel> roleModelSet ) {
        AccessToken temp = new AccessToken();
        roleModelSet.forEach(role -> { if(role.isClientRole()){addToToken(temp, role);}});

        for (Map.Entry<String, AccessToken.Access> entry : temp.getResourceAccess().entrySet()) {
            // Don't add client itself to the audience
            if (entry.getKey().equals(clientModel.getId())) {
                continue;
            }

            AccessToken.Access access = entry.getValue();
            if (access != null && access.getRoles() != null && !access.getRoles().isEmpty()) {
                token.addAudience(entry.getKey());
            }
        }
    }

    private static void addToToken(AccessToken token, RoleModel role) {

        AccessToken.Access access = null;
        if (role.getContainer() instanceof RealmModel) {
            access = token.getRealmAccess();
            if (token.getRealmAccess() == null) {
                access = new AccessToken.Access();
                token.setRealmAccess(access);
            } else if (token.getRealmAccess().getRoles() != null && token.getRealmAccess().isUserInRole(role.getName()))
                return;

        } else {
            ClientModel app = (ClientModel) role.getContainer();
            access = token.getResourceAccess(app.getClientId());
            if (access == null) {
                access = token.addAccess(app.getClientId());
                if (app.isSurrogateAuthRequired()) access.verifyCaller(true);
            } else if (access.isUserInRole(role.getName())) return;

        }
        access.addRole(role.getName());
    }


}

