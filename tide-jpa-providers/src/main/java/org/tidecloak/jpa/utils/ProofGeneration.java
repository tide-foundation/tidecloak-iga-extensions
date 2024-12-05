package org.tidecloak.jpa.utils;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.function.BiFunction;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.persistence.*;
import org.keycloak.admin.ui.rest.model.ClientRole;
import org.keycloak.common.ClientConnection;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.managers.UserSessionManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.tidecloak.jpa.entities.UserClientAccessProofEntity;
import org.tidecloak.jpa.models.ProofData;
import org.tidecloak.jpa.models.TideClientAdapter;

import static org.keycloak.admin.ui.rest.model.RoleMapper.convertToModel;

// TODO: remove this file after IGA supports GROUP, otherwise use TideAuthzProofUtil !!!!!
public class ProofGeneration {

    private final KeycloakSession session;
    private final RealmModel realm;
    private  final  EntityManager em;
    private static final ObjectMapper objectMapper = new ObjectMapper();

    public ProofGeneration(KeycloakSession session, RealmModel realm, EntityManager em) {
        this.session = session;
        this.realm = realm;
        this.em = em;
    }

    public void generateProofAndSaveToTable(String userId, ClientModel client) {
        session.getContext().setClient(client); // Context setup for token generation.
        UserModel user = session.users().getUserById(realm, userId);
        updateOrAddEntity(user, client);
    }

    public List<UserModel> getAllGroupMembersIncludingSubgroups(RealmModel realm, GroupModel group) {
        List<UserModel> allMembers = new ArrayList<>();
        // Add current group members
        List<UserModel> groupMembers = session.users().getGroupMembersStream(realm, group).collect(Collectors.toList());
        allMembers.addAll(groupMembers);

        // Recursively add members from subgroups
        group.getSubGroupsStream().forEach(subgroup ->
                allMembers.addAll(getAllGroupMembersIncludingSubgroups(realm, subgroup))
        );

        return allMembers;
    }

    public void regenerateProofsForMembers(List<ClientRole> clientRoles, List<UserModel> members) {
        List<ClientModel> clientList = new ArrayList<>(session.clients().getClientsStream(realm).map(client -> {
                    ClientEntity clientEntity = em.find(ClientEntity.class, client.getId());
                    return new TideClientAdapter(realm, em, session, clientEntity);
                })
                .filter(TideClientAdapter::isFullScopeAllowed).toList());
        List<ClientModel> effectiveList = clientRoles.stream().map(role -> realm.getClientById(role.getClientId())).toList();
        clientList.addAll(effectiveList);

        List<ClientModel> uniqueClients = clientList.stream().distinct().collect(Collectors.toList());
        // Generate proofs for all members
        members.forEach(member -> {
            uniqueClients.forEach(client -> {
                try {
                    generateProofAndSaveToTable(member.getId(), client);
                } catch (Exception e) {
                    // Handle exceptions, e.g., log error or continue with other members/roles
                    System.err.println("Error generating access token for user " + member.getId() + " : " + e.getMessage());
                }
            });
        });
    }

    public void regenerateProofForClient(ClientModel client, List<UserModel> members) {
        // Generate proofs for all members
        members.forEach(member -> {
            try {
                generateProofAndSaveToTable(member.getId(), client);
            } catch (Exception e) {
                // Handle exceptions, e.g., log error or continue with other members/roles
                System.err.println("Error generating access token for user " + member.getId() + " and client " + client.getId() + ": " + e.getMessage());
            }
        });
    }

    public List<ClientRole> getEffectiveGroupClientRoles(GroupModel group){
        return toSortedClientRoles(addSubClientRoles(addParents(group).flatMap(GroupModel::getRoleMappingsStream)),realm);
    }

    public Stream<RoleModel> addSubClientRoles(Stream<RoleModel> roles) {
        return addSubRoles(roles).filter(RoleModel::isClientRole);
    }

    private List<ClientRole> toSortedClientRoles(Stream<RoleModel> roles, RealmModel realm) {
        return roles.map(roleModel -> convertToModel(roleModel, realm))
                .sorted(Comparator.comparing(ClientRole::getClient).thenComparing(ClientRole::getRole))
                .collect(Collectors.toList());
    }

    public String generateAccessTokenString(ClientModel client, UserModel user, String scopeParam){
        try{
            objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);

            AccessToken token = sessionAware(client, user, scopeParam, (userSession, clientSessionCtx) -> {
                TokenManager tokenManager = new TokenManager();
                return tokenManager.responseBuilder(realm, client, null, session, userSession, clientSessionCtx)
                        .generateAccessToken().getAccessToken();
            });
            return objectMapper.writeValueAsString(token);

        }
        catch (JsonProcessingException e) {

            throw new RuntimeException("Failed to process token", e);
        }
    }

    public AccessToken generateAccessToken(ClientModel client, UserModel user, String scopeParam){

        return sessionAware(client, user, scopeParam, (userSession, clientSessionCtx) -> {
            TokenManager tokenManager = new TokenManager();
            return tokenManager.responseBuilder(realm, client, null, session, userSession, clientSessionCtx)
                    .generateAccessToken().getAccessToken();
        });

    }

    private void updateOrAddEntity(UserModel user, ClientModel client){
        try {
            UserEntity userEntity = em.getReference(UserEntity.class, user.getId());
            // Check if an existing access proof entry is present
            UserClientAccessProofEntity proof = em.find(UserClientAccessProofEntity.class,
                    new UserClientAccessProofEntity.Key(userEntity, client.getId()), LockModeType.PESSIMISTIC_WRITE);
            ProofData proofData = cleanTokenAndGetChecksum(client, user);
            if (proof == null) {
                // Entry does not exist, create a new one
                proof = new UserClientAccessProofEntity();
                proof.setClientId(client.getId());
                proof.setUser(userEntity);
                proof.setAccessProof(proofData.proof);
                proof.setAccessProofMeta(proofData.proofMeta);
                em.persist(proof); // Persist the new entity

            } else {
                // Entry exists, update the existing entry
                proof.setAccessProof(proofData.proof);
                proof.setAccessProofMeta(proofData.proofMeta);
            }
            em.flush();
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private ProofData cleanTokenAndGetChecksum(ClientModel client, UserModel user) {
        String newAccessProof = generateAccessTokenString(client, user, "openid"); // scopeParam can be dyanmic when we support saml.

        try{
            ObjectMapper objMapper = new ObjectMapper();
            objMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);

            JsonNode jsonNode = objMapper.readTree(newAccessProof);
            ObjectNode object = (ObjectNode) jsonNode;
            objMapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);

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
            String tokenString = objMapper.writeValueAsString(sortedJson);

            // Generate the meta here
            // Create a root node
            ObjectNode rootNode = objMapper.createObjectNode();
            var jsonProperties = object.properties();
            generateMeta(rootNode, jsonProperties);
            var metaString =  objMapper.writeValueAsString(rootNode);


            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] tokenBytes = digest.digest(
                    tokenString.getBytes(StandardCharsets.UTF_8));
            var proof = Base64.getEncoder().encodeToString(tokenBytes);

            return new ProofData(proof, metaString);
        }
        catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to process token", e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    public String cleanProofDraft (AccessToken token) {
        try{
            ObjectMapper objMapper = new ObjectMapper();
            objMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);

            JsonNode jsonNode = objMapper.valueToTree(token);
            ObjectNode object = (ObjectNode) jsonNode;
            objMapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);

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

            return objMapper.writeValueAsString(sortedJson);
        }
        catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to process token", e);
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

    private Stream<RoleModel> addSubRoles(Stream<RoleModel> roles) {
        return addSubRoles(roles, new HashSet<>());
    }

    private Stream<RoleModel> addSubRoles(Stream<RoleModel> roles, HashSet<RoleModel> visited) {
        List<RoleModel> roleList = roles.collect(Collectors.toList());
        visited.addAll(roleList);
        return Stream.concat(roleList.stream(), roleList.stream().flatMap(r -> addSubRoles(r.getCompositesStream().filter(s -> !visited.contains(s)), visited)));
    }

    private Stream<GroupModel> addParents(GroupModel group) {
        if (group.getParent() == null) {
            return Stream.of(group);
        }
        return Stream.concat(Stream.of(group), addParents(group.getParent()));
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

            AuthenticationManager.setClientScopesInSession(session, authSession);
            ClientSessionContext clientSessionCtx = TokenManager.attachAuthenticationSession(session, userSession, authSession);

            return function.apply(userSession, clientSessionCtx);

        } finally {
            if (authSession != null) {
                authSessionManager.removeAuthenticationSession(realm, authSession, false);
            }
        }
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

}
