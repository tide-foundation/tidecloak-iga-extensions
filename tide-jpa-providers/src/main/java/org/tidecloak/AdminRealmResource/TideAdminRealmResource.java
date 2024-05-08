package org.tidecloak.AdminRealmResource;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.exportimport.ExportOptions;
import org.keycloak.exportimport.util.ExportUtils;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.keycloak.services.resources.admin.permissions.UserPermissionEvaluator;

import org.tidecloak.Protocol.mapper.TideRolesUtil;
import org.tidecloak.interfaces.ActionType;
import org.tidecloak.interfaces.ChangeSetType;
import org.tidecloak.interfaces.DraftChangeSet;
import org.tidecloak.interfaces.DraftStatus;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.drafting.TideUserDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.jpa.models.ProofData;
import org.tidecloak.jpa.models.TideUserAdapter;
import org.tidecloak.jpa.utils.ProofGeneration;
import twitter4j.v1.User;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class TideAdminRealmResource {

    private final KeycloakSession session;
    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;

    public TideAdminRealmResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth) {
        this.session = session;
        this.realm = realm;
        this.auth = auth;
    }

    // UI STUFF!

    @GET
    @Path("users/{user-id}/roles/{role-id}/draft/status")
    public DraftStatus getUserRoleAssignmentDraftStatus(@PathParam("user-id") String userId, @PathParam("role-id") String roleId) {
        // do the authorization with the existing admin permissions (e.g. realm management roles)
        final UserPermissionEvaluator userPermissionEvaluator = auth.users();
        userPermissionEvaluator.requireQuery();

        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        UserEntity userEntity = em.find(UserEntity.class, userId);

        try {
            return em.createNamedQuery("getUserRoleAssignmentDraftEntity", TideUserRoleMappingDraftEntity.class)
                    .setParameter("user", userEntity)
                    .setParameter("roleId", roleId)
                    .getSingleResult().getDraftStatus();
        } catch (NoResultException e) {
            return null;
        }

    }

    @GET
    @Path("users/{user-id}/draft/status")
    public DraftStatus getUserDraftStatus(@PathParam("user-id") String id) {
        // do the authorization with the existing admin permissions (e.g. realm management roles)
        final UserPermissionEvaluator userPermissionEvaluator = auth.users();
        userPermissionEvaluator.requireQuery();

        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        UserEntity userEntity = em.find(UserEntity.class, id);

        try {
            return em.createNamedQuery("getTideUserDraftEntity", TideUserDraftEntity.class)
                    .setParameter("user", userEntity)
                    .getSingleResult().getDraftStatus();
        } catch (NoResultException e) {
            // Handle case where no draft status is found
            System.out.println("I AM NULL");
            return null;
        }

    }

//    @GET
//    @Path("composite/{parent-id}/child/{child-id}/draft/status")
//    public DraftStatus getRoleDraftStatus(@PathParam("parent-id") String parentId, @PathParam("child-id") String childId) {
//        // do the authorization with the existing admin permissions (e.g. realm management roles)
//        final UserPermissionEvaluator userPermissionEvaluator = auth.users();
//        userPermissionEvaluator.requireQuery();
//
//        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
//
//        TideCompositeRoleDraftEntity entity = em.find(TideCompositeRoleDraftEntity.class, new TideCompositeRoleDraftEntity.Key(parentId, childId));
//
//        if (entity == null){
//            return null;
//        }
//
//        return entity.getDraftStatus();
//
//
//    }

// UI STUFF END!

    // APPROVAL MECHANISM STARTS HERE
    // NEED DIFFERENT ENDPOINTS FOR EACH TYPE?

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("change-set/sign")
    public void signChangeset(DraftChangeSet changeSet){

        System.out.println(realm.getName());
        if (ChangeSetType.valueOf(changeSet.getType()) == ChangeSetType.USER_ROLE){
            EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

            TideUserRoleMappingDraftEntity draftRecord = em.find(TideUserRoleMappingDraftEntity.class, changeSet.getChangeSetId());
            Stream<AccessProofDetailEntity> accessProofDetailEntity = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                    .setParameter("recordId", draftRecord.getId())
                    .getResultStream();

            List<String> proofDetails = accessProofDetailEntity.map(AccessProofDetailEntity::getProofDraft).toList();

            // We have the proofDetails


                // need to get the draft changes



                //String draftRecord = userRepJson(userRep);
                // TODO: update timestamp to show creation of the changeset, for this example it should be when the new role was assigned to this user
                // GET THE CHANGESET and add to THE USER REP, in this case its one role from a client
                // NEED THIS MECHANISIM FOR PROOF DRAFT
                // atm shows the timestamp of user creation
                // {"id":"92a99e11-8915-4c65-b2ad-79f40661e0f5","username":"sasha1","firstName":"sasha1","lastName":"sasha1","email":"sasha1@tide.org","emailVerified":false,"createdTimestamp":1715062299309,"enabled":true,"totp":false,"disableableCredentialTypes":[],"requiredActions":[],"clientRoles":{"client 1":["client 1 role 1"]},"notBefore":0,"groups":["/group 1"]}

                //System.out.println(draftRecord);

                // generate the proof
                // somehow turn changeset into json format?????~??!?!?!?!?!?
                // just get a list of users and inform admin
                // e.g. list of users who will gain access

                // expand the roles to show the admin what this role gives the users

            }

        // PARSE JSON, look for type e.g. USER, GROUP, COMPOSITE ROLE, ROLE
        // use the correct method based on type to generate proof for user.
        // can we use the changeset-id for this ? how to construct the token exactly ?
        // query both approved and draft and construct token like that.


    }


    private String userRepJson(UserRepresentation userRep) {
        try{
            ObjectMapper objMapper = new ObjectMapper();
            objMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
            objMapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);

            return objMapper.writeValueAsString(userRep);
        }
        catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to process change set", e);
        }
    }

    //TODO: move into a more generic util file
    public static Set<RoleModel> getDeepUserRoleMappings(Set<RoleModel> roleModels, UserModel user, KeycloakSession session, RealmModel realm, EntityManager manager) {
        user.getGroupsStream().forEach(group -> TideRolesUtil.addGroupRoles(TideRolesUtil.wrapGroupModel(group, session, realm, manager), roleModels, DraftStatus.APPROVED, ActionType.CREATE));
        return TideRolesUtil.expandCompositeRoles(roleModels, DraftStatus.APPROVED, ActionType.CREATE);
    }
    public static Set<RoleModel> getAccess(Set<RoleModel> roleModels, ClientModel client, Stream<ClientScopeModel> clientScopes) {

        if (client.isFullScopeAllowed()) {
            return roleModels;
        } else {

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

            return roleModels;
        }
    }

    //TODO: CLEAN THIS MONSTROSITY!!!!
    public static void setTokenClaims(AccessToken token, Set<RoleModel> roles) {
        System.out.println("SEETING CLAIMS");
        roles.forEach(x -> System.out.println(x.getName()));
        System.out.println("TOKEN ACCESS");
        System.out.println(token.getRealmAccess());
        System.out.println(token.getResourceAccess());
        AccessToken.Access realmAccess = new AccessToken.Access();
        Map<String, AccessToken.Access> clientAccesses = new HashMap<>();
        for (RoleModel role : roles) {
            if (role.getContainer() instanceof RealmModel) {
                realmAccess.addRole(role.getName());
            } else if (role.getContainer() instanceof ClientModel client) {
                clientAccesses.computeIfAbsent(client.getClientId(), k -> new AccessToken.Access())
                        .addRole(role.getName());
            }
        }
        // Add our roles to what is existing
        // If original token does not include any roles we dont add.
        if (token.getRealmAccess() != null) {
            if(token.getRealmAccess().getRoles() != null && realmAccess.getRoles() != null){
                realmAccess.getRoles().forEach(role -> {
                    if (!token.getRealmAccess().getRoles().contains(role)){
                        token.getRealmAccess().addRole(role);
                    }
                });
            }
        }
        if (!token.getResourceAccess().isEmpty()) {
            clientAccesses.forEach((clientKey, clientAccess) -> {
                AccessToken.Access tokenClientRoles = token.getResourceAccess().get(clientKey);
                if (tokenClientRoles != null) {
                    Set<String> newRoles = clientAccess.getRoles();
                    if (!tokenClientRoles.getRoles().containsAll(newRoles)) {
                        newRoles.stream()
                                .filter(role -> !tokenClientRoles.getRoles().contains(role))
                                .forEach(tokenClientRoles::addRole);
                    }
                }else {
                    if (clientAccess.getRoles() != null){
                        token.getResourceAccess().put(clientKey, clientAccess);
                    }
                }
            });
        }
        if ( token.getRealmAccess() == null) {
            System.out.println(" token realm is NULL");
            if (realmAccess.getRoles() != null ){
                System.out.println("ALL NULL");
                token.setRealmAccess(realmAccess);
            }

        }
        if (token.getResourceAccess().isEmpty() ){
            System.out.println("token resource is null");
            if(!clientAccesses.isEmpty()){
                System.out.println("ALL NULL");
                token.setResourceAccess(clientAccesses);
            }
        }
    }


}
