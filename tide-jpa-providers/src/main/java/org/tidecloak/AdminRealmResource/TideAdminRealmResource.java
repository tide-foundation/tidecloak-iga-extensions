package org.tidecloak.AdminRealmResource;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.keycloak.services.resources.admin.permissions.UserPermissionEvaluator;

import org.tidecloak.jpa.utils.TideRolesUtil;
import org.tidecloak.interfaces.ActionType;
import org.tidecloak.interfaces.ChangeSetType;
import org.tidecloak.interfaces.DraftChangeSet;
import org.tidecloak.interfaces.DraftStatus;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.drafting.TideCompositeRoleMappingDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.jpa.utils.ProofGeneration;

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

    // add a button on ui that posts to this endpoint
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("change-set/sign")
    public void signChangeset(DraftChangeSet changeSet){
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<String> proofDetails;
        System.out.println(realm.getName());
        Object draftRecordEntity = new Object();

        if (ChangeSetType.valueOf(changeSet.getType()) == ChangeSetType.USER_ROLE) {


            draftRecordEntity = em.find(TideUserRoleMappingDraftEntity.class, changeSet.getChangeSetId());
            Stream<AccessProofDetailEntity> accessProofDetailEntity = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                    .setParameter("recordId", ((TideUserRoleMappingDraftEntity) draftRecordEntity).getId())
                    .getResultStream();

            proofDetails = accessProofDetailEntity.map(AccessProofDetailEntity::getProofDraft).toList();

        }
        if(ChangeSetType.valueOf(changeSet.getType()) == ChangeSetType.COMPOSITE_ROLE){
            draftRecordEntity = em.find(TideCompositeRoleMappingDraftEntity.class, changeSet.getChangeSetId());
            Stream<AccessProofDetailEntity> accessProofDetailEntity = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                    .setParameter("recordId", ((TideCompositeRoleMappingDraftEntity) draftRecordEntity).getId())
                    .getResultStream();

            proofDetails = accessProofDetailEntity.map(AccessProofDetailEntity::getProofDraft).toList();
        }
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);

            JsonNode tempNode = objectMapper.valueToTree(draftRecordEntity);
            var sortedTemp = ProofGeneration.sortJsonNode(tempNode);

            // send proofDetails and draftRecord to enclave to be signed with sessKey
            String draftRecord = objectMapper.writeValueAsString(sortedTemp);


        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }


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
                    if (!token.getRealmAccess().getRoles().contains(role)) {
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
            if (realmAccess.getRoles() != null ){
                token.setRealmAccess(realmAccess);
            }

        }
        if (token.getResourceAccess().isEmpty() ){
            if(!clientAccesses.isEmpty()){
                token.setResourceAccess(clientAccesses);
            }
        }
    }


}
