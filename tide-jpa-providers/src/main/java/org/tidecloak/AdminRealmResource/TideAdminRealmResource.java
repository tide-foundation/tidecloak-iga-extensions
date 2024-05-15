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
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.enums.SchemaType;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.keycloak.admin.ui.rest.model.ClientRole;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.keycloak.services.resources.admin.permissions.UserPermissionEvaluator;

import org.tidecloak.interfaces.*;
import org.tidecloak.jpa.entities.drafting.*;
import org.tidecloak.jpa.models.TideRoleAdapter;
import org.tidecloak.jpa.models.TideUserAdapter;
import org.tidecloak.jpa.utils.TideRolesUtil;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.utils.ProofGeneration;
import ua_parser.Client;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.keycloak.admin.ui.rest.model.RoleMapper.convertToModel;

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
//    @Path("composite/{user-id}/draft/status")
//    public DraftStatus getUserDraftStatus(@PathParam("user-id") String id) {
//        // do the authorization with the existing admin permissions (e.g. realm management roles)
//        final UserPermissionEvaluator userPermissionEvaluator = auth.users();
//        userPermissionEvaluator.requireQuery();
//
//        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
//        UserEntity userEntity = em.find(UserEntity.class, id);
//
//        try {
//            return em.createNamedQuery("getTideUserDraftEntity", TideUserDraftEntity.class)
//                    .setParameter("user", userEntity)
//                    .getSingleResult().getDraftStatus();
//        } catch (NoResultException e) {
//            // Handle case where no draft status is found
//            System.out.println("I AM NULL");
//            return null;
//        }
//
//    }

    @GET
    @Path("composite/{parent-id}/child/{child-id}/draft/status")
    public DraftStatus getRoleDraftStatus(@PathParam("parent-id") String parentId, @PathParam("child-id") String childId) {
        // do the authorization with the existing admin permissions (e.g. realm management roles)
        final UserPermissionEvaluator userPermissionEvaluator = auth.users();
        userPermissionEvaluator.requireQuery();

        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        var parentRole = realm.getRoleById(parentId);
        var childRole = realm.getRoleById(childId);

        List<TideCompositeRoleMappingDraftEntity> entity = em.createNamedQuery("getCompositeRoleMappingDraft", TideCompositeRoleMappingDraftEntity.class)
                .setParameter("composite", TideRolesUtil.toRoleEntity(parentRole, em))
                .setParameter("childRole", TideRolesUtil.toRoleEntity(childRole, em))
                .getResultList();

        if (entity.isEmpty()){
            return null;
        }

        return entity.get(0).getDraftStatus();


    }
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

        if (changeSet.getType() == ChangeSetType.USER_ROLE) {


            draftRecordEntity = em.find(TideUserRoleMappingDraftEntity.class, changeSet.getChangeSetId());
            Stream<AccessProofDetailEntity> accessProofDetailEntity = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                    .setParameter("recordId", ((TideUserRoleMappingDraftEntity) draftRecordEntity).getId())
                    .getResultStream();

            proofDetails = accessProofDetailEntity.map(AccessProofDetailEntity::getProofDraft).toList();

        }
        if(changeSet.getType() == ChangeSetType.COMPOSITE_ROLE){
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


    @GET
    @Path("change-set/requests")
    public List<RequestedChanges> getRequestedChanges() {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<RequestedChanges> requestedChangesList = new ArrayList<>();

        // Handling different types of data fetches
        requestedChangesList.addAll(processUserRoleMappings(em));
        requestedChangesList.addAll(processCompositeRoleMappings(em));

        return requestedChangesList;
    }

    private List<RequestedChanges> processUserRoleMappings(EntityManager em) {
        List<RequestedChanges> changes = new ArrayList<>();
        List<TideUserRoleMappingDraftEntity> mappings = em.createNamedQuery("getAllUserRoleMappingsByStatusAndRealm", TideUserRoleMappingDraftEntity.class)
                .setParameter("draftStatus", DraftStatus.DRAFT)
                .setParameter("realmId",realm.getId())
                .getResultList();

        for (TideUserRoleMappingDraftEntity m : mappings) {

            RoleModel role = realm.getRoleById(m.getRoleId());
            System.out.println(m.getId());
            if(role == null ||!role.isClientRole()){
                continue;
            }
            System.out.println(role.isClientRole());
            ClientModel clientModel = realm.getClientById(role.getContainerId());

            List<AccessProofDetailEntity> proofs = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                    .setParameter("recordId", m.getId())
                    .getResultList();

            RequestedChanges requestChange = new RequestedChanges(RequestType.USER, m.getId(), new ArrayList<>(), "");
            proofs.forEach(p -> {
                requestChange.getUserRecord().add(new RequestChangesUserRecord(p.getUser().getFirstName(), p.getId()));
            });


            requestChange.setDescription(String.format("Granting %s access in %s to user\\s: ", role.getName(), clientModel.getClientId()));

            changes.add(requestChange);
        }

        return changes;
    }

    // Example placeholder methods for other data types
    private List<RequestedChanges> processCompositeRoleMappings(EntityManager em) {
        List<RequestedChanges> changes = new ArrayList<>();
        List<TideCompositeRoleMappingDraftEntity> mappings = em.createNamedQuery("getAllCompositeRoleMappingsByStatusAndRealm", TideCompositeRoleMappingDraftEntity.class)
                .setParameter("draftStatus", DraftStatus.DRAFT)
                .setParameter("realmId", realm.getId())
                .getResultList();

        for (TideCompositeRoleMappingDraftEntity m : mappings) {
            if (m.getComposite() == null || !m.getComposite().isClientRole()){
                continue;
            }
            List<AccessProofDetailEntity> proofs = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                    .setParameter("recordId", m.getId())
                    .getResultList();

            RequestedChanges requestChange = new RequestedChanges(RequestType.USER, m.getId(), new ArrayList<>(), "");
            proofs.forEach(p -> {
                requestChange.getUserRecord().add(new RequestChangesUserRecord(p.getUser().getFirstName(), p.getId()));
            });
            ClientModel clientModel = realm.getClientById(m.getComposite().getClientId());
            requestChange.setDescription(String.format("Adding %s access to %s in %s", m.getChildRole().getName(), m.getComposite().getName(), clientModel.getClientId()));

            changes.add(requestChange);
        }

        return changes;
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("change-set/approve")
    public void approveChangeSet(List<DraftChangeSet> changeSets){
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        System.out.println(realm.getName());


        changeSets.forEach(change -> {
            if (change.getType() == ChangeSetType.USER_ROLE) {

                TideUserRoleMappingDraftEntity draftRecordEntity = em.find(TideUserRoleMappingDraftEntity.class, change.getChangeSetId());
                draftRecordEntity.setDraftStatus(DraftStatus.APPROVED);

            }
            if(change.getType() == ChangeSetType.COMPOSITE_ROLE){
                TideCompositeRoleMappingDraftEntity draftRecordEntity = em.find(TideCompositeRoleMappingDraftEntity.class, change.getChangeSetId());
                draftRecordEntity.setDraftStatus(DraftStatus.APPROVED);
            }
        });
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
        user.getGroupsStream().forEach(group -> TideRolesUtil.addGroupRoles(TideRolesUtil.wrapGroupModel(group, session, realm), roleModels, DraftStatus.APPROVED, ActionType.CREATE));
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
