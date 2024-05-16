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
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.keycloak.services.resources.admin.permissions.UserPermissionEvaluator;

import org.tidecloak.interfaces.*;
import org.tidecloak.jpa.entities.UserClientAccessProofEntity;
import org.tidecloak.jpa.entities.drafting.*;
import org.tidecloak.jpa.models.TideRoleAdapter;
import org.tidecloak.jpa.models.TideUserAdapter;
import org.tidecloak.jpa.utils.TideAuthzProofUtil;
import org.tidecloak.jpa.utils.TideRolesUtil;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.utils.ProofGeneration;
import ua_parser.Client;

import javax.management.relation.Role;
import java.security.NoSuchAlgorithmException;
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
                requestChange.getUserRecord().add(new RequestChangesUserRecord(p.getUser().getUsername(), p.getId(), realm.getClientById(p.getClientId()).getName()));
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
                requestChange.getUserRecord().add(new RequestChangesUserRecord(p.getUser().getUsername(), p.getId(), realm.getClientById(p.getClientId()).getName()));
            });
            ClientModel clientModel = realm.getClientById(m.getComposite().getClientId());
            requestChange.setDescription(String.format("Adding %s access to %s in %s", m.getChildRole().getName(), m.getComposite().getName(), clientModel.getClientId()));

            changes.add(requestChange);
        }

        return changes;
    }

    // This should be called after the drafts have been checked by the orks and the proof has been signed by the vvk.
    // Calling this method after getting the approval from the orks will update keycloak database for these records to active.
    // Need to give this endpoint the newly signed proof (signed by vvk) so it can be stored and used in the authz\authn flow
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("change-set/approve")
    public void approveChangeSet(List<DraftChangeSet> changeSets) throws NoSuchAlgorithmException, JsonProcessingException {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        System.out.println(realm.getName());

        for ( DraftChangeSet change : changeSets) {
            if (change.getType() == ChangeSetType.USER_ROLE) {
                System.out.println("I AM HERE IN USER ROLE");
                List<TideUserRoleMappingDraftEntity> mappings = em.createNamedQuery("getUserRoleMappingsByStatusAndRealmAndRecordId", TideUserRoleMappingDraftEntity.class)
                        .setParameter("draftStatus", DraftStatus.DRAFT)
                        .setParameter("changesetId", change.getChangeSetId())
                        .setParameter("realmId",realm.getId())
                        .getResultList();

                if ( mappings.isEmpty()){
                    continue;
                }
                // Should only be one so we grab the first one
                TideUserRoleMappingDraftEntity mapping = mappings.get(0);
                // WE APPROVE THE DRAFT RECORD AND CONTINUE WITH THE OTHER CHECKS
                // Can probably move this further down
                mapping.setDraftStatus(DraftStatus.APPROVED);
                RoleModel role = realm.getRoleById(mapping.getRoleId());
                if ( role == null || !role.isClientRole()) {
                    System.out.println("I not client role");
                    continue;
                }
                ClientModel clientModel = realm.getClientById(role.getContainerId());

                /*
                *
                * somewhere here we:
                * generate the meta for the vvk signed proof
                * store both meta and proof into db
                * then continue with checking the other records
                * hash it then store the proof
                * */
                // Get the user
                UserEntity user = mapping.getUser();
                UserModel userModel = session.users().getUserById(realm, user.getId());
                UserModel wrappedUser = TideRolesUtil.wrapUserModel(userModel, session, realm);
                TideAuthzProofUtil tideAuthzProofUtil = new TideAuthzProofUtil(session, realm, em);

                String draftProof = em.createNamedQuery("getProofDetailsForUserByClientAndRecordId", AccessProofDetailEntity.class)
                        .setParameter("user", user)
                        .setParameter("clientId", clientModel.getId())
                        .setParameter("recordId", change.getChangeSetId())
                        .getSingleResult().getProofDraft();

                tideAuthzProofUtil.saveProofToDatabase(draftProof, clientModel.getId(), user);


                // query the proof database, we need to update and draft or pending records with the new proof ( proof will be merged )
                List<ClientModel> affectedClients = new ArrayList<>(realm.getClientsStream().filter(ClientModel::isFullScopeAllowed).toList());
                affectedClients.add(clientModel);
                List<ClientModel> uniqueAffectedClients = affectedClients.stream().distinct().toList();


                // Query affected records to update the proof details
                for (ClientModel client: uniqueAffectedClients) {
                    List<AccessProofDetailEntity> pendingProofDetails = em.createNamedQuery("getProofDetailsForUserByClient", AccessProofDetailEntity.class)
                            .setParameter("user", user)
                            .setParameter("clientId", client.getId())
                            .getResultList();

                    for (AccessProofDetailEntity p : pendingProofDetails) {
                        // Find the draft record and update back to draft status to be re approved and signed as the access has now changed
                        TideUserRoleMappingDraftEntity draftEntity = em.find(TideUserRoleMappingDraftEntity.class, p.getRecordId() );
                        if(draftEntity == null || draftEntity.getDraftStatus() == DraftStatus.APPROVED) {
                            continue;
                        }
                        draftEntity.setDraftStatus(DraftStatus.DRAFT);
                        String proof = p.getProofDraft();
                        String updatedProof = tideAuthzProofUtil.updateDraftProofDetails(client, wrappedUser, proof);
                        p.setProofDraft(updatedProof);

                    };
                }
            }
            if(change.getType() == ChangeSetType.COMPOSITE_ROLE){
                List<TideCompositeRoleMappingDraftEntity> mappings = em.createNamedQuery("getAllCompositeRoleMappingsByStatusAndRealmAndRecordId", TideCompositeRoleMappingDraftEntity.class)
                        .setParameter("draftStatus", DraftStatus.DRAFT)
                        .setParameter("changesetId", change.getChangeSetId())
                        .setParameter("realmId",realm.getId())
                        .getResultList();

                if ( mappings.isEmpty()){
                    continue;
                }
                // ID's are unique for each record so we check if the query finds anything then just get the only record
                TideCompositeRoleMappingDraftEntity mapping = mappings.get(0);
                RoleEntity roleEntity = mapping.getComposite();
                RoleModel role = realm.getRoleById(roleEntity.getId());
                //Only this one record got approved, now we need to check who was affected
                mapping.setDraftStatus(DraftStatus.APPROVED);
                // query proof details for all records with this recordID
                ClientModel clientModel = realm.getClientById(role.getContainerId());
                List<ClientModel> affectedClients = new ArrayList<>(realm.getClientsStream().filter(ClientModel::isFullScopeAllowed).toList());
                affectedClients.add(clientModel);
                List<ClientModel> uniqueAffectedClients = affectedClients.stream().distinct().toList();
                TideAuthzProofUtil tideAuthzProofUtil = new TideAuthzProofUtil(session, realm, em);

                for (ClientModel client : uniqueAffectedClients){
                    List<AccessProofDetailEntity> allProofDetailsAffected = em.createNamedQuery("getProofDetailsByClient", AccessProofDetailEntity.class)
                            .setParameter("clientId", client.getId())
                            .getResultList();

                    // Need to do this for all fullscoped enabled clients and this specifc client
                    // Need to loop through and update all draft records that belong to an affected user and check if there are any pending requests for this user for the same record and update the status back to draft
                    for ( AccessProofDetailEntity proofDetail : allProofDetailsAffected){
                        // Get the user
                        UserEntity user = proofDetail.getUser();
                        UserModel userModel = session.users().getUserById(realm, user.getId());
                        UserModel wrappedUser = TideRolesUtil.wrapUserModel(userModel, session, realm);


                        // If its for the record that was just approved, we save the final proof in a different table
                        if (Objects.equals(proofDetail.getRecordId(), change.getChangeSetId())){
                            /*
                             *
                             * somewhere here we:
                             * generate the meta for the vvk signed proof
                             * store both meta and proof into db
                             * then continue with checking the other records
                             * hash it then store the proof
                             * */

                            // Get the user
                            System.out.println("SETTING FINAL PROOF FOR " + user.getFirstName());
                            // if record is the same we need to remove the proof draft entity and store the final one in the user clientaccess entity
                            String draftProof = em.createNamedQuery("getProofDetailsForUserByClientAndRecordId", AccessProofDetailEntity.class)
                                    .setParameter("user", user)
                                    .setParameter("clientId", client.getId())
                                    .setParameter("recordId", change.getChangeSetId())
                                    .getSingleResult().getProofDraft();

                            tideAuthzProofUtil.saveProofToDatabase(draftProof, client.getId(), user);
                        }

                        TideCompositeRoleMappingDraftEntity draftEntity = em.find(TideCompositeRoleMappingDraftEntity.class, proofDetail.getRecordId());
                        if(draftEntity == null || draftEntity.getDraftStatus() == DraftStatus.APPROVED) {
                            System.out.println("nothing here in composite role");
                            continue;
                        }
                        System.out.println("setting this back to draft " + draftEntity.getId());
                        draftEntity.setDraftStatus(DraftStatus.DRAFT);
                        String proof = proofDetail.getProofDraft();
                        String updatedProof = tideAuthzProofUtil.updateDraftProofDetails(client, wrappedUser, proof);
                        proofDetail.setProofDraft(updatedProof);

                        System.out.println(proof);
                        System.out.println(updatedProof);

                    }
                }
            }
        }
        em.flush();
    }

    private void resetUserPendingChanges(){

        // Need to get all proof records for this user.
        // Update has been approved so now we need to update all pending\draft proofs for this user to reflect actually access in jwt

        // We update for all full scoped enable clients and check if there are pending changes for the same client
        // if the record id exists in the changeset list we ignore this reset and continue.

    }
    private void resetCompositeRolePendingChanges(){

        // Need to get all proof records for this user.
        // Update has been approved so now we need to update all pending\draft proofs for this user to reflect actually access in jwt

        // We update for all full scoped enable clients and check if there are pending changes for the same client
        // if the record id exists in the changeset list we ignore this reset and continue.

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

}
