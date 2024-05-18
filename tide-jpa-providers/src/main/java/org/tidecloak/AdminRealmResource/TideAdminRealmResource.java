package org.tidecloak.AdminRealmResource;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
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
import org.tidecloak.jpa.utils.AccessDetails;
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
            em.lock(m, LockModeType.PESSIMISTIC_WRITE);
            RoleModel role = realm.getRoleById(m.getRoleId());
            if(role == null ||!role.isClientRole()){
                continue;
            }
            ClientModel clientModel = realm.getClientById(role.getContainerId());

            List<AccessProofDetailEntity> proofs = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                    .setParameter("recordId", m.getId())
                    .getResultList();

            RequestedChanges requestChange = new RequestedChanges(ChangeSetType.USER_ROLE, RequestType.USER,  m.getAction() ,m.getId(), new ArrayList<>(), "");
            proofs.forEach(p -> {
                em.lock(p, LockModeType.PESSIMISTIC_WRITE);
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
                    .setLockMode(LockModeType.PESSIMISTIC_WRITE)
                    .getResultList();

            RequestedChanges requestChange = new RequestedChanges( ChangeSetType.COMPOSITE_ROLE, RequestType.USER, m.getAction(), m.getId(), new ArrayList<>(), "");
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
    // TODO: change the draftStatus to either :
    //  DRAFT (just created no signatures),
    //  PENDING (has some signatures but not yet fully approved by all admins),
    //  APPROVED ( has all the signatures, HOWEVER this is not yet active),
    //  ACTIVE (approved record has now been finalised and saved to the DB, this is now active)
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("change-set/approve")
    public void approveChangeSet(List<DraftChangeSet> changeSets) throws NoSuchAlgorithmException, JsonProcessingException {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        for (DraftChangeSet change : changeSets) {
            ActionType action = change.getActionType();
            ChangeSetType type = change.getType();

            if (type == ChangeSetType.USER_ROLE || type == ChangeSetType.COMPOSITE_ROLE) {
                List<?> mappings = getMappings(em, change, type, action);
                if (mappings.isEmpty()) continue;

                Object mapping = mappings.get(0);
                em.lock(mapping, LockModeType.PESSIMISTIC_WRITE);

                if (type == ChangeSetType.USER_ROLE) {
                    processUserRoleMapping(change, (TideUserRoleMappingDraftEntity) mapping, em, action);
                } else if (type == ChangeSetType.COMPOSITE_ROLE) {
                    processCompositeRoleMapping(change, (TideCompositeRoleMappingDraftEntity) mapping, em, action);
                }

                em.flush();
            }
        }
    }

    private List<?> getMappings(EntityManager em, DraftChangeSet change, ChangeSetType type, ActionType action) {
        if (type == ChangeSetType.USER_ROLE) {
            if (action == ActionType.CREATE) {
                return em.createNamedQuery("getUserRoleMappingsByStatusAndRealmAndRecordId", TideUserRoleMappingDraftEntity.class)
                        .setParameter("draftStatus", DraftStatus.DRAFT)
                        .setParameter("changesetId", change.getChangeSetId())
                        .setParameter("realmId", realm.getId())
                        .getResultList();
            } else if (action == ActionType.DELETE) {
                return em.createNamedQuery("getUserRoleMappingsByDeleteStatusAndRealmAndRecordId", TideUserRoleMappingDraftEntity.class)
                        .setParameter("deleteStatus", DraftStatus.DRAFT)
                        .setParameter("changesetId", change.getChangeSetId())
                        .setParameter("realmId", realm.getId())
                        .getResultList();
            }
        } else if (type == ChangeSetType.COMPOSITE_ROLE) {
            if (action == ActionType.CREATE) {
                return em.createNamedQuery("getAllCompositeRoleMappingsByStatusAndRealmAndRecordId", TideCompositeRoleMappingDraftEntity.class)
                        .setParameter("draftStatus", DraftStatus.DRAFT)
                        .setParameter("changesetId", change.getChangeSetId())
                        .setParameter("realmId", realm.getId())
                        .getResultList();
            } else if (action == ActionType.DELETE) {
                return em.createNamedQuery("getAllCompositeRoleMappingsByDeletionStatusAndRealmAndRecordId", TideCompositeRoleMappingDraftEntity.class)
                        .setParameter("deleteStatus", DraftStatus.DRAFT)
                        .setParameter("changesetId", change.getChangeSetId())
                        .setParameter("realmId", realm.getId())
                        .getResultList();
            }
        }
        return Collections.emptyList();
    }

    private void processUserRoleMapping(DraftChangeSet change, TideUserRoleMappingDraftEntity mapping, EntityManager em, ActionType action) throws NoSuchAlgorithmException, JsonProcessingException {
        RoleModel role = realm.getRoleById(mapping.getRoleId());
        if (role == null || !role.isClientRole()) return;

        if (action == ActionType.CREATE) {
            mapping.setDraftStatus(DraftStatus.APPROVED);
            checkAndUpdateProofRecords(change, mapping, ChangeSetType.USER_ROLE, em);
        } else if (action == ActionType.DELETE) {
            mapping.setDeleteStatus(DraftStatus.APPROVED);
            checkAndUpdateProofRecords(change, mapping, ChangeSetType.USER_ROLE, em);
            UserModel user = session.users().getUserById(realm, mapping.getUser().getId());
            user.deleteRoleMapping(role);
        }
    }

    private void processCompositeRoleMapping(DraftChangeSet change, TideCompositeRoleMappingDraftEntity mapping, EntityManager em, ActionType action) throws NoSuchAlgorithmException, JsonProcessingException {
        if (action == ActionType.CREATE) {
            mapping.setDraftStatus(DraftStatus.APPROVED);
            checkAndUpdateProofRecords(change, mapping, ChangeSetType.COMPOSITE_ROLE, em);
        } else if (action == ActionType.DELETE) {
            mapping.setDeleteStatus(DraftStatus.APPROVED);
            checkAndUpdateProofRecords(change, mapping, ChangeSetType.COMPOSITE_ROLE, em);

            RoleModel composite = realm.getRoleById(mapping.getComposite().getId());
            RoleModel child = realm.getRoleById(mapping.getChildRole().getId());
            composite.removeCompositeRole(child);
        }
    }

    private void checkAndUpdateProofRecords(DraftChangeSet change, Object entity, ChangeSetType changeSetType, EntityManager em) throws NoSuchAlgorithmException, JsonProcessingException {
        List<ClientModel> affectedClients = getAffectedClients(entity, changeSetType);
        TideAuthzProofUtil tideAuthzProofUtil = new TideAuthzProofUtil(session, realm, em);

        for (ClientModel client : affectedClients) {
            List<AccessProofDetailEntity> proofDetails = getProofDetailsByChangeSetType(em, client, entity, changeSetType);
            for (AccessProofDetailEntity proofDetail : proofDetails) {
                em.lock(proofDetail, LockModeType.PESSIMISTIC_WRITE);

                UserEntity user = proofDetail.getUser();
                UserModel userModel = session.users().getUserById(realm, user.getId());
                UserModel wrappedUser = TideRolesUtil.wrapUserModel(userModel, session, realm);

                saveFinalProofDetailsOnApproval(proofDetail, change, em, user, client);
                RoleModel role = null;
                ActionType actionType = null;
                if (entity instanceof  TideUserRoleMappingDraftEntity) {
                     role = realm.getRoleById(((TideUserRoleMappingDraftEntity) entity).getRoleId());
                     actionType = ((TideUserRoleMappingDraftEntity) entity).getAction();
                }
                if ( entity instanceof  TideCompositeRoleMappingDraftEntity) {
                    role = realm.getRoleById(((TideCompositeRoleMappingDraftEntity) entity).getChildRole().getId());
                    actionType = ((TideCompositeRoleMappingDraftEntity) entity).getAction();
                }

                if (proofDetail.getChangesetType() == ChangeSetType.USER_ROLE) {
                    TideUserRoleMappingDraftEntity draftEntity = em.find(TideUserRoleMappingDraftEntity.class, proofDetail.getRecordId());
                    Object temp;

                    handleUserRoleMappingDraft(draftEntity, proofDetail, change, role, actionType, client, tideAuthzProofUtil, wrappedUser);
                } else if (proofDetail.getChangesetType() == ChangeSetType.COMPOSITE_ROLE) {
                    TideCompositeRoleMappingDraftEntity draftEntity = em.find(TideCompositeRoleMappingDraftEntity.class, proofDetail.getRecordId());
                    handleCompositeRoleMappingDraft(draftEntity, proofDetail, change, role, client, tideAuthzProofUtil, wrappedUser);
                }
            }
        }
    }

    private List<ClientModel> getAffectedClients(Object entity, ChangeSetType changeSetType) {
        List<ClientModel> affectedClients = new ArrayList<>(realm.getClientsStream().filter(ClientModel::isFullScopeAllowed).toList());
        ClientModel clientModel = null;
        if (changeSetType == ChangeSetType.USER_ROLE) {
            RoleModel roleModel = realm.getRoleById(((TideUserRoleMappingDraftEntity) entity).getRoleId());
            clientModel = realm.getClientById(roleModel.getContainerId());
        } else if (changeSetType == ChangeSetType.COMPOSITE_ROLE) {
            RoleModel role = realm.getRoleById(((TideCompositeRoleMappingDraftEntity) entity).getChildRole().getId());
            clientModel = realm.getClientById(role.getContainerId());
        }
        affectedClients.add(clientModel);
        return affectedClients.stream().distinct().toList();
    }

    private List<AccessProofDetailEntity> getProofDetailsByChangeSetType(EntityManager em, ClientModel client, Object entity, ChangeSetType changeSetType) {
        if (changeSetType == ChangeSetType.USER_ROLE) {
            UserEntity user = ((TideUserRoleMappingDraftEntity) entity).getUser();
            return em.createNamedQuery("getProofDetailsForUserByClient", AccessProofDetailEntity.class)
                    .setParameter("user", user)
                    .setParameter("clientId", client.getId())
                    .setLockMode(LockModeType.PESSIMISTIC_WRITE)
                    .getResultList();
        } else if (changeSetType == ChangeSetType.COMPOSITE_ROLE) {
            return em.createNamedQuery("getProofDetailsByClient", AccessProofDetailEntity.class)
                    .setParameter("clientId", client.getId())
                    .getResultList();
        }
        return Collections.emptyList();
    }

    private void handleUserRoleMappingDraft(TideUserRoleMappingDraftEntity draftEntity, AccessProofDetailEntity proofDetail, DraftChangeSet change, RoleModel role, ActionType actionType, ClientModel client, TideAuthzProofUtil tideAuthzProofUtil, UserModel wrappedUser) throws JsonProcessingException, NoSuchAlgorithmException {
        if (draftEntity == null || (draftEntity.getDraftStatus() == DraftStatus.APPROVED && draftEntity.getDeleteStatus() == null)) {
            return;
        }
        if (change.getActionType() == ActionType.DELETE) {
            if (draftEntity.getDraftStatus() == DraftStatus.APPROVED && draftEntity.getDeleteStatus() == DraftStatus.PENDING) {
                draftEntity.setDeleteStatus(DraftStatus.DRAFT);
            } else {
                draftEntity.setDraftStatus(DraftStatus.DRAFT);
            }
            String proof = proofDetail.getProofDraft();
            Set<RoleModel> rolesToRemove = new HashSet<>();
            rolesToRemove.add(role);
            AccessDetails accessDetails = tideAuthzProofUtil.getAccessToRemove(client, rolesToRemove);
            String updatedProof = tideAuthzProofUtil.removeAccesFromToken(proof, accessDetails);
            proofDetail.setProofDraft(updatedProof);
            return;
        }

        draftEntity.setDraftStatus(DraftStatus.DRAFT);
        String proof = proofDetail.getProofDraft();
        Set<RoleModel> roleSet = new HashSet<>();
        roleSet.add(role);
        String updatedProof = tideAuthzProofUtil.updateDraftProofDetails(client, wrappedUser, proof, roleSet, actionType);
        proofDetail.setProofDraft(updatedProof);
    }

    private void handleCompositeRoleMappingDraft(TideCompositeRoleMappingDraftEntity draftEntity, AccessProofDetailEntity proofDetail, DraftChangeSet change, RoleModel roleModel, ClientModel client, TideAuthzProofUtil tideAuthzProofUtil, UserModel wrappedUser) throws JsonProcessingException, NoSuchAlgorithmException {
        if (draftEntity == null || (draftEntity.getDraftStatus() == DraftStatus.APPROVED && draftEntity.getDeleteStatus() == null)) {
            return;
        }
        if (change.getActionType() == ActionType.DELETE) {
            if (draftEntity.getDraftStatus() == DraftStatus.APPROVED && draftEntity.getDeleteStatus() == DraftStatus.PENDING) {
                draftEntity.setDeleteStatus(DraftStatus.DRAFT);
            } else {
                draftEntity.setDraftStatus(DraftStatus.DRAFT);
            }
            String proof = proofDetail.getProofDraft();
            Set<RoleModel> rolesToRemove = new HashSet<>();
            rolesToRemove.add(roleModel);
            AccessDetails accessDetails = tideAuthzProofUtil.getAccessToRemove(client, rolesToRemove);
            String updatedProof = tideAuthzProofUtil.removeAccesFromToken(proof, accessDetails);
            proofDetail.setProofDraft(updatedProof);
            return;
        }
        draftEntity.setDraftStatus(DraftStatus.DRAFT);
        String proof = proofDetail.getProofDraft();
        Set<RoleModel> roleSet = new HashSet<>();
        roleSet.add(roleModel);
        String updatedProof = tideAuthzProofUtil.updateDraftProofDetails(client, wrappedUser, proof, roleSet, draftEntity.getAction());
        proofDetail.setProofDraft(updatedProof);
    }

    private void saveFinalProofDetailsOnApproval(AccessProofDetailEntity proofDetail, DraftChangeSet change, EntityManager em, UserEntity user, ClientModel client) throws NoSuchAlgorithmException, JsonProcessingException {
        TideAuthzProofUtil tideAuthzProofUtil = new TideAuthzProofUtil(session, realm, em);
        if (Objects.equals(proofDetail.getRecordId(), change.getChangeSetId())) {
            String draftProof = em.createNamedQuery("getProofDetailsForUserByClientAndRecordId", AccessProofDetailEntity.class)
                    .setParameter("user", user)
                    .setParameter("clientId", client.getId())
                    .setParameter("recordId", change.getChangeSetId())
                    .getSingleResult().getProofDraft();

            tideAuthzProofUtil.saveProofToDatabase(draftProof, client.getId(), user);

            em.createNamedQuery("deleteProofRecordForUserAndClient")
                    .setParameter("recordId", change.getChangeSetId())
                    .setParameter("user", user)
                    .setParameter("clientId", client.getId())
                    .executeUpdate();
        }
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
