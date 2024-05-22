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
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.keycloak.services.resources.admin.permissions.UserPermissionEvaluator;

import org.tidecloak.interfaces.*;
import org.tidecloak.jpa.entities.UserClientAccessProofEntity;
import org.tidecloak.jpa.entities.drafting.*;
import org.tidecloak.jpa.models.TideClientAdapter;
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
import static org.tidecloak.Protocol.mapper.TideRolesProtocolMapper.getAccess;

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
    @Path("change-set/users/requests")
    public List<RequestedChanges> getRequestedChangesForUsers() {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        // Handling different types of data fetches
        return new ArrayList<>(processUserRoleMappings(em));
    }



    @GET
    @Path("change-set/roles/requests")
    public List<RequestedChanges> getRequestedChanges() {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<RequestedChanges> requestedChangesList = new ArrayList<>(processRoleMappings(em));
        // Handling different types of data fetches
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


            requestChange.setDescription(String.format("Granting \"%s\" access in \"%s\" to user\\s: ", role.getName(), clientModel.getClientId()));

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
            requestChange.setDescription(String.format("Adding \"%s\" access to \"%s\" in \"%s\"", m.getChildRole().getName(), m.getComposite().getName(), clientModel.getClientId()));

            changes.add(requestChange);
        }

        return changes;
    }

    private List<RequestedChanges> processRoleMappings(EntityManager em) {
        List<RequestedChanges> changes = new ArrayList<>();
        List<TideRoleDraftEntity> mappings = em.createNamedQuery("getAllRolesByStatusAndRealm", TideRoleDraftEntity.class)
                .setParameter("deleteStatus", DraftStatus.DRAFT)
                .setParameter("realmId", realm.getId())
                .getResultList();

        for (TideRoleDraftEntity m : mappings) {
            if (!m.getRole().isClientRole()){
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
            ClientModel clientModel = realm.getClientById(m.getRole().getClientId());
            requestChange.setDescription(String.format("Deleting  \"%s\" access in \"%s\"", m.getRole().getName(), clientModel.getClientId()));

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

            List<?> mappings = getMappings(em, change, type, action);
            if (mappings.isEmpty()) continue;

            Object mapping = mappings.get(0);
            em.lock(mapping, LockModeType.PESSIMISTIC_WRITE);

            if (type == ChangeSetType.USER_ROLE) {
                processUserRoleMapping(change, (TideUserRoleMappingDraftEntity) mapping, em, action);
            } else if (type == ChangeSetType.COMPOSITE_ROLE) {
                processCompositeRoleMapping(change, (TideCompositeRoleMappingDraftEntity) mapping, em, action);
            } else if ( type == ChangeSetType.ROLE) {
                processRole(change, (TideRoleDraftEntity) mapping, em, action);
            } else if ( type == ChangeSetType.USER) {
                processUser(change, (TideUserDraftEntity) mapping, em, action);
            } else if ( type == ChangeSetType.CLIENT) {
                processClient(change, (TideClientFullScopeStatusDraftEntity) mapping, em, action);
            }

            em.flush();

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
        } else if ( type == ChangeSetType.ROLE){
            if (action == ActionType.DELETE) {
                return em.createNamedQuery("getRoleDraftByRoleAndDeleteStatus", TideRoleDraftEntity.class)
                        .setParameter("deleteStatus", DraftStatus.DRAFT)
                        .setParameter("changesetId", change.getChangeSetId())
                        .getResultList();
            }
        }
        else if ( type == ChangeSetType.USER){
            if (action == ActionType.CREATE) {
                return em.createNamedQuery("getTideUserDraftEntityByDraftStatusAndId", TideUserDraftEntity.class)
                        .setParameter("draftStatus", DraftStatus.DRAFT)
                        .setParameter("changesetId", change.getChangeSetId())
                        .getResultList();
            }
        }
        else if ( type == ChangeSetType.CLIENT){
            if (action == ActionType.CREATE) {
                return em.createNamedQuery("getClientFullScopeStatusDraftByIdAndFullScopeEnabled", TideClientFullScopeStatusDraftEntity.class)
                        .setParameter("fullScopeEnabled", DraftStatus.DRAFT)
                        .setParameter("changesetId", change.getChangeSetId())
                        .getResultList();
            }
            if (action == ActionType.DELETE) {
                return em.createNamedQuery("getClientFullScopeStatusDraftByIdAndFullScopeDisabled", TideClientFullScopeStatusDraftEntity.class)
                        .setParameter("fullScopeDisabled", DraftStatus.DRAFT)
                        .setParameter("changesetId", change.getChangeSetId())
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
            em.persist(mapping);
            em.flush();
            checkAndUpdateProofRecords(change, mapping, ChangeSetType.USER_ROLE, em);
        } else if (action == ActionType.DELETE) {
            mapping.setDeleteStatus(DraftStatus.APPROVED);
            em.persist(mapping);
            em.flush();
            checkAndUpdateProofRecords(change, mapping, ChangeSetType.USER_ROLE, em);
            UserModel user = session.users().getUserById(realm, mapping.getUser().getId());
            user.deleteRoleMapping(role);
        }
    }

    private void processCompositeRoleMapping(DraftChangeSet change, TideCompositeRoleMappingDraftEntity mapping, EntityManager em, ActionType action) throws NoSuchAlgorithmException, JsonProcessingException {
        if (action == ActionType.CREATE) {
            mapping.setDraftStatus(DraftStatus.APPROVED);
            em.persist(mapping);
            em.flush();
            checkAndUpdateProofRecords(change, mapping, ChangeSetType.COMPOSITE_ROLE, em);
        } else if (action == ActionType.DELETE) {
            mapping.setDeleteStatus(DraftStatus.APPROVED);
            em.persist(mapping);
            em.flush();
            checkAndUpdateProofRecords(change, mapping, ChangeSetType.COMPOSITE_ROLE, em);

            RoleModel composite = realm.getRoleById(mapping.getComposite().getId());
            RoleModel child = realm.getRoleById(mapping.getChildRole().getId());
            composite.removeCompositeRole(child);
        }
    }

    private void processRole(DraftChangeSet change, TideRoleDraftEntity mapping, EntityManager em, ActionType action) throws NoSuchAlgorithmException, JsonProcessingException {
        // ROLE types only handle deletes for now
        if (action == ActionType.DELETE) {
            mapping.setDeleteStatus(DraftStatus.APPROVED);
            em.persist(mapping);
            em.flush();
            checkAndUpdateProofRecords(change, mapping, ChangeSetType.ROLE, em);

            RoleModel role = realm.getRoleById(mapping.getRole().getId());

            realm.removeRole(role);

            // After this role record has been removed, we go through and check the other change requests
            // check user role table for any pending/draft requests for this role
            // check the access proof records for this record id

            List<String> userRoleMappingIds = em.createNamedQuery("getUserRoleMappingDraftsByRole", String.class)
                    .setParameter("roleId", mapping.getRole().getId())
                    .getResultList();

            List<String> recordsToRemove = new ArrayList<>(userRoleMappingIds);

            em.createNamedQuery("deleteUserRoleMappingDraftsByRole")
                    .setParameter("roleId", mapping.getRole().getId())
                    .executeUpdate();

            // check composite role table for any pending/draft requests for role
            // check the access proof records for this record id
            List<String> compositeRoleIds = em.createNamedQuery("selectIdsForRemoval", String.class)
                    .setParameter("role", mapping.getRole())
                    .getResultList();
            recordsToRemove.addAll(compositeRoleIds);
            recordsToRemove.add(mapping.getId());

            em.createNamedQuery("removeDraftRequestsOnRemovalOfRole")
                    .setParameter("role", mapping.getRole())
                    .executeUpdate();

            recordsToRemove.forEach(id -> {
                em.createNamedQuery("deleteProofRecords")
                        .setParameter("recordId", id)
                        .executeUpdate();
            });
        }
    }

    private void processUser(DraftChangeSet change, TideUserDraftEntity mapping, EntityManager em, ActionType action) throws NoSuchAlgorithmException, JsonProcessingException {
        if (action == ActionType.CREATE) {
            mapping.setDraftStatus(DraftStatus.APPROVED);
            em.persist(mapping);
            em.flush();
            checkAndUpdateProofRecords(change, mapping, ChangeSetType.USER, em);

            // no longer need to track, proofs are now saved
            em.remove(mapping);
            em.flush();
        }
    }
    private void processClient(DraftChangeSet change, TideClientFullScopeStatusDraftEntity mapping, EntityManager em, ActionType action) throws NoSuchAlgorithmException, JsonProcessingException {
        if (action == ActionType.CREATE) {
            mapping.setFullScopeEnabled(DraftStatus.APPROVED);
            em.persist(mapping);
            em.flush();
            checkAndUpdateProofRecords(change, mapping, ChangeSetType.CLIENT, em);
        }
        else if (action == ActionType.DELETE){

            mapping.setFullScopeDisabled(DraftStatus.APPROVED);
            em.persist(mapping);
            em.flush();
            checkAndUpdateProofRecords(change, mapping, ChangeSetType.CLIENT, em);
            ClientModel client = new TideClientAdapter(realm, em, session, mapping.getClient());
            client.setFullScopeAllowed(false);
        }
    }

    private void checkAndUpdateProofRecords(DraftChangeSet change, Object entity, ChangeSetType changeSetType, EntityManager em) throws NoSuchAlgorithmException, JsonProcessingException {
        List<ClientModel> affectedClients = getAffectedClients(entity, changeSetType, em);
        TideAuthzProofUtil tideAuthzProofUtil = new TideAuthzProofUtil(session, realm, em);

        for (ClientModel client : affectedClients) {
            List<AccessProofDetailEntity> proofDetails = getProofDetailsByChangeSetType(em, client, entity, changeSetType);
            System.out.println("PROOF DETAILS HERE");
            proofDetails.forEach(x -> System.out.println(x.getId()));
            for (AccessProofDetailEntity proofDetail : proofDetails) {
                em.lock(proofDetail, LockModeType.PESSIMISTIC_WRITE);
                UserEntity user = proofDetail.getUser();
                UserModel userModel = session.users().getUserById(realm, user.getId());
                UserModel wrappedUser = TideRolesUtil.wrapUserModel(userModel, session, realm);

                // When a record is approved and gets submitted, we save the final proof to the db
                saveFinalProofDetailsOnApproval(proofDetail, change, em, user, client);

                // We then check any pending or draft records that were affected and update.
                Set<RoleModel> roleSet = new HashSet<>();
                ActionType actionType = null;

                // In this section we set up what is needed depending on the record that was APPROVED
                if (entity instanceof  TideUserRoleMappingDraftEntity) {
                    // Check if role belongs to a client
                    roleSet.add(TideRolesUtil.wrapRoleModel(realm.getRoleById(((TideUserRoleMappingDraftEntity) entity).getRoleId()), session, realm));
                     actionType = ((TideUserRoleMappingDraftEntity) entity).getAction();
                }
                else if ( entity instanceof  TideCompositeRoleMappingDraftEntity) {
                    roleSet.add(TideRolesUtil.wrapRoleModel(realm.getRoleById(((TideCompositeRoleMappingDraftEntity) entity).getChildRole().getId()), session, realm));
                    actionType = ((TideCompositeRoleMappingDraftEntity) entity).getAction();
                }
                else if ( entity instanceof  TideRoleDraftEntity ){
                    roleSet.add(TideRolesUtil.wrapRoleModel(realm.getRoleById(((TideRoleDraftEntity) entity).getRole().getId()), session, realm));
                    actionType = ((TideRoleDraftEntity) entity).getAction();
                }
                else if ( entity instanceof  TideClientFullScopeStatusDraftEntity ) {
                    ClientEntity clientEntity = ((TideClientFullScopeStatusDraftEntity) entity).getClient();
                    ClientModel clientModel = realm.getClientById(clientEntity.getId());
                    roleSet.addAll(clientModel.getRolesStream().collect(Collectors.toSet()));

                    Set<RoleModel> activeRoles = TideRolesUtil.getDeepUserRoleMappings(wrappedUser, session, realm, em, DraftStatus.APPROVED, ActionType.CREATE).stream().filter(role -> {
                        if (role.isClientRole()) {
                            return !Objects.equals(((ClientModel) role.getContainer()).getClientId(), client.getClientId());
                        }
                        return true;
                    }).collect(Collectors.toSet());

                    roleSet.addAll(activeRoles);
                }

                // Here, we go through each proof and update according to the type of change it was. These are the draft records that were still waiting for approval.
                // They are now invalidated and needs to be updated
                if (proofDetail.getChangesetType() == ChangeSetType.USER_ROLE) {
                    TideUserRoleMappingDraftEntity draftEntity = em.find(TideUserRoleMappingDraftEntity.class, proofDetail.getRecordId());
                    handleUserRoleMappingDraft(draftEntity, proofDetail, change, roleSet, actionType, client, tideAuthzProofUtil, wrappedUser, em);
                } else if (proofDetail.getChangesetType() == ChangeSetType.COMPOSITE_ROLE) {
                    TideCompositeRoleMappingDraftEntity draftEntity = em.find(TideCompositeRoleMappingDraftEntity.class, proofDetail.getRecordId());
                    handleCompositeRoleMappingDraft(draftEntity, proofDetail, change, roleSet, client, tideAuthzProofUtil, wrappedUser);
                }
                else if ( proofDetail.getChangesetType() == ChangeSetType.ROLE) {
                    TideRoleDraftEntity draftEntity = em.find(TideRoleDraftEntity.class, proofDetail.getRecordId());
                    handRoleDraft(draftEntity, proofDetail, change, roleSet, client, tideAuthzProofUtil, wrappedUser);
                }
                else if ( proofDetail.getChangesetType() == ChangeSetType.USER) {
                    TideUserDraftEntity draftEntity = em.find(TideUserDraftEntity.class, proofDetail.getRecordId());
                    handUserDraft(draftEntity, proofDetail, client, tideAuthzProofUtil, wrappedUser);
                }
                else if ( proofDetail.getChangesetType() == ChangeSetType.CLIENT) {
                    TideClientFullScopeStatusDraftEntity draftEntity = em.find(TideClientFullScopeStatusDraftEntity.class, proofDetail.getRecordId());
                    handClientDraft(draftEntity, proofDetail, change, client, tideAuthzProofUtil, wrappedUser, em);
                }
            }
        }
    }

    private List<ClientModel> getAffectedClients(Object entity, ChangeSetType changeSetType, EntityManager em) {
        if (changeSetType == ChangeSetType.CLIENT) {
            List<ClientModel> client = new ArrayList<>();
            ClientEntity clientEntity = ((TideClientFullScopeStatusDraftEntity) entity).getClient();
            client.add(realm.getClientById(clientEntity.getId()));
            return client;
        }

        List<ClientModel> affectedClients = new ArrayList<>(realm.getClientsStream().map(client -> {
            ClientEntity clientEntity = em.find(ClientEntity.class, client.getId());
            return new TideClientAdapter(realm, em, session, clientEntity);
        }).filter(x -> {
            ClientEntity clientEntity = em.find(ClientEntity.class, x.getId());
            // Check if client is pending approval for full scope
            List<TideClientFullScopeStatusDraftEntity> scopeDraft = em.createNamedQuery("getClientFullScopeStatusByFullScopeEnabledStatus", TideClientFullScopeStatusDraftEntity.class)
                    .setParameter("client", clientEntity)
                    .setParameter("fullScopeEnabled", DraftStatus.DRAFT)
                    .getResultList();
            return x.isFullScopeAllowed() || !scopeDraft.isEmpty();

        }).toList());

        ClientModel clientModel = null;
        if (changeSetType == ChangeSetType.USER_ROLE) {
            RoleModel roleModel = realm.getRoleById(((TideUserRoleMappingDraftEntity) entity).getRoleId());
            clientModel = realm.getClientById(roleModel.getContainerId());
        } else if (changeSetType == ChangeSetType.COMPOSITE_ROLE) {
            RoleModel role = realm.getRoleById(((TideCompositeRoleMappingDraftEntity) entity).getChildRole().getId());
            clientModel = realm.getClientById(role.getContainerId());
        } else if (changeSetType == ChangeSetType.ROLE) {
            RoleModel role = realm.getRoleById(((TideRoleDraftEntity) entity).getRole().getId());
            clientModel = realm.getClientById(role.getContainerId());
        }
        affectedClients.add(clientModel);
        return affectedClients.stream().distinct().toList();
    }

    private List<AccessProofDetailEntity> getProofDetailsByChangeSetType(EntityManager em, ClientModel client, Object entity, ChangeSetType changeSetType) {
        if (changeSetType == ChangeSetType.USER_ROLE ) {
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
        } else if (changeSetType == ChangeSetType.COMPOSITE_ROLE || changeSetType == ChangeSetType.ROLE || changeSetType == ChangeSetType.CLIENT) {
            return em.createNamedQuery("getProofDetailsByClient", AccessProofDetailEntity.class)
                    .setParameter("clientId", client.getId())
                    .getResultList();
        }
        return Collections.emptyList();
    }

    private void handleUserRoleMappingDraft(TideUserRoleMappingDraftEntity draftEntity, AccessProofDetailEntity proofDetail, DraftChangeSet change, Set<RoleModel>  roles, ActionType actionType, ClientModel client, TideAuthzProofUtil tideAuthzProofUtil, UserModel wrappedUser, EntityManager em) throws JsonProcessingException, NoSuchAlgorithmException {
        if (draftEntity == null || (draftEntity.getDraftStatus() == DraftStatus.APPROVED && draftEntity.getDeleteStatus() == null)) {
            return;
        }
        if (change.getActionType() == ActionType.DELETE) {
            if (change.getType() == ChangeSetType.CLIENT){
                String proof = proofDetail.getProofDraft();
                // get the role this record was trying to add
                TideUserRoleMappingDraftEntity userRoleDraft = em.find(TideUserRoleMappingDraftEntity.class, proofDetail.getRecordId());
                if ( userRoleDraft != null){
                    roles.add(realm.getRoleById(userRoleDraft.getRoleId()));
                }
                AccessDetails accessDetails = tideAuthzProofUtil.getAccessToRemove(client, roles, true);
                String updatedProof = tideAuthzProofUtil.removeAccesFromToken(proof, accessDetails);
                proofDetail.setProofDraft(updatedProof);
                return;
            }
            // For deletion roles
            if (draftEntity.getDraftStatus() == DraftStatus.APPROVED && draftEntity.getDeleteStatus() == DraftStatus.PENDING) {
                draftEntity.setDeleteStatus(DraftStatus.DRAFT);
            } else {
                draftEntity.setDraftStatus(DraftStatus.DRAFT);
            }
            String proof = proofDetail.getProofDraft();
            AccessDetails accessDetails = tideAuthzProofUtil.getAccessToRemove(client, roles, client.isFullScopeAllowed());
            String updatedProof = tideAuthzProofUtil.removeAccesFromToken(proof, accessDetails);
            proofDetail.setProofDraft(updatedProof);
            return;
        }

        draftEntity.setDraftStatus(DraftStatus.DRAFT);
        String proof = proofDetail.getProofDraft();
        String updatedProof = tideAuthzProofUtil.updateDraftProofDetails(client, wrappedUser, proof, roles, actionType, client.isFullScopeAllowed());
        proofDetail.setProofDraft(updatedProof);
    }

    private void handleCompositeRoleMappingDraft(TideCompositeRoleMappingDraftEntity draftEntity, AccessProofDetailEntity proofDetail, DraftChangeSet change, Set<RoleModel> roles, ClientModel client, TideAuthzProofUtil tideAuthzProofUtil, UserModel wrappedUser) throws JsonProcessingException, NoSuchAlgorithmException {
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
            AccessDetails accessDetails = tideAuthzProofUtil.getAccessToRemove(client, roles, client.isFullScopeAllowed());
            String updatedProof = tideAuthzProofUtil.removeAccesFromToken(proof, accessDetails);
            proofDetail.setProofDraft(updatedProof);
            return;
        }
        draftEntity.setDraftStatus(DraftStatus.DRAFT);
        String proof = proofDetail.getProofDraft();

        String updatedProof = tideAuthzProofUtil.updateDraftProofDetails(client, wrappedUser, proof, roles, draftEntity.getAction(), client.isFullScopeAllowed());
        proofDetail.setProofDraft(updatedProof);
    }

    private void handRoleDraft(TideRoleDraftEntity draftEntity, AccessProofDetailEntity proofDetail, DraftChangeSet change, Set<RoleModel> roles, ClientModel client, TideAuthzProofUtil tideAuthzProofUtil, UserModel wrappedUser) throws JsonProcessingException, NoSuchAlgorithmException {
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
            AccessDetails accessDetails = tideAuthzProofUtil.getAccessToRemove(client, roles, client.isFullScopeAllowed());
            String updatedProof = tideAuthzProofUtil.removeAccesFromToken(proof, accessDetails);
            proofDetail.setProofDraft(updatedProof);
            return;
        }
        draftEntity.setDraftStatus(DraftStatus.DRAFT);
        String proof = proofDetail.getProofDraft();
        String updatedProof = tideAuthzProofUtil.updateDraftProofDetails(client, wrappedUser, proof, roles, draftEntity.getAction(),client.isFullScopeAllowed());
        proofDetail.setProofDraft(updatedProof);
    }

    private void handUserDraft(TideUserDraftEntity draftEntity, AccessProofDetailEntity proofDetail, ClientModel client, TideAuthzProofUtil tideAuthzProofUtil, UserModel wrappedUser) throws JsonProcessingException, NoSuchAlgorithmException {
        if (draftEntity == null || (draftEntity.getDraftStatus() == DraftStatus.APPROVED && draftEntity.getDeleteStatus() == null)) {
            return;
        }
//        if (change.getActionType() == ActionType.DELETE) {
//            if (draftEntity.getDraftStatus() == DraftStatus.APPROVED && draftEntity.getDeleteStatus() == DraftStatus.PENDING) {
//                draftEntity.setDeleteStatus(DraftStatus.DRAFT);
//            } else {
//                draftEntity.setDraftStatus(DraftStatus.DRAFT);
//            }
//            String proof = proofDetail.getProofDraft();
//            Set<RoleModel> rolesToRemove = new HashSet<>();
//            rolesToRemove.add(roleModel);
//            AccessDetails accessDetails = tideAuthzProofUtil.getAccessToRemove(client, rolesToRemove);
//            String updatedProof = tideAuthzProofUtil.removeAccesFromToken(proof, accessDetails);
//            proofDetail.setProofDraft(updatedProof);
//            return;
//        }
        draftEntity.setDraftStatus(DraftStatus.DRAFT);
        String proof = proofDetail.getProofDraft();
        Set<RoleModel> roleSet = new HashSet<>();
        String updatedProof = tideAuthzProofUtil.updateDraftProofDetails(client, wrappedUser, proof, roleSet, draftEntity.getAction(), client.isFullScopeAllowed());
        proofDetail.setProofDraft(updatedProof);
    }

    private void handClientDraft(TideClientFullScopeStatusDraftEntity draftEntity, AccessProofDetailEntity proofDetail,DraftChangeSet change, ClientModel client, TideAuthzProofUtil tideAuthzProofUtil, UserModel wrappedUser, EntityManager em) throws JsonProcessingException, NoSuchAlgorithmException {
        boolean isDraftEntityNull = draftEntity == null;
        boolean isFullScopeEnabledApprovedAndDisabledNull = draftEntity != null &&
                draftEntity.getFullScopeEnabled() == DraftStatus.APPROVED &&
                draftEntity.getFullScopeDisabled() == null;
        boolean isFullScopeDisabledApprovedAndEnabledNull = draftEntity != null &&
                draftEntity.getFullScopeDisabled() == DraftStatus.APPROVED &&
                draftEntity.getFullScopeEnabled() == null;

        if (isDraftEntityNull || isFullScopeEnabledApprovedAndDisabledNull || isFullScopeDisabledApprovedAndEnabledNull) {
            return;
        }

        if (change.getActionType() == ActionType.DELETE) {
            if (draftEntity.getFullScopeDisabled() == DraftStatus.APPROVED && draftEntity.getFullScopeEnabled() == DraftStatus.PENDING) {
                draftEntity.setFullScopeEnabled(DraftStatus.DRAFT);
            }

            String proof = proofDetail.getProofDraft();
            // We only want to remove the roles that are not this clients role.
            Set<RoleModel> activeRoles = TideRolesUtil.getDeepUserRoleMappings(wrappedUser, session, realm, em, DraftStatus.APPROVED, ActionType.CREATE).stream().filter(x -> {
                if (x.isClientRole()){
                    return !Objects.equals(((ClientModel) x.getContainer()).getClientId(), client.getClientId());
                }
                return true;
            }).collect(Collectors.toSet());

            Set<RoleModel> roles = getAccess(activeRoles, client, client.getClientScopes(true).values().stream(), true);
            AccessDetails accessDetails = tideAuthzProofUtil.getAccessToRemove(client, roles, false);
            String updatedProof = tideAuthzProofUtil.removeAccesFromToken(proof, accessDetails);
            proofDetail.setProofDraft(updatedProof);
            return;
        }
        // this section here for any client changes. We need to check if there are any pending drafts and create any new records.
        // The client fullscope was enabled and approved. So now any pending\draft changes for this client needs to also appear.
        // per user , per client
        // user-role mappings - need extra record for this client with this new user role
        // composite role mappings - if a user is affected, need to show this in this client proof
        // deletions - need extra record to show a role no longer existing in this clients proof per user affected

        draftEntity.setFullScopeEnabled(DraftStatus.DRAFT);
        String proof = proofDetail.getProofDraft();
        Set<RoleModel> roleSet = new HashSet<>();
        String updatedProof = tideAuthzProofUtil.updateDraftProofDetails(client, wrappedUser, proof, roleSet, draftEntity.getAction(), true);
        proofDetail.setProofDraft(updatedProof);
    }

    private void saveFinalProofDetailsOnApproval(AccessProofDetailEntity proofDetail, DraftChangeSet change, EntityManager em, UserEntity user, ClientModel client) throws NoSuchAlgorithmException, JsonProcessingException {
        TideAuthzProofUtil tideAuthzProofUtil = new TideAuthzProofUtil(session, realm, em);
        if (Objects.equals(proofDetail.getRecordId(), change.getChangeSetId())) {
            // have a check here for composite role actions, ensure the composite role is granted to user. If no we dont bother saving a final proof.
            if ( change.getType() == ChangeSetType.COMPOSITE_ROLE) {
                TideCompositeRoleMappingDraftEntity record = em.find(TideCompositeRoleMappingDraftEntity.class, proofDetail.getRecordId());
                if ( record == null ) {
                    return;
                }

                List<TideUserRoleMappingDraftEntity> userRoleRecord = em.createNamedQuery("getUserRoleAssignmentDraftEntity", TideUserRoleMappingDraftEntity.class)
                        .setParameter("user", user)
                        .setParameter("roleId", record.getComposite().getId())
                        .getResultList();
                // If composite role is not yet granted to user, then we dont bother with final proof
                // TODO: check if status is ACTIVE (all admin signed, and was finalised by getting vvk to sign)
                if( userRoleRecord.isEmpty() || userRoleRecord.get(0).getDraftStatus() != DraftStatus.APPROVED){
                    return;
                }
            }
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
}
