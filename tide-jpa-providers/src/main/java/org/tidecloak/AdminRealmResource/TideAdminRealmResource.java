package org.tidecloak.AdminRealmResource;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.persistence.NoResultException;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.tidecloak.Protocol.mapper.TideRolesProtocolMapper;
import org.tidecloak.interfaces.*;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.drafting.*;
import org.tidecloak.jpa.models.TideClientAdapter;
import org.tidecloak.jpa.models.TideUserAdapter;
import org.tidecloak.jpa.utils.AccessDetails;
import org.tidecloak.jpa.utils.ProofGeneration;
import org.tidecloak.jpa.utils.TideAuthzProofUtil;
import org.tidecloak.jpa.utils.TideRolesUtil;

import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.stream.Collectors;

public class TideAdminRealmResource {

    private final KeycloakSession session;
    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;

    public TideAdminRealmResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth) {
        this.session = session;
        this.realm = realm;
        this.auth = auth;
    }

    @GET
    @Path("users/{user-id}/roles/{role-id}/draft/status")
    public Response getUserRoleAssignmentDraftStatus(@PathParam("user-id") String userId, @PathParam("role-id") String roleId) {
        auth.users().requireQuery(); // Ensure the user has the necessary permissions

        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        UserEntity userEntity = em.find(UserEntity.class, userId);

        try {
            DraftStatus draftStatus = em.createNamedQuery("getUserRoleAssignmentDraftEntity", TideUserRoleMappingDraftEntity.class)
                    .setParameter("user", userEntity)
                    .setParameter("roleId", roleId)
                    .getSingleResult()
                    .getDraftStatus();
            return Response.ok(draftStatus).build();
        } catch (NoResultException e) {
            // Return 404 if no draft status is found
            return Response.status(Response.Status.NOT_FOUND).entity("Draft status not found").build();
        }
    }

    @GET
    @Path("users/{user-id}/draft/status")
    public Response getUserDraftStatus(@PathParam("user-id") String id) {
        auth.users().requireQuery(); // Ensure the user has the necessary permissions

        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        UserEntity userEntity = em.find(UserEntity.class, id);

        try {
            DraftStatus draftStatus = em.createNamedQuery("getTideUserDraftEntity", TideUserDraftEntity.class)
                    .setParameter("user", userEntity)
                    .getSingleResult()
                    .getDraftStatus();
            return Response.ok(draftStatus).build();
        } catch (NoResultException e) {
            // Return 404 if no draft status is found
            return Response.status(Response.Status.NOT_FOUND).entity("Draft status not found").build();
        }
    }

    @GET
    @Path("composite/{parent-id}/child/{child-id}/draft/status")
    public Response getRoleDraftStatus(@PathParam("parent-id") String parentId, @PathParam("child-id") String childId) {
        auth.users().requireQuery(); // Ensure the user has the necessary permissions

        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        RoleModel parentRole = realm.getRoleById(parentId);
        RoleModel childRole = realm.getRoleById(childId);

        List<TideCompositeRoleMappingDraftEntity> entity = em.createNamedQuery("getCompositeRoleMappingDraft", TideCompositeRoleMappingDraftEntity.class)
                .setParameter("composite", TideRolesUtil.toRoleEntity(parentRole, em))
                .setParameter("childRole", TideRolesUtil.toRoleEntity(childRole, em))
                .getResultList();

        return entity.isEmpty() ? Response.status(Response.Status.NOT_FOUND).entity("Draft status not found").build() : Response.ok(entity.get(0).getDraftStatus()).build();
    }


    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("change-set/sign")
    public Response signChangeset(DraftChangeSet changeSet) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<String> proofDetails;
        Object draftRecordEntity;

        if (changeSet.getType() == ChangeSetType.USER_ROLE) {
            draftRecordEntity = em.find(TideUserRoleMappingDraftEntity.class, changeSet.getChangeSetId());
            proofDetails = getProofDetails(em, ((TideUserRoleMappingDraftEntity) draftRecordEntity).getId());
        } else if (changeSet.getType() == ChangeSetType.COMPOSITE_ROLE) {
            draftRecordEntity = em.find(TideCompositeRoleMappingDraftEntity.class, changeSet.getChangeSetId());
            proofDetails = getProofDetails(em, ((TideCompositeRoleMappingDraftEntity) draftRecordEntity).getId());
        } else {
            // Return 400 if change set type is unsupported
            return Response.status(Response.Status.BAD_REQUEST).entity("Unsupported change set type").build();
        }

        try {
            ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
            JsonNode tempNode = objectMapper.valueToTree(draftRecordEntity);
            JsonNode sortedTemp = ProofGeneration.sortJsonNode(tempNode);
            String draftRecord = objectMapper.writeValueAsString(sortedTemp);
            // Return success message after signing the changeset
            return Response.ok("Change set signed successfully").build();
        } catch (JsonProcessingException e) {
            // Return 500 if there is an error processing JSON
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Error processing JSON").build();
        }
    }

    @GET
    @Path("change-set/users/requests")
    public Response getRequestedChangesForUsers() {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<RequestedChanges> changes = new ArrayList<>(processUserRoleMappings(em));
        return Response.ok(changes).build();
    }

    @GET
    @Path("change-set/roles/requests")
    public Response getRequestedChanges() {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<RequestedChanges> requestedChangesList = new ArrayList<>(processRoleMappings(em));
        requestedChangesList.addAll(processCompositeRoleMappings(em));
        return Response.ok(requestedChangesList).build();
    }

    @GET
    @Path("change-set/clients/requests")
    public Response getRequestedChangesForClients() {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<RequestedChanges> changes = new ArrayList<>(processClientDraftRecords(em));
        return Response.ok(changes).build();
    }

    private List<RequestedChanges> processClientDraftRecords(EntityManager em) {
        List<RequestedChanges> changes = new ArrayList<>();
        List<TideClientFullScopeStatusDraftEntity> mappings = em.createNamedQuery("getClientFullScopeStatusDraftByIdAndEitherFullScopeStatus", TideClientFullScopeStatusDraftEntity.class)
                .setParameter("status", DraftStatus.DRAFT)
                .getResultList();

        for (TideClientFullScopeStatusDraftEntity c : mappings) {
            em.lock(c, LockModeType.PESSIMISTIC_WRITE); // Lock the entity to prevent concurrent modifications
            ClientModel client = realm.getClientById(c.getClient().getId());
            if (client == null) {
                continue;
            }

            List<AccessProofDetailEntity> proofs = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                    .setParameter("recordId", c.getId())
                    .getResultList();


            RequestedChanges requestChange = new RequestedChanges("",ChangeSetType.CLIENT, RequestType.CLIENT, client.getClientId(), c.getAction(), c.getId(), new ArrayList<>(), DraftStatus.DRAFT);
            proofs.forEach(p -> {
                em.lock(p, LockModeType.PESSIMISTIC_WRITE);
                requestChange.getUserRecord().add(new RequestChangesUserRecord(p.getUser().getUsername(), p.getId(), c.getClient().getClientId()));
            });

            if(c.getFullScopeEnabled() != DraftStatus.ACTIVE) {
                String action = "Enabling Full-Scope on Client";

                requestChange.setAction(action);
                requestChange.setStatus(c.getFullScopeEnabled());
            }
            else if ( c.getFullScopeDisabled() != DraftStatus.ACTIVE) {
                String action = "Disabling Full-Scope on Client";
                requestChange.setAction(action);
                requestChange.setStatus(c.getFullScopeDisabled());
            }
            changes.add(requestChange);
        }
        return changes;
    }

    private List<RequestedChanges> processUserRoleMappings(EntityManager em) {
        List<RequestedChanges> changes = new ArrayList<>();
        List<TideUserRoleMappingDraftEntity> mappings = em.createNamedQuery("getAllUserRoleMappingsByStatusAndRealm", TideUserRoleMappingDraftEntity.class)
                .setParameter("draftStatus", DraftStatus.DRAFT)
                .setParameter("realmId", realm.getId())
                .getResultList();

        for (TideUserRoleMappingDraftEntity m : mappings) {
            em.lock(m, LockModeType.PESSIMISTIC_WRITE); // Lock the entity to prevent concurrent modifications
            RoleModel role = realm.getRoleById(m.getRoleId());
            if (role == null || !role.isClientRole()) {
                continue;
            }
            ClientModel clientModel = realm.getClientById(role.getContainerId());
            List<AccessProofDetailEntity> proofs = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                    .setParameter("recordId", m.getId())
                    .getResultList();

            String action = "Granting Role to User";
            RequestedChanges requestChange = new RoleChangeRequest(realm.getRoleById(m.getRoleId()).getName(), action, ChangeSetType.USER_ROLE, RequestType.USER, clientModel.getClientId(), m.getAction(), m.getId(), new ArrayList<>(), m.getDraftStatus());
            proofs.forEach(p -> {
                em.lock(p, LockModeType.PESSIMISTIC_WRITE);
                requestChange.getUserRecord().add(new RequestChangesUserRecord(p.getUser().getUsername(), p.getId(), realm.getClientById(p.getClientId()).getClientId()));
            });
            changes.add(requestChange);
        }
        return changes;
    }

    private List<RequestedChanges> processCompositeRoleMappings(EntityManager em) {
        List<RequestedChanges> changes = new ArrayList<>();
        List<TideCompositeRoleMappingDraftEntity> mappings = em.createNamedQuery("getAllCompositeRoleMappingsByStatusAndRealm", TideCompositeRoleMappingDraftEntity.class)
                .setParameter("draftStatus", DraftStatus.DRAFT)
                .setParameter("realmId", realm.getId())
                .getResultList();

        for (TideCompositeRoleMappingDraftEntity m : mappings) {
            if (m.getComposite() == null || !m.getComposite().isClientRole()) {
                continue;
            }
            List<AccessProofDetailEntity> proofs = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                    .setParameter("recordId", m.getId())
                    .setLockMode(LockModeType.PESSIMISTIC_WRITE)
                    .getResultList();

            String action = "Granting Role to Composite Role";
            RequestedChanges requestChange = new CompositeRoleChangeRequest(m.getComposite().getName(), m.getChildRole().getName(), action, ChangeSetType.COMPOSITE_ROLE, RequestType.ROLE, realm.getClientById(m.getComposite().getClientId()).getClientId(), m.getAction(), m.getId(), new ArrayList<>(), m.getDraftStatus());
            proofs.forEach(p -> requestChange.getUserRecord().add(new RequestChangesUserRecord(p.getUser().getUsername(), p.getId(), realm.getClientById(p.getClientId()).getName())));
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
            if (!m.getRole().isClientRole()) {
                continue;
            }
            List<AccessProofDetailEntity> proofs = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                    .setParameter("recordId", m.getId())
                    .setLockMode(LockModeType.PESSIMISTIC_WRITE)
                    .getResultList();
            String action = "Deleting Role from Client";
            RequestedChanges requestChange = new RoleChangeRequest(m.getRole().getName(), action, ChangeSetType.ROLE, RequestType.ROLE, realm.getClientById(m.getRole().getClientId()).getClientId(),m.getAction(), m.getId(), new ArrayList<>(), m.getDeleteStatus());
            proofs.forEach(p -> requestChange.getUserRecord().add(new RequestChangesUserRecord(p.getUser().getUsername(), p.getId(), realm.getClientById(p.getClientId()).getClientId())));

            changes.add(requestChange);
        }
        return changes;
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("change-set/commit")
    public Response approveChangeSet(List<DraftChangeSet> changeSets) throws NoSuchAlgorithmException, JsonProcessingException {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        for (DraftChangeSet change : changeSets) {
            ActionType action = change.getActionType();
            ChangeSetType type = change.getType();
            List<?> mappings = getMappings(em, change, type, action);

            if (mappings.isEmpty()) continue;
            Object mapping = mappings.get(0);
            em.lock(mapping, LockModeType.PESSIMISTIC_WRITE); // Lock the entity to prevent concurrent modifications

            switch (type) {
                case USER_ROLE -> processUserRoleMapping(change, (TideUserRoleMappingDraftEntity) mapping, em, action);
                case COMPOSITE_ROLE -> processCompositeRoleMapping(change, (TideCompositeRoleMappingDraftEntity) mapping, em, action);
                case ROLE -> processRole(change, (TideRoleDraftEntity) mapping, em, action);
                case USER -> processUser(change, (TideUserDraftEntity) mapping, em, action);
                case CLIENT -> processClient(change, (TideClientFullScopeStatusDraftEntity) mapping, em, action);
            }

            em.flush(); // Persist changes to the database
        }
        // Return success message after approving the change sets
        return Response.ok("Change sets approved").build();
    }

    private List<?> getMappings(EntityManager em, DraftChangeSet change, ChangeSetType type, ActionType action) {
        return switch (type) {
            case USER_ROLE -> getUserRoleMappings(em, change, action);
            case GROUP, USER_GROUP_MEMBERSHIP, GROUP_ROLE -> null;
            case COMPOSITE_ROLE -> getCompositeRoleMappings(em, change, action);
            case ROLE -> getRoleMappings(em, change, action);
            case USER -> getUserMappings(em, change, action);
            case CLIENT -> getClientMappings(em, change, action);
        };
    }

    // Helper methods for retrieving specific mappings
    private List<?> getUserRoleMappings(EntityManager em, DraftChangeSet change, ActionType action) {
        String queryName = action == ActionType.CREATE ? "getUserRoleMappingsByStatusAndRealmAndRecordId" : "getUserRoleMappingsByDeleteStatusAndRealmAndRecordId";
        return em.createNamedQuery(queryName, TideUserRoleMappingDraftEntity.class)
                .setParameter(action == ActionType.CREATE ? "draftStatus" : "deleteStatus", DraftStatus.DRAFT)
                .setParameter("changesetId", change.getChangeSetId())
                .setParameter("realmId", realm.getId())
                .getResultList();
    }

    private List<?> getCompositeRoleMappings(EntityManager em, DraftChangeSet change, ActionType action) {
        String queryName = action == ActionType.CREATE ? "getAllCompositeRoleMappingsByStatusAndRealmAndRecordId" : "getAllCompositeRoleMappingsByDeletionStatusAndRealmAndRecordId";
        return em.createNamedQuery(queryName, TideCompositeRoleMappingDraftEntity.class)
                .setParameter(action == ActionType.CREATE ? "draftStatus" : "deleteStatus", DraftStatus.DRAFT)
                .setParameter("changesetId", change.getChangeSetId())
                .setParameter("realmId", realm.getId())
                .getResultList();
    }

    private List<?> getRoleMappings(EntityManager em, DraftChangeSet change, ActionType action) {
        return em.createNamedQuery("getRoleDraftByRoleAndDeleteStatus", TideRoleDraftEntity.class)
                .setParameter("deleteStatus", DraftStatus.DRAFT)
                .setParameter("changesetId", change.getChangeSetId())
                .getResultList();
    }

    private List<?> getUserMappings(EntityManager em, DraftChangeSet change, ActionType action) {
        return em.createNamedQuery("getTideUserDraftEntityByDraftStatusAndId", TideUserDraftEntity.class)
                .setParameter("draftStatus", DraftStatus.DRAFT)
                .setParameter("changesetId", change.getChangeSetId())
                .getResultList();
    }

    private List<?> getClientMappings(EntityManager em, DraftChangeSet change, ActionType action) {
        String queryName = action == ActionType.CREATE ? "getClientFullScopeStatusDraftByIdAndFullScopeEnabled" : "getClientFullScopeStatusDraftByIdAndFullScopeDisabled";
        return em.createNamedQuery(queryName, TideClientFullScopeStatusDraftEntity.class)
                .setParameter(action == ActionType.CREATE ? "fullScopeEnabled" : "fullScopeDisabled", DraftStatus.DRAFT)
                .setParameter("changesetId", change.getChangeSetId())
                .getResultList();
    }

    private void processUserRoleMapping(DraftChangeSet change, TideUserRoleMappingDraftEntity mapping, EntityManager em, ActionType action) throws NoSuchAlgorithmException, JsonProcessingException {
        RoleModel role = realm.getRoleById(mapping.getRoleId());
        if (role == null || !role.isClientRole()) return;

        if (action == ActionType.CREATE) {
            commitDraft(mapping, em, DraftStatus.ACTIVE);
        } else if (action == ActionType.DELETE) {
            commitDraft(mapping, em, DraftStatus.APPROVED, true);
            UserModel user = session.users().getUserById(realm, mapping.getUser().getId());
            user.deleteRoleMapping(role);
        }
        checkAndUpdateProofRecords(change, mapping, ChangeSetType.USER_ROLE, em);
    }

    private void processCompositeRoleMapping(DraftChangeSet change, TideCompositeRoleMappingDraftEntity mapping, EntityManager em, ActionType action) throws NoSuchAlgorithmException, JsonProcessingException {
        if (action == ActionType.CREATE) {
            commitDraft(mapping, em, DraftStatus.ACTIVE);
        } else if (action == ActionType.DELETE) {
            commitDraft(mapping, em, DraftStatus.APPROVED, true);
            RoleModel composite = realm.getRoleById(mapping.getComposite().getId());
            RoleModel child = realm.getRoleById(mapping.getChildRole().getId());
            composite.removeCompositeRole(child);
        }
        checkAndUpdateProofRecords(change, mapping, ChangeSetType.COMPOSITE_ROLE, em);
    }

    private void processRole(DraftChangeSet change, TideRoleDraftEntity mapping, EntityManager em, ActionType action) throws NoSuchAlgorithmException, JsonProcessingException {
        if (action == ActionType.DELETE) {
            commitDraft(mapping, em, DraftStatus.APPROVED, true);
            RoleModel role = realm.getRoleById(mapping.getRole().getId());
            realm.removeRole(role);
            cleanupRoleRecords(em, mapping);
        }
        checkAndUpdateProofRecords(change, mapping, ChangeSetType.ROLE, em);
    }

    private void processUser(DraftChangeSet change, TideUserDraftEntity mapping, EntityManager em, ActionType action) throws NoSuchAlgorithmException, JsonProcessingException {
        if (action == ActionType.CREATE) {
            commitDraft(mapping, em, DraftStatus.ACTIVE);
            em.remove(mapping);
            em.flush();
        }
        checkAndUpdateProofRecords(change, mapping, ChangeSetType.USER, em);
    }

    private void processClient(DraftChangeSet change, TideClientFullScopeStatusDraftEntity mapping, EntityManager em, ActionType action) throws NoSuchAlgorithmException, JsonProcessingException {
        if (action == ActionType.CREATE) {
            commitDraft(mapping, em, DraftStatus.APPROVED);
            ClientModel client = new TideClientAdapter(realm, em, session, mapping.getClient());
            client.setFullScopeAllowed(true);
        } else if (action == ActionType.DELETE) {
            commitDraft(mapping, em, DraftStatus.APPROVED, true);
            ClientModel client = new TideClientAdapter(realm, em, session, mapping.getClient());
            client.setFullScopeAllowed(false);
        }
        checkAndUpdateProofRecords(change, mapping, ChangeSetType.CLIENT, em);
    }

    private void commitDraft(Object mapping, EntityManager em, DraftStatus status) {
        commitDraft(mapping, em, status, false);
    }

    private void commitDraft(Object mapping, EntityManager em, DraftStatus status, boolean isDelete) {
        if (mapping instanceof TideUserRoleMappingDraftEntity) {
            if (isDelete) {
                ((TideUserRoleMappingDraftEntity) mapping).setDeleteStatus(status);
            } else {
                ((TideUserRoleMappingDraftEntity) mapping).setDraftStatus(status);
            }
        } else if (mapping instanceof TideCompositeRoleMappingDraftEntity) {
            if (isDelete) {
                ((TideCompositeRoleMappingDraftEntity) mapping).setDeleteStatus(status);
            } else {
                ((TideCompositeRoleMappingDraftEntity) mapping).setDraftStatus(status);
            }
        } else if (mapping instanceof TideRoleDraftEntity) {
            if (isDelete) {
                ((TideRoleDraftEntity) mapping).setDeleteStatus(status);
            } else {
                ((TideRoleDraftEntity) mapping).setDraftStatus(status);
            }
        } else if (mapping instanceof TideUserDraftEntity) {
            ((TideUserDraftEntity) mapping).setDraftStatus(status);
        } else if (mapping instanceof TideClientFullScopeStatusDraftEntity) {
            if (isDelete) {
                ((TideClientFullScopeStatusDraftEntity) mapping).setFullScopeDisabled(status);
            } else {
                ((TideClientFullScopeStatusDraftEntity) mapping).setFullScopeEnabled(status);
            }
        }
        em.persist(mapping);
        em.flush();
    }

    private void cleanupRoleRecords(EntityManager em, TideRoleDraftEntity mapping) {
        List<String> recordsToRemove = new ArrayList<>(em.createNamedQuery("getUserRoleMappingDraftsByRole", String.class)
                .setParameter("roleId", mapping.getRole().getId())
                .getResultList());

        em.createNamedQuery("deleteUserRoleMappingDraftsByRole")
                .setParameter("roleId", mapping.getRole().getId())
                .executeUpdate();

        recordsToRemove.addAll(em.createNamedQuery("selectIdsForRemoval", String.class)
                .setParameter("role", mapping.getRole())
                .getResultList());
        recordsToRemove.add(mapping.getId());

        em.createNamedQuery("removeDraftRequestsOnRemovalOfRole")
                .setParameter("role", mapping.getRole())
                .executeUpdate();

        recordsToRemove.forEach(id -> em.createNamedQuery("deleteProofRecords")
                .setParameter("recordId", id)
                .executeUpdate());
    }

    private void checkAndUpdateProofRecords(DraftChangeSet change, Object entity, ChangeSetType changeSetType, EntityManager em) throws NoSuchAlgorithmException, JsonProcessingException {
        List<ClientModel> affectedClients = getAffectedClients(entity, changeSetType, em);
        TideAuthzProofUtil tideAuthzProofUtil = new TideAuthzProofUtil(session, realm, em);

        for (ClientModel client : affectedClients) {
            List<AccessProofDetailEntity> proofDetails = getProofDetailsByChangeSetType(em, client, entity, changeSetType);
            for (AccessProofDetailEntity proofDetail : proofDetails) {
                em.lock(proofDetail, LockModeType.PESSIMISTIC_WRITE);
                UserEntity user = proofDetail.getUser();
                UserModel userModel = session.users().getUserById(realm, user.getId());
                UserModel wrappedUser = TideRolesUtil.wrapUserModel(userModel, session, realm);

                if (saveFinalProofDetailsOnApproval(proofDetail, change, em, user, client)) {
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
                        activeRoles = TideRolesUtil.getDeepUserRoleMappings(wrappedUser, session, realm, em, DraftStatus.ACTIVE, ActionType.CREATE).stream().filter(role -> {
                            if (role.isClientRole()) {
                                return !Objects.equals(((ClientModel) role.getContainer()).getClientId(), client.getClientId());
                            }
                            return true;
                        }).collect(Collectors.toSet());
                    } else {
                        activeRoles = new HashSet<>(TideRolesUtil.getDeepUserRoleMappings(wrappedUser, session, realm, em, DraftStatus.ACTIVE, ActionType.CREATE));
                    }
                    roleSet.addAll(activeRoles);
                }

                if (proofDetail.getChangesetType() == ChangeSetType.USER_ROLE) {
                    TideUserRoleMappingDraftEntity draftEntity = em.find(TideUserRoleMappingDraftEntity.class, proofDetail.getRecordId());
                    handleUserRoleMappingDraft(draftEntity, proofDetail, change, roleSet, actionType, client, tideAuthzProofUtil, wrappedUser, em);
                }
                else if (proofDetail.getChangesetType() == ChangeSetType.COMPOSITE_ROLE) {
                    TideCompositeRoleMappingDraftEntity draftEntity = em.find(TideCompositeRoleMappingDraftEntity.class, proofDetail.getRecordId());
                    handleCompositeRoleMappingDraft(draftEntity, proofDetail, change, roleSet, client, tideAuthzProofUtil, wrappedUser, em);
                }
                else if (proofDetail.getChangesetType() == ChangeSetType.ROLE) {
                    TideRoleDraftEntity draftEntity = em.find(TideRoleDraftEntity.class, proofDetail.getRecordId());
                    handleRoleDraft(draftEntity, proofDetail, change, roleSet, client, tideAuthzProofUtil, wrappedUser, em);
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
                    return clientModel.isFullScopeAllowed() || !scopeDraft.isEmpty();
                }).distinct().collect(Collectors.toList());

        if (changeSetType == ChangeSetType.USER_ROLE) {
            RoleModel roleModel = realm.getRoleById(((TideUserRoleMappingDraftEntity) entity).getRoleId());
            affectedClients.add(realm.getClientById(roleModel.getContainerId()));
        } else if (changeSetType == ChangeSetType.COMPOSITE_ROLE) {
            RoleModel role = realm.getRoleById(((TideCompositeRoleMappingDraftEntity) entity).getChildRole().getId());
            affectedClients.add(realm.getClientById(role.getContainerId()));
        } else if (changeSetType == ChangeSetType.ROLE) {
            RoleModel role = realm.getRoleById(((TideRoleDraftEntity) entity).getRole().getId());
            affectedClients.add(realm.getClientById(role.getContainerId()));
        }

        return affectedClients.stream().distinct().collect(Collectors.toList());
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
                    UserModel user = session.users().getUserById(realm, t.getUser().getId());
                    TideAuthzProofUtil util = new TideAuthzProofUtil(session, realm, em);

                    TideUserRoleMappingDraftEntity role = em.find(TideUserRoleMappingDraftEntity.class, t.getRecordId());
                    Set<RoleModel> roles = new HashSet<>();
                    roles.add(realm.getRoleById(role.getRoleId()));
                    util.generateAndSaveProofDraft(client, user, roles, t.getRecordId(), ChangeSetType.USER_ROLE, ActionType.CREATE, true);
                }
                return em.createNamedQuery("getProofDetailsByClient", AccessProofDetailEntity.class)
                        .setParameter("clientId", client.getId())
                        .getResultList();
            } else {
                return em.createNamedQuery("getProofDetailsByClient", AccessProofDetailEntity.class)
                        .setParameter("clientId", client.getId())
                        .getResultList();
            }
        }
        return Collections.emptyList();
    }

    private void handleUserRoleMappingDraft(TideUserRoleMappingDraftEntity draftEntity, AccessProofDetailEntity proofDetail, DraftChangeSet change, Set<RoleModel> roles, ActionType actionType, ClientModel client, TideAuthzProofUtil tideAuthzProofUtil, UserModel wrappedUser, EntityManager em) throws JsonProcessingException, NoSuchAlgorithmException {
        if (draftEntity == null || (draftEntity.getDraftStatus() == DraftStatus.ACTIVE && draftEntity.getDeleteStatus() == null)) {
            return;
        }

        if (change.getActionType() == ActionType.DELETE) {
            if (change.getType() == ChangeSetType.CLIENT) {
                boolean hasCommittedRole = ((TideUserAdapter) wrappedUser).getRoleMappingsStreamByStatusAndAction(DraftStatus.ACTIVE, ActionType.CREATE)
                        .anyMatch(x -> x.isClientRole() && Objects.equals(x.getContainerId(), client.getId()));

                if (hasCommittedRole) {
                    String proof = proofDetail.getProofDraft();
                    TideUserRoleMappingDraftEntity userRoleDraft = em.find(TideUserRoleMappingDraftEntity.class, proofDetail.getRecordId());
                    if (userRoleDraft != null) {
                        roles.add(realm.getRoleById(userRoleDraft.getRoleId()));
                    }
                    AccessDetails accessDetails = tideAuthzProofUtil.getAccessToRemove(client, roles, true);
                    String updatedProof = tideAuthzProofUtil.removeAccesFromToken(proof, accessDetails);
                    String newProof = tideAuthzProofUtil.removeAudienceFromToken(updatedProof);
                    proofDetail.setProofDraft(newProof);
                    return;
                } else {
                    em.remove(proofDetail);
                    em.flush();
                }
            }

            if (draftEntity.getDraftStatus() == DraftStatus.ACTIVE && draftEntity.getDeleteStatus() == DraftStatus.PENDING) {
                draftEntity.setDeleteStatus(DraftStatus.DRAFT);
            } else if (draftEntity.getDraftStatus() == DraftStatus.APPROVED) {
                draftEntity.setDraftStatus(DraftStatus.DRAFT);
            }
            String proof = proofDetail.getProofDraft();
            AccessDetails accessDetails = tideAuthzProofUtil.getAccessToRemove(client, roles, client.isFullScopeAllowed());
            String updatedProof = tideAuthzProofUtil.removeAccesFromToken(proof, accessDetails);
            String newProof = tideAuthzProofUtil.removeAudienceFromToken(updatedProof);
            proofDetail.setProofDraft(newProof);
            return;
        }

        roles.add(realm.getRoleById(draftEntity.getRoleId()));
        draftEntity.setDraftStatus(DraftStatus.DRAFT);
        String proof = proofDetail.getProofDraft();
        String updatedProof = tideAuthzProofUtil.updateDraftProofDetails(client, wrappedUser, proof, roles, actionType, true);
        proofDetail.setProofDraft(updatedProof);
    }

    private void handleCompositeRoleMappingDraft(TideCompositeRoleMappingDraftEntity draftEntity, AccessProofDetailEntity proofDetail, DraftChangeSet change, Set<RoleModel> roles, ClientModel client, TideAuthzProofUtil tideAuthzProofUtil, UserModel wrappedUser, EntityManager em) throws JsonProcessingException, NoSuchAlgorithmException {
        if (draftEntity == null || (draftEntity.getDraftStatus() == DraftStatus.ACTIVE && draftEntity.getDeleteStatus() == null)) {
            return;
        }

        if (change.getActionType() == ActionType.DELETE) {
            if (change.getType() == ChangeSetType.CLIENT) {
                String proof = proofDetail.getProofDraft();
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
                }

                Set<RoleModel> rolesToAdd = ((TideUserAdapter) wrappedUser).getRoleMappingsStreamByStatusAndAction(DraftStatus.ACTIVE, ActionType.CREATE).filter(r -> r.isClientRole() && Objects.equals(r.getContainerId(), client.getId())).collect(Collectors.toSet());
                String updatedProof = tideAuthzProofUtil.updateDraftProofDetails(client, wrappedUser, proof, rolesToAdd, draftEntity.getAction(), true);
                AccessDetails accessDetails = tideAuthzProofUtil.getAccessToRemove(client, roles, true);
                String cleanedProof = tideAuthzProofUtil.removeAccesFromToken(updatedProof, accessDetails);
                String newProof = tideAuthzProofUtil.removeAudienceFromToken(cleanedProof);
                proofDetail.setProofDraft(newProof);
                return;
            }

            if (draftEntity.getDraftStatus() == DraftStatus.ACTIVE && draftEntity.getDeleteStatus() == DraftStatus.PENDING) {
                draftEntity.setDeleteStatus(DraftStatus.DRAFT);
            } else if (draftEntity.getDraftStatus() == DraftStatus.APPROVED) {
                draftEntity.setDraftStatus(DraftStatus.DRAFT);
            }
            String proof = proofDetail.getProofDraft();
            AccessDetails accessDetails = tideAuthzProofUtil.getAccessToRemove(client, roles, client.isFullScopeAllowed());
            String updatedProof = tideAuthzProofUtil.removeAccesFromToken(proof, accessDetails);
            String newProof = tideAuthzProofUtil.removeAudienceFromToken(updatedProof);
            proofDetail.setProofDraft(newProof);
            return;
        }

        draftEntity.setDraftStatus(DraftStatus.DRAFT);
        String proof = proofDetail.getProofDraft();
        String updatedProof = tideAuthzProofUtil.updateDraftProofDetails(client, wrappedUser, proof, roles, draftEntity.getAction(), true);
        proofDetail.setProofDraft(updatedProof);
    }

    private void handleRoleDraft(TideRoleDraftEntity draftEntity, AccessProofDetailEntity proofDetail, DraftChangeSet change, Set<RoleModel> roles, ClientModel client, TideAuthzProofUtil tideAuthzProofUtil, UserModel wrappedUser, EntityManager em) throws JsonProcessingException, NoSuchAlgorithmException {
        if (draftEntity == null || (draftEntity.getDraftStatus() == DraftStatus.ACTIVE && draftEntity.getDeleteStatus() == null)) {
            return;
        }

        if (change.getActionType() == ActionType.DELETE) {
            if (change.getType() == ChangeSetType.CLIENT) {
                String proof = proofDetail.getProofDraft();
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
                }
                AccessDetails accessDetails = tideAuthzProofUtil.getAccessToRemove(client, roles, true);
                String updatedProof = tideAuthzProofUtil.removeAccesFromToken(proof, accessDetails);
                String newProof = tideAuthzProofUtil.removeAudienceFromToken(updatedProof);
                proofDetail.setProofDraft(newProof);
                return;
            }
            if (draftEntity.getDraftStatus() == DraftStatus.ACTIVE && draftEntity.getDeleteStatus() == DraftStatus.PENDING) {
                draftEntity.setDeleteStatus(DraftStatus.DRAFT);
            } else if (draftEntity.getDraftStatus() == DraftStatus.APPROVED) {
                draftEntity.setDraftStatus(DraftStatus.DRAFT);
            }
            String proof = proofDetail.getProofDraft();
            AccessDetails accessDetails = tideAuthzProofUtil.getAccessToRemove(client, roles, client.isFullScopeAllowed());
            String updatedProof = tideAuthzProofUtil.removeAccesFromToken(proof, accessDetails);
            String newProof = tideAuthzProofUtil.removeAudienceFromToken(updatedProof);
            proofDetail.setProofDraft(newProof);
            return;
        }

        draftEntity.setDraftStatus(DraftStatus.DRAFT);
        String proof = proofDetail.getProofDraft();
        String updatedProof = tideAuthzProofUtil.updateDraftProofDetails(client, wrappedUser, proof, roles, draftEntity.getAction(), true);
        proofDetail.setProofDraft(updatedProof);
    }

    private void handleUserDraft(TideUserDraftEntity draftEntity, AccessProofDetailEntity proofDetail, ClientModel client, TideAuthzProofUtil tideAuthzProofUtil, UserModel wrappedUser) throws JsonProcessingException, NoSuchAlgorithmException {
        if (draftEntity == null || (draftEntity.getDraftStatus() == DraftStatus.ACTIVE && draftEntity.getDeleteStatus() == null)) {
            return;
        }

        draftEntity.setDraftStatus(DraftStatus.DRAFT);
        String proof = proofDetail.getProofDraft();
        Set<RoleModel> roleSet = new HashSet<>();
        String updatedProof = tideAuthzProofUtil.updateDraftProofDetails(client, wrappedUser, proof, roleSet, draftEntity.getAction(), client.isFullScopeAllowed());
        proofDetail.setProofDraft(updatedProof);
    }

    private void handleClientDraft(TideClientFullScopeStatusDraftEntity draftEntity, AccessProofDetailEntity proofDetail, DraftChangeSet change, ClientModel client, TideAuthzProofUtil tideAuthzProofUtil, UserModel wrappedUser, EntityManager em) throws JsonProcessingException, NoSuchAlgorithmException {
        if (draftEntity == null || (draftEntity.getFullScopeEnabled() == DraftStatus.ACTIVE && draftEntity.getFullScopeDisabled() == null)
                || (draftEntity.getFullScopeDisabled() == DraftStatus.ACTIVE && draftEntity.getFullScopeEnabled() == DraftStatus.NULL)) {
            return;
        }

        if (change.getActionType() == ActionType.DELETE) {
            if (draftEntity.getFullScopeDisabled() == DraftStatus.ACTIVE && draftEntity.getFullScopeEnabled() == DraftStatus.PENDING) {
                draftEntity.setFullScopeEnabled(DraftStatus.DRAFT);
            }

            String proof = proofDetail.getProofDraft();
            Set<RoleModel> activeRoles = TideRolesUtil.getDeepUserRoleMappings(wrappedUser, session, realm, em, DraftStatus.ACTIVE, ActionType.CREATE).stream().filter(role -> {
                if (role.isClientRole()) {
                    return !Objects.equals(((ClientModel) role.getContainer()).getClientId(), client.getClientId());
                }
                return true;
            }).collect(Collectors.toSet());

            Set<RoleModel> roles = TideRolesProtocolMapper.getAccess(activeRoles, client, client.getClientScopes(true).values().stream(), true);
            AccessDetails accessDetails = tideAuthzProofUtil.getAccessToRemove(client, roles, false);
            String updatedProof = tideAuthzProofUtil.removeAccesFromToken(proof, accessDetails);
            String newProof = tideAuthzProofUtil.removeAudienceFromToken(updatedProof);
            proofDetail.setProofDraft(newProof);
            return;
        }

        draftEntity.setFullScopeEnabled(DraftStatus.DRAFT);
        String proof = proofDetail.getProofDraft();
        Set<RoleModel> roleSet = new HashSet<>();
        String updatedProof = tideAuthzProofUtil.updateDraftProofDetails(client, wrappedUser, proof, roleSet, draftEntity.getAction(), true);
        proofDetail.setProofDraft(updatedProof);
    }

    private Boolean saveFinalProofDetailsOnApproval(AccessProofDetailEntity proofDetail, DraftChangeSet change, EntityManager em, UserEntity user, ClientModel client) throws NoSuchAlgorithmException, JsonProcessingException {
        if (Objects.equals(proofDetail.getRecordId(), change.getChangeSetId())) {
            if (change.getType() == ChangeSetType.COMPOSITE_ROLE) {
                TideCompositeRoleMappingDraftEntity record = em.find(TideCompositeRoleMappingDraftEntity.class, proofDetail.getRecordId());
                if (record == null) {
                    return false;
                }

                List<TideUserRoleMappingDraftEntity> userRoleRecord = em.createNamedQuery("getUserRoleAssignmentDraftEntity", TideUserRoleMappingDraftEntity.class)
                        .setParameter("user", user)
                        .setParameter("roleId", record.getComposite().getId())
                        .getResultList();


                if (userRoleRecord.isEmpty() || userRoleRecord.get(0).getDraftStatus() != DraftStatus.ACTIVE) {
                    return false;
                }
            }
            new TideAuthzProofUtil(session, realm, em).saveProofToDatabase(proofDetail.getProofDraft(), client.getId(), user);
            em.remove(proofDetail);
            em.flush();

            if(change.getType() == ChangeSetType.USER_ROLE) {
                TideUserRoleMappingDraftEntity record = em.find(TideUserRoleMappingDraftEntity.class, proofDetail.getRecordId());
                UserModel userModel = session.users().getUserById(realm, user.getId());
                UserModel wrappedUser = TideRolesUtil.wrapUserModel(userModel, session, realm);
                RoleEntity roleEntity = em.find(RoleEntity.class, record.getRoleId());
                List<TideCompositeRoleMappingDraftEntity> compositeRoleDrafts = em.createNamedQuery("getCompositeEntityByParent", TideCompositeRoleMappingDraftEntity.class)
                        .setParameter("composite", roleEntity)
                        .getResultList();
                TideAuthzProofUtil util = new TideAuthzProofUtil(session, realm, em);
                for(TideCompositeRoleMappingDraftEntity draft : compositeRoleDrafts){
                    if(draft.getDraftStatus() != DraftStatus.ACTIVE){
                        Set<RoleModel> roles = new HashSet<>();
                        roles.add(realm.getRoleById(draft.getChildRole().getId()));
                        util.generateAndSaveProofDraft(client, wrappedUser, roles, draft.getId(), ChangeSetType.COMPOSITE_ROLE, ActionType.CREATE, true);
                    }
                }
            }
            return true;
        }
        return false;
    }

    private List<String> getProofDetails(EntityManager em, String recordId) {
        return em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                .setParameter("recordId", recordId)
                .getResultStream()
                .map(AccessProofDetailEntity::getProofDraft)
                .collect(Collectors.toList());
    }
}
