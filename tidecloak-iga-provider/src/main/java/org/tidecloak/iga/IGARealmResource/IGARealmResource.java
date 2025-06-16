package org.tidecloak.iga.IGARealmResource;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.persistence.NoResultException;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.cache.UserCache;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.midgard.Midgard;
import org.midgard.models.*;
import org.midgard.models.InitializerCertificateModel.InitializerCertifcate;
import org.midgard.models.RequestExtensions.UserContextSignRequest;
import org.midgard.models.UserContext.UserContext;
import org.tidecloak.iga.ChangeSetCommitter.ChangeSetCommitter;
import org.tidecloak.iga.ChangeSetCommitter.ChangeSetCommitterFactory;
import org.tidecloak.iga.ChangeSetProcessors.ChangeSetProcessor;
import org.tidecloak.iga.ChangeSetProcessors.ChangeSetProcessorFactory;
import org.tidecloak.iga.ChangeSetProcessors.keys.UserClientKey;
import org.tidecloak.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.iga.ChangeSetProcessors.models.ChangeSetRequestList;
import org.tidecloak.iga.ChangeSetProcessors.utils.TideEntityUtils;
import org.tidecloak.iga.ChangeSetSigner.ChangeSetSigner;
import org.tidecloak.iga.ChangeSetSigner.ChangeSetSignerFactory;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.shared.enums.WorkflowType;
import org.tidecloak.iga.interfaces.models.*;
import org.tidecloak.iga.utils.IGAUtils;
import org.tidecloak.jpa.entities.*;
import org.tidecloak.jpa.entities.drafting.*;
import org.tidecloak.shared.enums.models.WorkflowParams;
import org.tidecloak.shared.models.SecretKeys;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.tidecloak.iga.TideRequests.TideRoleRequests.*;

public class IGARealmResource {

    private final KeycloakSession session;
    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;

    public IGARealmResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth) {
        this.session = session;
        this.realm = realm;
        this.auth = auth;
    }

    @GET
    @Path("users/{user-id}/roles/{role-id}/draft/status")
    public Response getUserRoleAssignmentDraftStatus(@PathParam("user-id") String userId, @PathParam("role-id") String roleId) {
        if(!IGAUtils.isIGAEnabled(realm)){
            return Response.ok().entity(new ArrayList<>()).build();
        }
        auth.users().requireQuery(); // Ensure the user has the necessary permissions

        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        UserEntity userEntity = em.find(UserEntity.class, userId);

        try {
            TideUserRoleMappingDraftEntity userRoleMappingDraft = em.createNamedQuery("getUserRoleAssignmentDraftEntity", TideUserRoleMappingDraftEntity.class)
                    .setParameter("user", userEntity)
                    .setParameter("roleId", roleId)
                    .getSingleResult();

            Map<String, DraftStatus> statusMap = new HashMap<>();
            statusMap.put("draftStatus", userRoleMappingDraft.getDraftStatus());
            statusMap.put("deleteStatus", userRoleMappingDraft.getDeleteStatus());


            return Response.ok(statusMap).build();
        } catch (NoResultException e) {
            return Response.status(Response.Status.OK).entity(new ArrayList<>()).build();
        }
    }

    @GET
    @Path("users/{user-id}/draft/status")
    public Response getUserDraftStatus(@PathParam("user-id") String id) {
        if(!IGAUtils.isIGAEnabled(realm)){
            return Response.ok().entity(new ArrayList<>()).build();
        }
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
            return Response.status(Response.Status.OK).entity(new ArrayList<>()).build();
        }
    }

    @GET
    @Path("composite/{parent-id}/child/{child-id}/draft/status")
    public Response getRoleDraftStatus(@PathParam("parent-id") String parentId, @PathParam("child-id") String childId) {
        if(!IGAUtils.isIGAEnabled(realm)){
            return Response.ok().entity(new ArrayList<>()).build();
        }
        auth.users().requireQuery(); // Ensure the user has the necessary permissions

        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        RoleModel parentRole = realm.getRoleById(parentId);
        RoleModel childRole = realm.getRoleById(childId);

        try{
            TideCompositeRoleMappingDraftEntity entity = em.createNamedQuery("getCompositeRoleMappingDraft", TideCompositeRoleMappingDraftEntity.class)
                    .setParameter("composite", TideEntityUtils.toRoleEntity(parentRole, em))
                    .setParameter("childRole", TideEntityUtils.toRoleEntity(childRole, em))
                    .getSingleResult();

            Map<String, DraftStatus> statusMap = new HashMap<>();
            statusMap.put("draftStatus", entity.getDraftStatus());
            statusMap.put("deleteStatus", entity.getDeleteStatus());
            return Response.ok(statusMap).build();
        }
        catch (NoResultException e) {
            return Response.status(Response.Status.OK).entity(new ArrayList<>()).build();
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("change-set/cancel")
    public Response cancelChangeSet(ChangeSetRequest changeSet) throws Exception {
        try{
            auth.realm().requireManageRealm();
            EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
            ChangeSetType type = changeSet.getType();

            List<?> mapping = IGAUtils.fetchDraftRecordEntityByRequestId(em, type, changeSet.getChangeSetId());
            if (mapping.isEmpty()) {
                return Response.status(Response.Status.NOT_FOUND).entity("Change request was not found.").build();
            }

            mapping.forEach(m -> {
                em.lock(m, LockModeType.PESSIMISTIC_WRITE); // Lock the entity to prevent concurrent modifications
                ChangeSetProcessorFactory processorFactory = new ChangeSetProcessorFactory(); // Initialize the processor factory
                WorkflowParams params = new WorkflowParams(null, false, changeSet.getActionType(), changeSet.getType());
                try {
                    processorFactory.getProcessor(changeSet.getType()).executeWorkflow(session, m, em, WorkflowType.CANCEL, params, null);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });

            ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(changeSet.getChangeSetId(), changeSet.getType()));
            if(changesetRequestEntity != null ) {
                changesetRequestEntity.getAdminAuthorizations().clear();
                em.remove(changesetRequestEntity);
            }
            em.flush();
            UserCache userCache = session.getProvider(UserCache.class);
            userCache.clear();

            // Return success message after approving the change sets
            return Response.ok("Change set request has been canceled").build();

        } catch(Exception e) {
            return buildResponse(500, "There was an error commiting this change set request. " + e.getMessage());

        }
    }


    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("change-set/sign")
    public Response signChangeset(ChangeSetRequest changeSet) throws Exception {
        try{
            return signChangeSets(Collections.singletonList(changeSet));
        }catch (Exception ex) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(ex.getMessage()).build();
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("change-set/sign/batch")
    public Response signMultipleChangeSets(ChangeSetRequestList changeSets) throws Exception {
        try{
            return signChangeSets(changeSets.getChangeSets());
        }catch (Exception ex) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(ex.getMessage()).build();
        }
    }


    @GET
    @Path("change-set/users/requests")
    public Response getRequestedChangesForUsers() {
        auth.realm().requireManageRealm();
        if(!IGAUtils.isIGAEnabled(realm)){
            return Response.ok().entity(new ArrayList<>()).build();
        }
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<RequestedChanges> changes = new ArrayList<>(processUserRoleMappings(em, realm));
        return Response.ok(changes).build();
    }

    @GET
    @Path("change-set/roles/requests")
    public Response getRequestedChanges() {
        auth.realm().requireManageRealm();

        if(!IGAUtils.isIGAEnabled(realm)){
            return Response.ok().entity(new ArrayList<>()).build();
        }
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<RequestedChanges> requestedChangesList = new ArrayList<>(processRoleMappings(em, realm));
        requestedChangesList.addAll(processCompositeRoleMappings(em, realm));
        return Response.ok(requestedChangesList).build();
    }

    @GET
    @Path("change-set/clients/requests")
    public Response getRequestedChangesForClients() {
        auth.realm().requireManageRealm();

        if(!IGAUtils.isIGAEnabled(realm)){
            return Response.ok().entity(new ArrayList<>()).build();
        }
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<RequestedChanges> changes = new ArrayList<>(processClientDraftRecords(em, realm));
        return Response.ok(changes).build();
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("change-set/commit")
    public Response commitChangeSet(ChangeSetRequest change) throws Exception {
        try{
            return commitChangeSets(Collections.singletonList(change));
        }catch (Exception ex) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(ex.getMessage()).build();
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("change-set/commit/batch")
    public Response commitMultipleChangeSets(ChangeSetRequestList changeSets) throws Exception {
        try{
            return commitChangeSets(changeSets.getChangeSets());
        }
        catch (Exception ex) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(ex.getMessage()).build();
        }
    }

    @POST
    @Path("generate-default-user-context")
    public Response generateDefaultUserContext(@Parameter(description = "Clients to generate the default user context for") List<String> clients) {
        auth.realm().requireManageRealm();
        ChangeSetProcessorFactory changeSetProcessorFactory = new ChangeSetProcessorFactory();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        try {
            for (String clientId : clients) {
                ClientModel clientModel = realm.getClientByClientId(clientId);
                if (clientModel == null) continue;

                ClientEntity client = em.find(ClientEntity.class, clientModel.getId());
                if (client == null) continue;

                List<TideClientDraftEntity> clientDrafts = em.createNamedQuery("getClientFullScopeStatus", TideClientDraftEntity.class)
                        .setParameter("client", client)
                        .getResultList();
                if (clientDrafts.isEmpty()) continue;

                for (TideClientDraftEntity draft : clientDrafts) {

                    // Remove existing Access Proofs
                    List<AccessProofDetailEntity> accessProof = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                            .setParameter("recordId", draft.getChangeRequestId()).getResultList();
                    accessProof.clear();
                    // Remove existing ChangeSetRequestEntity
                    ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class,
                            new ChangesetRequestEntity.Key(draft.getChangeRequestId(), ChangeSetType.CLIENT));
                    if (changesetRequestEntity != null) {
                        changesetRequestEntity.getAdminAuthorizations().clear();
                        em.remove(changesetRequestEntity);
                    }

                    // Execute Workflow
                    try {
                        draft.setDraftStatus(DraftStatus.DRAFT);
                        WorkflowParams params = new WorkflowParams(DraftStatus.DRAFT, false, ActionType.CREATE, ChangeSetType.CLIENT);
                        changeSetProcessorFactory.getProcessor(ChangeSetType.CLIENT)
                                .executeWorkflow(session, draft, em, WorkflowType.REQUEST, params, null);
                    } catch (Exception e) {
                        throw new WebApplicationException("Workflow execution failed for draft: " + draft.getId(), e, Response.Status.INTERNAL_SERVER_ERROR);
                    }
                }
            }

            em.flush(); // Flush once after processing all clients for efficiency
            return Response.ok("Default User Contexts Generated").build();

        } catch (Exception e) {
            return buildResponse(500, "There was an error generating the default user contexts. " + e.getMessage());
        }
    }

    public static List<RequestedChanges> processClientDraftRecords(EntityManager em, RealmModel realm) {
        // Get all pending changes, records that do not have an active delete status or active draft status
        return processClientDraftRecords(em, realm, DraftStatus.ACTIVE);
    }
    public static List<RequestedChanges> processClientDraftRecords(EntityManager em, RealmModel realm, DraftStatus draftStatus ) {
        List<RequestedChanges> changes = new ArrayList<>();
        List<TideClientDraftEntity> mappings = em.createNamedQuery("getClientFullScopeStatusDraftThatDoesNotHaveStatus", TideClientDraftEntity.class)
                .setParameter("status", draftStatus)
                .setParameter("status2", DraftStatus.NULL)
                .getResultList();


        for (TideClientDraftEntity c : mappings) {
            em.lock(c, LockModeType.PESSIMISTIC_WRITE); // Lock the entity to prevent concurrent modifications
            ClientModel client = realm.getClientById(c.getClient().getId());
            if (client == null) {
                continue;
            }

            List<AccessProofDetailEntity> proofs = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                    .setParameter("recordId", c.getChangeRequestId())
                    .getResultList();


            RequestedChanges requestChange = new RequestedChanges("",ChangeSetType.CLIENT_FULLSCOPE, RequestType.CLIENT, client.getClientId(), realm.getName(), c.getAction(), c.getChangeRequestId(), new ArrayList<>(), DraftStatus.DRAFT, DraftStatus.NULL);
            proofs.forEach(p -> {
                em.lock(p, LockModeType.PESSIMISTIC_WRITE);

                if(p.getChangesetType().equals(ChangeSetType.CLIENT_DEFAULT_USER_CONTEXT)) {
                    requestChange.getUserRecord().add(new RequestChangesUserRecord("Default User Context for all USERS", p.getId(), c.getClient().getClientId(), p.getProofDraft()));
                }
                else if (p.getChangesetType().equals(ChangeSetType.CLIENT_FULLSCOPE)) {
                    requestChange.getUserRecord().add(new RequestChangesUserRecord(p.getUser().getUsername(), p.getId(), c.getClient().getClientId(), p.getProofDraft()));
                }
            });

            if(c.getFullScopeEnabled() != DraftStatus.ACTIVE && c.getFullScopeEnabled() != DraftStatus.NULL) {
                String action = "Enabling Full-Scope on Client";

                requestChange.setAction(action);
                requestChange.setStatus(c.getFullScopeEnabled());
                requestChange.setActionType(ActionType.CREATE);
            }
            else if ( c.getFullScopeDisabled() != DraftStatus.ACTIVE && c.getFullScopeDisabled() != DraftStatus.NULL) {
                String action = "Disabling Full-Scope on Client";
                requestChange.setAction(action);
                requestChange.setStatus(c.getFullScopeDisabled());
                requestChange.setActionType(ActionType.DELETE);
            }
            changes.add(requestChange);

        }
        List<AccessProofDetailEntity> proofs = em.createNamedQuery("getProofDetailsForDraftByChangeSetTypeAndRealm", AccessProofDetailEntity.class)
                .setParameter("realmId", realm.getId())
                .setParameter("changesetType", ChangeSetType.CLIENT)
                .getResultList();
        if (!proofs.isEmpty()) {
            proofs.forEach(p -> {
                TideClientDraftEntity tideClientDraftEntity = (TideClientDraftEntity) IGAUtils.fetchDraftRecordEntity(em, p.getChangesetType(), p.getChangeRequestKey().getMappingId());
                ClientModel client = realm.getClientById(p.getClientId());
                RequestedChanges requestChange = new RequestedChanges("New Client Created",ChangeSetType.CLIENT, RequestType.CLIENT, client.getClientId(), realm.getName(), ActionType.CREATE, p.getChangeRequestKey().getChangeRequestId(), new ArrayList<>(), tideClientDraftEntity.getDraftStatus(), DraftStatus.NULL);
                requestChange.getUserRecord().add(new RequestChangesUserRecord("Default User Context for all USERS", p.getId(), client.getClientId(), p.getProofDraft()));
                changes.add(requestChange);
            });
        }
        return changes;
    }
    public static List<RequestedChanges> processUserRoleMappings(EntityManager em, RealmModel realm) {
        // Get all pending changes, records that do not have an active delete status or active draft status
        return processUserRoleMappings(em, realm, DraftStatus.ACTIVE);
    }

    public static List<RequestedChanges> processUserRoleMappings(EntityManager em, RealmModel realm, DraftStatus status) {
        List<RequestedChanges> changes = new ArrayList<>();
        List<TideUserRoleMappingDraftEntity> mappings = em.createNamedQuery("getAllPendingUserRoleMappingsByRealm", TideUserRoleMappingDraftEntity.class)
            .setParameter("draftStatus", status)
            .setParameter("deleteStatus", status)
            .setParameter("realmId", realm.getId())
            .getResultList();

        for (TideUserRoleMappingDraftEntity m : mappings) {
            em.lock(m, LockModeType.PESSIMISTIC_WRITE); // Lock the entity to prevent concurrent modifications
            RoleModel role = realm.getRoleById(m.getRoleId());
            if (role == null ) {
                continue;
            }
            String clientId = role.isClientRole() ? realm.getClientById(role.getContainerId()).getClientId() : null;
            List<AccessProofDetailEntity> proofs = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                    .setParameter("recordId", m.getChangeRequestId())
                    .getResultList();

            if(proofs.isEmpty()){
                continue;
            }

            boolean isDeleteRequest = m.getDraftStatus() == DraftStatus.ACTIVE && (m.getDeleteStatus() != DraftStatus.ACTIVE || m.getDeleteStatus() != null);
            String actionDescription = isDeleteRequest ? "Unassigning Role from User" : "Granting Role to User";
            ActionType action = isDeleteRequest ? ActionType.DELETE : ActionType.CREATE;
            RequestedChanges requestChange = new RoleChangeRequest(realm.getRoleById(m.getRoleId()).getName(), actionDescription, ChangeSetType.USER_ROLE, RequestType.USER, clientId, realm.getName(), action, m.getChangeRequestId(), new ArrayList<>(), m.getDraftStatus(), m.getDeleteStatus());
            proofs.forEach(p -> {
                em.lock(p, LockModeType.PESSIMISTIC_WRITE);
                requestChange.getUserRecord().add(new RequestChangesUserRecord(p.getUser().getUsername(), p.getId(), realm.getClientById(p.getClientId()).getClientId(), p.getProofDraft()));
            });
            changes.add(requestChange);
        }
        return changes;
    }

    public static List<RequestedChanges> processCompositeRoleMappings(EntityManager em, RealmModel realm) {
        // Get all pending changes, records that do not have an active delete status or active draft status
        return processCompositeRoleMappings(em, realm, DraftStatus.ACTIVE);
    }

        public static List<RequestedChanges> processCompositeRoleMappings(EntityManager em, RealmModel realm, DraftStatus status) {
        List<RequestedChanges> changes = new ArrayList<>();
        List<TideCompositeRoleMappingDraftEntity> mappings = em.createNamedQuery("getAllCompositeRoleMappingsByRealm", TideCompositeRoleMappingDraftEntity.class)
                .setParameter("draftStatus", status)
                .setParameter("deleteStatus", status)
                .setParameter("realmId", realm.getId())
                .getResultList();

        for (TideCompositeRoleMappingDraftEntity m : mappings) {
            if (m.getComposite() == null) {
                continue;
            }
            List<AccessProofDetailEntity> proofs = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                    .setParameter("recordId", m.getChangeRequestId())
                    .setLockMode(LockModeType.PESSIMISTIC_WRITE)
                    .getResultList();
            if(proofs.isEmpty()){
                continue;
            }
            boolean isDeleteRequest = m.getDraftStatus() == DraftStatus.ACTIVE && (m.getDeleteStatus() != DraftStatus.ACTIVE || m.getDeleteStatus() != null);
            String actionDescription = isDeleteRequest ? "Removing Role from Composite Role": "Granting Role to Composite Role";
            ActionType action = isDeleteRequest ? ActionType.DELETE : ActionType.CREATE;

            String clientId = m.getComposite().isClientRole() ? realm.getClientById(m.getComposite().getClientId()).getClientId() : "" ;
            RequestedChanges requestChange = new CompositeRoleChangeRequest(m.getChildRole().getName(), m.getComposite().getName(), actionDescription, ChangeSetType.COMPOSITE_ROLE, RequestType.ROLE, clientId, realm.getName(), action, m.getChangeRequestId(), new ArrayList<>(), m.getDraftStatus(), m.getDeleteStatus());

            proofs.forEach(p -> {
                if ( p.getChangesetType().equals(ChangeSetType.DEFAULT_ROLES)){
                    requestChange.getUserRecord().add(new RequestChangesUserRecord("Default User Context For All Users", p.getId(), realm.getClientById(p.getClientId()).getClientId(), p.getProofDraft()));

                } else {
                    requestChange.getUserRecord().add(new RequestChangesUserRecord(p.getUser().getUsername(), p.getId(), realm.getClientById(p.getClientId()).getClientId(), p.getProofDraft()));
                }
            });
            changes.add(requestChange);
        }


        return changes;
    }
    public static List<RequestedChanges> processRoleMappings(EntityManager em, RealmModel realm) {
        // Get all pending changes, records that do not have an active delete status or active draft status
        return  processRoleMappings(em, realm, DraftStatus.ACTIVE);
    }
    public static List<RequestedChanges> processRoleMappings(EntityManager em, RealmModel realm, DraftStatus status) {
        List<RequestedChanges> changes = new ArrayList<>();
        List<TideRoleDraftEntity> mappings = em.createNamedQuery("getAllRoleDraft", TideRoleDraftEntity.class)
                .setParameter("draftStatus", status)
                .setParameter("deleteStatus", status)
                .setParameter("realmId", realm.getId())
                .getResultList();

        for (TideRoleDraftEntity m : mappings) {
            String clientId = m.getRole().isClientRole() ? m.getRole().getClientId() : null;
            List<AccessProofDetailEntity> proofs = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                    .setParameter("recordId", m.getChangeRequestId())
                    .getResultList();
            if(proofs.isEmpty()){
                continue;
            }

            String action = clientId != null ? "Deleting Role from Client" : "Deleting Role from Realm" ;
            RequestedChanges requestChange = new RoleChangeRequest(m.getRole().getName(), action, ChangeSetType.ROLE, RequestType.ROLE, clientId, realm.getName(), ActionType.DELETE, m.getChangeRequestId(), new ArrayList<>(), m.getDraftStatus(), m.getDeleteStatus());
            proofs.forEach(p -> requestChange.getUserRecord().add(new RequestChangesUserRecord(p.getUser().getUsername(), p.getId(), realm.getClientById(p.getClientId()).getClientId(), p.getProofDraft())));
            changes.add(requestChange);
        }
        return changes;
    }

    private List<?> getRoleFromMapping(EntityManager em, ChangeSetRequest change, ChangeSetType type, ActionType action, RealmModel realm) {
        return switch (type) {
            case USER_ROLE -> getUserRoleMappings(em, change, action, realm);
            case GROUP, USER_GROUP_MEMBERSHIP, GROUP_ROLE -> null;
            case COMPOSITE_ROLE, DEFAULT_ROLES -> getCompositeRoleMappings(em, change, action, realm);
            case ROLE -> getRoleMappings(em, change, action);
            case USER -> getUserMappings(em, change, action);
            case CLIENT_FULLSCOPE -> getClientMappings(em, change, action);
            case CLIENT -> getClientEntity(em, change);
            default -> Collections.emptyList();
        };
    }

    // Helper methods for retrieving specific mappings
    public static List<?> getUserRoleMappings(EntityManager em, ChangeSetRequest change, ActionType action, RealmModel realm) {
        String queryName = action == ActionType.CREATE ? "getUserRoleMappingsByStatusAndRealmAndRecordId" : "getUserRoleMappingsByDeleteStatusAndRealmAndRecordId";
        return em.createNamedQuery(queryName, TideUserRoleMappingDraftEntity.class)
                .setParameter(action == ActionType.CREATE ? "draftStatus" : "deleteStatus", DraftStatus.APPROVED)
                .setParameter("changesetId", change.getChangeSetId())
                .setParameter("realmId", realm.getId())
                .getResultList();
    }

    public static List<?> getCompositeRoleMappings(EntityManager em, ChangeSetRequest change, ActionType action, RealmModel realm) {
        String queryName = action == ActionType.CREATE ? "getAllCompositeRoleMappingsByStatusAndRealmAndRecordId" : "getAllCompositeRoleMappingsByDeletionStatusAndRealmAndRecordId";
        return em.createNamedQuery(queryName, TideCompositeRoleMappingDraftEntity.class)
                .setParameter(action == ActionType.CREATE ? "draftStatus" : "deleteStatus", DraftStatus.APPROVED)
                .setParameter("changesetId", change.getChangeSetId())
                .setParameter("realmId", realm.getId())
                .getResultList();
    }

    public static List<?> getRoleMappings(EntityManager em, ChangeSetRequest change, ActionType action) {
        return em.createNamedQuery("getRoleDraftByRoleAndDeleteStatus", TideRoleDraftEntity.class)
                .setParameter("deleteStatus", DraftStatus.APPROVED)
                .setParameter("changesetId", change.getChangeSetId())
                .getResultList();
    }

    public static List<?> getUserMappings(EntityManager em, ChangeSetRequest change, ActionType action) {
        return em.createNamedQuery("getTideUserDraftEntityByDraftStatusAndId", TideUserDraftEntity.class)
                .setParameter("draftStatus", DraftStatus.APPROVED)
                .setParameter("changesetId", change.getChangeSetId())
                .getResultList();
    }

    public static List<?> getClientMappings(EntityManager em, ChangeSetRequest change, ActionType action) {
        String queryName = action == ActionType.CREATE ? "getClientFullScopeStatusDraftByIdAndFullScopeEnabled" : "getClientFullScopeStatusDraftByIdAndFullScopeDisabled";
        return em.createNamedQuery(queryName, TideClientDraftEntity.class)
                .setParameter(action == ActionType.CREATE ? "fullScopeEnabled" : "fullScopeDisabled", DraftStatus.APPROVED)
                .setParameter("changesetId", change.getChangeSetId())
                .getResultList();
    }

    public static List<?> getClientEntity(EntityManager em, ChangeSetRequest change) {
        return em.createNamedQuery("getClientDraftById", TideClientDraftEntity.class)
                .setParameter("changesetId", change.getChangeSetId())
                .getResultList();
    }

    private Response buildResponse(int status, String message) {
        return Response.status(status)
                .entity(message)
                .type(MediaType.TEXT_PLAIN)
                .build();
    }

    public Response signChangeSets(List<ChangeSetRequest> changeSets) throws Exception {
        auth.realm().requireManageRealm();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        RealmModel realm = session.getContext().getRealm();
        ChangeSetSigner signer = ChangeSetSignerFactory.getSigner(session);
        List<String> signedJsonList = new ArrayList<>();
        ObjectMapper objectMapper = new ObjectMapper();

        if (changeSets.size() > 1) {
            Map<ChangeSetType, List<Object>> requests =
                    changeSets.stream()
                            .collect(Collectors.groupingBy(
                                    ChangeSetRequest::getType,
                                    Collectors.flatMapping(
                                            req -> IGAUtils
                                                    .fetchDraftRecordEntityByRequestId(
                                                            em, req.getType(), req.getChangeSetId()
                                                    )
                                                    .stream(),
                                            Collectors.toList()
                                    )
                            ));
            ChangeSetProcessorFactory processorFactory = new ChangeSetProcessorFactory();

            List<ChangesetRequestEntity> changeRequests = requests.entrySet().stream()
                    .flatMap(entry -> {
                        ChangeSetType requestType = entry.getKey();
                        List<Object> entities = entry.getValue();
                        try {
                            // Return a stream of results from each processor
                            return processorFactory.getProcessor(requestType)
                                    .combineChangeRequests(session, entities, em)
                                    .stream();
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    })
                    .collect(Collectors.toList());

            for (ChangesetRequestEntity changeSet : changeRequests) {
                try {
                    Object draftRecordEntity = IGAUtils.fetchDraftRecordEntityByRequestId(em, changeSet.getChangesetType(), changeSet.getChangesetRequestId()).get(0);
                    Response singleResp = signer.sign(new ChangeSetRequest(changeSet.getChangesetRequestId(), changeSet.getChangesetType(), ActionType.NONE), em, session, realm, draftRecordEntity, auth.adminAuth());
                    // extract that JSON payload
                    String jsonBody = singleResp.readEntity(String.class);

                    // collect it
                    signedJsonList.add(jsonBody);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            };
        }
        else {
            for (ChangeSetRequest changeSet : changeSets) {
                Object draftRecordEntity = IGAUtils.fetchDraftRecordEntityByRequestId(em, changeSet.getType(), changeSet.getChangeSetId()).get(0);
                if (draftRecordEntity == null) {
                    return Response.status(Response.Status.BAD_REQUEST)
                            .entity("Unsupported change set type for ID: " + changeSet.getChangeSetId())
                            .build();
                }
                try {
                    Response singleResp = signer.sign(changeSet, em, session, realm, draftRecordEntity, auth.adminAuth());
                    // extract that JSON payload
                    String jsonBody = singleResp.readEntity(String.class);

                    // collect it
                    signedJsonList.add(jsonBody);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        }

        return Response.ok(objectMapper.writeValueAsString(signedJsonList)).build();
    }

    private Response commitChangeSets(List<ChangeSetRequest> changeSets) throws Exception {
        auth.realm().requireManageRealm();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        RealmModel realm = session.getContext().getRealm();

        for (ChangeSetRequest changeSet: changeSets){
            Object draftRecordEntity= IGAUtils.fetchDraftRecordEntityByRequestId(em, changeSet.getType(), changeSet.getChangeSetId()).get(0);
            if (draftRecordEntity ==  null) {
                return Response.status(Response.Status.BAD_REQUEST).entity("Unsupported change set type").build();
            }
            try {
                ChangeSetCommitter committer = ChangeSetCommitterFactory.getCommitter(session);
                committer.commit(changeSet, em, session, realm, draftRecordEntity, auth.adminAuth());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

        }
        return Response.ok("Change sets approved and committed").build();
    }

}
