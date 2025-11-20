package org.tidecloak.base.iga.IGARealmResource;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.persistence.NoResultException;
import jakarta.persistence.TypedQuery;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.cache.UserCache;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.tidecloak.base.iga.ChangeSetCommitter.ChangeSetCommitter;
import org.tidecloak.base.iga.ChangeSetCommitter.ChangeSetCommitterFactory;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessorFactory;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessorFactoryProvider;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequestList;
import org.tidecloak.base.iga.ChangeSetProcessors.utils.TideEntityUtils;
import org.tidecloak.base.iga.ChangeSetSigner.ChangeSetSigner;
import org.tidecloak.base.iga.ChangeSetSigner.ChangeSetSignerFactory;
import org.tidecloak.base.iga.interfaces.ChangesetRequestAdapter;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.shared.enums.WorkflowType;
import org.tidecloak.base.iga.interfaces.models.*;
import org.tidecloak.jpa.entities.*;
import org.tidecloak.jpa.entities.drafting.*;
import org.tidecloak.shared.enums.models.WorkflowParams;

import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.tidecloak.shared.utils.UserContextDraftUtil.findDraftsNotInAccessProof;

public class IGARealmResource {

    private final KeycloakSession session;
    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;

    protected static final Logger logger = Logger.getLogger(IGARealmResource.class);


    public IGARealmResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth) {
        this.session = session;
        this.realm = realm;
        this.auth = auth;
    }

    @POST
    @Path("toggle-iga")
    @Produces(MediaType.TEXT_PLAIN)

    public Response toggleIGA(@FormParam("isIGAEnabled") boolean isEnabled) throws Exception {
        try{
            RealmModel masterRealm = session.realms().getRealmByName(Config.getAdminRealm());
            if(realm.equals(masterRealm)){
                return buildResponse(400, "Master realm does not support IGA.");
            }

            EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
            auth.realm().requireManageRealm();
            session.getContext().getRealm().setAttribute("isIGAEnabled", isEnabled);
            logger.info("IGA has been toggled to : " + isEnabled);

            IdentityProviderModel tideIdp = session.identityProviders().getByAlias("tide");
            ComponentModel componentModel = realm.getComponentsStream()
                    .filter(x -> "tide-vendor-key".equals(x.getProviderId()))  // Use .equals for string comparison
                    .findFirst()
                    .orElse(null);

            // if IGA is on and tideIdp exists, we need to enable EDDSA as default sig
            if (tideIdp != null && componentModel != null) {
                String currentAlgorithm = session.getContext().getRealm().getDefaultSignatureAlgorithm();

                if (isEnabled) {
                    if (!"EdDSA".equalsIgnoreCase(currentAlgorithm)) {
                        session.getContext().getRealm().setDefaultSignatureAlgorithm("EdDSA");
                        logger.info("IGA has been enabled, default signature algorithm updated to EdDSA");
                    }
                    // Check the TideClientDraft Table and generate and AccessProofDetails that dont exist.
                    List<TideClientDraftEntity> entities = findDraftsNotInAccessProof(em, realm);
                    entities.forEach(c -> {
                        try {
                            WorkflowParams params = new WorkflowParams(DraftStatus.DRAFT, false, ActionType.CREATE, ChangeSetType.CLIENT);
                            ChangeSetProcessorFactory changeSetProcessorFactory = ChangeSetProcessorFactoryProvider.getFactory();
                            changeSetProcessorFactory.getProcessor(ChangeSetType.CLIENT).executeWorkflow(session, c, em, WorkflowType.REQUEST, params, null);
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    });
                } else {
                    // If tide IDP exists but IGA is disabled, default signature cannot be EdDSA
                    // TODO: Fix error: Uncaught server error: java.lang.RuntimeException: org.keycloak.crypto.SignatureException:
                    // Signing failed. java.security.InvalidKeyException: Unsupported key type (tide eddsa key)
                    if (currentAlgorithm.equalsIgnoreCase("EdDSA")) {
                        session.getContext().getRealm().setDefaultSignatureAlgorithm("RS256");
                        logger.info("IGA has been disabled, default signature algorithm updated to RS256");
                    }
                }
            }
            return buildResponse(200, "IGA has been toggled to : " + isEnabled);
        }catch(Exception e) {
            logger.error("Error toggling IGA on realm: ", e);
            throw e;
        }
    }

    @POST
    @Path("add-rejection")
    @Produces(MediaType.TEXT_PLAIN)
    public Response AddRejection(@FormParam("changeSetId") String changeSetId, @FormParam("actionType") String actionType, @FormParam("changeSetType") String changeSetType) throws Exception {
        try {
            auth.realm().requireManageRealm();
            ChangesetRequestAdapter.saveAdminRejection(session, changeSetType, changeSetId, actionType, auth.adminAuth().getUser());
            return buildResponse(200, "Successfully added admin rejection to changeSetRequest with id " + changeSetId);

        } catch (Exception e) {
            logger.error("Error adding rejection to change set request with ID: " + changeSetId +"." + Arrays.toString(e.getStackTrace()));
            return  buildResponse(500, "Error adding rejection to change set request with ID: " + changeSetId +" ." + e.getMessage());
        }
    }

    @GET
    @Path("users/{user-id}/roles/{role-id}/draft/status")
    public Response getUserRoleAssignmentDraftStatus(@PathParam("user-id") String userId, @PathParam("role-id") String roleId) {
        if(!BasicIGAUtils.isIGAEnabled(realm)){
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
        if(!BasicIGAUtils.isIGAEnabled(realm)){
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
        if(!BasicIGAUtils.isIGAEnabled(realm)){
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
            return cancelChangeSets(Collections.singletonList(changeSet));

        } catch(Exception e) {
            return buildResponse(500, "There was an error cancelling this change set request. " + e.getMessage());

        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("change-set/cancel/batch")
    public Response cancelChangeSets(ChangeSetRequestList changeSets) throws Exception {
        try{
            return cancelChangeSets(changeSets.getChangeSets());
        } catch(Exception e) {
            return buildResponse(500, "There was an error cancelling these change set requests. " + e.getMessage());

        }
    }


    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("change-set/sign")
    public Response signChangeset(ChangeSetRequest changeSet) throws Exception {
        try{
            List<String> result = signChangeSets(Collections.singletonList(changeSet));
            return Response.ok(result.get(0)).build();
        }catch (Exception ex) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(ex.getMessage()).build();
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("change-set/sign/batch")
    public Response signMultipleChangeSets(ChangeSetRequestList changeSets) throws Exception {
        try{
            ObjectMapper objectMapper = new ObjectMapper();
            List<String> result =  signChangeSets(changeSets.getChangeSets());
            return Response.ok(objectMapper.writeValueAsString(result)).build();
        }catch (Exception ex) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(ex.getMessage()).build();
        }
    }

    @GET
    @Path("change-set/requests")
    public Response getChangeRequests(
            @QueryParam("id") String changesetRequestId,
            @QueryParam("type") String changesetTypeParam
    ) {
        auth.realm().requireManageRealm();

        if (!BasicIGAUtils.isIGAEnabled(realm)) {
            return Response.ok(Collections.emptyList()).build();
        }

        if ((changesetRequestId == null || changesetRequestId.isBlank()) &&
                (changesetTypeParam == null || changesetTypeParam.isBlank())) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Either 'id' or 'type' query parameter must be provided")
                    .build();
        }

        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<ChangesetRequestEntity> entities;

        try {
            if (changesetRequestId != null && !changesetRequestId.isBlank()) {

                TypedQuery<ChangesetRequestEntity> query =
                        (TypedQuery<ChangesetRequestEntity>) em.createNamedQuery("getAllChangeRequestsByRecordId"
                        );
                query.setParameter("changesetRequestId", changesetRequestId);

                entities = query.getResultList();
            } else {

                ChangeSetType type;
                try {
                    type = ChangeSetType.valueOf(changesetTypeParam);
                } catch (IllegalArgumentException ex) {
                    return Response.status(Response.Status.BAD_REQUEST)
                            .entity("Invalid ChangeSetType: " + changesetTypeParam)
                            .build();
                }

                TypedQuery<ChangesetRequestEntity> query =
                        em.createNamedQuery("getAllChangeRequestsByChangeSetType",
                                ChangesetRequestEntity.class);
                query.setParameter("changesetType", type);

                entities = query.getResultList();
            }
        } catch (Exception e) {
            return Response.serverError()
                    .entity("Error retrieving change-set requests: " + e.getMessage())
                    .build();
        }

        List<ChangesetRequestRepresentation> results = entities.stream()
                .map(ChangesetRequestRepresentation::fromEntity)
                .collect(Collectors.toList());

        return Response.ok(results).build();
    }



    @GET
    @Path("change-set/users/requests")
    public Response getRequestedChangesForUsers() {
        auth.realm().requireManageRealm();
        if(!BasicIGAUtils.isIGAEnabled(realm)){
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

        if(!BasicIGAUtils.isIGAEnabled(realm)){
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

        if(!BasicIGAUtils.isIGAEnabled(realm)){
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
        ChangeSetProcessorFactory changeSetProcessorFactory = ChangeSetProcessorFactoryProvider.getFactory();
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
                    accessProof.forEach(em::remove);
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
        List<TideClientDraftEntity> mappings = em.createNamedQuery("getClientFullScopeStatusDraftThatDoesNotHaveStatus", TideClientDraftEntity.class)
                .setParameter("status", DraftStatus.ACTIVE)
                .setParameter("status2", DraftStatus.NULL)
                .getResultList();


        return processClientDraftRecords(em, realm, mappings);
    }

    public static List<RequestedChanges> processPreApprovedClientDraftRecords(EntityManager em, RealmModel realm, List<DraftStatus> statuses) {

        List<TideClientDraftEntity> mappings = em.createNamedQuery("getPreApprovedClientFullScopeStatusDraftThatDoesNotHaveStatus", TideClientDraftEntity.class)
                .setParameter("status", statuses)
                .setParameter("activeStatus", DraftStatus.ACTIVE)
                .setParameter("status2", DraftStatus.NULL)
                .getResultList();

        return processClientDraftRecords(em, realm, mappings);
    }

    public static List<RequestedChanges> processClientDraftRecords(EntityManager em, RealmModel realm, List<TideClientDraftEntity> mappings ) {
        List<RequestedChanges> changes = new ArrayList<>();

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
                TideClientDraftEntity tideClientDraftEntity = (TideClientDraftEntity) BasicIGAUtils.fetchDraftRecordEntity(em, p.getChangesetType(), p.getChangeRequestKey().getMappingId());
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
        List<TideUserRoleMappingDraftEntity> mappings = em.createNamedQuery("getAllPendingUserRoleMappingsByRealm", TideUserRoleMappingDraftEntity.class)
                .setParameter("draftStatus", DraftStatus.ACTIVE)
                .setParameter("deleteStatus", DraftStatus.ACTIVE)
                .setParameter("realmId", realm.getId())
                .getResultList();
        return processUserRoleMappings(em, realm, mappings);
    }

    public static List<RequestedChanges> processPreApprovedUserRoleMappings(EntityManager em, RealmModel realm, List<DraftStatus> statuses) {

        List<TideUserRoleMappingDraftEntity> mappings = em.createNamedQuery("getAllPreApprovedUserRoleMappingsByRealm", TideUserRoleMappingDraftEntity.class)
                .setParameter("draftStatus", statuses)
                .setParameter("activeStatus", DraftStatus.ACTIVE)
                .setParameter("realmId", realm.getId())
                .getResultList();

        return processUserRoleMappings(em, realm, mappings);
    }

    public static List<RequestedChanges> processUserRoleMappings(EntityManager em, RealmModel realm, List<TideUserRoleMappingDraftEntity> mappings) {
        List<RequestedChanges> changes = new ArrayList<>();

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
        List<TideCompositeRoleMappingDraftEntity> mappings = em.createNamedQuery("getAllCompositeRoleMappingsByRealm", TideCompositeRoleMappingDraftEntity.class)
                .setParameter("draftStatus", DraftStatus.ACTIVE)
                .setParameter("deleteStatus", DraftStatus.ACTIVE)
                .setParameter("realmId", realm.getId())
                .getResultList();

        return processCompositeRoleMappings(em, realm, mappings);
    }

    public static List<RequestedChanges> processPreApprovedCompositeRoleMappings(EntityManager em, RealmModel realm, List<DraftStatus> statuses) {

        List<TideCompositeRoleMappingDraftEntity> mappings = em.createNamedQuery("getAllPreApprovedCompositeRoleMappingsByRealm", TideCompositeRoleMappingDraftEntity.class)
                .setParameter("draftStatus", statuses)
                .setParameter("activeStatus", DraftStatus.ACTIVE)
                .setParameter("realmId", realm.getId())
                .getResultList();

        return processCompositeRoleMappings(em, realm, mappings);
    }

        public static List<RequestedChanges> processCompositeRoleMappings(EntityManager em, RealmModel realm, List<TideCompositeRoleMappingDraftEntity> mappings ) {
        List<RequestedChanges> changes = new ArrayList<>();
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
        List<TideRoleDraftEntity> mappings = em.createNamedQuery("getAllRoleDraft", TideRoleDraftEntity.class)
                .setParameter("draftStatus", DraftStatus.ACTIVE)
                .setParameter("deleteStatus", DraftStatus.ACTIVE)
                .setParameter("realmId", realm.getId())
                .getResultList();

        return  processRoleMappings(em, realm, mappings);
    }

    public static List<RequestedChanges> processPreApprovedRoleMappings(EntityManager em, RealmModel realm, List<DraftStatus> statuses) {

        List<TideRoleDraftEntity> mappings = em.createNamedQuery("getAllPreApprovedRoleDraft", TideRoleDraftEntity.class)
                .setParameter("draftStatus", statuses)
                .setParameter("activeStatus", DraftStatus.ACTIVE)
                .setParameter("realmId", realm.getId())
                .getResultList();

        return processRoleMappings(em, realm, mappings);
    }

    public static List<RequestedChanges> processRoleMappings(EntityManager em, RealmModel realm, List<TideRoleDraftEntity> mappings) {
        List<RequestedChanges> changes = new ArrayList<>();


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

    public List<String> signChangeSets(List<ChangeSetRequest> changeSets) throws Exception {
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
                                            req -> BasicIGAUtils
                                                    .fetchDraftRecordEntityByRequestId(
                                                            em, req.getType(), req.getChangeSetId()
                                                    )
                                                    .stream(),
                                            Collectors.toList()
                                    )
                            ));
            ChangeSetProcessorFactory processorFactory = ChangeSetProcessorFactoryProvider.getFactory();

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
                    List<?> draftRecordEntities = BasicIGAUtils.fetchDraftRecordEntityByRequestId(
                            em,
                            changeSet.getChangesetType(),
                            changeSet.getChangesetRequestId()
                    );

                    boolean allDelete = draftRecordEntities.stream()
                            .map(BasicIGAUtils::getActionTypeFromEntity)
                            .allMatch(actionType -> actionType == ActionType.DELETE);

                    ActionType actionType = allDelete ? ActionType.DELETE : ActionType.CREATE;

                    Response singleResp = signer.sign(new ChangeSetRequest(changeSet.getChangesetRequestId(), changeSet.getChangesetType(), actionType), em, session, realm, draftRecordEntities, auth.adminAuth());
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
                List<?> draftRecordEntities = BasicIGAUtils.fetchDraftRecordEntityByRequestId(em, changeSet.getType(), changeSet.getChangeSetId());
                if (draftRecordEntities == null || draftRecordEntities.isEmpty()) {
                    throw new BadRequestException("Unsupported change set type for ID: " + changeSet.getChangeSetId());
                }
                try {
                    Response singleResp = signer.sign(changeSet, em, session, realm, draftRecordEntities, auth.adminAuth());
                    // extract that JSON payload
                    String jsonBody = singleResp.readEntity(String.class);

                    // collect it
                    signedJsonList.add(jsonBody);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        }

        return signedJsonList;
    }

    private Response commitChangeSets(List<ChangeSetRequest> changeSets) throws Exception {
        auth.realm().requireManageRealm();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        RealmModel realm = session.getContext().getRealm();
        List<ChangeSetRequest> filtered = new ArrayList<>(changeSets.stream()
                .collect(Collectors.toMap(
                        ChangeSetRequest::getChangeSetId,
                        Function.identity(),
                        (existing, replacement) -> existing
                ))
                .values());

        for (ChangeSetRequest changeSet: filtered){
            List<?> draftRecordEntities= BasicIGAUtils.fetchDraftRecordEntityByRequestId(em, changeSet.getType(), changeSet.getChangeSetId());
            if (draftRecordEntities ==  null || draftRecordEntities.isEmpty()) {
                return Response.status(Response.Status.BAD_REQUEST).entity("Unsupported change set type").build();
            }
            try {
                ChangeSetCommitter committer = ChangeSetCommitterFactory.getCommitter(session);
                committer.commit(changeSet, em, session, realm, draftRecordEntities.get(0), auth.adminAuth());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

        }
        return Response.ok("Change sets approved and committed").build();
    }

    private Response cancelChangeSets(List<ChangeSetRequest> changeSets){
            auth.realm().requireManageRealm();
            EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

            changeSets.forEach(changeSet -> {

                ChangeSetType type = changeSet.getType();

                List<?> mapping = BasicIGAUtils.fetchDraftRecordEntityByRequestId(em, type, changeSet.getChangeSetId());
                if (mapping != null && mapping.isEmpty()) {
                    return;
                }

                mapping.forEach(m -> {
                    em.lock(m, LockModeType.PESSIMISTIC_WRITE); // Lock the entity to prevent concurrent modifications
                    ChangeSetProcessorFactory processorFactory = ChangeSetProcessorFactoryProvider.getFactory();// Initialize the processor factory
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

            });

        // Return success message after approving the change sets
        return Response.ok("Change set request has been canceled").build();
    }

    /**
     * Lightweight REST representation of the JPA entity
     */
    public static class ChangesetRequestRepresentation {
        public String changesetRequestId;
        public String changesetType;
        public String draftRequest;
        public Long timestamp;
        public int adminAuthorizationsCount;

        public static ChangesetRequestRepresentation fromEntity(ChangesetRequestEntity entity) {
            ChangesetRequestRepresentation rep = new ChangesetRequestRepresentation();
            rep.changesetRequestId = entity.getChangesetRequestId();
            rep.changesetType = entity.getChangesetType() != null
                    ? entity.getChangesetType().name()
                    : null;
            rep.draftRequest = entity.getDraftRequest();
            rep.timestamp = entity.getTimestamp();
            rep.adminAuthorizationsCount = entity.getAdminAuthorizations() != null
                    ? entity.getAdminAuthorizations().size()
                    : 0;
            return rep;
        }
    }

}
