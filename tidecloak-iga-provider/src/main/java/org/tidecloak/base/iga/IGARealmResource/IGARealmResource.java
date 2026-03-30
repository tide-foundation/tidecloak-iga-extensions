package org.tidecloak.base.iga.IGARealmResource;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
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
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.representations.idm.RolesRepresentation;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.tidecloak.base.iga.ChangeSetCommitter.ChangeSetCommitter;
import org.tidecloak.base.iga.ChangeSetCommitter.ChangeSetCommitterFactory;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessor;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessorFactory;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessorFactoryProvider;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequestList;
import org.tidecloak.base.iga.ChangeSetProcessors.models.WhatIfRequest;
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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.midgard.Midgard;
import org.midgard.models.*;
import org.midgard.models.Policy.*;
import org.midgard.models.RequestExtensions.*;
import org.tidecloak.shared.models.SecretKeys;

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

        // Store the admin user info in the session so processors can stamp it on ChangesetRequestEntity
        try {
            UserModel adminUser = auth.adminAuth().getUser();
            if (adminUser != null) {
                session.setAttribute("requestedByUserId", adminUser.getId());
                session.setAttribute("requestedByUsername", adminUser.getUsername());
            }
        } catch (Exception e) {
            // best effort
        }
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

                    // Get the admin console client
                    ClientModel secAdminConsole =
                            session.clients().getClientByClientId(realm, Constants.ADMIN_CONSOLE_CLIENT_ID);

                    // Ensure current auth server URL is in web origins
                    Set<String> currentWebOrigins = new HashSet<>(secAdminConsole.getWebOrigins());
                    currentWebOrigins.add(session.getContext().getAuthServerUrl().toString());
                    secAdminConsole.setWebOrigins(currentWebOrigins);

                    // Re-sign IDP settings so the new web origin is included
                    signIdpSettings(tideIdp, componentModel);

                    // Find the "roles" client scope
                    ClientScopeModel rolesScope =
                            session.clientScopes()
                                    .getClientScopesStream(realm)
                                    .filter(cs -> "roles".equalsIgnoreCase(cs.getName()))
                                    .findFirst()
                                    .orElse(null);

                    if (rolesScope == null) {
                        throw new IllegalStateException("roles client scope not found");
                    }

                    // Get predefined mappers from the roles scope
                    ProtocolMapperModel scopeClientRole =
                            rolesScope.getProtocolMapperByName("openid-connect", "client roles");
                    ProtocolMapperModel scopeRealmRole =
                            rolesScope.getProtocolMapperByName("openid-connect", "realm roles");

                    if (scopeClientRole == null || scopeRealmRole == null) {
                        throw new IllegalStateException("Expected predefined mappers 'client roles' / 'realm roles' not found on roles scope");
                    }

                    // Clone mappers like the Admin Console would when "Add predefined mapper" is used
                    ProtocolMapperModel clientRoleMapper = cloneMapper(scopeClientRole);
                    ProtocolMapperModel realmRoleMapper  = cloneMapper(scopeRealmRole);

                    // Apply your config changes on the clones
                    Map<String, String> clientRoleConfig = new HashMap<>(clientRoleMapper.getConfig());
                    clientRoleConfig.put("lightweight.claim", "true");
                    clientRoleMapper.setConfig(clientRoleConfig);

                    Map<String, String> realmRoleConfig = new HashMap<>(realmRoleMapper.getConfig());
                    realmRoleConfig.put("lightweight.claim", "true");
                    realmRoleMapper.setConfig(realmRoleConfig);

                    // Check if the client already has mappers with these names
                    ProtocolMapperModel existingClientRole =
                            secAdminConsole.getProtocolMapperByName("openid-connect", clientRoleMapper.getName());
                    ProtocolMapperModel existingRealmRole =
                            secAdminConsole.getProtocolMapperByName("openid-connect", realmRoleMapper.getName());

                    // If mapper exists, just update its config; if not, add the cloned mapper
                    if (existingClientRole == null) {
                        secAdminConsole.addProtocolMapper(clientRoleMapper);
                    } else {
                        Map<String, String> cfg = new HashMap<>(existingClientRole.getConfig());
                        cfg.put("lightweight.claim", "true");
                        existingClientRole.setConfig(cfg);
                    }

                    if (existingRealmRole == null) {
                        secAdminConsole.addProtocolMapper(realmRoleMapper);
                    } else {
                        Map<String, String> cfg = new HashMap<>(existingRealmRole.getConfig());
                        cfg.put("lightweight.claim", "true");
                        existingRealmRole.setConfig(cfg);
                    }

                } else {
                    // If tide IDP exists but IGA is disabled, default signature cannot be EdDSA
                    // TODO: Fix error: Uncaught server error: java.lang.RuntimeException: org.keycloak.crypto.SignatureException:
                    // Signing failed. java.security.InvalidKeyException: Unsupported key type (tide eddsa key)
                    if (currentAlgorithm.equalsIgnoreCase("EdDSA")) {
                        session.getContext().getRealm().setDefaultSignatureAlgorithm("RS256");
                        logger.info("IGA has been disabled, default signature algorithm updated to RS256");
                    }
                }
            } else {
                if (isEnabled){
                    // Get a list of users
                    ClientModel realmManagement = session.clients().getClientByClientId(realm, Constants.REALM_MANAGEMENT_CLIENT_ID);
                    RoleModel realmAdmin = session.roles().getClientRole(realmManagement, "realm-admin");
                    List<UserModel> users = session.users().searchForUserStream(realm, new HashMap<>()).toList();
                    // sign realm-admin roles
                    users.forEach(u -> {
                        UserEntity ue = em.find(UserEntity.class, u.getId());
                        TideUserRoleMappingDraftEntity userRoleMappingDraft = em.createNamedQuery("getUserRoleAssignmentDraftEntity", TideUserRoleMappingDraftEntity.class)
                                .setParameter("user", ue)
                                .setParameter("roleId", realmAdmin.getId())
                                .getSingleResult();

                        if (userRoleMappingDraft.getDraftStatus().equals(DraftStatus.DRAFT)) {
                            ChangeSetRequest cr = new ChangeSetRequest();
                            cr.setChangeSetId(userRoleMappingDraft.getChangeRequestId());
                            cr.setActionType(userRoleMappingDraft.getAction());
                            cr.setType(ChangeSetType.USER_ROLE);
                            try {
                                signChangeSets(Collections.singletonList(cr));
                                commitChangeSets(Collections.singletonList(cr));
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                        }
                    });
                }
            }

            // enable events by default
            realm.setEventsEnabled(true);
            realm.setAdminEventsEnabled(true);
            realm.setAdminEventsDetailsEnabled(true);

            return buildResponse(200, "IGA has been toggled to : " + isEnabled);
        }catch(Exception e) {
            logger.error("Error toggling IGA on realm: ", e);
            throw e;
        }
    }

    // --- Helper: clone a mapper from the scope to use on the client ---
    ProtocolMapperModel cloneMapper(ProtocolMapperModel source) {
        ProtocolMapperModel clone = new ProtocolMapperModel();
        clone.setName(source.getName());                 // same name as predefined
        clone.setProtocol(source.getProtocol());         // e.g. "openid-connect"
        clone.setProtocolMapper(source.getProtocolMapper());
        clone.setConfig(new HashMap<>(source.getConfig()));
        return clone;
    }


    @POST
    @Path("add-rejection")
    @Produces(MediaType.TEXT_PLAIN)
    public Response AddRejection(@FormParam("changeSetId") String changeSetId, @FormParam("actionType") String actionType, @FormParam("changeSetType") String changeSetType) throws Exception {
        try {
            auth.users().requireManage();
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
            List<Map<String, Object>> result = signChangeSets(Collections.singletonList(changeSet));
            return Response.ok(result.get(0)).build();
        }catch (Exception ex) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(ex.getMessage()).build();
        }
    }

    @POST
    @Path("change-set/sign/batch")
    public Response signMultipleChangeSets(ChangeSetRequestList changeSets) throws Exception {
        try {
            // Now returns List<Map<String, Object>>
            List<Map<String, Object>> result = signChangeSets(changeSets.getChangeSets());

            // Let JAX-RS / Jackson serialize it, no need for manual ObjectMapper
            return Response.ok(result).build();
        } catch (Exception ex) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(ex.getMessage())
                    .build();
        }
    }


    @GET
    @Path("change-set/requests")
    public Response getChangeRequests(
            @QueryParam("id") String changesetRequestId,
            @QueryParam("type") String changesetTypeParam
    ) {
        auth.users().requireManage();

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
        auth.users().requireManage();
        if(!BasicIGAUtils.isIGAEnabled(realm)){
            return Response.ok().entity(new ArrayList<>()).build();
        }
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<RequestedChanges> changes = new ArrayList<>(processUserRoleMappings(em, realm));
        enrichWithRequestedBy(em, changes);
        return Response.ok(changes).build();
    }

    @GET
    @Path("change-set/roles/requests")
    public Response getRequestedChanges() {
        auth.users().requireManage();

        if(!BasicIGAUtils.isIGAEnabled(realm)){
            return Response.ok().entity(new ArrayList<>()).build();
        }
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<RequestedChanges> requestedChangesList = new ArrayList<>(processRoleMappings(em, realm));
        requestedChangesList.addAll(processCompositeRoleMappings(em, realm));
        enrichWithRequestedBy(em, requestedChangesList);
        return Response.ok(requestedChangesList).build();
    }

    @GET
    @Path("change-set/clients/requests")
    public Response getRequestedChangesForClients() {
        auth.users().requireManage();

        if(!BasicIGAUtils.isIGAEnabled(realm)){
            return Response.ok().entity(new ArrayList<>()).build();
        }
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<RequestedChanges> changes = new ArrayList<>(processClientDraftRecords(em, realm));
        enrichWithRequestedBy(em, changes);
        return Response.ok(changes).build();
    }

    @GET
    @Path("change-set/groups/requests")
    public Response getRequestedChangesForGroups() {
        auth.users().requireManage();

        if (!BasicIGAUtils.isIGAEnabled(realm)) {
            return Response.ok().entity(new ArrayList<>()).build();
        }
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<RequestedChanges> changes = new ArrayList<>();
        changes.addAll(processGroupRoleMappings(em, realm));
        changes.addAll(processGroupMemberships(em, realm));
        changes.addAll(processGroupMoves(em, realm));
        enrichWithRequestedBy(em, changes);
        return Response.ok(changes).build();
    }

    @GET
    @Path("change-set/counts")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getChangeSetCounts() {
        auth.users().requireManage();
        if (!BasicIGAUtils.isIGAEnabled(realm)) {
            Map<String, Integer> empty = new LinkedHashMap<>();
            empty.put("users", 0);
            empty.put("roles", 0);
            empty.put("clients", 0);
            empty.put("groups", 0);
            empty.put("total", 0);
            return Response.ok(empty).build();
        }
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        int users = processUserRoleMappings(em, realm).size();
        int roles = processRoleMappings(em, realm).size() + processCompositeRoleMappings(em, realm).size();
        int clients = processClientDraftRecords(em, realm).size();
        int groups = processGroupRoleMappings(em, realm).size()
                + processGroupMemberships(em, realm).size()
                + processGroupMoves(em, realm).size();

        Map<String, Integer> counts = new LinkedHashMap<>();
        counts.put("users", users);
        counts.put("roles", roles);
        counts.put("clients", clients);
        counts.put("groups", groups);
        counts.put("total", users + roles + clients + groups);
        return Response.ok(counts).build();
    }

    @GET
    @Path("change-set/all/requests")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAllChangeSetRequests() {
        auth.users().requireManage();
        if (!BasicIGAUtils.isIGAEnabled(realm)) {
            Map<String, List<?>> empty = new LinkedHashMap<>();
            empty.put("users", new ArrayList<>());
            empty.put("roles", new ArrayList<>());
            empty.put("clients", new ArrayList<>());
            empty.put("groups", new ArrayList<>());
            return Response.ok(empty).build();
        }
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        List<RequestedChanges> users = new ArrayList<>(processUserRoleMappings(em, realm));
        enrichWithRequestedBy(em, users);

        List<RequestedChanges> roles = new ArrayList<>(processRoleMappings(em, realm));
        roles.addAll(processCompositeRoleMappings(em, realm));
        enrichWithRequestedBy(em, roles);

        List<RequestedChanges> clients = new ArrayList<>(processClientDraftRecords(em, realm));
        enrichWithRequestedBy(em, clients);

        List<RequestedChanges> groups = new ArrayList<>();
        groups.addAll(processGroupRoleMappings(em, realm));
        groups.addAll(processGroupMemberships(em, realm));
        groups.addAll(processGroupMoves(em, realm));
        enrichWithRequestedBy(em, groups);

        Map<String, List<RequestedChanges>> result = new LinkedHashMap<>();
        result.put("users", users);
        result.put("roles", roles);
        result.put("clients", clients);
        result.put("groups", groups);
        return Response.ok(result).build();
    }

    @GET
    @Path("change-set/{id}/activity")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getChangeSetActivity(@PathParam("id") String changesetRequestId) {
        auth.users().requireManage();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        try {
            // Find all changeset request entities with this ID (across types)
            List<ChangesetRequestEntity> entities = em.createNamedQuery("getAllChangeRequestsByRecordId", ChangesetRequestEntity.class)
                    .setParameter("changesetRequestId", changesetRequestId)
                    .getResultList();

            if (entities.isEmpty()) {
                return Response.ok(Map.of("approvals", List.of(), "comments", List.of(), "requestedBy", "", "requestedByUsername", "")).build();
            }

            ChangesetRequestEntity cre = entities.get(0);

            // Build approval/rejection list
            List<Map<String, Object>> approvals = new ArrayList<>();
            for (AdminAuthorizationEntity auth : cre.getAdminAuthorizations()) {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("userId", auth.getUserId());
                entry.put("username", auth.getUsername() != null ? auth.getUsername() : "");
                entry.put("isApproval", auth.getIsApproval());
                entry.put("timestamp", auth.getActionTimestamp());
                approvals.add(entry);
            }

            // Get comments
            List<ChangesetCommentEntity> commentEntities = em.createNamedQuery("getCommentsByChangesetRequestId", ChangesetCommentEntity.class)
                    .setParameter("changesetRequestId", changesetRequestId)
                    .getResultList();

            List<Map<String, Object>> comments = new ArrayList<>();
            for (ChangesetCommentEntity c : commentEntities) {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("id", c.getId());
                entry.put("userId", c.getUserId());
                entry.put("username", c.getUsername());
                entry.put("comment", c.getComment());
                entry.put("timestamp", c.getTimestamp());
                comments.add(entry);
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("requestedBy", cre.getRequestedBy() != null ? cre.getRequestedBy() : "");
            result.put("requestedByUsername", cre.getRequestedByUsername() != null ? cre.getRequestedByUsername() : "");
            result.put("timestamp", cre.getTimestamp());
            result.put("approvals", approvals);
            result.put("comments", comments);

            return Response.ok(result).build();
        } catch (Exception e) {
            return Response.serverError().entity("Error fetching activity: " + e.getMessage()).build();
        }
    }

    @POST
    @Path("change-set/{id}/comments")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response addChangeSetComment(@PathParam("id") String changesetRequestId, Map<String, String> body) {
        auth.users().requireManage();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        try {
            String commentText = body.get("comment");
            if (commentText == null || commentText.isBlank()) {
                return Response.status(Response.Status.BAD_REQUEST).entity("Comment text is required").build();
            }

            UserModel adminUser = auth.adminAuth().getUser();

            ChangesetCommentEntity comment = new ChangesetCommentEntity();
            comment.setId(KeycloakModelUtils.generateId());
            comment.setChangesetRequestId(changesetRequestId);
            comment.setUserId(adminUser.getId());
            comment.setUsername(adminUser.getUsername());
            comment.setComment(commentText);
            em.persist(comment);
            em.flush();

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("id", comment.getId());
            result.put("userId", comment.getUserId());
            result.put("username", comment.getUsername());
            result.put("comment", comment.getComment());
            result.put("timestamp", comment.getTimestamp());

            return Response.ok(result).build();
        } catch (Exception e) {
            return Response.serverError().entity("Error adding comment: " + e.getMessage()).build();
        }
    }

    @PUT
    @Path("change-set/{id}/comments/{commentId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateChangeSetComment(@PathParam("id") String changesetRequestId, @PathParam("commentId") String commentId, Map<String, String> body) {
        auth.users().requireManage();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        try {
            String commentText = body.get("comment");
            if (commentText == null || commentText.isBlank()) {
                return Response.status(Response.Status.BAD_REQUEST).entity("Comment text is required").build();
            }

            ChangesetCommentEntity comment = em.find(ChangesetCommentEntity.class, commentId);
            if (comment == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("Comment not found").build();
            }

            UserModel adminUser = auth.adminAuth().getUser();
            if (!comment.getUserId().equals(adminUser.getId())) {
                return Response.status(Response.Status.FORBIDDEN).entity("You can only edit your own comments").build();
            }

            comment.setComment(commentText);
            comment.setTimestamp(System.currentTimeMillis() / 1000);
            em.merge(comment);
            em.flush();

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("id", comment.getId());
            result.put("userId", comment.getUserId());
            result.put("username", comment.getUsername());
            result.put("comment", comment.getComment());
            result.put("timestamp", comment.getTimestamp());

            return Response.ok(result).build();
        } catch (Exception e) {
            return Response.serverError().entity("Error updating comment: " + e.getMessage()).build();
        }
    }

    @DELETE
    @Path("change-set/{id}/comments/{commentId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response deleteChangeSetComment(@PathParam("id") String changesetRequestId, @PathParam("commentId") String commentId) {
        auth.users().requireManage();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        try {
            ChangesetCommentEntity comment = em.find(ChangesetCommentEntity.class, commentId);
            if (comment == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("Comment not found").build();
            }

            UserModel adminUser = auth.adminAuth().getUser();
            if (!comment.getUserId().equals(adminUser.getId())) {
                return Response.status(Response.Status.FORBIDDEN).entity("You can only delete your own comments").build();
            }

            em.remove(comment);
            em.flush();

            return Response.ok(Map.of("deleted", true)).build();
        } catch (Exception e) {
            return Response.serverError().entity("Error deleting comment: " + e.getMessage()).build();
        }
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

    public static List<RequestedChanges> processGroupRoleMappings(EntityManager em, RealmModel realm) {
        List<TideGroupRoleMappingEntity> mappings = em.createNamedQuery("getAllPendingGroupRoleMappingsByRealm", TideGroupRoleMappingEntity.class)
                .setParameter("draftStatus", DraftStatus.ACTIVE)
                .setParameter("realm", realm.getId())
                .getResultList();

        List<RequestedChanges> changes = new ArrayList<>();
        for (TideGroupRoleMappingEntity m : mappings) {
            if (m.getGroup() == null) continue;

            GroupModel group = realm.getGroupById(m.getGroup().getId());
            RoleModel role = realm.getRoleById(m.getRoleId());
            if (group == null || role == null) continue;

            List<AccessProofDetailEntity> proofs = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                    .setParameter("recordId", m.getChangeRequestId())
                    .getResultList();
            if (proofs.isEmpty()) continue;

            String actionDescription = m.getAction() == ActionType.DELETE ? "Removing Role from Group" : "Granting Role to Group";
            String clientId = role.isClientRole() ? realm.getClientById(role.getContainerId()).getClientId() : null;

            GroupChangeRequest requestChange = new GroupChangeRequest(
                    group.getName(), role.getName(), null, actionDescription,
                    ChangeSetType.GROUP_ROLE, RequestType.GROUP, clientId, realm.getName(),
                    m.getAction(), m.getChangeRequestId(), new ArrayList<>(), m.getDraftStatus()
            );

            proofs.forEach(p -> {
                em.lock(p, LockModeType.PESSIMISTIC_WRITE);
                requestChange.getUserRecord().add(new RequestChangesUserRecord(
                        p.getUser().getUsername(), p.getId(),
                        realm.getClientById(p.getClientId()).getClientId(), p.getProofDraft()
                ));
            });
            changes.add(requestChange);
        }
        return changes;
    }

    public static List<RequestedChanges> processGroupMemberships(EntityManager em, RealmModel realm) {
        List<TideUserGroupMembershipEntity> mappings = em.createNamedQuery("getAllPendingUserGroupMembershipDraftsByRealm", TideUserGroupMembershipEntity.class)
                .setParameter("draftStatus", DraftStatus.ACTIVE)
                .setParameter("realmId", realm.getId())
                .getResultList();

        List<RequestedChanges> changes = new ArrayList<>();
        for (TideUserGroupMembershipEntity m : mappings) {
            GroupModel group = realm.getGroupById(m.getGroupId());
            if (group == null) continue;

            String userName = m.getUser() != null ? m.getUser().getUsername() : "Unknown";

            List<AccessProofDetailEntity> proofs = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                    .setParameter("recordId", m.getChangeRequestId())
                    .getResultList();
            if (proofs.isEmpty()) continue;

            String actionDescription = m.getAction() == ActionType.DELETE ? "Removing User from Group" : "Adding User to Group";

            GroupChangeRequest requestChange = new GroupChangeRequest(
                    group.getName(), null, userName, actionDescription,
                    ChangeSetType.USER_GROUP_MEMBERSHIP, RequestType.GROUP, null, realm.getName(),
                    m.getAction(), m.getChangeRequestId(), new ArrayList<>(), m.getDraftStatus()
            );

            proofs.forEach(p -> {
                em.lock(p, LockModeType.PESSIMISTIC_WRITE);
                requestChange.getUserRecord().add(new RequestChangesUserRecord(
                        p.getUser().getUsername(), p.getId(),
                        realm.getClientById(p.getClientId()).getClientId(), p.getProofDraft()
                ));
            });
            changes.add(requestChange);
        }
        return changes;
    }

    private List<?> getRoleFromMapping(EntityManager em, ChangeSetRequest change, ChangeSetType type, ActionType action, RealmModel realm) {
        return switch (type) {
            case USER_ROLE -> getUserRoleMappings(em, change, action, realm);
            case GROUP_ROLE -> getGroupRoleMappings(em, change);
            case GROUP -> getGroupDraftMappings(em, change);
            case USER_GROUP_MEMBERSHIP -> getGroupMembershipMappings(em, change);
            case GROUP_MOVE -> getGroupMoveMappings(em, change);
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

    public static List<?> getGroupRoleMappings(EntityManager em, ChangeSetRequest change) {
        return em.createNamedQuery("GetGroupRoleDraftEntityByRequestId", TideGroupRoleMappingEntity.class)
                .setParameter("requestId", change.getChangeSetId())
                .getResultList();
    }

    public static List<?> getGroupDraftMappings(EntityManager em, ChangeSetRequest change) {
        return em.createNamedQuery("GetGroupDraftEntityByRequestId", TideGroupDraftEntity.class)
                .setParameter("requestId", change.getChangeSetId())
                .getResultList();
    }

    public static List<?> getGroupMembershipMappings(EntityManager em, ChangeSetRequest change) {
        return em.createNamedQuery("GetUserGroupMembershipDraftEntityByRequestId", TideUserGroupMembershipEntity.class)
                .setParameter("requestId", change.getChangeSetId())
                .getResultList();
    }

    public static List<?> getGroupMoveMappings(EntityManager em, ChangeSetRequest change) {
        return em.createNamedQuery("GetGroupMoveDraftEntityByRequestId", TideGroupMoveDraftEntity.class)
                .setParameter("requestId", change.getChangeSetId())
                .getResultList();
    }

    public static List<RequestedChanges> processGroupMoves(EntityManager em, RealmModel realm) {
        List<TideGroupMoveDraftEntity> mappings = em.createNamedQuery("getAllPendingGroupMoveDraftsByRealm", TideGroupMoveDraftEntity.class)
                .setParameter("draftStatus", DraftStatus.ACTIVE)
                .setParameter("realmId", realm.getId())
                .getResultList();

        List<RequestedChanges> changes = new ArrayList<>();
        for (TideGroupMoveDraftEntity m : mappings) {
            GroupModel group = realm.getGroupById(m.getGroupId());
            if (group == null) continue;

            List<AccessProofDetailEntity> proofs = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                    .setParameter("recordId", m.getChangeRequestId())
                    .getResultList();
            if (proofs.isEmpty()) continue;

            String newParentName = m.getNewParentId() != null ?
                    realm.getGroupById(m.getNewParentId()) != null ? realm.getGroupById(m.getNewParentId()).getName() : "Unknown" :
                    "Top Level";
            String actionDescription = "Moving Group to " + newParentName;

            GroupChangeRequest requestChange = new GroupChangeRequest(
                    group.getName(), null, null, actionDescription,
                    ChangeSetType.GROUP_MOVE, RequestType.GROUP, null, realm.getName(),
                    m.getAction(), m.getChangeRequestId(), new ArrayList<>(), m.getDraftStatus()
            );

            proofs.forEach(p -> {
                em.lock(p, LockModeType.PESSIMISTIC_WRITE);
                requestChange.getUserRecord().add(new RequestChangesUserRecord(
                        p.getUser().getUsername(), p.getId(),
                        realm.getClientById(p.getClientId()).getClientId(), p.getProofDraft()
                ));
            });
            changes.add(requestChange);
        }
        return changes;
    }

    // ── Policy Template endpoints ───────────────────────────────────

    @POST
    @Path("policy-templates")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response createPolicyTemplate(Map<String, Object> body) {
        auth.realm().requireManageRealm();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        ObjectMapper mapper = new ObjectMapper();

        try {
            String name = (String) body.get("name");
            String description = (String) body.get("description");
            String contractCode = (String) body.get("contractCode");
            String modelId = (String) body.get("modelId");
            Object parameters = body.get("parameters");

            if (name == null || name.isBlank()) {
                return Response.status(Response.Status.BAD_REQUEST).entity("name is required").build();
            }
            if (contractCode == null || contractCode.isBlank()) {
                return Response.status(Response.Status.BAD_REQUEST).entity("contractCode is required").build();
            }

            PolicyTemplateEntity entity = new PolicyTemplateEntity();
            entity.setId(UUID.randomUUID().toString());
            entity.setRealmId(realm.getId());
            entity.setName(name);
            entity.setDescription(description);
            entity.setContractCode(contractCode);
            entity.setModelId(modelId);
            entity.setCreatedBy(auth.adminAuth().getUser().getUsername());

            if (parameters != null) {
                entity.setParameters(mapper.writeValueAsString(parameters));
            }

            em.persist(entity);
            em.flush();

            logger.infof("[PolicyTemplate] CREATE realm=%s name=%s id=%s", realm.getName(), name, entity.getId());

            Map<String, Object> result = new HashMap<>();
            result.put("success", true);
            result.put("id", entity.getId());
            result.put("name", name);
            result.put("description", description);
            result.put("modelId", modelId);
            return Response.ok(result, MediaType.APPLICATION_JSON).build();
        } catch (Exception e) {
            logger.error("[PolicyTemplate] Error creating template", e);
            return Response.serverError().entity("Failed to create policy template: " + e.getMessage()).build();
        }
    }

    @PUT
    @Path("policy-templates/{id}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response updatePolicyTemplate(@PathParam("id") String id, Map<String, Object> body) {
        auth.realm().requireManageRealm();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        ObjectMapper mapper = new ObjectMapper();

        try {
            PolicyTemplateEntity entity = em.find(PolicyTemplateEntity.class, id);
            if (entity == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("Template not found").build();
            }

            if (entity.getRealmId() != null && !entity.getRealmId().equals(realm.getId())) {
                return Response.status(Response.Status.FORBIDDEN).entity("Cannot update template from another realm").build();
            }

            String name = (String) body.get("name");
            String description = (String) body.get("description");
            String contractCode = (String) body.get("contractCode");
            String modelId = (String) body.get("modelId");
            Object parameters = body.get("parameters");

            if (name == null || name.isBlank()) {
                return Response.status(Response.Status.BAD_REQUEST).entity("name is required").build();
            }
            if (contractCode == null || contractCode.isBlank()) {
                return Response.status(Response.Status.BAD_REQUEST).entity("contractCode is required").build();
            }

            entity.setName(name);
            entity.setDescription(description);
            entity.setContractCode(contractCode);
            entity.setModelId(modelId);

            if (parameters != null) {
                entity.setParameters(mapper.writeValueAsString(parameters));
            } else {
                entity.setParameters(null);
            }

            em.merge(entity);
            em.flush();

            logger.infof("[PolicyTemplate] UPDATE realm=%s name=%s id=%s", realm.getName(), name, id);

            Map<String, Object> result = new HashMap<>();
            result.put("success", true);
            result.put("id", id);
            result.put("name", name);
            return Response.ok(result, MediaType.APPLICATION_JSON).build();
        } catch (Exception e) {
            logger.error("[PolicyTemplate] Error updating template", e);
            return Response.serverError().entity("Failed to update policy template: " + e.getMessage()).build();
        }
    }

    @GET
    @Path("policy-templates")
    @Produces(MediaType.APPLICATION_JSON)
    public Response listPolicyTemplates() {
        auth.realm().requireManageRealm();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        ObjectMapper mapper = new ObjectMapper();

        try {
            List<PolicyTemplateEntity> entities = em.createNamedQuery("getPolicyTemplatesByRealm", PolicyTemplateEntity.class)
                    .setParameter("realmId", realm.getId())
                    .getResultList();

            List<Map<String, Object>> templates = new ArrayList<>();
            for (PolicyTemplateEntity entity : entities) {
                Map<String, Object> t = new HashMap<>();
                t.put("id", entity.getId());
                t.put("name", entity.getName());
                t.put("description", entity.getDescription());
                t.put("contractCode", entity.getContractCode());
                t.put("modelId", entity.getModelId());
                t.put("createdBy", entity.getCreatedBy());
                t.put("timestamp", entity.getTimestamp());
                t.put("realmId", entity.getRealmId());

                if (entity.getParameters() != null) {
                    t.put("parameters", mapper.readValue(entity.getParameters(), List.class));
                } else {
                    t.put("parameters", new ArrayList<>());
                }

                templates.add(t);
            }

            return Response.ok(templates, MediaType.APPLICATION_JSON).build();
        } catch (Exception e) {
            logger.error("[PolicyTemplate] Error listing templates", e);
            return Response.serverError().entity("Failed to list policy templates: " + e.getMessage()).build();
        }
    }

    @DELETE
    @Path("policy-templates/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response deletePolicyTemplate(@PathParam("id") String id) {
        auth.realm().requireManageRealm();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        try {
            PolicyTemplateEntity entity = em.find(PolicyTemplateEntity.class, id);
            if (entity == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("Template not found").build();
            }

            // Only allow deleting templates owned by this realm (not global ones)
            if (entity.getRealmId() != null && !entity.getRealmId().equals(realm.getId())) {
                return Response.status(Response.Status.FORBIDDEN).entity("Cannot delete template from another realm").build();
            }

            em.remove(entity);
            em.flush();

            logger.infof("[PolicyTemplate] DELETE realm=%s id=%s", realm.getName(), id);
            return Response.ok(Map.of("success", true)).build();
        } catch (Exception e) {
            logger.error("[PolicyTemplate] Error deleting template", e);
            return Response.serverError().entity("Failed to delete policy template: " + e.getMessage()).build();
        }
    }

    // ── Realm Policy endpoints (Midgard-signed) ─────────────────────────

    @GET
    @Path("realm-policy")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getRealmPolicy() {
        auth.realm().requireManageRealm();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        try {
            // Check for committed (active) realm policy
            List<PolicyDraftEntity> active = em.createNamedQuery("getActiveRealmPolicy", PolicyDraftEntity.class)
                    .setParameter("realmId", realm.getId())
                    .getResultList();

            // Check for pending realm policy
            List<PolicyDraftEntity> pending = em.createNamedQuery("getPendingRealmPolicy", PolicyDraftEntity.class)
                    .setParameter("realmId", realm.getId())
                    .getResultList();

            // Check for delete-pending realm policy
            List<PolicyDraftEntity> deletePending = em.createNamedQuery("getDeletePendingRealmPolicy", PolicyDraftEntity.class)
                    .setParameter("realmId", realm.getId())
                    .getResultList();

            Map<String, Object> result = new HashMap<>();

            if (!deletePending.isEmpty()) {
                PolicyDraftEntity entity = deletePending.get(0);
                result.put("status", "delete_pending");
                result.put("id", entity.getId());
                result.put("templateId", entity.getTemplateId());
                result.put("changesetRequestId", entity.getChangesetRequestId());
                result.put("policyData", entity.getPolicy());
                result.put("timestamp", entity.getTimestamp());

                if (entity.getTemplateId() != null) {
                    PolicyTemplateEntity template = em.find(PolicyTemplateEntity.class, entity.getTemplateId());
                    if (template != null) {
                        result.put("templateName", template.getName());
                    }
                }

                ChangesetRequestEntity changesetReq = em.find(ChangesetRequestEntity.class,
                        new ChangesetRequestEntity.Key(entity.getChangesetRequestId(), ChangeSetType.POLICY));
                if (changesetReq != null) {
                    result.put("requestModel", changesetReq.getRequestModel());
                }

                try {
                    DraftStatus changesetStatus = ChangesetRequestAdapter.getChangeSetStatus(
                            session, entity.getChangesetRequestId(), ChangeSetType.POLICY);
                    result.put("changesetStatus", changesetStatus.name());
                } catch (Exception ex) {
                    result.put("changesetStatus", "DRAFT");
                }
            } else if (!active.isEmpty()) {
                PolicyDraftEntity entity = active.get(0);
                result.put("status", "active");
                result.put("id", entity.getId());
                result.put("templateId", entity.getTemplateId());
                result.put("policyData", entity.getPolicy()); // Base64 Midgard Policy bytes
                result.put("timestamp", entity.getTimestamp());

                if (entity.getTemplateId() != null) {
                    PolicyTemplateEntity template = em.find(PolicyTemplateEntity.class, entity.getTemplateId());
                    if (template != null) {
                        result.put("templateName", template.getName());
                    }
                }
            } else if (!pending.isEmpty()) {
                PolicyDraftEntity entity = pending.get(0);
                result.put("status", "pending");
                result.put("id", entity.getId());
                result.put("templateId", entity.getTemplateId());
                result.put("changesetRequestId", entity.getChangesetRequestId());
                result.put("timestamp", entity.getTimestamp());

                if (entity.getTemplateId() != null) {
                    PolicyTemplateEntity template = em.find(PolicyTemplateEntity.class, entity.getTemplateId());
                    if (template != null) {
                        result.put("templateName", template.getName());
                    }
                }

                // Include the model request data for the approval popup
                ChangesetRequestEntity changesetReq = em.find(ChangesetRequestEntity.class,
                        new ChangesetRequestEntity.Key(entity.getChangesetRequestId(), ChangeSetType.POLICY));
                if (changesetReq != null) {
                    result.put("requestModel", changesetReq.getRequestModel());
                }

                // Include the changeset approval status
                try {
                    DraftStatus changesetStatus = ChangesetRequestAdapter.getChangeSetStatus(
                            session, entity.getChangesetRequestId(), ChangeSetType.POLICY);
                    result.put("changesetStatus", changesetStatus.name());
                } catch (Exception ex) {
                    result.put("changesetStatus", "DRAFT");
                }
            } else {
                result.put("status", "none");
            }

            return Response.ok(result, MediaType.APPLICATION_JSON).build();
        } catch (Exception e) {
            logger.error("[RealmPolicy] Error fetching realm policy", e);
            return Response.serverError().entity("Failed to get realm policy: " + e.getMessage()).build();
        }
    }

    @POST
    @Path("realm-policy/pending")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response createPendingRealmPolicy(Map<String, Object> body) {
        auth.realm().requireManageRealm();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        ObjectMapper mapper = new ObjectMapper();

        try {
            String templateId = (String) body.get("templateId");
            String contractCode = (String) body.get("contractCode");
            Object paramValues = body.get("paramValues");

            if (templateId == null || templateId.isBlank()) {
                return Response.status(Response.Status.BAD_REQUEST).entity("templateId is required").build();
            }
            if (contractCode == null || contractCode.isBlank()) {
                return Response.status(Response.Status.BAD_REQUEST).entity("contractCode is required").build();
            }

            // Verify template exists
            PolicyTemplateEntity template = em.find(PolicyTemplateEntity.class, templateId);
            if (template == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("Template not found").build();
            }

            // Check no existing active or pending realm policy
            List<PolicyDraftEntity> active = em.createNamedQuery("getActiveRealmPolicy", PolicyDraftEntity.class)
                    .setParameter("realmId", realm.getId()).getResultList();
            List<PolicyDraftEntity> pendingList = em.createNamedQuery("getPendingRealmPolicy", PolicyDraftEntity.class)
                    .setParameter("realmId", realm.getId()).getResultList();
            if (!active.isEmpty()) {
                return Response.status(Response.Status.CONFLICT).entity("Active realm policy already exists. Delete it first.").build();
            }
            if (!pendingList.isEmpty()) {
                return Response.status(Response.Status.CONFLICT).entity("Pending realm policy already exists.").build();
            }

            // Get VRK config from tide-vendor-key component
            ComponentModel componentModel = realm.getComponentsStream()
                    .filter(x -> x.getProviderId().equalsIgnoreCase(org.tidecloak.shared.Constants.TIDE_VENDOR_KEY))
                    .findFirst().orElse(null);
            if (componentModel == null) {
                return Response.status(Response.Status.BAD_REQUEST).entity("No tide-vendor-key component configured for this realm").build();
            }

            MultivaluedHashMap<String, String> config = componentModel.getConfig();
            String vvkId = config.getFirst("vvkId");
            String currentSecretKeys = config.getFirst("clientSecret");
            SecretKeys secretKeys = mapper.readValue(currentSecretKeys, SecretKeys.class);

            // Compute SHA512 contractId from C# source (same as Forseti/keylessh)
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] hash = sha512.digest(contractCode.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                hexString.append(String.format("%02X", b));
            }
            String contractId = hexString.toString();

            // Build policy parameters
            PolicyParameters policyParams = new PolicyParameters();
            policyParams.put("threshold", 1);
            if (paramValues != null) {
                @SuppressWarnings("unchecked")
                Map<String, Object> pv = (Map<String, Object>) paramValues;
                for (Map.Entry<String, Object> entry : pv.entrySet()) {
                    policyParams.put(entry.getKey(), entry.getValue());
                }
            }

            // Create Midgard Policy object (same pattern as createRolePolicyDraft)
            Policy policy = new Policy(contractId, "any", vvkId, ApprovalType.EXPLICIT, ExecutionType.PUBLIC, policyParams);
            String policyBase64 = Base64.getEncoder().encodeToString(policy.ToBytes());

            // Create PolicySignRequest with Forseti contract upload
            PolicySignRequest pSignReq = new PolicySignRequest(policy.ToBytes(), "Policy:1");
            pSignReq.AddContractToUpload(PolicySignRequest.ContractType.forseti, contractCode.getBytes(StandardCharsets.UTF_8));

            // VRK authorization
            SignRequestSettingsMidgard signedSettings = constructRealmPolicySignSettings(config, secretKeys.activeVrk);
            pSignReq.SetAuthorization(
                    Midgard.SignWithVrk(pSignReq.GetDataToAuthorize(), signedSettings.VendorRotatingPrivateKey)
            );

            // Create ModelRequest (same pattern as createRolePolicyDraft)
            ModelRequest modelReq = ModelRequest.New("Policy", "1", "Policy:1", pSignReq.GetDraft(), policy.ToBytes());
            var expireAtTime = (System.currentTimeMillis() / 1000) + 2628000; // 1 month
            modelReq.SetCustomExpiry(expireAtTime);
            modelReq = ModelRequest.InitializeTideRequestWithVrk(modelReq, signedSettings, "Policy:1",
                    jakarta.xml.bind.DatatypeConverter.parseHexBinary(config.getFirst("gVRK")),
                    Base64.getDecoder().decode(config.getFirst("gVRKCertificate")));

            // Store PolicyDraftEntity with REALM_PENDING scope
            String policyDraftId = KeycloakModelUtils.generateId();
            PolicyDraftEntity policyDraft = new PolicyDraftEntity();
            policyDraft.setId(policyDraftId);
            policyDraft.setRealmId(realm.getId());
            policyDraft.setScope("REALM_PENDING");
            policyDraft.setTemplateId(templateId);
            policyDraft.setPolicy(policyBase64);
            policyDraft.setChangesetRequestId(policyDraftId + "policy");
            em.persist(policyDraft);

            // Store ChangesetRequestEntity (same as multi-admin flow)
            ChangesetRequestEntity changesetReq = new ChangesetRequestEntity();
            changesetReq.setDraftRequest(Base64.getEncoder().encodeToString(policy.getDataToVerify()));
            changesetReq.setChangesetType(ChangeSetType.POLICY);
            changesetReq.setChangesetRequestId(policyDraftId + "policy");
            changesetReq.setRequestModel(Base64.getEncoder().encodeToString(modelReq.Encode()));
            em.persist(changesetReq);

            em.flush();

            logger.infof("[RealmPolicy] PENDING realm=%s templateId=%s id=%s contractId=%s",
                    realm.getName(), templateId, policyDraftId, contractId);

            // Return model request data for the approval popup
            Map<String, Object> result = new HashMap<>();
            result.put("success", true);
            result.put("id", policyDraftId);
            result.put("changesetRequestId", policyDraftId + "policy");
            result.put("requestModel", Base64.getEncoder().encodeToString(modelReq.Encode()));
            result.put("templateName", template.getName());
            result.put("contractId", contractId);
            return Response.ok(result, MediaType.APPLICATION_JSON).build();
        } catch (Exception e) {
            logger.error("[RealmPolicy] Error creating pending realm policy", e);
            return Response.serverError().entity("Failed to create pending realm policy: " + e.getMessage()).build();
        }
    }

    @POST
    @Path("realm-policy/commit")
    @Produces(MediaType.APPLICATION_JSON)
    public Response commitRealmPolicy() {
        auth.realm().requireManageRealm();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        ObjectMapper mapper = new ObjectMapper();

        try {
            // Find the pending realm policy
            List<PolicyDraftEntity> pendingList = em.createNamedQuery("getPendingRealmPolicy", PolicyDraftEntity.class)
                    .setParameter("realmId", realm.getId())
                    .getResultList();
            if (pendingList.isEmpty()) {
                return Response.status(Response.Status.NOT_FOUND).entity("No pending realm policy to commit").build();
            }

            PolicyDraftEntity pending = pendingList.get(0);

            // Load the changeset request
            ChangesetRequestEntity changesetReq = em.find(ChangesetRequestEntity.class,
                    new ChangesetRequestEntity.Key(pending.getChangesetRequestId(), ChangeSetType.POLICY));
            if (changesetReq == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("Changeset request not found").build();
            }

            // Get VRK config
            ComponentModel componentModel = realm.getComponentsStream()
                    .filter(x -> x.getProviderId().equalsIgnoreCase(org.tidecloak.shared.Constants.TIDE_VENDOR_KEY))
                    .findFirst().orElse(null);
            if (componentModel == null) {
                return Response.status(Response.Status.BAD_REQUEST).entity("No tide-vendor-key configured").build();
            }

            MultivaluedHashMap<String, String> config = componentModel.getConfig();
            String currentSecretKeys = config.getFirst("clientSecret");
            SecretKeys secretKeys = mapper.readValue(currentSecretKeys, SecretKeys.class);

            SignRequestSettingsMidgard settings = constructRealmPolicySignSettings(config, secretKeys.activeVrk);

            // Reconstruct the ModelRequest and sign it
            ModelRequest modelReq = ModelRequest.FromBytes(Base64.getDecoder().decode(changesetReq.getRequestModel()));

            // Attach the current admin policy (same as keylessh commit flow)
            ClientModel realmManagement = session.clients().getClientByClientId(realm, Constants.REALM_MANAGEMENT_CLIENT_ID);
            RoleModel tideRole = realmManagement.getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
            if (tideRole != null) {
                List<TideRoleDraftEntity> roleDrafts = em.createNamedQuery("getRoleDraftByRoleId", TideRoleDraftEntity.class)
                        .setParameter("roleId", tideRole.getId())
                        .getResultList();
                if (!roleDrafts.isEmpty() && roleDrafts.get(0).getInitCert() != null) {
                    Policy adminPolicy = Policy.From(Base64.getDecoder().decode(roleDrafts.get(0).getInitCert()));
                    modelReq.SetPolicy(adminPolicy.ToBytes());
                }
            }

            // Sign via Midgard
            SignatureResponse response = Midgard.SignModel(settings, modelReq);

            // Add signature to the realm policy
            Policy realmPolicy = Policy.From(Base64.getDecoder().decode(pending.getPolicy()));
            realmPolicy.AddSignature(Base64.getDecoder().decode(response.Signatures[0]));

            // Commit: update PolicyDraftEntity to REALM scope with signed policy
            pending.setPolicy(Base64.getEncoder().encodeToString(realmPolicy.ToBytes()));
            pending.setScope("REALM");
            pending.setChangesetRequestId(null);
            pending.setTimestamp(System.currentTimeMillis());

            // Remove changeset request
            em.remove(changesetReq);
            em.flush();

            logger.infof("[RealmPolicy] COMMIT realm=%s id=%s", realm.getName(), pending.getId());

            Map<String, Object> result = new HashMap<>();
            result.put("success", true);
            result.put("id", pending.getId());
            return Response.ok(result, MediaType.APPLICATION_JSON).build();
        } catch (Exception e) {
            logger.error("[RealmPolicy] Error committing realm policy", e);
            return Response.serverError().entity("Failed to commit realm policy: " + e.getMessage()).build();
        }
    }

    @POST
    @Path("realm-policy/request-delete")
    @Produces(MediaType.APPLICATION_JSON)
    public Response requestDeleteRealmPolicy() {
        auth.realm().requireManageRealm();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        ObjectMapper mapper = new ObjectMapper();

        try {
            // 1. Find active realm policy
            List<PolicyDraftEntity> active = em.createNamedQuery("getActiveRealmPolicy", PolicyDraftEntity.class)
                    .setParameter("realmId", realm.getId())
                    .getResultList();
            if (active.isEmpty()) {
                return Response.status(Response.Status.NOT_FOUND).entity("No active realm policy to delete").build();
            }

            // 2. Guard against existing pending requests
            List<PolicyDraftEntity> deletePending = em.createNamedQuery("getDeletePendingRealmPolicy", PolicyDraftEntity.class)
                    .setParameter("realmId", realm.getId())
                    .getResultList();
            if (!deletePending.isEmpty()) {
                return Response.status(Response.Status.CONFLICT).entity("A delete request is already pending").build();
            }
            List<PolicyDraftEntity> createPending = em.createNamedQuery("getPendingRealmPolicy", PolicyDraftEntity.class)
                    .setParameter("realmId", realm.getId())
                    .getResultList();
            if (!createPending.isEmpty()) {
                return Response.status(Response.Status.CONFLICT).entity("A create request is already pending").build();
            }

            PolicyDraftEntity activePolicy = active.get(0);

            // 3. Get VRK config
            ComponentModel componentModel = realm.getComponentsStream()
                    .filter(x -> x.getProviderId().equalsIgnoreCase(org.tidecloak.shared.Constants.TIDE_VENDOR_KEY))
                    .findFirst().orElse(null);
            if (componentModel == null) {
                return Response.status(Response.Status.BAD_REQUEST).entity("No tide-vendor-key component configured").build();
            }

            MultivaluedHashMap<String, String> config = componentModel.getConfig();
            String currentSecretKeys = config.getFirst("clientSecret");
            SecretKeys secretKeys = mapper.readValue(currentSecretKeys, SecretKeys.class);

            // 4. Reconstruct the Policy from existing bytes
            byte[] policyBytes = Base64.getDecoder().decode(activePolicy.getPolicy());
            Policy policy = Policy.From(policyBytes);

            // 5. Create PolicySignRequest (no contract upload for delete)
            PolicySignRequest pSignReq = new PolicySignRequest(policy.ToBytes(), "Policy:1");

            // 6. VRK authorization
            SignRequestSettingsMidgard signedSettings = constructRealmPolicySignSettings(config, secretKeys.activeVrk);
            pSignReq.SetAuthorization(
                    Midgard.SignWithVrk(pSignReq.GetDataToAuthorize(), signedSettings.VendorRotatingPrivateKey)
            );

            // 7. Create ModelRequest
            ModelRequest modelReq = ModelRequest.New("Policy", "1", "Policy:1", pSignReq.GetDraft(), policy.ToBytes());
            var expireAtTime = (System.currentTimeMillis() / 1000) + 2628000; // 1 month
            modelReq.SetCustomExpiry(expireAtTime);
            modelReq = ModelRequest.InitializeTideRequestWithVrk(modelReq, signedSettings, "Policy:1",
                    jakarta.xml.bind.DatatypeConverter.parseHexBinary(config.getFirst("gVRK")),
                    Base64.getDecoder().decode(config.getFirst("gVRKCertificate")));

            // 8. Change scope to REALM_DELETE_PENDING and set changeset ID
            String changesetId = activePolicy.getId() + "policy-delete";
            activePolicy.setScope("REALM_DELETE_PENDING");
            activePolicy.setChangesetRequestId(changesetId);

            // 9. Create ChangesetRequestEntity
            ChangesetRequestEntity changesetReq = new ChangesetRequestEntity();
            changesetReq.setDraftRequest(Base64.getEncoder().encodeToString(policy.getDataToVerify()));
            changesetReq.setChangesetType(ChangeSetType.POLICY);
            changesetReq.setChangesetRequestId(changesetId);
            changesetReq.setRequestModel(Base64.getEncoder().encodeToString(modelReq.Encode()));
            em.persist(changesetReq);

            em.flush();

            logger.infof("[RealmPolicy] DELETE_PENDING realm=%s id=%s", realm.getName(), activePolicy.getId());

            Map<String, Object> result = new HashMap<>();
            result.put("success", true);
            result.put("id", activePolicy.getId());
            result.put("changesetRequestId", changesetId);
            result.put("requestModel", Base64.getEncoder().encodeToString(modelReq.Encode()));
            return Response.ok(result, MediaType.APPLICATION_JSON).build();
        } catch (Exception e) {
            logger.error("[RealmPolicy] Error requesting realm policy deletion", e);
            return Response.serverError().entity("Failed to request realm policy deletion: " + e.getMessage()).build();
        }
    }

    @POST
    @Path("realm-policy/commit-delete")
    @Produces(MediaType.APPLICATION_JSON)
    public Response commitDeleteRealmPolicy() {
        auth.realm().requireManageRealm();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        ObjectMapper mapper = new ObjectMapper();

        try {
            // 1. Find the delete-pending realm policy
            List<PolicyDraftEntity> deletePendingList = em.createNamedQuery("getDeletePendingRealmPolicy", PolicyDraftEntity.class)
                    .setParameter("realmId", realm.getId())
                    .getResultList();
            if (deletePendingList.isEmpty()) {
                return Response.status(Response.Status.NOT_FOUND).entity("No delete-pending realm policy to commit").build();
            }

            PolicyDraftEntity pending = deletePendingList.get(0);

            // 2. Load the changeset request
            ChangesetRequestEntity changesetReq = em.find(ChangesetRequestEntity.class,
                    new ChangesetRequestEntity.Key(pending.getChangesetRequestId(), ChangeSetType.POLICY));
            if (changesetReq == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("Changeset request not found").build();
            }

            // 3. Get VRK config
            ComponentModel componentModel = realm.getComponentsStream()
                    .filter(x -> x.getProviderId().equalsIgnoreCase(org.tidecloak.shared.Constants.TIDE_VENDOR_KEY))
                    .findFirst().orElse(null);
            if (componentModel == null) {
                return Response.status(Response.Status.BAD_REQUEST).entity("No tide-vendor-key configured").build();
            }

            MultivaluedHashMap<String, String> config = componentModel.getConfig();
            String currentSecretKeys = config.getFirst("clientSecret");
            SecretKeys secretKeys = mapper.readValue(currentSecretKeys, SecretKeys.class);

            SignRequestSettingsMidgard settings = constructRealmPolicySignSettings(config, secretKeys.activeVrk);

            // 4. Reconstruct the ModelRequest and sign it
            ModelRequest modelReq = ModelRequest.FromBytes(Base64.getDecoder().decode(changesetReq.getRequestModel()));

            // 5. Attach admin policy
            ClientModel realmManagement = session.clients().getClientByClientId(realm, Constants.REALM_MANAGEMENT_CLIENT_ID);
            RoleModel tideRole = realmManagement.getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
            if (tideRole != null) {
                List<TideRoleDraftEntity> roleDrafts = em.createNamedQuery("getRoleDraftByRoleId", TideRoleDraftEntity.class)
                        .setParameter("roleId", tideRole.getId())
                        .getResultList();
                if (!roleDrafts.isEmpty() && roleDrafts.get(0).getInitCert() != null) {
                    Policy adminPolicy = Policy.From(Base64.getDecoder().decode(roleDrafts.get(0).getInitCert()));
                    modelReq.SetPolicy(adminPolicy.ToBytes());
                }
            }

            // 6. Sign via Midgard
            SignatureResponse response = Midgard.SignModel(settings, modelReq);

            // 7. Remove the PolicyDraftEntity and ChangesetRequestEntity
            em.remove(changesetReq);
            em.remove(pending);
            em.flush();

            logger.infof("[RealmPolicy] COMMIT-DELETE realm=%s id=%s", realm.getName(), pending.getId());

            Map<String, Object> result = new HashMap<>();
            result.put("success", true);
            result.put("id", pending.getId());
            return Response.ok(result, MediaType.APPLICATION_JSON).build();
        } catch (Exception e) {
            logger.error("[RealmPolicy] Error committing realm policy deletion", e);
            return Response.serverError().entity("Failed to commit realm policy deletion: " + e.getMessage()).build();
        }
    }

    @DELETE
    @Path("realm-policy")
    @Produces(MediaType.APPLICATION_JSON)
    public Response deleteRealmPolicy() {
        auth.realm().requireManageRealm();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        try {
            // Handle delete-pending: revert to active
            List<PolicyDraftEntity> deletePending = em.createNamedQuery("getDeletePendingRealmPolicy", PolicyDraftEntity.class)
                    .setParameter("realmId", realm.getId())
                    .getResultList();
            for (PolicyDraftEntity entity : deletePending) {
                if (entity.getChangesetRequestId() != null) {
                    ChangesetRequestEntity changesetReq = em.find(ChangesetRequestEntity.class,
                            new ChangesetRequestEntity.Key(entity.getChangesetRequestId(), ChangeSetType.POLICY));
                    if (changesetReq != null) {
                        changesetReq.getAdminAuthorizations().clear();
                        em.remove(changesetReq);
                    }
                }
                entity.setScope("REALM");
                entity.setChangesetRequestId(null);
            }

            // Handle pending creation: remove entirely
            List<PolicyDraftEntity> pending = em.createNamedQuery("getPendingRealmPolicy", PolicyDraftEntity.class)
                    .setParameter("realmId", realm.getId())
                    .getResultList();
            for (PolicyDraftEntity entity : pending) {
                if (entity.getChangesetRequestId() != null) {
                    ChangesetRequestEntity changesetReq = em.find(ChangesetRequestEntity.class,
                            new ChangesetRequestEntity.Key(entity.getChangesetRequestId(), ChangeSetType.POLICY));
                    if (changesetReq != null) {
                        changesetReq.getAdminAuthorizations().clear();
                        em.remove(changesetReq);
                    }
                }
                em.remove(entity);
            }

            em.flush();
            logger.infof("[RealmPolicy] DELETE/CANCEL realm=%s", realm.getName());
            return Response.ok(Map.of("success", true)).build();
        } catch (Exception e) {
            logger.error("[RealmPolicy] Error deleting/cancelling realm policy", e);
            return Response.serverError().entity("Failed to delete/cancel realm policy: " + e.getMessage()).build();
        }
    }

    // ── Forseti Contract endpoints ───────────────────────────────────

    @PUT
    @Path("forseti-contracts")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response upsertForsetiContract(Map<String, Object> body) {
        auth.realm().requireManageRealm();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        try {
            String contractCode = (String) body.get("contractCode");
            String name = (String) body.get("name");

            if (contractCode == null || contractCode.isBlank()) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("contractCode is required").build();
            }

            // Compute SHA512 hash of contract code
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] hash = sha512.digest(contractCode.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                hexString.append(String.format("%02X", b));
            }
            String contractHash = hexString.toString();

            // Check if contract already exists for this realm + hash
            List<ForsetiContractEntity> existing = em.createNamedQuery(
                    "getForsetiContractByRealmAndHash", ForsetiContractEntity.class)
                    .setParameter("realmId", realm.getId())
                    .setParameter("contractHash", contractHash)
                    .getResultList();

            ForsetiContractEntity entity;
            if (!existing.isEmpty()) {
                entity = existing.get(0);
                if (name != null) entity.setName(name);
                entity.setContractCode(contractCode);
                entity.setTimestamp(System.currentTimeMillis());
                em.merge(entity);
            } else {
                entity = new ForsetiContractEntity();
                entity.setId(UUID.randomUUID().toString());
                entity.setRealmId(realm.getId());
                entity.setContractHash(contractHash);
                entity.setContractCode(contractCode);
                entity.setName(name);
                em.persist(entity);
            }
            em.flush();

            logger.infof("[ForsetiContract] UPSERT realm=%s hash=%s id=%s",
                    realm.getName(), contractHash, entity.getId());

            Map<String, Object> result = new HashMap<>();
            result.put("success", true);
            result.put("id", entity.getId());
            result.put("contractHash", contractHash);
            return Response.ok(result, MediaType.APPLICATION_JSON).build();
        } catch (Exception e) {
            logger.error("[ForsetiContract] Error upserting contract", e);
            return Response.serverError()
                    .entity("Failed to upsert Forseti contract: " + e.getMessage()).build();
        }
    }

    @GET
    @Path("forseti-contracts")
    @Produces(MediaType.APPLICATION_JSON)
    public Response listForsetiContracts() {
        auth.realm().requireManageRealm();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        try {
            List<ForsetiContractEntity> entities = em.createNamedQuery(
                    "getForsetiContractsByRealm", ForsetiContractEntity.class)
                    .setParameter("realmId", realm.getId())
                    .getResultList();

            List<Map<String, Object>> contracts = new ArrayList<>();
            for (ForsetiContractEntity entity : entities) {
                Map<String, Object> c = new HashMap<>();
                c.put("id", entity.getId());
                c.put("contractHash", entity.getContractHash());
                c.put("contractCode", entity.getContractCode());
                c.put("name", entity.getName());
                c.put("timestamp", entity.getTimestamp());
                contracts.add(c);
            }

            return Response.ok(contracts, MediaType.APPLICATION_JSON).build();
        } catch (Exception e) {
            logger.error("[ForsetiContract] Error listing contracts", e);
            return Response.serverError()
                    .entity("Failed to list Forseti contracts: " + e.getMessage()).build();
        }
    }

    // ── SSH Policy endpoints ──────────────────────────────────────────

    @PUT
    @Path("ssh-policies")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response upsertSshPolicy(Map<String, Object> body) {
        auth.realm().requireManageRealm();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        try {
            String roleId = (String) body.get("roleId");
            String contractCode = (String) body.get("contractCode");
            String approvalType = (String) body.get("approvalType");
            String executionType = (String) body.get("executionType");
            Integer threshold = body.get("threshold") != null ? ((Number) body.get("threshold")).intValue() : 1;
            String policyData = (String) body.get("policyData");

            if (roleId == null || roleId.isBlank()) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("roleId is required").build();
            }

            // Upsert the Forseti contract if contract code is provided
            String contractEntityId = null;
            if (contractCode != null && !contractCode.isBlank()) {
                MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
                byte[] hash = sha512.digest(contractCode.getBytes(StandardCharsets.UTF_8));
                StringBuilder hexString = new StringBuilder();
                for (byte b : hash) {
                    hexString.append(String.format("%02X", b));
                }
                String contractHash = hexString.toString();

                List<ForsetiContractEntity> existingContracts = em.createNamedQuery(
                        "getForsetiContractByRealmAndHash", ForsetiContractEntity.class)
                        .setParameter("realmId", realm.getId())
                        .setParameter("contractHash", contractHash)
                        .getResultList();

                ForsetiContractEntity contractEntity;
                if (!existingContracts.isEmpty()) {
                    contractEntity = existingContracts.get(0);
                } else {
                    contractEntity = new ForsetiContractEntity();
                    contractEntity.setId(UUID.randomUUID().toString());
                    contractEntity.setRealmId(realm.getId());
                    contractEntity.setContractHash(contractHash);
                    contractEntity.setContractCode(contractCode);
                    em.persist(contractEntity);
                }
                contractEntityId = contractEntity.getId();
            }

            // Upsert the SSH policy
            List<SshPolicyEntity> existing = em.createNamedQuery(
                    "getSshPolicyByRealmAndRoleId", SshPolicyEntity.class)
                    .setParameter("realmId", realm.getId())
                    .setParameter("roleId", roleId)
                    .getResultList();

            SshPolicyEntity entity;
            if (!existing.isEmpty()) {
                entity = existing.get(0);
            } else {
                entity = new SshPolicyEntity();
                entity.setId(UUID.randomUUID().toString());
                entity.setRealmId(realm.getId());
                entity.setRoleId(roleId);
            }

            if (contractEntityId != null) {
                entity.setContractId(contractEntityId);
            }
            entity.setApprovalType(approvalType != null ? approvalType : "implicit");
            entity.setExecutionType(executionType != null ? executionType : "private");
            entity.setThreshold(threshold);
            entity.setPolicyData(policyData);
            entity.setTimestamp(System.currentTimeMillis());

            if (existing.isEmpty()) {
                em.persist(entity);
            } else {
                em.merge(entity);
            }
            em.flush();

            logger.infof("[SshPolicy] UPSERT realm=%s roleId=%s id=%s",
                    realm.getName(), roleId, entity.getId());

            Map<String, Object> result = new HashMap<>();
            result.put("success", true);
            result.put("id", entity.getId());
            result.put("roleId", roleId);
            return Response.ok(result, MediaType.APPLICATION_JSON).build();
        } catch (Exception e) {
            logger.error("[SshPolicy] Error upserting SSH policy", e);
            return Response.serverError()
                    .entity("Failed to upsert SSH policy: " + e.getMessage()).build();
        }
    }

    @GET
    @Path("ssh-policies")
    @Produces(MediaType.APPLICATION_JSON)
    public Response listSshPolicies() {
        auth.realm().requireManageRealm();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        try {
            List<SshPolicyEntity> entities = em.createNamedQuery(
                    "getSshPoliciesByRealm", SshPolicyEntity.class)
                    .setParameter("realmId", realm.getId())
                    .getResultList();

            List<Map<String, Object>> policies = new ArrayList<>();
            for (SshPolicyEntity entity : entities) {
                Map<String, Object> p = new HashMap<>();
                p.put("id", entity.getId());
                p.put("roleId", entity.getRoleId());
                p.put("contractId", entity.getContractId());
                p.put("approvalType", entity.getApprovalType());
                p.put("executionType", entity.getExecutionType());
                p.put("threshold", entity.getThreshold());
                p.put("policyData", entity.getPolicyData());
                p.put("timestamp", entity.getTimestamp());

                // Include contract details if linked
                if (entity.getContractId() != null) {
                    ForsetiContractEntity contract = em.find(ForsetiContractEntity.class, entity.getContractId());
                    if (contract != null) {
                        p.put("contractHash", contract.getContractHash());
                        p.put("contractName", contract.getName());
                        p.put("contractCode", contract.getContractCode());
                    }
                }

                policies.add(p);
            }

            return Response.ok(policies, MediaType.APPLICATION_JSON).build();
        } catch (Exception e) {
            logger.error("[SshPolicy] Error listing SSH policies", e);
            return Response.serverError()
                    .entity("Failed to list SSH policies: " + e.getMessage()).build();
        }
    }

    @DELETE
    @Path("ssh-policies")
    @Produces(MediaType.APPLICATION_JSON)
    public Response deleteSshPolicy(@QueryParam("roleId") String roleId) {
        auth.realm().requireManageRealm();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        try {
            if (roleId == null || roleId.isEmpty()) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("roleId query parameter is required").build();
            }

            int deleted = em.createNamedQuery("deleteSshPolicyByRealmAndRoleId")
                    .setParameter("realmId", realm.getId())
                    .setParameter("roleId", roleId)
                    .executeUpdate();

            if (deleted == 0) {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("SSH policy not found for roleId: " + roleId).build();
            }

            em.flush();
            logger.infof("[SshPolicy] DELETE realm=%s roleId=%s", realm.getName(), roleId);

            Map<String, Object> result = new HashMap<>();
            result.put("success", true);
            return Response.ok(result, MediaType.APPLICATION_JSON).build();
        } catch (Exception e) {
            logger.error("[SshPolicy] Error deleting SSH policy", e);
            return Response.serverError()
                    .entity("Failed to delete SSH policy: " + e.getMessage()).build();
        }
    }

    @GET
    @Path("role-policies")
    @Produces(MediaType.APPLICATION_JSON)
    public Response listRolePolicies() {
        auth.realm().requireManageRealm();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        try {
            // Get all TideRoleDraftEntities in this realm that have an initCert
            List<TideRoleDraftEntity> roleDrafts = em.createQuery(
                    "SELECT r FROM TideRoleDraftEntity r WHERE r.initCert IS NOT NULL " +
                    "AND r.role IN (SELECT u FROM RoleEntity u WHERE u.realmId = :realmId)",
                    TideRoleDraftEntity.class)
                    .setParameter("realmId", realm.getId())
                    .getResultList();

            // Resolve role name for tide-realm-admin to exclude it
            String tideRealmAdminRoleId = null;
            ClientModel realmMgmt = session.clients().getClientByClientId(realm, Constants.REALM_MANAGEMENT_CLIENT_ID);
            if (realmMgmt != null) {
                RoleModel tideAdminRole = realmMgmt.getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
                if (tideAdminRole != null) {
                    tideRealmAdminRoleId = tideAdminRole.getId();
                }
            }

            List<Map<String, Object>> result = new ArrayList<>();
            for (TideRoleDraftEntity draft : roleDrafts) {
                RoleEntity roleEntity = draft.getRole();
                if (roleEntity == null) continue;

                // Skip tide-realm-admin — it's shown separately as admin policy
                if (roleEntity.getId().equals(tideRealmAdminRoleId)) continue;

                // Parse the policy from initCert
                Map<String, Object> entry = new HashMap<>();
                entry.put("id", draft.getId());
                entry.put("roleId", roleEntity.getId());
                entry.put("roleName", roleEntity.getName());
                entry.put("clientRole", roleEntity.isClientRole());
                if (roleEntity.isClientRole()) {
                    ClientModel client = realm.getClientById(roleEntity.getClientId());
                    if (client != null) {
                        entry.put("clientId", client.getClientId());
                    }
                }
                entry.put("timestamp", draft.getTimestamp());
                entry.put("hasSig", draft.getInitCertSig() != null && !draft.getInitCertSig().isEmpty());

                try {
                    Policy policy = Policy.From(Base64.getDecoder().decode(draft.getInitCert()));
                    entry.put("policyDisplay", policy.toString());
                } catch (Exception e) {
                    entry.put("policyDisplay", null);
                }

                result.add(entry);
            }

            return Response.ok(result, MediaType.APPLICATION_JSON).build();
        } catch (Exception e) {
            logger.error("[RolePolicies] Error listing role policies", e);
            return Response.serverError()
                    .entity("Failed to list role policies: " + e.getMessage()).build();
        }
    }

    // Helper: build sign settings for realm policy (same as ConstructSignSettings in TideAdminRealmResource)
    private SignRequestSettingsMidgard constructRealmPolicySignSettings(MultivaluedHashMap<String, String> config, String vrk) {
        int threshold = Integer.parseInt(System.getenv("THRESHOLD_T"));
        int max = Integer.parseInt(System.getenv("THRESHOLD_N"));

        SignRequestSettingsMidgard settings = new SignRequestSettingsMidgard();
        settings.VVKId = config.getFirst("vvkId");
        settings.HomeOrkUrl = config.getFirst("systemHomeOrk");
        settings.PayerPublicKey = config.getFirst("payerPublic");
        settings.ObfuscatedVendorPublicKey = config.getFirst("obfGVVK");
        settings.VendorRotatingPrivateKey = vrk;
        settings.Threshold_T = threshold;
        settings.Threshold_N = max;

        return settings;
    }

    /**
     * Signs IDP settings including all client web origins.
     * Duplicated from VendorResource.SignIdpSettings in tidecloak-idp-extensions.
     */
    private void signIdpSettings(IdentityProviderModel idp, ComponentModel componentModel) {
        try {
            MultivaluedHashMap<String, String> config = componentModel.getConfig();
            ObjectMapper objectMapper = new ObjectMapper();
            String currentSecretKeys = config.getFirst("clientSecret");
            SecretKeys secretKeys = objectMapper.readValue(currentSecretKeys, SecretKeys.class);

            if (secretKeys.activeVrk == null || secretKeys.activeVrk.trim().isEmpty()) {
                logger.warn("Unable to sign settings, no active license for realm " + realm.getName());
                return;
            }

            SignRequestSettingsMidgard settings = constructRealmPolicySignSettings(config, secretKeys.activeVrk);

            boolean isBackupOn = idp.getConfig().getOrDefault("backupOn", "false").equalsIgnoreCase("true");
            VendorSettings vendorSettings = new VendorSettings(realm.isRegistrationAllowed(), isBackupOn, idp.getConfig().get("ImageURL"), idp.getConfig().get("LogoURL"));
            String vendorSettingsString = objectMapper.writeValueAsString(vendorSettings);

            String encodedRealmName = java.net.URLEncoder.encode(realm.getName(), StandardCharsets.UTF_8);
            String authServerUrl = session.getContext().getAuthServerUrl().toString();
            authServerUrl = authServerUrl.endsWith("/") ? authServerUrl : authServerUrl + "/";

            String loginEndpoint = authServerUrl + "realms/" + encodedRealmName + "/broker/tide/endpoint";
            String linkTideAccEndpoint = authServerUrl + "realms/" + encodedRealmName + "/login-actions/required-action";
            String changeSetEndpoint = idp.getConfig().get("changeSetEndpoint");
            String customAdminUIDomain = idp.getConfig().get("CustomAdminUIDomain");

            List<String> urls = new ArrayList<>();
            urls.add(loginEndpoint);
            urls.add(linkTideAccEndpoint);
            urls.add(changeSetEndpoint);
            if (customAdminUIDomain != null) {
                urls.add(customAdminUIDomain);
            }

            // Collect all client web origins
            record ClientOrigins(String clientId, List<String> origins) {}
            List<ClientOrigins> clientorigins;
            try (java.util.stream.Stream<ClientModel> s = realm.getClientsStream()) {
                clientorigins = s
                        .map(c -> new ClientOrigins(c.getClientId(), getAllWebOriginsForClient(c)))
                        .collect(Collectors.toList());
            }

            List<String> clientOriginsToSend = new ArrayList<>();
            for (ClientOrigins co : clientorigins) {
                clientOriginsToSend.addAll(co.origins());
            }

            String clientJsonUrls = objectMapper.writeValueAsString(clientOriginsToSend);
            String jsonUrls = objectMapper.writeValueAsString(urls);
            String draft = jsonUrls + "|" + clientJsonUrls + "|" + vendorSettingsString;

            ModelRequest req = ModelRequest.New("TidecloakUpdateSettings", "1", "VRK:1", draft.getBytes(StandardCharsets.UTF_8));
            req.SetAuthorization(Midgard.SignWithVrk(req.GetDataToAuthorize(), settings.VendorRotatingPrivateKey));
            req.SetAuthorizer(jakarta.xml.bind.DatatypeConverter.parseHexBinary(config.getFirst("gVRK")));
            req.SetAuthorizerCertificate(Base64.getDecoder().decode(config.getFirst("gVRKCertificate")));
            SignatureResponse response = Midgard.SignModel(settings, req);

            idp.getConfig().put("loginURLSig", response.Signatures[0]);
            idp.getConfig().put("linkTideURLSig", response.Signatures[1]);
            idp.getConfig().put("changeSetURLSig", response.Signatures[2]);
            if (customAdminUIDomain != null) {
                idp.getConfig().put("customAdminUIDomainSig", response.Signatures[3]);
            }

            int urlIndex = 0;
            for (ClientOrigins co : clientorigins) {
                String clientId = co.clientId();
                for (String origin : co.origins()) {
                    idp.getConfig().put("clientAuth:" + clientId + origin, response.Signatures[urlIndex + urls.size()]);
                    urlIndex++;
                }
            }

            idp.getConfig().put("settingsSig", response.Signatures[response.Signatures.length - 1]);
            session.identityProviders().update(idp);

        } catch (Exception e) {
            throw new RuntimeException("Unable to sign Identity provider settings: " + e.getMessage(), e);
        }
    }

    private static List<String> getAllWebOriginsForClient(ClientModel client) {
        Set<String> origins = new LinkedHashSet<>();
        for (String raw : client.getWebOrigins()) {
            String o = extractOrigin(raw);
            if (o != null) origins.add(o);
        }
        if (client.getRootUrl() != null) { String o = extractOrigin(client.getRootUrl()); if (o != null) origins.add(o); }
        if (client.getBaseUrl() != null) { String o = extractOrigin(client.getBaseUrl()); if (o != null) origins.add(o); }
        if (client.getManagementUrl() != null) { String o = extractOrigin(client.getManagementUrl()); if (o != null) origins.add(o); }
        for (String redirect : client.getRedirectUris()) {
            String o = extractOrigin(redirect);
            if (o != null) origins.add(o);
        }
        return new ArrayList<>(origins);
    }

    private static String extractOrigin(String uriStr) {
        if (uriStr == null) return null;
        uriStr = uriStr.trim();
        if (uriStr.equals("+")) return null;
        try {
            java.net.URI u = new java.net.URI(uriStr);
            String scheme = u.getScheme();
            String host = u.getHost();
            int port = u.getPort();
            if (scheme == null || host == null) return null;
            return (port == -1) ? scheme + "://" + host : scheme + "://" + host + ":" + port;
        } catch (java.net.URISyntaxException e) {
            return null;
        }
    }

    @POST
    @Path("what-if-token")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response whatIfToken(WhatIfRequest request) {
        auth.realm().requireManageRealm();
        try {
            if (request.getChangeSetType() == null || request.getActionType() == null
                    || request.getUserId() == null || request.getClientId() == null) {
                return buildResponse(400, "changeSetType, actionType, userId, and clientId are required.");
            }

            ChangeSetProcessorFactory processorFactory = ChangeSetProcessorFactoryProvider.getFactory();
            ChangeSetProcessor<?> processor = processorFactory.getProcessor(request.getChangeSetType());
            String whatIfToken = processor.generateWhatIfToken(session, realm, request);

            return Response.ok(whatIfToken, MediaType.APPLICATION_JSON).build();
        } catch (IllegalArgumentException e) {
            return buildResponse(400, e.getMessage());
        } catch (Exception e) {
            logger.error("Error generating what-if token", e);
            return buildResponse(500, "Error generating what-if token: " + e.getMessage());
        }
    }

    private Response buildResponse(int status, String message) {
        return Response.status(status)
                .entity(message)
                .type(MediaType.TEXT_PLAIN)
                .build();
    }

    public List<Map<String, Object>> signChangeSets(List<ChangeSetRequest> changeSets) throws Exception {
        auth.users().requireManage();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        RealmModel realm = session.getContext().getRealm();
        ChangeSetSigner signer = ChangeSetSignerFactory.getSigner(session);

        // Store policyRoleId and dynamicData in session so deep processing methods
        // (e.g. TideChangeSetProcessor for UserContext signing) can access them
        if (changeSets != null && !changeSets.isEmpty()) {
            String policyRoleId = changeSets.get(0).getPolicyRoleId();
            if (policyRoleId != null) {
                session.setAttribute("policyRoleId", policyRoleId);
            }
            List<String> dynamicData = changeSets.get(0).getDynamicData();
            if (dynamicData != null && !dynamicData.isEmpty()) {
                session.setAttribute("dynamicData", dynamicData);
                System.out.println("[signChangeSets] Stored dynamicData in session: " + dynamicData.size() + " elements");
            }
        }

        // When firstAdmin authorizer, only allow signing one tide-realm-admin at a time
        ComponentModel tideComponent = realm.getComponentsStream()
                .filter(x -> x.getProviderId().equalsIgnoreCase(org.tidecloak.shared.Constants.TIDE_VENDOR_KEY))
                .findFirst()
                .orElse(null);
        if (tideComponent != null && changeSets.size() > 1) {
            List<AuthorizerEntity> realmAuthorizers = em.createNamedQuery("getAuthorizerByProviderIdAndTypes", AuthorizerEntity.class)
                    .setParameter("ID", tideComponent.getId())
                    .setParameter("types", List.of("firstAdmin", "multiAdmin"))
                    .getResultList();
            if (!realmAuthorizers.isEmpty() && "firstAdmin".equals(realmAuthorizers.get(0).getType())) {
                RoleModel tideRealmAdminRole = realm.getClientByClientId(org.keycloak.models.Constants.REALM_MANAGEMENT_CLIENT_ID)
                        .getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
                if (tideRealmAdminRole != null) {
                    long authorityCount = changeSets.stream()
                            .filter(cs -> cs.getType() == ChangeSetType.USER_ROLE)
                            .filter(cs -> {
                                List<?> drafts = BasicIGAUtils.fetchDraftRecordEntityByRequestId(em, cs.getType(), cs.getChangeSetId());
                                return drafts.stream().anyMatch(d ->
                                        d instanceof TideUserRoleMappingDraftEntity urm
                                                && urm.getRoleId().equals(tideRealmAdminRole.getId()));
                            })
                            .count();
                    if (authorityCount > 1) {
                        throw new BadRequestException("As firstAdmin, you can only sign one tide-realm-admin assignment at a time");
                    }
                }
            }
        }

        List<Map<String, Object>> signedList = new ArrayList<>();
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
                            return processorFactory.getProcessor(requestType)
                                    .combineChangeRequests(session, entities, em)
                                    .stream();
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    })
                    .collect(Collectors.toList());

            for (ChangesetRequestEntity changeSet : changeRequests) {
                List<?> draftRecordEntities = BasicIGAUtils.fetchDraftRecordEntityByRequestId(
                        em,
                        changeSet.getChangesetType(),
                        changeSet.getChangesetRequestId()
                );

                boolean allDelete = draftRecordEntities.stream()
                        .map(BasicIGAUtils::getActionTypeFromEntity)
                        .allMatch(actionType -> actionType == ActionType.DELETE);

                ActionType actionType = allDelete ? ActionType.DELETE : ActionType.CREATE;

                ChangeSetRequest bulkReq = new ChangeSetRequest(
                        changeSet.getChangesetRequestId(),
                        changeSet.getChangesetType(),
                        actionType
                );
                // Carry over policyRoleId and dynamicData from the original request
                // so MultiAdmin.signWithAuthorizer() can resolve and set the signed policy
                String policyRoleId = changeSets.get(0).getPolicyRoleId();
                if (policyRoleId != null) {
                    bulkReq.setPolicyRoleId(policyRoleId);
                }
                List<String> dynamicData = changeSets.get(0).getDynamicData();
                if (dynamicData != null && !dynamicData.isEmpty()) {
                    bulkReq.setDynamicData(dynamicData);
                }

                Response singleResp = signer.sign(
                        bulkReq,
                        em,
                        session,
                        realm,
                        draftRecordEntities,
                        auth.adminAuth()
                );

                handleSignerResponse(singleResp, objectMapper, signedList);
            }
        } else {
            for (ChangeSetRequest changeSet : changeSets) {
                List<?> draftRecordEntities = BasicIGAUtils.fetchDraftRecordEntityByRequestId(
                        em,
                        changeSet.getType(),
                        changeSet.getChangeSetId()
                );

                if (draftRecordEntities == null || draftRecordEntities.isEmpty()) {
                    throw new BadRequestException(
                            "Unsupported change set type for ID: " + changeSet.getChangeSetId()
                    );
                }

                Response singleResp = signer.sign(
                        changeSet,
                        em,
                        session,
                        realm,
                        draftRecordEntities,
                        auth.adminAuth()
                );

                handleSignerResponse(singleResp, objectMapper, signedList);
            }
        }

        return signedList;
    }

    /**
     * Handles both:
     *  - FirstAdmin: JSON OBJECT -> { ... }
     *  - MultiAdmin: JSON ARRAY  -> [ { ... }, { ... } ]
     */
    private void handleSignerResponse(Response singleResp,
                                      ObjectMapper objectMapper,
                                      List<Map<String, Object>> signedList) throws Exception {

        String jsonBody = singleResp.readEntity(String.class);
        if (jsonBody == null || jsonBody.isBlank()) {
            return; // or throw, depending on your contract
        }

        JsonNode root = objectMapper.readTree(jsonBody);

        if (root.isArray()) {
            // MultiAdmin: List<Map<String,Object>>
            for (JsonNode node : root) {
                Map<String, Object> parsed = objectMapper.convertValue(
                        node,
                        new TypeReference<Map<String, Object>>() {}
                );
                signedList.add(parsed);
            }
        } else if (root.isObject()) {
            // FirstAdmin: single result object
            Map<String, Object> parsed = objectMapper.convertValue(
                    root,
                    new TypeReference<Map<String, Object>>() {}
            );
            signedList.add(parsed);
        } else {
            throw new BadRequestException("Unsupported signer response JSON shape: " + jsonBody);
        }
    }


    private Response commitChangeSets(List<ChangeSetRequest> changeSets) throws Exception {
        auth.users().requireManage();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        RealmModel realm = session.getContext().getRealm();
        List<ChangeSetRequest> filtered = new ArrayList<>(changeSets.stream()
                .collect(Collectors.toMap(
                        ChangeSetRequest::getChangeSetId,
                        Function.identity(),
                        (existing, replacement) -> existing
                ))
                .values());

        // Store batch changeSetIds so post-commit recalculation can skip batch-mates
        List<String> batchIds = filtered.stream()
                .map(ChangeSetRequest::getChangeSetId)
                .collect(Collectors.toList());
        session.setAttribute("batchAuthorityIds", batchIds);

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

        // Commit deferred policy changes AFTER all UserContext models have been signed.
        // This prevents the ORK threshold from changing mid-batch.
        @SuppressWarnings("unchecked")
        List<Object[]> deferredPolicyCommits = (List<Object[]>) session.getAttribute("deferredPolicyCommits", List.class);
        if (deferredPolicyCommits != null) {
            for (Object[] entry : deferredPolicyCommits) {
                org.tidecloak.base.iga.TideRequests.TideRoleRequests.commitRolePolicy(
                        session, (String) entry[0], entry[1], (String) entry[2]);
            }
        }

        return Response.ok("Change sets approved and committed").build();
    }

    private Response cancelChangeSets(List<ChangeSetRequest> changeSets){
            auth.users().requireManage();
            EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

            changeSets.forEach(changeSet -> {

                ChangeSetType type = changeSet.getType();

                List<?> mapping = BasicIGAUtils.fetchDraftRecordEntityByRequestId(em, type, changeSet.getChangeSetId());
                if (mapping != null && mapping.isEmpty()) {
                    ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(changeSet.getChangeSetId(), type));
                    if(changesetRequestEntity != null){
                        em.remove(changesetRequestEntity);
                        em.flush();
                    }
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

    @POST
    @Path("role-policy/{roleId}/init-cert")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response setRolePolicyInitCert(@PathParam("roleId") String roleId, Map<String, String> body) {
        auth.users().requireManage();

        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        TideRoleDraftEntity roleDraft;
        try {
            roleDraft = em.createNamedQuery("getRoleDraftByRoleId", TideRoleDraftEntity.class)
                    .setParameter("roleId", roleId)
                    .getSingleResult();
        } catch (NoResultException e) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity(Map.of("error", "No TideRoleDraftEntity found for roleId: " + roleId))
                    .build();
        }

        String initCert = body.get("initCert");
        if (initCert == null || initCert.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "initCert is required"))
                    .build();
        }

        roleDraft.setInitCert(initCert);

        String initCertSig = body.get("initCertSig");
        if (initCertSig != null && !initCertSig.isBlank()) {
            roleDraft.setInitCertSig(initCertSig);
        }

        em.flush();
        return Response.ok(Map.of("message", "initCert updated for role " + roleId)).build();
    }

    /**
     * Get a user's committed UserContext and its VVK signature for a given client.
     * Returns { accessProof, accessProofSig } from USER_CLIENT_ACCESS_PROOF.
     */
    @GET
    @Path("user-context/{userId}/{clientId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getUserContext(@PathParam("userId") String userId, @PathParam("clientId") String clientId) {
        auth.users().requireManage();

        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        UserEntity userEntity = em.find(UserEntity.class, userId);
        if (userEntity == null) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity(Map.of("error", "User not found: " + userId))
                    .build();
        }

        UserClientAccessProofEntity proof = em.find(
                UserClientAccessProofEntity.class,
                new UserClientAccessProofEntity.Key(userEntity, clientId)
        );

        if (proof == null) {
            return Response.ok(Map.of("accessProof", "", "accessProofSig", "")).build();
        }

        return Response.ok(Map.of(
                "accessProof", proof.getAccessProof() != null ? proof.getAccessProof() : "",
                "accessProofSig", proof.getAccessProofSig() != null ? proof.getAccessProofSig() : ""
        )).build();
    }

    /**
     * Resolve the affected user's committed UserContext + sig from a changeSetId.
     * Looks up the draft entity → user + role → client, then queries USER_CLIENT_ACCESS_PROOF directly.
     */
    @GET
    @Path("change-set/{changeSetId}/user-context")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getChangeSetUserContext(@PathParam("changeSetId") String changeSetId) {
        auth.users().requireManage();

        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        // Find the draft entity for this change set to get the affected user + role
        List<TideUserRoleMappingDraftEntity> drafts = em.createNamedQuery(
                        "GetUserRoleMappingDraftEntityByRequestId", TideUserRoleMappingDraftEntity.class)
                .setParameter("requestId", changeSetId)
                .getResultList();

        if (drafts.isEmpty()) {
            return Response.ok(Map.of("accessProof", "", "accessProofSig", "")).build();
        }

        TideUserRoleMappingDraftEntity draft = drafts.get(0);
        UserEntity user = draft.getUser();

        // Resolve clientId from the role
        RoleModel role = realm.getRoleById(draft.getRoleId());
        String clientId = (role != null && role.isClientRole())
                ? realm.getClientById(role.getContainerId()).getClientId()
                : null;

        if (clientId == null) {
            return Response.ok(Map.of("accessProof", "", "accessProofSig", "")).build();
        }

        // Go directly to committed user context
        UserClientAccessProofEntity committed = em.find(
                UserClientAccessProofEntity.class,
                new UserClientAccessProofEntity.Key(user, clientId)
        );

        if (committed == null) {
            return Response.ok(Map.of("accessProof", "", "accessProofSig", "")).build();
        }

        return Response.ok(Map.of(
                "accessProof", committed.getAccessProof() != null ? committed.getAccessProof() : "",
                "accessProofSig", committed.getAccessProofSig() != null ? committed.getAccessProofSig() : ""
        )).build();
    }

    /**
     * Enriches RequestedChanges with requestedBy info from the ChangesetRequestEntity.
     */
    private void enrichWithRequestedBy(EntityManager em, List<? extends RequestedChanges> changes) {
        for (RequestedChanges change : changes) {
            if (change.getDraftRecordId() != null) {
                try {
                    List<ChangesetRequestEntity> entities = em.createNamedQuery("getAllChangeRequestsByRecordId", ChangesetRequestEntity.class)
                            .setParameter("changesetRequestId", change.getDraftRecordId())
                            .getResultList();
                    if (!entities.isEmpty()) {
                        ChangesetRequestEntity cre = entities.get(0);
                        change.setRequestedBy(cre.getRequestedBy());
                        change.setRequestedByUsername(cre.getRequestedByUsername());

                        // Approval / rejection summary
                        List<AdminAuthorizationEntity> auths = cre.getAdminAuthorizations();
                        if (auths != null) {
                            List<String> approvers = new ArrayList<>();
                            List<String> deniers = new ArrayList<>();
                            for (AdminAuthorizationEntity auth : auths) {
                                String name = auth.getUsername() != null ? auth.getUsername() : auth.getUserId();
                                if (auth.getIsApproval()) {
                                    approvers.add(name);
                                } else {
                                    deniers.add(name);
                                }
                            }
                            change.setApprovalCount(approvers.size());
                            change.setRejectionCount(deniers.size());
                            change.setApprovedBy(approvers);
                            change.setDeniedBy(deniers);
                        }

                        // Comment count
                        try {
                            Long commentCount = em.createQuery(
                                    "SELECT COUNT(c) FROM ChangesetCommentEntity c WHERE c.changesetRequestId = :id", Long.class)
                                    .setParameter("id", change.getDraftRecordId())
                                    .getSingleResult();
                            change.setCommentCount(commentCount != null ? commentCount.intValue() : 0);
                        } catch (Exception ignored2) {
                            // Best effort
                        }
                    } else {
                        logger.warnf("enrichWithRequestedBy: No ChangesetRequestEntity found for draftId=%s", change.getDraftRecordId());
                    }
                } catch (Exception ignored) {
                    // Best effort
                }
            }
        }
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
