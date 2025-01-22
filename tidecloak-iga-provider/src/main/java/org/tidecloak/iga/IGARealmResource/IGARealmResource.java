package org.tidecloak.iga.IGARealmResource;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.persistence.NoResultException;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.midgard.Midgard;
import org.midgard.models.*;
import org.midgard.models.InitializerCertificateModel.InitializerCertifcate;
import org.midgard.models.RequestExtensions.UserContextSignRequest;
import org.midgard.models.UserContext.UserContext;
import org.tidecloak.iga.changesetprocessors.ChangeSetProcessorFactory;
import org.tidecloak.iga.changesetprocessors.models.ChangeSetRequest;
import org.tidecloak.iga.changesetprocessors.utils.TideEntityUtils;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.shared.enums.WorkflowType;
import org.tidecloak.iga.interfaces.ChangesetRequestAdapter;
import org.tidecloak.iga.interfaces.models.*;
import org.tidecloak.iga.utils.IGAUtils;
import org.tidecloak.jpa.entities.*;
import org.tidecloak.jpa.entities.drafting.*;
import org.tidecloak.shared.models.SecretKeys;

import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;

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

    // TODO: Enclave signing to be done here (each admin will push a button that hits this endpoint)
    // This current changes draftRecords to approve which marks the draft record ready to be commited(APPROVE IS NOT YET COMMITED)
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("change-set/sign")
    public Response signChangeset(ChangeSetRequest changeSet) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        var tideIdp = session.getContext().getRealm().getIdentityProviderByAlias("tide");

        // Fetch the draft record entity and proof details based on the change set type
        Object draftRecordEntity= IGAUtils.fetchDraftRecordEntity(em, changeSet.getType(), changeSet.getChangeSetId());
        List<AccessProofDetailEntity> proofDetails = IGAUtils.getAccessProofs(em, IGAUtils.getEntityId(draftRecordEntity));;

        if (draftRecordEntity == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Unsupported change set type").build();
        }

        try {
            ComponentModel componentModel = realm.getComponentsStream()
                    .filter(x -> "tide-vendor-key".equals(x.getProviderId()))  // Use .equals for string comparison
                    .findFirst()
                    .orElse(null);

            if(componentModel == null) {
                return buildResponse(400, "There is no tide-vendor-key component set up for this realm, " + realm.getName());
            }


            // Check if changeset is for adding a tide realm admin.
            MultivaluedHashMap<String, String> config = componentModel.getConfig();
            List<AuthorizerEntity> realmAuthorizers = em.createNamedQuery("getAuthorizerByProviderId", AuthorizerEntity.class)
                    .setParameter("ID", componentModel.getId()).getResultList();

            boolean isAssigningTideRealmAdminRole;
            if(draftRecordEntity instanceof TideUserRoleMappingDraftEntity){
                RoleModel tideRole = session.clients().getClientByClientId(realm, Constants.REALM_MANAGEMENT_CLIENT_ID).getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
                isAssigningTideRealmAdminRole = ((TideUserRoleMappingDraftEntity) draftRecordEntity).getRoleId().equals(tideRole.getId());
            } else {
                isAssigningTideRealmAdminRole = false;
            }

            if (realmAuthorizers.isEmpty()){
                throw new Exception("Authorizer not found for this realm.");
            }

            List<UserContext> userContexts = new ArrayList<>();
            proofDetails.forEach(p -> {
                userContexts.add(new UserContext(p.getProofDraft()));
            });

            RoleModel tideRole = session.clients().getClientByClientId(realm, Constants.REALM_MANAGEMENT_CLIENT_ID).getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
            RoleEntity role = em.getReference(RoleEntity.class, tideRole.getId());
            TideRoleDraftEntity tideRoleEntity = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class)
                    .setParameter("role", role).getSingleResult();

            InitializerCertifcate cert = InitializerCertifcate.FromString(tideRoleEntity.getInitCert());
            ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, changeSet.getChangeSetId());
            if (changesetRequestEntity == null){
                throw new Exception("No change-set request entity found with this recordId " + changeSet.getChangeSetId());
            }
            if (IGAUtils.isIGAEnabled(realm) && tideIdp != null) {
                if (isAssigningTideRealmAdminRole &&  realmAuthorizers.size() == 1 && realmAuthorizers.get(0).getType().equalsIgnoreCase("firstAdmin")) {
                    List<String> signatures = IGAUtils.signInitialTideAdmin(config, userContexts.toArray(new UserContext[0]), cert, realmAuthorizers.get(0), changesetRequestEntity);
                    tideRoleEntity.setInitCertSig(signatures.get(0));
                    for(int i = 0; i < userContexts.size(); i++){
                        proofDetails.get(i).setSignature(signatures.get(i + 1));
                    }
                    em.flush();
                }
            }

            ObjectMapper objectMapper = new ObjectMapper();
            if (!realmAuthorizers.get(0).getType().equalsIgnoreCase("firstAdmin") && IGAUtils.isIGAEnabled(realm) && tideIdp != null) {
                //String changeRequestString = objectMapper.writeValueAsString(changeSetRequests);
                String redirectUrl = tideIdp.getConfig().get("changeSetEndpoint");
                String redirectUrlSig = tideIdp.getConfig().get("changeSetURLSig");
                URI redirectURI = new URI(redirectUrl);

                UserSessionModel userSession = session.sessions().getUserSession(realm, auth.adminAuth().getToken().getSessionId());
                String port = redirectURI.getPort() == -1 ? "" : ":" + redirectURI.getPort();
                String voucherURL = redirectURI.getScheme() + "://" + redirectURI.getHost() + port + "/realms/" +
                session.getContext().getRealm().getName() + "/tidevouchers/fromUserSession?sessionId=" +userSession.getId();

                URI uri = Midgard.CreateURL(
                        auth.adminAuth().getToken().getSessionId(),
                        redirectURI.toString(),//userSession.getNote("redirectUri"),
                        redirectUrlSig,
                        tideIdp.getConfig().get("homeORKurl"),
                        config.getFirst("clientId"),
                        config.getFirst("gVRK"),
                        config.getFirst("gVRKCertificate"),
                        realm.isRegistrationAllowed(),
                        Boolean.valueOf(tideIdp.getConfig().get("backupOn")),
                        tideIdp.getConfig().get("LogoURL"),
                        tideIdp.getConfig().get("ImageURL"),
                        "approval",
                        tideIdp.getConfig().get("settingsSig"),
                        voucherURL, //voucherURL,
                        ""
                );

                Map<String, String> response = new HashMap<>();
                response.put("message", "Opening Enclave to request approval.");
                response.put("uri", String.valueOf(uri));
                response.put("changeSetRequests", changesetRequestEntity.getDraftRequest());
                response.put("requiresApprovalPopup", "true");
                response.put("expiry", String.valueOf(changesetRequestEntity.getTimestamp() + 2628000)); // month expiry

                return buildResponse(200, objectMapper.writeValueAsString(response));
            }

            // Update the draft status
            IGAUtils.updateDraftStatus(changeSet.getType(), changeSet.getActionType(), draftRecordEntity);

            em.flush();

            Map<String, String> response = new HashMap<>();
            response.put("message", "Change set signed successfully.");
            response.put("uri", "");
            response.put("changeSetRequests", "");
            response.put("requiresApprovalPopup", "false");

            return buildResponse(200, objectMapper.writeValueAsString(response));
        }
        catch (NumberFormatException e) {
            throw new RuntimeException("Environment variables THRESHOLD_T or THRESHOLD_N is invalid: " + e.getMessage());
        }
        catch (JsonProcessingException e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Error processing JSON " + e.getMessage()).build();
        } catch (Exception ex) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(ex.getMessage()).build();

        }
    }

    @GET
    @Path("change-set/users/requests")
    public Response getRequestedChangesForUsers() {
        if(!IGAUtils.isIGAEnabled(realm)){
            return Response.ok().entity(new ArrayList<>()).build();
        }
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<RequestedChanges> changes = new ArrayList<>(processUserRoleMappings(em));
        return Response.ok(changes).build();
    }

    @GET
    @Path("change-set/roles/requests")
    public Response getRequestedChanges() {
        if(!IGAUtils.isIGAEnabled(realm)){
            return Response.ok().entity(new ArrayList<>()).build();
        }
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<RequestedChanges> requestedChangesList = new ArrayList<>(processRoleMappings(em));
        requestedChangesList.addAll(processCompositeRoleMappings(em));
        return Response.ok(requestedChangesList).build();
    }

    @GET
    @Path("change-set/clients/requests")
    public Response getRequestedChangesForClients() {
        if(!IGAUtils.isIGAEnabled(realm)){
            return Response.ok().entity(new ArrayList<>()).build();
        }
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<RequestedChanges> changes = new ArrayList<>(processClientDraftRecords(em));
        return Response.ok(changes).build();
    }

    private List<RequestedChanges> processClientDraftRecords(EntityManager em) {
        List<RequestedChanges> changes = new ArrayList<>();
        List<TideClientDraftEntity> mappings = em.createNamedQuery("getClientFullScopeStatusDraftThatDoesNotHaveStatus", TideClientDraftEntity.class)
                .setParameter("status", DraftStatus.ACTIVE)
                .setParameter("status2", DraftStatus.NULL)
                .getResultList();

        for (TideClientDraftEntity c : mappings) {
            em.lock(c, LockModeType.PESSIMISTIC_WRITE); // Lock the entity to prevent concurrent modifications
            ClientModel client = realm.getClientById(c.getClient().getId());
            if (client == null) {
                continue;
            }

            List<AccessProofDetailEntity> proofs = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                    .setParameter("recordId", c.getId())
                    .getResultList();


            RequestedChanges requestChange = new RequestedChanges("",ChangeSetType.CLIENT_FULLSCOPE, RequestType.CLIENT, client.getClientId(), realm.getName(), c.getAction(), c.getId(), new ArrayList<>(), DraftStatus.DRAFT, DraftStatus.NULL);
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
                TideClientDraftEntity tideClientDraftEntity = em.find(TideClientDraftEntity.class, p.getRecordId());
                ClientModel client = realm.getClientById(p.getClientId());
                RequestedChanges requestChange = new RequestedChanges("New Client Created",ChangeSetType.CLIENT, RequestType.CLIENT, client.getClientId(), realm.getName(), ActionType.CREATE, p.getRecordId(), new ArrayList<>(), tideClientDraftEntity.getDraftStatus(), DraftStatus.NULL);
                requestChange.getUserRecord().add(new RequestChangesUserRecord("Default User Context for all USERS", p.getId(), client.getClientId(), p.getProofDraft()));
                changes.add(requestChange);
            });
        }
        return changes;
    }

    private List<RequestedChanges> processUserRoleMappings(EntityManager em) {
        List<RequestedChanges> changes = new ArrayList<>();

        // Get all pending changes
        List<TideUserRoleMappingDraftEntity> mappings = em.createNamedQuery("getAllPendingUserRoleMappingsByRealm", TideUserRoleMappingDraftEntity.class)
                .setParameter("draftStatus", DraftStatus.ACTIVE)
                .setParameter("deleteStatus", DraftStatus.ACTIVE)
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
                    .setParameter("recordId", m.getId())
                    .getResultList();
            boolean isDeleteRequest = m.getDraftStatus() == DraftStatus.ACTIVE && (m.getDeleteStatus() != DraftStatus.ACTIVE || m.getDeleteStatus() != null);
            String actionDescription = isDeleteRequest ? "Unassigning Role from User" : "Granting Role to User";
            ActionType action = isDeleteRequest ? ActionType.DELETE : ActionType.CREATE;
            RequestedChanges requestChange = new RoleChangeRequest(realm.getRoleById(m.getRoleId()).getName(), actionDescription, ChangeSetType.USER_ROLE, RequestType.USER, clientId, realm.getName(), action, m.getId(), new ArrayList<>(), m.getDraftStatus(), m.getDeleteStatus());
            proofs.forEach(p -> {
                em.lock(p, LockModeType.PESSIMISTIC_WRITE);
                requestChange.getUserRecord().add(new RequestChangesUserRecord(p.getUser().getUsername(), p.getId(), realm.getClientById(p.getClientId()).getClientId(), p.getProofDraft()));
            });
            changes.add(requestChange);
        }
        return changes;
    }

    private List<RequestedChanges> processCompositeRoleMappings(EntityManager em) {
        List<RequestedChanges> changes = new ArrayList<>();
        List<TideCompositeRoleMappingDraftEntity> mappings = em.createNamedQuery("getAllCompositeRoleMappingsByRealm", TideCompositeRoleMappingDraftEntity.class)
                .setParameter("draftStatus", DraftStatus.ACTIVE)
                .setParameter("deleteStatus", DraftStatus.ACTIVE)
                .setParameter("realmId", realm.getId())
                .getResultList();

        for (TideCompositeRoleMappingDraftEntity m : mappings) {
            if (m.getComposite() == null) {
                continue;
            }
            List<AccessProofDetailEntity> proofs = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                    .setParameter("recordId", m.getId())
                    .setLockMode(LockModeType.PESSIMISTIC_WRITE)
                    .getResultList();
            boolean isDeleteRequest = m.getDraftStatus() == DraftStatus.ACTIVE && (m.getDeleteStatus() != DraftStatus.ACTIVE || m.getDeleteStatus() != null);
            String actionDescription = isDeleteRequest ? "Removing Role from Composite Role": "Granting Role to Composite Role";
            ActionType action = isDeleteRequest ? ActionType.DELETE : ActionType.CREATE;

            String clientId = m.getComposite().isClientRole() ? realm.getClientById(m.getComposite().getClientId()).getClientId() : "" ;
            RequestedChanges requestChange = new CompositeRoleChangeRequest(m.getChildRole().getName(), m.getComposite().getName(), actionDescription, ChangeSetType.COMPOSITE_ROLE, RequestType.ROLE, clientId, realm.getName(), action, m.getId(), new ArrayList<>(), m.getDraftStatus(), m.getDeleteStatus());

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

    private List<RequestedChanges> processRoleMappings(EntityManager em) {
        List<RequestedChanges> changes = new ArrayList<>();
        List<TideRoleDraftEntity> mappings = em.createNamedQuery("getAllRoleDraft", TideRoleDraftEntity.class)
                .setParameter("draftStatus", DraftStatus.ACTIVE)
                .setParameter("deleteStatus", DraftStatus.ACTIVE)
                .setParameter("realmId", realm.getId())
                .getResultList();

        for (TideRoleDraftEntity m : mappings) {
            String clientId = m.getRole().isClientRole() ? m.getRole().getClientId() : null;
            List<AccessProofDetailEntity> proofs = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                    .setParameter("recordId", m.getId())
                    .setLockMode(LockModeType.PESSIMISTIC_WRITE)
                    .getResultList();
            String action = "Deleting Role from Client";
            RequestedChanges requestChange = new RoleChangeRequest(m.getRole().getName(), action, ChangeSetType.ROLE, RequestType.ROLE, clientId, realm.getName(), ActionType.DELETE, m.getId(), new ArrayList<>(), m.getDraftStatus(), m.getDeleteStatus());
            proofs.forEach(p -> requestChange.getUserRecord().add(new RequestChangesUserRecord(p.getUser().getUsername(), p.getId(), realm.getClientById(p.getClientId()).getClientId(), p.getProofDraft())));

            changes.add(requestChange);
        }
        return changes;
    }

    // TODO: implement request to vvk ork to be signed, this retreives infomoration from ADMIN UI when the "COMMIT" button is clicked to processes all "user draft changeset details" and update any affected drafts
    // Need to retrieve the final proofs back for the commited draft record and store it in the database
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("change-set/commit")
    public Response commitChangeSet(ChangeSetRequest change) throws Exception {

        try{
            //TODO: switch to new authorizer
            EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
            List<AuthorizerEntity> realmAuthorizers = null;
            ComponentModel componentModel = realm.getComponentsStream()
                    .filter(x -> "tide-vendor-key".equals(x.getProviderId()))  // Use .equals for string comparison
                    .findFirst()
                    .orElse(null);

            var tideIdp = session.getContext().getRealm().getIdentityProviderByAlias("tide");
            ActionType action = change.getActionType();
            ChangeSetType type = change.getType();


            List<?> mappings = getMappings(em, change, type, action);
            if (mappings == null || mappings.isEmpty()) {
                return Response.status(Response.Status.NOT_FOUND).entity("Change request was not found.").build();
            }
            Object mapping = mappings.get(0);
            em.lock(mapping, LockModeType.PESSIMISTIC_WRITE); // Lock the entity to prevent concurrent modifications

            if (tideIdp != null && componentModel != null){
                realmAuthorizers = em.createNamedQuery("getAuthorizerByProviderId", AuthorizerEntity.class)
                        .setParameter("ID", componentModel.getId()).getResultList();

                if (realmAuthorizers.isEmpty()){
                    throw new Exception("Authorizer not found for this realm.");
                }

                if ( !realmAuthorizers.get(0).getType().equalsIgnoreCase("firstAdmin")) {

                    // Fetch the draft record entity and proof details based on the change set type
                    Object draftRecordEntity= IGAUtils.fetchDraftRecordEntity(em, change.getType(), change.getChangeSetId());
                    List<AccessProofDetailEntity> proofDetails = IGAUtils.getAccessProofs(em, IGAUtils.getEntityId(draftRecordEntity));;

                    List<UserContext> userContexts = new ArrayList<>();
                    proofDetails.forEach(p -> {
                        userContexts.add(new UserContext(p.getProofDraft()));
                    });
                    ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, change.getChangeSetId());
                    if (changesetRequestEntity == null){
                        throw new Exception("No change-set request entity found with this recordId " + change.getChangeSetId());
                    }

                    // Check if changeset is for adding a tide realm admin.
                    MultivaluedHashMap<String, String> config = componentModel.getConfig();

                    RoleModel tideRole = session.clients().getClientByClientId(realm, Constants.REALM_MANAGEMENT_CLIENT_ID).getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
                    RoleEntity role = em.getReference(RoleEntity.class, tideRole.getId());
                    TideRoleDraftEntity tideRoleEntity = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class)
                            .setParameter("role", role).getSingleResult();

                    InitializerCertifcate cert = InitializerCertifcate.FromString(tideRoleEntity.getInitCert());

                    UserContextSignRequest req = new UserContextSignRequest("Admin:1");

                    req.SetDraft(Base64.getDecoder().decode(changesetRequestEntity.getDraftRequest()));
                    req.SetUserContexts(userContexts.toArray(new UserContext[0]));
                    req.SetCustomExpiry(changesetRequestEntity.getTimestamp() + 2628000); // expiry in 1 month
                    AdminAuthorizerBuilder authorizerBuilder = new AdminAuthorizerBuilder();
                    authorizerBuilder.AddInitCert(cert);
                    authorizerBuilder.AddInitCertSignature(tideRoleEntity.getInitCertSig());

                    changesetRequestEntity.getAdminAuthorizations().forEach(auth -> {
                        authorizerBuilder.AddAdminAuthorization(AdminAuthorization.FromString(auth));
                    });

                    int threshold = Integer.parseInt(System.getenv("THRESHOLD_T"));
                    int max = Integer.parseInt(System.getenv("THRESHOLD_N"));

                    if ( threshold == 0 || max == 0){
                        throw new RuntimeException("Env variables not set: THRESHOLD_T=" + threshold + ", THRESHOLD_N=" + max);
                    }

                    String currentSecretKeys = config.getFirst("clientSecret");
                    ObjectMapper objectMapper = new ObjectMapper();
                    SecretKeys secretKeys = objectMapper.readValue(currentSecretKeys, SecretKeys.class);

                    SignRequestSettingsMidgard settings = new SignRequestSettingsMidgard();
                    settings.VVKId = config.getFirst("vvkId");
                    settings.HomeOrkUrl = config.getFirst("systemHomeOrk");
                    settings.PayerPublicKey = config.getFirst("payerPublic");
                    settings.ObfuscatedVendorPublicKey = config.getFirst("obfGVVK");
                    settings.VendorRotatingPrivateKey = secretKeys.activeVrk;
                    settings.Threshold_T = threshold;
                    settings.Threshold_N = max;

                    authorizerBuilder.AddAuthorizationToSignRequest(req);

                    if(isTideRealmRoleAssignment(mapping)) {
                        RoleInitializerCertificateDraftEntity roleInitCert = getDraftRoleInitCert(session, change.getChangeSetId());
                        if(roleInitCert == null) {
                            throw new Exception("Role Init Cert draft not found for changeSet, " + change.getChangeSetId());
                        }
                        req.SetInitializationCertificate(InitializerCertifcate.FromString(roleInitCert.getInitCert()));
                        SignatureResponse response = Midgard.SignModel(settings, req);
                        for ( int i = 0; i < userContexts.size(); i++){
                            proofDetails.get(i).setSignature(response.Signatures[i + 1]);
                        }
                        commitRoleInitCert(session, change.getChangeSetId(), response.Signatures[0]);
                    } else {
                        SignatureResponse response = Midgard.SignModel(settings, req);

                        for ( int i = 0; i < userContexts.size(); i++){
                            proofDetails.get(i).setSignature(response.Signatures[i]);
                        }
                    }

                }
            }

            ChangeSetProcessorFactory processorFactory = new ChangeSetProcessorFactory(); // Initialize the processor factory
            processorFactory.getProcessor(type).executeWorkflow(session, mapping, em, WorkflowType.COMMIT, null, null);

            if (type.equals(ChangeSetType.USER_ROLE) && realmAuthorizers != null){
                RoleModel role = realm.getRoleById(((TideUserRoleMappingDraftEntity) mapping).getRoleId());
                if (role.getName().equalsIgnoreCase(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN)){
                    realmAuthorizers.get(0).setType("multiAdmin");
                }
            }

            em.flush(); // Persist changes to the database
            // Return success message after approving the change sets
            return Response.ok("Change sets approved").build();

        } catch(Exception e) {
            return buildResponse(500, "There was an error commiting this change set request. " + e.getMessage());

        }

    }

    private List<?> getMappings(EntityManager em, ChangeSetRequest change, ChangeSetType type, ActionType action) {
        return switch (type) {
            case USER_ROLE -> getUserRoleMappings(em, change, action);
            case GROUP, USER_GROUP_MEMBERSHIP, GROUP_ROLE -> null;
            case COMPOSITE_ROLE, DEFAULT_ROLES -> getCompositeRoleMappings(em, change, action);
            case ROLE -> getRoleMappings(em, change, action);
            case USER -> getUserMappings(em, change, action);
            case CLIENT_FULLSCOPE -> getClientMappings(em, change, action);
            case CLIENT -> getClientEntity(em, change);
            default -> Collections.emptyList();
        };
    }

    // Helper methods for retrieving specific mappings
    private List<?> getUserRoleMappings(EntityManager em, ChangeSetRequest change, ActionType action) {
        String queryName = action == ActionType.CREATE ? "getUserRoleMappingsByStatusAndRealmAndRecordId" : "getUserRoleMappingsByDeleteStatusAndRealmAndRecordId";
        return em.createNamedQuery(queryName, TideUserRoleMappingDraftEntity.class)
                .setParameter(action == ActionType.CREATE ? "draftStatus" : "deleteStatus", DraftStatus.APPROVED)
                .setParameter("changesetId", change.getChangeSetId())
                .setParameter("realmId", realm.getId())
                .getResultList();
    }

    private List<?> getCompositeRoleMappings(EntityManager em, ChangeSetRequest change, ActionType action) {
        String queryName = action == ActionType.CREATE ? "getAllCompositeRoleMappingsByStatusAndRealmAndRecordId" : "getAllCompositeRoleMappingsByDeletionStatusAndRealmAndRecordId";
        return em.createNamedQuery(queryName, TideCompositeRoleMappingDraftEntity.class)
                .setParameter(action == ActionType.CREATE ? "draftStatus" : "deleteStatus", DraftStatus.APPROVED)
                .setParameter("changesetId", change.getChangeSetId())
                .setParameter("realmId", realm.getId())
                .getResultList();
    }

    private List<?> getRoleMappings(EntityManager em, ChangeSetRequest change, ActionType action) {
        return em.createNamedQuery("getRoleDraftByRoleAndDeleteStatus", TideRoleDraftEntity.class)
                .setParameter("deleteStatus", DraftStatus.APPROVED)
                .setParameter("changesetId", change.getChangeSetId())
                .getResultList();
    }

    private List<?> getUserMappings(EntityManager em, ChangeSetRequest change, ActionType action) {
        return em.createNamedQuery("getTideUserDraftEntityByDraftStatusAndId", TideUserDraftEntity.class)
                .setParameter("draftStatus", DraftStatus.APPROVED)
                .setParameter("changesetId", change.getChangeSetId())
                .getResultList();
    }

    private List<?> getClientMappings(EntityManager em, ChangeSetRequest change, ActionType action) {
        String queryName = action == ActionType.CREATE ? "getClientFullScopeStatusDraftByIdAndFullScopeEnabled" : "getClientFullScopeStatusDraftByIdAndFullScopeDisabled";
        return em.createNamedQuery(queryName, TideClientDraftEntity.class)
                .setParameter(action == ActionType.CREATE ? "fullScopeEnabled" : "fullScopeDisabled", DraftStatus.APPROVED)
                .setParameter("changesetId", change.getChangeSetId())
                .getResultList();
    }

    private List<?> getClientEntity(EntityManager em, ChangeSetRequest change) {
        return em.createNamedQuery("getClientDraftById", TideClientDraftEntity.class)
                .setParameter("changesetId", change.getChangeSetId())
                .getResultList();
    }


    private List<String> getProofDetails(EntityManager em, String recordId) {
        return em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                .setParameter("recordId", recordId)
                .getResultStream()
                .map(AccessProofDetailEntity::getProofDraft)
                .collect(Collectors.toList());
    }

    private Response buildResponse(int status, String message) {
        return Response.status(status)
                .header("Access-Control-Allow-Origin", "*")
                .entity(message)
                .type(MediaType.TEXT_PLAIN)
                .build();
    }

    private boolean isTideRealmRoleAssignment(Object mapping){
        if ( mapping instanceof  TideUserRoleMappingDraftEntity tideUserRoleMappingDraftEntity){
            RoleModel roleModel = realm.getRoleById(tideUserRoleMappingDraftEntity.getRoleId());
            return roleModel.getName().equalsIgnoreCase(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
        }
        return false;
    }

}
