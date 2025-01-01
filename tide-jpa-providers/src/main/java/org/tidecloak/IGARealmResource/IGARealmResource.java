package org.tidecloak.IGARealmResource;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
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
import org.midgard.Serialization.JsonSorter;
import org.midgard.models.*;
import org.midgard.models.InitializerCertificateModel.InitializerCertifcate;
import org.midgard.models.RequestExtensions.UserContextSignRequest;
import org.midgard.models.UserContext.UserContext;
import org.tidecloak.enums.ActionType;
import org.tidecloak.interfaces.ChangeSetType;
import org.tidecloak.enums.DraftStatus;
import org.tidecloak.interfaces.*;
import org.tidecloak.interfaces.TidecloakChangeSetRequest.TidecloakUserContextRequest;
import org.tidecloak.jpa.entities.*;
import org.tidecloak.jpa.entities.drafting.*;
import org.tidecloak.jpa.models.TideClientAdapter;
import org.tidecloak.jpa.utils.IGAUtils;
import org.tidecloak.jpa.utils.TideAuthzProofUtil;
import org.tidecloak.jpa.utils.TideRolesUtil;

import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;

import static org.tidecloak.TideRequests.TideRoleRequests.tideRealmAdminRole;
import static org.tidecloak.jpa.models.ChangesetRequestAdapter.getChangesetRequestEntity;
import static org.tidecloak.jpa.utils.IGAUtils.*;

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
        if(!isIGAEnabled(realm)){
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
        if(!isIGAEnabled(realm)){
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
        if(!isIGAEnabled(realm)){
            return Response.ok().entity(new ArrayList<>()).build();
        }
        auth.users().requireQuery(); // Ensure the user has the necessary permissions

        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        RoleModel parentRole = realm.getRoleById(parentId);
        RoleModel childRole = realm.getRoleById(childId);

        try{
            TideCompositeRoleMappingDraftEntity entity = em.createNamedQuery("getCompositeRoleMappingDraft", TideCompositeRoleMappingDraftEntity.class)
                    .setParameter("composite", TideRolesUtil.toRoleEntity(parentRole, em))
                    .setParameter("childRole", TideRolesUtil.toRoleEntity(childRole, em))
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
    public Response signChangeset(DraftChangeSetRequest changeSet) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        var tideIdp = session.getContext().getRealm().getIdentityProviderByAlias("tide");

        // Fetch the draft record entity and proof details based on the change set type
        Object draftRecordEntity= IGAUtils.fetchDraftRecordEntity(em, changeSet.getType(), changeSet.getChangeSetId());
        List<AccessProofDetailEntity> proofDetails = getAccessProofs(em, getEntityId(draftRecordEntity));;

        if (draftRecordEntity == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Unsupported change set type").build();
        }

        try {
            // TODO: send stuff to be signed by admin\s, have a check to see if this request was the last signature needed and update draft records to "APPROVE" status
            // TODO: currently on signed by VRK, NO MULTI ADMINS YET!!!
            // update from "DRAFT" to "PENDING" if its the first signature.
            // leave as "PENDING" if still needing more signatures
            // Process the draft record entity
            String draftRecord = processDraftRecord(draftRecordEntity);
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

            boolean isAssigningTideAdminRole;
            if(draftRecordEntity instanceof TideUserRoleMappingDraftEntity){
                RoleModel role = session.clients().getClientByClientId(realm, Constants.REALM_MANAGEMENT_CLIENT_ID).getRole(tideRealmAdminRole);
                isAssigningTideAdminRole = ((TideUserRoleMappingDraftEntity) draftRecordEntity).getRoleId().equals(role.getId()) && realmAuthorizers.size() == 1;
            } else {
                isAssigningTideAdminRole = false;
            }

            if (realmAuthorizers.isEmpty()){
                throw new Exception("Authorizer not found for this realm.");
            }

            List<UserContext> userContexts = new ArrayList<>();
            proofDetails.forEach(p -> {
                userContexts.add(new UserContext(p.getProofDraft()));
            });

            RoleModel tideRole = session.clients().getClientByClientId(realm, Constants.REALM_MANAGEMENT_CLIENT_ID).getRole(tideRealmAdminRole);
            RoleEntity role = em.getReference(RoleEntity.class, tideRole.getId());
            TideRoleDraftEntity tideRoleEntity = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class)
                    .setParameter("role", role).getSingleResult();

            InitializerCertifcate cert = InitializerCertifcate.FromString(tideRoleEntity.getInitCert());
            ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, changeSet.getChangeSetId());
            if (changesetRequestEntity == null){
                throw new Exception("No change-set request entity found with this recordId " + changeSet.getChangeSetId());
            }
            if (isIGAEnabled(realm) && tideIdp != null){
                if (isAssigningTideAdminRole) {
                    if (!realmAuthorizers.get(0).getType().equalsIgnoreCase("firstAdmin")){
                        throw new Exception("Invalid realm authorizer type for initial tide admin role assignment. Found " + realmAuthorizers.get(0).getType());
                    }

                    List<String> signatures = signInitialTideAdmin(config, userContexts.toArray(new UserContext[0]), cert, realmAuthorizers.get(0), changesetRequestEntity);
                    tideRoleEntity.setInitCertSig(signatures.get(0));
                    for(int i = 0; i < userContexts.size(); i++){
                        proofDetails.get(i).setSignature(signatures.get(i + 1));
                    }
                    em.flush();
                }
            }

            ObjectMapper objectMapper = new ObjectMapper();
            if (!realmAuthorizers.get(0).getType().equalsIgnoreCase("firstAdmin") && isIGAEnabled(realm) && tideIdp != null) {
                //String changeRequestString = objectMapper.writeValueAsString(changeSetRequests);
                String redirectUrl = "";
                String redirectUrlSig = "";
                if(changeSet.getType().equals(ChangeSetType.USER_ROLE)){
                    redirectUrl = tideIdp.getConfig().get("changeSetUsersEndpoint");
                    redirectUrlSig = tideIdp.getConfig().get("changeSetUsersURLSig");
                }else if (changeSet.getType().equals(ChangeSetType.COMPOSITE_ROLE) || changeSet.getType().equals(ChangeSetType.ROLE)){
                    redirectUrl = tideIdp.getConfig().get("changeSetRolesEndpoint");
                    redirectUrlSig = tideIdp.getConfig().get("changeSetRolesURLSig");
                }else if (changeSet.getType().equals(ChangeSetType.CLIENT)){
                    redirectUrl = tideIdp.getConfig().get("changeSetClientsEndpoint");
                    redirectUrlSig = tideIdp.getConfig().get("changeSetClientsURLSig");
                }
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
            updateDraftStatus(changeSet.getType(), changeSet.getActionType(), draftRecordEntity);

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

    public static String constructIdToken(String jsonString, Set<String> allowedKeys, String client) throws Exception {
        // Create a copy to avoid modifying the original node
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode proofDraftNode = objectMapper.readTree(jsonString);

        // Ensure the JsonNode is an ObjectNode
        if (!(proofDraftNode instanceof ObjectNode)) {
            throw new IllegalArgumentException("Expected an ObjectNode as input");
        }

        ObjectNode filteredNode = ((ObjectNode) proofDraftNode).deepCopy();

        // Collect keys to remove to avoid ConcurrentModificationException
        List<String> keysToRemove = new ArrayList<>();
        Iterator<String> fieldNames = filteredNode.fieldNames();
        while (fieldNames.hasNext()) {
            String fieldName = fieldNames.next();
            if (!allowedKeys.contains(fieldName)) {
                keysToRemove.add(fieldName);
            }
        }

        // Remove the collected keys
        for (String key : keysToRemove) {
            filteredNode.remove(key);
        }

        // Add the new key-value pair
        filteredNode.put("aud", client);

        // Return the filtered and sorted JsonNode as a string
        return objectMapper.writeValueAsString(JsonSorter.parseAndSortArrays(filteredNode));
    }

    private String processDraftRecord(Object draftRecordEntity) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        JsonNode tempNode = objectMapper.valueToTree(draftRecordEntity);
        JsonNode sortedTemp = JsonSorter.parseAndSortArrays(tempNode);
        return objectMapper.writeValueAsString(sortedTemp);
    }

    @GET
    @Path("change-set/users/requests")
    public Response getRequestedChangesForUsers() {
        if(!isIGAEnabled(realm)){
            return Response.ok().entity(new ArrayList<>()).build();
        }
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<RequestedChanges> changes = new ArrayList<>(processUserRoleMappings(em));
        return Response.ok(changes).build();
    }

    @GET
    @Path("change-set/roles/requests")
    public Response getRequestedChanges() {
        if(!isIGAEnabled(realm)){
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
        if(!isIGAEnabled(realm)){
            return Response.ok().entity(new ArrayList<>()).build();
        }
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<RequestedChanges> changes = new ArrayList<>(processClientDraftRecords(em));
        return Response.ok(changes).build();
    }

    private List<RequestedChanges> processClientDraftRecords(EntityManager em) {
        List<RequestedChanges> changes = new ArrayList<>();
        List<TideClientFullScopeStatusDraftEntity> mappings = em.createNamedQuery("getClientFullScopeStatusDraftThatDoesNotHaveStatus", TideClientFullScopeStatusDraftEntity.class)
                .setParameter("status", DraftStatus.ACTIVE)
                .setParameter("status2", DraftStatus.NULL)
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


            RequestedChanges requestChange = new RequestedChanges("",ChangeSetType.CLIENT, RequestType.CLIENT, client.getClientId(), realm.getName(), c.getAction(), c.getId(), new ArrayList<>(), DraftStatus.DRAFT, DraftStatus.NULL);
            proofs.forEach(p -> {
                em.lock(p, LockModeType.PESSIMISTIC_WRITE);
                requestChange.getUserRecord().add(new RequestChangesUserRecord(p.getUser().getUsername(), p.getId(), c.getClient().getClientId(), p.getProofDraft()));
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
            if (m.getComposite() == null || !m.getComposite().isClientRole()) {
                continue;
            }
            List<AccessProofDetailEntity> proofs = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                    .setParameter("recordId", m.getId())
                    .setLockMode(LockModeType.PESSIMISTIC_WRITE)
                    .getResultList();
            boolean isDeleteRequest = m.getDraftStatus() == DraftStatus.ACTIVE && (m.getDeleteStatus() != DraftStatus.ACTIVE || m.getDeleteStatus() != null);
            String actionDescription = isDeleteRequest ? "Removing Role from Composite Role": "Granting Role to Composite Role";
            ActionType action = isDeleteRequest ? ActionType.DELETE : ActionType.CREATE;

            RequestedChanges requestChange = new CompositeRoleChangeRequest(m.getChildRole().getName(), m.getComposite().getName(), actionDescription, ChangeSetType.COMPOSITE_ROLE, RequestType.ROLE, realm.getClientById(m.getComposite().getClientId()).getClientId(), realm.getName(), action, m.getId(), new ArrayList<>(), m.getDraftStatus(), m.getDeleteStatus());
            proofs.forEach(p -> requestChange.getUserRecord().add(new RequestChangesUserRecord(p.getUser().getUsername(), p.getId(), realm.getClientById(p.getClientId()).getClientId(), p.getProofDraft())));
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
    public Response commitChangeSet(DraftChangeSetRequest change) throws Exception {

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
                    List<AccessProofDetailEntity> proofDetails = getAccessProofs(em, getEntityId(draftRecordEntity));;

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

                    RoleModel tideRole = session.clients().getClientByClientId(realm, Constants.REALM_MANAGEMENT_CLIENT_ID).getRole(tideRealmAdminRole);
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
                    SignatureResponse response = Midgard.SignModel(settings, req);

                    for ( int i = 0; i < userContexts.size(); i++){
                        proofDetails.get(i).setSignature(response.Signatures[i]);
                    }
                }
            }


            switch (type) {
                case USER_ROLE -> processUserRoleMapping(change, (TideUserRoleMappingDraftEntity) mapping, em, action);
                case COMPOSITE_ROLE -> processCompositeRoleMapping(change, (TideCompositeRoleMappingDraftEntity) mapping, em, action);
                case ROLE -> processRole(change, (TideRoleDraftEntity) mapping, em, action);
                case USER -> processUser(change, (TideUserDraftEntity) mapping, em, action);
                case CLIENT -> processClient(change, (TideClientFullScopeStatusDraftEntity) mapping, em, action);
            }

            if (type.equals(ChangeSetType.USER_ROLE) && realmAuthorizers != null){
                RoleModel role = realm.getRoleById(((TideUserRoleMappingDraftEntity) mapping).getRoleId());
                if (role.getName().equalsIgnoreCase(tideRealmAdminRole)){
                    realmAuthorizers.get(0).setType("test");

                }
            }

            ChangesetRequestEntity changesetRequestEntity = getChangesetRequestEntity(session, change.getChangeSetId());
            em.remove(changesetRequestEntity);
            em.flush(); // Persist changes to the database
            // Return success message after approving the change sets
            return Response.ok("Change sets approved").build();

        } catch(Exception e) {
            return buildResponse(500, "There was an error commiting this change set request. " + e.getMessage());

        }

    }

    private List<?> getMappings(EntityManager em, DraftChangeSetRequest change, ChangeSetType type, ActionType action) {
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
    private List<?> getUserRoleMappings(EntityManager em, DraftChangeSetRequest change, ActionType action) {
        String queryName = action == ActionType.CREATE ? "getUserRoleMappingsByStatusAndRealmAndRecordId" : "getUserRoleMappingsByDeleteStatusAndRealmAndRecordId";
        return em.createNamedQuery(queryName, TideUserRoleMappingDraftEntity.class)
                .setParameter(action == ActionType.CREATE ? "draftStatus" : "deleteStatus", DraftStatus.APPROVED)
                .setParameter("changesetId", change.getChangeSetId())
                .setParameter("realmId", realm.getId())
                .getResultList();
    }

    private List<?> getCompositeRoleMappings(EntityManager em, DraftChangeSetRequest change, ActionType action) {
        String queryName = action == ActionType.CREATE ? "getAllCompositeRoleMappingsByStatusAndRealmAndRecordId" : "getAllCompositeRoleMappingsByDeletionStatusAndRealmAndRecordId";
        return em.createNamedQuery(queryName, TideCompositeRoleMappingDraftEntity.class)
                .setParameter(action == ActionType.CREATE ? "draftStatus" : "deleteStatus", DraftStatus.APPROVED)
                .setParameter("changesetId", change.getChangeSetId())
                .setParameter("realmId", realm.getId())
                .getResultList();
    }

    private List<?> getRoleMappings(EntityManager em, DraftChangeSetRequest change, ActionType action) {
        return em.createNamedQuery("getRoleDraftByRoleAndDeleteStatus", TideRoleDraftEntity.class)
                .setParameter("deleteStatus", DraftStatus.APPROVED)
                .setParameter("changesetId", change.getChangeSetId())
                .getResultList();
    }

    private List<?> getUserMappings(EntityManager em, DraftChangeSetRequest change, ActionType action) {
        return em.createNamedQuery("getTideUserDraftEntityByDraftStatusAndId", TideUserDraftEntity.class)
                .setParameter("draftStatus", DraftStatus.APPROVED)
                .setParameter("changesetId", change.getChangeSetId())
                .getResultList();
    }

    private List<?> getClientMappings(EntityManager em, DraftChangeSetRequest change, ActionType action) {
        String queryName = action == ActionType.CREATE ? "getClientFullScopeStatusDraftByIdAndFullScopeEnabled" : "getClientFullScopeStatusDraftByIdAndFullScopeDisabled";
        return em.createNamedQuery(queryName, TideClientFullScopeStatusDraftEntity.class)
                .setParameter(action == ActionType.CREATE ? "fullScopeEnabled" : "fullScopeDisabled", DraftStatus.APPROVED)
                .setParameter("changesetId", change.getChangeSetId())
                .getResultList();
    }

    private void processUserRoleMapping(DraftChangeSetRequest change, TideUserRoleMappingDraftEntity mapping, EntityManager em, ActionType action) throws Exception {
        RoleModel role = realm.getRoleById(mapping.getRoleId());
        if (role == null) return;
        TideAuthzProofUtil util = new TideAuthzProofUtil(session, realm, em);

        // ONLY COMMIT AFTER CHECKING THE APPROVALS WERE VALID !
        if (action == ActionType.CREATE) {
            if(mapping.getDraftStatus() != DraftStatus.APPROVED){
                throw new RuntimeException("Draft record has not been approved by all admins.");
            }
            commitDraft(mapping, em);
        } else if (action == ActionType.DELETE) {
            if(mapping.getDeleteStatus() != DraftStatus.APPROVED){
                throw new RuntimeException("Deletion has not been approved by all admins.");
            }
            commitDraft(mapping, em, DraftStatus.ACTIVE, true);
            UserModel user = session.users().getUserById(realm, mapping.getUser().getId());
            user.deleteRoleMapping(role);
        }
        util.checkAndUpdateProofRecords(change, mapping, ChangeSetType.USER_ROLE, em);
    }

    private void processCompositeRoleMapping(DraftChangeSetRequest change, TideCompositeRoleMappingDraftEntity mapping, EntityManager em, ActionType action) throws Exception {
        //TODO: SEND THE TIDECLOAKDRAFTCHANGESET request to orks here
        TideAuthzProofUtil util = new TideAuthzProofUtil(session, realm, em);
        TidecloakUserContextRequest tidecloakUserContextRequest = util.generateTidecloakDraftChangeSetRequest(em, change.getChangeSetId(), mapping, mapping.getTimestamp());
        // send TidecloakDraftChangeSetRequest to get signed by VVK
        // get the proofs back in the order it was send (desc order by timestamp) and store it in the database HERE!

        // ONLY COMMIT AFTER CHECKING THE APPROVALS WERE VALID !
        if (action == ActionType.CREATE) {
            if(mapping.getDraftStatus() != DraftStatus.APPROVED){
                throw new RuntimeException("Draft record has not been approved by all admins.");
            }
            commitDraft(mapping, em);
        } else if (action == ActionType.DELETE) {
            if(mapping.getDeleteStatus() != DraftStatus.APPROVED){
                throw new RuntimeException("Deletion has not been approved by all admins.");
            }
            commitDraft(mapping, em, DraftStatus.ACTIVE, true);
            RoleModel composite = realm.getRoleById(mapping.getComposite().getId());
            RoleModel child = realm.getRoleById(mapping.getChildRole().getId());
            composite.removeCompositeRole(child);
        }

        util.checkAndUpdateProofRecords(change, mapping, ChangeSetType.COMPOSITE_ROLE, em);
    }

    private void processRole(DraftChangeSetRequest change, TideRoleDraftEntity mapping, EntityManager em, ActionType action) throws Exception {
        //TODO: SEND THE TIDECLOAKDRAFTCHANGESET request to orks here
        TideAuthzProofUtil util = new TideAuthzProofUtil(session, realm, em);
        TidecloakUserContextRequest tidecloakUserContextRequest = util.generateTidecloakDraftChangeSetRequest(em, change.getChangeSetId(), mapping, mapping.getTimestamp());
        // send TidecloakDraftChangeSetRequest to get signed by VVK
        // get the proofs back in the order it was send (desc order by timestamp) and store it in the database HERE!

        // ONLY COMMIT AFTER CHECKING THE APPROVALS WERE VALID !
        if (action == ActionType.DELETE) {
            if(mapping.getDeleteStatus() != DraftStatus.APPROVED){
                throw new RuntimeException("Deletion has not been approved by all admins.");
            }
            commitDraft(mapping, em, DraftStatus.ACTIVE, true);
            RoleModel role = realm.getRoleById(mapping.getRole().getId());
            realm.removeRole(role);
            cleanupRoleRecords(em, mapping);
        }

        util.checkAndUpdateProofRecords(change, mapping, ChangeSetType.ROLE, em);
    }

    private void processUser(DraftChangeSetRequest change, TideUserDraftEntity mapping, EntityManager em, ActionType action) throws Exception {
        //TODO: SEND THE TIDECLOAKDRAFTCHANGESET request to orks here
        TideAuthzProofUtil util = new TideAuthzProofUtil(session, realm, em);
        TidecloakUserContextRequest tidecloakUserContextRequest = util.generateTidecloakDraftChangeSetRequest(em, change.getChangeSetId(), mapping, mapping.getTimestamp());
        // send TidecloakDraftChangeSetRequest to get signed by VVK
        // get the proofs back in the order it was send (desc order by timestamp) and store it in the database HERE!

        // ONLY COMMIT AFTER CHECKING THE APPROVALS WERE VALID !
        if (action == ActionType.CREATE) {
            if(mapping.getDraftStatus() != DraftStatus.APPROVED){
                throw new RuntimeException("Draft record has not been approved by all admins.");
            }
            commitDraft(mapping, em);
            em.remove(mapping);
            em.flush();
        }

        util.checkAndUpdateProofRecords(change, mapping, ChangeSetType.USER, em);
    }

    private void processClient(DraftChangeSetRequest change, TideClientFullScopeStatusDraftEntity mapping, EntityManager em, ActionType action) throws Exception {
        //TODO: SEND THE TIDECLOAKDRAFTCHANGESET request to orks here
        TideAuthzProofUtil util = new TideAuthzProofUtil(session, realm, em);
        TidecloakUserContextRequest tidecloakUserContextRequest = util.generateTidecloakDraftChangeSetRequest(em, change.getChangeSetId(), mapping, mapping.getTimestamp());
        // send TidecloakDraftChangeSetRequest to get signed by VVK
        // get the proofs back in the order it was send (desc order by timestamp) and store it in the database HERE!

        // ONLY COMMIT AFTER CHECKING THE APPROVALS WERE VALID !
        if (action == ActionType.CREATE) {
            if(mapping.getFullScopeEnabled() != DraftStatus.APPROVED){
                throw new RuntimeException("Draft record has not been approved by all admins.");
            }
            commitDraft(mapping, em);
            ClientModel client = new TideClientAdapter(realm, em, session, mapping.getClient());
            client.setFullScopeAllowed(true);
        } else if (action == ActionType.DELETE) {
            if(mapping.getFullScopeDisabled() != DraftStatus.APPROVED){
                throw new RuntimeException("Draft record has not been approved by all admins.");
            }
            commitDraft(mapping, em, DraftStatus.ACTIVE, true);
            ClientModel client = new TideClientAdapter(realm, em, session, mapping.getClient());
            client.setFullScopeAllowed(false);
        }

        util.checkAndUpdateProofRecords(change, mapping, ChangeSetType.CLIENT, em);
    }

    private void commitDraft(Object mapping, EntityManager em) {
        commitDraft(mapping, em, DraftStatus.ACTIVE, false);
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
                ((TideClientFullScopeStatusDraftEntity) mapping).setFullScopeEnabled(DraftStatus.NULL);
                ((TideClientFullScopeStatusDraftEntity) mapping).setFullScopeDisabled(status);
            } else {
                ((TideClientFullScopeStatusDraftEntity) mapping).setFullScopeDisabled(DraftStatus.NULL);
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

//    private void checkAndUpdateProofRecords(DraftChangeSetRequest change, Object entity, ChangeSetType changeSetType, EntityManager em) throws NoSuchAlgorithmException, JsonProcessingException {
//        List<ClientModel> affectedClients = getAffectedClients(entity, changeSetType, em);
//        TideAuthzProofUtil tideAuthzProofUtil = new TideAuthzProofUtil(session, realm, em);
//
//        for (ClientModel client : affectedClients) {
//            // Get all draft access proof details for this client.
//            List<AccessProofDetailEntity> proofDetails = getProofDetailsByChangeSetType(em, client, entity, changeSetType);
//            for (AccessProofDetailEntity proofDetail : proofDetails) {
//                em.lock(proofDetail, LockModeType.PESSIMISTIC_WRITE);
//                UserEntity user = proofDetail.getUser();
//                UserModel userModel = session.users().getUserById(realm, user.getId());
//                UserModel wrappedUser = TideRolesUtil.wrapUserModel(userModel, session, realm);
//
//                // Check if this draft access proof is for this draft change request
//                if (Objects.equals(proofDetail.getRecordId(), change.getChangeSetId())) {
//
//                    // If this draft change request is a user role grant, we need to check if it is granting a composite role to the user.
//                    if(change.getType() == ChangeSetType.USER_ROLE) {
//                        TideUserRoleMappingDraftEntity record = em.find(TideUserRoleMappingDraftEntity.class, proofDetail.getRecordId());
//                        RoleEntity roleEntity = em.find(RoleEntity.class, record.getRoleId());
//                        List<TideCompositeRoleMappingDraftEntity> compositeRoleDrafts = em.createNamedQuery("getCompositeEntityByParent", TideCompositeRoleMappingDraftEntity.class)
//                                .setParameter("composite", roleEntity)
//                                .getResultList();
//                        TideAuthzProofUtil util = new TideAuthzProofUtil(session, realm, em);
//
//                        // Check all composite role records and see if that have been commited.
//                        for(TideCompositeRoleMappingDraftEntity draft : compositeRoleDrafts) {
//                            // If a record is still draft or pending, need to create a new access proof detail draft for this user and client.
//                            if(draft.getDraftStatus() != DraftStatus.ACTIVE){
//                                Set<RoleModel> roles = new HashSet<>();
//                                roles.add(realm.getRoleById(draft.getChildRole().getId()));
//                                // Create new drafts
//                                util.generateAndSaveProofDraft(client, wrappedUser, roles, draft.getId(), ChangeSetType.COMPOSITE_ROLE, ActionType.CREATE, true);
//                            }
//                        }
//                    }
//                    em.remove(proofDetail); // this proof is commited, so now we remove
//                    em.flush();
//                    continue;
//                }
//
//                Set<RoleModel> roleSet = new HashSet<>();
//                ActionType actionType = null;
//
//                if (entity instanceof TideUserRoleMappingDraftEntity) {
//                    roleSet.add(TideRolesUtil.wrapRoleModel(realm.getRoleById(((TideUserRoleMappingDraftEntity) entity).getRoleId()), session, realm));
//                    actionType = ((TideUserRoleMappingDraftEntity) entity).getAction();
//                } else if (entity instanceof TideCompositeRoleMappingDraftEntity) {
//                    roleSet.add(TideRolesUtil.wrapRoleModel(realm.getRoleById(((TideCompositeRoleMappingDraftEntity) entity).getChildRole().getId()), session, realm));
//                    actionType = ((TideCompositeRoleMappingDraftEntity) entity).getAction();
//                } else if (entity instanceof TideRoleDraftEntity) {
//                    roleSet.add(TideRolesUtil.wrapRoleModel(realm.getRoleById(((TideRoleDraftEntity) entity).getRole().getId()), session, realm));
//                    actionType = ((TideRoleDraftEntity) entity).getAction();
//                } else if (entity instanceof TideClientFullScopeStatusDraftEntity) {
//                    Set<RoleModel> activeRoles;
//                    if (((TideClientFullScopeStatusDraftEntity) entity).getAction() == ActionType.DELETE) {
//                        activeRoles = TideRolesUtil.getDeepUserRoleMappings(wrappedUser, session, realm, em, DraftStatus.ACTIVE).stream().filter(role -> {
//                            if (role.isClientRole()) {
//                                return !Objects.equals(((ClientModel) role.getContainer()).getClientId(), client.getClientId());
//                            }
//                            return true;
//                        }).collect(Collectors.toSet());
//                    } else {
//                        activeRoles = new HashSet<>(TideRolesUtil.getDeepUserRoleMappings(wrappedUser, session, realm, em, DraftStatus.ACTIVE));
//                    }
//                    roleSet.addAll(activeRoles);
//                }
//
//                if (proofDetail.getChangesetType() == ChangeSetType.USER_ROLE) {
//                    TideUserRoleMappingDraftEntity draftEntity = em.find(TideUserRoleMappingDraftEntity.class, proofDetail.getRecordId());
//                    handleUserRoleMappingDraft(draftEntity, proofDetail, change, roleSet, actionType, client, tideAuthzProofUtil, wrappedUser, em);
//                }
//                else if (proofDetail.getChangesetType() == ChangeSetType.COMPOSITE_ROLE) {
//                    TideCompositeRoleMappingDraftEntity draftEntity = em.find(TideCompositeRoleMappingDraftEntity.class, proofDetail.getRecordId());
//                    handleCompositeRoleMappingDraft(draftEntity, proofDetail, change, roleSet, client, tideAuthzProofUtil, wrappedUser, em);
//                }
//                else if (proofDetail.getChangesetType() == ChangeSetType.ROLE) {
//                    TideRoleDraftEntity draftEntity = em.find(TideRoleDraftEntity.class, proofDetail.getRecordId());
//                    handleRoleDraft(draftEntity, proofDetail, change, roleSet, client, tideAuthzProofUtil, wrappedUser, em);
//                }
//                else if (proofDetail.getChangesetType() == ChangeSetType.USER) {
//                    TideUserDraftEntity draftEntity = em.find(TideUserDraftEntity.class, proofDetail.getRecordId());
//                    handleUserDraft(draftEntity, proofDetail, client, tideAuthzProofUtil, wrappedUser);
//                }
//                else if (proofDetail.getChangesetType() == ChangeSetType.CLIENT) {
//                    TideClientFullScopeStatusDraftEntity draftEntity = em.find(TideClientFullScopeStatusDraftEntity.class, proofDetail.getRecordId());
//                    handleClientDraft(draftEntity, proofDetail, change, client, tideAuthzProofUtil, wrappedUser, em);
//                }
//            }
//        }
//    }


//    private List<ClientModel> getAffectedClients(Object entity, ChangeSetType changeSetType, EntityManager em) {
//        if (changeSetType == ChangeSetType.CLIENT) {
//            List<ClientModel> client = new ArrayList<>();
//            ClientEntity clientEntity = ((TideClientFullScopeStatusDraftEntity) entity).getClient();
//            client.add(realm.getClientById(clientEntity.getId()));
//            return client;
//        }
//
//        List<ClientModel> affectedClients = realm.getClientsStream()
//                .map(client -> new TideClientAdapter(realm, em, session, em.getReference(ClientEntity.class, client.getId())))
//                .filter(clientModel -> {
//                    ClientEntity clientEntity = em.find(ClientEntity.class, clientModel.getId());
//                    List<TideClientFullScopeStatusDraftEntity> scopeDraft = em.createNamedQuery("getClientFullScopeStatusByFullScopeEnabledStatus", TideClientFullScopeStatusDraftEntity.class)
//                            .setParameter("client", clientEntity)
//                            .setParameter("fullScopeEnabled", DraftStatus.DRAFT)
//                            .getResultList();
//                    return clientModel.isFullScopeAllowed() || (scopeDraft != null && !scopeDraft.isEmpty());
//                }).distinct().collect(Collectors.toList());
//
//        if (changeSetType == ChangeSetType.USER_ROLE) {
//            RoleModel roleModel = realm.getRoleById(((TideUserRoleMappingDraftEntity) entity).getRoleId());
//            affectedClients.add(realm.getClientById(roleModel.getContainerId()));
//        } else if (changeSetType == ChangeSetType.COMPOSITE_ROLE) {
//            RoleModel role = realm.getRoleById(((TideCompositeRoleMappingDraftEntity) entity).getChildRole().getId());
//            affectedClients.add(realm.getClientById(role.getContainerId()));
//        } else if (changeSetType == ChangeSetType.ROLE) {
//            RoleModel role = realm.getRoleById(((TideRoleDraftEntity) entity).getRole().getId());
//            affectedClients.add(realm.getClientById(role.getContainerId()));
//        }
//
//        return affectedClients.stream().distinct().collect(Collectors.toList());
//    }
//
//    private List<AccessProofDetailEntity> getProofDetailsByChangeSetType(EntityManager em, ClientModel client, Object entity, ChangeSetType changeSetType) throws JsonProcessingException {
//        if (changeSetType == ChangeSetType.USER_ROLE) {
//            UserEntity user = ((TideUserRoleMappingDraftEntity) entity).getUser();
//            return em.createNamedQuery("getProofDetailsForUserByClient", AccessProofDetailEntity.class)
//                    .setParameter("user", user)
//                    .setParameter("clientId", client.getId())
//                    .getResultList();
//        } else if (changeSetType == ChangeSetType.USER) {
//            UserEntity user = ((TideUserDraftEntity) entity).getUser();
//            return em.createNamedQuery("getProofDetailsForUserByClient", AccessProofDetailEntity.class)
//                    .setParameter("user", user)
//                    .setParameter("clientId", client.getId())
//                    .getResultList();
//        } else if (changeSetType == ChangeSetType.COMPOSITE_ROLE || changeSetType == ChangeSetType.ROLE) {
//            return em.createNamedQuery("getProofDetailsByClient", AccessProofDetailEntity.class)
//                    .setParameter("clientId", client.getId())
//                    .getResultList();
//        }
//        else if (changeSetType == ChangeSetType.CLIENT) {
//            if (((TideClientFullScopeStatusDraftEntity) entity).getAction() == ActionType.CREATE) {
//                String clientId = ((TideClientFullScopeStatusDraftEntity) entity).getClient().getId();
//
//                List<String> recordIds = em.createNamedQuery("getProofDetailsByClient", AccessProofDetailEntity.class)
//                        .setParameter("clientId", clientId)
//                        .getResultStream().map(AccessProofDetailEntity::getRecordId).distinct().toList();
//
//                List<AccessProofDetailEntity> proofs = new ArrayList<>();
//                proofs.addAll(em.createNamedQuery("getProofDetailsForDraftByChangeSetType", AccessProofDetailEntity.class)
//                        .setParameter("changesetType", ChangeSetType.USER_ROLE)
//                        .getResultStream().filter(proof -> !recordIds.contains(proof.getRecordId())).toList());
//
//                proofs.addAll(em.createNamedQuery("getProofDetailsForDraftByChangeSetType", AccessProofDetailEntity.class)
//                        .setParameter("changesetType", ChangeSetType.COMPOSITE_ROLE)
//                        .getResultStream().filter(proof -> !recordIds.contains(proof.getRecordId())).toList());
//
//                proofs.addAll(em.createNamedQuery("getProofDetailsForDraftByChangeSetType", AccessProofDetailEntity.class)
//                        .setParameter("changesetType", ChangeSetType.ROLE)
//                        .getResultStream().filter(proof -> !recordIds.contains(proof.getRecordId())).toList());
//
//                List<AccessProofDetailEntity> uniqueProofs = proofs.stream()
//                        .collect(Collectors.collectingAndThen(
//                                Collectors.toMap(
//                                        AccessProofDetailEntity::getUser,
//                                        e -> e,
//                                        (e1, e2) -> e1 // If there are duplicates, keep the first one
//                                ),
//                                map -> new ArrayList<>(map.values())
//                        ));
//                for (AccessProofDetailEntity t : uniqueProofs) {
//
//                    if (t.getChangesetType() == ChangeSetType.USER_ROLE) {
//                        UserModel user = session.users().getUserById(realm, t.getUser().getId());
//                        TideAuthzProofUtil util = new TideAuthzProofUtil(session, realm, em);
//
//                        TideUserRoleMappingDraftEntity role = em.find(TideUserRoleMappingDraftEntity.class, t.getRecordId());
//                        Set<RoleModel> roles = new HashSet<>();
//                        RoleModel roleModel = realm.getRoleById(role.getRoleId());
//                        if (roleModel != null){
//                            roles.add(roleModel);
//                        }
//
//                        util.generateAndSaveProofDraft(client, user, roles, t.getRecordId(), ChangeSetType.USER_ROLE, ActionType.CREATE, true);
//
//                    } else if ( t.getChangesetType() == ChangeSetType.COMPOSITE_ROLE) {
//                        UserModel user = session.users().getUserById(realm, t.getUser().getId());
//                        TideAuthzProofUtil util = new TideAuthzProofUtil(session, realm, em);
//
//                        TideCompositeRoleMappingDraftEntity role = em.find(TideCompositeRoleMappingDraftEntity.class, t.getRecordId());
//                        Set<RoleModel> roles = new HashSet<>();
//                        RoleModel roleModel = realm.getRoleById(role.getChildRole().getId());
//                        if (roleModel != null){
//                            roles.add(roleModel);
//                        }
//                        util.generateAndSaveProofDraft(client, user, roles, t.getRecordId(), ChangeSetType.COMPOSITE_ROLE, ActionType.CREATE, true);
//
//                    } else if ( t.getChangesetType() == ChangeSetType.ROLE) {
//                        UserModel user = session.users().getUserById(realm, t.getUser().getId());
//                        TideAuthzProofUtil util = new TideAuthzProofUtil(session, realm, em);
//
//                        TideRoleDraftEntity role = em.find(TideRoleDraftEntity.class, t.getRecordId());
//                        Set<RoleModel> roles = new HashSet<>();
//                        RoleModel roleModel = realm.getRoleById(role.getRole().getId());
//                        if (roleModel != null){
//                            roles.add(roleModel);
//                        }
//                        util.generateAndSaveProofDraft(client, user, roles, t.getRecordId(), ChangeSetType.ROLE, ActionType.DELETE, true);
//
//                    }
//
//                }
//            }
//            return em.createNamedQuery("getProofDetailsByClient", AccessProofDetailEntity.class)
//                    .setParameter("clientId", client.getId())
//                    .getResultList();
//        }
//        return Collections.emptyList();
//    }
//
//    private void handleUserRoleMappingDraft(TideUserRoleMappingDraftEntity draftEntity, AccessProofDetailEntity proofDetail, DraftChangeSetRequest change, Set<RoleModel> roles, ActionType actionType, ClientModel client, TideAuthzProofUtil tideAuthzProofUtil, UserModel wrappedUser, EntityManager em) throws JsonProcessingException, NoSuchAlgorithmException {
//        if (draftEntity == null || (draftEntity.getDraftStatus() == DraftStatus.ACTIVE && draftEntity.getDeleteStatus() == null)) {
//            return;
//        }
//        if (change.getActionType() == ActionType.DELETE) {
//            if (change.getType() == ChangeSetType.CLIENT) {
//                boolean hasCommittedRole = ((TideUserAdapter) wrappedUser).getRoleMappingsStreamByStatusAndAction(DraftStatus.ACTIVE, ActionType.CREATE)
//                        .anyMatch(x -> x.isClientRole() && Objects.equals(x.getContainer().getId(), client.getId()));
//
//                if (hasCommittedRole) {
//                    String proof = proofDetail.getProofDraft();
//
//                    TideUserRoleMappingDraftEntity userRoleDraft = em.find(TideUserRoleMappingDraftEntity.class, proofDetail.getRecordId());
//                    if (userRoleDraft != null) {
//                        RoleModel role = realm.getRoleById(userRoleDraft.getRoleId());
//                        if(role.isClientRole() && Objects.equals(role.getContainer().getId(), client.getId())) {
//                            em.remove(proofDetail);
//                            em.flush();
//                            return;
//                        }
//                        roles.add(realm.getRoleById(userRoleDraft.getRoleId()));
//                    }
//                    AccessDetails accessDetails = tideAuthzProofUtil.getAccessToRemove(client, roles, true);
//                    String updatedProof = tideAuthzProofUtil.removeAccessFromToken(proof, accessDetails);
//                    String newProof = tideAuthzProofUtil.removeAudienceFromToken(updatedProof);
//                    proofDetail.setProofDraft(newProof);
//                } else {
//                    // Remove the proof detail if this no longer affects the client
//                    em.remove(proofDetail);
//                    em.flush();
//                }
//                return;
//            }
//
//            if (draftEntity.getDraftStatus() == DraftStatus.ACTIVE && draftEntity.getDeleteStatus() != null) {
//                draftEntity.setDeleteStatus(DraftStatus.DRAFT);
//            } else if (draftEntity.getDraftStatus() == DraftStatus.APPROVED) {
//                draftEntity.setDraftStatus(DraftStatus.DRAFT);
//            }
//            String proof = proofDetail.getProofDraft();
//            AccessDetails accessDetails = tideAuthzProofUtil.getAccessToRemove(client, roles, client.isFullScopeAllowed());
//            String updatedProof = tideAuthzProofUtil.removeAccessFromToken(proof, accessDetails);
//            String newProof = tideAuthzProofUtil.removeAudienceFromToken(updatedProof);
//            proofDetail.setProofDraft(newProof);
//            return;
//        }
//
//        String proof = proofDetail.getProofDraft();
//        if (draftEntity.getDraftStatus() == DraftStatus.ACTIVE && draftEntity.getDeleteStatus() != null) {
//            draftEntity.setDeleteStatus(DraftStatus.DRAFT);
//            String updatedProof = tideAuthzProofUtil.updateDraftProofDetails(client, wrappedUser, proof, roles, actionType, true);
//            var ogRole = new HashSet<RoleModel>();
//            ogRole.add(realm.getRoleById(draftEntity.getRoleId()));
//            AccessDetails accessDetails = tideAuthzProofUtil.getAccessToRemove(client, ogRole, client.isFullScopeAllowed());
//            String newProof = tideAuthzProofUtil.removeAccessFromToken(updatedProof, accessDetails);
//            proofDetail.setProofDraft(newProof);
//        } else if (draftEntity.getDraftStatus() == DraftStatus.APPROVED) {
//            roles.add(realm.getRoleById(draftEntity.getRoleId()));
//            draftEntity.setDraftStatus(DraftStatus.DRAFT);
//            String updatedProof = tideAuthzProofUtil.updateDraftProofDetails(client, wrappedUser, proof, roles, actionType, true);
//            proofDetail.setProofDraft(updatedProof);
//        }
//
//    }
//
//    private void handleCompositeRoleMappingDraft(TideCompositeRoleMappingDraftEntity draftEntity, AccessProofDetailEntity proofDetail, DraftChangeSetRequest change, Set<RoleModel> roles, ClientModel client, TideAuthzProofUtil tideAuthzProofUtil, UserModel wrappedUser, EntityManager em) throws JsonProcessingException, NoSuchAlgorithmException {
//        if (draftEntity == null || (draftEntity.getDraftStatus() == DraftStatus.ACTIVE && draftEntity.getDeleteStatus() == null)) {
//            return;
//        }
//
//        if (change.getActionType() == ActionType.DELETE) {
//            if (change.getType() == ChangeSetType.CLIENT) {
//                String proof = proofDetail.getProofDraft();
//                TideCompositeRoleMappingDraftEntity compositeRoleMappingDraft = em.find(TideCompositeRoleMappingDraftEntity.class, proofDetail.getRecordId());
//                if (compositeRoleMappingDraft != null) {
//                    RoleModel childRole = realm.getRoleById(compositeRoleMappingDraft.getChildRole().getId());
//                    RoleModel compositeRole = realm.getRoleById(compositeRoleMappingDraft.getComposite().getId());
//                    if (childRole.isClientRole() && !Objects.equals(childRole.getContainerId(), client.getId())) {
//                        roles.add(childRole);
//                    }
//                    if (compositeRole.isClientRole() && !Objects.equals(compositeRole.getContainerId(), client.getId())) {
//                        roles.add(compositeRole);
//                    }
//                }
//
//                Set<RoleModel> rolesToAdd = ((TideUserAdapter) wrappedUser).getRoleMappingsStreamByStatusAndAction(DraftStatus.ACTIVE, ActionType.CREATE).filter(r -> r.isClientRole() && Objects.equals(r.getContainerId(), client.getId())).collect(Collectors.toSet());
//                String updatedProof = tideAuthzProofUtil.updateDraftProofDetails(client, wrappedUser, proof, rolesToAdd, draftEntity.getAction(), true);
//                AccessDetails accessDetails = tideAuthzProofUtil.getAccessToRemove(client, roles, true);
//                String cleanedProof = tideAuthzProofUtil.removeAccessFromToken(updatedProof, accessDetails);
//                String newProof = tideAuthzProofUtil.removeAudienceFromToken(cleanedProof);
//                proofDetail.setProofDraft(newProof);
//                return;
//            }
//
//            if (draftEntity.getDraftStatus() == DraftStatus.ACTIVE && draftEntity.getDeleteStatus() != null) {
//                draftEntity.setDeleteStatus(DraftStatus.DRAFT);
//            } else if (draftEntity.getDraftStatus() == DraftStatus.APPROVED) {
//                draftEntity.setDraftStatus(DraftStatus.DRAFT);
//            }
//            String proof = proofDetail.getProofDraft();
//            AccessDetails accessDetails = tideAuthzProofUtil.getAccessToRemove(client, roles, client.isFullScopeAllowed());
//            String updatedProof = tideAuthzProofUtil.removeAccessFromToken(proof, accessDetails);
//            String newProof = tideAuthzProofUtil.removeAudienceFromToken(updatedProof);
//            proofDetail.setProofDraft(newProof);
//            return;
//        }
//
//        String proof = proofDetail.getProofDraft();
//        if (draftEntity.getDraftStatus() == DraftStatus.ACTIVE && draftEntity.getDeleteStatus() != null) {
//            draftEntity.setDeleteStatus(DraftStatus.DRAFT);
//            String updatedProof = tideAuthzProofUtil.updateDraftProofDetails(client, wrappedUser, proof, roles, ActionType.CREATE, true);
//            var ogRole = new HashSet<RoleModel>();
//            ogRole.add(realm.getRoleById(draftEntity.getChildRole().getId()));
//            AccessDetails accessDetails = tideAuthzProofUtil.getAccessToRemove(client, ogRole, client.isFullScopeAllowed());
//            String newProof = tideAuthzProofUtil.removeAccessFromToken(updatedProof, accessDetails);
//            proofDetail.setProofDraft(newProof);
//        } else if (draftEntity.getDraftStatus() == DraftStatus.APPROVED) {
//            draftEntity.setDraftStatus(DraftStatus.DRAFT);
//            String updatedProof = tideAuthzProofUtil.updateDraftProofDetails(client, wrappedUser, proof, roles, draftEntity.getAction(), true);
//            proofDetail.setProofDraft(updatedProof);
//        }
//    }
//
//    private void handleRoleDraft(TideRoleDraftEntity draftEntity, AccessProofDetailEntity proofDetail, DraftChangeSetRequest change, Set<RoleModel> roles, ClientModel client, TideAuthzProofUtil tideAuthzProofUtil, UserModel wrappedUser, EntityManager em) throws JsonProcessingException, NoSuchAlgorithmException {
//        if (draftEntity == null || (draftEntity.getDraftStatus() == DraftStatus.ACTIVE && draftEntity.getDeleteStatus() == null)) {
//            return;
//        }
//
//        if (change.getActionType() == ActionType.DELETE) {
//            if (change.getType() == ChangeSetType.CLIENT) {
//                String proof = proofDetail.getProofDraft();
//                TideCompositeRoleMappingDraftEntity compositeRoleMappingDraft = em.find(TideCompositeRoleMappingDraftEntity.class, proofDetail.getRecordId());
//                if (compositeRoleMappingDraft != null) {
//                    RoleModel childRole = realm.getRoleById(compositeRoleMappingDraft.getChildRole().getId());
//                    RoleModel compositeRole = realm.getRoleById(compositeRoleMappingDraft.getComposite().getId());
//                    if (childRole.isClientRole() && !Objects.equals(childRole.getContainerId(), client.getId())) {
//                        roles.add(childRole);
//                    }
//                    if (compositeRole.isClientRole() && !Objects.equals(compositeRole.getContainerId(), client.getId())) {
//                        roles.add(compositeRole);
//                    }
//                }
//                AccessDetails accessDetails = tideAuthzProofUtil.getAccessToRemove(client, roles, true);
//                String updatedProof = tideAuthzProofUtil.removeAccessFromToken(proof, accessDetails);
//                String newProof = tideAuthzProofUtil.removeAudienceFromToken(updatedProof);
//                proofDetail.setProofDraft(newProof);
//                return;
//            }
//            if (draftEntity.getDraftStatus() == DraftStatus.ACTIVE && draftEntity.getDeleteStatus() != null) {
//                draftEntity.setDeleteStatus(DraftStatus.DRAFT);
//            } else if (draftEntity.getDraftStatus() == DraftStatus.APPROVED) {
//                draftEntity.setDraftStatus(DraftStatus.DRAFT);
//            }
//            String proof = proofDetail.getProofDraft();
//            AccessDetails accessDetails = tideAuthzProofUtil.getAccessToRemove(client, roles, client.isFullScopeAllowed());
//            String updatedProof = tideAuthzProofUtil.removeAccessFromToken(proof, accessDetails);
//            String newProof = tideAuthzProofUtil.removeAudienceFromToken(updatedProof);
//            proofDetail.setProofDraft(newProof);
//            return;
//        }
//        String proof = proofDetail.getProofDraft();
//        if (draftEntity.getDraftStatus() == DraftStatus.ACTIVE && draftEntity.getDeleteStatus() != null) {
//            draftEntity.setDeleteStatus(DraftStatus.DRAFT);
//            String updatedProof = tideAuthzProofUtil.updateDraftProofDetails(client, wrappedUser, proof, roles, ActionType.CREATE, true);
//            var ogRole = new HashSet<RoleModel>();
//            ogRole.add(realm.getRoleById(draftEntity.getRole().getId()));
//            AccessDetails accessDetails = tideAuthzProofUtil.getAccessToRemove(client, ogRole, client.isFullScopeAllowed());
//            String newProof = tideAuthzProofUtil.removeAccessFromToken(updatedProof, accessDetails);
//            proofDetail.setProofDraft(newProof);
//        } else if (draftEntity.getDraftStatus() == DraftStatus.APPROVED) {
//            draftEntity.setDraftStatus(DraftStatus.DRAFT);
//            String updatedProof = tideAuthzProofUtil.updateDraftProofDetails(client, wrappedUser, proof, roles, draftEntity.getAction(), true);
//            proofDetail.setProofDraft(updatedProof);
//        }
//
//    }
//
//    private void handleUserDraft(TideUserDraftEntity draftEntity, AccessProofDetailEntity proofDetail, ClientModel client, TideAuthzProofUtil tideAuthzProofUtil, UserModel wrappedUser) throws JsonProcessingException, NoSuchAlgorithmException {
//        if (draftEntity == null || (draftEntity.getDraftStatus() == DraftStatus.ACTIVE && draftEntity.getDeleteStatus() == null)) {
//            return;
//        }
//        if (draftEntity.getDraftStatus() == DraftStatus.ACTIVE && draftEntity.getDeleteStatus() != null) {
//            draftEntity.setDeleteStatus(DraftStatus.DRAFT);
//        } else if (draftEntity.getDraftStatus() == DraftStatus.APPROVED) {
//            draftEntity.setDraftStatus(DraftStatus.DRAFT);
//        }
//        String proof = proofDetail.getProofDraft();
//        Set<RoleModel> roleSet = new HashSet<>();
//        String updatedProof = tideAuthzProofUtil.updateDraftProofDetails(client, wrappedUser, proof, roleSet, draftEntity.getAction(), client.isFullScopeAllowed());
//        proofDetail.setProofDraft(updatedProof);
//    }
//
//    private void handleClientDraft(TideClientFullScopeStatusDraftEntity draftEntity, AccessProofDetailEntity proofDetail, DraftChangeSetRequest change, ClientModel client, TideAuthzProofUtil tideAuthzProofUtil, UserModel wrappedUser, EntityManager em) throws JsonProcessingException, NoSuchAlgorithmException {
//        if (draftEntity == null || (draftEntity.getFullScopeEnabled() == DraftStatus.ACTIVE && draftEntity.getFullScopeDisabled() == DraftStatus.NULL)
//                || (draftEntity.getFullScopeDisabled() == DraftStatus.ACTIVE && draftEntity.getFullScopeEnabled() == DraftStatus.NULL)) {
//            return;
//        }
//
//        if (change.getActionType() == ActionType.DELETE) {
//            if (draftEntity.getFullScopeDisabled() == DraftStatus.ACTIVE && draftEntity.getFullScopeEnabled() == DraftStatus.PENDING) {
//                draftEntity.setFullScopeEnabled(DraftStatus.DRAFT);
//            }
//
//            String proof = proofDetail.getProofDraft();
//            Set<RoleModel> activeRoles = TideRolesUtil.getDeepUserRoleMappings(wrappedUser, session, realm, em, DraftStatus.ACTIVE).stream().filter(role -> {
//                if (role.isClientRole()) {
//                    return !Objects.equals(((ClientModel) role.getContainer()).getClientId(), client.getClientId());
//                }
//                return true;
//            }).collect(Collectors.toSet());
//
//            Set<RoleModel> roles = TideRolesProtocolMapper.getAccess(activeRoles, client, client.getClientScopes(true).values().stream(), true);
//            AccessDetails accessDetails = tideAuthzProofUtil.getAccessToRemove(client, roles, false);
//            String updatedProof = tideAuthzProofUtil.removeAccessFromToken(proof, accessDetails);
//            String newProof = tideAuthzProofUtil.removeAudienceFromToken(updatedProof);
//            proofDetail.setProofDraft(newProof);
//            return;
//        }
//
//        draftEntity.setFullScopeEnabled(DraftStatus.DRAFT);
//        String proof = proofDetail.getProofDraft();
//        Set<RoleModel> roleSet = new HashSet<>();
//        String updatedProof = tideAuthzProofUtil.updateDraftProofDetails(client, wrappedUser, proof, roleSet, draftEntity.getAction(), true);
//        proofDetail.setProofDraft(updatedProof);
//    }

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


}
