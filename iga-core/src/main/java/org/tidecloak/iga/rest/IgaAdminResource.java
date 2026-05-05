package org.tidecloak.iga.rest;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.tidecloak.iga.entities.IgaAuthorizationEntity;
import org.tidecloak.iga.entities.IgaAuthorizerEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.entities.IgaCommentEntity;
import org.tidecloak.iga.entities.IgaForsetiContractEntity;
import org.tidecloak.iga.entities.IgaLicenseHistoryEntity;
import org.tidecloak.iga.entities.IgaLicensingDraftEntity;
import org.tidecloak.iga.entities.IgaRolePolicyEntity;
import org.tidecloak.iga.entities.IgaServerCertDraftEntity;
import org.tidecloak.iga.providers.IgaAuthorizerService;
import org.tidecloak.iga.providers.IgaChangeRequestService;
import org.tidecloak.iga.providers.IgaConflictException;
import org.tidecloak.iga.providers.IgaFirstAdminSignPreviewService;
import org.tidecloak.iga.providers.IgaForsetiContractService;
import org.tidecloak.iga.providers.IgaLicenseHistoryService;
import org.tidecloak.iga.providers.IgaLicensingDraftService;
import org.tidecloak.iga.providers.IgaRolePolicyService;
import org.tidecloak.iga.providers.IgaServerCertDraftService;
import org.tidecloak.iga.replay.IgaReplayDispatcher;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * JAX-RS resource at path "iga" providing change request approval workflow endpoints.
 */
@Path("iga")
public class IgaAdminResource {

    private final KeycloakSession session;
    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;

    public IgaAdminResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth) {
        this.session = session;
        this.realm = realm;
        this.auth = auth;
    }

    private EntityManager getEm() {
        return session.getProvider(JpaConnectionProvider.class).getEntityManager();
    }

    private IgaChangeRequestService getService() {
        return new IgaChangeRequestService(getEm(), session);
    }

    private IgaAuthorizerService getAuthorizerService() {
        return new IgaAuthorizerService(getEm());
    }

    private IgaRolePolicyService getRolePolicyService() {
        return new IgaRolePolicyService(getEm());
    }

    private IgaForsetiContractService getForsetiContractService() {
        return new IgaForsetiContractService(getEm());
    }

    private IgaServerCertDraftService getServerCertDraftService() {
        return new IgaServerCertDraftService(getEm(), getService());
    }

    private IgaLicensingDraftService getLicensingDraftService() {
        return new IgaLicensingDraftService(getEm(), getService());
    }

    private IgaLicenseHistoryService getLicenseHistoryService() {
        return new IgaLicenseHistoryService(getEm());
    }

    private IgaFirstAdminSignPreviewService getFirstAdminSignPreviewService() {
        return new IgaFirstAdminSignPreviewService(
                getEm(),
                session,
                realm,
                getService(),
                getRolePolicyService(),
                getAuthorizerService(),
                getForsetiContractService());
    }

    private String currentUserId() {
        try {
            if (auth != null && auth.adminAuth() != null && auth.adminAuth().getUser() != null) {
                return auth.adminAuth().getUser().getId();
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private UserModel currentUser() {
        try {
            if (auth != null && auth.adminAuth() != null) {
                return auth.adminAuth().getUser();
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // GET /iga/change-requests
    // -------------------------------------------------------------------------

    @GET
    @Path("change-requests")
    @Produces(MediaType.APPLICATION_JSON)
    public List<IgaChangeRequestRepresentation> listChangeRequests(
            @QueryParam("status") String status) {

        auth.realm().requireManageRealm();

        String effectiveStatus = (status != null && !status.isBlank()) ? status : "PENDING";
        EntityManager em = getEm();

        TypedQuery<IgaChangeRequestEntity> query = em.createNamedQuery(
                "IgaChangeRequest.findPendingByRealm", IgaChangeRequestEntity.class);
        query.setParameter("realmId", realm.getId());

        List<IgaChangeRequestEntity> results;
        if ("PENDING".equals(effectiveStatus)) {
            results = query.getResultList();
        } else {
            // For non-PENDING statuses fall back to a simple JPQL query
            results = em.createQuery(
                    "SELECT cr FROM IgaChangeRequestEntity cr WHERE cr.realmId = :realmId AND cr.status = :status ORDER BY cr.createdAt DESC",
                    IgaChangeRequestEntity.class)
                    .setParameter("realmId", realm.getId())
                    .setParameter("status", effectiveStatus)
                    .getResultList();
        }

        IgaChangeRequestService service = getService();
        return results.stream()
                .map(cr -> toRepresentation(cr, service))
                .collect(Collectors.toList());
    }

    // -------------------------------------------------------------------------
    // GET /iga/change-requests/{id}
    // -------------------------------------------------------------------------

    @GET
    @Path("change-requests/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getChangeRequest(@PathParam("id") String id) {
        auth.realm().requireManageRealm();

        EntityManager em = getEm();
        IgaChangeRequestEntity cr = em.find(IgaChangeRequestEntity.class, id);
        if (cr == null || !realm.getId().equals(cr.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        return Response.ok(toRepresentation(cr, getService())).build();
    }

    // -------------------------------------------------------------------------
    // POST /iga/change-requests/{id}/authorize
    // -------------------------------------------------------------------------

    @POST
    @Path("change-requests/{id}/authorize")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response authorize(@PathParam("id") String id, Map<String, Object> body) {
        auth.realm().requireManageRealm();

        EntityManager em = getEm();
        IgaChangeRequestEntity cr = em.find(IgaChangeRequestEntity.class, id);
        if (cr == null || !realm.getId().equals(cr.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        if (!"PENDING".equals(cr.getStatus())) {
            return Response.status(Response.Status.CONFLICT)
                    .entity(Map.of("error", "Change request is not in PENDING state"))
                    .build();
        }

        String partialSig = body != null ? (String) body.get("partialSig") : null;
        String authorizedBy = currentUserId();

        IgaChangeRequestService service = getService();
        service.authorize(id, authorizedBy, partialSig);

        long count = service.countAuthorizations(id);
        int threshold = getThreshold();

        if (count >= threshold) {
            // Combine partial sigs (concatenation — pluggable later)
            String finalSignature = combineSignatures(id, em);
            IgaReplayDispatcher.replay(session, cr, finalSignature);
        }

        // Re-fetch to return updated state
        IgaChangeRequestEntity updated = em.find(IgaChangeRequestEntity.class, id);
        return Response.ok(toRepresentation(updated, service)).build();
    }

    // -------------------------------------------------------------------------
    // POST /iga/change-requests/{id}/first-admin-sign-preview
    // -------------------------------------------------------------------------

    /**
     * Resolve a change request to its full signing payload (all foreign keys
     * expanded to full entity data), log it, and return it. No cryptography is
     * performed — this is a prototype for the FirstAdmin signing flow. The real
     * Midgard.signClaims() call will replace the log line once Midgard is updated.
     */
    @POST
    @Path("change-requests/{id}/first-admin-sign-preview")
    @Produces(MediaType.APPLICATION_JSON)
    public Response firstAdminSignPreview(@PathParam("id") String id) {
        auth.realm().requireManageRealm();

        Map<String, Object> payload = getFirstAdminSignPreviewService().buildAndLog(id);
        if (payload == null) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        return Response.ok(payload).build();
    }

    // -------------------------------------------------------------------------
    // PUT /iga/change-requests/{id}
    // -------------------------------------------------------------------------

    @PUT
    @Path("change-requests/{id}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @SuppressWarnings("unchecked")
    public Response updateChangeRequest(@PathParam("id") String id, Map<String, Object> body) {
        auth.realm().requireManageRealm();

        EntityManager em = getEm();
        IgaChangeRequestEntity cr = em.find(IgaChangeRequestEntity.class, id);
        if (cr == null || !realm.getId().equals(cr.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        List<Map<String, Object>> newRows = (List<Map<String, Object>>) body.get("rows");
        if (newRows == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "Missing 'rows' field"))
                    .build();
        }

        IgaChangeRequestService service = getService();
        service.updateRows(id, newRows);

        IgaChangeRequestEntity updated = em.find(IgaChangeRequestEntity.class, id);
        return Response.ok(toRepresentation(updated, service)).build();
    }

    // -------------------------------------------------------------------------
    // POST /iga/change-requests/{id}/deny
    // -------------------------------------------------------------------------

    @POST
    @Path("change-requests/{id}/deny")
    public Response deny(@PathParam("id") String id) {
        auth.realm().requireManageRealm();

        EntityManager em = getEm();
        IgaChangeRequestEntity cr = em.find(IgaChangeRequestEntity.class, id);
        if (cr == null || !realm.getId().equals(cr.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        IgaChangeRequestService service = getService();
        service.deny(id, currentUserId());
        return Response.noContent().build();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private int getThreshold() {
        String val = realm.getAttribute("iga.threshold");
        if (val != null) {
            try { return Integer.parseInt(val); } catch (NumberFormatException ignored) {}
        }
        return 1;
    }

    private String combineSignatures(String changeRequestId, EntityManager em) {
        TypedQuery<IgaAuthorizationEntity> q = em.createNamedQuery(
                "IgaAuthorization.findByChangeRequest", IgaAuthorizationEntity.class);
        q.setParameter("changeRequestId", changeRequestId);
        List<IgaAuthorizationEntity> auths = q.getResultList();
        StringBuilder combined = new StringBuilder();
        for (IgaAuthorizationEntity a : auths) {
            if (a.getPartialSig() != null) combined.append(a.getPartialSig());
        }
        return combined.toString();
    }

    // -------------------------------------------------------------------------
    // Comments
    // -------------------------------------------------------------------------

    @GET
    @Path("change-requests/{id}/comments")
    @Produces(MediaType.APPLICATION_JSON)
    public Response listComments(@PathParam("id") String id) {
        auth.realm().requireManageRealm();

        EntityManager em = getEm();
        IgaChangeRequestEntity cr = em.find(IgaChangeRequestEntity.class, id);
        if (cr == null || !realm.getId().equals(cr.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        List<IgaCommentEntity> comments = getService().listComments(id);
        List<IgaCommentRepresentation> reps = comments.stream()
                .map(this::toCommentRepresentation)
                .collect(Collectors.toList());
        return Response.ok(reps).build();
    }

    @POST
    @Path("change-requests/{id}/comments")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response addComment(@PathParam("id") String id, Map<String, Object> body) {
        auth.realm().requireManageRealm();

        EntityManager em = getEm();
        IgaChangeRequestEntity cr = em.find(IgaChangeRequestEntity.class, id);
        if (cr == null || !realm.getId().equals(cr.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        String comment = body != null ? (String) body.get("comment") : null;
        Response validation = validateCommentText(comment);
        if (validation != null) return validation;

        UserModel user = currentUser();
        if (user == null) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(Map.of("error", "No authenticated admin user"))
                    .build();
        }

        IgaCommentEntity created = getService().addComment(id, user.getId(), user.getUsername(), comment);
        return Response.status(Response.Status.CREATED)
                .entity(toCommentRepresentation(created))
                .build();
    }

    @PUT
    @Path("change-requests/{id}/comments/{commentId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateComment(@PathParam("id") String id,
                                   @PathParam("commentId") String commentId,
                                   Map<String, Object> body) {
        auth.realm().requireManageRealm();

        EntityManager em = getEm();
        IgaChangeRequestEntity cr = em.find(IgaChangeRequestEntity.class, id);
        if (cr == null || !realm.getId().equals(cr.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        IgaCommentEntity existing = em.find(IgaCommentEntity.class, commentId);
        if (existing == null || existing.getChangeRequest() == null
                || !id.equals(existing.getChangeRequest().getId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        String currentUserId = currentUserId();
        if (currentUserId == null || !currentUserId.equals(existing.getUserId())) {
            return Response.status(Response.Status.FORBIDDEN)
                    .entity(Map.of("error", "Only the comment author may edit this comment"))
                    .build();
        }

        String newText = body != null ? (String) body.get("comment") : null;
        Response validation = validateCommentText(newText);
        if (validation != null) return validation;

        IgaCommentEntity updated = getService().updateComment(commentId, newText);
        return Response.ok(toCommentRepresentation(updated)).build();
    }

    @DELETE
    @Path("change-requests/{id}/comments/{commentId}")
    public Response deleteComment(@PathParam("id") String id,
                                   @PathParam("commentId") String commentId) {
        // Both authors and realm admins may delete; we don't pre-call requireManageRealm()
        // here because authors who lack manage-realm should still be able to delete their own.
        EntityManager em = getEm();
        IgaChangeRequestEntity cr = em.find(IgaChangeRequestEntity.class, id);
        if (cr == null || !realm.getId().equals(cr.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        IgaCommentEntity existing = em.find(IgaCommentEntity.class, commentId);
        if (existing == null || existing.getChangeRequest() == null
                || !id.equals(existing.getChangeRequest().getId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        String currentUserId = currentUserId();
        boolean isAuthor = currentUserId != null && currentUserId.equals(existing.getUserId());
        boolean isAdmin = false;
        if (!isAuthor) {
            try {
                auth.realm().requireManageRealm();
                isAdmin = true;
            } catch (Exception e) {
                // not a realm admin
            }
        }
        if (!isAuthor && !isAdmin) {
            return Response.status(Response.Status.FORBIDDEN)
                    .entity(Map.of("error", "Only the comment author or a realm admin may delete this comment"))
                    .build();
        }

        getService().deleteComment(commentId);
        return Response.noContent().build();
    }

    // -------------------------------------------------------------------------
    // Authorizers
    // -------------------------------------------------------------------------

    @GET
    @Path("authorizers")
    @Produces(MediaType.APPLICATION_JSON)
    public List<IgaAuthorizerRepresentation> listAuthorizers(@QueryParam("type") String type) {
        auth.realm().requireManageRealm();

        IgaAuthorizerService service = getAuthorizerService();
        List<IgaAuthorizerEntity> results;
        if (type != null && !type.isBlank()) {
            results = service.listByRealmAndType(realm.getId(), type);
        } else {
            results = service.listByRealm(realm.getId());
        }
        return results.stream()
                .map(this::toAuthorizerRepresentation)
                .collect(Collectors.toList());
    }

    @GET
    @Path("authorizers/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAuthorizer(@PathParam("id") String id) {
        auth.realm().requireManageRealm();

        IgaAuthorizerEntity entity = getAuthorizerService().findById(id);
        if (entity == null || !realm.getId().equals(entity.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        return Response.ok(toAuthorizerRepresentation(entity)).build();
    }

    @POST
    @Path("authorizers")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response createAuthorizer(IgaAuthorizerRepresentation rep) {
        auth.realm().requireManageRealm();

        if (rep == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "Missing request body"))
                    .build();
        }
        if (rep.getProviderId() == null || rep.getProviderId().isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "providerId is required"))
                    .build();
        }
        if (rep.getType() == null || rep.getType().isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "type is required"))
                    .build();
        }
        if (rep.getAuthorizer() == null || rep.getAuthorizer().isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "authorizer is required"))
                    .build();
        }
        if (rep.getAuthorizerCertificate() == null || rep.getAuthorizerCertificate().isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "authorizerCertificate is required"))
                    .build();
        }

        IgaAuthorizerEntity created = getAuthorizerService().create(
                realm.getId(),
                rep.getProviderId(),
                rep.getType(),
                rep.getAuthorizer(),
                rep.getAuthorizerCertificate());
        return Response.status(Response.Status.CREATED)
                .entity(toAuthorizerRepresentation(created))
                .build();
    }

    @DELETE
    @Path("authorizers/{id}")
    public Response deleteAuthorizer(@PathParam("id") String id) {
        auth.realm().requireManageRealm();

        IgaAuthorizerService service = getAuthorizerService();
        IgaAuthorizerEntity entity = service.findById(id);
        if (entity == null || !realm.getId().equals(entity.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        service.delete(id);
        return Response.noContent().build();
    }

    // -------------------------------------------------------------------------
    // Role Policies
    // -------------------------------------------------------------------------

    @GET
    @Path("role-policies")
    @Produces(MediaType.APPLICATION_JSON)
    public List<IgaRolePolicyRepresentation> listRolePolicies() {
        auth.realm().requireManageRealm();

        return getRolePolicyService().listByRealm(realm.getId()).stream()
                .map(this::toRolePolicyRepresentation)
                .collect(Collectors.toList());
    }

    @GET
    @Path("role-policies/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getRolePolicy(@PathParam("id") String id) {
        auth.realm().requireManageRealm();

        IgaRolePolicyEntity entity = getRolePolicyService().findById(id);
        if (entity == null || !realm.getId().equals(entity.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        return Response.ok(toRolePolicyRepresentation(entity)).build();
    }

    @GET
    @Path("role-policies/role/{roleId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getRolePolicyByRole(@PathParam("roleId") String roleId) {
        auth.realm().requireManageRealm();

        IgaRolePolicyEntity entity = getRolePolicyService()
                .findByRealmAndRole(realm.getId(), roleId);
        if (entity == null) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        return Response.ok(toRolePolicyRepresentation(entity)).build();
    }

    @POST
    @Path("role-policies")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response upsertRolePolicy(IgaRolePolicyRepresentation rep) {
        auth.realm().requireManageRealm();

        if (rep == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "Missing request body"))
                    .build();
        }
        if (rep.getRoleId() == null || rep.getRoleId().isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "roleId is required"))
                    .build();
        }
        if (rep.getPolicy() == null || rep.getPolicy().isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "policy is required"))
                    .build();
        }
        if (rep.getPolicySig() == null || rep.getPolicySig().isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "policySig is required"))
                    .build();
        }
        if (rep.getPolicySig().length() > 512) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "policySig exceeds maximum length of 512 characters"))
                    .build();
        }

        IgaRolePolicyEntity upserted = getRolePolicyService().upsert(
                realm.getId(),
                rep.getRoleId(),
                rep.getPolicy(),
                rep.getPolicySig(),
                rep.getContractId(),
                rep.getApprovalType(),
                rep.getExecutionType(),
                rep.getThreshold(),
                rep.getPolicyData());
        return Response.ok(toRolePolicyRepresentation(upserted)).build();
    }

    @DELETE
    @Path("role-policies/role/{roleId}")
    public Response deleteRolePolicyByRole(@PathParam("roleId") String roleId) {
        auth.realm().requireManageRealm();

        IgaRolePolicyService service = getRolePolicyService();
        IgaRolePolicyEntity existing = service.findByRealmAndRole(realm.getId(), roleId);
        if (existing == null) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        service.deleteByRealmAndRole(realm.getId(), roleId);
        return Response.noContent().build();
    }

    @DELETE
    @Path("role-policies/{id}")
    public Response deleteRolePolicy(@PathParam("id") String id) {
        auth.realm().requireManageRealm();

        IgaRolePolicyService service = getRolePolicyService();
        IgaRolePolicyEntity existing = service.findById(id);
        if (existing == null || !realm.getId().equals(existing.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        service.deleteById(id);
        return Response.noContent().build();
    }

    // -------------------------------------------------------------------------
    // Forseti Contracts
    // -------------------------------------------------------------------------

    @GET
    @Path("forseti-contracts")
    @Produces(MediaType.APPLICATION_JSON)
    public List<IgaForsetiContractRepresentation> listForsetiContracts() {
        auth.realm().requireManageRealm();

        return getForsetiContractService().listByRealm(realm.getId()).stream()
                .map(this::toForsetiContractRepresentation)
                .collect(Collectors.toList());
    }

    @GET
    @Path("forseti-contracts/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getForsetiContract(@PathParam("id") String id) {
        auth.realm().requireManageRealm();

        IgaForsetiContractEntity entity = getForsetiContractService().findById(id);
        if (entity == null || !realm.getId().equals(entity.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        return Response.ok(toForsetiContractRepresentation(entity)).build();
    }

    @POST
    @Path("forseti-contracts")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response upsertForsetiContract(IgaForsetiContractRepresentation rep) {
        auth.realm().requireManageRealm();

        if (rep == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "Missing request body"))
                    .build();
        }
        if (rep.getContractCode() == null || rep.getContractCode().isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "contractCode is required"))
                    .build();
        }
        if (rep.getContractCode().length() > 1_048_576) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "contractCode exceeds maximum length of 1048576 characters"))
                    .build();
        }

        IgaForsetiContractEntity upserted = getForsetiContractService().upsert(
                realm.getId(),
                rep.getContractCode(),
                rep.getName());
        return Response.ok(toForsetiContractRepresentation(upserted)).build();
    }

    @DELETE
    @Path("forseti-contracts/{id}")
    public Response deleteForsetiContract(@PathParam("id") String id) {
        auth.realm().requireManageRealm();

        IgaForsetiContractService service = getForsetiContractService();
        IgaForsetiContractEntity existing = service.findById(id);
        if (existing == null || !realm.getId().equals(existing.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        service.deleteById(id);
        return Response.noContent().build();
    }

    // -------------------------------------------------------------------------
    // Server Cert Drafts (workload TLS / SPIFFE cert request flow)
    // -------------------------------------------------------------------------

    @GET
    @Path("server-certs")
    @Produces(MediaType.APPLICATION_JSON)
    public List<IgaServerCertDraftRepresentation> listServerCerts() {
        auth.realm().requireManageRealm();
        return getServerCertDraftService().listByRealm(realm.getId()).stream()
                .map(this::toServerCertDraftRepresentation)
                .collect(Collectors.toList());
    }

    @GET
    @Path("server-certs/active")
    @Produces(MediaType.APPLICATION_JSON)
    public List<IgaServerCertDraftRepresentation> listActiveServerCerts() {
        auth.realm().requireManageRealm();
        return getServerCertDraftService().listActive(realm.getId()).stream()
                .map(this::toServerCertDraftRepresentation)
                .collect(Collectors.toList());
    }

    @GET
    @Path("server-certs/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getServerCert(@PathParam("id") String id) {
        auth.realm().requireManageRealm();
        IgaServerCertDraftEntity entity = getServerCertDraftService().findById(id);
        if (entity == null || !realm.getId().equals(entity.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        return Response.ok(toServerCertDraftRepresentation(entity)).build();
    }

    @GET
    @Path("server-certs/instance/{instanceId}")
    @Produces(MediaType.APPLICATION_JSON)
    public List<IgaServerCertDraftRepresentation> listServerCertsByInstance(
            @PathParam("instanceId") String instanceId) {
        auth.realm().requireManageRealm();
        return getServerCertDraftService()
                .findByRealmAndInstance(realm.getId(), instanceId).stream()
                .map(this::toServerCertDraftRepresentation)
                .collect(Collectors.toList());
    }

    @POST
    @Path("server-certs/request")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response requestServerCert(IgaServerCertDraftRepresentation rep) {
        auth.realm().requireManageRealm();

        if (rep == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "Missing request body"))
                    .build();
        }
        if (rep.getClientId() == null || rep.getClientId().isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "clientId is required"))
                    .build();
        }
        if (rep.getInstanceId() == null || rep.getInstanceId().isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "instanceId is required"))
                    .build();
        }
        if (rep.getPublicKey() == null || rep.getPublicKey().isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "publicKey is required"))
                    .build();
        }
        if (rep.getPublicKey().length() > 4096) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "publicKey exceeds maximum length of 4096 characters"))
                    .build();
        }
        if (rep.getSpiffeId() != null && rep.getSpiffeId().length() > 512) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "spiffeId exceeds maximum length of 512 characters"))
                    .build();
        }
        if (rep.getSignedPolicy() != null && rep.getSignedPolicy().length() > 8192) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "signedPolicy exceeds maximum length of 8192 characters"))
                    .build();
        }

        IgaServerCertDraftEntity created = getServerCertDraftService().createRequest(
                realm,
                currentUserId(),
                rep.getClientId(),
                rep.getInstanceId(),
                rep.getSpiffeId(),
                rep.getPublicKey(),
                rep.getPublicKeyFingerprint(),
                rep.getRequestedLifetime(),
                rep.getSignedPolicy());
        return Response.status(Response.Status.CREATED)
                .entity(toServerCertDraftRepresentation(created))
                .build();
    }

    @POST
    @Path("server-certs/{id}/issue")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response issueServerCert(@PathParam("id") String id, Map<String, Object> body) {
        auth.realm().requireManageRealm();

        IgaServerCertDraftService service = getServerCertDraftService();
        IgaServerCertDraftEntity entity = service.findById(id);
        if (entity == null || !realm.getId().equals(entity.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        String certificate = body != null ? (String) body.get("certificate") : null;
        String trustBundle = body != null ? (String) body.get("trustBundle") : null;
        if (certificate == null || certificate.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "certificate is required"))
                    .build();
        }
        if (trustBundle == null || trustBundle.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "trustBundle is required"))
                    .build();
        }

        IgaServerCertDraftEntity updated = service.issueCert(id, certificate, trustBundle);
        return Response.ok(toServerCertDraftRepresentation(updated)).build();
    }

    @POST
    @Path("server-certs/{id}/revoke")
    @Produces(MediaType.APPLICATION_JSON)
    public Response revokeServerCert(@PathParam("id") String id) {
        auth.realm().requireManageRealm();

        IgaServerCertDraftService service = getServerCertDraftService();
        IgaServerCertDraftEntity entity = service.findById(id);
        if (entity == null || !realm.getId().equals(entity.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        IgaServerCertDraftEntity updated = service.revoke(id);
        return Response.ok(toServerCertDraftRepresentation(updated)).build();
    }

    @DELETE
    @Path("server-certs/{id}")
    public Response deleteServerCert(@PathParam("id") String id) {
        auth.realm().requireManageRealm();

        IgaServerCertDraftService service = getServerCertDraftService();
        IgaServerCertDraftEntity entity = service.findById(id);
        if (entity == null || !realm.getId().equals(entity.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        service.deleteById(id);
        return Response.noContent().build();
    }

    // -------------------------------------------------------------------------
    // Licensing Drafts (realm license install/rotate flow)
    // -------------------------------------------------------------------------

    @POST
    @Path("licensing/trigger")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response triggerLicensing(Map<String, Object> body) {
        auth.realm().requireManageRealm();

        String actionType = body != null ? (String) body.get("actionType") : null;
        if (actionType == null || actionType.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "actionType is required"))
                    .build();
        }
        if (!"INSTALL_LICENSE".equals(actionType) && !"ROTATE_LICENSE".equals(actionType)) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "actionType must be INSTALL_LICENSE or ROTATE_LICENSE"))
                    .build();
        }

        IgaLicensingDraftEntity created = getLicensingDraftService().createRequest(
                realm,
                currentUserId(),
                actionType);
        return Response.status(Response.Status.CREATED)
                .entity(toLicensingDraftRepresentation(created))
                .build();
    }

    @GET
    @Path("licensing/drafts")
    @Produces(MediaType.APPLICATION_JSON)
    public List<IgaLicensingDraftRepresentation> listLicensingDrafts() {
        auth.realm().requireManageRealm();
        return getLicensingDraftService().listByRealm(realm.getId()).stream()
                .map(this::toLicensingDraftRepresentation)
                .collect(Collectors.toList());
    }

    @GET
    @Path("licensing/drafts/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getLicensingDraft(@PathParam("id") String id) {
        auth.realm().requireManageRealm();
        IgaLicensingDraftEntity entity = getLicensingDraftService().findById(id);
        if (entity == null || !realm.getId().equals(entity.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        return Response.ok(toLicensingDraftRepresentation(entity)).build();
    }

    @DELETE
    @Path("licensing/drafts/{id}")
    public Response deleteLicensingDraft(@PathParam("id") String id) {
        auth.realm().requireManageRealm();

        IgaLicensingDraftService service = getLicensingDraftService();
        IgaLicensingDraftEntity entity = service.findById(id);
        if (entity == null || !realm.getId().equals(entity.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        service.deleteById(id);
        return Response.noContent().build();
    }

    // -------------------------------------------------------------------------
    // License History (append-only audit log) + issuance endpoint
    // -------------------------------------------------------------------------

    @GET
    @Path("licensing/history")
    @Produces(MediaType.APPLICATION_JSON)
    public List<IgaLicenseHistoryRepresentation> listLicenseHistory() {
        auth.realm().requireManageRealm();
        return getLicenseHistoryService().listByRealm(realm.getId()).stream()
                .map(this::toLicenseHistoryRepresentation)
                .collect(Collectors.toList());
    }

    @GET
    @Path("licensing/history/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getLicenseHistory(@PathParam("id") String id) {
        auth.realm().requireManageRealm();
        IgaLicenseHistoryEntity entity = getLicenseHistoryService().findById(id);
        if (entity == null || !realm.getId().equals(entity.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        return Response.ok(toLicenseHistoryRepresentation(entity)).build();
    }

    @GET
    @Path("licensing/history/excluding-active")
    @Produces(MediaType.APPLICATION_JSON)
    public List<IgaLicenseHistoryRepresentation> listLicenseHistoryExcludingActive(
            @QueryParam("activeGvrk") String activeGvrk) {
        auth.realm().requireManageRealm();

        List<IgaLicenseHistoryEntity> all = getLicenseHistoryService().listByRealm(realm.getId());
        if (activeGvrk == null || activeGvrk.isBlank()) {
            return all.stream()
                    .map(this::toLicenseHistoryRepresentation)
                    .collect(Collectors.toList());
        }
        return all.stream()
                .filter(h -> !activeGvrk.equals(h.getGvrk()))
                .map(this::toLicenseHistoryRepresentation)
                .collect(Collectors.toList());
    }

    @POST
    @Path("licensing/drafts/{draftId}/issue")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response issueLicense(@PathParam("draftId") String draftId, Map<String, Object> body) {
        auth.realm().requireManageRealm();

        IgaLicensingDraftService draftService = getLicensingDraftService();
        IgaLicensingDraftEntity draft = draftService.findById(draftId);
        if (draft == null || !realm.getId().equals(draft.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        if (body == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "Missing request body"))
                    .build();
        }

        String providerId = (String) body.get("providerId");
        String vrk = (String) body.get("vrk");
        String gvrk = (String) body.get("gvrk");
        String signature = (String) body.get("signature");

        if (providerId == null || providerId.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "providerId is required"))
                    .build();
        }
        if (vrk == null || vrk.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "vrk is required"))
                    .build();
        }
        if (gvrk == null || gvrk.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "gvrk is required"))
                    .build();
        }
        if (signature == null || signature.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "signature is required"))
                    .build();
        }

        String gvrkCertificate = (String) body.get("gvrkCertificate");
        String vvkId = (String) body.get("vvkId");
        String customerId = (String) body.get("customerId");
        String vendorId = (String) body.get("vendorId");
        String payerPub = (String) body.get("payerPub");
        String walletId = (String) body.get("walletId");
        Object expiryRaw = body.get("expiry");
        Long expiry = null;
        if (expiryRaw instanceof Number) {
            expiry = ((Number) expiryRaw).longValue();
        } else if (expiryRaw instanceof String && !((String) expiryRaw).isBlank()) {
            try { expiry = Long.parseLong((String) expiryRaw); } catch (NumberFormatException ignored) {}
        }

        IgaLicenseHistoryEntity history = getLicenseHistoryService().record(
                realm.getId(),
                providerId,
                vrk,
                gvrk,
                gvrkCertificate,
                vvkId,
                customerId,
                vendorId,
                payerPub,
                walletId,
                expiry);

        draftService.setSignature(draftId, signature);

        return Response.ok(Map.of(
                "historyId", history.getId(),
                "draftId", draftId
        )).build();
    }

    private IgaLicenseHistoryRepresentation toLicenseHistoryRepresentation(IgaLicenseHistoryEntity entity) {
        IgaLicenseHistoryRepresentation rep = new IgaLicenseHistoryRepresentation();
        rep.setId(entity.getId());
        rep.setRealmId(entity.getRealmId());
        rep.setProviderId(entity.getProviderId());
        rep.setVrk(entity.getVrk());
        rep.setGvrk(entity.getGvrk());
        rep.setGvrkCertificate(entity.getGvrkCertificate());
        rep.setVvkId(entity.getVvkId());
        rep.setCustomerId(entity.getCustomerId());
        rep.setVendorId(entity.getVendorId());
        rep.setPayerPub(entity.getPayerPub());
        rep.setWalletId(entity.getWalletId());
        rep.setExpiry(entity.getExpiry());
        rep.setCreatedAt(entity.getCreatedAt());
        return rep;
    }

    private IgaLicensingDraftRepresentation toLicensingDraftRepresentation(IgaLicensingDraftEntity entity) {
        IgaLicensingDraftRepresentation rep = new IgaLicensingDraftRepresentation();
        rep.setId(entity.getId());
        rep.setChangeRequestId(entity.getChangeRequest() != null ? entity.getChangeRequest().getId() : null);
        rep.setRealmId(entity.getRealmId());
        rep.setActionType(entity.getActionType());
        rep.setSignature(entity.getSignature());
        rep.setCreatedAt(entity.getCreatedAt());
        rep.setUpdatedAt(entity.getUpdatedAt());
        return rep;
    }

    private IgaServerCertDraftRepresentation toServerCertDraftRepresentation(IgaServerCertDraftEntity entity) {
        IgaServerCertDraftRepresentation rep = new IgaServerCertDraftRepresentation();
        rep.setId(entity.getId());
        rep.setChangeRequestId(entity.getChangeRequest() != null ? entity.getChangeRequest().getId() : null);
        rep.setRealmId(entity.getRealmId());
        rep.setClientId(entity.getClientId());
        rep.setInstanceId(entity.getInstanceId());
        rep.setSpiffeId(entity.getSpiffeId());
        rep.setPublicKey(entity.getPublicKey());
        rep.setPublicKeyFingerprint(entity.getPublicKeyFingerprint());
        rep.setRequestedLifetime(entity.getRequestedLifetime());
        rep.setCertificate(entity.getCertificate());
        rep.setTrustBundle(entity.getTrustBundle());
        rep.setSignedPolicy(entity.getSignedPolicy());
        rep.setRevoked(entity.isRevoked());
        rep.setRevokedAt(entity.getRevokedAt());
        rep.setCreatedAt(entity.getCreatedAt());
        rep.setUpdatedAt(entity.getUpdatedAt());
        return rep;
    }

    private IgaForsetiContractRepresentation toForsetiContractRepresentation(IgaForsetiContractEntity entity) {
        IgaForsetiContractRepresentation rep = new IgaForsetiContractRepresentation();
        rep.setId(entity.getId());
        rep.setRealmId(entity.getRealmId());
        rep.setContractHash(entity.getContractHash());
        rep.setContractCode(entity.getContractCode());
        rep.setName(entity.getName());
        rep.setCreatedAt(entity.getCreatedAt());
        rep.setUpdatedAt(entity.getUpdatedAt());
        return rep;
    }

    private IgaRolePolicyRepresentation toRolePolicyRepresentation(IgaRolePolicyEntity entity) {
        IgaRolePolicyRepresentation rep = new IgaRolePolicyRepresentation();
        rep.setId(entity.getId());
        rep.setRealmId(entity.getRealmId());
        rep.setRoleId(entity.getRoleId());
        rep.setPolicy(entity.getPolicy());
        rep.setPolicySig(entity.getPolicySig());
        rep.setContractId(entity.getContractId());
        rep.setApprovalType(entity.getApprovalType());
        rep.setExecutionType(entity.getExecutionType());
        rep.setThreshold(entity.getThreshold());
        rep.setPolicyData(entity.getPolicyData());
        rep.setCreatedAt(entity.getCreatedAt());
        rep.setUpdatedAt(entity.getUpdatedAt());
        return rep;
    }

    private IgaAuthorizerRepresentation toAuthorizerRepresentation(IgaAuthorizerEntity entity) {
        IgaAuthorizerRepresentation rep = new IgaAuthorizerRepresentation();
        rep.setId(entity.getId());
        rep.setRealmId(entity.getRealmId());
        rep.setProviderId(entity.getProviderId());
        rep.setType(entity.getType());
        rep.setAuthorizer(entity.getAuthorizer());
        rep.setAuthorizerCertificate(entity.getAuthorizerCertificate());
        rep.setCreatedAt(entity.getCreatedAt());
        return rep;
    }

    private Response validateCommentText(String comment) {
        if (comment == null || comment.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "Comment text must be non-empty"))
                    .build();
        }
        if (comment.length() > 2000) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "Comment text exceeds maximum length of 2000 characters"))
                    .build();
        }
        return null;
    }

    private IgaCommentRepresentation toCommentRepresentation(IgaCommentEntity entity) {
        IgaCommentRepresentation rep = new IgaCommentRepresentation();
        rep.setId(entity.getId());
        rep.setUserId(entity.getUserId());
        rep.setUsername(entity.getUsername());
        rep.setComment(entity.getComment());
        rep.setCreatedAt(entity.getCreatedAt());
        rep.setUpdatedAt(entity.getUpdatedAt());
        return rep;
    }

    private IgaChangeRequestRepresentation toRepresentation(IgaChangeRequestEntity cr,
                                                              IgaChangeRequestService service) {
        IgaChangeRequestRepresentation rep = new IgaChangeRequestRepresentation();
        rep.setId(cr.getId());
        rep.setRealmId(cr.getRealmId());
        rep.setEntityType(cr.getEntityType());
        rep.setEntityId(cr.getEntityId());
        rep.setActionType(cr.getActionType());
        rep.setStatus(cr.getStatus());
        rep.setRequestedBy(cr.getRequestedBy());
        rep.setCreatedAt(cr.getCreatedAt());
        rep.setResolvedAt(cr.getResolvedAt());
        rep.setResolvedBy(cr.getResolvedBy());
        try {
            rep.setRows(service.parseRows(cr.getRowsJson()));
        } catch (Exception ignored) {
        }
        rep.setAuthorizationCount(service.countAuthorizations(cr.getId()));
        return rep;
    }
}
