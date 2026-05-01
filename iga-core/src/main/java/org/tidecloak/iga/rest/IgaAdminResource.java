package org.tidecloak.iga.rest;

import jakarta.ws.rs.Consumes;
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
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.tidecloak.iga.entities.IgaAuthorizationEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.providers.IgaChangeRequestService;
import org.tidecloak.iga.providers.IgaConflictException;
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

    private String currentUserId() {
        try {
            if (auth != null && auth.adminAuth() != null && auth.adminAuth().getUser() != null) {
                return auth.adminAuth().getUser().getId();
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
