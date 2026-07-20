package org.tidecloak.iga.rest;

import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import org.tidecloak.iga.providers.IgaPendingApprovalException;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Maps {@link IgaPendingApprovalException} to HTTP 202 Accepted with a
 * machine-readable JSON body so admin UIs / API clients can display
 * a friendly "Change request created" notification.
 */
@Provider
public class IgaPendingApprovalExceptionMapper implements ExceptionMapper<IgaPendingApprovalException> {

    // The exception itself does not carry the realm (it is thrown deep in the
    // model SPI layer). The realm is always recoverable from the in-flight
    // admin-REST request URI, whose path is .../admin/realms/{realm}/...
    // (every IgaPendingApprovalException is thrown while servicing such a
    // request: client/group/org/user/realm create via the Admin REST API).
    // UriInfo is the cleanest reliable source — it requires no changes to the
    // six model-layer throw sites or the exception class.
    @Context
    UriInfo uriInfo;

    @Override
    public Response toResponse(IgaPendingApprovalException ex) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "PENDING");
        body.put("changeRequestId", ex.getChangeRequestId());
        body.put("entityType", ex.getEntityType());
        body.put("actionType", ex.getActionType());
        body.put("message", "Change request created — awaiting approval");

        Response.ResponseBuilder rb = Response.status(Response.Status.ACCEPTED)
                .entity(body)
                .type(MediaType.APPLICATION_JSON);

        // Add a synthetic Location header pointing at the existing CR-get
        // endpoint: GET /admin/realms/{realm}/iga/change-requests/{id}
        // (IgaAdminResource#getChangeRequest). Native Admin-REST / automation
        // callers follow this to poll the change request. The 202 status and
        // JSON body above are left exactly as-is.
        String realm = resolveRealm();
        if (realm != null && ex.getChangeRequestId() != null) {
            String location = "/admin/realms/" + realm
                    + "/iga/change-requests/" + ex.getChangeRequestId();
            rb.header(HttpHeaders.LOCATION, location);
        }

        return rb.build();
    }

    /**
     * Extract the realm name from the current request URI. The Keycloak admin
     * REST path is {@code .../admin/realms/{realm}/...}; we take the path
     * segment immediately following the {@code realms} segment. Falls back to
     * the matched {@code realm} path parameter if present. Returns {@code null}
     * if the realm cannot be determined (no Location header is then emitted —
     * the 202 body still fully identifies the change request).
     */
    private String resolveRealm() {
        if (uriInfo == null) {
            return null;
        }
        // Prefer a matched {realm} path parameter when RESTEasy resolved one.
        MultivaluedMap<String, String> pathParams = uriInfo.getPathParameters();
        if (pathParams != null) {
            String p = pathParams.getFirst("realm");
            if (p != null && !p.isBlank()) {
                return p;
            }
        }
        // Otherwise walk the path segments and take the one after "realms".
        List<jakarta.ws.rs.core.PathSegment> segments = uriInfo.getPathSegments();
        if (segments != null) {
            for (int i = 0; i < segments.size() - 1; i++) {
                if ("realms".equals(segments.get(i).getPath())) {
                    String r = segments.get(i + 1).getPath();
                    if (r != null && !r.isBlank()) {
                        return r;
                    }
                }
            }
        }
        return null;
    }
}
