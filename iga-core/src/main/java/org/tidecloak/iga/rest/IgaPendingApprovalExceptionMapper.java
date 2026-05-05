package org.tidecloak.iga.rest;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import org.tidecloak.iga.providers.IgaPendingApprovalException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Maps {@link IgaPendingApprovalException} to HTTP 202 Accepted with a
 * machine-readable JSON body so admin UIs / API clients can display
 * a friendly "Change request created" notification.
 */
@Provider
public class IgaPendingApprovalExceptionMapper implements ExceptionMapper<IgaPendingApprovalException> {

    @Override
    public Response toResponse(IgaPendingApprovalException ex) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "PENDING");
        body.put("changeRequestId", ex.getChangeRequestId());
        body.put("entityType", ex.getEntityType());
        body.put("actionType", ex.getActionType());
        body.put("message", "Change request created — awaiting approval");
        return Response.status(Response.Status.ACCEPTED)
                .entity(body)
                .type(MediaType.APPLICATION_JSON)
                .build();
    }
}
