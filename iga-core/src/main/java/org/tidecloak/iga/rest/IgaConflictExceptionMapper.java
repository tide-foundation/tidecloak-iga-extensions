package org.tidecloak.iga.rest;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import org.tidecloak.iga.providers.IgaConflictException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Maps {@link IgaConflictException} to HTTP 409 Conflict with a machine-readable
 * JSON body that names the conflicting (already-PENDING) change request.
 *
 * <p>Without this mapper, an {@code IgaConflictException} thrown deep in the
 * model-SPI layer (e.g. {@code IgaUserAdapter.grantRole → checkNoPendingCr},
 * {@code IgaRealmAdapter}, {@code IgaChangeRequestService.coalesceOrCreate}, …)
 * propagates uncaught all the way to Keycloak's {@code KeycloakErrorHandler},
 * which logs an <em>"Uncaught server error"</em> and returns HTTP 500. A pending
 * change request that legitimately blocks a contradictory mutation is a normal,
 * client-correctable condition — it must surface as a clean 409, never a 500.</p>
 *
 * <p>Discovered by RESTEasy via the {@link Provider} annotation, exactly like the
 * sibling {@link IgaPendingApprovalExceptionMapper} (no services-file entry).</p>
 */
@Provider
public class IgaConflictExceptionMapper implements ExceptionMapper<IgaConflictException> {

    @Override
    public Response toResponse(IgaConflictException ex) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "PENDING_CHANGE_REQUEST_CONFLICT");
        body.put("conflictingChangeRequestId", ex.getExistingChangeRequestId());
        body.put("message", "A conflicting change request is already pending approval"
                + " for this entity (change request " + ex.getExistingChangeRequestId()
                + "). Resolve or deny it before requesting this change.");

        return Response.status(Response.Status.CONFLICT)
                .entity(body)
                .type(MediaType.APPLICATION_JSON)
                .build();
    }
}
