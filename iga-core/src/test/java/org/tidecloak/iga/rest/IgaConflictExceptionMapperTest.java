package org.tidecloak.iga.rest;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import org.tidecloak.iga.providers.IgaConflictException;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link IgaConflictExceptionMapper}: an {@link IgaConflictException}
 * thrown deep in the model-SPI layer must map to a clean HTTP 409 with the
 * conflicting change-request id — NEVER reach {@code KeycloakErrorHandler} as an
 * uncaught 500 (the original bug: a client-role grant blocked by an unrelated
 * pending CR surfaced as "Uncaught server error" / 500).
 */
class IgaConflictExceptionMapperTest {

    private final IgaConflictExceptionMapper mapper = new IgaConflictExceptionMapper();

    @Test
    void mapsToConflict409() {
        Response resp = mapper.toResponse(
                new IgaConflictException("8cda9e5f-fc1c-4b37-babe-388b680e2ac2"));

        assertEquals(Response.Status.CONFLICT.getStatusCode(), resp.getStatus());
        assertEquals(409, resp.getStatus());
    }

    @Test
    void bodyCarriesConflictingChangeRequestId() {
        String crId = "8cda9e5f-fc1c-4b37-babe-388b680e2ac2";
        Response resp = mapper.toResponse(new IgaConflictException(crId));

        Object entity = resp.getEntity();
        @SuppressWarnings("unchecked")
        Map<String, Object> body = assertInstanceOf(Map.class, entity);
        assertEquals("PENDING_CHANGE_REQUEST_CONFLICT", body.get("error"));
        assertEquals(crId, body.get("conflictingChangeRequestId"));
        assertTrue(String.valueOf(body.get("message")).contains(crId),
                "message should name the conflicting CR id");
    }

    @Test
    void responseIsJson() {
        Response resp = mapper.toResponse(new IgaConflictException("any-cr-id"));
        assertEquals(MediaType.APPLICATION_JSON_TYPE, resp.getMediaType());
    }
}
