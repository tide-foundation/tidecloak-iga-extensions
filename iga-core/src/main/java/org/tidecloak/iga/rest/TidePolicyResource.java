package org.tidecloak.iga.rest;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.entities.TidePolicyEntity;
import org.tidecloak.iga.providers.TidePolicyService;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.List;
import java.util.Map;

public class TidePolicyResource {
    private final KeycloakSession session;
    private final AuthenticationManager.AuthResult auth;
    private final TidePolicyService service;
    
    public TidePolicyResource(KeycloakSession session) {
        this.session = session;
        this.auth = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
        this.service = new TidePolicyService(session);
    }

    @GET
    @Path("find/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getPolicy(@PathParam("id") String id) {
        if (this.auth == null) {
            throw new NotAuthorizedException("Bearer token required");
        }
        TidePolicyEntity entity = this.service.getPolicy(id);
        if (entity != null) {
            return Response.ok(entity).build();
        } else {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity(Map.of("error", "Tide policy not found: " + id))
                    .build();
        }
    }

    @GET
    @Path("all")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAllPolicies() {
        if (this.auth == null) {
            throw new NotAuthorizedException("Bearer token required");
        }
        RealmModel realm = this.session.getContext().getRealm();
        List<TidePolicyEntity> policies = this.service.listPolicies(realm);
        return Response.ok(policies).build();
    }

    @POST
    @Path("add")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response addPolicy(@FormParam("id") String id,
                              @FormParam("data") String data) {
        if (this.auth == null) {
            throw new NotAuthorizedException("Bearer token required");
        }
        if (id == null || id.isBlank() || data == null || data.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "Both 'id' and 'data' form fields are required"))
                    .build();
        }

        // notes is empty for this endpoint; realm is the request's realm
        String notes = "";
        RealmModel realm = this.session.getContext().getRealm();
        String requestedBy = this.auth.user().getId();

        // Routes through IGA: a change request when IGA is enabled, or a direct
        // write returning null when it isn't.
        IgaChangeRequestEntity changeRequest = this.service.create(realm, id, data, notes, requestedBy);

        if (changeRequest != null) {
            // IGA enabled — write is pending approval; hand back the CR id
            return Response.ok(Map.of("changeRequestId", changeRequest.getId())).build();
        }
        // IGA disabled — policy was written straight through
        return Response.ok(Map.of("id", id)).build();
    }
}
