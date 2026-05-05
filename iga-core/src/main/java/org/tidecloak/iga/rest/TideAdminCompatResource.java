package org.tidecloak.iga.rest;

import jakarta.enterprise.inject.Vetoed;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;

import java.util.Map;

/**
 * Backwards-compat admin resource at /admin/realms/{realm}/tide-admin
 * Replaces the old IGA's IGARealmResource.toggleIga endpoint so the existing admin UI works.
 */
@Path("tide-admin")
@Vetoed
public class TideAdminCompatResource {

    private static final Logger logger = Logger.getLogger(TideAdminCompatResource.class);
    private static final String IGA_ATTRIBUTE = "isIGAEnabled";

    private final KeycloakSession session;
    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;

    public TideAdminCompatResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth) {
        this.session = session;
        this.realm = realm;
        this.auth = auth;
    }

    @POST
    @Path("toggle-iga")
    @Produces(MediaType.APPLICATION_JSON)
    public Response toggleIga() {
        auth.realm().requireManageRealm();
        boolean current = "true".equals(realm.getAttribute(IGA_ATTRIBUTE));
        boolean next = !current;
        realm.setAttribute(IGA_ATTRIBUTE, Boolean.toString(next));
        logger.infof("IGA has been toggled to : %s for realm %s", next, realm.getName());
        return Response.ok(Map.of("enabled", next)).build();
    }

    @GET
    @Path("iga-status")
    @Produces(MediaType.APPLICATION_JSON)
    public Response status() {
        auth.realm().requireViewRealm();
        boolean enabled = "true".equals(realm.getAttribute(IGA_ATTRIBUTE));
        return Response.ok(Map.of("enabled", enabled)).build();
    }
}
