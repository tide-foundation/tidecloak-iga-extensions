package org.tidecloak.TideResource;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.openapi.annotations.parameters.RequestBody;
import org.jboss.logging.Logger;
import org.jboss.resteasy.reactive.server.multipart.FormValue;
import org.jboss.resteasy.reactive.server.multipart.MultipartFormDataInput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.Collection;
import java.util.Map;


public class TideAdminRealmResource {

    private final KeycloakSession session;
    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;

    protected static final Logger logger = Logger.getLogger(TideAdminRealmResource.class);
    public TideAdminRealmResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth) {
        this.session = session;
        this.realm = realm;
        this.auth = auth;
    }
    @POST
    @Path("toggle-iga")
    @Produces(MediaType.TEXT_PLAIN)

    public Response toggleIGA(@FormParam("isIGAEnabled") boolean isEnabled) {
        try{
            auth.realm().requireManageRealm();
            session.getContext().getRealm().setAttribute("isIGAEnabled", isEnabled);
            logger.info("IGA has been toggled to : " + isEnabled);

            // if IGA is on, we need to enable EDDSA as default sig
            // TODO: this should be removed once we have IDP-LESS IGA
            if(isEnabled){
                session.getContext().getRealm().setDefaultSignatureAlgorithm("EdDSA");
                logger.info("IGA has been enabled, default signature algorithm updated to EdDSA");
            }
            return buildResponse(200, "IGA has been toggled to : " + isEnabled);
        }catch(Exception e) {
            logger.error("Error toggling IGA on realm: ", e);
            throw e;
        }

    }

    private Response buildResponse(int status, String message) {
        return Response.status(status)
                .header("Access-Control-Allow-Origin", "*")
                .entity(message)
                .type(MediaType.TEXT_PLAIN)
                .build();
    }


}


