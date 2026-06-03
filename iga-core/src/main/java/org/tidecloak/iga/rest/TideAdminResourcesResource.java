package org.tidecloak.iga.rest;

import jakarta.enterprise.inject.Vetoed;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.jboss.logging.Logger;
import org.keycloak.authentication.actiontoken.execactions.ExecuteActionsActionToken;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;

import java.util.List;

/**
 * JAX-RS resource served at {@code /admin/realms/{realm}/tideAdminResources/*}.
 *
 * <p>The TideCloak admin UI's admin-client {@code tideProvider} calls a handful of
 * {@code /tideAdminResources/*} routes. After the IGA decoupling (the old
 * {@code tidecloak-iga-provider} module that carried
 * {@code org.tidecloak.tide.iga.AdminResource.TideAdminRealmResource} is no longer
 * built or deployed — only {@code iga-core} ships), those routes returned 404 because
 * no provider with id {@code tideAdminResources} was registered in the deployed jar.
 *
 * <p>This resource restores the URL surface from inside the deployed {@code iga-core}
 * jar. It is split deliberately:
 *
 * <ul>
 *   <li><b>{@code get-required-action-link}</b> is fully implemented. It depends only on
 *       core Keycloak ({@link ExecuteActionsActionToken}, {@link LoginActionsService})
 *       — none of the removed {@code org.tidecloak.base.iga.*} /
 *       {@code org.tidecloak.jpa.entities.*} monolith classes — so it ports cleanly and
 *       has no overlap with the {@code /iga/*} change-request flow.</li>
 *   <li><b>{@code add-review} / {@code add-rejection} / {@code trigger-license-signing}</b>
 *       are routed (no longer 404) but intentionally return {@code 410 Gone}. Their old
 *       implementation in {@code TideAdminRealmResource} relied on
 *       {@code ChangesetRequestAdapter.saveAdminAuthorizaton/saveAdminRejection},
 *       {@code RealmLicenseProcessor} and the {@code ChangeSetProcessor} factory — all
 *       removed by the decoupling — and the approve/reject/licensing semantics have moved
 *       to the {@code /iga/*} change-request flow
 *       ({@code /iga/change-requests/{id}/authorize}, {@code .../deny},
 *       {@code /iga/licensing/trigger}). Resurrecting the old code path would not compile
 *       and would conflict with the new flow, so these endpoints fail closed with a clear
 *       message instead.</li>
 *   <li><b>{@code add-authorization} / {@code new-voucher}</b> are routed but return
 *       {@code 410 Gone}. They are declared in the admin-client {@code tideProvider} but
 *       are <em>not invoked</em> anywhere in the admin UI, and never existed as routes in
 *       the old {@code TideAdminRealmResource} either.</li>
 * </ul>
 *
 * <p>{@code @Vetoed} keeps Quarkus ARC from trying to treat this admin sub-resource (with
 * its non-CDI constructor params) as a CDI bean, mirroring the other iga-core admin
 * sub-resources.
 */
@Path("tideAdminResources")
@Vetoed
public class TideAdminResourcesResource {

    protected static final Logger logger = Logger.getLogger(TideAdminResourcesResource.class);

    private final KeycloakSession session;
    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;

    public TideAdminResourcesResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth) {
        this.session = session;
        this.realm = realm;
        this.auth = auth;
    }

    // -------------------------------------------------------------------------
    // POST /tideAdminResources/get-required-action-link
    // Fully restored. Clean dependency surface (core Keycloak only).
    // -------------------------------------------------------------------------
    @POST
    @Path("get-required-action-link")
    public Response getRequiredActionLink(
            @Parameter(description = "Select User Id") @QueryParam("userId") String userId,
            @Parameter(description = "Redirect uri") @QueryParam(OIDCLoginProtocol.REDIRECT_URI_PARAM) String redirectUri,
            @Parameter(description = "Client id") @QueryParam(OIDCLoginProtocol.CLIENT_ID_PARAM) String clientId,
            @Parameter(description = "Number of seconds after which the generated token expires") @QueryParam("lifespan") Integer lifespan,
            @Parameter(description = "Required actions the user needs to complete") List<String> actions
    ) {
        UserModel user = session.users().getUserById(realm, userId);
        auth.users().requireManage(user);

        int expiration = Time.currentTime() + lifespan;
        ExecuteActionsActionToken token =
                new ExecuteActionsActionToken(user.getId(), user.getEmail(), expiration, actions, redirectUri, clientId);
        try {
            var builder = LoginActionsService.actionTokenProcessor(session.getContext().getUri());
            builder.queryParam("key", token.serialize(session, realm, session.getContext().getUri()));

            String link = builder.build(realm.getName()).toString();
            return Response.status(200).entity(link).type(MediaType.TEXT_PLAIN).build();

        } catch (Exception e) {
            throw ErrorResponse.error("Failed to get link tide account URL " + e.getMessage(),
                    Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    // -------------------------------------------------------------------------
    // The routes below are restored to the URL surface (no longer 404) but fail
    // closed: their old behaviour depended on monolith classes removed by the IGA
    // decoupling and/or has migrated to the /iga/* change-request flow.
    // -------------------------------------------------------------------------

    @POST
    @Path("add-review")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response addReview() {
        return gone("add-review",
                "Recording an approval outcome has moved to the /iga change-request flow "
                        + "(POST /admin/realms/{realm}/iga/change-requests/{id}/authorize).");
    }

    @POST
    @Path("add-rejection")
    public Response addRejection() {
        return gone("add-rejection",
                "Recording a rejection outcome has moved to the /iga change-request flow "
                        + "(POST /admin/realms/{realm}/iga/change-requests/{id}/deny).");
    }

    @POST
    @Path("add-authorization")
    public Response addAuthorization() {
        return gone("add-authorization",
                "This endpoint is no longer provided; the admin UI does not call it. "
                        + "Authorization is handled by the /iga change-request flow.");
    }

    @POST
    @Path("new-voucher")
    public Response newVoucher() {
        return gone("new-voucher",
                "This endpoint is no longer provided; the admin UI does not call it.");
    }

    @POST
    @Path("trigger-license-signing")
    public Response triggerLicenseSigning() {
        return gone("trigger-license-signing",
                "License signing has moved to the /iga flow "
                        + "(POST /admin/realms/{realm}/iga/licensing/trigger).");
    }

    private Response gone(String route, String detail) {
        auth.realm().requireManageRealm();
        logger.infof("tideAdminResources/%s is routed but deprecated post-IGA-decoupling: %s", route, detail);
        return Response.status(Response.Status.GONE)
                .entity("Endpoint /tideAdminResources/" + route + " is no longer available. " + detail)
                .type(MediaType.TEXT_PLAIN)
                .build();
    }
}
