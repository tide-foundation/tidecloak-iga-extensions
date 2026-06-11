package org.tidecloak.iga.rest;

import jakarta.enterprise.inject.Vetoed;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
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
import org.tidecloak.iga.providers.IgaSystemProvisionerProvider;

import java.util.List;
import java.util.Map;

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

    /**
     * Required-action alias for the Tide link-account flow. Mirrors
     * {@code org.tidecloak.idp...LinkTideAccount.PROVIDER_ID}, which lives in the
     * idp-extensions module and is not on iga-core's classpath, so the literal is
     * duplicated here intentionally.
     */
    private static final String LINK_TIDE_ACCOUNT_ACTION = "link-tide-account-action";

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

        // Invite-eligibility gate (IGA on): when IGA is enabled and this is a Tide
        // link-account invite, the target user must satisfy BOTH conditions before a
        // link can be issued — this endpoint is the SINGLE point of enforcement:
        //   1. the user carries attribute tideInvitable == "true" (admin has marked
        //      the user as eligible to be invited; same attribute the idp-extensions
        //      TideIdpAdminRealmResource guard reads), and
        //   2. the user's Tide identity is already committed (attestation present).
        // Each failure returns a distinct, user-facing reason so the UI can tell the
        // admin exactly why the link was withheld. Non-IGA realms and users that
        // satisfy both conditions are unaffected and still get the link as today.
        // Action alias mirrors org.tidecloak.idp...LinkTideAccount.PROVIDER_ID
        // ("link-tide-account-action"), which is not on iga-core's classpath.
        boolean isIgaEnabled = "true".equalsIgnoreCase(realm.getAttribute("isIGAEnabled"));
        boolean isTideLinkInvite = actions != null && actions.contains(LINK_TIDE_ACCOUNT_ACTION);
        if (isIgaEnabled && isTideLinkInvite) {
            boolean invitable = "true".equals(user.getFirstAttribute("tideInvitable"));
            if (!invitable) {
                throw ErrorResponse.error(
                        "This user cannot be invited: the 'tideInvitable' attribute is not set to true.",
                        Response.Status.BAD_REQUEST);
            }
            boolean committed = session.getProvider(IgaSystemProvisionerProvider.class)
                    .isUserIdentityCommitted(realm, userId);
            if (!committed) {
                throw ErrorResponse.error(
                        "This user must be approved and committed before a Tide invite link can be generated.",
                        Response.Status.BAD_REQUEST);
            }
        }

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
    // GET /tideAdminResources/users/{userId}/committed
    // Read-only: lets the admin UI proactively disable the invite-link action for
    // users who are not yet eligible. Mirrors the get-required-action-link gate:
    // IGA-off folds committed=true so the UI never disables on committed when IGA
    // is off; tideInvitable always reflects the stored attribute regardless of IGA
    // state so a future UI consumer (e.g. the Send Email path) can read both
    // eligibility signals from one call without a new endpoint.
    // -------------------------------------------------------------------------
    @GET
    @Path("users/{userId}/committed")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getUserCommitted(@PathParam("userId") String userId) {
        UserModel user = session.users().getUserById(realm, userId);
        // View-level read; mirrors the per-user authorization this resource uses
        // for get-required-action-link (auth.users().requireManage(user)).
        auth.users().requireView(user);

        boolean isIgaEnabled = "true".equalsIgnoreCase(realm.getAttribute("isIGAEnabled"));
        boolean committed = !isIgaEnabled
                || session.getProvider(IgaSystemProvisionerProvider.class)
                          .isUserIdentityCommitted(realm, userId);
        boolean invitable = "true".equals(user.getFirstAttribute("tideInvitable"));
        return Response.ok(Map.of("committed", committed, "tideInvitable", invitable)).build();
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
