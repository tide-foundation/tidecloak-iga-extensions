package org.tidecloak.tide.iga.AdminResource;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.jboss.logging.Logger;
import org.keycloak.authentication.actiontoken.execactions.ExecuteActionsActionToken;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.common.util.Time;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.midgard.Midgard;
import org.midgard.models.AdminAuthorization;
import org.midgard.models.UserContext.UserContext;
import org.midgard.models.VendorData;
import org.tidecloak.base.iga.interfaces.ChangesetRequestAdapter;
import org.tidecloak.jpa.entities.UserClientAccessProofEntity;
import org.tidecloak.shared.models.SecretKeys;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;

public class TideAdminRealmResource {

    private final KeycloakSession session;
    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;

    public static final String TIDE_REALM_ADMIN_ROLE = "tide-realm-admin";
    protected static final String TIDE_VENDOR_KEY_PROVIDER_ID = "tide-vendor-key";

    protected static final Logger logger = Logger.getLogger(TideAdminRealmResource.class);

    public TideAdminRealmResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth) {
        this.session = session;
        this.realm = realm;
        this.auth = auth;
    }

    @POST
    @Path("add-authorization")
    @Produces(MediaType.TEXT_PLAIN)
    public Response addAuthorization(@FormParam("changeSetId") String changeSetId,
                                     @FormParam("actionType") String actionType,
                                     @FormParam("changeSetType") String changeSetType,
                                     @FormParam("authorizerApproval") String authorizerApproval,
                                     @FormParam("authorizerAuthentication") String authorizerAuthentication) {
        try {
            // Permission gate: require the tide-realm-admin role
            RoleModel adminRole = session.getContext().getRealm()
                    .getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID)
                    .getRole(TIDE_REALM_ADMIN_ROLE);
            if (!auth.adminAuth().getUser().hasRole(adminRole)) {
                return ErrorPage.error(session, null, Response.Status.FORBIDDEN, "Insufficient permission.");
            }

            ComponentModel componentModel = session.getContext().getRealm().getComponentsStream()
                    .filter(x -> TIDE_VENDOR_KEY_PROVIDER_ID.equals(x.getProviderId()))
                    .findFirst()
                    .orElse(null);

            if (componentModel == null) {
                String msg = "No tide-vendor-key component configured for realm " + realm.getName();
                logger.warn(msg);
                return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, msg);
            }

            MultivaluedHashMap<String, String> cfg = componentModel.getConfig();
            String secretBlob = cfg.getFirst("clientSecret");
            if (secretBlob == null || secretBlob.isBlank()) {
                return buildResponse(400, "Missing clientSecret in tide-vendor-key config");
            }

            ObjectMapper om = new ObjectMapper();
            SecretKeys secretKeys = om.readValue(secretBlob, SecretKeys.class);
            String vrk = (secretKeys.activeVrk != null && !secretKeys.activeVrk.isBlank())
                    ? secretKeys.activeVrk
                    : secretKeys.VZK;

            if (vrk == null || vrk.isBlank()) {
                return buildResponse(400, "No VRK available (activeVrk/VZK empty)");
            }

            VendorData vendorData = Midgard.DecryptVendorData(authorizerAuthentication, vrk);

            ChangesetRequestAdapter.saveAdminAuthorizaton(
                    session,
                    changeSetType,
                    changeSetId,
                    actionType,
                    auth.adminAuth().getUser(),
                    vendorData.AuthToken,
                    vendorData.blindSig,
                    authorizerApproval
            );

            return buildResponse(200, "Successfully added admin authorization to changeSetRequest " + changeSetId);

        } catch (Exception e) {
            logger.errorf(e, "Error adding authorization to change set request (id=%s)", changeSetId);
            return buildResponse(500, "Error adding authorization to change set request: " + e.getMessage());
        }
    }

    @POST
    @Path("add-rejection")
    @Produces(MediaType.TEXT_PLAIN)
    public Response addRejection(@FormParam("changeSetId") String changeSetId,
                                 @FormParam("actionType") String actionType,
                                 @FormParam("changeSetType") String changeSetType) {
        try {
            RoleModel adminRole = session.getContext().getRealm()
                    .getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID)
                    .getRole(TIDE_REALM_ADMIN_ROLE);
            if (!auth.adminAuth().getUser().hasRole(adminRole)) {
                return ErrorPage.error(session, null, Response.Status.FORBIDDEN, "Insufficient permission.");
            }

            ComponentModel componentModel = session.getContext().getRealm().getComponentsStream()
                    .filter(x -> TIDE_VENDOR_KEY_PROVIDER_ID.equals(x.getProviderId()))
                    .findFirst()
                    .orElse(null);

            if (componentModel == null) {
                String msg = "No tide-vendor-key component configured for realm " + realm.getName();
                logger.warn(msg);
                return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, msg);
            }

            ChangesetRequestAdapter.saveAdminRejection(session, changeSetType, changeSetId, actionType, auth.adminAuth().getUser());
            return buildResponse(200, "Successfully added admin rejection to changeSetRequest " + changeSetId);

        } catch (Exception e) {
            logger.errorf(e, "Error adding rejection to change set request (id=%s)", changeSetId);
            return buildResponse(500, "Error adding rejection to change set request: " + e.getMessage());
        }
    }

    @POST
    @Path("new-voucher")
    @Produces(MediaType.TEXT_PLAIN)
    public Response getAdminVouchers(@FormParam("voucherRequest") String voucherRequest) {
        try {
            auth.realm().requireManageRealm();
            return Response.status(200)
                    .header("Access-Control-Allow-Origin", "*")
                    .entity(getVouchers(voucherRequest))
                    .type(MediaType.TEXT_PLAIN)
                    .build();
        } catch (Exception ex) {
            logger.error("Voucher request failed", ex);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("Voucher request failed: " + ex.getMessage())
                    .type(MediaType.TEXT_PLAIN)
                    .build();
        }
    }

    private String getVouchers(String voucherRequest) throws JsonProcessingException {
        ComponentModel componentModel = session.getContext().getRealm().getComponentsStream()
                .filter(x -> TIDE_VENDOR_KEY_PROVIDER_ID.equals(x.getProviderId()))
                .findFirst()
                .orElse(null);

        if (componentModel == null) {
            throw new BadRequestException("No tide-vendor-key component configured for realm " + realm.getName());
        }

        MultivaluedHashMap<String, String> cfg = componentModel.getConfig();
        String secretBlob = cfg.getFirst("clientSecret");
        if (secretBlob == null || secretBlob.isBlank()) {
            throw new BadRequestException("Missing clientSecret in tide-vendor-key config");
        }

        ObjectMapper om = new ObjectMapper();
        SecretKeys secretKeys = om.readValue(secretBlob, SecretKeys.class);

        String vvkId = cfg.getFirst("vvkId");
        String payerPublicKey = cfg.getFirst("payerPublic");

        // Use active VRK if vvkId is present; otherwise pending VRK for initial license bootstrap.
        String vrk = (vvkId == null || vvkId.isEmpty()) ? secretKeys.pendingVrk : secretKeys.activeVrk;

        return Midgard.GetVouchers(
                voucherRequest,
                cfg.getFirst("obfGVVK"),
                payerPublicKey,
                vrk
        );
    }

    @GET
    @Path("get-init-cert")
    @Produces(MediaType.TEXT_PLAIN)
    public Response getInitCert(@QueryParam("roleId") String roleId) {
        // Wrappers removed in the new engine; role init cert is no longer fetched from TideRoleDraftEntity here.
        // If you still need this, wire it to your replay store (e.g., ReplayMetaStore) and return the compact cert.
        return buildResponse(400, "get-init-cert is not supported by the new engine (no draft wrappers).");
    }

    @GET
    @Path("Create-Approval-URI")
    public Response createApprovalUri() throws URISyntaxException, JsonProcessingException {
        IdentityProviderModel tideIdp = session.identityProviders().getByAlias("tide");

        ComponentModel componentModel = realm.getComponentsStream()
                .filter(x -> TIDE_VENDOR_KEY_PROVIDER_ID.equals(x.getProviderId()))
                .findFirst()
                .orElse(null);

        if (componentModel == null) {
            return buildResponse(400, "No tide-vendor-key component configured for realm " + realm.getName());
        }

        MultivaluedHashMap<String, String> cfg = componentModel.getConfig();

        ObjectMapper om = new ObjectMapper();
        String defaultAdminUiDomain = tideIdp.getConfig().get("changeSetEndpoint");
        String customAdminUiDomain  = tideIdp.getConfig().get("CustomAdminUIDomain");
        String redirectUrlSig       = tideIdp.getConfig().get("changeSetURLSig");

        URI redirectURI = new URI(defaultAdminUiDomain);
        UserSessionModel userSession = session.sessions().getUserSession(realm, auth.adminAuth().getToken().getSessionId());

        String port = (redirectURI.getPort() == -1) ? "" : ":" + redirectURI.getPort();
        String voucherURL = redirectURI.getScheme() + "://" + redirectURI.getHost() + port
                + "/realms/" + realm.getName()
                + "/tidevouchers/fromUserSession?sessionId=" + userSession.getId();

        URI uri = Midgard.CreateURL(
                auth.adminAuth().getToken().getSessionId(),
                redirectURI.toString(),
                redirectUrlSig,
                tideIdp.getConfig().get("homeORKurl"),
                cfg.getFirst("clientId"),
                cfg.getFirst("gVRK"),
                cfg.getFirst("gVRKCertificate"),
                realm.isRegistrationAllowed(),
                Boolean.parseBoolean(tideIdp.getConfig().getOrDefault("backupOn", "false")),
                tideIdp.getConfig().get("LogoURL"),
                tideIdp.getConfig().get("ImageURL"),
                "approval",
                tideIdp.getConfig().get("settingsSig"),
                voucherURL,
                ""
        );

        URI customDomainUri = null;
        if (customAdminUiDomain != null) {
            customDomainUri = Midgard.CreateURL(
                    auth.adminAuth().getToken().getSessionId(),
                    customAdminUiDomain,
                    tideIdp.getConfig().get("customAdminUIDomainSig"),
                    tideIdp.getConfig().get("homeORKurl"),
                    cfg.getFirst("clientId"),
                    cfg.getFirst("gVRK"),
                    cfg.getFirst("gVRKCertificate"),
                    realm.isRegistrationAllowed(),
                    Boolean.parseBoolean(tideIdp.getConfig().getOrDefault("backupOn", "false")),
                    tideIdp.getConfig().get("LogoURL"),
                    tideIdp.getConfig().get("ImageURL"),
                    "approval",
                    tideIdp.getConfig().get("settingsSig"),
                    voucherURL,
                    ""
            );
        }

        Map<String, String> response = new HashMap<>();
        response.put("message", "Opening Enclave to request approval.");
        response.put("uri", String.valueOf(uri));
        if (customDomainUri != null) {
            response.put("customDomainUri", String.valueOf(customDomainUri));
        }

        return buildResponse(200, om.writeValueAsString(response));
    }

    @POST
    @Path("create-authorization")
    @Produces(MediaType.TEXT_PLAIN)
    public Response createAuthorization(@QueryParam("clientId") String clientId,
                                        @FormParam("authorizerApproval") String authorizerApproval,
                                        @FormParam("authorizerAuthentication") String authorizerAuthentication) {
        try {
            EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
            UserModel user = auth.adminAuth().getUser();

            ComponentModel componentModel = session.getContext().getRealm().getComponentsStream()
                    .filter(x -> TIDE_VENDOR_KEY_PROVIDER_ID.equals(x.getProviderId()))
                    .findFirst()
                    .orElse(null);

            if (componentModel == null) {
                String msg = "No tide-vendor-key component configured for realm " + realm.getName();
                logger.warn(msg);
                return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, msg);
            }

            MultivaluedHashMap<String, String> cfg = componentModel.getConfig();
            ObjectMapper om = new ObjectMapper();
            String secretBlob = cfg.getFirst("clientSecret");
            if (secretBlob == null || secretBlob.isBlank()) {
                return buildResponse(400, "Missing clientSecret in tide-vendor-key config");
            }

            SecretKeys secretKeys = om.readValue(secretBlob, SecretKeys.class);
            String vrk = (secretKeys.activeVrk != null && !secretKeys.activeVrk.isBlank())
                    ? secretKeys.activeVrk
                    : secretKeys.VZK;

            if (vrk == null || vrk.isBlank()) {
                return buildResponse(400, "No VRK available (activeVrk/VZK empty)");
            }

            VendorData vendorData = Midgard.DecryptVendorData(authorizerAuthentication, vrk);

            UserEntity userEntity = em.find(UserEntity.class, user.getId());
            List<UserClientAccessProofEntity> proofs = em.createNamedQuery("getAccessProofByUserAndClientId", UserClientAccessProofEntity.class)
                    .setParameter("user", userEntity)
                    .setParameter("clientId", realm.getClientByClientId(clientId).getId())
                    .getResultList();

            if (proofs == null || proofs.isEmpty()) {
                throw new BadRequestException("User has no roles for client " + clientId + " (userId=" + userEntity.getId() + ")");
            }

            UserClientAccessProofEntity proof = proofs.get(0);
            UserContext adminContext = new UserContext(proof.getAccessProof());

            AdminAuthorization adminAuthorization = new AdminAuthorization(
                    adminContext.ToString(),
                    proof.getAccessProofSig(),
                    vendorData.AuthToken,
                    vendorData.blindSig,
                    authorizerApproval
            );

            return buildResponse(200, adminAuthorization.ToString());

        } catch (Exception e) {
            logger.error("Error creating authorization", e);
            return buildResponse(500, "Error creating authorization: " + e.getMessage());
        }
    }

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
        ExecuteActionsActionToken token = new ExecuteActionsActionToken(
                user.getId(),
                user.getEmail(),
                expiration,
                actions,
                redirectUri,
                clientId
        );
        try {
            UriBuilder builder = LoginActionsService.actionTokenProcessor(session.getContext().getUri());
            builder.queryParam("key", token.serialize(session, realm, session.getContext().getUri()));

            String link = builder.build(realm.getName()).toString();
            return buildResponse(200, link);

        } catch (Exception e) {
            throw ErrorResponse.error("Failed to get required action link: " + e.getMessage(),
                    Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    private Response buildResponse(int status, String message) {
        return Response.status(status)
                .entity(message)
                .type(MediaType.TEXT_PLAIN)
                .build();
    }
}
