package org.tidecloak.TideResource;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.actiontoken.execactions.ExecuteActionsActionToken;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.common.util.Time;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.midgard.Midgard;
import org.midgard.models.AdminAuthorization;
import org.midgard.models.InitializerCertificateModel.InitializerCertifcate;
import org.midgard.models.RuleDefinition;
import org.midgard.models.UserContext.UserContext;
import org.midgard.models.VendorData;
import org.tidecloak.iga.ChangeSetProcessors.ChangeSetProcessorFactory;
import org.tidecloak.iga.interfaces.ChangesetRequestAdapter;
import org.tidecloak.jpa.entities.UserClientAccessProofEntity;
import org.tidecloak.jpa.entities.drafting.TideClientDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideRoleDraftEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.shared.enums.WorkflowType;
import org.tidecloak.shared.enums.models.WorkflowParams;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.stream.Collectors;

import static org.tidecloak.iga.TideRequests.TideRoleRequests.*;
import static org.tidecloak.shared.utils.UserContextDraftUtil.findDraftsNotInAccessProof;

public class TideAdminRealmResource {

    private final KeycloakSession session;
    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;
    public static final String tideRealmAdminRole = "tide-realm-admin";
    protected static final String tideVendorKeyId = "tide-vendor-key";

    protected static final Logger logger = Logger.getLogger(TideAdminRealmResource.class);
    public TideAdminRealmResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth) {
        this.session = session;
        this.realm = realm;
        this.auth = auth;
    }

    @POST
    @Path("add-authorization")
    @Produces(MediaType.TEXT_PLAIN)
    public Response AddAuthorization(@FormParam("changeSetId") String changeSetId, @FormParam("actionType") String actionType, @FormParam("changeSetType") String changeSetType, @FormParam("authorizerApproval") String authorizerApproval, @FormParam("authorizerAuthentication") String authorizerAuthentication ) throws Exception {
        try {
            RoleModel role = session.getContext().getRealm().getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID).getRole(tideRealmAdminRole);
            auth.adminAuth().getUser().hasRole(role);

            ComponentModel componentModel = session.getContext().getRealm().getComponentsStream()
                    .filter(x -> tideVendorKeyId.equals(x.getProviderId()))  // Use .equals for string comparison
                    .findFirst()
                    .orElse(null);

            if(componentModel == null) {
                logger.warn("There is no tide-vendor-key component set up for this realm, " + session.getContext().getRealm());
                return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, "There is no tide-vendor-key component set up for this realm, " + session.getContext().getRealm());
            }
            MultivaluedHashMap<String, String> tideVendorKeyConfig = componentModel.getConfig();
            ObjectMapper objectMapper = new ObjectMapper();
            String currentSecretKeys = tideVendorKeyConfig.getFirst("clientSecret");

            SecretKeys secretKeys = objectMapper.readValue(currentSecretKeys, SecretKeys.class);
            String vrk = secretKeys.activeVrk;

            VendorData vendorData = Midgard.DecryptVendorData(authorizerAuthentication, vrk);

            ChangesetRequestAdapter.saveAdminAuthorizaton(session, changeSetType, changeSetId, actionType, auth.adminAuth().getUser(), vendorData.AuthToken, vendorData.blindSig, authorizerApproval);

            return buildResponse(200, "Successfully added admin authorization to changeSetRequest with id " + changeSetId);

        } catch (Exception e) {
            logger.error("Error adding authorization to change set request with ID: " + changeSetId +"." + Arrays.toString(e.getStackTrace()));
            return  buildResponse(500, "Error adding authorization to change set request with ID: " + changeSetId +" ." + e.getMessage());
        }
    }

    @POST
    @Path("add-rejection")
    @Produces(MediaType.TEXT_PLAIN)
    public Response AddRejection(@FormParam("changeSetId") String changeSetId, @FormParam("actionType") String actionType, @FormParam("changeSetType") String changeSetType) throws Exception {
        try {
            RoleModel role = session.getContext().getRealm().getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID).getRole(tideRealmAdminRole);
            auth.adminAuth().getUser().hasRole(role);

            ComponentModel componentModel = session.getContext().getRealm().getComponentsStream()
                    .filter(x -> tideVendorKeyId.equals(x.getProviderId()))  // Use .equals for string comparison
                    .findFirst()
                    .orElse(null);

            if(componentModel == null) {
                logger.warn("There is no tide-vendor-key component set up for this realm, " + session.getContext().getRealm());
                return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, "There is no tide-vendor-key component set up for this realm, " + session.getContext().getRealm());
            }
            ChangesetRequestAdapter.saveAdminRejection(session, changeSetType, changeSetId, actionType, auth.adminAuth().getUser());

            return buildResponse(200, "Successfully added admin rejection to changeSetRequest with id " + changeSetId);

        } catch (Exception e) {
            logger.error("Error adding rejection to change set request with ID: " + changeSetId +"." + Arrays.toString(e.getStackTrace()));
            return  buildResponse(500, "Error adding rejection to change set request with ID: " + changeSetId +" ." + e.getMessage());
        }
    }


    @POST
    @Path("new-voucher")
    @Produces(MediaType.TEXT_PLAIN)
    public Response GetAdminVouchers(@FormParam("voucherRequest") String voucherRequest){
        try{
            auth.realm().requireManageRealm();
            // Now that we know this is an admin - we provided whatever voucher they want
            return Response.status(200)
                    .header("Access-Control-Allow-Origin", "*")
                    .entity(getVouchers(voucherRequest))
                    .type(MediaType.TEXT_PLAIN)
                    .build();

        }catch(Exception ex){
            ex.printStackTrace();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("File upload failed: " + ex.getMessage()).type(MediaType.TEXT_PLAIN).build();
        }
    }
    private String getVouchers(
            String voucherRequest
    ) throws JsonProcessingException {
        ComponentModel componentModel = session.getContext().getRealm().getComponentsStream()
                .filter(x -> "tide-vendor-key".equals(x.getProviderId()))  // Use .equals for string comparison
                .findFirst()
                .orElse(null);

        MultivaluedHashMap<String, String> config = componentModel.getConfig();

        String currentSecretKeys = config.getFirst("clientSecret");
        ObjectMapper objectMapper = new ObjectMapper();
        SecretKeys secretKeys = objectMapper.readValue(currentSecretKeys, SecretKeys.class);
        String vvkId = config.getFirst("vvkId");


        String payerPublicKey = config.getFirst("payerPublic");

        // Always use the active vrk unless this is the initial license. The initial license does not yet have an active VRK and is waiting on the pending vrk to be commited
        String vrk = vvkId == null || vvkId.isEmpty() ? secretKeys.pendingVrk : secretKeys.activeVrk;
        String response = Midgard.GetVouchers(
                voucherRequest,
                config.getFirst("obfGVVK"),
                payerPublicKey,
                vrk);

        return response;
    }

    @POST
    @Path("toggle-iga")
    @Produces(MediaType.TEXT_PLAIN)

    public Response toggleIGA(@FormParam("isIGAEnabled") boolean isEnabled) throws Exception {
        try{
            RealmModel masterRealm = session.realms().getRealmByName(Config.getAdminRealm());
            if(realm.equals(masterRealm)){
                return buildResponse(400, "Master realm does not support IGA.");
            }

            EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
            auth.realm().requireManageRealm();
            session.getContext().getRealm().setAttribute("isIGAEnabled", isEnabled);
            logger.info("IGA has been toggled to : " + isEnabled);

            IdentityProviderModel tideIdp = session.identityProviders().getByAlias("tide");
            ComponentModel componentModel = realm.getComponentsStream()
                    .filter(x -> "tide-vendor-key".equals(x.getProviderId()))  // Use .equals for string comparison
                    .findFirst()
                    .orElse(null);

            // if IGA is on and tideIdp exists, we need to enable EDDSA as default sig
            if (tideIdp != null && componentModel != null) {
                String currentAlgorithm = session.getContext().getRealm().getDefaultSignatureAlgorithm();

                if (isEnabled) {
                    if (!"EdDSA".equalsIgnoreCase(currentAlgorithm)) {
                        session.getContext().getRealm().setDefaultSignatureAlgorithm("EdDSA");
                        logger.info("IGA has been enabled, default signature algorithm updated to EdDSA");
                    }
                    // Check the TideClientDraft Table and generate and AccessProofDetails that dont exist.
                    List<TideClientDraftEntity> entities = findDraftsNotInAccessProof(em, realm);
                    entities.forEach(c -> {
                        try {
                            WorkflowParams params = new WorkflowParams(DraftStatus.DRAFT, false, ActionType.CREATE, ChangeSetType.CLIENT);
                            ChangeSetProcessorFactory changeSetProcessorFactory = new ChangeSetProcessorFactory();
                            changeSetProcessorFactory.getProcessor(ChangeSetType.CLIENT).executeWorkflow(session, c, em, WorkflowType.REQUEST, params, null);
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    });
                } else {
                    // If tide IDP exists but IGA is disabled, default signature cannot be EdDSA
                    // TODO: Fix error: Uncaught server error: java.lang.RuntimeException: org.keycloak.crypto.SignatureException:
                    // Signing failed. java.security.InvalidKeyException: Unsupported key type (tide eddsa key)
                    if (currentAlgorithm.equalsIgnoreCase("EdDSA")) {
                        session.getContext().getRealm().setDefaultSignatureAlgorithm("RS256");
                        logger.info("IGA has been disabled, default signature algorithm updated to RS256");
                    }
                }
            }
            return buildResponse(200, "IGA has been toggled to : " + isEnabled);
        }catch(Exception e) {
            logger.error("Error toggling IGA on realm: ", e);
            throw e;
        }
    }

    @GET
    @Path("get-init-cert")
    @Produces(MediaType.TEXT_PLAIN)
    public Response GetInitCert(@QueryParam("roleId") String roleId) throws Exception {
        try{
            EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
            ObjectMapper objectMapper = new ObjectMapper();
            List<TideRoleDraftEntity> tideRoleDraftEntity = em.createNamedQuery("getRoleDraftByRoleId", TideRoleDraftEntity.class)
                    .setParameter("roleId", roleId).getResultList();

            if(tideRoleDraftEntity.isEmpty()){
                throw new Exception("Invalid request, no role draft entity found for this role ID: " + roleId);
            }

            InitializerCertifcate initializerCertifcate = InitializerCertifcate.FromString(tideRoleDraftEntity.get(0).getInitCert());

            Map<String, String> response = new HashMap<>();
            response.put("cert", Base64.getUrlEncoder().encodeToString(initializerCertifcate.Encode()));
            response.put("sig", tideRoleDraftEntity.get(0).getInitCertSig());

            return buildResponse(200, objectMapper.writeValueAsString(response));
        }catch(Exception e) {
            logger.error("Error getting init cert: ", e);
            throw e;
        }
    }

    @GET
    @Path("Create-Approval-URI")
    public Response CreateApprovalUri() throws URISyntaxException, JsonProcessingException {
        IdentityProviderModel tideIdp = session.identityProviders().getByAlias("tide");

        ComponentModel componentModel = realm.getComponentsStream()
                .filter(x -> "tide-vendor-key".equals(x.getProviderId()))  // Use .equals for string comparison
                .findFirst()
                .orElse(null);

        if(componentModel == null) {
            return buildResponse(400, "There is no tide-vendor-key component set up for this realm, " + realm.getName());
        }

        MultivaluedHashMap<String, String> config = componentModel.getConfig();

        ObjectMapper objectMapper = new ObjectMapper();
        String defaultAdminUiDomain = tideIdp.getConfig().get("changeSetEndpoint");
        String customAdminUiDomain = tideIdp.getConfig().get("CustomAdminUIDomain");
        String redirectUrlSig = tideIdp.getConfig().get("changeSetURLSig");

        URI redirectURI = new URI(defaultAdminUiDomain);
        UserSessionModel userSession = session.sessions().getUserSession(realm, auth.adminAuth().getToken().getSessionId());
        String port = redirectURI.getPort() == -1 ? "" : ":" + redirectURI.getPort();
        String voucherURL = redirectURI.getScheme() + "://" + redirectURI.getHost() + port + "/realms/" +
                session.getContext().getRealm().getName() + "/tidevouchers/fromUserSession?sessionId=" +userSession.getId();

        URI uri = Midgard.CreateURL(
                auth.adminAuth().getToken().getSessionId(),
                redirectURI.toString(),//userSession.getNote("redirectUri"),
                redirectUrlSig,
                tideIdp.getConfig().get("homeORKurl"),
                config.getFirst("clientId"),
                config.getFirst("gVRK"),
                config.getFirst("gVRKCertificate"),
                realm.isRegistrationAllowed(),
                Boolean.valueOf(tideIdp.getConfig().get("backupOn")),
                tideIdp.getConfig().get("LogoURL"),
                tideIdp.getConfig().get("ImageURL"),
                "approval",
                tideIdp.getConfig().get("settingsSig"),
                voucherURL, //voucherURL,
                ""
        );

        URI customDomainUri = null;
        if(customAdminUiDomain != null) {
            customDomainUri = Midgard.CreateURL(
                    auth.adminAuth().getToken().getSessionId(),
                    customAdminUiDomain,//userSession.getNote("redirectUri"),
                    tideIdp.getConfig().get("customAdminUIDomainSig"),
                    tideIdp.getConfig().get("homeORKurl"),
                    config.getFirst("clientId"),
                    config.getFirst("gVRK"),
                    config.getFirst("gVRKCertificate"),
                    realm.isRegistrationAllowed(),
                    Boolean.valueOf(tideIdp.getConfig().get("backupOn")),
                    tideIdp.getConfig().get("LogoURL"),
                    tideIdp.getConfig().get("ImageURL"),
                    "approval",
                    tideIdp.getConfig().get("settingsSig"),
                    voucherURL, //voucherURL,
                    ""
            );
        }

        Map<String, String> response = new HashMap<>();
        response.put("message", "Opening Enclave to request approval.");
        response.put("uri", String.valueOf(uri));
        if(customAdminUiDomain != null) {
            response.put("customDomainUri", String.valueOf(customDomainUri));
        }

        return buildResponse(200, objectMapper.writeValueAsString(response));
    }

    @POST
    @Path("create-authorization")
    @Produces(MediaType.TEXT_PLAIN)
    public Response CreateAuthorization(@QueryParam("clientId") String clientId, @FormParam("authorizerApproval") String authorizerApproval, @FormParam("authorizerAuthentication") String authorizerAuthentication ) throws Exception {
        try {
            EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
            UserModel user = auth.adminAuth().getUser();

            ComponentModel componentModel = session.getContext().getRealm().getComponentsStream()
                    .filter(x -> tideVendorKeyId.equals(x.getProviderId()))  // Use .equals for string comparison
                    .findFirst()
                    .orElse(null);

            if(componentModel == null) {
                logger.warn("There is no tide-vendor-key component set up for this realm, " + session.getContext().getRealm());
                return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, "There is no tide-vendor-key component set up for this realm, " + session.getContext().getRealm());
            }
            MultivaluedHashMap<String, String> tideVendorKeyConfig = componentModel.getConfig();
            ObjectMapper objectMapper = new ObjectMapper();
            String currentSecretKeys = tideVendorKeyConfig.getFirst("clientSecret");

            SecretKeys secretKeys = objectMapper.readValue(currentSecretKeys, SecretKeys.class);
            String vrk = secretKeys.activeVrk;

            VendorData vendorData = Midgard.DecryptVendorData(authorizerAuthentication, vrk);
            ;
            UserEntity userEntity = em.find(UserEntity.class, user.getId());
            List<UserClientAccessProofEntity> userClientAccessProofEntity = em.createNamedQuery("getAccessProofByUserAndClientId", UserClientAccessProofEntity.class)
                    .setParameter("user", userEntity)
                    .setParameter("clientId", realm.getClientByClientId(clientId).getId()).getResultList();

            if ( userClientAccessProofEntity == null || userClientAccessProofEntity.isEmpty() ){
                throw new Exception("This user does not have any roles for this client: Client UID: " + clientId + ", User ID: " + userEntity.getId());
            }

            UserContext adminContext = new UserContext(userClientAccessProofEntity.get(0).getAccessProof());
            AdminAuthorization adminAuthorization = new AdminAuthorization(adminContext.ToString(), userClientAccessProofEntity.get(0).getAccessProofSig(), vendorData.AuthToken, vendorData.blindSig, authorizerApproval);


            return buildResponse(200, adminAuthorization.ToString());

        } catch (Exception e) {
            logger.error("Error creating authorization" + Arrays.toString(e.getStackTrace()));
            return  buildResponse(500, "Error creating authorization" + e.getMessage());
        }
    }

//    @GET
//    @Path("get-init-cert")
//    @Produces(MediaType.TEXT_PLAIN)
//    public Response GetInitCert(@QueryParam("roleId") String roleId) throws Exception {
//        try{
//            EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
//            ObjectMapper objectMapper = new ObjectMapper();
//            List<TideRoleDraftEntity> tideRoleDraftEntity = em.createNamedQuery("getRoleDraftByRoleId", TideRoleDraftEntity.class)
//                    .setParameter("roleId", roleId).getResultList();
//
//            if(tideRoleDraftEntity.isEmpty()){
//                throw new Exception("Invalid request, no role draft entity found for this role ID: " + roleId);
//            }
//
//            Map<String, String> response = new HashMap<>();
//            response.put("cert", tideRoleDraftEntity.get(0).getInitCert());
//            response.put("sig", tideRoleDraftEntity.get(0).getInitCertSig());
//
//            return buildResponse(200, objectMapper.writeValueAsString(response));
//        }catch(Exception e) {
//            logger.error("Error getting init cert: ", e);
//            throw e;
//        }
//    }

    @POST
    @Path("get-required-action-link")
    public Response getRequiredActionLink(
            @Parameter(description = "Select User Id") @QueryParam("userId") String userId,
            @Parameter(description = "Redirect uri") @QueryParam(OIDCLoginProtocol.REDIRECT_URI_PARAM) String redirectUri,
            @Parameter(description = "Client id") @QueryParam(OIDCLoginProtocol.CLIENT_ID_PARAM) String clientId,
            @Parameter(description = "Number of seconds after which the generated token expires") @QueryParam("lifespan") Integer lifespan,
            @Parameter(description = "Required actions the user needs to complete") List<String> actions
    ){
        UserModel user = session.users().getUserById(realm, userId);
        auth.users().requireManage(user);

        int expiration = Time.currentTime() + lifespan;
        ExecuteActionsActionToken token = new ExecuteActionsActionToken(user.getId(), user.getEmail(), expiration, actions, redirectUri, clientId);
        try {
            UriBuilder builder = LoginActionsService.actionTokenProcessor(session.getContext().getUri());
            builder.queryParam("key", token.serialize(session, realm, session.getContext().getUri()));

            String link = builder.build(realm.getName()).toString();

            return buildResponse(200, link);

        } catch (Exception e) {
            throw ErrorResponse.error("Failed to get link tide account URL " + e.getMessage(), Response.Status.INTERNAL_SERVER_ERROR);
        }


    }

    private Response buildResponse(int status, String message) {
        return Response.status(status)
                .entity(message)
                .type(MediaType.TEXT_PLAIN)
                .build();
    }
    
    public static class SecretKeys {
        public String activeVrk;
        public String pendingVrk;
        public String VZK;
        public List<String> history = new ArrayList<>();

        // Method to add a new entry to the history
        public void addToHistory(String newEntry) {
            history.add(newEntry);
        }
    }
}
