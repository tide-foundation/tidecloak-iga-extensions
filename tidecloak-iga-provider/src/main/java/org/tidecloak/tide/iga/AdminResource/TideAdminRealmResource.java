package org.tidecloak.tide.iga.AdminResource;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.xml.bind.DatatypeConverter;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.jboss.logging.Logger;
import org.keycloak.authentication.actiontoken.execactions.ExecuteActionsActionToken;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.common.util.Time;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.cache.CacheRealmProvider;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.midgard.Midgard;
import org.midgard.models.*;
import org.midgard.models.InitializerCertificateModel.InitializerCertifcate;
import org.midgard.models.UserContext.UserContext;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessor;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessorFactory;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessorFactoryProvider;
import org.tidecloak.base.iga.interfaces.ChangesetRequestAdapter;
import org.tidecloak.base.iga.interfaces.models.RequestType;
import org.tidecloak.base.iga.interfaces.models.RequestedChanges;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.jpa.entities.LicensingDraftEntity;
import org.tidecloak.jpa.entities.UserClientAccessProofEntity;
import org.tidecloak.jpa.entities.drafting.TideRoleDraftEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.shared.enums.WorkflowType;
import org.tidecloak.shared.enums.models.WorkflowParams;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.stream.Stream;

import static org.keycloak.models.credential.dto.PasswordSecretData.logger;

public class TideAdminRealmResource {

    private final KeycloakSession session;
    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;
    public static final String tideRealmAdminRole = "tide-realm-admin";
    protected static final String tideVendorKeyId = "tide-vendor-key";
    private final ChangeSetProcessor<LicensingDraftEntity> processor;


    protected static final Logger logger = Logger.getLogger(TideAdminRealmResource.class);
    public TideAdminRealmResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth) {
        this.session = session;
        this.realm = realm;
        this.auth = auth;
        ChangeSetProcessorFactory factory = ChangeSetProcessorFactoryProvider.getFactory();
        this.processor = factory.getProcessor(ChangeSetType.REALM_LICENSING);
    }

    @GET
    @Path("change-set/licensing/requests")
    public Response getRequestedChangesForUsers() {
        auth.realm().requireManageRealm();
        if(!BasicIGAUtils.isIGAEnabled(realm)){
            return Response.ok().entity(new ArrayList<>()).build();
        }
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<RequestedChanges> changes = new ArrayList<>(processLicensingRequests(em, realm));
        return Response.ok(changes).build();
    }

    @POST
    @Path("trigger-license-signing")
    @Produces(MediaType.TEXT_PLAIN)
    public Response triggerLicensing(@QueryParam("gvrk") String gvrk) {
        try {
            auth.realm().requireManageRealm();
            final String realmId = realm.getId();

            // 1) Only proceed if license is active (truthy). Anything else blocks.
            boolean licenseActive = false;
            try {
                // Use whatever “active” signal you already expose. This one returns a boolean.
                licenseActive = IsPendingLicenseActive(realm);
            } catch (Exception e) {
                // Treat errors as “not active”
                licenseActive = false;
            }

            if (!licenseActive) {
                return buildResponse(
                        409,
                        "License is not active yet. Please try again after the license becomes active."
                );
            }

            // 2) Prevent duplicate drafts for this realm
            EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
            List<LicensingDraftEntity> drafts = em
                    .createNamedQuery("LicensingDraft.findByRealm", LicensingDraftEntity.class)
                    .setParameter("realmId", realmId)
                    .getResultList();

            if (!drafts.isEmpty()) {
                return buildResponse(200, "Licensing already triggered, awaiting review.");
            }
            String igaAttribute = realm.getAttribute("isIGAEnabled");
            boolean isIGAEnabled = igaAttribute != null && igaAttribute.equalsIgnoreCase("true");

            // Just sign with VRK
            if(!isIGAEnabled){
                try {
                    RotateVrk(realmId, session, gvrk);
                    return buildResponse(200, "Licensing has been rotated.");
                }catch (Exception e) {
                    logger.error("Error rotating license", e);
                    return buildResponse(500, "Error rotating license: " + e.getMessage());
                }

            }

            // 3) Create draft
            LicensingDraftEntity draft = new LicensingDraftEntity();
            draft.setId(org.keycloak.models.utils.KeycloakModelUtils.generateId());
            draft.setDraftStatus(DraftStatus.DRAFT);
            draft.setAction(ActionType.CREATE);
            draft.setRealmId(realmId);
            em.persist(draft);
            em.flush();

            // 4) Kick workflow — LICENSING changeset
            WorkflowParams params = new WorkflowParams(
                    DraftStatus.DRAFT,
                    false,
                    ActionType.CREATE,
                    ChangeSetType.REALM_LICENSING
            );
            processor.executeWorkflow(session, draft, em, WorkflowType.REQUEST, params, null);

            return buildResponse(200, "Licensing Change Request created and awaiting quorum approval.");

        } catch (Exception e) {
            logger.error("Error creating licensing change request", e);
            return buildResponse(500, "Error creating licensing change request: " + e.getMessage());
        }
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

    private static List<RequestedChanges> processLicensingRequests(EntityManager em, RealmModel realm) {
        // Get all pending changes, records that do not have an active delete status or active draft status
        List<LicensingDraftEntity> drafts = em
                .createNamedQuery("LicensingDraft.findByRealmAndStatusNotEqual",
                        LicensingDraftEntity.class)
                .setParameter("realmId", realm.getId())
                .setParameter("status", DraftStatus.ACTIVE)
                .getResultList();

        return processLicensingRequests(em, realm, drafts);
    }

    public static List<RequestedChanges> processLicensingRequests(EntityManager em, RealmModel realm, List<LicensingDraftEntity> entities) {
        List<RequestedChanges> changes = new ArrayList<>();

        for (LicensingDraftEntity e : entities) {
            em.lock(e, LockModeType.PESSIMISTIC_WRITE); // Lock the entity to prevent concurrent modifications

            String actionDescription = "Tide offboarding has been requested";
            RequestedChanges requestChange = new RequestedChanges(actionDescription, ChangeSetType.REALM_LICENSING, RequestType.SETTINGS, null, realm.getId(), ActionType.CREATE, e.getChangeRequestId(), List.of(), e.getDraftStatus(), DraftStatus.NULL);
            changes.add(requestChange);
        }
        return changes;
    }

    private static SignRequestSettingsMidgard ConstructSignSettings(MultivaluedHashMap<String, String> keyProviderConfig, String vrk){
        int threshold = Integer.parseInt(System.getenv("THRESHOLD_T"));
        int max = Integer.parseInt(System.getenv("THRESHOLD_N"));

        SignRequestSettingsMidgard settings = new SignRequestSettingsMidgard();
        settings.VVKId = keyProviderConfig.getFirst("vvkId");
        settings.HomeOrkUrl = keyProviderConfig.getFirst("systemHomeOrk");
        settings.PayerPublicKey = keyProviderConfig.getFirst("payerPublic");
        settings.ObfuscatedVendorPublicKey = keyProviderConfig.getFirst("obfGVVK");
        settings.VendorRotatingPrivateKey = vrk;
        settings.Threshold_T = threshold;
        settings.Threshold_N = max;

        return settings;
    }
    private static boolean IsPendingLicenseActive(RealmModel realm) throws Exception {
        try {
            ComponentModel componentModel;
            try (Stream<ComponentModel> components = realm.getComponentsStream()) {
                componentModel = components
                        .filter(c -> "tide-vendor-key".equals(c.getProviderId()))
                        .findAny() // findAny can be more efficient than findFirst if ordering doesn't matter
                        .orElse(null);
            }

            if(componentModel == null) {
                logger.warn("There is no tide-vendor-key component set up for this realm, " + realm.getName());
                throw new BadRequestException("There is no tide-vendor-key component set up for this realm, " + realm.getName());
            }

            MultivaluedHashMap<String, String> config = componentModel.getConfig();
            String homeOrkUrl = config.getFirst("systemHomeOrk");
            String payerPublic = config.getFirst("payerPublic");
            String pendingVendorId = config.getFirst("pendingVendorId");

            return  Midgard.IsLicenseActive(homeOrkUrl, payerPublic, pendingVendorId);

        } catch (Exception e) {
            logger.warn("Could not check if pending license is active", e);// may be committed by JTA which can't
            e.printStackTrace();
            throw new Exception("Could not check if pending license is active ");

        }
    }
    public static void RotateVrk(String realmId, KeycloakSession session, String gVRK) throws JsonProcessingException {
        try {
            RealmModel realm = session.realms().getRealm(realmId);
            ComponentModel componentModel;
            try (Stream<ComponentModel> components = realm.getComponentsStream()) {
                componentModel = components
                        .filter(c -> "tide-vendor-key".equals(c.getProviderId()))
                        .findAny() // findAny can be more efficient than findFirst if ordering doesn't matter
                        .orElse(null);
            }

            if(componentModel == null) {
                logger.warn("There is no tide-vendor-key component set up for this realm, " + realm.getName());
                throw new BadRequestException("There is no tide-vendor-key component set up for this realm, " + realm.getName());
            }

            MultivaluedHashMap<String, String> config = componentModel.getConfig();
            ObjectMapper objectMapper = new ObjectMapper();
            String currentSecretKeys = config.getFirst("clientSecret");
            SecretKeys secretKeys = objectMapper.readValue(currentSecretKeys, SecretKeys.class);;

            SignRequestSettingsMidgard settings = ConstructSignSettings(config, secretKeys.activeVrk);

            ModelRequest req = ModelRequest.New("RotateVRK", "1", "VRK:1", DatatypeConverter.parseHexBinary(gVRK));

            req.SetAuthorization(Midgard.SignWithVrk(req.GetDataToAuthorize(), settings.VendorRotatingPrivateKey));
            req.SetAuthorizer(DatatypeConverter.parseHexBinary(config.getFirst("gVRK")));
            req.SetAuthorizerCertificate(Base64.getDecoder().decode(config.getFirst("gVRKCertificate")));

            SignatureResponse response = Midgard.SignModel(settings, req);


            // Add pending GVRK signature to configuration. The pending configuartion is now signed/authorized and is awaiting SWITCH on current license expiry.
            config.putSingle("pendingGVRKCertificate", response.Signatures[0]);

            componentModel.setConfig(config);
            realm.updateComponent(componentModel);

            CacheRealmProvider cacheRealmProvider = session.getProvider(CacheRealmProvider.class);
            cacheRealmProvider.clear();

            logger.info("Successfully rotated VRK, configuration pending switch on current license expiry");

        } catch(Exception e){
            logger.warn("Could not generate and save tide network keys", e);// may be committed by JTA which can't
            e.printStackTrace();
            throw e;
        }
    }
}
