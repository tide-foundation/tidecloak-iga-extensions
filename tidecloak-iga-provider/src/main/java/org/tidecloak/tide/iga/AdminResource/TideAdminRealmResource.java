package org.tidecloak.tide.iga.AdminResource;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import liquibase.change.Change;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.jboss.logging.Logger;
import org.keycloak.authentication.actiontoken.execactions.ExecuteActionsActionToken;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.common.util.Time;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.cache.CacheRealmProvider;
import org.keycloak.models.jpa.entities.ComponentEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.midgard.Midgard;
import org.midgard.models.*;
import org.midgard.models.UserContext.UserContext;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessor;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessorFactory;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessorFactoryProvider;
import org.tidecloak.base.iga.ChangeSetProcessors.processors.RealmLicenseProcessor;
import org.tidecloak.base.iga.interfaces.ChangesetRequestAdapter;
import org.tidecloak.base.iga.interfaces.models.ChangeSetTypeEntity;
import org.tidecloak.base.iga.interfaces.models.RequestType;
import org.tidecloak.base.iga.interfaces.models.RequestedChanges;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.jpa.entities.*;
import org.tidecloak.jpa.entities.AuthorizerEntity;
import org.tidecloak.jpa.entities.Licensing.LicenseHistoryEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.shared.enums.WorkflowType;
import org.tidecloak.shared.enums.models.WorkflowParams;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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
        if (!BasicIGAUtils.isIGAEnabled(realm)) {
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

            ComponentModel componentModel = findVendorComponent(realm);
            if (componentModel == null) {
                logger.warn("There is no tide-vendor-key component set up for this realm, " + realm.getName());
                return ErrorPage.error(session, null, Response.Status.BAD_REQUEST,
                        "There is no tide-vendor-key component set up for this realm, " + realm.getName());
            }

            // 1) Only proceed if license is active (truthy). Anything else blocks.
            boolean licenseActive;
            try {
                licenseActive = IsPendingLicenseActive(realm);
            } catch (Exception e) {
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

            // IGA and authorizer gating
            String igaAttribute = realm.getAttribute("isIGAEnabled");
            boolean isIGAEnabled = igaAttribute != null && igaAttribute.equalsIgnoreCase("true");
            List<AuthorizerEntity> realmAuthorizers = em.createNamedQuery(
                            "getAuthorizerByProviderIdAndTypes", AuthorizerEntity.class)
                    .setParameter("ID", componentModel.getId())
                    .setParameter("types", List.of("firstAdmin", "multiAdmin"))
                    .getResultList();

            if (realmAuthorizers.isEmpty()) {
                throw new Exception("Authorizer not found for this realm.");
            }

            // Just sign with VRK if no IGA or still first-admin single approver
            if (!isIGAEnabled ||
                    (realmAuthorizers.get(0).getType().equalsIgnoreCase("firstAdmin") && realmAuthorizers.size() == 1)) {
                try {
                    RotateVrk(realmId, session, gvrk);
                    return buildResponse(200, "Licensing has been rotated.");
                } catch (Exception e) {
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

            Runnable callback = () -> {
                try {
                    if(processor instanceof RealmLicenseProcessor realmLicenseProcessor){
                        realmLicenseProcessor.saveDraftReq(draft, em, realm, gvrk);
                    }
                } catch (Exception e) {
                    throw new RuntimeException("Error during FULL_SCOPE callback", e);
                }
            };
            processor.executeWorkflow(session, draft, em, WorkflowType.REQUEST, params, callback);

            return buildResponse(200, "Licensing Change Request created and awaiting quorum approval.");

        } catch (Exception e) {
            logger.error("Error creating licensing change request", e);
            return buildResponse(500, "Error creating licensing change request: " + e.getMessage());
        }
    }

    // ---------------------------------------
    // HISTORY: filter out the CURRENT active
    // ---------------------------------------
    /**
     * Load LICENSE_HISTORY for this realm's vendor component, but DO NOT return the
     * currently active gVRK entry. The row remains in the DB (append-only), it is
     * simply hidden from the returned list to avoid UI confusion.
     *
     * Use this helper wherever you currently collect history for the UI.
     */
    private static List<LicenseHistoryEntity> getLicenseHistoryExcludingActive(KeycloakSession session, RealmModel realm) {
        ComponentModel cm = findVendorComponent(realm);
        if (cm == null) {
            return List.of();
        }
        MultivaluedHashMap<String, String> cfg = cm.getConfig();
        String activeGvrk = cfg.getFirst("gVRK");
        String active = (activeGvrk == null) ? "" : activeGvrk.trim().toUpperCase();

        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        ComponentEntity componentEntity = em.find(ComponentEntity.class, cm.getId());

        List<LicenseHistoryEntity> all = em.createNamedQuery("getLicenseHistoryForKey", LicenseHistoryEntity.class)
                .setParameter("componentEntity", componentEntity)
                .getResultList();

        if (active.isEmpty()) {
            return all;
        }

        return all.stream()
                .filter(h -> {
                    String g = (h.getGVRK() == null) ? "" : h.getGVRK().trim().toUpperCase();
                    return !g.equals(active);
                })
                .collect(Collectors.toList());
    }

    @POST
    @Path("add-review")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_PLAIN)
    public Response addApproval(
            @FormParam("changeSetId") String changeSetId,
            @FormParam("changeSetType") String changeSetType,
            @FormParam("actionType") String actionType,
            @FormParam("requests") List<String> requests

    ) {
        try {
            // Check admin role
            RoleModel role = session.getContext()
                    .getRealm()
                    .getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID)
                    .getRole(tideRealmAdminRole);

            if (!auth.adminAuth().getUser().hasRole(role)) {
                return buildResponse(403, "Not authorized to add approvals");
            }

            EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

            ChangesetRequestEntity changesetRequestEntity = ChangesetRequestAdapter.getChangesetRequestEntity(session, changeSetId, ChangeSetType.valueOf(changeSetType));

            // Optional: sanity check
            if (requests == null || requests.isEmpty()) {
                return buildResponse(400, "No requests provided");
            }

            // Map requests to entities one-to-one (up to the shortest list)
                requests.forEach(req -> {
                    changesetRequestEntity.setRequestModel(req);
                    try {
                        ChangesetRequestAdapter.saveAdminAuthorizaton(session, changeSetType, changeSetId, actionType,
                                auth.adminAuth().getUser());
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                });



            return buildResponse(
                    200,
                    "Successfully added admin approval to changeSetRequest with id " + changeSetId
            );

        } catch (Exception e) {
            logger.error("Error adding approval to change set request with ID: " + changeSetId, e);
            return buildResponse(
                    500,
                    "Error adding approval to change set request with ID: "
                            + changeSetId + " . " + e.getMessage()
            );
        }
    }

    @POST
    @Path("add-rejection")
    @Produces(MediaType.TEXT_PLAIN)
    public Response AddRejection(@FormParam("changeSetId") String changeSetId,
                                 @FormParam("actionType") String actionType,
                                 @FormParam("changeSetType") String changeSetType) {
        try {
            RoleModel role = session.getContext().getRealm()
                    .getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID)
                    .getRole(tideRealmAdminRole);
            auth.adminAuth().getUser().hasRole(role);

            ComponentModel componentModel = findVendorComponent(session.getContext().getRealm());
            if (componentModel == null) {
                logger.warn("There is no tide-vendor-key component set up for this realm, "
                        + session.getContext().getRealm());
                return ErrorPage.error(session, null, Response.Status.BAD_REQUEST,
                        "There is no tide-vendor-key component set up for this realm, "
                                + session.getContext().getRealm());
            }
            ChangesetRequestAdapter.saveAdminRejection(session, changeSetType, changeSetId, actionType,
                    auth.adminAuth().getUser());

            return buildResponse(200,
                    "Successfully added admin rejection to changeSetRequest with id " + changeSetId);

        } catch (Exception e) {
            logger.error("Error adding rejection to change set request with ID: " + changeSetId, e);
            return buildResponse(500,
                    "Error adding rejection to change set request with ID: " + changeSetId + " ." + e.getMessage());
        }
    }

    @POST
    @Path("new-voucher")
    @Produces(MediaType.TEXT_PLAIN)
    public Response GetAdminVouchers(@FormParam("voucherRequest") String voucherRequest) {
        try {
            auth.realm().requireManageRealm();
            return Response.status(200)
                    .header("Access-Control-Allow-Origin", "*")
                    .entity(getVouchers(voucherRequest))
                    .type(MediaType.TEXT_PLAIN)
                    .build();

        } catch (Exception ex) {
            logger.error("File upload failed", ex);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("File upload failed: " + ex.getMessage())
                    .type(MediaType.TEXT_PLAIN)
                    .build();
        }
    }

    private String getVouchers(String voucherRequest) throws JsonProcessingException {
        ComponentModel componentModel = findVendorComponent(session.getContext().getRealm());
        MultivaluedHashMap<String, String> config = componentModel.getConfig();

        String currentSecretKeys = config.getFirst("clientSecret");
        ObjectMapper objectMapper = new ObjectMapper();
        SecretKeys secretKeys = objectMapper.readValue(currentSecretKeys, SecretKeys.class);
        String vvkId = config.getFirst("vvkId");

        String payerPublicKey = config.getFirst("payerPublic");
        String vrk = (vvkId == null || vvkId.isEmpty()) ? secretKeys.pendingVrk : secretKeys.activeVrk;

        return Midgard.GetVouchers(
                voucherRequest,
                config.getFirst("obfGVVK"),
                payerPublicKey,
                vrk
        );
    }

    @GET
    @Path("Create-Approval-URI")
    public Response CreateApprovalUri() throws URISyntaxException, JsonProcessingException {
        IdentityProviderModel tideIdp = session.identityProviders().getByAlias("tide");

        ComponentModel componentModel = findVendorComponent(realm);
        if (componentModel == null) {
            return buildResponse(400,
                    "There is no tide-vendor-key component set up for this realm, " + realm.getName());
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
                session.getContext().getRealm().getName() + "/tidevouchers/fromUserSession?sessionId=" + userSession.getId();

        URI uri = Midgard.CreateURL(
                auth.adminAuth().getToken().getSessionId(),
                redirectURI.toString(),
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
                    config.getFirst("clientId"),
                    config.getFirst("gVRK"),
                    config.getFirst("gVRKCertificate"),
                    realm.isRegistrationAllowed(),
                    Boolean.valueOf(tideIdp.getConfig().get("backupOn")),
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
        if (customAdminUiDomain != null) {
            response.put("customDomainUri", String.valueOf(customDomainUri));
        }

        return buildResponse(200, objectMapper.writeValueAsString(response));
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
        ExecuteActionsActionToken token =
                new ExecuteActionsActionToken(user.getId(), user.getEmail(), expiration, actions, redirectUri, clientId);
        try {
            var builder = LoginActionsService.actionTokenProcessor(session.getContext().getUri());
            builder.queryParam("key", token.serialize(session, realm, session.getContext().getUri()));

            String link = builder.build(realm.getName()).toString();
            return buildResponse(200, link);

        } catch (Exception e) {
            throw ErrorResponse.error("Failed to get link tide account URL " + e.getMessage(),
                    Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    // ---------------------
    // Helper / Utilities
    // ---------------------

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
        public void addToHistory(String newEntry) { history.add(newEntry); }
    }

    private static List<RequestedChanges> processLicensingRequests(EntityManager em, RealmModel realm) {
        List<LicensingDraftEntity> drafts = em
                .createNamedQuery("LicensingDraft.findByRealmAndStatusNotEqual", LicensingDraftEntity.class)
                .setParameter("realmId", realm.getId())
                .setParameter("status", DraftStatus.ACTIVE)
                .getResultList();

        return processLicensingRequests(em, realm, drafts);
    }

    public static List<RequestedChanges> processLicensingRequests(EntityManager em, RealmModel realm, List<LicensingDraftEntity> entities) {
        List<RequestedChanges> changes = new ArrayList<>();
        for (LicensingDraftEntity e : entities) {
            em.lock(e, LockModeType.PESSIMISTIC_WRITE);
            String actionDescription = "Tide offboarding has been requested";
            RequestedChanges requestChange = new RequestedChanges(
                    actionDescription, ChangeSetType.REALM_LICENSING, RequestType.SETTINGS,
                    null, realm.getId(), ActionType.CREATE, e.getChangeRequestId(),
                    List.of(), e.getDraftStatus(), DraftStatus.NULL);
            changes.add(requestChange);
        }
        return changes;
    }

    public static SignRequestSettingsMidgard ConstructSignSettings(MultivaluedHashMap<String, String> keyProviderConfig, String vrk) {
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
            ComponentModel componentModel = findVendorComponent(realm);
            if (componentModel == null) {
                logger.warn("There is no tide-vendor-key component set up for this realm, " + realm.getName());
                throw new BadRequestException("There is no tide-vendor-key component set up for this realm, " + realm.getName());
            }

            MultivaluedHashMap<String, String> config = componentModel.getConfig();
            String homeOrkUrl = config.getFirst("systemHomeOrk");
            String payerPublic = config.getFirst("payerPublic");
            String pendingVendorId = config.getFirst("pendingVendorId");

            return Midgard.IsLicenseActive(homeOrkUrl, payerPublic, pendingVendorId);

        } catch (Exception e) {
            logger.warn("Could not check if pending license is active", e);
            throw new Exception("Could not check if pending license is active ");
        }
    }

    public static void RotateVrk(String realmId, KeycloakSession session, String gVRK) throws JsonProcessingException {
        try {
            if (gVRK == null || gVRK.isBlank()) {
                throw new BadRequestException("Provided gVRK is empty.");
            }
            final String gvrk = normalizeHex(gVRK);
            if (gvrk.isEmpty()) {
                throw new BadRequestException("Provided gVRK must be an even-length hex string.");
            }

            RealmModel realm = session.realms().getRealm(realmId);
            ComponentModel componentModel = findVendorComponent(realm);
            if (componentModel == null) {
                String msg = "There is no tide-vendor-key component set up for this realm, " + realm.getName();
                logger.warn(msg);
                throw new BadRequestException(msg);
            }

            MultivaluedHashMap<String, String> config = componentModel.getConfig();
            ObjectMapper objectMapper = new ObjectMapper();
            String currentSecretKeys = config.getFirst("clientSecret");
            SecretKeys secretKeys = objectMapper.readValue(currentSecretKeys, SecretKeys.class);

            // Build signing settings using current active VRK
            SignRequestSettingsMidgard settings = ConstructSignSettings(config, secretKeys.activeVrk);

            // Sign the PROVIDED gVRK (hex)
            ModelRequest req = ModelRequest.New("RotateVRK", "1", "VRK:1",
                    jakarta.xml.bind.DatatypeConverter.parseHexBinary(gvrk));
            req.SetAuthorization(Midgard.SignWithVrk(req.GetDataToAuthorize(), settings.VendorRotatingPrivateKey));
            req.SetAuthorizer(jakarta.xml.bind.DatatypeConverter.parseHexBinary(config.getFirst("gVRK")));
            req.SetAuthorizerCertificate(java.util.Base64.getDecoder().decode(config.getFirst("gVRKCertificate")));

            SignatureResponse response = Midgard.SignModel(settings, req);

            // Persist BOTH pending values (so pending→active switch works)
            config.putSingle("pendingGVRK", gvrk);
            config.putSingle("pendingGVRKCertificate", response.Signatures[0]);
            // Optionally: config.putSingle("pendingVendorId", config.getFirst("vendorId"));

            componentModel.setConfig(config);
            realm.updateComponent(componentModel);

            CacheRealmProvider cacheRealmProvider = session.getProvider(CacheRealmProvider.class);
            cacheRealmProvider.clear();

            logger.infof("Successfully rotated VRK for realm=%s; pendingGVRK set and certificate stored.", realm.getName());

        } catch (Exception e) {
            logger.warn("Could not generate and save tide network keys", e);
            throw e;
        }
    }

    // ------------------
    // tiny shared utils
    // ------------------

    public static ComponentModel findVendorComponent(RealmModel realm) {
        try (Stream<ComponentModel> components = realm.getComponentsStream()) {
            return components
                    .filter(c -> tideVendorKeyId.equals(c.getProviderId()))
                    .findAny()
                    .orElse(null);
        }
    }

    private static String getActiveGvrk(RealmModel realm) {
        ComponentModel cm = findVendorComponent(realm);
        if (cm == null) return null;
        String v = cm.getConfig().getFirst("gVRK");
        return (v == null || v.isBlank()) ? null : v;
    }

    /** Uppercased hex or "" if invalid. */
    private static String normalizeHex(String s) {
        if (s == null) return "";
        String t = s.trim();
        if (t.startsWith("0x") || t.startsWith("0X")) t = t.substring(2);
        if (t.isEmpty() || (t.length() % 2) != 0) return "";
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            boolean hex = (c >= '0' && c <= '9') ||
                    (c >= 'a' && c <= 'f') ||
                    (c >= 'A' && c <= 'F');
            if (!hex) return "";
        }
        return t.toUpperCase();
    }
}
