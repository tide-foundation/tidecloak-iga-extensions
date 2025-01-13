package org.tidecloak.TideResource;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.*;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.midgard.Midgard;
import org.midgard.models.VendorData;
import org.tidecloak.iga.interfaces.ChangesetRequestAdapter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.tidecloak.iga.TideRequests.TideRoleRequests.createRealmAdminInitCert;

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
            auth.realm().requireManageRealm();
            session.getContext().getRealm().setAttribute("isIGAEnabled", isEnabled);
            logger.info("IGA has been toggled to : " + isEnabled);

            IdentityProviderModel tideIdp = session.getContext().getRealm().getIdentityProviderByAlias("tide");

            // if IGA is on and tideIdp exists, we need to enable EDDSA as default sig
            if (tideIdp != null) {
                String currentAlgorithm = session.getContext().getRealm().getDefaultSignatureAlgorithm();

                if (isEnabled) {
                    if (!"EdDSA".equalsIgnoreCase(currentAlgorithm)) {
                        session.getContext().getRealm().setDefaultSignatureAlgorithm("EdDSA");
                        logger.info("IGA has been enabled, default signature algorithm updated to EdDSA");
                    }
                    ClientModel realmManagement = realm.getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID);
                    if(session.roles().getClientRole(realmManagement, org.tidecloak.shared.Constants.TIDE_REALM_ADMIN) == null){
                        createRealmAdminInitCert(session);
                    }
                } else {
                    // If tide IDP exists but IGA is disabled, default signature cannot be EdDSA
                    // TODO: Fix error: Uncaught server error: java.lang.RuntimeException: org.keycloak.crypto.SignatureException:
                    // Signing failed. java.security.InvalidKeyException: Unsupported key type (tide eddsa key)
                    if ("EdDSA".equalsIgnoreCase(currentAlgorithm)) {
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

    private Response buildResponse(int status, String message) {
        return Response.status(status)
                .header("Access-Control-Allow-Origin", "*")
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
