package org.tidecloak.tide.iga.authorizer;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.core.Response;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.*;
import org.keycloak.services.resources.admin.AdminAuth;
import org.midgard.Midgard;
import org.midgard.models.AdminAuthorization;
import org.midgard.models.AdminAuthorizerBuilder;
import org.midgard.models.AuthorizerPolicyModel.AuthorizerPolicy;
import org.midgard.models.RequestExtensions.UserContextSignRequest;
import org.midgard.models.SignRequestSettingsMidgard;
import org.midgard.models.SignatureResponse;
import org.midgard.models.UserContext.UserContext;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessorFactory;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.AuthorizerEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.shared.enums.WorkflowType;
import org.tidecloak.shared.enums.models.WorkflowParams;
import org.tidecloak.shared.models.SecretKeys;
import org.tidecloak.tide.replay.UserContextPolicyHashUtil;
import org.tidecloak.tide.replay.ReplayMetaStore;

import java.net.URI;
import java.util.*;

import static org.tidecloak.base.iga.utils.BasicIGAUtils.isAuthorityAssignment;
import static org.tidecloak.base.iga.utils.BasicIGAUtils.sortAccessProof;
import static org.tidecloak.tide.replay.TideRoleReplaySupport.commitRoleAuthorizerPolicy;

public class MultiAdmin implements Authorizer {

    private static String unwrapCompactOrFirst(String stored) {
        if (stored == null) return null;
        String s = stored.trim();
        if (!s.startsWith("{")) return s;
        try {
            ObjectMapper om = new ObjectMapper();
            @SuppressWarnings("unchecked")
            Map<String, Object> m = om.readValue(s, Map.class);
            Object v = m.get("auth");
            if (v == null && !m.isEmpty()) v = m.values().iterator().next();
            return v == null ? null : String.valueOf(v);
        } catch (Exception e) {
            return s;
        }
    }

    @Override
    public Response signWithAuthorizer(ChangeSetRequest changeSet, EntityManager em, KeycloakSession session, RealmModel realm, Object draftEntity, AdminAuth auth, AuthorizerEntity authorizer, ComponentModel componentModel) throws Exception {
        IdentityProviderModel tideIdp = session.identityProviders().getByAlias("tide");
        ObjectMapper objectMapper = new ObjectMapper();
        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(changeSet.getChangeSetId(), changeSet.getType()));

        if (changesetRequestEntity == null){
            throw new BadRequestException("No change-set request entity found with this recordId and type " + changeSet.getChangeSetId() + " , " + changeSet.getType());
        }

        var config = componentModel.getConfig();

        String defaultAdminUiDomain = tideIdp.getConfig().get("changeSetEndpoint");
        String customAdminUiDomain = tideIdp.getConfig().get("CustomAdminUIDomain");
        String redirectUrlSig = tideIdp.getConfig().get("changeSetURLSig");

        URI redirectURI = new URI(defaultAdminUiDomain);
        UserSessionModel userSession = session.sessions().getUserSession(realm, auth.getToken().getSessionId());
        String port = redirectURI.getPort() == -1 ? "" : ":" + redirectURI.getPort();
        String voucherURL = redirectURI.getScheme() + "://" + redirectURI.getHost() + port + "/realms/" +
                session.getContext().getRealm().getName() + "/tidevouchers/fromUserSession?sessionId=" + userSession.getId();

        URI uri = Midgard.CreateURL(
                auth.getToken().getSessionId(),
                redirectURI.toString(),
                redirectUrlSig,
                tideIdp.getConfig().get("homeORKurl"),
                config.getFirst("clientId"),
                config.getFirst("gVRK"),
                config.getFirst("gVRKCertificate"),
                realm.isRegistrationAllowed(),
                Boolean.parseBoolean(tideIdp.getConfig().get("backupOn")),
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
                    auth.getToken().getSessionId(),
                    customAdminUiDomain,
                    tideIdp.getConfig().get("customAdminUIDomainSig"),
                    tideIdp.getConfig().get("homeORKurl"),
                    config.getFirst("clientId"),
                    config.getFirst("gVRK"),
                    config.getFirst("gVRKCertificate"),
                    realm.isRegistrationAllowed(),
                    Boolean.parseBoolean(tideIdp.getConfig().get("backupOn")),
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
        response.put("changeSetRequests", changesetRequestEntity.getDraftRequest());
        response.put("requiresApprovalPopup", "true");
        response.put("expiry", String.valueOf(changesetRequestEntity.getTimestamp() + 2628000));
        if (customAdminUiDomain != null) {
            response.put("customDomainUri", String.valueOf(customDomainUri));
        }

        return Response.ok(objectMapper.writeValueAsString(response)).build();
    }

    @Override
    public Response commitWithAuthorizer(ChangeSetRequest changeSet, EntityManager em, KeycloakSession session, RealmModel realm, Object draftEntity, AdminAuth auth, AuthorizerEntity authorizer, ComponentModel componentModel) throws Exception {
        IdentityProviderModel tideIdp = session.identityProviders().getByAlias("tide");
        ObjectMapper objectMapper = new ObjectMapper();
        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(changeSet.getChangeSetId(), changeSet.getType()));

        if (changesetRequestEntity == null){
            throw new BadRequestException("No change-set request entity found with this recordId and type " + changeSet.getChangeSetId() + " , " + changeSet.getType());
        }

        var config = componentModel.getConfig();
        List<AccessProofDetailEntity> proofDetails = BasicIGAUtils.getAccessProofs(em, BasicIGAUtils.getEntityChangeRequestId(draftEntity), changeSet.getType());
        proofDetails.sort(Comparator.comparingLong(AccessProofDetailEntity::getCreatedTimestamp).reversed());

        List<AccessProofDetailEntity> orderedProofDetails = sortAccessProof(proofDetails);
        List<UserContext> orderedContext = orderedProofDetails.stream().map(a -> new UserContext(a.getProofDraft())).toList();

        // Resolve the AP used for this approval (bundle or compact):
        String compactOrBundle;
        boolean isAuthorityAssignment = isAuthorityAssignment(session, draftEntity, em);
        if (isAuthorityAssignment) {
            // replay-specific draft
            compactOrBundle = ReplayMetaStore.getRoleInitCert(session, changeSet.getChangeSetId());
            if (compactOrBundle == null || compactOrBundle.isBlank()) {
                throw new BadRequestException("Role Init Cert draft not found for changeSet, " + changeSet.getChangeSetId());
            }
        } else {
            // current, committed cert from role attributes
            ClientModel realmMgmt = session.clients().getClientByClientId(realm, org.keycloak.models.Constants.REALM_MANAGEMENT_CLIENT_ID);
            RoleModel tideAdmin = realmMgmt.getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
            compactOrBundle = Optional.ofNullable(tideAdmin.getFirstAttribute("InitCertBundle"))
                    .orElse(tideAdmin.getFirstAttribute("InitCert"));
            if (compactOrBundle == null || compactOrBundle.isBlank()) {
                throw new BadRequestException("Tide admin role has no InitCert/InitCertBundle attributes set.");
            }
        }

        String compact = unwrapCompactOrFirst(compactOrBundle);
        AuthorizerPolicy cert = AuthorizerPolicy.fromCompact(compact);

        UserContextSignRequest req = new UserContextSignRequest("Admin:2");
        req.SetDraft(Base64.getDecoder().decode(changesetRequestEntity.getDraftRequest()));
        req.SetUserContexts(orderedContext.toArray(new UserContext[0]));
        req.SetCustomExpiry(changesetRequestEntity.getTimestamp() + 2628000);

        AdminAuthorizerBuilder authorizerBuilder = new AdminAuthorizerBuilder();
        authorizerBuilder.AddInitCert(cert.toCompactString());

        changesetRequestEntity.getAdminAuthorizations().forEach(a -> {
            authorizerBuilder.AddAdminAuthorization(AdminAuthorization.FromString(a.getAdminAuthorization()));
        });

        int threshold = Integer.parseInt(System.getenv("THRESHOLD_T"));
        int max       = Integer.parseInt(System.getenv("THRESHOLD_N"));
        if (threshold == 0 || max == 0){
            throw new RuntimeException("Env variables not set: THRESHOLD_T=" + threshold + ", THRESHOLD_N=" + max);
        }

        String currentSecretKeys = config.getFirst("clientSecret");
        SecretKeys secretKeys = objectMapper.readValue(currentSecretKeys, SecretKeys.class);

        SignRequestSettingsMidgard settings = new SignRequestSettingsMidgard();
        settings.VVKId                     = config.getFirst("vvkId");
        settings.HomeOrkUrl                = config.getFirst("systemHomeOrk");
        settings.PayerPublicKey            = config.getFirst("payerPublic");
        settings.ObfuscatedVendorPublicKey = config.getFirst("obfGVVK");
        settings.VendorRotatingPrivateKey  = secretKeys.activeVrk;
        settings.Threshold_T               = threshold;
        settings.Threshold_N               = max;

        authorizerBuilder.AddAuthorizationToSignRequest(req);

        if (isAuthorityAssignment) {
            // use the replay draft AP for this request, and commit AP on success
            String draftBundleOrCompact = ReplayMetaStore.getRoleInitCert(session, changeSet.getChangeSetId());
            String draftCompact = UserContextPolicyHashUtil.unwrapCompactOrFirst(draftBundleOrCompact);
            AuthorizerPolicy draftCert = AuthorizerPolicy.fromCompact(draftCompact);

            req.SetInitializationCertificate(draftCert);
            SignatureResponse response = Midgard.SignModel(settings, req);

            for (int i = 0; i < orderedProofDetails.size(); i++){
                orderedProofDetails.get(i).setSignature(response.Signatures[i + 1]);
            }
            commitRoleAuthorizerPolicy(session, changeSet.getChangeSetId(), draftEntity, response.Signatures[0]);
        } else {
            SignatureResponse response = Midgard.SignModel(settings, req);
            for (int i = 0; i < orderedProofDetails.size(); i++){
                orderedProofDetails.get(i).setSignature(response.Signatures[i]);
            }
        }

        ChangeSetProcessorFactory processorFactory = new ChangeSetProcessorFactory();
        WorkflowParams workflowParams = new WorkflowParams(null, false, null, changeSet.getType());
        processorFactory.getProcessor(changeSet.getType()).executeWorkflow(session, draftEntity, em, WorkflowType.COMMIT, workflowParams, null);
        String authorizerType = authorizer.getType();
        if (isAuthorityAssignment) {
            if (org.tidecloak.shared.Constants.TIDE_INITIAL_AUTHORIZER.equals(authorizer.getType())){
                authorizer.setType(org.tidecloak.shared.Constants.TIDE_MULTI_ADMIN_AUTHORIZER);
            }
        }
        em.flush();
        return Response.ok("Change set approved and committed with authorizer type:  " + authorizerType).build();
    }
}
