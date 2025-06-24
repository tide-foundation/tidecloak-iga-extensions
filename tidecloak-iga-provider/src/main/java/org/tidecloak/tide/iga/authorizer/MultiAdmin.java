package org.tidecloak.tide.iga.authorizer;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.core.Response;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.services.resources.admin.AdminAuth;
import org.midgard.Midgard;
import org.midgard.models.AdminAuthorization;
import org.midgard.models.AdminAuthorizerBuilder;
import org.midgard.models.InitializerCertificateModel.InitializerCertifcate;
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
import org.tidecloak.jpa.entities.drafting.RoleInitializerCertificateDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideRoleDraftEntity;
import org.tidecloak.shared.enums.WorkflowType;
import org.tidecloak.shared.enums.models.WorkflowParams;
import org.tidecloak.shared.models.SecretKeys;

import java.net.URI;
import java.util.*;

import static org.tidecloak.base.iga.TideRequests.TideRoleRequests.commitRoleInitCert;
import static org.tidecloak.base.iga.TideRequests.TideRoleRequests.getDraftRoleInitCert;
import static org.tidecloak.base.iga.utils.BasicIGAUtils.isAuthorityAssignment;
import static org.tidecloak.base.iga.utils.BasicIGAUtils.sortAccessProof;

public class MultiAdmin implements Authorizer{

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
                session.getContext().getRealm().getName() + "/tidevouchers/fromUserSession?sessionId=" +userSession.getId();

        URI uri = Midgard.CreateURL(
                auth.getToken().getSessionId(),
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
                    auth.getToken().getSessionId(),
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
        response.put("changeSetRequests", changesetRequestEntity.getDraftRequest());
        response.put("requiresApprovalPopup", "true");
        response.put("expiry", String.valueOf(changesetRequestEntity.getTimestamp() + 2628000)); // month expiry
        if(customAdminUiDomain != null) {
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

        RoleModel tideRole = session.clients().getClientByClientId(realm, Constants.REALM_MANAGEMENT_CLIENT_ID).getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
        RoleEntity role = em.getReference(RoleEntity.class, tideRole.getId());
        TideRoleDraftEntity tideRoleEntity = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class)
                .setParameter("role", role).getSingleResult();

        InitializerCertifcate cert = InitializerCertifcate.FromString(tideRoleEntity.getInitCert());
        UserContextSignRequest req = new UserContextSignRequest("Admin:1");
        req.SetDraft(Base64.getDecoder().decode(changesetRequestEntity.getDraftRequest()));
        req.SetUserContexts(orderedContext.toArray(new UserContext[0]));
        req.SetCustomExpiry(changesetRequestEntity.getTimestamp() + 2628000); // expiry in 1 month
        AdminAuthorizerBuilder authorizerBuilder = new AdminAuthorizerBuilder();
        authorizerBuilder.AddInitCert(cert);
        authorizerBuilder.AddInitCertSignature(tideRoleEntity.getInitCertSig());

        changesetRequestEntity.getAdminAuthorizations().forEach(a -> {
            authorizerBuilder.AddAdminAuthorization(AdminAuthorization.FromString(a.getAdminAuthorization()));
        });

        int threshold = Integer.parseInt(System.getenv("THRESHOLD_T"));
        int max = Integer.parseInt(System.getenv("THRESHOLD_N"));

        if ( threshold == 0 || max == 0){
            throw new RuntimeException("Env variables not set: THRESHOLD_T=" + threshold + ", THRESHOLD_N=" + max);
        }

        String currentSecretKeys = config.getFirst("clientSecret");
        SecretKeys secretKeys = objectMapper.readValue(currentSecretKeys, SecretKeys.class);

        SignRequestSettingsMidgard settings = new SignRequestSettingsMidgard();
        settings.VVKId = config.getFirst("vvkId");
        settings.HomeOrkUrl = config.getFirst("systemHomeOrk");
        settings.PayerPublicKey = config.getFirst("payerPublic");
        settings.ObfuscatedVendorPublicKey = config.getFirst("obfGVVK");
        settings.VendorRotatingPrivateKey = secretKeys.activeVrk;
        settings.Threshold_T = threshold;
        settings.Threshold_N = max;

        authorizerBuilder.AddAuthorizationToSignRequest(req);

        boolean isAuthorityAssignment = isAuthorityAssignment(session, draftEntity, em);

        if(isAuthorityAssignment) {
            RoleInitializerCertificateDraftEntity roleInitCert = getDraftRoleInitCert(session, changeSet.getChangeSetId());
            if(roleInitCert == null) {
                throw new BadRequestException("Role Init Cert draft not found for changeSet, " + changeSet.getChangeSetId());
            }
            req.SetInitializationCertificate(InitializerCertifcate.FromString(roleInitCert.getInitCert()));
            SignatureResponse response = Midgard.SignModel(settings, req);

            for ( int i = 0; i < orderedProofDetails.size(); i++){
                orderedProofDetails.get(i).setSignature(response.Signatures[i + 1]);
            }
            commitRoleInitCert(session, changeSet.getChangeSetId(), draftEntity, response.Signatures[0]);

        } else {
            SignatureResponse response = Midgard.SignModel(settings, req);

            for ( int i = 0; i < orderedProofDetails.size(); i++){
                orderedProofDetails.get(i).setSignature(response.Signatures[i]);
            }
        }

        ChangeSetProcessorFactory processorFactory = new ChangeSetProcessorFactory(); // Initialize the processor factory

        WorkflowParams workflowParams = new WorkflowParams(null, false, null, changeSet.getType());
        processorFactory.getProcessor(changeSet.getType()).executeWorkflow(session, draftEntity, em, WorkflowType.COMMIT, workflowParams, null);
        String authorizerType = authorizer.getType();
        if (isAuthorityAssignment) {
            if (authorizer.getType().equals(org.tidecloak.shared.Constants.TIDE_INITIAL_AUTHORIZER)){
                authorizer.setType(org.tidecloak.shared.Constants.TIDE_MULTI_ADMIN_AUTHORIZER);

            }
        }
        em.flush();
        return Response.ok("Change set approved and committed with authorizer type:  " + authorizerType).build();
    }
}
