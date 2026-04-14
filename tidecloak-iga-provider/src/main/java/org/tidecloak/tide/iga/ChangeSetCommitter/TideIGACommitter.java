package org.tidecloak.tide.iga.ChangeSetCommitter;

import jakarta.persistence.EntityManager;
import jakarta.ws.rs.core.Response;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminAuth;
import org.keycloak.common.util.MultivaluedHashMap;
import org.tidecloak.base.iga.ChangeSetCommitter.ChangeSetCommitter;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.base.iga.serveridentity.ServerCertBuilder;
import org.tidecloak.tide.iga.authorizer.Authorizer;
import org.tidecloak.tide.iga.authorizer.AuthorizerFactory;
import org.tidecloak.jpa.entities.AuthorizerEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.ServerCertDraftEntity;
import org.tidecloak.shared.Constants;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.shared.models.SecretKeys;
import org.tidecloak.base.iga.interfaces.ChangesetRequestAdapter;
import org.keycloak.models.RoleModel;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.midgard.Midgard;
import org.midgard.models.ModelRequest;
import org.midgard.models.SignRequestSettingsMidgard;
import org.midgard.models.SignatureResponse;
import org.midgard.models.Policy.Policy;
import org.midgard.models.Policy.PolicyParameters;
import org.midgard.models.Policy.ApprovalType;
import org.midgard.models.Policy.ExecutionType;
import org.midgard.models.RequestExtensions.PolicySignRequest;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.logging.Logger;

public class TideIGACommitter implements ChangeSetCommitter {
    private static final Logger logger = Logger.getLogger(TideIGACommitter.class.getName());
    @Override
    public Response commit(ChangeSetRequest changeSet, EntityManager em, KeycloakSession session, RealmModel realm, Object draftEntity, AdminAuth auth) throws Exception {
        // Check for key provider
        ComponentModel componentModel = realm.getComponentsStream()
                .filter(x -> x.getProviderId().equalsIgnoreCase(Constants.TIDE_VENDOR_KEY))  // Use .equals for string comparison
                .findFirst()
                .orElse(null);

        if (componentModel == null) {
            // No key provider, use non-IGA logic
            return null;
        }

        // Handle SERVER_CERT commit: build X.509, sign with VVK, store cert
        if (changeSet.getType() == ChangeSetType.SERVER_CERT) {
            return commitServerCert(changeSet, em, session, realm, draftEntity, componentModel);
        }

        // Fetch authorizers
        List<AuthorizerEntity> realmAuthorizers = em.createNamedQuery("getAuthorizerByProviderIdAndTypes", AuthorizerEntity.class)
                .setParameter("ID", componentModel.getId())
                .setParameter("types", List.of("firstAdmin", "multiAdmin"))
                .getResultList();

        if (realmAuthorizers.isEmpty()) {
            throw new Exception("Authorizer not found for this realm.");
        }

        AuthorizerEntity primaryAuthorizer = realmAuthorizers.get(0);
        String authorizerType = primaryAuthorizer.getType();

        // Delegate to the appropriate sub-strategy
        Authorizer authorizerSigner = AuthorizerFactory.getCommitter(authorizerType);
        if (authorizerSigner != null) {
            return authorizerSigner.commitWithAuthorizer(changeSet, em, session, realm, draftEntity, auth, primaryAuthorizer, componentModel);
        }
        return Response.status(Response.Status.BAD_REQUEST).entity("Unsupported authorizer type").build();
    }

    /**
     * Commit a SERVER_CERT change-set: build X.509 TBS, sign with VVK via ORKs, store signed cert.
     */
    private Response commitServerCert(ChangeSetRequest changeSet, EntityManager em, KeycloakSession session,
                                       RealmModel realm, Object draftEntity, ComponentModel componentModel) throws Exception {
        if (!(draftEntity instanceof ServerCertDraftEntity draft)) {
            throw new Exception("Expected ServerCertDraftEntity for SERVER_CERT commit");
        }

        ObjectMapper objectMapper = new ObjectMapper();
        MultivaluedHashMap<String, String> config = componentModel.getConfig();

        // Build Midgard signing settings
        int threshold = Integer.parseInt(System.getenv("THRESHOLD_T"));
        int max = Integer.parseInt(System.getenv("THRESHOLD_N"));
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

        String gVRK = config.getFirst("gVRK");
        String gVRKCertificate = config.getFirst("gVRKCertificate");

        // Build X.509 TBS certificate (always needed for final certificate assembly)
        String issuerCn = "tide.realm." + realm.getName();
        byte[] tbsCert = ServerCertBuilder.buildTbs(
                draft.getPublicKey(),
                draft.getClientId(),
                realm.getName(),
                issuerCn,
                draft.getSpiffeId(),
                draft.getRequestedLifetime()
        );

        // Check if the requestModel was already built during sign time (multi-admin flow).
        // If so, reuse it to avoid rebuilding and to keep consistency with the enclave-approved model.
        ChangesetRequestEntity existingChangesetReq = em.find(
                ChangesetRequestEntity.class,
                new ChangesetRequestEntity.Key(changeSet.getChangeSetId(), ChangeSetType.SERVER_CERT)
        );
        // --- Step 1: Sign ServerCert:1 policy fresh via ORK network ---
        // Always create a fresh policy on each approval — if the policy gets revoked on the ORKs,
        // a new one must be generated.
        logger.info("[SERVER_CERT] Building fresh ServerCert:1 policy...");

        String sCertPolicyKey = changeSet.getChangeSetId() + "-scpo";
        ChangesetRequestEntity sCertPolicyEntity = em.find(
                ChangesetRequestEntity.class,
                new ChangesetRequestEntity.Key(sCertPolicyKey, ChangeSetType.POLICY)
        );

        // Build the ServerCert:1 policy object
        PolicyParameters sCertPolicyParams = new PolicyParameters();
        sCertPolicyParams.put("realm", realm.getName());
        // Calculate threshold from active tide-realm-admin count
        RoleModel tideAdminRole = session.clients()
                .getClientByClientId(realm, org.keycloak.models.Constants.REALM_MANAGEMENT_CLIENT_ID)
                .getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
        int adminCount = ChangesetRequestAdapter.getNumberOfActiveAdmins(session, realm, tideAdminRole, em);
        int approvalThreshold = Math.max(1, (int) (0.7 * Math.max(1, adminCount)));
        sCertPolicyParams.put("threshold", approvalThreshold);
        sCertPolicyParams.put("role", org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
        sCertPolicyParams.put("resource", "realm-management");
        Policy sCertPolicy = new Policy("ServerCert:1", new String[]{"ServerCert:1"}, settings.VVKId,
                ApprovalType.EXPLICIT, ExecutionType.PUBLIC, sCertPolicyParams);

        if (sCertPolicyEntity != null && sCertPolicyEntity.getRequestModel() != null) {
            // Reuse model from sign time (has admin dokens from enclave)
            ModelRequest sCertPolicyModelReq = ModelRequest.FromBytes(Base64.getDecoder().decode(sCertPolicyEntity.getRequestModel()));
            SignatureResponse sCertPolicySignResp = Midgard.SignModel(settings, sCertPolicyModelReq);
            sCertPolicy.AddSignature(java.util.Base64.getDecoder().decode(sCertPolicySignResp.Signatures[0]));
            logger.info("[SERVER_CERT] ServerCert:1 policy signed (from sign-time enclave model)");
        } else {
            // Build fresh (single-admin / firstAdmin flow) — use VRK:1 auth
            byte[] authorizerBytes = HexFormat.of().parseHex(gVRK);
            byte[] certBytes = java.util.Base64.getDecoder().decode(gVRKCertificate);

            PolicySignRequest sCertPolicySignReq = new PolicySignRequest(sCertPolicy.ToBytes(), "VRK:1");
            ModelRequest sCertPolicyModelReq = ModelRequest.New("Policy", "1", "VRK:1",
                    sCertPolicySignReq.GetDraft(), sCertPolicy.ToBytes());
            sCertPolicyModelReq.SetAuthorizer(authorizerBytes);
            sCertPolicyModelReq.SetAuthorizerCertificate(certBytes);
            sCertPolicyModelReq.SetAuthorization(
                    Midgard.SignWithVrk(sCertPolicyModelReq.GetDataToAuthorize(), settings.VendorRotatingPrivateKey));
            SignatureResponse sCertPolicySignResp = Midgard.SignModel(settings, sCertPolicyModelReq);
            sCertPolicy.AddSignature(java.util.Base64.getDecoder().decode(sCertPolicySignResp.Signatures[0]));
            logger.info("[SERVER_CERT] ServerCert:1 policy signed (fresh build)");
        }

        // Clean up the policy entity (no longer needed after signing)
        if (sCertPolicyEntity != null) {
            if (sCertPolicyEntity.getAdminAuthorizations() != null) {
                sCertPolicyEntity.getAdminAuthorizations().clear();
            }
            em.remove(sCertPolicyEntity);
        }

        // --- Step 2: Build sCert:1 model with signed policy attached ---
        ModelRequest req;
        if (existingChangesetReq != null && existingChangesetReq.getRequestModel() != null) {
            req = ModelRequest.FromBytes(Base64.getDecoder().decode(existingChangesetReq.getRequestModel()));
        } else {
            ObjectNode metadata = objectMapper.createObjectNode();
            metadata.put("type", "server-cert");
            metadata.put("realm", realm.getName());
            metadata.put("clientId", draft.getClientId());
            metadata.put("instanceId", draft.getInstanceId());
            metadata.put("spiffeId", draft.getSpiffeId());
            byte[] dynamicData = objectMapper.writeValueAsBytes(metadata);

            req = ModelRequest.New("ServerCert", "1", "Policy:1", tbsCert);
            req.SetCustomExpiry((System.currentTimeMillis() / 1000) + 86400);
            req.SetDynamicData(dynamicData);

            byte[] authorizerBytes = HexFormat.of().parseHex(gVRK);
            byte[] certBytes = java.util.Base64.getDecoder().decode(gVRKCertificate);
            ModelRequest.InitializeTideRequestWithVrk(req, settings, "ServerCert:1", authorizerBytes, certBytes);
        }
        // Attach the VVK-signed ServerCert:1 policy
        req.SetPolicy(sCertPolicy.ToBytes());

        // --- Step 3: Sign sCert:1 ---
        SignatureResponse signatureResponse = Midgard.SignModel(settings, req);

        // Decode the VVK signature
        byte[] signatureBytes = java.util.Base64.getDecoder().decode(
                signatureResponse.Signatures[0].replace('-', '+').replace('_', '/')
        );

        // Assemble using the TBS that was actually signed (from the model's draft, not rebuilt)
        byte[] signedTbs = req.GetDraft();
        byte[] fullCert = ServerCertBuilder.assembleCertificate(signedTbs, signatureBytes);
        String certPem = ServerCertBuilder.toPem(fullCert);

        // Build trust bundle: VVK CA certificate (VVK-signed via ORK network)
        String gVVK = config.getFirst("clientId"); // "clientId" config stores the gVVK public key
        byte[] vvkPubBytes = HexFormat.of().parseHex(gVVK);
        byte[] caTbs = ServerCertBuilder.buildVvkCaTbs(vvkPubBytes, realm.getName());

        // Check if the CA cert model was built at sign time (multi-admin flow with enclave approval)
        String caKey = changeSet.getChangeSetId() + "-ca";
        ChangesetRequestEntity caEntity = em.find(
                ChangesetRequestEntity.class,
                new ChangesetRequestEntity.Key(caKey, ChangeSetType.SERVER_CERT)
        );

        byte[] caSignatureBytes;
        byte[] caTbsForAssembly = caTbs; // default: use freshly built TBS
        if (caEntity != null && caEntity.getRequestModel() != null) {
            // Reuse from sign time (has admin dokens from enclave)
            ModelRequest caReq = ModelRequest.FromBytes(Base64.getDecoder().decode(caEntity.getRequestModel()));
            // Use the SAME TBS that was signed (draft from sign time), not the rebuilt one
            caTbsForAssembly = caReq.GetDraft();
            caReq.SetPolicy(sCertPolicy.ToBytes());
            SignatureResponse caSignResponse = Midgard.SignModel(settings, caReq);
            caSignatureBytes = java.util.Base64.getDecoder().decode(
                    caSignResponse.Signatures[0].replace('-', '+').replace('_', '/'));
            logger.info("[SERVER_CERT] VVK CA cert signed via ORK network (reused from sign time)");
        } else {
            // Fallback: sign with VRK locally (single-admin / firstAdmin flow)
            caSignatureBytes = Midgard.Sign(settings.VendorRotatingPrivateKey, caTbs);
            logger.info("[SERVER_CERT] VVK CA cert signed with VRK (fallback)");
        }
        // Assemble with the TBS that was actually signed (timestamps match)
        byte[] fullCaCert = ServerCertBuilder.assembleCertificate(caTbsForAssembly, caSignatureBytes);
        String trustBundle = ServerCertBuilder.toPem(fullCaCert);

        // --- Sign the raw public key ---
        String pkKey = changeSet.getChangeSetId() + "-pk";
        ChangesetRequestEntity pkEntity = em.find(
                ChangesetRequestEntity.class,
                new ChangesetRequestEntity.Key(pkKey, ChangeSetType.SERVER_CERT)
        );

        String signedPublicKey = null;
        if (pkEntity != null && pkEntity.getRequestModel() != null) {
            ModelRequest pkReq = ModelRequest.FromBytes(Base64.getDecoder().decode(pkEntity.getRequestModel()));
            byte[] signedPubKeyDraft = pkReq.GetDraft();
            pkReq.SetPolicy(sCertPolicy.ToBytes());
            SignatureResponse pkSignResponse = Midgard.SignModel(settings, pkReq);
            byte[] pkSignatureBytes = java.util.Base64.getDecoder().decode(
                    pkSignResponse.Signatures[0].replace('-', '+').replace('_', '/'));
            // Store as base64: publicKeyBytes + "." + signatureBytes
            signedPublicKey = java.util.Base64.getEncoder().encodeToString(signedPubKeyDraft)
                    + "." + java.util.Base64.getEncoder().encodeToString(pkSignatureBytes);
            logger.info("[SERVER_CERT] Public key signed via ORK network");
        }

        // Store the signed certificate
        draft.setCertificate(certPem);
        draft.setTrustBundle(trustBundle);
        if (signedPublicKey != null) {
            draft.setSignedPolicy(signedPublicKey); // Reuse signedPolicy field for signed public key
        }
        draft.setDraftStatus(DraftStatus.ACTIVE);
        em.merge(draft);

        // Remove the change request entities
        ChangesetRequestEntity changesetReq = em.find(
                ChangesetRequestEntity.class,
                new ChangesetRequestEntity.Key(changeSet.getChangeSetId(), ChangeSetType.SERVER_CERT)
        );
        if (changesetReq != null) {
            changesetReq.getAdminAuthorizations().clear();
            em.remove(changesetReq);
        }

        // Clean up the CA cert entity
        if (caEntity != null) {
            if (caEntity.getAdminAuthorizations() != null) {
                caEntity.getAdminAuthorizations().clear();
            }
            em.remove(caEntity);
        }

        // Clean up the public key entity
        if (pkEntity != null) {
            if (pkEntity.getAdminAuthorizations() != null) {
                pkEntity.getAdminAuthorizations().clear();
            }
            em.remove(pkEntity);
        }

        em.flush();

        return Response.ok("Server certificate issued for " + draft.getSpiffeId()).build();
    }
}