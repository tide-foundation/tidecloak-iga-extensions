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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.midgard.Midgard;
import org.midgard.models.ModelRequest;
import org.midgard.models.SignRequestSettingsMidgard;
import org.midgard.models.SignatureResponse;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

public class TideIGACommitter implements ChangeSetCommitter {
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

        // Build X.509 TBS certificate
        String issuerCn = "tide.realm." + realm.getName();
        byte[] tbsCert = ServerCertBuilder.buildTbs(
                draft.getPublicKey(),
                draft.getClientId(),
                realm.getName(),
                issuerCn,
                draft.getSpiffeId(),
                draft.getRequestedLifetime()
        );

        // Build DynamicData
        ObjectNode metadata = objectMapper.createObjectNode();
        metadata.put("realm", realm.getName());
        metadata.put("clientId", draft.getClientId());
        metadata.put("instanceId", draft.getInstanceId());
        metadata.put("spiffeId", draft.getSpiffeId());
        metadata.put("requestedLifetime", draft.getRequestedLifetime());
        byte[] dynamicData = objectMapper.writeValueAsBytes(metadata);

        // Create and sign the model request
        ModelRequest req = ModelRequest.New("ServerCert", "1", "VRK:1", tbsCert);
        req.SetDynamicData(dynamicData);
        req.SetAuthorization(Midgard.SignWithVrk(req.GetDataToAuthorize(), settings.VendorRotatingPrivateKey));
        req.SetAuthorizer(HexFormat.of().parseHex(gVRK));
        req.SetAuthorizerCertificate(java.util.Base64.getDecoder().decode(gVRKCertificate));

        SignatureResponse signatureResponse = Midgard.SignModel(settings, req);

        // Decode the VVK signature
        byte[] signatureBytes = java.util.Base64.getDecoder().decode(
                signatureResponse.Signatures[0].replace('-', '+').replace('_', '/')
        );

        // Assemble complete X.509 certificate
        byte[] fullCert = ServerCertBuilder.assembleCertificate(tbsCert, signatureBytes);
        String certPem = ServerCertBuilder.toPem(fullCert);

        // Build trust bundle: self-signed VVK CA certificate
        // The CA cert TBS is signed by VVK via ORK network
        byte[] vvkPubBytes = HexFormat.of().parseHex(gVRK);
        byte[] caTbs = ServerCertBuilder.buildVvkCaTbs(vvkPubBytes, realm.getName());

        ModelRequest caReq = ModelRequest.New("ServerCert", "1", "VRK:1", caTbs);
        ObjectNode caMeta = objectMapper.createObjectNode();
        caMeta.put("realm", realm.getName());
        caMeta.put("clientId", "VVK-CA");
        caMeta.put("instanceId", "trust-bundle");
        caMeta.put("spiffeId", "spiffe://tide.realm." + realm.getName());
        caMeta.put("requestedLifetime", 315360000L); // 10 years
        caReq.SetDynamicData(objectMapper.writeValueAsBytes(caMeta));
        caReq.SetAuthorization(Midgard.SignWithVrk(caReq.GetDataToAuthorize(), settings.VendorRotatingPrivateKey));
        caReq.SetAuthorizer(HexFormat.of().parseHex(gVRK));
        caReq.SetAuthorizerCertificate(java.util.Base64.getDecoder().decode(gVRKCertificate));

        SignatureResponse caSignResponse = Midgard.SignModel(settings, caReq);
        byte[] caSignatureBytes = java.util.Base64.getDecoder().decode(
                caSignResponse.Signatures[0].replace('-', '+').replace('_', '/'));
        String trustBundle = ServerCertBuilder.buildVvkCaCert(vvkPubBytes, realm.getName(), caSignatureBytes);

        // Store the signed certificate
        draft.setCertificate(certPem);
        draft.setTrustBundle(trustBundle);
        draft.setDraftStatus(DraftStatus.ACTIVE);
        em.merge(draft);

        // Remove the change request entity
        ChangesetRequestEntity changesetReq = em.find(
                ChangesetRequestEntity.class,
                new ChangesetRequestEntity.Key(changeSet.getChangeSetId(), ChangeSetType.SERVER_CERT)
        );
        if (changesetReq != null) {
            changesetReq.getAdminAuthorizations().clear();
            em.remove(changesetReq);
        }

        em.flush();

        return Response.ok("Server certificate issued for " + draft.getSpiffeId()).build();
    }
}