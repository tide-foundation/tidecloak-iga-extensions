package org.tidecloak.tide.iga.utils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.keycloak.common.util.MultivaluedHashMap;
import org.midgard.Midgard;
import org.midgard.models.AdminAuthorization;
import org.midgard.models.AdminAuthorizerBuilder;
import org.midgard.models.AuthorizerPolicyModel.AuthorizerPolicy;
import org.midgard.models.RequestExtensions.UserContextSignRequest;
import org.midgard.models.SignRequestSettingsMidgard;
import org.midgard.models.SignatureResponse;
import org.tidecloak.jpa.entities.AuthorizerEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.shared.models.SecretKeys;
import org.midgard.models.UserContext.UserContext;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

public class IGAUtils {

    /**
     * AP-based initial admin signing (replacement for the old InitCert path).
     * - Builds Authorizer/AuthorizerCertificate/AuthorizerApprovals memories via AdminAuthorizerBuilder using the
     *   provided AuthorizerPolicy and the approvals already attached to the ChangeSet.
     * - Uses VRK to authorize the request (same as before).
     * - Returns N signatures (one per UserContext). There is no “+1” init-cert slot in the AP path.
     */
    public static List<String> signInitialTideAdminWithAP(
            MultivaluedHashMap<String, String> keyProviderConfig,
            UserContext[] userContexts,
            AuthorizerPolicy adminAp,
            ChangesetRequestEntity changesetRequestEntity
    ) throws Exception {

        // Secrets & thresholds
        String currentSecretKeys = keyProviderConfig.getFirst("clientSecret");
        ObjectMapper objectMapper = new ObjectMapper();
        SecretKeys secretKeys = objectMapper.readValue(currentSecretKeys, SecretKeys.class);

        int threshold = Integer.parseInt(Objects.requireNonNullElse(System.getenv("THRESHOLD_T"), "0"));
        int max       = Integer.parseInt(Objects.requireNonNullElse(System.getenv("THRESHOLD_N"), "0"));

        if (threshold == 0 || max == 0) {
            throw new RuntimeException("Env variables not set: THRESHOLD_T=" + threshold + ", THRESHOLD_N=" + max);
        }

        // Count "normal" user contexts (no admin AP hash inside)
        int numberOfUserContext = 0;
        for (UserContext uc : userContexts) {
            if (uc.getInitCertHash() == null) numberOfUserContext++;
        }

        // Midgard settings (unchanged)
        SignRequestSettingsMidgard settings = new SignRequestSettingsMidgard();
        settings.VVKId                    = keyProviderConfig.getFirst("vvkId");
        settings.HomeOrkUrl               = keyProviderConfig.getFirst("systemHomeOrk");
        settings.PayerPublicKey           = keyProviderConfig.getFirst("payerPublic");
        settings.ObfuscatedVendorPublicKey= keyProviderConfig.getFirst("obfGVVK");
        settings.VendorRotatingPrivateKey = secretKeys.activeVrk;
        settings.Threshold_T              = threshold;
        settings.Threshold_N              = max;

        // Build the sign request
        UserContextSignRequest req = new UserContextSignRequest("VRK:1");
        req.SetDraft(Base64.getDecoder().decode(changesetRequestEntity.getDraftRequest()));
        req.SetUserContexts(userContexts);
        req.SetNumberOfUserContexts(numberOfUserContext);

        // VRK authorization stays the same
        req.SetAuthorization(Midgard.SignWithVrk(req.GetDataToAuthorize(), settings.VendorRotatingPrivateKey));

        // Attach Authorizer memories using AP + approvals from the changeset
        AdminAuthorizerBuilder builder = new AdminAuthorizerBuilder();
        builder.AddAuthorizerPolicy(adminAp);
        changesetRequestEntity.getAdminAuthorizations().forEach(a ->
                builder.AddAdminAuthorization(AdminAuthorization.FromString(a.getAdminAuthorization()))
        );
        builder.AddAuthorizationToSignRequest(req);

        // Call Midgard
        SignatureResponse response = Midgard.SignModel(settings, req);

        // Return exactly one signature per user context (no init-cert slot in AP path)
        List<String> signatures = new ArrayList<>(userContexts.length);
        for (int i = 0; i < userContexts.length; i++) {
            signatures.add(response.Signatures[i]);
        }
        return signatures;
    }

    /**
     * Generic VRK-based signing for user contexts using an already-stored Authorizer/Certificate memories.
     * This is unchanged from before and remains compatible with the AP-based authorizer storage,
     * because AuthorizerEntity carries the packed authorizer memories (head+sig and admin certs).
     */
    public static List<String> signContextsWithVrk(
            MultivaluedHashMap<String, String> keyProviderConfig,
            UserContext[] userContexts,
            AuthorizerEntity authorizer,
            ChangesetRequestEntity changesetRequestEntity
    ) throws Exception {

        String currentSecretKeys = keyProviderConfig.getFirst("clientSecret");
        ObjectMapper objectMapper = new ObjectMapper();
        SecretKeys secretKeys = objectMapper.readValue(currentSecretKeys, SecretKeys.class);

        int threshold = Integer.parseInt(Objects.requireNonNullElse(System.getenv("THRESHOLD_T"), "0"));
        int max       = Integer.parseInt(Objects.requireNonNullElse(System.getenv("THRESHOLD_N"), "0"));

        if (threshold == 0 || max == 0) {
            throw new RuntimeException("Env variables not set: THRESHOLD_T=" + threshold + ", THRESHOLD_N=" + max);
        }

        int numberOfUserContext = 0;
        for (UserContext uc : userContexts) {
            if (uc.getInitCertHash() == null) numberOfUserContext++;
        }

        SignRequestSettingsMidgard settings = new SignRequestSettingsMidgard();
        settings.VVKId                    = keyProviderConfig.getFirst("vvkId");
        settings.HomeOrkUrl               = keyProviderConfig.getFirst("systemHomeOrk");
        settings.PayerPublicKey           = keyProviderConfig.getFirst("payerPublic");
        settings.ObfuscatedVendorPublicKey= keyProviderConfig.getFirst("obfGVVK");
        settings.VendorRotatingPrivateKey = secretKeys.activeVrk;
        settings.Threshold_T              = threshold;
        settings.Threshold_N              = max;

        UserContextSignRequest req = new UserContextSignRequest("VRK:1");
        req.SetDraft(Base64.getDecoder().decode(changesetRequestEntity.getDraftRequest()));
        req.SetUserContexts(userContexts);
        req.SetAuthorization(Midgard.SignWithVrk(req.GetDataToAuthorize(), settings.VendorRotatingPrivateKey));

        // Use the stored authorizer memories (hex/base64) – these are AP-based in the new model
        req.SetAuthorizer(HexFormat.of().parseHex(authorizer.getAuthorizer()));
        req.SetAuthorizerCertificate(Base64.getDecoder().decode(authorizer.getAuthorizerCertificate()));
        req.SetNumberOfUserContexts(numberOfUserContext);

        SignatureResponse response = Midgard.SignModel(settings, req);

        List<String> signatures = new ArrayList<>(userContexts.length);
        for (int i = 0; i < userContexts.length; i++) {
            signatures.add(response.Signatures[i]);
        }
        return signatures;
    }
    private static boolean arrayContainsExact(JsonNode n, String exact) {
        if (n == null || !n.isArray()) return false;
        for (JsonNode e : n) if (e.isTextual() && exact.equals(e.asText())) return true;
        return false;
    }

}
