package org.tidecloak.tide.iga.utils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.common.util.MultivaluedHashMap;
import org.midgard.Midgard;
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

public class IGAUtils {

    private static final ObjectMapper M = new ObjectMapper();

    /* ---------------------------------------------------------
     * Helpers for AP bundle + cfg.hash (sha512 of "header.payload")
     * --------------------------------------------------------- */

    /** Return the compact “h.p” (strip an optional signature segment if present). */
    public static String compactNoSig(String compact) {
        if (compact == null || compact.isBlank()) return compact;
        String[] parts = compact.split("\\.");
        if (parts.length >= 2) return parts[0] + "." + parts[1];
        return compact;
    }

    /** sha512:HEX over UTF-8 bytes of compact “h.p”. */
    public static String cfgHash(String compactNoSig) {
        try {
            byte[] data = compactNoSig.getBytes(StandardCharsets.UTF_8);
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            byte[] d = md.digest(data);
            StringBuilder sb = new StringBuilder(d.length * 2);
            for (byte b : d) sb.append(String.format("%02x", b));
            return "sha512:" + sb;
        } catch (Exception e) {
            throw new RuntimeException("cfgHash failed", e);
        }
    }

    /** Parse role draft initCert column that now stores a bundle: {"auth":"h.p[.sig]","sign":"h.p[.sig]"} or legacy single string. */
    public static Map<String, String> parseApBundle(String raw) {
        Map<String, String> out = new HashMap<>(2);
        try {
            JsonNode n = M.readTree(raw);
            if (n.isObject() && n.has("auth") && n.has("sign")) {
                out.put("auth", n.get("auth").asText());
                out.put("sign", n.get("sign").asText());
                return out;
            }
        } catch (Exception ignored) {}
        // legacy: single compact stored directly
        out.put("auth", raw);
        out.put("sign", raw);
        return out;
    }

    /** Build the policyRefs map from a stored bundle string. */
    public static Map<String, List<String>> buildPolicyRefs(String bundleOrCompact) {
        Map<String, String> compacts = parseApBundle(bundleOrCompact);
        String authHp = compactNoSig(compacts.get("auth"));
        String signHp = compactNoSig(compacts.get("sign"));
        String hashAuth = cfgHash(authHp);
        String hashSign = cfgHash(signHp);

        Map<String, List<String>> refs = new LinkedHashMap<>();
        // keys match your “stage:model:version” convention
        refs.put("auth:Admin:2", Collections.singletonList(hashAuth));
        refs.put("sign:UserContext:2", Collections.singletonList(hashSign));
        return refs;
    }

    /* ---------------------------------------------------------
     * VRK signing (no InitCert in request anymore)
     * --------------------------------------------------------- */

    /**
     * Signs the provided user contexts (admins first, then normal) with VRK.
     * - Reads SecretKeys from keyProviderConfig["clientSecret"]
     * - Uses THRESHOLD_T/N envs as before
     * - Attaches Authorizer (vendor) and AuthorizerCertificate to the request
     * - Returns exactly one signature per user context (in the same order)
     *
     * NOTE: If you also want to transmit policyRefs to the server,
     * add them to the request model if your Midgard wrapper supports it
     * (e.g., req.SetPolicyRefs(..) or req.AddClaim("policyRefs", json)).
     */
    public static List<String> signContextsWithVrk(
            MultivaluedHashMap<String, String> keyProviderConfig,
            UserContext[] orderedUserContexts,
            AuthorizerEntity authorizer,
            ChangesetRequestEntity changesetRequestEntity,
            String authorizerPolicy
    ) throws Exception {

        String currentSecretKeys = keyProviderConfig.getFirst("clientSecret");
        SecretKeys secretKeys = new ObjectMapper().readValue(currentSecretKeys, SecretKeys.class);

        int threshold = Integer.parseInt(Optional.ofNullable(System.getenv("THRESHOLD_T")).orElse("0"));
        int max = Integer.parseInt(Optional.ofNullable(System.getenv("THRESHOLD_N")).orElse("0"));
        if (threshold == 0 || max == 0) {
            throw new RuntimeException("Env variables not set: THRESHOLD_T=" + threshold + ", THRESHOLD_N=" + max);
        }

        int numberOfUserContext = 0;
        for (UserContext uc : orderedUserContexts) {
            if (uc.getInitCertHash() == null) numberOfUserContext++;
        }

        SignRequestSettingsMidgard settings = new SignRequestSettingsMidgard();
        settings.VVKId = keyProviderConfig.getFirst("vvkId");
        settings.HomeOrkUrl = keyProviderConfig.getFirst("systemHomeOrk");
        settings.PayerPublicKey = keyProviderConfig.getFirst("payerPublic");
        settings.ObfuscatedVendorPublicKey = keyProviderConfig.getFirst("obfGVVK");
        settings.VendorRotatingPrivateKey = secretKeys.activeVrk;
        settings.Threshold_T = threshold;
        settings.Threshold_N = max;

        // Build the request (no InitCert, just contexts)
        UserContextSignRequest req = new UserContextSignRequest("VRK:1");
        req.SetDraft(Base64.getDecoder().decode(changesetRequestEntity.getDraftRequest()));
        req.SetUserContexts(orderedUserContexts);
        if(authorizerPolicy != null) {
            System.out.println(authorizerPolicy);
            req.SetInitializationCertificate(AuthorizerPolicy.fromCompact(authorizerPolicy));
        }

        // If your request model supports custom claims, uncomment and feed policyRefs here:
        // Map<String, List<String>> policyRefs = IGAUtils.buildPolicyRefs(roleApBundle);
        // String refsJson = new ObjectMapper().writeValueAsString(policyRefs);
        // req.AddClaim("policyRefs", refsJson);

        // Vendor authorization over DataToAuthorize
        req.SetAuthorization(
                Midgard.SignWithVrk(req.GetDataToAuthorize(), settings.VendorRotatingPrivateKey)
        );

        // Authorizer (vendor) identity + certificate
        req.SetAuthorizer(HexFormat.of().parseHex(authorizer.getAuthorizer()));
        req.SetAuthorizerCertificate(Base64.getDecoder().decode(authorizer.getAuthorizerCertificate()));
        req.SetNumberOfUserContexts(numberOfUserContext);

        SignatureResponse response = Midgard.SignModel(settings, req);

        List<String> signatures = new ArrayList<>();
        // exactly one per user context (no InitCert slot anymore)
        for (int i = 0; i < orderedUserContexts.length; i++) {
            signatures.add(response.Signatures[i]);
        }
        return signatures;
    }
}
