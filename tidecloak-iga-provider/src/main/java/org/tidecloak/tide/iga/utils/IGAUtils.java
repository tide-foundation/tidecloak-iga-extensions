package org.tidecloak.tide.iga.utils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.midgard.Midgard;
import org.midgard.models.AuthorizerPolicyModel.AuthorizerPolicy;
import org.midgard.models.AuthorizerPolicyModel.AuthorizerPolicyPayload;
import org.midgard.models.RequestExtensions.UserContextSignRequest;
import org.midgard.models.SignRequestSettingsMidgard;
import org.midgard.models.SignatureResponse;
import org.tidecloak.jpa.entities.AuthorizerEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.shared.models.SecretKeys;
import org.midgard.models.UserContext.UserContext;
import org.tidecloak.tide.replay.UserContextPolicyHashUtil;

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

    public static String compactNoSig(String compact) {
        if (compact == null || compact.isBlank()) return compact;
        String[] parts = compact.split("\\.");
        if (parts.length >= 2) return parts[0] + "." + parts[1];
        return compact;
    }

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
        out.put("auth", raw);
        out.put("sign", raw);
        return out;
    }

    public static Map<String, List<String>> buildPolicyRefs(String bundleOrCompact) {
        Map<String, String> compacts = parseApBundle(bundleOrCompact);
        String authHp = compactNoSig(compacts.get("auth"));
        String signHp = compactNoSig(compacts.get("sign"));
        String hashAuth = cfgHash(authHp);
        String hashSign = cfgHash(signHp);

        Map<String, List<String>> refs = new LinkedHashMap<>();
        refs.put("auth:Admin:2", Collections.singletonList(hashAuth));
        refs.put("sign:UserContext:2", Collections.singletonList(hashSign));
        return refs;
    }

    /**
     * Signs the provided user contexts (admins first, then normal) with VRK.
     * Injects policy hash (ph) into allow.{auth,sign} when available.
     */
    public static List<String> signContextsWithVrk(
            org.keycloak.common.util.MultivaluedHashMap<String, String> keyProviderConfig,
            UserContext[] orderedUserContexts,
            AuthorizerEntity authorizer,
            ChangesetRequestEntity changesetRequestEntity,
            String authorizerPolicy // compact OR JSON package (preferred)
    ) throws Exception {

        // ----- config / keys -----
        String currentSecretKeys = keyProviderConfig.getFirst("clientSecret");
        SecretKeys secretKeys = new ObjectMapper().readValue(currentSecretKeys, SecretKeys.class);

        int threshold = Integer.parseInt(Optional.ofNullable(System.getenv("THRESHOLD_T")).orElse("0"));
        int max       = Integer.parseInt(Optional.ofNullable(System.getenv("THRESHOLD_N")).orElse("0"));
        if (threshold == 0 || max == 0) {
            throw new RuntimeException("Env variables not set: THRESHOLD_T=" + threshold + ", THRESHOLD_N=" + max);
        }

        int numberOfUserContext = 0;
        for (UserContext uc : orderedUserContexts) {
            if (uc.getInitCertHash() == null) numberOfUserContext++;
        }

        SignRequestSettingsMidgard settings = new SignRequestSettingsMidgard();
        settings.VVKId                     = keyProviderConfig.getFirst("vvkId");
        settings.HomeOrkUrl                = keyProviderConfig.getFirst("systemHomeOrk");
        settings.PayerPublicKey            = keyProviderConfig.getFirst("payerPublic");
        settings.ObfuscatedVendorPublicKey = keyProviderConfig.getFirst("obfGVVK");
        settings.VendorRotatingPrivateKey  = secretKeys.activeVrk;
        settings.Threshold_T               = threshold;
        settings.Threshold_N               = max;

        // ----- parse Authorizer Policy input; build AuthorizerPolicy for request -----
        final ObjectMapper OM = new ObjectMapper();

        final AuthorizerPolicy signAp; // for SetInitializationCertificate
        final String          signBh;  // expected bh in admin contexts

        if (authorizerPolicy == null || authorizerPolicy.isBlank()) {
            throw new IllegalArgumentException("Missing authorizerPolicy");
        }

        if (authorizerPolicy.trim().startsWith("{")) {
            JsonNode root = OM.readTree(authorizerPolicy);
            JsonNode signNode = Objects.requireNonNull(root.get("sign"), "authorizerPolicy JSON missing 'sign'");

            String signCompact;
            if (signNode.isTextual()) {
                signCompact = signNode.asText();
            } else if (signNode.isObject() && signNode.get("compact") != null && signNode.get("compact").isTextual()) {
                signCompact = signNode.get("compact").asText();
            } else {
                throw new IllegalArgumentException("'sign' must be a string compact or object with 'compact'");
            }

            AuthorizerPolicy base = AuthorizerPolicy.fromCompact(signCompact);

            AuthorizerPolicyPayload p = base.payload();
            if (signNode.isObject()) {
                if (signNode.hasNonNull("assemblyBase64")) p.assemblyBase64 = signNode.get("assemblyBase64").asText();
                if (signNode.hasNonNull("entryType"))      p.entryType      = signNode.get("entryType").asText();
                if (signNode.hasNonNull("sdkVersion"))     p.sdkVersion     = signNode.get("sdkVersion").asText();
                if (signNode.hasNonNull("dllSize"))        p.dllSize        = signNode.get("dllSize").asLong();
                if (signNode.hasNonNull("manifestHash"))   p.manifestHash   = signNode.get("manifestHash").asText();
            }

            signAp = AuthorizerPolicy.of(base.header(), p);
            signBh = (signNode.isObject() && signNode.hasNonNull("bh"))
                    ? signNode.get("bh").asText()
                    : signAp.payload().bh;

        } else {
            signAp = AuthorizerPolicy.fromCompact(authorizerPolicy);
            signBh = signAp.payload().bh;
        }

        // ----- compute ph and inject into contexts -----
        String ph = null;
        try {
            String compact = signAp.toCompactString();
            ph = UserContextPolicyHashUtil.computePolicyHashFromCompact(compact);
        } catch (Exception ignored) {}

        if (ph != null) {
            for (int i = 0; i < orderedUserContexts.length; i++) {
                String json = orderedUserContexts[i].ToString();
                String upd  = UserContextPolicyHashUtil.injectAllowHash(json, ph, true, true);
                orderedUserContexts[i] = new UserContext(upd);
            }
        }

        // ----- build the request -----
        UserContextSignRequest req = new UserContextSignRequest("VRK:1");
        req.SetDraft(Base64.getDecoder().decode(changesetRequestEntity.getDraftRequest()));
        req.SetUserContexts(orderedUserContexts);
        req.SetInitializationCertificate(signAp);

        // Optional preflight (skip for "firstAdmin" authorizer)
        String authorizerType = Optional.ofNullable(authorizer.getType()).orElse("");
        if (!"firstAdmin".equalsIgnoreCase(authorizerType)) {
            boolean anyAdminHasPolicyHash = false;
            for (UserContext uc : orderedUserContexts) {
                String json = uc.ToString();
                if (UserContextPolicyHashUtil.isAllowAnySha256(json)) {
                    anyAdminHasPolicyHash = true;
                    break;
                }
            }
            if (!anyAdminHasPolicyHash) {
                throw new Exception("Admin context 'allow.sign' does not include a policy hash (ph): " + signBh);
            }
        }

        req.SetAuthorization(
                Midgard.SignWithVrk(req.GetDataToAuthorize(), settings.VendorRotatingPrivateKey)
        );
        req.SetAuthorizer(HexFormat.of().parseHex(authorizer.getAuthorizer()));
        req.SetAuthorizerCertificate(Base64.getDecoder().decode(authorizer.getAuthorizerCertificate()));
        req.SetNumberOfUserContexts(numberOfUserContext);

        SignatureResponse response = Midgard.SignModel(settings, req);

        List<String> signatures = new ArrayList<>();
        for (int i = 0; i < orderedUserContexts.length; i++) {
            signatures.add(response.Signatures[i]);
        }
        return signatures;
    }
}
