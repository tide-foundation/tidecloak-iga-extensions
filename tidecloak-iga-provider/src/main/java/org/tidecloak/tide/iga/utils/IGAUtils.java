package org.tidecloak.tide.iga.utils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.keycloak.common.util.MultivaluedHashMap;
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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.Base64;
import java.util.HexFormat;
import java.util.regex.Pattern;

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
            String authorizerPolicy // compact OR JSON package (preferred)
    ) throws Exception {

        // ----- config / keys -----
        String currentSecretKeys = keyProviderConfig.getFirst("clientSecret");
        SecretKeys secretKeys = new ObjectMapper().readValue(currentSecretKeys, SecretKeys.class);

        int threshold = Integer.parseInt(Optional.ofNullable(System.getenv("THRESHOLD_T")).orElse("0"));
        int max       = Integer.parseInt(Optional.ofNullable(System.getenv("THRESHOLD_N")).orElse("0"));
        if (threshold == 0 || max == 0) {
// --- Tide: compute policy hash (ph) from compact AP and inject into allow.{auth,sign} for admin contexts ---
String __tide_compact = null;
try {
    if (authorizerPolicy != null && authorizerPolicy.contains(".")) {
        __tide_compact = authorizerPolicy;
    } else if (signAp != null) {
        try { __tide_compact = signAp.toCompactString(); } catch (Throwable __ignore) { __tide_compact = null; }
    }
} catch (Throwable __ignore) { __tide_compact = null; }
String __tide_ph = null;
try {
    if (__tide_compact != null) {
        __tide_ph = org.tidecloak.tide.replay.UserContextPolicyHashUtil.computePolicyHashFromCompact(__tide_compact);
    }
} catch (Throwable __ignore) { __tide_ph = null; }
if (__tide_ph != null) {
    for (int __i = 0; __i < orderedUserContexts.length; __i++) {
        String __json = orderedUserContexts[__i].ToString();
        String __upd = org.tidecloak.tide.replay.UserContextPolicyHashUtil.injectAllowHash(__json, __tide_ph, true, true);
        orderedUserContexts[__i] = new org.midgard.models.UserContext.UserContext(__upd);
    }
}

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

        // ----- parse Authorizer Policy input; produce an enriched AP object for SetInitializationCertificate -----
        final ObjectMapper M = new ObjectMapper();

        final AuthorizerPolicy signAp; // the object we'll pass to SetInitializationCertificate
        final String          signBh;  // the BH we must find in allow.sign (admin contexts)

        if (authorizerPolicy == null || authorizerPolicy.isBlank()) {
            throw new IllegalArgumentException("Missing authorizerPolicy");
        }

        if (authorizerPolicy.trim().startsWith("{")) {
            // JSON package:
            // {
            //   "auth": {"compact":"...", "bh":"sha256:...", "assemblyBase64":"...", "entryType":"...", "sdkVersion":"1.0.0"},
            //   "sign": {"compact":"...", "bh":"sha256:...", "assemblyBase64":"...", "entryType":"...", "sdkVersion":"1.0.0"}
            // }
            JsonNode root = M.readTree(authorizerPolicy);
            JsonNode signNode = Objects.requireNonNull(root.get("sign"), "authorizerPolicy JSON missing 'sign'");

            // 1) materialize from compact
            String signCompact;
            if (signNode.isTextual()) {
                signCompact = signNode.asText();
            } else if (signNode.isObject() && signNode.get("compact") != null && signNode.get("compact").isTextual()) {
                signCompact = signNode.get("compact").asText();
            } else {
                throw new IllegalArgumentException("'sign' must be a string compact or object with 'compact'");
            }

            AuthorizerPolicy base = AuthorizerPolicy.fromCompact(signCompact);

            // 2) enrich payload with DLL/meta if present
            AuthorizerPolicyPayload p = base.payload(); // mutable fields
            if (signNode.isObject()) {
                if (signNode.hasNonNull("assemblyBase64")) p.assemblyBase64 = signNode.get("assemblyBase64").asText();
                if (signNode.hasNonNull("entryType"))      p.entryType      = signNode.get("entryType").asText();
                if (signNode.hasNonNull("sdkVersion"))     p.sdkVersion     = signNode.get("sdkVersion").asText();
                if (signNode.hasNonNull("dllSize"))        p.dllSize        = signNode.get("dllSize").asLong();
                if (signNode.hasNonNull("manifestHash"))   p.manifestHash   = signNode.get("manifestHash").asText();
            }

            // reconstruct to refresh compact bytes in case payload changed
            signAp = AuthorizerPolicy.of(base.header(), p);

            // 3) bh to check
            signBh = (signNode.isObject() && signNode.hasNonNull("bh"))
                    ? signNode.get("bh").asText()
                    : signAp.payload().bh;

        } else {
            // Legacy: single compact string (no DLL carried)
            signAp = AuthorizerPolicy.fromCompact(authorizerPolicy);
            signBh = signAp.payload().bh;
        }

        if (signBh == null || !signBh.startsWith("sha256:")) {
            throw new IllegalArgumentException("AuthorizerPolicy bh missing/invalid");
        }

        // ----- build the request -----
        UserContextSignRequest req = new UserContextSignRequest("VRK:1");
        req.SetDraft(Base64.getDecoder().decode(changesetRequestEntity.getDraftRequest()));
        req.SetUserContexts(orderedUserContexts);

        // Attach the (possibly enriched) AuthorizerPolicy object for vetting/gating/DLL storage
        req.SetInitializationCertificate(signAp);

        
// ----- preflight: ensure an admin context includes a policy hash (ph) in allow.{auth|sign} -----
boolean anyAdminHasPolicyHash = false;
for (UserContext uc : orderedUserContexts) {
    String json = uc.ToString();
    try {
        if (__tide_ph != null) {
            if (org.tidecloak.tide.replay.UserContextPolicyHashUtil.hasExactAllowHash(json, __tide_ph)) {
                anyAdminHasPolicyHash = true;
                break;
            }
        } else {
            if (org.tidecloak.tide.replay.UserContextPolicyHashUtil.isAllowAnySha256(json)) {
                anyAdminHasPolicyHash = true;
                break;
            }
        }
    } catch (Throwable __ignore) { }
}
// === CHANGE: If authorizer is "firstAdmin", skip this local check and let Forseti do the policy check ===
        String authorizerType = Optional.ofNullable(authorizer.getType()).orElse("");
        if (!anyAdminHasPolicyHash && !authorizerType.equalsIgnoreCase("firstAdmin")) {
            throw new Exception("Admin context 'allow.sign' does not include a policy hash (ph): " + signBh);
        }

        // ----- vendor auth over DataToAuthorize, authorizer identity -----
        req.SetAuthorization(
                Midgard.SignWithVrk(req.GetDataToAuthorize(), settings.VendorRotatingPrivateKey)
        );
        req.SetAuthorizer(HexFormat.of().parseHex(authorizer.getAuthorizer()));
        req.SetAuthorizerCertificate(Base64.getDecoder().decode(authorizer.getAuthorizerCertificate()));
        req.SetNumberOfUserContexts(numberOfUserContext);

        // ----- sign -----
        SignatureResponse response = Midgard.SignModel(settings, req);

        List<String> signatures = new ArrayList<>();
        for (int i = 0; i < orderedUserContexts.length; i++) {
            signatures.add(response.Signatures[i]);
        }
        return signatures;
    }

    // helpers
    private static boolean arrayHasSha256(JsonNode n, java.util.regex.Pattern pat) {
        if (n == null || !n.isArray()) return false;
        for (JsonNode e : n) if (e.isTextual() && pat.matcher(e.asText()).matches()) return true;
        return false;
    }
    private static boolean arrayContainsExact(JsonNode n, String exact) {
        if (n == null || !n.isArray()) return false;
        for (JsonNode e : n) if (e.isTextual() && exact.equals(e.asText())) return true;
        return false;
    }

}
