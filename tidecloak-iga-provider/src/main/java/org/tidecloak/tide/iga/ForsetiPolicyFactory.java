package org.tidecloak.tide.iga;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RoleModel;
import org.midgard.Midgard;
import org.midgard.models.AuthorizerPolicyModel.AuthorizerPolicy;
import org.midgard.models.AuthorizerPolicyModel.AuthorizerPolicyHeader;
import org.midgard.models.AuthorizerPolicyModel.AuthorizerPolicyPayload;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.function.BiConsumer;

public final class ForsetiPolicyFactory {

    private ForsetiPolicyFactory() {}

    /** Load a text resource from classpath (e.g. "policies/DefaultTideAdminPolicy.cs"). */
    private static String readResource(String pathOnClasspath) {
        try (InputStream is = Thread.currentThread()
                .getContextClassLoader()
                .getResourceAsStream(pathOnClasspath)) {
            if (is == null) {
                throw new IllegalStateException("Policy source not found on classpath: " + pathOnClasspath);
            }
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load policy source: " + pathOnClasspath, e);
        }
    }

    /** sha256:HEX helper. */
    private static String sha256Hex(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return "sha256:" + bytesToHex(md.digest(data));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /** sha512:HEX helper (cfg.hash of "header.payload" bytes). */
    private static String sha512Hex(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            return "sha512:" + bytesToHex(md.digest(data));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    /**
     * Minimal draft AP builder (unsigned): compiles the given C# policy (once),
     * persists the DLL via {@code codeStore.accept(bh, assemblyB64)} if provided,
     * and returns a single AuthorizerPolicy ("h.p", no signature).
     *
     * This is the default Admin:2 template variant.
     */
    public static AuthorizerPolicy createRoleAuthorizerPolicy_DefaultAdminTemplate(
            KeycloakSession session,
            String resource,
            RoleModel role,
            List<String> signModels,
            BiConsumer<String, String> codeStore // (bh, assemblyB64)
    ) throws JsonProcessingException {

        // Resolve vendor / vvk
        ComponentModel tideKey = session.getContext().getRealm().getComponentsStream()
                .filter(x -> x.getProviderId().equalsIgnoreCase(org.tidecloak.shared.Constants.TIDE_VENDOR_KEY))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Tide vendor key component not found"));

        String vvkId  = tideKey.getConfig().getFirst("vvkId");
        String vendor = session.getContext().getRealm().getName();

        String tideThreshold = role.getFirstAttribute("tideThreshold");
        if (tideThreshold == null) throw new IllegalStateException("Role missing 'tideThreshold'");
        int threshold = Integer.parseInt(tideThreshold);

        // Compile the default policy from resources
        final String entryType  = "Ork.Forseti.Builtins.AuthorizerTemplatePolicy";
        final String sdkVersion = "1.0.0";
        final String source     = readResource("policies/DefaultTideAdminPolicy.cs");

        var compile = Midgard.CompilePolicy(source, entryType, sdkVersion);
        if (compile.diagnostics != null && !compile.diagnostics.isBlank()) {
            throw new IllegalStateException("Policy compile diagnostics: " + compile.diagnostics);
        }
        // Store DLL by content hash (bh)
        if (codeStore != null) codeStore.accept(compile.bh, compile.assemblyBase64);

        // Build UNSIGNED AP (header + payload)
        var header = new AuthorizerPolicyHeader(vvkId, "EdDSA", "1");

        var payload = new AuthorizerPolicyPayload();
        payload.vvkid      = vvkId;
        payload.vendor     = vendor;
        payload.resource   = resource;
        payload.threshold  = threshold;
        payload.id         = UUID.randomUUID().toString();
        payload.authFlows  = new ArrayList<>(List.of("Admin:2")); // template is Admin:2
        payload.signmodels = new ArrayList<>(signModels == null ? List.of("UserContext:1") : signModels);
        payload.policy     = role.getName();

        // Linkage + metadata
        payload.bh         = compile.bh;      // code blob hash (sha256:...)
        payload.entryType  = compile.entryType;
        payload.sdkVersion = compile.sdkVersion;
        payload.mode       = "enforce";
        payload.action     = "*";
        payload.iat        = System.currentTimeMillis() / 1000;

        return AuthorizerPolicy.of(header, payload);
    }

    /**
     * Build two draft APs (auth & sign) for the same compiled policy.
     * They are currently identical in content; the "stage" is determined by server routing (Forseti routes),
     * and the client will reference them via {@code policyRefs["auth:..."]} and {@code policyRefs["sign:..."]}.
     *
     * Returns a map with keys: "auth" and "sign".
     */
    public static Map<String, AuthorizerPolicy> createRoleAuthorizerPolicies(
            KeycloakSession session,
            String resource,
            RoleModel role,
            List<String> signModels,
            String policySource,   // C# source for the template
            String entryType,      // e.g. "Ork.Forseti.Builtins.AuthorizerTemplatePolicy"
            String sdkVersion,     // e.g. "1.0.0"
            BiConsumer<String, String> codeStore // (bh, assemblyB64)
    ) throws JsonProcessingException {

        // Resolve vendor / vvk
        ComponentModel tideKey = session.getContext().getRealm().getComponentsStream()
                .filter(x -> x.getProviderId().equalsIgnoreCase(org.tidecloak.shared.Constants.TIDE_VENDOR_KEY))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Tide vendor key component not found"));

        String vvkId  = tideKey.getConfig().getFirst("vvkId");
        String vendor = session.getContext().getRealm().getName();

        String tideThreshold = role.getFirstAttribute("tideThreshold");
        if (tideThreshold == null) throw new IllegalStateException("Role missing 'tideThreshold'");
        int threshold = Integer.parseInt(tideThreshold);

        // Compile once
        var compile = Midgard.CompilePolicy(policySource, entryType, sdkVersion);
        if (compile.diagnostics != null && !compile.diagnostics.isBlank()) {
            throw new IllegalStateException("Policy compile diagnostics: " + compile.diagnostics);
        }
        if (codeStore != null) codeStore.accept(compile.bh, compile.assemblyBase64);

        // Header shared by both APs
        var header = new AuthorizerPolicyHeader(vvkId, "EdDSA", "1");

        // ---- payload for AUTH (unique id) ----
        var payloadAuth = new AuthorizerPolicyPayload();
        payloadAuth.vvkid      = vvkId;
        payloadAuth.vendor     = vendor;
        payloadAuth.resource   = resource;
        payloadAuth.threshold  = threshold;
        payloadAuth.id         = UUID.randomUUID().toString();
        payloadAuth.authFlows  = new ArrayList<>(List.of("Admin:2"));
        payloadAuth.signmodels = new ArrayList<>(signModels == null ? List.of("UserContext:1") : signModels);
        payloadAuth.policy     = role.getName();
        payloadAuth.bh         = compile.bh;
        payloadAuth.entryType  = compile.entryType;
        payloadAuth.sdkVersion = compile.sdkVersion;
        payloadAuth.mode       = "enforce";
        payloadAuth.action     = "*";
        // if your payload model doesn't have iat, delete the next line:
        payloadAuth.iat        = System.currentTimeMillis() / 1000;

        var apAuth = AuthorizerPolicy.of(header, payloadAuth);

        // ---- payload for SIGN (another unique id) ----
        var payloadSign = new AuthorizerPolicyPayload();
        payloadSign.vvkid      = vvkId;
        payloadSign.vendor     = vendor;
        payloadSign.resource   = resource;
        payloadSign.threshold  = threshold;
        payloadSign.id         = UUID.randomUUID().toString(); // different from auth
        payloadSign.authFlows  = new ArrayList<>(List.of("Admin:2"));
        payloadSign.signmodels = new ArrayList<>(signModels == null ? List.of("UserContext:1") : signModels);
        payloadSign.policy     = role.getName();
        payloadSign.bh         = compile.bh;
        payloadSign.entryType  = compile.entryType;
        payloadSign.sdkVersion = compile.sdkVersion;
        payloadSign.mode       = "enforce";
        payloadSign.action     = "*";
        // if your payload model doesn't have iat, delete the next line:
        payloadSign.iat        = System.currentTimeMillis() / 1000;

        var apSign = AuthorizerPolicy.of(header, payloadSign);

        // ---- (optional) compute cfg.hash for policyRefs ----
        // var preAuth = Midgard.BuildPolicyReceiptPreSign(header, payloadAuth);
        // var preSign = Midgard.BuildPolicyReceiptPreSign(header, payloadSign);
        // String cfgHashAuth = "sha512:" + bytesToHex(preAuth.hash); // or sha512Hex(preAuth.data)
        // String cfgHashSign = "sha512:" + bytesToHex(preSign.hash);

        Map<String, AuthorizerPolicy> out = new HashMap<>(2);
        out.put("auth", apAuth);
        out.put("sign", apSign);
        return out;
    }

}
