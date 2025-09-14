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
        payload.signmodels = new ArrayList<>(signModels == null ? Collections.emptyList() : signModels);
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
            String policySource,   // C# source
            String entryType,      // e.g. "Ork.Forseti.Builtins.AuthorizerTemplatePolicy"
            String sdkVersion      // e.g. "1.0.0"
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

        var header = new AuthorizerPolicyHeader(vvkId, "EdDSA", "1");

        java.util.function.Supplier<AuthorizerPolicyPayload> makePayload = () -> {
            var p = new AuthorizerPolicyPayload();
            p.vvkid      = vvkId;
            p.vendor     = vendor;
            p.resource   = resource;
            p.threshold  = threshold;
            p.id         = java.util.UUID.randomUUID().toString();
            p.authFlows  = new java.util.ArrayList<>(java.util.List.of("Admin:2"));
            p.signmodels = new java.util.ArrayList<>(signModels == null ? java.util.Collections.emptyList() : signModels);
            p.policy     = role.getName();
            p.bh         = compile.bh;
            p.entryType  = compile.entryType;
            p.sdkVersion = compile.sdkVersion;
            p.mode       = "enforce";
            p.action     = "*";
            p.iat        = System.currentTimeMillis() / 1000;

            // Embed the compiled DLL so the server can vet/validate it (no client code store)
            p.assemblyBase64 = compile.assemblyBase64;
            p.dllSize    = (long) java.util.Base64.getDecoder().decode(compile.assemblyBase64).length;

            return p;
        };

        var apAuth = AuthorizerPolicy.of(header, makePayload.get());
        var apSign = AuthorizerPolicy.of(header, makePayload.get());

        var out = new java.util.HashMap<String, AuthorizerPolicy>(2);
        out.put("auth", apAuth);
        out.put("sign", apSign);
        return out;
    }

}
