package org.midgard.models.AuthorizerPolicyModel;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Objects;

/**
 * Bundles the server-signed AuthorizerPolicy "receipt" with the compiled DLL metadata.
 * This is what you persist and/or pass around after compile + receipt-build.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public final class ConstructedAuthorizerPolicy {

    private static final ObjectMapper M = new ObjectMapper();

    @JsonProperty("policy")         public final AuthorizerPolicy policy;   // header+payload (+optional sig)
    @JsonProperty("compact")        public final String compact;            // b64u(header)+"."+b64u(payload)[."."+b64u(sig)]
    @JsonProperty("data")           public final String data;               // b64u(header)+"."+b64u(payload) (bytes-to-sign)
    @JsonProperty("hash")           public final String hash;               // sha512 of UTF8(data)
    @JsonProperty("assemblyBase64") public final String assemblyBase64;     // compiled DLL (base64)
    @JsonProperty("bh")             public final String bh;                 // "sha256:<HEX>" of DLL
    @JsonProperty("entryType")      public final String entryType;          // verified FQN from DLL
    @JsonProperty("sdkVersion")     public final String sdkVersion;         // Policy SDK fence

    public ConstructedAuthorizerPolicy(
            AuthorizerPolicy policy,
            String compact,
            String data,
            String hash,
            String assemblyBase64,
            String bh,
            String entryType,
            String sdkVersion) {
        this.policy         = Objects.requireNonNull(policy, "policy");
        this.compact        = compact;
        this.data           = data;
        this.hash           = hash;
        this.assemblyBase64 = assemblyBase64;
        this.bh             = bh;
        this.entryType      = entryType;
        this.sdkVersion     = sdkVersion;
    }

    /** Build directly from pieces you already hold (no bridge JSON parsing). */
    public static ConstructedAuthorizerPolicy fromPieces(
            AuthorizerPolicy policy,
            String assemblyBase64, String bh, String entryType, String sdkVersion,
            String compact, String data, String hash) {
        return new ConstructedAuthorizerPolicy(
                policy, compact, data, hash, assemblyBase64, bh, entryType, sdkVersion
        );
    }

    /**
     * Build by parsing the raw JSON payloads returned by the C# bridge:
     *  - compileJson  : result of Exports.CompilePolicy (assemblyBase64, bh, entryType, sdkVersion, diagnostics)
     *  - envelopeJson : result of Exports.BuildAuthorizerPolicy (compact, data, hash, diagnostics)
     */
    public static ConstructedAuthorizerPolicy fromBridgeJson(
            AuthorizerPolicy policy,
            String compileJson,
            String envelopeJson) {

        try {
            JsonNode c = M.readTree(compileJson);
            JsonNode e = M.readTree(envelopeJson);

            String cDiag = getOpt(c, "diagnostics");
            String eDiag = getOpt(e, "diagnostics");
            if (cDiag != null && !cDiag.isBlank()) throw new IllegalArgumentException("CompilePolicy diagnostics: " + cDiag);
            if (eDiag != null && !eDiag.isBlank()) throw new IllegalArgumentException("BuildAuthorizerPolicy diagnostics: " + eDiag);

            String assemblyBase64 = getReq(c, "assemblyBase64");
            String bh             = getReq(c, "bh");
            String entryType      = getReq(c, "entryType");
            String sdkVersion     = getReq(c, "sdkVersion");

            String compact        = getReq(e, "compact");
            String data           = getReq(e, "data");
            String hash           = getReq(e, "hash");

            return new ConstructedAuthorizerPolicy(
                    policy, compact, data, hash,
                    assemblyBase64, bh, entryType, sdkVersion
            );
        } catch (Exception ex) {
            throw new IllegalArgumentException("Failed to build ConstructedAuthorizerPolicy", ex);
        }
    }

    private static String getOpt(JsonNode n, String f) {
        JsonNode v = n.get(f);
        return (v == null || v.isNull()) ? null : v.asText();
    }
    private static String getReq(JsonNode n, String f) {
        String v = getOpt(n, f);
        if (v == null || v.isBlank()) throw new IllegalArgumentException("Missing field: " + f);
        return v;
    }

    @Override public String toString() {
        return "ConstructedAuthorizerPolicy{bh='" + bh + "', entryType='" + entryType + "', sdkVersion='" + sdkVersion + "'}";
    }
}
