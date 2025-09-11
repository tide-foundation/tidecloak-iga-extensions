package org.midgard.models.AuthorizerPolicyModel;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.nio.charset.StandardCharsets;
import java.util.*;

import static java.util.Base64.getUrlDecoder;
import static java.util.Base64.getUrlEncoder;

/**
 * Server-signed attestation for a vetted policy artifact (DLL + manifest).
 * Compact form: base64url(json(header)) + "." + base64url(json(payload)) [+ "." + base64url(signature)]
 *
 * NOTE: This is different from the user-signed allow-list. This one is signed by the SERVER.
 */
public final class AuthorizerPolicy {

    private static final ObjectMapper M = new ObjectMapper()
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
            .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false)
            .setSerializationInclusion(JsonInclude.Include.NON_NULL);

    private static String b64u(byte[] b) { return getUrlEncoder().withoutPadding().encodeToString(b); }
    private static byte[] b64ud(String s) { return getUrlDecoder().decode(s); }

    private final AuthorizerPolicyHeader header;
    private final AuthorizerPolicyPayload payload;
    private final String compactNoSig;   // "h.p"
    private final byte[] signingBytes;   // UTF-8 of compactNoSig
    private final String signatureB64Url; // optional (3rd segment)

    public AuthorizerPolicy(AuthorizerPolicyHeader header, AuthorizerPolicyPayload payload, String signatureB64Url) {
        this.header = Objects.requireNonNull(header, "header");
        this.payload = Objects.requireNonNull(payload, "payload");
        try {
            String h = b64u(M.writeValueAsBytes(header));
            String p = b64u(M.writeValueAsBytes(payload));
            this.compactNoSig = h + "." + p;
            this.signingBytes  = compactNoSig.getBytes(StandardCharsets.UTF_8);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Failed to serialize AuthorizerPolicy", e);
        }
        this.signatureB64Url = signatureB64Url;
    }

    public static AuthorizerPolicy of(AuthorizerPolicyHeader h, AuthorizerPolicyPayload p) {
        return new AuthorizerPolicy(h, p, null);
    }

    /** Returns a new instance carrying the signature (does not mutate the original). */
    public AuthorizerPolicy withSignature(String sigB64Url) {
        return new AuthorizerPolicy(this.header, this.payload, sigB64Url);
    }

    public AuthorizerPolicyHeader header()  { return header; }
    public AuthorizerPolicyPayload payload(){ return payload; }
    /** Bytes that must be signed by the SERVER key. */
    public byte[] bytesForSigning()         { return signingBytes; }
    /** "header.payload" (no signature) */
    public String toCompactString()         { return compactNoSig; }
    /** "header.payload[.signature]" */
    public String toCompactStringWithSignature() {
        return (signatureB64Url == null || signatureB64Url.isBlank())
                ? compactNoSig
                : compactNoSig + "." + signatureB64Url;
    }

    /** Parse "h.p" or "h.p.s". */
    public static AuthorizerPolicy fromCompact(String compact) {
        if (compact == null || compact.isBlank()) throw new IllegalArgumentException("Empty compact");
        String[] parts = compact.split("\\.");
        if (parts.length != 2 && parts.length != 3) throw new IllegalArgumentException("Compact must have 2 or 3 segments");
        try {
            var h = M.readValue(b64ud(parts[0]), AuthorizerPolicyHeader.class);
            var p = M.readValue(b64ud(parts[1]), AuthorizerPolicyPayload.class);
            var s = parts.length == 3 ? parts[2] : null;
            return new AuthorizerPolicy(h, p, s);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid AuthorizerPolicy compact", e);
        }
    }

    /** Optional: quick structural validation; returns first error or null if OK. */
    public String validate() {
        if (header.kid == null || header.kid.isBlank()) return "kid missing";
        if (header.alg == null || header.alg.isBlank()) return "alg missing";
        if (header.vn  == null || header.vn.isBlank())  return "vn missing";
        if (!"policy-receipt".equals(header.typ)) return "typ must be 'policy-receipt'";

        if (payload.bh == null || !payload.bh.startsWith("sha256:")) return "bh missing/invalid";
        if (payload.entryType == null || payload.entryType.isBlank()) return "entryType missing";
        if (payload.sdkVersion == null || payload.sdkVersion.isBlank()) return "sdkVersion missing";
        // manifestHash is OPTIONAL unless manifestKey/storeKey present
        if ((payload.manifestKey != null || payload.storeKey != null)
                && (payload.manifestHash == null || !payload.manifestHash.startsWith("sha256:")))
            return "manifestHash required when manifest/store keys are present";
        if (payload.iat == null || payload.iat <= 0) return "iat missing/invalid";
        return null;
    }

}
