package org.tidecloak.shared.models;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.Base64;

/**
 * Minimal JSON-backed container for user-context (JWT-like) previews.
 * Back-compat fields:
 *   - "Threshold"         : integer
 *   - "InitCertHash"      : base64url bytes (legacy)
 * New fields for AP path:
 *   - "AuthorizerPolicyHash" : string marker (e.g. "sha256:ABCD..."), null/absent if none
 */
public class UserContext {
    private final JsonNode contents;

    public UserContext(String data) {
        ObjectMapper mapper = new ObjectMapper();
        try {
            this.contents = mapper.readTree(data);
        } catch (JsonProcessingException ex) {
            throw new RuntimeException("Could not serialize data into json format");
        }
    }

    public UserContext(JsonNode data) {
        this.contents = data;
    }

    // ---------------- Threshold ----------------

    public void setThreshold(int threshold) {
        ObjectNode objectNode = (ObjectNode) this.contents;
        if (threshold <= 0) {
            objectNode.remove("Threshold");
        } else {
            objectNode.put("Threshold", threshold);
        }
    }

    public int getThreshold() {
        ObjectNode objectNode = (ObjectNode) this.contents;
        JsonNode t = objectNode.get("Threshold");
        return t != null ? t.asInt() : 0;
    }

    // ---------------- Legacy InitCert hash (back-compat) ----------------

    public void setInitCertHash(byte[] hash) {
        ObjectNode objectNode = (ObjectNode) this.contents;
        if (hash == null) {
            objectNode.remove("InitCertHash");
        } else {
            objectNode.put("InitCertHash", Base64.getUrlEncoder().encodeToString(hash));
        }
    }

    public byte[] getInitCertHash() {
        ObjectNode objectNode = (ObjectNode) this.contents;
        JsonNode initCertHash = objectNode.get("InitCertHash");
        return initCertHash != null ? Base64.getUrlDecoder().decode(initCertHash.asText()) : null;
    }

    // ---------------- New AP marker ----------------

    /**
     * Set the AuthorizerPolicy marker used to associate admin approvals with this context.
     * Typical values are content-hash markers like "sha256:..." or "sha512:...".
     * Pass null to remove the field.
     */
    public void setAuthorizerPolicyHash(String marker) {
        ObjectNode objectNode = (ObjectNode) this.contents;
        if (marker == null || marker.isBlank()) {
            objectNode.remove("AuthorizerPolicyHash");
        } else {
            objectNode.put("AuthorizerPolicyHash", marker);
        }
    }

    /**
     * @return The AuthorizerPolicy marker string (e.g., "sha256:..."), or null if not present.
     */
    public String getAuthorizerPolicyHash() {
        ObjectNode objectNode = (ObjectNode) this.contents;
        JsonNode n = objectNode.get("AuthorizerPolicyHash");
        return (n == null || n.isNull()) ? null : n.asText();
    }

    // ---------------- Serialization ----------------

    public String ToString() {
        ObjectMapper mapper = new ObjectMapper();
        try {
            return mapper.writeValueAsString(this.contents);
        } catch (JsonProcessingException ex) {
            throw new RuntimeException("Could not write json contents into a byte array");
        }
    }

    public byte[] Encode() {
        ObjectMapper mapper = new ObjectMapper();
        try {
            return mapper.writeValueAsBytes(this.contents);
        } catch (JsonProcessingException ex) {
            throw new RuntimeException("Could not write json contents into a byte array");
        }
    }
}
