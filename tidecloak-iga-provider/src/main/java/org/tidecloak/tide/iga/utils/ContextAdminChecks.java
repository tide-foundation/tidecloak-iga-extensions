package org.tidecloak.tide.iga.utils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.regex.Pattern;

public final class ContextAdminChecks {
    private static final ObjectMapper OM = new ObjectMapper();
    private static final Pattern SHA256_LINK = Pattern.compile("(?i)^\\s*sha256:[0-9a-f]{64}\\s*$");

    /**
     * True if node is an array containing at least one "sha256:<64-hex>" string.
     */
    private static boolean arrayHasSha256(JsonNode n) {
        if (n == null || !n.isArray()) return false;
        for (JsonNode e : n) {
            if (e.isTextual() && SHA256_LINK.matcher(e.asText()).matches())
                return true;
        }
        return false;
    }

    /**
     * True if the JSON object has allow.auth/sign with any sha256:* link.
     */
    public static boolean isAdminByAllowAny(ObjectNode root) {
        if (root == null) return false;
        JsonNode allow = root.get("allow");
        if (allow == null || !allow.isObject()) return false;
        return arrayHasSha256(allow.get("auth")) || arrayHasSha256(allow.get("sign"));
    }

    /**
     * Your full rule: admin iff InitCertHash present OR allow.* contains sha256:*
     */
    public static boolean isAdminContext(ObjectNode root) {
        if (root == null) return false;
        if (root.hasNonNull("InitCertHash")) return true;           // legacy path
        return isAdminByAllowAny(root);                              // AP allow-list path
    }

    /**
     * Convenience overload if you only have a String.
     */
    public static boolean isAdminContext(String userContextJson) {
        try {
            JsonNode root = OM.readTree(userContextJson);
            return (root instanceof ObjectNode) && isAdminContext((ObjectNode) root);
        } catch (Exception e) {
            return false;
        }
    }
}
