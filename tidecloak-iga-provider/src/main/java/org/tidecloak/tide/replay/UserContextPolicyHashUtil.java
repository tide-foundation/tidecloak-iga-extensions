package org.tidecloak.tide.replay;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.tidecloak.shared.utils.JsonSorter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import java.util.Objects;

public final class UserContextPolicyHashUtil {
    private UserContextPolicyHashUtil() { }

    public static String unwrapCompactOrFirst(String stored) {
        if (stored == null) return null;
        String s = stored.trim();
        if (!s.startsWith("{")) return s;
        try {
            ObjectMapper om = new ObjectMapper();
            @SuppressWarnings("unchecked")
            Map<String, Object> m = om.readValue(s, Map.class);
            Object v = m.get("auth");
            if (v == null && !m.isEmpty()) v = m.values().iterator().next();
            return v == null ? null : String.valueOf(v);
        } catch (Exception e) {
            return s;
        }
    }

    public static String computePolicyHashFromCompact(String compact) throws Exception {
        String[] parts = compact.split("\\.");
        if (parts.length < 2) throw new IllegalArgumentException("Compact must contain header.payload");
        String hp = parts[0] + "." + parts[1];
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(hp.getBytes(StandardCharsets.UTF_8));
        String hex = java.util.HexFormat.of().withUpperCase().formatHex(digest);
        return "sha256:" + hex;
    }

    public static String injectAllowHash(String userContextJson, String hash, boolean includeAuth, boolean includeSign) {
        try {
            ObjectMapper om = new ObjectMapper();
            ObjectNode root = (ObjectNode) om.readTree(userContextJson);
            ObjectNode allow = root.with("allow");
            if (includeAuth) appendIfMissing((ArrayNode) allow.withArray("auth"), hash);
            if (includeSign) appendIfMissing((ArrayNode) allow.withArray("sign"), hash);
            return om.writeValueAsString(JsonSorter.parseAndSortArrays(root.toString()));
        } catch (Exception e) {
            throw new RuntimeException("injectAllowHash failed", e);
        }
    }

    private static void appendIfMissing(ArrayNode arr, String value) {
        for (int i = 0; i < arr.size(); i++) {
            if (Objects.equals(arr.get(i).asText(), value)) return;
        }
        arr.add(value);
    }

    public static boolean isAllowAnySha256(String userContextJson) {
        try {
            ObjectMapper om = new ObjectMapper();
            ObjectNode root = (ObjectNode) om.readTree(userContextJson);
            ObjectNode allow = (ObjectNode) root.get("allow");
            if (allow == null) return false;
            return arrayHasSha256(allow.get("auth")) || arrayHasSha256(allow.get("sign"));
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean arrayHasSha256(com.fasterxml.jackson.databind.JsonNode arr) {
        if (arr == null || !arr.isArray()) return false;
        for (var it : arr) {
            if (it.isTextual() && it.asText().startsWith("sha256:")) return true;
        }
        return false;
    }
}
