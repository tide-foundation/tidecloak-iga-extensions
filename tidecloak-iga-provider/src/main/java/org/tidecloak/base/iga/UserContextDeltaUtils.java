package org.tidecloak.base.iga;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.*;

public final class UserContextDeltaUtils {
    private static final ObjectMapper M = new ObjectMapper();

    private UserContextDeltaUtils() {}

    /**
     * Safe JSON parser for user-context objects.
     * - Null/blank -> {}.
     * - Non-object JSON -> {}.
     * - On error -> {}.
     */
    public static ObjectNode parseJson(String json) {
        try {
            if (json == null || json.isBlank()) return M.createObjectNode();
            JsonNode n = M.readTree(json);
            return n != null && n.isObject() ? (ObjectNode) n : M.createObjectNode();
        } catch (Exception ignore) {
            return M.createObjectNode();
        }
    }

    /**
     * Shallow delta: returns a map you can feed to buildWithDelta() to rebuild tx from default.
     * We only track role adds/removes and simple field overrides.
     */
    public static Map<String, Object> deriveDelta(String defaultJson, String txJson) {
        Map<String, Object> out = new HashMap<>();
        try {
            JsonNode d = M.readTree(defaultJson == null ? "{}" : defaultJson);
            JsonNode t = M.readTree(txJson == null ? "{}" : txJson);

            // roles
            Set<String> dr = new HashSet<>();
            d.path("roles").forEach(n -> dr.add(n.asText()));
            Set<String> tr = new HashSet<>();
            t.path("roles").forEach(n -> tr.add(n.asText()));

            Set<String> add = new HashSet<>(tr);
            add.removeAll(dr);
            Set<String> rem = new HashSet<>(dr);
            rem.removeAll(tr);

            if (!add.isEmpty()) out.put("addRoles", new ArrayList<>(add));
            if (!rem.isEmpty()) out.put("removeRoles", new ArrayList<>(rem));

            // simple overrides
            Iterator<String> it = t.fieldNames();
            while (it.hasNext()) {
                String k = it.next();
                if ("roles".equals(k) || "authorizerPolicies".equals(k)) continue;
                JsonNode tv = t.get(k);
                JsonNode dv = d.get(k);
                if (!Objects.equals(tv, dv)) {
                    if (tv.isTextual()) out.put(k, tv.asText());
                    else if (tv.isBoolean()) out.put(k, tv.asBoolean());
                    else if (tv.isNumber()) out.put(k, tv.numberValue());
                }
            }
        } catch (Exception ignore) {
            // best-effort
        }
        return out;
    }
}
