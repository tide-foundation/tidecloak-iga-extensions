package org.tidecloak.base.iga;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RoleModel;
import org.midgard.models.AuthorizerPolicyModel.AuthorizerPolicy;
import org.tidecloak.jpa.store.RoleAttributeLongStore;

import java.util.*;

/**
 * Resolve AuthorizerPolicy models from role attributes.
 *
 * Prefers the long-attribute store (ROLE_ATTRIBUTE_LONG) for "tide.ap.model",
 * falling back to the short attribute when needed.
 */
public final class AuthorizerPolicyResolver {

    private AuthorizerPolicyResolver() {}

    private static final ObjectMapper om = new ObjectMapper();

    /**
     * Back-compat: parse AP(s) from role *short* attributes only.
     * If you want long-attr support, use the session-aware overload.
     */
    public static List<AuthorizerPolicy> fromRoleAttributes(Collection<RoleModel> roles) {
        List<AuthorizerPolicy> out = new ArrayList<>();
        for (RoleModel role : roles) {
            // 1) Full model string (preferred key name)
            for (String k : role.getAttributes().keySet()) {
                if (k.equalsIgnoreCase("tide.ap.model")
                        || k.equalsIgnoreCase("tide.ap.models")) { // allow multi
                    role.getAttributeStream(k).forEach(v -> parseAndAdd(v, out));
                }
            }
            // 2) Back-compat keys (auth/sign) – optional
            role.getAttributeStream("tide.ap.auth").forEach(v -> parseAndAdd(v, out));
            role.getAttributeStream("tide.ap.sign").forEach(v -> parseAndAdd(v, out));
        }
        return out;
    }

    /**
     * Preferred: parse AP(s) using the long-attribute store with fallback to short attributes.
     */
    public static List<AuthorizerPolicy> fromRoleAttributes(KeycloakSession session, Collection<RoleModel> roles) {
        List<AuthorizerPolicy> out = new ArrayList<>();

        for (RoleModel role : roles) {
            // Prefer long-attr store for tide.ap.model
            String longVal = RoleAttributeLongStore.getRaw(session, role.getId(), "tide.ap.model");
            if (longVal != null && !longVal.isBlank()) {
                parseAndAdd(longVal, out);
            }

            // Merge short/multi attributes as well
            role.getAttributeStream("tide.ap.model").forEach(v -> parseAndAdd(v, out));
            role.getAttributeStream("tide.ap.models").forEach(v -> parseAndAdd(v, out));

            // Back-compat keys:
            role.getAttributeStream("tide.ap.auth").forEach(v -> parseAndAdd(v, out));
            role.getAttributeStream("tide.ap.sign").forEach(v -> parseAndAdd(v, out));
        }
        return out;
    }

    private static void parseAndAdd(String raw, List<AuthorizerPolicy> out) {
        if (raw == null || raw.isBlank()) return;
        try {
            String s = raw.trim();
            AuthorizerPolicy ap;
            if (!s.startsWith("{") && !s.startsWith("[")) {
                ap = AuthorizerPolicy.fromCompact(s);
            } else {
                ap = om.readValue(s, AuthorizerPolicy.class);
            }
            out.add(ap);
        } catch (Exception ignored) {
            // be lenient; bad attribute should not break the flow
        }
    }
}
