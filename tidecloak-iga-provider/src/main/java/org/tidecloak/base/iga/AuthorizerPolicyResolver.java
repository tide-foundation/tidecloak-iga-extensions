package org.tidecloak.base.iga;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.models.RoleModel;
import org.midgard.models.AuthorizerPolicyModel.AuthorizerPolicy;

import java.util.*;

public final class AuthorizerPolicyResolver {
    private AuthorizerPolicyResolver() {}

    private static final ObjectMapper om = new ObjectMapper();

    /** Parse AP(s) from role attributes. Supports compact or full JSON. */
    public static List<AuthorizerPolicy> fromRoleAttributes(Collection<RoleModel> roles) {
        List<AuthorizerPolicy> out = new ArrayList<>();
        for (RoleModel role : roles) {
            // 1) Full model string (your new preferred storage)
            for (String k : role.getAttributes().keySet()) {
                if (k.equalsIgnoreCase("tide.ap.model")
                        || k.equalsIgnoreCase("tide.ap.models")) {      // allow multi
                    role.getAttributeStream(k).forEach(v -> parseAndAdd(v, out));
                }
            }
            // 2) Back-compat keys (auth/sign) – optional
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
        } catch (Exception ignored) { /* be lenient; bad attribute should not break the flow */ }
    }
}
