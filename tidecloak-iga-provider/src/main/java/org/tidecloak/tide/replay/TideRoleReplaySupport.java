package org.tidecloak.tide.replay;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.models.ModelException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RoleModel;
import org.midgard.models.AuthorizerPolicyModel.AuthorizerPolicy;
import org.tidecloak.base.iga.utils.BasicIGAUtils;

import java.util.*;

/**
 * Helpers to stage/commit role AuthorizerPolicy (AP) changes via ReplayMetaStore.
 */
public final class TideRoleReplaySupport {
    private TideRoleReplaySupport() { }

    public static void createRoleAuthorizerPolicyDraft(
            KeycloakSession session,
            String replayId,
            String certVersion,
            double thresholdPercentage,
            int numberOfAdditionalAdmins,
            RoleModel role
    ) throws Exception {
        String stored = Optional.ofNullable(role.getFirstAttribute("InitCertBundle"))
                .orElse(role.getFirstAttribute("InitCert"));

        String compactBase;
        if (stored != null && stored.trim().startsWith("{")) {
            @SuppressWarnings("unchecked")
            Map<String, String> m = new ObjectMapper().readValue(stored, Map.class);
            compactBase = m.getOrDefault("auth", m.values().stream().findFirst().orElseThrow());
        } else {
            compactBase = stored;
        }

        if (compactBase == null || compactBase.isBlank()) {
            throw new ModelException("Role has no existing InitCert/InitCertBundle to base draft on");
        }

        AuthorizerPolicy prev = AuthorizerPolicy.fromCompact(compactBase);
        int population = Math.max(1, numberOfAdditionalAdmins);
        int newThreshold = Math.max(1, (int) Math.ceil(thresholdPercentage * population));

        // clone & set new threshold
        AuthorizerPolicy ap = AuthorizerPolicy.fromCompact(compactBase);
        ap.payload().threshold = newThreshold;

        ReplayMetaStore.setRoleInitCert(session, replayId, ap.toCompactString());
    }

    public static void commitRoleAuthorizerPolicy(KeycloakSession session,
                                                  String replayId,
                                                  Object mapping,
                                                  String signature) throws Exception {
        String roleId = resolveRoleId(mapping);
        if (roleId == null || roleId.isBlank()) {
            throw new ModelException("Unable to resolve role id from mapping");
        }
        RoleModel roleModel = session.getContext().getRealm().getRoleById(roleId);
        if (roleModel == null) throw new ModelException("Role not found for id=" + roleId);

        String stored = ReplayMetaStore.getRoleInitCert(session, replayId);
        if (stored == null || stored.isBlank()) return;

        if (stored.trim().startsWith("{")) {
            roleModel.setSingleAttribute("InitCertBundle", stored);
            roleModel.removeAttribute("InitCert");
        } else {
            roleModel.setSingleAttribute("InitCert", stored);
            roleModel.removeAttribute("InitCertBundle");
        }
        if (signature != null) roleModel.setSingleAttribute("InitCertSig", signature);

        try {
            String compact = UserContextPolicyHashUtil.unwrapCompactOrFirst(stored);
            AuthorizerPolicy ap = AuthorizerPolicy.fromCompact(compact);
            if (ap.payload().threshold != null) {
                roleModel.setSingleAttribute("tideThreshold", Integer.toString(ap.payload().threshold));
            }
        } catch (Exception ignore) { }

        ReplayMetaStore.clearRoleInitCert(session, replayId);
    }

    /** Resolve role id from a variety of mapping shapes (getter/field), or fallback to parsing draft JSON. */
    private static String resolveRoleId(Object mapping) {
        if (mapping == null) return null;

        // Common direct getters
        for (String g : new String[] { "getRoleId", "getTargetRoleId", "getId" }) {
            try {
                Object v = mapping.getClass().getMethod(g).invoke(mapping);
                if (v != null && !String.valueOf(v).isBlank()) return String.valueOf(v);
            } catch (NoSuchMethodException ignored) {
            } catch (Throwable t) {
                throw new RuntimeException("Error reading " + g + " from mapping: " + t.getMessage(), t);
            }
        }
        // Nested role getter
        try {
            Object role = mapping.getClass().getMethod("getRole").invoke(mapping);
            if (role != null) {
                try {
                    Object id = role.getClass().getMethod("getId").invoke(role);
                    if (id != null && !String.valueOf(id).isBlank()) return String.valueOf(id);
                } catch (NoSuchMethodException ignored) { }
            }
        } catch (NoSuchMethodException ignored) {
        } catch (Throwable t) {
            throw new RuntimeException("Error reading getRole()/getId() from mapping: " + t.getMessage(), t);
        }

        // Fields
        for (String f : new String[] { "roleId", "targetRoleId", "id" }) {
            try {
                var fld = mapping.getClass().getDeclaredField(f);
                fld.setAccessible(true);
                Object v = fld.get(mapping);
                if (v != null && !String.valueOf(v).isBlank()) return String.valueOf(v);
            } catch (NoSuchFieldException ignored) {
            } catch (Throwable t) {
                throw new RuntimeException("Error reading field " + f + " from mapping: " + t.getMessage(), t);
            }
        }

        // Last resort: parse any embedded draft/payload JSON via BasicIGAUtils
        try {
            return BasicIGAUtils.resolveTargetRoleIdFromDraft(mapping, null);
        } catch (Throwable ignored) { }

        return null;
    }
}
