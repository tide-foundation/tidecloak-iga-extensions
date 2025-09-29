package org.tidecloak.base.iga.TideRequests;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.models.*;
import org.midgard.models.AuthorizerPolicyModel.AuthorizerPolicy;
import org.tidecloak.jpa.store.RoleAttributeLongStore;
import org.tidecloak.tide.iga.ForsetiPolicyFactory;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * New-engine helpers for role-bound AuthorizerPolicy (AP).
 *
 * Key ideas:
 * - Any role may carry an AP via role attribute "tide.ap.model" (compact string).
 * - Threshold is mirrored in role attribute "tideThreshold" (string).
 * - Large AP values are stored in ROLE_ATTRIBUTE_LONG via RoleAttributeLongStore to avoid VARCHAR(255) overflow.
 */
public class TideRoleRequests {

    /** Attribute keys used on roles. */
    public static final String ATTR_AP_COMPACT   = "tide.ap.model";     // compact AuthorizerPolicy (logical name)
    public static final String ATTR_THRESHOLD    = "tideThreshold";     // numeric string
    public static final String ADMIN_DEFAULT_POL = "policies/DefaultTideAdminPolicy.cs";

    private static final ObjectMapper M = new ObjectMapper();

    /**
     * Idempotently create a default "TIDE_REALM_ADMIN" role under realm-management, composite to REALM_ADMIN,
     * generate a baseline AP (auth/sign) via Forseti template, and store it on the role.
     */
    public static void createRealmAdminAuthorizerPolicy(KeycloakSession session) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        ClientModel realmMgmt = realm.getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID);
        if (realmMgmt == null) {
            throw new IllegalStateException("Realm management client not found");
        }

        RoleModel realmAdmin = realmMgmt.getRole(AdminRoles.REALM_ADMIN);
        if (realmAdmin == null) {
            throw new IllegalStateException("REALM_ADMIN role not found on realm-management");
        }

        RoleModel tideRealmAdmin = realmMgmt.getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
        if (tideRealmAdmin == null) {
            tideRealmAdmin = realmMgmt.addRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
            tideRealmAdmin.addCompositeRole(realmAdmin);
        }

        int threshold = getRoleThreshold(tideRealmAdmin, 1);
        tideRealmAdmin.setSingleAttribute(ATTR_THRESHOLD, Integer.toString(threshold));

        String resource = Constants.ADMIN_CONSOLE_CLIENT_ID;
        List<String> signModels = new ArrayList<>(List.of("UserContext:2", "Rules:1"));
        String policySource = loadDefaultPolicySource();

        Map<String, AuthorizerPolicy> aps = ForsetiPolicyFactory.createRoleAuthorizerPolicies(
                session,
                resource,
                tideRealmAdmin,
                signModels,
                policySource,
                "Ork.Forseti.Builtins.AuthorizerTemplatePolicy",
                "1.0.0"
        );

        String apAuthCompact = aps.get("auth").toCompactString();
        String apSignCompact = aps.get("sign").toCompactString();

        // Persist in ROLE_ATTRIBUTE_LONG to avoid varchar(255) overflow.
        RoleAttributeLongStore.putRaw(session, tideRealmAdmin.getId(), ATTR_AP_COMPACT, apAuthCompact);
        RoleAttributeLongStore.putRaw(session, tideRealmAdmin.getId(), "tide.ap.model.sign", apSignCompact);

        // Optionally mirror to short attributes only if they fit.
        mirrorShortIfFits(tideRealmAdmin, ATTR_AP_COMPACT, apAuthCompact);
        mirrorShortIfFits(tideRealmAdmin, "tide.ap.model.sign", apSignCompact);
    }

    /** Prefer this overload when a session is available: it reads long-store first, then short attr. */
    public static AuthorizerPolicy getRoleAuthorizerPolicy(KeycloakSession session, RoleModel role) {
        try {
            String longVal = RoleAttributeLongStore.getRaw(session, role.getId(), ATTR_AP_COMPACT);
            if (longVal != null && !longVal.isBlank()) {
                return AuthorizerPolicy.fromCompact(longVal.trim());
            }
        } catch (Throwable ignored) { /* fall back */ }
        return getRoleAuthorizerPolicy(role);
    }

    /** Back-compat: read AP from short attribute only. */
    public static AuthorizerPolicy getRoleAuthorizerPolicy(RoleModel role) {
        String compact = role.getFirstAttribute(ATTR_AP_COMPACT);
        if (compact == null || compact.isBlank()) return null;
        return AuthorizerPolicy.fromCompact(compact.trim());
    }

    /** Prefer this overload to persist via long-store and mirror short if it fits. */
    public static void setRoleAuthorizerPolicy(KeycloakSession session, RoleModel role, AuthorizerPolicy ap) {
        if (ap == null) {
            RoleAttributeLongStore.delete(session, role.getId(), ATTR_AP_COMPACT);
            role.removeAttribute(ATTR_AP_COMPACT);
            return;
        }
        String compact = ap.toCompactString();
        RoleAttributeLongStore.putRaw(session, role.getId(), ATTR_AP_COMPACT, compact);
        mirrorShortIfFits(role, ATTR_AP_COMPACT, compact);

        if (ap.payload() != null && ap.payload().threshold != null) {
            role.setSingleAttribute(ATTR_THRESHOLD, Integer.toString(ap.payload().threshold));
        }
    }

    /** Back-compat: writes only to short attribute (avoid using for big values). */
    public static void setRoleAuthorizerPolicy(RoleModel role, AuthorizerPolicy ap) {
        if (ap == null) {
            role.removeAttribute(ATTR_AP_COMPACT);
            return;
        }
        String compact = ap.toCompactString();
        mirrorShortIfFits(role, ATTR_AP_COMPACT, compact);
        if (ap.payload() != null && ap.payload().threshold != null) {
            role.setSingleAttribute(ATTR_THRESHOLD, Integer.toString(ap.payload().threshold));
        }
    }

    public static AuthorizerPolicy upsertRoleAPWithComputedThreshold(
            KeycloakSession session,
            RoleModel role,
            double thresholdPct,
            int additionalAdmins,
            List<String> signModels
    ) throws JsonProcessingException {
        int holders = countRoleHolders(session, session.getContext().getRealm(), role);
        int population = Math.max(0, holders) + Math.max(0, additionalAdmins);
        int newThreshold = Math.max(1, (int) Math.ceil(thresholdPct * Math.max(1, population)));

        String resource = resolveResourceForRole(role, Constants.ADMIN_CONSOLE_CLIENT_ID);
        List<String> sms = (signModels == null) ? Collections.emptyList() : new ArrayList<>(signModels);

        AuthorizerPolicy ap = ForsetiPolicyFactory.createRoleAuthorizerPolicy_DefaultAdminTemplate(
                session, resource, role, sms, (bh, dllB64) -> { /* NOOP */ }
        );
        ap.payload().threshold = newThreshold;

        role.setSingleAttribute(ATTR_THRESHOLD, Integer.toString(newThreshold));

        // Persist AP in long-store and mirror short if it fits
        String compact = ap.toCompactString();
        RoleAttributeLongStore.putRaw(session, role.getId(), ATTR_AP_COMPACT, compact);
        mirrorShortIfFits(role, ATTR_AP_COMPACT, compact);

        return ap;
    }

    public static void recomputeAndPersistThreshold(KeycloakSession session,
                                                    RoleModel role,
                                                    double thresholdPct,
                                                    int additionalAdmins) throws JsonProcessingException {
        AuthorizerPolicy current = getRoleAuthorizerPolicy(session, role);
        if (current == null) {
            upsertRoleAPWithComputedThreshold(session, role, thresholdPct, additionalAdmins, List.of());
            return;
        }

        int holders = countRoleHolders(session, session.getContext().getRealm(), role);
        int population = Math.max(0, holders) + Math.max(0, additionalAdmins);
        int newThreshold = Math.max(1, (int) Math.ceil(thresholdPct * Math.max(1, population)));

        current.payload().threshold = newThreshold;
        role.setSingleAttribute(ATTR_THRESHOLD, Integer.toString(newThreshold));

        // Re-write AP to long-store (content changed) and mirror short if it fits
        String compact = current.toCompactString();
        RoleAttributeLongStore.putRaw(session, role.getId(), ATTR_AP_COMPACT, compact);
        mirrorShortIfFits(role, ATTR_AP_COMPACT, compact);
    }

    /* ───────────────────────────────────────────────
       Utilities
       ─────────────────────────────────────────────── */

    private static int getRoleThreshold(RoleModel role, int fallback) {
        String t = role.getFirstAttribute(ATTR_THRESHOLD);
        if (t == null || t.isBlank()) return fallback;
        try { return Integer.parseInt(t.trim()); } catch (NumberFormatException nfe) { return fallback; }
    }

    private static String resolveResourceForRole(RoleModel role, String defaultResource) {
        String res = role.getFirstAttribute("tide.ap.resource");
        return (res == null || res.isBlank()) ? defaultResource : res;
    }

    private static int countRoleHolders(KeycloakSession session, RealmModel realm, RoleModel role) {
        // Use RoleMembers stream (available across KC versions better than getUsersStream)
        try {
            long cnt = session.users().getRoleMembersStream(realm, role).count();
            return (int) Math.min(cnt, Integer.MAX_VALUE);
        } catch (Throwable ignore) {
            return 0;
        }
    }

    private static String loadDefaultPolicySource() {
        try (InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream(ADMIN_DEFAULT_POL)) {
            if (is == null) throw new IllegalStateException("Default policy not found at resources/" + ADMIN_DEFAULT_POL);
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Failed to read " + ADMIN_DEFAULT_POL, e);
        }
    }

    /** Mirror to ROLE_ATTRIBUTE only if value length <= 255; else ensure short attr is absent. */
    private static void mirrorShortIfFits(RoleModel role, String name, String value) {
        if (value != null && value.length() <= 255) {
            role.setSingleAttribute(name, value);
        } else {
            role.removeAttribute(name);
        }
    }
}
