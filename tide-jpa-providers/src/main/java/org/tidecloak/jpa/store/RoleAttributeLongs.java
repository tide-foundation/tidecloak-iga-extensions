package org.tidecloak.jpa.store;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;

/** Tiny helper around RoleAttributeLongStore for common keys. */
public final class RoleAttributeLongs {
    private RoleAttributeLongs() {}

    public static final String ATTR_AP_MODEL = "tide.ap.model";

    public static void setApCompact(KeycloakSession session, RoleModel role, String apCompactRaw) {
        if (role == null) return;
        if (apCompactRaw == null || apCompactRaw.isBlank()) {
            RoleAttributeLongStore.delete(session, role.getId(), ATTR_AP_MODEL);
            role.removeAttribute(ATTR_AP_MODEL); // keep short-attr clean too
            return;
        }
        RoleAttributeLongStore.putRaw(session, role.getId(), ATTR_AP_MODEL, apCompactRaw);
        // keep a tiny marker in short-attrs (optional, helps “presence” checks)
        role.setSingleAttribute(ATTR_AP_MODEL, "_longref_");
    }

    public static String getApCompact(KeycloakSession session, RealmModel realm, String roleId) {
        return RoleAttributeLongStore.getRaw(session, roleId, ATTR_AP_MODEL);
    }
}
