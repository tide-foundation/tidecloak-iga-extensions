package org.tidecloak.tide.replay;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

public final class ReplayMetaStore {
    private ReplayMetaStore() { }

    private static String key(String replayId, String name) {
        return "tide:replay:" + replayId + ":" + name;
    }

    public static void setRoleInitCert(org.keycloak.models.KeycloakSession session, String replayId, String value) {
        RealmModel realm = session.getContext().getRealm();
        realm.setAttribute(key(replayId, "roleInitCert"), value);
    }

    public static String getRoleInitCert(org.keycloak.models.KeycloakSession session, String replayId) {
        RealmModel realm = session.getContext().getRealm();
        return realm.getAttribute(key(replayId, "roleInitCert"));
    }

    public static void clearRoleInitCert(org.keycloak.models.KeycloakSession session, String replayId) {
        RealmModel realm = session.getContext().getRealm();
        realm.removeAttribute(key(replayId, "roleInitCert"));
    }
}
