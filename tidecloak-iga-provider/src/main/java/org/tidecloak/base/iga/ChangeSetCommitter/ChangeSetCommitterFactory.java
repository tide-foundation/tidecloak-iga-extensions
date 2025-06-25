package org.tidecloak.base.iga.ChangeSetCommitter;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.shared.Constants;

public class ChangeSetCommitterFactory {
    public static ChangeSetCommitter getCommitter(KeycloakSession session) throws Exception {
        try {
            // Attempt to dynamically load the override factory
            Class<?> clazz = Class.forName("org.tidecloak.tide.iga.ChangeSetCommitter.TideChangeSetCommitterFactory");
            return (ChangeSetCommitter) clazz
                    .getMethod("getCommitter", KeycloakSession.class)
                    .invoke(null, session);
        } catch (ClassNotFoundException e) {
            // Override not present – fallback to base logic
            return fallbackCommitter(session);
        } catch (Exception e) {
            throw new RuntimeException("Error while trying to load TideChangeSetCommitterFactory", e);
        }
    }

    private static ChangeSetCommitter fallbackCommitter(KeycloakSession session) throws Exception {
        RealmModel realm = session.getContext().getRealm();

        ComponentModel componentModel = realm.getComponentsStream()
                .filter(x -> x.getProviderId().equalsIgnoreCase(Constants.TIDE_VENDOR_KEY))  // Use .equals for string comparison
                .findFirst()
                .orElse(null);

        if (BasicIGAUtils.isIGAEnabled(realm) && componentModel == null) {
            return new BasicIGACommitter();

        }
        throw new Exception("IGA must be enabled");
    }

}