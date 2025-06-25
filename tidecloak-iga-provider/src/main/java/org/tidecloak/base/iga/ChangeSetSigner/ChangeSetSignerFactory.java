package org.tidecloak.base.iga.ChangeSetSigner;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.shared.Constants;

public class ChangeSetSignerFactory {

    public static ChangeSetSigner getSigner(KeycloakSession session) throws Exception {
        try {
            // Attempt to dynamically load the override factory
            Class<?> clazz = Class.forName("org.tidecloak.tide.iga.ChangeSetSigner.TideChangeSetSignerFactory");
            return (ChangeSetSigner) clazz
                    .getMethod("getSigner", KeycloakSession.class)
                    .invoke(null, session);
        } catch (ClassNotFoundException e) {
            // Override not present – fallback to base logic
            return fallbackSigner(session);
        } catch (Exception e) {
            throw new RuntimeException("Error while trying to load TideChangeSetSignerFactory", e);
        }
    }

    private static ChangeSetSigner fallbackSigner(KeycloakSession session) throws Exception {
        RealmModel realm = session.getContext().getRealm();

        ComponentModel componentModel = realm.getComponentsStream()
                .filter(x -> x.getProviderId().equalsIgnoreCase(Constants.TIDE_VENDOR_KEY))
                .findFirst()
                .orElse(null);

        if (BasicIGAUtils.isIGAEnabled(realm) && componentModel == null) {
            return new BasicIGASigner();
        }

        throw new Exception("IGA must be enabled");
    }
}
