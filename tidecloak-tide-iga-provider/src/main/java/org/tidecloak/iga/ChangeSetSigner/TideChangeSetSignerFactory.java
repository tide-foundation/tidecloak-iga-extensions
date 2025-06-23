package org.tidecloak.iga.ChangeSetSigner;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.tidecloak.iga.utils.BasicIGAUtils;
import org.tidecloak.shared.Constants;

public class TideChangeSetSignerFactory extends ChangeSetSignerFactory {

    public static ChangeSetSigner getSigner(KeycloakSession session) throws Exception {
        RealmModel realm = session.getContext().getRealm();

        ComponentModel componentModel = realm.getComponentsStream()
                .filter(x -> x.getProviderId().equalsIgnoreCase(Constants.TIDE_VENDOR_KEY))  // Use .equals for string comparison
                .findFirst()
                .orElse(null);

        if (BasicIGAUtils.isIGAEnabled(realm) && componentModel != null ) {
            return new TideIGASigner();
        }
        if (BasicIGAUtils.isIGAEnabled(realm) && componentModel == null) {
            return new BasicIGASigner();

        }
        throw new Exception("IGA must be enabled");
    }

}
