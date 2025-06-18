package org.tidecloak.iga.ChangeSetCommitter;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.tidecloak.iga.ChangeSetSigner.BasicIGASigner;
import org.tidecloak.iga.ChangeSetSigner.TideIGASigner;
import org.tidecloak.iga.utils.IGAUtils;
import org.tidecloak.shared.Constants;

public class ChangeSetCommitterFactory {
    public static ChangeSetCommitter getCommitter(KeycloakSession session) throws Exception {
        RealmModel realm = session.getContext().getRealm();

        ComponentModel componentModel = realm.getComponentsStream()
                .filter(x -> x.getProviderId().equalsIgnoreCase(Constants.TIDE_VENDOR_KEY))  // Use .equals for string comparison
                .findFirst()
                .orElse(null);

        if (IGAUtils.isIGAEnabled(realm) && componentModel != null ) {
            return new TideIGACommitter();
        }
        else if (IGAUtils.isIGAEnabled(realm) && componentModel == null) {
            return new BasicIGACommitter();

        }
        throw new Exception("IGA must be enabled");
    }

}
