package org.tidecloak.iga.changesetsigner;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminAuth;
import org.tidecloak.iga.utils.IGAUtils;
import org.tidecloak.shared.Constants;

public class ChangeSetSignerFactory {
    public static ChangeSetSigner getSigner(KeycloakSession session) throws Exception {
        RealmModel realm = session.getContext().getRealm();

        ComponentModel componentModel = realm.getComponentsStream()
                .filter(x -> x.getProviderId().equalsIgnoreCase(Constants.TIDE_VENDOR_KEY))  // Use .equals for string comparison
                .findFirst()
                .orElse(null);

        if (IGAUtils.isIGAEnabled(realm) && componentModel != null ) {
            return new TideIGASigner();
        }
        else if (IGAUtils.isIGAEnabled(realm) && componentModel == null) {
            return new BasicIGASigner();

        }
        throw new Exception("IGA must be enabled");
    }
}
