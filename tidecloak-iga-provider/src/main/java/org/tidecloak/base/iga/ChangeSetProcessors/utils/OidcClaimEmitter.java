package org.tidecloak.base.iga.ChangeSetProcessors.utils;

import org.keycloak.models.*;
import org.keycloak.representations.AccessToken;

public final class OidcClaimEmitter {
    private OidcClaimEmitter() {}
    public static void emit(KeycloakSession session, UserModel user, ClientModel client, AccessToken token) {
        // For Keycloak 26.x, full emulation requires ProtocolMappers. For preview purposes,
        // we keep this a no-op to avoid coupling with SPI internals. Safe to extend later.
    }
}
