package org.tidecloak.base.iga.ChangeSetProcessors.utils;

import org.keycloak.models.*;

import java.util.Set;

public final class ClientScopeResolver {
    private ClientScopeResolver() {}
    public static void collectScopedClients(KeycloakSession session, ClientModel client, Set<ClientModel> out) {
        out.add(client); // Minimal safe behavior. Extend if you want cross-client scope awareness.
    }
    public static void markOptionalScopeInactive(ClientModel client, ClientScopeModel scope) {
        // no-op in preview context
    }
}
