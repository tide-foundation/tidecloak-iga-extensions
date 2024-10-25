package org.tidecloak.jpa.utils;

import org.keycloak.representations.AccessToken;

import java.util.Map;

public class AccessDetails {
    private AccessToken.Access realmAccess;
    private Map<String, AccessToken.Access> clientAccesses;

    public AccessDetails(AccessToken.Access realmAccess, Map<String, AccessToken.Access> clientAccesses) {
        this.realmAccess = realmAccess;
        this.clientAccesses = clientAccesses;
    }

    public AccessToken.Access getRealmAccess() {
        return realmAccess;
    }

    public Map<String, AccessToken.Access> getClientAccesses() {
        return clientAccesses;
    }
}
