// # TIDECLOAK IMPLEMENTATION
package org.tidecloak.preview.authz;

import org.keycloak.models.*;
import org.keycloak.representations.AccessToken;

import java.util.Set;

/** No-op policy linker. If a rules engine is available, hook here to enrich the token with authorization data. */
public class PolicyLinker {
    public static void attachPolicies(KeycloakSession session, RealmModel realm, Set<RoleModel> roles, AccessToken token){
        // Intentionally left as a no-op for Base-IGA. Tide-IGA can patch this at build-time.
    }
}
