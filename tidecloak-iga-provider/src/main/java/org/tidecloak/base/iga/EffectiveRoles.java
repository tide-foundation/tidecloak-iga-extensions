package org.tidecloak.base.iga;

import org.keycloak.models.*;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

public final class EffectiveRoles {
    private EffectiveRoles() {}

    public static Set<RoleModel> collect(KeycloakSession session, RealmModel realm, UserModel user) {
        Set<RoleModel> out = new HashSet<>();

        // Direct role mappings
        out.addAll(user.getRoleMappingsStream().collect(Collectors.toSet()));

        // Group roles
        user.getGroupsStream().forEach(g -> {
            out.addAll(g.getRoleMappingsStream().collect(Collectors.toSet()));
        });

        // Expand composites transitively
        Set<RoleModel> closure = new HashSet<>();
        for (RoleModel r : out) expandComposite(r, closure);
        out.addAll(closure);

        return out;
    }

    private static void expandComposite(RoleModel r, Set<RoleModel> acc) {
        r.getCompositesStream().forEach(c -> {
            if (acc.add(c)) expandComposite(c, acc);
        });
    }
}
