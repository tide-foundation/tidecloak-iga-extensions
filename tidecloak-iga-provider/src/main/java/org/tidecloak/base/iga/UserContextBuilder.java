package org.tidecloak.base.iga;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.keycloak.models.*;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public final class UserContextBuilder {

    private UserContextBuilder() {}

    /** Build the current active context (claims) for user+client. */
    public static ObjectNode build(KeycloakSession session, RealmModel realm, UserModel user, ClientModel client) {
        ObjectNode root = JsonNodeFactory.instance.objectNode();

        root.put("sub", user.getId());
        root.put("clientId", client.getClientId());
        root.put("realm", realm.getName());

        // Roles (realm + client)
        Set<String> roles = new HashSet<>();
        user.getRoleMappingsStream().forEach(r -> roles.add(r.getName()));
        user.getClientRoleMappingsStream(client).forEach(r -> roles.add(r.getName()));

        root.putArray("roles").addAll(
                roles.stream().sorted().map(JsonNodeFactory.instance::textNode).toList()
        );

        // Groups
        Set<String> groups = user.getGroupsStream().map(GroupModel::getName).collect(Collectors.toCollection(TreeSet::new));
        root.putArray("groups").addAll(groups.stream().map(JsonNodeFactory.instance::textNode).toList());

        return root;
    }

    /** Build the context as-if a delta were applied. Shallow, additive/removal of first-level arrays/flags. */
    public static ObjectNode buildWithDelta(KeycloakSession session, RealmModel realm, UserModel user, ClientModel client,
                                            Map<String, Object> delta) {
        ObjectNode base = build(session, realm, user, client);
        if (delta == null || delta.isEmpty()) return base;

        @SuppressWarnings("unchecked")
        List<String> addRoles = (List<String>) delta.getOrDefault("addRoles", Collections.emptyList());
        @SuppressWarnings("unchecked")
        List<String> removeRoles = (List<String>) delta.getOrDefault("removeRoles", Collections.emptyList());

        Set<String> roles = new HashSet<>();
        base.withArray("roles").forEach(n -> roles.add(n.asText()));
        roles.addAll(addRoles);
        roles.removeAll(removeRoles);

        base.putArray("roles").removeAll();
        roles.stream().sorted().forEach(r -> base.withArray("roles").add(r));

        // Merge simple overrides
        delta.forEach((k, v) -> {
            if ("addRoles".equals(k) || "removeRoles".equals(k)) return;
            if (v instanceof String s) base.put(k, s);
            else if (v instanceof Boolean b) base.put(k, b);
            else if (v instanceof Number n) base.put(k, n.doubleValue());
        });

        return base;
    }

    /** Add all linked AuthorizerPolicy references into the context (for UI & signing). */
    public static void attachAuthorizerPolicies(KeycloakSession session, RealmModel realm, UserModel user, ClientModel client,
                                                ObjectNode ctx) {
        Set<RoleModel> effective = Stream.concat(
                        user.getRoleMappingsStream(),
                        user.getClientRoleMappingsStream(client))
                .collect(Collectors.toSet());

        Set<String> apModels = new HashSet<>();
        for (RoleModel r : effective) {
            String apModel = r.getFirstAttribute("tide.ap.model");
            if (apModel != null && !apModel.isBlank()) apModels.add(apModel);
        }

        if (!apModels.isEmpty()) {
            var arr = ctx.putArray("authorizerPolicies");
            apModels.stream().sorted().forEach(arr::add);
        }
    }
}
