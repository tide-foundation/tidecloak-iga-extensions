package org.tidecloak.TideRequests;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RoleModel;
import org.tidecloak.AdminRealmResource.TideAdminRealmResource;

import java.util.*;


public class TideRoleRequests {
    public static final String tideKeyProvider = "tide-vendor-key";


     // Creates a Realm Admin role for current realm. The role has full access to manage the current realm.
    public static void createRealmAdminRole(KeycloakSession session) {
        String realmAdminRoleName = "realm-admin";
        String realmManagementId = "realm-management";
        var realmAdminRole = session.getContext().getClient().addRole(realmAdminRoleName);
        session.getContext().getRealm().getClientByClientId(realmManagementId).getRolesStream().forEach(realmAdminRole::addCompositeRole);


    }

    public static void createRoleInitCert(KeycloakSession session, RoleModel role) throws JsonProcessingException {
        ClientModel client = session.getContext().getClient();

        // Grab from tide key provider
        ComponentModel componentModel = session.getContext().getRealm().getComponentsStream()
                .filter(x -> tideKeyProvider.equals(x.getProviderId()))
                .findFirst()
                .orElse(null);

        MultivaluedHashMap<String, String> config = componentModel.getConfig();

        // grab vrk
        ObjectMapper objectMapper = new ObjectMapper();
        String currentSecretKeys = config.getFirst("clientSecret");
        TideAdminRealmResource.SecretKeys secretKeys = objectMapper.readValue(currentSecretKeys, TideAdminRealmResource.SecretKeys.class);
        String vrk = secretKeys.activeVrk;

        // Expand role to grab the lowest role e.g. superAdmin:read
        HashSet<RoleModel> roleSet = new HashSet<RoleModel>();
        roleSet.add(role);
        Set<String> groups = expandCompositeRoles(roleSet);


        groups.forEach(System.out::println);

    }

    private static Set<String> expandCompositeRoles(Set<RoleModel> roles) {
        Set<RoleModel> visited = new HashSet<>();
        Set<String> expandedRoles = new HashSet<>();

        roles.forEach(roleModel -> {
            expandedRoles.addAll(expandCompositeRolesWithPaths(roleModel, visited));
        });

        return expandedRoles;
    }


    private static Set<String> expandCompositeRolesWithPaths(RoleModel role, Set<RoleModel> visited) {
        Set<String> rolePaths = new HashSet<>();

        if (!visited.contains(role)) {
            Deque<Pair<RoleModel, String>> stack = new ArrayDeque<>();
            stack.add(new Pair<>(role, ""));

            while (!stack.isEmpty()) {
                Pair<RoleModel, String> currentPair = stack.pop();
                RoleModel currentRole = currentPair.getKey();
                String path = currentPair.getValue();

                // Append current role to the path
                String rolePath = path.isEmpty() ? currentRole.getName() : path + ":" + currentRole.getName();

                // Check if it's a leaf node (not composite)
                if (!currentRole.isComposite()) {
                    // TODO: update to be more dyanmic for other attributes
                    String attributeValue = currentRole.getFirstAttribute("threshold");
                    String finalPath = (attributeValue != null && !attributeValue.isEmpty())
                            ? rolePath + "=" + attributeValue
                            : rolePath;
                    rolePaths.add(finalPath);
                } else {
                    // Traverse only if it's a composite to find child roles
                    currentRole.getCompositesStream()
                            .filter(r -> !visited.contains(r))
                            .forEach(r -> {
                                visited.add(r);
                                stack.add(new Pair<>(r, rolePath));
                            });
                }
            }
        }

        return rolePaths;
    }

    public static class Pair<K, V> {
        private final K key;
        private final V value;

        public Pair(K key, V value) {
            this.key = key;
            this.value = value;
        }

        public K getKey() {
            return key;
        }

        public V getValue() {
            return value;
        }
    }
}

