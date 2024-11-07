package org.tidecloak.TideRequests;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RoleModel;
import org.midgard.Midgard;
import org.midgard.models.InitializerCertificateModel.InitializerCertifcate;
import org.tidecloak.AdminRealmResource.TideAdminRealmResource;

import java.util.*;


public class TideRoleRequests {
    public static final String tideKeyProvider = "tide-vendor-key";


     // Creates a Realm Admin role for current realm. The role has full access to manage the current realm.
    public static void createRealmAdminRole(KeycloakSession session) throws JsonProcessingException {
        String realmAdminRoleName = "tide-realm-admin";
        String realmManagementId = "realm-management";
        String resource = "security-admin-console";

        var realmAdminRole = session.getContext().getRealm().addRole(realmAdminRoleName);
        session.getContext().getRealm().getClientByClientId(realmManagementId).getRolesStream().forEach(realmAdminRole::addCompositeRole);
        var finalRealmAdminRole = session.getContext().getRealm().getRole(realmAdminRoleName);
        ArrayList<String> signModels = new ArrayList<String>();
        signModels.add("AccessTokens");
        InitializerCertifcate initCert = createRoleInitCert(session, resource,finalRealmAdminRole, "0.0.0", "EdDSA", signModels);

        // store against realm role
    }

    public static InitializerCertifcate createRoleInitCert(KeycloakSession session, String resource, RoleModel role , String certVersion, String algorithm, ArrayList<String> signModels) throws JsonProcessingException {
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

        if (secretKeys.activeVrk.isEmpty()){
            throw new RuntimeException("Cannot generate Role initializer certificate, no active license was found");
        }

        String vvkId = config.getFirst("vvkId");
        String vendor = session.getContext().getRealm().getName();

        // Expand role to grab the lowest role e.g. superAdmin:read
        Map<String, Object> groups = expandCompositeRolesAsNestedStructure(role);

        return Midgard.constructInitCert(vvkId, algorithm, certVersion, vendor, resource, groups,  signModels);

    }

    private static Map<String, Object> expandCompositeRolesAsNestedStructure(RoleModel rootRole) {
        Set<RoleModel> visited = new HashSet<>();
        return expandCompositeRolesToNestedJson(rootRole, visited);
    }


    private static Map<String, Object> expandCompositeRolesToNestedJson(RoleModel role, Set<RoleModel> visited) {
        if (visited.contains(role)) {
            return null; // Prevent circular references
        }
        visited.add(role);

        Map<String, Object> roleJson = new HashMap<>();
        Map<String, Object> currentRole = new HashMap<>();

        if (!role.isComposite()) {
            // If the role is a leaf, add attributes if they exist
            Map<String, List<String>> attributes = role.getAttributes();
            if (!attributes.isEmpty()) {
                Map<String, Object> attributesMap = new HashMap<>();
                attributes.forEach((key, values) -> {
                    attributesMap.put(key, values.size() > 1 ? values : values.get(0));
                });
                currentRole.put("attributes", attributesMap);
            }
        } else {
            // Process child roles if composite
            role.getCompositesStream()
                    .filter(childRole -> !visited.contains(childRole))
                    .forEach(childRole -> {
                        Map<String, Object> childJson = expandCompositeRolesToNestedJson(childRole, visited);
                        if (childJson != null) {
                            currentRole.putAll(childJson); // Add child role JSON to current role
                        }
                    });
        }

        roleJson.put(role.getName(), currentRole);
        return roleJson;
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

