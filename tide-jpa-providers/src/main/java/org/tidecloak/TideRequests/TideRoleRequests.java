package org.tidecloak.TideRequests;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.midgard.Midgard;
import org.midgard.models.InitializerCertificateModel.InitializerCertifcate;
import org.tidecloak.jpa.entities.drafting.TideRoleDraftEntity;

import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;


public class TideRoleRequests {
    public static final String tideKeyProvider = "tide-vendor-key";
    public static final String tideRealmAdminRole = "tide-realm-admin";



    // Creates a Realm Admin role for current realm. The role has full access to manage the current realm.
    public static void createRealmAdminInitCert(KeycloakSession session) throws JsonProcessingException {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        ClientModel realmManagement = session.getContext().getRealm().getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID);

        String resource = Constants.ADMIN_CONSOLE_CLIENT_ID;
        RoleModel realmAdmin = session.getContext().getRealm().getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID).getRole(AdminRoles.REALM_ADMIN);
        RoleModel tideRealmAdmin = realmManagement.addRole(tideRealmAdminRole);
        tideRealmAdmin.addCompositeRole(realmAdmin);
        tideRealmAdmin.setSingleAttribute("tideThreshold", "1");

        ArrayList<String> signModels = new ArrayList<String>();
        signModels.add("AccessTokens");

        InitializerCertifcate initCert = createRoleInitCert(session, resource, tideRealmAdmin, "0.0.0", "EdDSA", signModels);

        RoleEntity roleEntity = em.find(RoleEntity.class, realmAdmin.getId());
        TideRoleDraftEntity roleDraft = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class)
                .setParameter("role", roleEntity)
                .getSingleResult();

        ObjectMapper objectMapper = new ObjectMapper();
        String initCertString =  objectMapper.writeValueAsString(initCert);
        roleDraft.setInitCert(initCertString);
        em.flush();
    }

    public static InitializerCertifcate createRoleInitCert(KeycloakSession session, String resource, RoleModel role , String certVersion, String algorithm, ArrayList<String> signModels) throws JsonProcessingException {
        // Grab from tide key provider
        ComponentModel componentModel = session.getContext().getRealm().getComponentsStream()
                .filter(x -> tideKeyProvider.equals(x.getProviderId()))
                .findFirst()
                .orElse(null);

        MultivaluedHashMap<String, String> config = componentModel.getConfig();
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
        // Prevent circular references
        if (visited.contains(role)) {
            return null;
        }
        visited.add(role);

        // Use LinkedHashMap to preserve the insertion order of keys
        Map<String, Object> currentRole = new LinkedHashMap<>();
        Map<String, Object> attributesMap = new HashMap<>();

        // Collect "tide" attributes in a single pass
        role.getAttributes().forEach((key, values) -> {
            if (key.startsWith("tide")) {
                attributesMap.put(key, values.size() > 1 ? values : values.get(0));
            }
        });

        // Add attributes if they exist and do not already exist in the parent role
        if (!attributesMap.isEmpty()) {
            currentRole.put("attributes", attributesMap);  // Place attributes directly after the parent role
        }

        // Process child roles if the role is composite
        if (role.isComposite()) {
            role.getCompositesStream()
                    .filter(childRole -> !visited.contains(childRole))
                    .forEach(childRole -> {
                        // Recursively get JSON for each child role
                        Map<String, Object> childJson = expandCompositeRolesToNestedJson(childRole, visited);
                        if (childJson != null && !childJson.isEmpty()) {
                            // Add the child JSON under its parent role, but don't repeat its name
                            // We use the child role's name only once, no nested repetition
                            currentRole.put(childRole.getName(), childJson.get(childRole.getName()));
                        }
                    });
        }

        // If currentRole has any attributes or child roles, we wrap it with the parent role's name
        // Otherwise, return null (i.e., no relevant data)
        return currentRole.isEmpty() ? null : Map.of(role.getName(), currentRole);
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

