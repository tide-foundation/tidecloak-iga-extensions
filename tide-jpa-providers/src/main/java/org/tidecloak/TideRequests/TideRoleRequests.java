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
import org.tidecloak.jpa.utils.IGAUtils;

import java.util.*;


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
        System.out.println("HERE");
        System.out.println(initCertString);
        roleDraft.setInitCert(initCertString);
        em.flush();
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
        IGAUtils.SecretKeys secretKeys = objectMapper.readValue(currentSecretKeys, IGAUtils.SecretKeys.class);
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
                    if(key.startsWith("tide")){
                        attributesMap.put(key, values.size() > 1 ? values : values.get(0));
                    }
                });
                currentRole.put("attributes", attributesMap);
            }
        } else {
            // Process child roles if composite
            role.getCompositesStream()
                    .filter(childRole -> !visited.contains(childRole))
                    .forEach(childRole -> {
                        Map<String, Object> childJson = expandCompositeRolesToNestedJson(childRole, visited);
                        if (childJson != null && !childJson.isEmpty()) { // Only add non-empty child roles
                            currentRole.putAll(childJson); // Add child role JSON to current role
                        }
                    });
        }

        // Only add roles with attributes or nested non-empty roles
        if (!currentRole.isEmpty()) {
            roleJson.put(role.getName(), currentRole);
        }

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

