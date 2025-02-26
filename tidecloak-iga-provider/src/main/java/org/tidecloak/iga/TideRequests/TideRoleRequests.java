package org.tidecloak.iga.TideRequests;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.midgard.Midgard;
import org.midgard.models.InitializerCertificateModel.InitializerCertifcate;
import org.tidecloak.jpa.entities.drafting.RoleInitializerCertificateDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideRoleDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.shared.enums.DraftStatus;

import java.util.*;
import java.util.stream.Collectors;


public class TideRoleRequests {



    // Creates a Realm Admin role for current realm. The role has full access to manage the current realm.
    public static void createRealmAdminInitCert(KeycloakSession session) throws Exception {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        ClientModel realmManagement = session.getContext().getRealm().getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID);

        String resource = Constants.ADMIN_CONSOLE_CLIENT_ID;
        RoleModel realmAdmin = session.getContext().getRealm().getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID).getRole(AdminRoles.REALM_ADMIN);
        RoleModel tideRealmAdmin = realmManagement.addRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
        tideRealmAdmin.addCompositeRole(realmAdmin);
        tideRealmAdmin.setSingleAttribute("tideThreshold", "1");

        ArrayList<String> signModels = new ArrayList<String>();
        signModels.add("UserContext:1");

        InitializerCertifcate initCert = createRoleInitCert(session, resource, tideRealmAdmin, "1", "EdDSA", signModels);

        if (initCert == null){
            throw new Exception("Unable to create initCert for TideRealmAdminRole, tideThreshold needs to be set");
        }

        RoleEntity roleEntity = em.find(RoleEntity.class, tideRealmAdmin.getId());
        TideRoleDraftEntity roleDraft = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class)
                .setParameter("role", roleEntity)
                .getSingleResult();

        ObjectMapper objectMapper = new ObjectMapper();
        String initCertString =  objectMapper.writeValueAsString(initCert);
        roleDraft.setInitCert(initCertString);
        em.flush();
    }

    public static void createRoleInitCertDraft(KeycloakSession session,  String recordId, String certVersion, double thresholdPercentage, int numberOfAdditionalAdmins ) throws Exception {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        String resource = Constants.ADMIN_CONSOLE_CLIENT_ID;
        RoleModel tideRealmAdmin = session.getContext().getRealm().getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID).getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
        String algorithm = "EdDSA";

        ArrayList<String> signModels = new ArrayList<String>();
        signModels.add("UserContext:1");

        List<TideUserRoleMappingDraftEntity> users = em.createNamedQuery("getUserRoleMappingsByStatusAndRole", TideUserRoleMappingDraftEntity.class)
                .setParameter("draftStatus", DraftStatus.ACTIVE)
                .setParameter("roleId", tideRealmAdmin.getId())
                .getResultList();

        int numberOfActiveAdmins = users.size();

        // numberOfActiveAdmins + 1 because we a requesting to add an additional admin
        // TODO: update to be able to change additional admin value when we can approve multiple admins at a time. ATM its one at a time.
        int threshold = Math.max(1, (int) (thresholdPercentage * (numberOfActiveAdmins + numberOfAdditionalAdmins)));

        // Grab from tide key provider
        ComponentModel componentModel = session.getContext().getRealm().getComponentsStream()
                .filter(x -> x.getProviderId().equalsIgnoreCase(org.tidecloak.shared.Constants.TIDE_VENDOR_KEY))
                .findFirst()
                .orElse(null);

        MultivaluedHashMap<String, String> config = componentModel.getConfig();
        String vvkId = config.getFirst("vvkId");
        String vendor = session.getContext().getRealm().getName();
        InitializerCertifcate initializerCertifcate = Midgard.constructInitCert(vvkId, algorithm, certVersion, vendor, resource, threshold,  signModels);

        List<RoleInitializerCertificateDraftEntity> roleInitializerCertificateDraftEntity = em.createNamedQuery("getInitCertByChangeSetId", RoleInitializerCertificateDraftEntity.class).setParameter("changesetId", recordId).getResultList();

        if(!roleInitializerCertificateDraftEntity.isEmpty()){
            throw new Exception("There is already a pending change request with this record ID, " + recordId);
        }
        ObjectMapper objectMapper = new ObjectMapper();
        String initCertString =  objectMapper.writeValueAsString(initializerCertifcate);
        RoleInitializerCertificateDraftEntity initCertDraft = new RoleInitializerCertificateDraftEntity();
        initCertDraft.setId(KeycloakModelUtils.generateId());
        initCertDraft.setChangesetRequestId(recordId);
        initCertDraft.setInitCert(initCertString);
        em.persist(initCertDraft);
        em.flush();
    }

    public static RoleInitializerCertificateDraftEntity getDraftRoleInitCert(KeycloakSession session, String recordId){
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<RoleInitializerCertificateDraftEntity> roleInitializerCertificateDraftEntity = em.createNamedQuery("getInitCertByChangeSetId", RoleInitializerCertificateDraftEntity.class).setParameter("changesetId", recordId).getResultList();
        if(roleInitializerCertificateDraftEntity.isEmpty()){
            return null;
        }
        return roleInitializerCertificateDraftEntity.get(0);
    }

    public static void commitRoleInitCert(KeycloakSession session, String recordId, String signature) throws Exception {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        RoleModel tideRealmAdmin = session.getContext().getRealm().getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID).getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
        RoleEntity roleEntity = em.find(RoleEntity.class, tideRealmAdmin.getId());

        List<TideRoleDraftEntity> tideRoleDraftEntity = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class).setParameter("role", roleEntity).getResultList();
        if(tideRoleDraftEntity.isEmpty()){
            throw new Exception("No tide role entity found for tide-realm-admin");
        }
        RoleInitializerCertificateDraftEntity roleInitializerCertificateDraftEntity = getDraftRoleInitCert(session, recordId);
        if(roleInitializerCertificateDraftEntity == null) {
            throw new Exception("There is no change request with this record ID, " + recordId);
        }

        tideRoleDraftEntity.get(0).setInitCert(roleInitializerCertificateDraftEntity.getInitCert());
        tideRoleDraftEntity.get(0).setInitCertSig(signature);
        InitializerCertifcate initCert = InitializerCertifcate.FromString(roleInitializerCertificateDraftEntity.getInitCert());
        tideRealmAdmin.setSingleAttribute("tideThreshold", Integer.toString(initCert.getPayload().getThreshold()));
        em.remove(roleInitializerCertificateDraftEntity);
        em.flush();
    }

    public static InitializerCertifcate createRoleInitCert(KeycloakSession session, String resource, RoleModel role , String certVersion, String algorithm, ArrayList<String> signModels) throws JsonProcessingException {
        // Grab from tide key provider
        ComponentModel componentModel = session.getContext().getRealm().getComponentsStream()
                .filter(x -> x.getProviderId().equalsIgnoreCase(org.tidecloak.shared.Constants.TIDE_VENDOR_KEY))
                .findFirst()
                .orElse(null);

        MultivaluedHashMap<String, String> config = componentModel.getConfig();
        String vvkId = config.getFirst("vvkId");
        String vendor = session.getContext().getRealm().getName();

        String tideThreshold = role.getFirstAttribute("tideThreshold");
        if (tideThreshold == null ) {
            return null;
        }

        int threshold = Integer.parseInt(tideThreshold);

        return Midgard.constructInitCert(vvkId, algorithm, certVersion, vendor, resource, threshold,  signModels);

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

