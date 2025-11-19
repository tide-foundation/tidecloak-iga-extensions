package org.tidecloak.base.iga.TideRequests;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.midgard.models.Policy.*;

import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.tidecloak.jpa.entities.drafting.PolicyDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideRoleDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.shared.enums.DraftStatus;


import java.util.*;

import static org.tidecloak.base.iga.utils.BasicIGAUtils.getRoleIdFromEntity;


public class TideRoleRequests {

    // Creates a Realm Admin role for current realm. The role has full access to manage the current realm.
    public static void createRealmAdminPolicy(KeycloakSession session) throws Exception {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        ClientModel realmManagement = session.getContext().getRealm().getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID);

        String resource = Constants.ADMIN_CONSOLE_CLIENT_ID;
        RoleModel realmAdmin = session.getContext().getRealm().getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID).getRole(AdminRoles.REALM_ADMIN);
        RoleModel tideRealmAdmin = realmManagement.addRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
        tideRealmAdmin.addCompositeRole(realmAdmin);
        tideRealmAdmin.setSingleAttribute("tideThreshold", "1");

        ArrayList<String> signModels = new ArrayList<String>(List.of("UserContext:1", "Policy:1", "Offboard:1", "RotateVRK:1"));

        Policy policy = createRolePolicy(session, tideRealmAdmin);

        if (policy == null){
            throw new Exception("Unable to create initCert for TideRealmAdminRole, tideThreshold needs to be set");
        }

        RoleEntity roleEntity = em.find(RoleEntity.class, tideRealmAdmin.getId());
        TideRoleDraftEntity roleDraft = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class)
                .setParameter("role", roleEntity)
                .getSingleResult();

        ObjectMapper objectMapper = new ObjectMapper();
        String rolePolicyString =  policy.ToString();
        roleDraft.setInitCert(rolePolicyString);

        em.flush();
    }

    public static void createRolePolicyDraft(KeycloakSession session, String policyString, String recordId ) throws Exception {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<PolicyDraftEntity> policyDraftEntity = em.createNamedQuery("getPolicyByChangeSetId", PolicyDraftEntity.class).setParameter("changesetId", recordId).getResultList();
        Policy.FromString(policyString);

        if(!policyDraftEntity.isEmpty()){
            throw new Exception("There is already a pending change request with this record ID, " + recordId);
        }
        PolicyDraftEntity policyDraft = new PolicyDraftEntity();
        policyDraft.setId(KeycloakModelUtils.generateId());
        policyDraft.setChangesetRequestId(recordId);
        policyDraft.setPolicy(policyString);
        em.persist(policyDraftEntity);
        em.flush();
    }

    public static void createRolePolicyDraft(KeycloakSession session,  String recordId, double thresholdPercentage, int numberOfAdditionalAdmins, RoleModel role) throws Exception {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        String algorithm = "EdDSA";
        List<TideRoleDraftEntity> roleDraft = em.createNamedQuery("getRoleDraftByRoleId", TideRoleDraftEntity.class)
                .setParameter("roleId", role.getId())
                .getResultList();
        if(roleDraft.isEmpty()){
            throw new Exception("This authorizer role does not have an role draft entity, " + role.getName());
        }

        List<TideUserRoleMappingDraftEntity> users = em.createNamedQuery("getUserRoleMappingsByStatusAndRole", TideUserRoleMappingDraftEntity.class)
                .setParameter("draftStatus", DraftStatus.ACTIVE)
                .setParameter("roleId", role.getId())
                .getResultList();

        int numberOfActiveAdmins = users.size();

        // TODO: update to be able to change additional admin value when we can approve multiple admins at a time. ATM its one at a time.
        int threshold = Math.max(1, (int) (thresholdPercentage * (numberOfActiveAdmins + numberOfAdditionalAdmins)));

        // Grab from tide key provider
        ComponentModel componentModel = session.getContext().getRealm().getComponentsStream()
                .filter(x -> x.getProviderId().equalsIgnoreCase(org.tidecloak.shared.Constants.TIDE_VENDOR_KEY))
                .findFirst()
                .orElse(null);

        MultivaluedHashMap<String, String> config = componentModel.getConfig();
        String vvkId = config.getFirst("vvkId");
        String vendor = session.getContext().getRealm().getName();;

        PolicyParameters params = new PolicyParameters();
        params.put("threshold", threshold);
        params.put("role", org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
        Policy policy = new Policy("GenericRealmAccessThresholdRole:1", "any", vvkId, params);

        List<PolicyDraftEntity> policyDraftEntities = em.createNamedQuery("getPolicyByChangeSetId", PolicyDraftEntity.class).setParameter("changesetId", recordId).getResultList();

        if(!policyDraftEntities.isEmpty()){
            throw new Exception("There is already a pending change request with this record ID, " + recordId);
        }
        ObjectMapper objectMapper = new ObjectMapper();
        String policyString =  policy.ToString();
        PolicyDraftEntity policyDraftEntity = new PolicyDraftEntity();
        policyDraftEntity.setId(KeycloakModelUtils.generateId());
        policyDraftEntity.setChangesetRequestId(recordId);
        policyDraftEntity.setPolicy(policyString);
        em.persist(policyDraftEntity);
        em.flush();
    }

    public static PolicyDraftEntity getDraftRolePolicy(KeycloakSession session, String recordId){
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<PolicyDraftEntity> policyDraftEntities = em.createNamedQuery("getPolicyByChangeSetId", PolicyDraftEntity.class).setParameter("changesetId", recordId).getResultList();
        if(policyDraftEntities.isEmpty()){
            return null;
        }
        return policyDraftEntities.get(0);
    }

    public static void commitRolePolicy(KeycloakSession session, String recordId, Object mapping, String signature) throws Exception {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        String roleId = getRoleIdFromEntity(mapping);
        RoleEntity roleEntity = em.find(RoleEntity.class, roleId);
        if(roleEntity == null) {
            throw new Exception("No role entity found");
        }

        RoleModel roleModel = session.getContext().getRealm().getRoleById(roleId);


        List<TideRoleDraftEntity> roleDraftEntity = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class).setParameter("role", roleEntity).getResultList();
        if(roleDraftEntity.isEmpty()){
            throw new Exception("No tide role entity found");
        }
        PolicyDraftEntity policyDraftEntity = getDraftRolePolicy(session, recordId);
        if(policyDraftEntity == null) {
            System.out.println("No policyto commit");
            return;
        }

        roleDraftEntity.get(0).setInitCert(policyDraftEntity.getPolicy());
        roleDraftEntity.get(0).setInitCertSig(signature);
        Policy policy = Policy.FromString(policyDraftEntity.getPolicy());

        roleModel.setSingleAttribute("tideThreshold", policy.GetParameter("threshold", String.class).toString());
        roleModel.removeAttribute("InitCertDraftId");

        em.remove(policyDraftEntity);
        em.flush();

    }

    public static Policy createRolePolicy(KeycloakSession session, int threshold) throws JsonProcessingException {
        // Grab from tide key provider
        ComponentModel componentModel = session.getContext().getRealm().getComponentsStream()
                .filter(x -> x.getProviderId().equalsIgnoreCase(org.tidecloak.shared.Constants.TIDE_VENDOR_KEY))
                .findFirst()
                .orElse(null);
        MultivaluedHashMap<String, String> config = componentModel.getConfig();
        String vvkId = config.getFirst("vvkId");

        PolicyParameters params = new PolicyParameters();
        params.put("threshold", threshold);
        params.put("role", org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);

        return new Policy("GenericRealmAccessThresholdRole:1", "Policy",  vvkId, params);
    }

    public static Policy createRolePolicy(KeycloakSession session, RoleModel role ) throws JsonProcessingException {
        // Grab from tide key provider
        ComponentModel componentModel = session.getContext().getRealm().getComponentsStream()
                .filter(x -> x.getProviderId().equalsIgnoreCase(org.tidecloak.shared.Constants.TIDE_VENDOR_KEY))
                .findFirst()
                .orElse(null);
        MultivaluedHashMap<String, String> config = componentModel.getConfig();
        String vvkId = config.getFirst("vvkId");


        String tideThreshold = role.getFirstAttribute("tideThreshold");
        if (tideThreshold == null ) {
            return null;
        }
        int threshold = Integer.parseInt(tideThreshold);

        PolicyParameters params = new PolicyParameters();
        params.put("threshold", threshold);
        params.put("role", org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);

        return new Policy("GenericRealmAccessThresholdRole:1", "any",  vvkId, params);
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
