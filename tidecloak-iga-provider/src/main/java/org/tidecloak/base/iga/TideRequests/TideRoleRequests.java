package org.tidecloak.base.iga.TideRequests;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.midgard.models.AuthorizerPolicyModel.AuthorizerPolicy;
import org.tidecloak.jpa.entities.drafting.RoleInitializerCertificateDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideRoleDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.shared.models.InitializerCertificateModel.InitializerCertificate;
import org.tidecloak.tide.iga.ForsetiPolicyFactory;

import java.util.*;
import java.util.function.BiConsumer;

import static org.tidecloak.base.iga.utils.BasicIGAUtils.getRoleIdFromEntity;

public class TideRoleRequests {

    /* -------------------------------------------------------------------------
     * Utilities
     * ---------------------------------------------------------------------- */

    /** No-op codeStore; replace with persistence to your blob store (keyed by bh). */
    private static final BiConsumer<String, String> NOOP_CODE_STORE = (bh, assemblyB64) -> {
        // TODO: persist assemblyB64 under key "bh" (S3/DB/filesystem)
    };

    /** Load the TideRoleDraftEntity for a given Keycloak role. */
    private static TideRoleDraftEntity requireRoleDraft(EntityManager em, RoleEntity roleEntity) throws Exception {
        List<TideRoleDraftEntity> drafts = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class)
                .setParameter("role", roleEntity)
                .getResultList();
        if (drafts.isEmpty()) throw new Exception("No TideRoleDraftEntity found for role id=" + roleEntity.getId());
        return drafts.get(0);
    }

    /* -------------------------------------------------------------------------
     * Admin:2 default (draft AP) into role draft
     * ---------------------------------------------------------------------- */

    /** Create the realm admin role and persist its AP (compact "h.p") in the legacy initCert column. */
    public static void createRealmAdminAuthorizerPolicy(KeycloakSession session) throws Exception {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        ClientModel realmManagement = session.getContext().getRealm()
                .getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID);

        String resource = Constants.ADMIN_CONSOLE_CLIENT_ID;

        RoleModel kcRealmAdmin = session.getContext().getRealm()
                .getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID)
                .getRole(AdminRoles.REALM_ADMIN);

        RoleModel tideRealmAdmin = realmManagement.addRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
        tideRealmAdmin.addCompositeRole(kcRealmAdmin);
        tideRealmAdmin.setSingleAttribute("tideThreshold", "1");

        // signmodels the policy will allow (UserContext signing + optional Rules)
        List<String> signModels = List.of("UserContext:2", "Rules:1");

        // Build a DRAFT (unsigned) AP using the default Admin:2 → UserContext:1 template
        AuthorizerPolicy ap = ForsetiPolicyFactory.createRoleAuthorizerPolicy_DefaultAdminTemplate(
                session, resource, tideRealmAdmin, signModels, NOOP_CODE_STORE
        );
        if (ap == null) throw new Exception("Unable to create default AuthorizerPolicy for admin role");

        // Persist compact "h.p" (unsigned) in the legacy initCert column
        RoleEntity roleEntity = session.getProvider(JpaConnectionProvider.class).getEntityManager()
                .find(RoleEntity.class, tideRealmAdmin.getId());
        TideRoleDraftEntity roleDraft = requireRoleDraft(em, roleEntity);
        roleDraft.setInitCert(ap.toCompactString());
        em.flush();
    }

    /* -------------------------------------------------------------------------
     * Create an AP "draft row" (stored in legacy RoleInitializerCertificateDraftEntity)
     * ---------------------------------------------------------------------- */

    /**
     * Build a new draft AP for a role, copying routing/signmodels from the current draft,
     * but recomputing threshold based on users and "additional admins".
     */
    public static void createRoleAuthorizerPolicyDraft(
            KeycloakSession session,
            String recordId,
            String certVersion,                 // kept for parity; not used by default template
            double thresholdPercentage,
            int numberOfAdditionalAdmins,
            RoleModel role
    ) throws Exception {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        // Load existing role draft → get previous AP (compact "h.p")
        RoleEntity roleEntity = em.find(RoleEntity.class, role.getId());
        TideRoleDraftEntity roleDraft = requireRoleDraft(em, roleEntity);
        AuthorizerPolicy prev = AuthorizerPolicy.fromCompact(roleDraft.getInitCert());

        // Compute new threshold: ceil(percentage * (#existing + N new))
        List<TideUserRoleMappingDraftEntity> users = em.createNamedQuery("getUserRoleMappingsByStatusAndRole", TideUserRoleMappingDraftEntity.class)
                .setParameter("draftStatus", DraftStatus.ACTIVE)
                .setParameter("roleId", role.getId())
                .getResultList();

        int population = users.size() + Math.max(0, numberOfAdditionalAdmins);
        int newThreshold = Math.max(1, (int) Math.ceil(thresholdPercentage * population));

        // Keep previous resource/signmodels; ensure Admin:2 routing
        String resource = prev.payload().resource;
        List<String> signModels = new ArrayList<>(prev.payload().signmodels == null ? List.of("UserContext:1") : prev.payload().signmodels);

        // Build a fresh DRAFT AP (unsigned) with the default template
        AuthorizerPolicy ap = ForsetiPolicyFactory.createRoleAuthorizerPolicy_DefaultAdminTemplate(
                session, resource, role, signModels, NOOP_CODE_STORE
        );
        if (ap == null) throw new Exception("Failed to create AuthorizerPolicy draft");

        // Override threshold with the newly computed one
        ap.payload().threshold = newThreshold;

        // Ensure no duplicate pending draft for this record
        List<RoleInitializerCertificateDraftEntity> existing = em.createNamedQuery("getInitCertByChangeSetId", RoleInitializerCertificateDraftEntity.class)
                .setParameter("changesetId", recordId)
                .getResultList();
        if (!existing.isEmpty()) throw new Exception("Pending change request already exists: " + recordId);

        // Persist the compact "h.p" into the draft table (legacy)
        RoleInitializerCertificateDraftEntity draft = new RoleInitializerCertificateDraftEntity();
        draft.setId(KeycloakModelUtils.generateId());
        draft.setChangesetRequestId(recordId);
        draft.setInitCert(ap.toCompactString());
        em.persist(draft);
        em.flush();
    }

    public static RoleInitializerCertificateDraftEntity getDraftRoleInitCert(KeycloakSession session, String recordId){
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<RoleInitializerCertificateDraftEntity> list = em.createNamedQuery("getInitCertByChangeSetId", RoleInitializerCertificateDraftEntity.class)
                .setParameter("changesetId", recordId).getResultList();
        return list.isEmpty() ? null : list.get(0);
    }

    /* -------------------------------------------------------------------------
     * Commit a pending AP draft into the role draft (legacy column)
     * ---------------------------------------------------------------------- */

    /** Commit a pending AP draft; also mirror threshold to role attribute for UI/compat. */
    public static void commitRoleAuthorizerPolicy(KeycloakSession session, String recordId, Object mapping, String signature) throws Exception {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        String roleId = getRoleIdFromEntity(mapping);
        RoleEntity roleEntity = em.find(RoleEntity.class, roleId);
        if (roleEntity == null) throw new Exception("No role entity found");

        RoleModel roleModel = session.getContext().getRealm().getRoleById(roleId);

        List<TideRoleDraftEntity> tideDrafts = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class)
                .setParameter("role", roleEntity).getResultList();
        if (tideDrafts.isEmpty()) throw new Exception("No tide role draft found");

        RoleInitializerCertificateDraftEntity draft = getDraftRoleInitCert(session, recordId);
        if (draft == null) return; // nothing to commit

        // Move compact AP into the role draft, and store vendor signature if you have it
        tideDrafts.get(0).setInitCert(draft.getInitCert());   // compact "h.p"
        tideDrafts.get(0).setInitCertSig(signature);          // optional vendor sig blob

        // Mirror threshold into role attribute for compatibility
        AuthorizerPolicy ap = AuthorizerPolicy.fromCompact(draft.getInitCert());
        if (ap.payload().threshold != null) {
            roleModel.setSingleAttribute("tideThreshold", Integer.toString(ap.payload().threshold));
        }
        roleModel.removeAttribute("InitCertDraftId");

        em.remove(draft);
        em.flush();
    }

    /* -------------------------------------------------------------------------
     * Legacy InitCert creation paths (unchanged)
     * ---------------------------------------------------------------------- */

    // Creates a Realm Admin role for current realm. The role has full access to manage the current realm.
    public static void createRealmAdminInitCert(KeycloakSession session) throws Exception {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        ClientModel realmManagement = session.getContext().getRealm().getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID);

        String resource = Constants.ADMIN_CONSOLE_CLIENT_ID;
        RoleModel realmAdmin = session.getContext().getRealm()
                .getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID)
                .getRole(AdminRoles.REALM_ADMIN);

        RoleModel tideRealmAdmin = realmManagement.addRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
        tideRealmAdmin.addCompositeRole(realmAdmin);
        tideRealmAdmin.setSingleAttribute("tideThreshold", "1");

        ArrayList<String> signModels = new ArrayList<>(List.of("UserContext:1", "Rules:1"));

        // Build a DRAFT AP using the default template to keep behavior in sync
        AuthorizerPolicy authorizerPolicy = ForsetiPolicyFactory.createRoleAuthorizerPolicy_DefaultAdminTemplate(
                session, resource, tideRealmAdmin, signModels, NOOP_CODE_STORE
        );
        if (authorizerPolicy == null){
            throw new Exception("Unable to create authorizerPolicy for TideRealmAdminRole, tideThreshold needs to be set");
        }

        RoleEntity roleEntity = em.find(RoleEntity.class, tideRealmAdmin.getId());
        TideRoleDraftEntity roleDraft = requireRoleDraft(em, roleEntity);

        // Store compact "h.p" (not JSON of the object)
        roleDraft.setInitCert(authorizerPolicy.toCompactString());
        em.flush();
    }

    public static void createRoleInitCertDraft(KeycloakSession session, String initCertString, String recordId ) throws Exception {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<RoleInitializerCertificateDraftEntity> existing = em.createNamedQuery("getInitCertByChangeSetId", RoleInitializerCertificateDraftEntity.class)
                .setParameter("changesetId", recordId).getResultList();

        // Validates format; throws on error
        InitializerCertificate.FromString(initCertString);

        if(!existing.isEmpty()){
            throw new Exception("There is already a pending change request with this record ID, " + recordId);
        }
        RoleInitializerCertificateDraftEntity initCertDraft = new RoleInitializerCertificateDraftEntity();
        initCertDraft.setId(KeycloakModelUtils.generateId());
        initCertDraft.setChangesetRequestId(recordId);
        initCertDraft.setInitCert(initCertString);
        em.persist(initCertDraft);
        em.flush();
    }

    public static void commitRoleInitCert(KeycloakSession session, String recordId, Object mapping, String signature) throws Exception {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        String roleId = getRoleIdFromEntity(mapping);
        RoleEntity roleEntity = em.find(RoleEntity.class, roleId);
        if(roleEntity == null) throw new Exception("No role entity found");

        RoleModel roleModel = session.getContext().getRealm().getRoleById(roleId);

        List<TideRoleDraftEntity> roleDraftEntity = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class)
                .setParameter("role", roleEntity).getResultList();
        if(roleDraftEntity.isEmpty()) throw new Exception("No tide role entity found");

        RoleInitializerCertificateDraftEntity roleInitCertDraft = getDraftRoleInitCert(session, recordId);
        if(roleInitCertDraft == null) {
            System.out.println("No init cert to commit");
            return;
        }

        roleDraftEntity.get(0).setInitCert(roleInitCertDraft.getInitCert());
        roleDraftEntity.get(0).setInitCertSig(signature);

        InitializerCertificate initCert = InitializerCertificate.FromString(roleInitCertDraft.getInitCert());
        roleModel.setSingleAttribute("tideThreshold", Integer.toString(initCert.getPayload().getThreshold()));
        roleModel.removeAttribute("InitCertDraftId");

        em.remove(roleInitCertDraft);
        em.flush();
    }

    /* -------------------------------------------------------------------------
     * New helper to create a role AP draft for arbitrary role/resource
     * ---------------------------------------------------------------------- */

    /**
     * Creates a role AuthorizerPolicy draft using the default Admin:2 template and persists
     * it as a pending change. (Replaces the old createRoleAuthorizerPolicy(...) variant.)
     */
    public static void createRoleAuthorizerPolicy(
            KeycloakSession session,
            String recordId,
            RoleModel role,
            String resource,
            String certVersion,            // kept for parity; not used by template
            String algorithm,              // kept for parity; not used by template
            ArrayList<String> signModels,
            String thresholdStr
    ) throws Exception {
        var em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        List<RoleInitializerCertificateDraftEntity> existing = em.createNamedQuery("getInitCertByChangeSetId", RoleInitializerCertificateDraftEntity.class)
                .setParameter("changesetId", recordId).getResultList();
        if (!existing.isEmpty()) throw new Exception("Pending change request exists for " + recordId);

        int threshold = Integer.parseInt(thresholdStr);

        AuthorizerPolicy ap = ForsetiPolicyFactory.createRoleAuthorizerPolicy_DefaultAdminTemplate(
                session, resource, role, signModels, NOOP_CODE_STORE
        );
        if (ap == null) throw new Exception("Failed to create AuthorizerPolicy");

        ap.payload().threshold = threshold;

        RoleInitializerCertificateDraftEntity draft = new RoleInitializerCertificateDraftEntity();
        draft.setId(KeycloakModelUtils.generateId());
        draft.setChangesetRequestId(recordId);
        draft.setInitCert(ap.toCompactString());
        em.persist(draft);
        em.flush();
    }

    /* -------------------------------------------------------------------------
     * Existing InitCert builders (leave as-is for compatibility)
     * ---------------------------------------------------------------------- */

    public static void createRoleInitCert(KeycloakSession session, String recordId, String resource, String certVersion, String algorithm, ArrayList<String> signModels, String threshold) throws Exception {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        // Grab from tide key provider
        ComponentModel componentModel = session.getContext().getRealm().getComponentsStream()
                .filter(x -> x.getProviderId().equalsIgnoreCase(org.tidecloak.shared.Constants.TIDE_VENDOR_KEY))
                .findFirst()
                .orElse(null);

        MultivaluedHashMap<String, String> config = componentModel.getConfig();
        String vvkId = config.getFirst("vvkId");
        String vendor = session.getContext().getRealm().getName();

        InitializerCertificate initializerCertifcate = InitializerCertificate.constructInitCert(
                vvkId, algorithm, certVersion, vendor, resource, Integer.parseInt(threshold), signModels
        );

        List<RoleInitializerCertificateDraftEntity> existing = em.createNamedQuery("getInitCertByChangeSetId", RoleInitializerCertificateDraftEntity.class)
                .setParameter("changesetId", recordId).getResultList();

        if(!existing.isEmpty()){
            throw new Exception("There is already a pending change request with this record ID, " + recordId);
        }
        ObjectMapper objectMapper = new ObjectMapper();
        String initCertString = objectMapper.writeValueAsString(initializerCertifcate);
        RoleInitializerCertificateDraftEntity initCertDraft = new RoleInitializerCertificateDraftEntity();
        initCertDraft.setId(KeycloakModelUtils.generateId());
        initCertDraft.setChangesetRequestId(recordId);
        initCertDraft.setInitCert(initCertString);
        em.persist(initCertDraft);
        em.flush();
    }

    public static InitializerCertificate createRoleInitCert(KeycloakSession session, String resource, RoleModel role , String certVersion, String algorithm, ArrayList<String> signModels) throws JsonProcessingException {
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
        return InitializerCertificate.constructInitCert(vvkId, algorithm, certVersion, vendor, resource, threshold, signModels);
    }

    /**
     * Back-compat wrapper that used to call the “old” factory.
     * Now upgraded to the default Admin:2 template path.
     */
    public static AuthorizerPolicy createAdminAuthorizerPolicy(
            KeycloakSession session,
            String resource,
            RoleModel role,
            String certVersion,
            String algorithm,
            ArrayList<String> authFlows,     // ignored by default template (always Admin:2)
            ArrayList<String> signModels
    ) throws JsonProcessingException {
        AuthorizerPolicy ap = ForsetiPolicyFactory.createRoleAuthorizerPolicy_DefaultAdminTemplate(
                session, resource, role, signModels, NOOP_CODE_STORE
        );
        // Ensure threshold mirrors role attribute
        String tideThreshold = role.getFirstAttribute("tideThreshold");
        if (tideThreshold != null) {
            ap.payload().threshold = Integer.parseInt(tideThreshold);
        }
        return ap;
    }

    /* -------------------------------------------------------------------------
     * Role tree helpers (unchanged)
     * ---------------------------------------------------------------------- */

    private static Map<String, Object> expandCompositeRolesAsNestedStructure(RoleModel rootRole) {
        Set<RoleModel> visited = new HashSet<>();
        return expandCompositeRolesToNestedJson(rootRole, visited);
    }

    private static Map<String, Object> expandCompositeRolesToNestedJson(RoleModel role, Set<RoleModel> visited) {
        if (visited.contains(role)) return null;
        visited.add(role);

        Map<String, Object> currentRole = new LinkedHashMap<>();
        Map<String, Object> attributesMap = new HashMap<>();

        role.getAttributes().forEach((key, values) -> {
            if (key.startsWith("tide")) {
                attributesMap.put(key, values.size() > 1 ? values : values.get(0));
            }
        });

        if (!attributesMap.isEmpty()) {
            currentRole.put("attributes", attributesMap);
        }

        if (role.isComposite()) {
            role.getCompositesStream()
                    .filter(childRole -> !visited.contains(childRole))
                    .forEach(childRole -> {
                        Map<String, Object> childJson = expandCompositeRolesToNestedJson(childRole, visited);
                        if (childJson != null && !childJson.isEmpty()) {
                            currentRole.put(childRole.getName(), childJson.get(childRole.getName()));
                        }
                    });
        }

        return currentRole.isEmpty() ? null : Map.of(role.getName(), currentRole);
    }

    public static class Pair<K, V> {
        private final K key;
        private final V value;
        public Pair(K key, V value) { this.key = key; this.value = value; }
        public K getKey() { return key; }
        public V getValue() { return value; }
    }
}
