package org.tidecloak.base.iga.TideRequests;

// (imports unchanged)
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

    private static final BiConsumer<String, String> NOOP_CODE_STORE = (bh, assemblyB64) -> {};

    private static TideRoleDraftEntity requireRoleDraft(EntityManager em, RoleEntity roleEntity) throws Exception {
        List<TideRoleDraftEntity> drafts = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class)
                .setParameter("role", roleEntity)
                .getResultList();
        if (drafts.isEmpty()) throw new Exception("No TideRoleDraftEntity found for role id=" + roleEntity.getId());
        return drafts.get(0);
    }

    /** helper to unwrap JSON bundle {"auth": "...", "sign": "..."} to compact; prefer "auth". */
    private static String unwrapCompactOrFirst(String stored) {
        if (stored == null) return null;
        String s = stored.trim();
        if (!s.startsWith("{")) return s;
        try {
            ObjectMapper om = new ObjectMapper();
            @SuppressWarnings("unchecked")
            Map<String, Object> m = om.readValue(s, Map.class);
            Object v = m.get("auth");
            if (v == null && !m.isEmpty()) v = m.values().iterator().next();
            return v == null ? null : String.valueOf(v);
        } catch (Exception e) {
            return s;
        }
    }

    // -------- Admin:2 default (bundle) --------

    public static void createRealmAdminAuthorizerPolicy(KeycloakSession session) throws Exception {
        var em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        ClientModel realmMgmt = session.getContext().getRealm()
                .getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID);

        String resource = Constants.ADMIN_CONSOLE_CLIENT_ID;
        RoleModel realmAdmin = session.getContext().getRealm()
                .getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID)
                .getRole(AdminRoles.REALM_ADMIN);

        RoleModel tideRealmAdmin = realmMgmt.addRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
        tideRealmAdmin.addCompositeRole(realmAdmin);
        tideRealmAdmin.setSingleAttribute("tideThreshold", "1");

        ArrayList<String> signModels = new ArrayList<>(List.of("UserContext:2", "Rules:1"));

        String policySource = loadDefaultPolicySource();
        Map<String, AuthorizerPolicy> aps = ForsetiPolicyFactory.createRoleAuthorizerPolicies(
                session,
                resource,
                tideRealmAdmin,
                signModels,
                policySource,
                "Ork.Forseti.Builtins.AuthorizerTemplatePolicy",
                "1.0.0"
        );

        var roleEntity = em.find(org.keycloak.models.jpa.entities.RoleEntity.class, tideRealmAdmin.getId());
        var roleDraft = em.createNamedQuery("getRoleDraftByRole", org.tidecloak.jpa.entities.drafting.TideRoleDraftEntity.class)
                .setParameter("role", roleEntity)
                .getSingleResult();

        String bundle = new ObjectMapper().writeValueAsString(Map.of(
                "auth", aps.get("auth").toCompactString(),
                "sign", aps.get("sign").toCompactString()
        ));
        roleDraft.setInitCert(bundle);
        em.flush();
    }

    // -------- AP draft (single compact) --------

    public static void createRoleAuthorizerPolicyDraft(
            KeycloakSession session,
            String recordId,
            String certVersion,
            double thresholdPercentage,
            int numberOfAdditionalAdmins,
            RoleModel role
    ) throws Exception {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        RoleEntity roleEntity = em.find(RoleEntity.class, role.getId());
        TideRoleDraftEntity roleDraft = requireRoleDraft(em, roleEntity);

        String stored = roleDraft.getInitCert();
        String compactBase;
        if (stored != null && stored.trim().startsWith("{")) {
            @SuppressWarnings("unchecked")
            Map<String, String> m = new ObjectMapper().readValue(stored, Map.class);
            compactBase = m.getOrDefault("auth", m.values().stream().findFirst().orElseThrow());
        } else {
            compactBase = stored;
        }

        AuthorizerPolicy prev = AuthorizerPolicy.fromCompact(compactBase);

        List<TideUserRoleMappingDraftEntity> users = em.createNamedQuery("getUserRoleMappingsByStatusAndRole", TideUserRoleMappingDraftEntity.class)
                .setParameter("draftStatus", DraftStatus.ACTIVE)
                .setParameter("roleId", role.getId())
                .getResultList();

        int population = users.size() + Math.max(0, numberOfAdditionalAdmins);
        int newThreshold = Math.max(1, (int) Math.ceil(thresholdPercentage * population));

        String resource = prev.payload().resource;
        List<String> signModels = new ArrayList<>(prev.payload().signmodels == null ? Collections.emptyList() : prev.payload().signmodels);

        AuthorizerPolicy ap = ForsetiPolicyFactory.createRoleAuthorizerPolicy_DefaultAdminTemplate(
                session, resource, role, signModels, NOOP_CODE_STORE
        );
        if (ap == null) throw new Exception("Failed to create AuthorizerPolicy draft");

        ap.payload().threshold = newThreshold;

        List<RoleInitializerCertificateDraftEntity> existing = em.createNamedQuery("getInitCertByChangeSetId", RoleInitializerCertificateDraftEntity.class)
                .setParameter("changesetId", recordId)
                .getResultList();
        if (!existing.isEmpty()) throw new Exception("Pending change request already exists: " + recordId);

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
        if (draft == null) return;

        tideDrafts.get(0).setInitCert(draft.getInitCert());
        tideDrafts.get(0).setInitCertSig(signature);

        try {
            String compact = unwrapCompactOrFirst(draft.getInitCert());
            AuthorizerPolicy ap = AuthorizerPolicy.fromCompact(compact);
            if (ap.payload().threshold != null) {
                roleModel.setSingleAttribute("tideThreshold", Integer.toString(ap.payload().threshold));
            }
        } catch (Exception ignore) { }

        roleModel.removeAttribute("InitCertDraftId");
        em.remove(draft);
        em.flush();
    }

    // --- legacy InitCert helpers kept as-is (omitted for brevity; unchanged from your current file) ---

    public static InitializerCertificate createRoleInitCert(KeycloakSession session, String resource, RoleModel role , String certVersion, String algorithm, ArrayList<String> signModels) throws JsonProcessingException {
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

    public static AuthorizerPolicy createAdminAuthorizerPolicy(
            KeycloakSession session,
            String resource,
            RoleModel role,
            String certVersion,
            String algorithm,
            ArrayList<String> authFlows,
            ArrayList<String> signModels
    ) throws JsonProcessingException {
        AuthorizerPolicy ap = ForsetiPolicyFactory.createRoleAuthorizerPolicy_DefaultAdminTemplate(
                session, resource, role, signModels, NOOP_CODE_STORE
        );
        String tideThreshold = role.getFirstAttribute("tideThreshold");
        if (tideThreshold != null) {
            ap.payload().threshold = Integer.parseInt(tideThreshold);
        }
        return ap;
    }

    private static String loadDefaultPolicySource() {
        try (var is = Thread.currentThread().getContextClassLoader()
                .getResourceAsStream("policies/DefaultTideAdminPolicy.cs")) {
            if (is == null) throw new IllegalStateException("Default policy not found at resources/policies/DefaultTideAdminPolicy.cs");
            return new String(is.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Failed to read DefaultTideAdminPolicy.cs", e);
        }
    }
}
