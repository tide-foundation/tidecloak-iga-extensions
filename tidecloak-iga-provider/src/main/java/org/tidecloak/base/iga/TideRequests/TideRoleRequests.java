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

    public static void createRoleAuthorizerPolicyDraft(KeycloakSession session, String recordId, String certVersion, double thresholdPercentage, int numberOfAdditionalAdmins, RoleModel role) throws Exception {
        org.tidecloak.tide.replay.TideRoleReplaySupport.createRoleAuthorizerPolicyDraft(session, recordId, certVersion, thresholdPercentage, numberOfAdditionalAdmins, role);
    }
}
