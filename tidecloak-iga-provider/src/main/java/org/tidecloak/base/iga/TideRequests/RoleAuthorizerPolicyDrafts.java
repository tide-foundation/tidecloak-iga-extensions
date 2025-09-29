package org.tidecloak.base.iga.TideRequests;

import jakarta.persistence.EntityManager;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.tidecloak.jpa.entities.drafting.RoleAuthorizerPolicyDraftEntity;
import org.tidecloak.jpa.store.RoleAttributeLongStore;

import java.util.List;
import java.util.UUID;

public final class RoleAuthorizerPolicyDrafts {

    private RoleAuthorizerPolicyDrafts() {}

    public static RoleAuthorizerPolicyDraftEntity getDraftRoleAuthorizerPolicy(KeycloakSession session, String changeSetId) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<RoleAuthorizerPolicyDraftEntity> list = em.createNamedQuery(
                        "getRoleApDraftByRequestId", RoleAuthorizerPolicyDraftEntity.class)
                .setParameter("requestId", changeSetId)
                .getResultList();
        return list.isEmpty() ? null : list.get(0);
    }

    /**
     * Attach the approved AP to the role via long-attribute store (with short-attr mirror if it fits)
     * and remove the draft.
     */
    public static void commitRoleAuthorizerPolicy(KeycloakSession session,
                                                  String changeSetId,
                                                  Object draftEntity,
                                                  String authorizerSignature) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        RoleAuthorizerPolicyDraftEntity draft = getDraftRoleAuthorizerPolicy(session, changeSetId);
        if (draft == null) throw new IllegalStateException("AP draft not found for " + changeSetId);

        RoleEntity roleEntity = draft.getRole();
        RealmModel realm = session.getContext().getRealm();

        RoleModel role = session.roles().getRoleById(realm, roleEntity.getId());
        if (role == null) {
            throw new IllegalStateException("Role not found for AP draft roleId=" + roleEntity.getId());
        }

        // Save to long-attr and mirror to short if <= 255
        var store = new RoleAttributeLongStore();
        store.save(session, role, "tide.ap.model", draft.getApCompact());
        store.upsertMirrorShortIfFits(role, "tide.ap.model", draft.getApCompact());

        if (authorizerSignature != null && !authorizerSignature.isBlank()) {
            // Signature is typically short enough; if you anticipate longer values, add a long-store key similarly.
            role.setSingleAttribute("tide.ap.sig", authorizerSignature);
        }

        em.remove(em.contains(draft) ? draft : em.merge(draft));
        em.flush();
    }

    /** Convenience to create a draft from role + changeSet + apCompact (call from your staging path). */
    public static RoleAuthorizerPolicyDraftEntity createDraft(KeycloakSession session,
                                                              RoleModel role,
                                                              String changeSetId,
                                                              String apCompact) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        RoleAuthorizerPolicyDraftEntity e = new RoleAuthorizerPolicyDraftEntity();
        e.setId(UUID.randomUUID().toString());
        e.setRole(em.getReference(RoleEntity.class, role.getId()));
        e.setChangeRequestId(changeSetId);
        e.setApCompact(apCompact);
        e.setCreatedTimestamp(System.currentTimeMillis());
        em.persist(e);
        em.flush();
        return e;
    }
}
