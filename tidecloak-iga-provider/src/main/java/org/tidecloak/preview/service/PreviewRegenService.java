// # TIDECLOAK IMPLEMENTATION
package org.tidecloak.preview.service;

import jakarta.persistence.EntityManager;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.representations.AccessToken;
import org.keycloak.util.JsonSerialization;
import org.tidecloak.preview.dto.TokenPreviewSpec;
import org.tidecloak.preview.util.TokenPreviewBuilder;


import java.util.*;
import java.util.stream.Collectors;

public class PreviewRegenService {
    private final KeycloakSession session;
    public PreviewRegenService(KeycloakSession s){ this.session=s; }

    /** Regenerate preview "proofDraft" JSON for all pending change requests in the realm. */
    @SuppressWarnings("unchecked")
    public int regenerateAll(RealmModel realm){
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        // USER_ROLE drafts
        var userRoleDrafts = em.createNamedQuery("getAllPreApprovedUserRoleMappingsByRealm")
                .setParameter("draftStatus", java.util.List.of(
                        org.tidecloak.shared.enums.DraftStatus.DRAFT,
                        org.tidecloak.shared.enums.DraftStatus.PENDING,
                        org.tidecloak.shared.enums.DraftStatus.APPROVED
                ))
                .setParameter("activeStatus", org.tidecloak.shared.enums.DraftStatus.ACTIVE)
                .setParameter("realmId", realm.getId())
                .getResultList();

        int updated = 0;
        for(Object o : (java.util.List<Object>)userRoleDrafts){
            try{
                // For each proof detail tied to this change request, recompute a preview for that (user,client)
                String changeId = (String) o.getClass().getMethod("getChangeRequestId").invoke(o);
                var proofs = em.createNamedQuery("getProofDetailsForDraft", org.tidecloak.jpa.entities.AccessProofDetailEntity.class)
                        .setParameter("recordId", changeId)
                        .getResultList();

                // Extract roleId and action
                String roleId = (String) o.getClass().getMethod("getRoleId").invoke(o);
                var actionEnum = o.getClass().getMethod("getAction").invoke(o);
                boolean add = actionEnum.toString().equalsIgnoreCase("CREATE");

                RoleModel role = realm.getRoleById(roleId);
                String roleName = role.getName();
                String clientId = role.isClientRole() ? realm.getClientById(role.getContainerId()).getClientId() : null;

                for (var p : proofs){
                    try{
                        var user = p.getUser();
                        String uid = user != null ? user.getId() : null;
                        String clientIdForProof = p.getClientId();
                        TokenPreviewSpec spec = new TokenPreviewSpec();
                        spec.userId = uid;
                        spec.clientId = clientIdForProof;
                        if(add){
                            var rr = new TokenPreviewSpec.RoleRef();
                            rr.roleName = roleName; rr.clientId = clientId;
                            spec.addUserRoles = java.util.List.of(rr);
                        } else {
                            var rr = new TokenPreviewSpec.RoleRef();
                            rr.roleName = roleName; rr.clientId = clientId;
                            spec.removeUserRoles = java.util.List.of(rr);
                        }
                        var built = TokenPreviewBuilder.build(session, realm, spec);
                        AccessToken preview = built.preview;
                        p.setProofDraft(json);
                        em.merge(p);
                        updated++;
                    }catch(Exception ex){
                        // continue
                    }
                }
            }catch(Exception ignore){}
        }

        // TODO: composite-role, client full-scope, default-roles, group-drafting drafts can be added similarly.

        return updated;
    }
}
