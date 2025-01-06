package org.tidecloak.changeset.utils;

import jakarta.persistence.EntityManager;
import org.keycloak.models.*;
import org.tidecloak.enums.DraftStatus;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.models.TideRoleAdapter;
import org.tidecloak.models.TideUserAdapter;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.tidecloak.changeset.utils.TideEntityUtils.*;

public class UserContextUtils {

    public static List<AccessProofDetailEntity> getUserContextDrafts(EntityManager em, String recordId) {
        return em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                .setParameter("recordId", recordId)
                .getResultStream()
                .collect(Collectors.toList());
    }

    public static List<AccessProofDetailEntity> getUserContextDrafts(EntityManager em, ClientModel client, String recordId) {
        return em.createNamedQuery("getProofDetailsByClient", AccessProofDetailEntity.class)
                .setParameter("clientId", client.getId())
                .getResultList();
    }

    public static Set<RoleModel> getDeepUserRoleMappings(UserModel user, KeycloakSession session, RealmModel realm, DraftStatus draftStatus) {
        Set<RoleModel> roleMappings;
        if (user instanceof TideUserAdapter) {
            roleMappings = ((TideUserAdapter)user).getRoleMappingsStreamByStatus(draftStatus).map((x) -> wrapRoleModel(x, session, realm)).collect(Collectors.toSet());
        } else {
            roleMappings = user.getRoleMappingsStream().collect(Collectors.toSet());;
        }
        user.getGroupsStream().forEach((group) -> {
            addGroupRoles(wrapGroupModel(group, session, realm), roleMappings, draftStatus);
        });
        Set<TideRoleAdapter> wrappedRoles = roleMappings.stream().map((r) -> (TideRoleAdapter)wrapRoleModel(r, session, realm)).collect(Collectors.toSet());
        return expandCompositeRoles(wrappedRoles, draftStatus);
    }


}
