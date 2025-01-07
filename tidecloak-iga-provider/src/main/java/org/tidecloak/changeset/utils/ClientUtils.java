package org.tidecloak.changeset.utils;

import jakarta.persistence.EntityManager;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.tidecloak.enums.DraftStatus;
import org.tidecloak.models.TideClientAdapter;
import org.tidecloak.models.TideRoleAdapter;
import org.tidecloak.utils.TideRolesUtil;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class ClientUtils {
    public static List<ClientModel> getUniqueClientList(KeycloakSession session, RealmModel realm, RoleModel role, EntityManager em) {
        List<ClientModel> clientList = session.clients().getClientsStream(realm)
                .map(client -> new TideClientAdapter(realm, em, session, em.find(ClientEntity.class, client.getId())))
                .filter(TideClientAdapter::isFullScopeAllowed)
                .collect(Collectors.toList());

        if ( role.isClientRole()){
            clientList.add((ClientModel) role.getContainer());
        }

        // need to expand role and get the clientlist here too
        RoleEntity roleEntity = em.getReference(RoleEntity.class, role.getId());
        Set<TideRoleAdapter> wrappedRoles = new HashSet<>();
        wrappedRoles.add(new TideRoleAdapter(session, realm, em, roleEntity));

        Set<RoleModel> activeCompositeRoles = TideRolesUtil.expandCompositeRoles(wrappedRoles, DraftStatus.ACTIVE);

        activeCompositeRoles.forEach(activeCompRole -> {
            if (activeCompRole.getContainer() instanceof ClientModel){
                clientList.add((ClientModel) activeCompRole.getContainer());
            }
        });

        return clientList.stream().distinct().collect(Collectors.toList());
    }
}
