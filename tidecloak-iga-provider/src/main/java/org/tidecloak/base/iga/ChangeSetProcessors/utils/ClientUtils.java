package org.tidecloak.base.iga.ChangeSetProcessors.utils;

import jakarta.persistence.EntityManager;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.tidecloak.shared.Constants;
import org.tidecloak.base.iga.interfaces.TideClientAdapter;
import org.tidecloak.base.iga.interfaces.TideRoleAdapter;

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
        Set<RoleModel> wrappedRoles = new HashSet<>();
        wrappedRoles.add(new TideRoleAdapter(session, realm, em, roleEntity));

        UserContextUtils userContextUtils = new UserContextUtils();
        Set<RoleModel> activeCompositeRoles = userContextUtils.expandActiveCompositeRoles(session, wrappedRoles);

        activeCompositeRoles.forEach(activeCompRole -> {
            if (activeCompRole.getContainer() instanceof ClientModel){
                clientList.add((ClientModel) activeCompRole.getContainer());
            }
        });

        clientList.removeIf(r -> r.getClientId().equalsIgnoreCase(org.keycloak.models.Constants.BROKER_SERVICE_CLIENT_ID));

        return clientList.stream().distinct().collect(Collectors.toList());
    }

    public static List<ClientModel> getUniqueClientList(KeycloakSession session, RealmModel realm, RoleModel role) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<ClientModel> clientList = session.clients().getClientsStream(realm)
                .map(client -> new TideClientAdapter(realm, em, session, em.find(ClientEntity.class, client.getId())))
                .filter(TideClientAdapter::isFullScopeAllowed)
                .collect(Collectors.toList());

        if ( role.isClientRole()){
            clientList.add((ClientModel) role.getContainer());
        }

        // need to expand role and get the clientlist here too
        RoleEntity roleEntity = em.getReference(RoleEntity.class, role.getId());
        Set<RoleModel> wrappedRoles = new HashSet<>();
        wrappedRoles.add(new TideRoleAdapter(session, realm, em, roleEntity));

        UserContextUtils userContextUtils = new UserContextUtils();
        Set<RoleModel> activeCompositeRoles = userContextUtils.expandActiveCompositeRoles(session, wrappedRoles);

        activeCompositeRoles.forEach(activeCompRole -> {
            if (activeCompRole.getContainer() instanceof ClientModel){
                clientList.add((ClientModel) activeCompRole.getContainer());
            }
        });


        clientList.removeIf(r -> r.getClientId().equalsIgnoreCase(org.keycloak.models.Constants.BROKER_SERVICE_CLIENT_ID));


        return clientList.stream().distinct().collect(Collectors.toList());
    }
}
