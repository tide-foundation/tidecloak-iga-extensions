package org.tidecloak.base.iga.ChangeSetProcessors.utils;

import jakarta.persistence.EntityManager;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.jpa.entities.UserEntity;

public final class TideEntityUtils {
    private TideEntityUtils(){}

    public static RoleEntity toRoleEntity(RoleModel role, EntityManager em) {
        return role == null ? null : em.find(RoleEntity.class, role.getId());
    }

    public static UserEntity toUserEntity(UserModel user, EntityManager em) {
        return user == null ? null : em.find(UserEntity.class, user.getId());
    }

    public static ClientEntity toClientEntity(ClientModel client, EntityManager em) {
        return client == null ? null : em.find(ClientEntity.class, client.getId());
    }
}
