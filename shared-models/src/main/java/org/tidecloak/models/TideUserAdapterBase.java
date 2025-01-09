package org.tidecloak.models;

import jakarta.persistence.EntityManager;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.jpa.UserAdapter;
import org.keycloak.models.jpa.entities.UserEntity;

public abstract class TideUserAdapterBase extends UserAdapter {
    public TideUserAdapterBase(KeycloakSession session, RealmModel realm, EntityManager em, UserEntity user) {
        super(session, realm, em, user);
    }

    public UserModel wrapUserModel(UserModel userModel, KeycloakSession session, RealmModel realm) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        // If already wrapped in this type, return it
        if (userModel instanceof TideUserAdapterBase) {
            return userModel;
        }

        // Convert the user model to a UserEntity
        UserEntity userEntity = toUserEntity(userModel, em);

        // Return a basic implementation that allows compilation
        return new TideUserAdapterBase(session, realm, em, userEntity) {
        };
    }

    public static UserEntity toUserEntity(UserModel model, EntityManager em) {
        return em.getReference(UserEntity.class, model.getId());
    }

}
