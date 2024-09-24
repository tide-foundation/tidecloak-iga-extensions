package org.tidecloak.jpa.models;

import jakarta.persistence.EntityManager;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.jpa.RealmAdapter;
import org.keycloak.models.jpa.entities.RealmEntity;

public class TideRealmAdapter extends RealmAdapter {
    public TideRealmAdapter(KeycloakSession session, EntityManager em, RealmEntity realm) {
        super(session, em, realm);
    }

    @Override
    public RoleModel addRole(String name) {
        return session.roles().addRealmRole(this, name);
    }

    @Override
    public RoleModel addRole(String id, String name) {
        return session.roles().addRealmRole(this, id, name);
    }

    @Override
    public ClientModel addClient(String name) {
        return session.clients().addClient(this, name);
    }

    @Override
    public RoleModel getRoleById(String id) {
        return this.session.roles().getRoleById(this, id);
    }

}
