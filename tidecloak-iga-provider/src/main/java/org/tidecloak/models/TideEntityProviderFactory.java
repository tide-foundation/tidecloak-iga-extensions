package org.tidecloak.models;

import org.keycloak.Config.Scope;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.tidecloak.models.TideEntityProvider;

/** */
public class TideEntityProviderFactory implements JpaEntityProviderFactory {

    protected static final String ID = "tide-entity-provider";

    @Override
    public JpaEntityProvider create(KeycloakSession session) {
        return new TideEntityProvider();
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public void init(Scope config) {}

    @Override
    public void postInit(KeycloakSessionFactory factory) {}

    @Override
    public void close() {}

    private void realmRemoved(RealmModel.RealmRemovedEvent event) {}
}