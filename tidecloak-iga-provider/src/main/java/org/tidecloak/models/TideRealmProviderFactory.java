package org.tidecloak.models;

import jakarta.persistence.EntityManager;
import org.keycloak.Config;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.provider.ProviderEvent;
import org.keycloak.provider.ProviderEventListener;
import org.tidecloak.models.TideRealmProvider;

public class TideRealmProviderFactory implements RealmProviderFactory<TideRealmProvider>, ProviderEventListener {

    private Runnable onClose;

    public static final int PROVIDER_PRIORITY = 0;
    @Override
    public TideRealmProvider create(KeycloakSession session) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        return new TideRealmProvider(session, em, null, null);
    }

    @Override
    public void init(Config.Scope config) {

    }
    @Override
    public void postInit(KeycloakSessionFactory factory) {
        factory.register(this);
        onClose = () -> factory.unregister(this);
    }

    @Override
    public void close() {
        if (onClose != null) {
            onClose.run();
        }
    }


    @Override
    public String getId() {
        return "tideRealmProvider";
    }

    @Override
    public void onEvent(ProviderEvent event) {
        if (event instanceof RoleContainerModel.RoleRemovedEvent) {
            RoleContainerModel.RoleRemovedEvent e = (RoleContainerModel.RoleRemovedEvent) event;
            RoleModel role = e.getRole();
            RoleContainerModel container = role.getContainer();
            RealmModel realm;
            if (container instanceof RealmModel) {
                realm = (RealmModel) container;
            } else if (container instanceof ClientModel) {
                realm = ((ClientModel) container).getRealm();
            } else {
                return;
            }
            ((TideRealmProvider) e.getKeycloakSession().getProvider(RealmProvider.class)).preRemove(realm, role);
        }
    }
    @Override
    public int order() {
        return PROVIDER_PRIORITY;
    }
}
