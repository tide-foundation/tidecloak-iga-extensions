// # TIDECLOAK IMPLEMENTATION
package org.tidecloak.preview.rest;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class TokenPreviewRealmResourceProviderFactory implements RealmResourceProviderFactory {

    public static final String ID = "tidecloak";

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new TokenPreviewRealmResourceProvider(session);
    }

    @Override
    public void init(org.keycloak.Config.Scope config) { }

    @Override
    public void postInit(org.keycloak.models.KeycloakSessionFactory factory) { }

    @Override
    public void close() { }

    @Override
    public String getId() {
        return ID;
    }
}
