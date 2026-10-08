package org.tidecloak.iga.rest;

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class TidePolicyResourceProvider implements RealmResourceProviderFactory, RealmResourceProvider {

    public static final String ID = "tide-policy";   // → /realms/{realm}/tide-policy

    private KeycloakSession session;

    // ---- Factory ----

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        this.session = session;
        return this;
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    // ---- Provider ----

    @Override
    public Object getResource() {
        return new TidePolicyResource(session);
    }

    @Override
    public void close() {
        // shared by both interfaces — signature is identical, one method satisfies both
    }

    @Override
    public void init(Scope config) {

    }
}