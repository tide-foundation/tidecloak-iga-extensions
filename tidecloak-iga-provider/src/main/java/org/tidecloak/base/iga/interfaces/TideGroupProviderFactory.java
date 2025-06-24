package org.tidecloak.base.iga.interfaces;

import jakarta.persistence.EntityManager;
import org.keycloak.Config;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.GroupProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.Provider;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class TideGroupProviderFactory implements GroupProviderFactory {
    private Set<String> groupSearchableAttributes = null;
    @Override
    public Provider create(KeycloakSession session) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        return new TideRealmProvider(session, em, null, groupSearchableAttributes);
    }

    @Override
    public void init(Config.Scope config) {
        String[] searchableAttrsArr = config.getArray("searchableAttributes");
        if (searchableAttrsArr == null) {
            String s = System.getProperty("keycloak.group.searchableAttributes");
            searchableAttrsArr = s == null ? null : s.split("\\s*,\\s*");
        }
        if (searchableAttrsArr != null) {
            groupSearchableAttributes = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(searchableAttrsArr)));
        }
        else {
            groupSearchableAttributes = Collections.emptySet();
        }
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return "tideGroupProvider";
    }
}
