package org.tidecloak.models;

import jakarta.persistence.EntityManager;
import org.keycloak.Config;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientProvider;
import org.keycloak.models.ClientProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.saml.SamlConfigAttributes;

import java.util.*;

import static org.keycloak.models.jpa.JpaRealmProviderFactory.PROVIDER_PRIORITY;

public class TideClientProviderFactory implements ClientProviderFactory {
    private Set<String> clientSearchableAttributes = null;
    private static final List<String> REQUIRED_SEARCHABLE_ATTRIBUTES = Arrays.asList(
            "saml_idp_initiated_sso_url_name",
            SamlConfigAttributes.SAML_ARTIFACT_BINDING_IDENTIFIER
    );

    @Override
    public ClientProvider create(KeycloakSession session) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        return new TideRealmProvider(session, em, clientSearchableAttributes, null);
    }

    @Override
    public void init(Config.Scope config) {
        String[] searchableAttrsArr = config.getArray("searchableAttributes");
        if (searchableAttrsArr == null) {
            String s = System.getProperty("keycloak.client.searchableAttributes");
            searchableAttrsArr = s == null ? null : s.split("\\s*,\\s*");
        }
        HashSet<String> s = new HashSet<>(REQUIRED_SEARCHABLE_ATTRIBUTES);
        if (searchableAttrsArr != null) {
            s.addAll(Arrays.asList(searchableAttrsArr));
        }
        clientSearchableAttributes = Collections.unmodifiableSet(s);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return "tideClientProvider";
    }

    @Override
    public int order() {
        return PROVIDER_PRIORITY;
    }
}
