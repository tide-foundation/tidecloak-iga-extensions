package org.tidecloak.iga.interfaces;

import jakarta.persistence.EntityManager;
import org.keycloak.Config;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientProvider;
import org.keycloak.models.ClientProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.protocol.saml.SamlConfigAttributes;
import org.tidecloak.jpa.entities.drafting.TideClientDraftEntity;
import org.tidecloak.shared.enums.DraftStatus;


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
        factory.register((event) -> {
            if (event instanceof PostMigrationEvent) {
                try (KeycloakSession session = factory.create()) {
                    session.getTransactionManager().begin();

                    EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
                    List<TideClientDraftEntity> drafts = em
                            .createQuery("SELECT t FROM TideClientDraftEntity t WHERE t.fullScopeEnabled IS NULL OR t.fullScopeDisabled IS NULL",
                                    TideClientDraftEntity.class)
                            .getResultList();

                    drafts.forEach(d -> {
                        if(d.getFullScopeEnabled() == null) {
                            d.setFullScopeEnabled(DraftStatus.NULL);
                        }
                        if(d.getFullScopeDisabled() == null) {
                            d.setFullScopeDisabled(DraftStatus.NULL);
                        }
                    });
                    em.flush();
                    session.getTransactionManager().commit();
                } catch (Exception e) {
                    System.err.println("Error during PostMigrationEvent processing: " + e.getMessage());
                    e.printStackTrace();
                }
            }
        });
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
