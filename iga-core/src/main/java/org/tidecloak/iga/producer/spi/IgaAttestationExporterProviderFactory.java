package org.tidecloak.iga.producer.spi;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.tide.attestation.AttestationExporterProvider;
import org.keycloak.tide.attestation.AttestationExporterProviderFactory;

public class IgaAttestationExporterProviderFactory implements AttestationExporterProviderFactory {
    @Override
    public AttestationExporterProvider create(KeycloakSession session) {
        return new IgaAttestationExporterProvider(session);
    }
    @Override public void init(Config.Scope config) {}
    @Override public void postInit(KeycloakSessionFactory factory) {}
    @Override public void close() {}
    @Override public String getId() { return "iga"; }
}
