package org.tidecloak.iga.producer.spi;

import java.util.ArrayList;
import java.util.List;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.tide.attestation.AttestationExporterProvider;
import org.tidecloak.iga.producer.ExportRequest;
import org.tidecloak.iga.producer.RealmAttestationExporter;
import org.tidecloak.iga.producer.units.AttestationUnit;

public class IgaAttestationExporterProvider implements AttestationExporterProvider {
    private final KeycloakSession session;

    public IgaAttestationExporterProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public List<byte[]> exportSerializedAccessTokenUnits(RealmModel realm, String clientId, String userId, String scope) {
        ExportRequest req = ExportRequest.accessToken(clientId, userId, scope);
        List<AttestationUnit> units = new RealmAttestationExporter().export(session, realm, req);
        List<byte[]> out = new ArrayList<>(units.size());
        for (AttestationUnit u : units) {
            out.add(u.serialize());
        }
        return out;
    }
}
