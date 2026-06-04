package org.tidecloak.iga.producer.spi;

import java.util.ArrayList;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.tide.attestation.AttestationExporterProvider;
import org.keycloak.tide.attestation.SignedUnit;
import org.midgard.models.SignRequestSettingsMidgard;
import org.tidecloak.iga.attestors.TideAttestor;
import org.tidecloak.iga.producer.ExportRequest;
import org.tidecloak.iga.producer.RealmAttestationExporter;
import org.tidecloak.iga.producer.units.AttestationUnit;

public class IgaAttestationExporterProvider implements AttestationExporterProvider {
    private static final Logger log = Logger.getLogger(IgaAttestationExporterProvider.class);

    private final KeycloakSession session;

    public IgaAttestationExporterProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public List<byte[]> exportSerializedAccessTokenUnits(RealmModel realm, String clientId, String userId, String scope) {
        List<AttestationUnit> units = exportUnits(realm, clientId, userId, scope);
        List<byte[]> out = new ArrayList<>(units.size());
        for (AttestationUnit u : units) {
            out.add(u.serialize());
        }
        return out;
    }

    @Override
    public List<SignedUnit> exportSignedAccessTokenUnits(RealmModel realm, String clientId, String userId, String scope) {
        // 1. Build the units and serialize each ONCE — these are the exact bytes we sign AND ship.
        List<AttestationUnit> units = exportUnits(realm, clientId, userId, scope);
        if (units.isEmpty()) {
            // No units to attest — nothing to sign.
            return new ArrayList<>(0);
        }
        byte[][] envelopes = new byte[units.size()][];
        for (int i = 0; i < units.size(); i++) {
            envelopes[i] = units.get(i).serialize();
        }

        // 2. Derive signing settings + the firstAdmin authorizer pack from the realm's
        //    tide-vendor-key component config — the SAME derivation the firstAdmin ceremony
        //    uses (TideAttestor.constructSignSettings). No second env-var dependency.
        ComponentModel vendorKey = realm.getComponentsStream()
                .filter(c -> TideAttestor.TIDE_VENDOR_KEY_PROVIDER_ID.equals(c.getProviderId()))
                .findFirst()
                .orElseThrow(() -> new RuntimeException(
                        "IGA signed unit export: realm " + realm.getName()
                                + " has no tide-vendor-key component (VRK not provisioned)"));
        MultivaluedHashMap<String, String> config = vendorKey.getConfig();
        if (config == null) {
            throw new RuntimeException("IGA signed unit export: tide-vendor-key component has no config (realm "
                    + realm.getName() + ")");
        }

        // The firstAdmin AuthorizerPack (its ModelIds include AttestationUnit:1) — NOT the
        // main gVRK pack, which the ork's VRKAuthorizationFlow rejects for AttestationUnit:1.
        String firstAdminAuthorizer = config.getFirst(TideAttestor.CFG_FIRST_ADMIN_AUTHORIZER);
        String firstAdminAuthorizerCert = config.getFirst(TideAttestor.CFG_FIRST_ADMIN_AUTHORIZER_CERTIFICATE);
        if (firstAdminAuthorizer == null || firstAdminAuthorizer.isBlank()
                || firstAdminAuthorizerCert == null || firstAdminAuthorizerCert.isBlank()) {
            // Fail-closed: do NOT ship unsigned (placeholder) units. The M2M / no-firstAdmin-pack
            // realm has no authorizer that permits AttestationUnit:1, so it cannot stamp real sigs.
            log.warnf("IGA signed unit export: realm %s tide-vendor-key has no firstAdmin authorizer pack "
                            + "(authorizer/authorizerCertificate) — cannot produce real per-unit VVK signatures.",
                    realm.getName());
            throw new RuntimeException("IGA signed unit export: realm " + realm.getName()
                    + " is missing the firstAdmin authorizer pack (authorizer/authorizerCertificate) required to "
                    + "sign AttestationUnit:1; refusing to ship unsigned attestation units");
        }

        // 3. Batch-sign all envelopes in ONE Midgard.SignModel round-trip (the ork's
        //    AttestationUnitSignRequest returns Signatures[0..N-1], one per unit in order).
        try {
            SignRequestSettingsMidgard settings = TideAttestor.constructSignSettings(config);
            byte[][] sigs = TideAttestor.signUnitsWithFirstAdminVvk(
                    envelopes, settings, firstAdminAuthorizer, firstAdminAuthorizerCert, realm.getName());

            // 4. Pair each ORIGINAL envelope byte[] (the one we serialized and signed) with its
            //    sig — never re-serialize between signing and shipping.
            List<SignedUnit> out = new ArrayList<>(envelopes.length);
            for (int i = 0; i < envelopes.length; i++) {
                out.add(new SignedUnit(envelopes[i], sigs[i]));
            }
            log.debugf("IGA signed unit export: signed %d attestation unit(s) for realm %s.",
                    envelopes.length, realm.getName());
            return out;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("IGA signed unit export: per-unit VVK signing failed for realm "
                    + realm.getName() + ": " + e.getMessage(), e);
        }
    }

    private List<AttestationUnit> exportUnits(RealmModel realm, String clientId, String userId, String scope) {
        ExportRequest req = ExportRequest.accessToken(clientId, userId, scope);
        return new RealmAttestationExporter().export(session, realm, req);
    }
}
