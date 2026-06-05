package org.tidecloak.iga.producer.spi;

import java.util.ArrayList;
import java.util.List;
import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.tide.attestation.AttestationExporterProvider;
import org.keycloak.tide.attestation.SignedUnit;
import org.midgard.models.SignRequestSettingsMidgard;
import org.tidecloak.iga.attestors.TideAttestor;
import org.tidecloak.iga.producer.ExportRequest;
import org.tidecloak.iga.producer.RealmAttestationExporter;
import org.tidecloak.iga.producer.units.AttestationUnit;
import org.tidecloak.iga.producer.units.AttestationUnitType;

public class IgaAttestationExporterProvider implements AttestationExporterProvider {
    private static final Logger log = Logger.getLogger(IgaAttestationExporterProvider.class);

    /**
     * The bare VVK signature is always EXACTLY 64 bytes (Ed25519). A stored
     * {@code TIDE-FIRSTADMIN-v1:}+b64 attestation whose decoded body is not 64 bytes
     * is NOT a replayable envelope signature (e.g. the firstAdmin/policy STUB, which
     * is {@code base64(sha256(...))} = 32 bytes) — those fall back to re-sign.
     */
    static final int VVK_SIG_LEN = 64;

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

    /**
     * HYBRID replay/re-sign (Design B, Phase 1 — {@code user_role_mapping_set} only).
     *
     * <p>The {@code user_role_mapping_set} unit's final VVK signature is stamped onto
     * the user's {@code USER_ROLE_MAPPING.attestation} column at GRANT_ROLES commit time
     * (see {@link TideAttestor#signFirstAdminUnitWithVvk}). On a capable firstAdmin realm
     * that column holds {@code TIDE-FIRSTADMIN-v1:}+base64(64-byte VVK sig) over the EXACT
     * producer {@code UserRoleMappingSetUnit.serialize()} envelope. Login REPLAYS that
     * stored sig instead of re-signing — proving the sign-at-commit / replay-at-login
     * architecture on one unit.
     *
     * <p>All OTHER units are still re-signed in one Midgard round-trip (unchanged
     * behaviour). The {@code user_role_mapping_set} unit ALSO re-signs when its stored
     * attestation is a stub / missing (non-capable / dev / pre-flip realms) so pre-flip
     * login keeps working.
     */
    @Override
    public List<SignedUnit> exportSignedAccessTokenUnits(RealmModel realm, String clientId, String userId, String scope) {
        // 1. Build the units and serialize each ONCE — these are the exact bytes we sign/replay AND ship.
        List<AttestationUnit> units = exportUnits(realm, clientId, userId, scope);
        if (units.isEmpty()) {
            // No units to attest — nothing to sign.
            return new ArrayList<>(0);
        }
        byte[][] envelopes = new byte[units.size()][];
        for (int i = 0; i < units.size(); i++) {
            envelopes[i] = units.get(i).serialize();
        }

        // 1a. Locate the user_role_mapping_set unit (the user's owner-set) and try to
        //     REPLAY its stored VVK sig from USER_ROLE_MAPPING.attestation. The producer
        //     envelope (envelopes[urmIdx]) is byte-identical to what the commit signed
        //     (both = sorted UserRoleMappingSetUnit.serialize()), so we attach it verbatim
        //     with the decoded 64-byte sig — no re-sign.
        int urmIdx = -1;
        for (int i = 0; i < units.size(); i++) {
            if (units.get(i).type() == AttestationUnitType.USER_ROLE_MAPPING_SET) {
                urmIdx = i;
                break;
            }
        }
        byte[] replayedUrmSig = null;
        if (urmIdx >= 0) {
            String storedAttestation = lookupUserRoleMappingSetSig(userId);
            replayedUrmSig = decodeReplayableSig(storedAttestation);
            if (replayedUrmSig != null) {
                log.debugf("IGA signed unit export: REPLAYING user_role_mapping_set VVK sig from "
                        + "USER_ROLE_MAPPING.attestation for user %s (realm %s) — no re-sign.",
                        userId, realm.getName());
            } else {
                log.debugf("IGA signed unit export: user_role_mapping_set attestation for user %s (realm %s) "
                        + "is a stub/missing — re-signing it with the other units.", userId, realm.getName());
            }
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

        // 3. Collect the envelopes that still need a FRESH re-sign — everything except a
        //    successfully replayed user_role_mapping_set. The replayed index (if any) is
        //    skipped here and stitched back in at step 5 from the column.
        List<byte[]> toSign = new ArrayList<>(envelopes.length);
        List<Integer> toSignIdx = new ArrayList<>(envelopes.length);
        for (int i = 0; i < envelopes.length; i++) {
            if (i == urmIdx && replayedUrmSig != null) {
                continue; // replayed from the column — not re-signed
            }
            toSign.add(envelopes[i]);
            toSignIdx.add(i);
        }

        // 4. Batch-sign the still-re-signed envelopes in ONE Midgard.SignModel round-trip
        //    (Signatures[0..M-1], one per unit in order). If everything was replayed
        //    (only possible if the URM-set were the sole unit — not the case today), skip.
        byte[][] freshSigs;
        try {
            if (toSign.isEmpty()) {
                freshSigs = new byte[0][];
            } else {
                SignRequestSettingsMidgard settings = TideAttestor.constructSignSettings(config);
                freshSigs = TideAttestor.signUnitsWithFirstAdminVvk(
                        toSign.toArray(new byte[0][]), settings,
                        firstAdminAuthorizer, firstAdminAuthorizerCert, realm.getName());
            }
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("IGA signed unit export: per-unit VVK signing failed for realm "
                    + realm.getName() + ": " + e.getMessage(), e);
        }

        // 5. Reassemble the per-unit sigs in original order: the replayed URM-set sig from
        //    the column, the rest from the fresh batch. Pair each with its ORIGINAL envelope
        //    byte[] (never re-serialize between signing/replay and shipping).
        byte[][] perUnitSig = new byte[envelopes.length][];
        for (int j = 0; j < toSignIdx.size(); j++) {
            perUnitSig[toSignIdx.get(j)] = freshSigs[j];
        }
        if (urmIdx >= 0 && replayedUrmSig != null) {
            perUnitSig[urmIdx] = replayedUrmSig;
        }

        List<SignedUnit> out = new ArrayList<>(envelopes.length);
        for (int i = 0; i < envelopes.length; i++) {
            out.add(new SignedUnit(envelopes[i], perUnitSig[i]));
        }
        log.debugf("IGA signed unit export: %d unit(s) for realm %s (%d re-signed, %d replayed).",
                envelopes.length, realm.getName(), toSign.size(),
                (urmIdx >= 0 && replayedUrmSig != null) ? 1 : 0);
        return out;
    }

    /**
     * Decode a stored {@code USER_ROLE_MAPPING.attestation} into a replayable bare VVK
     * signature, or {@code null} if it is not a real replayable firstAdmin envelope sig
     * (null/blank, wrong prefix, undecodable, or wrong length — e.g. the 32-byte
     * {@code base64(sha256)} firstAdmin STUB). A non-null return is the EXACT 64-byte VVK
     * signature the commit stamped over the producer's {@code UserRoleMappingSetUnit}
     * envelope; the ork verifies it over the literal envelope bytes.
     *
     * <p>Pure + side-effect-free so the replay contract is unit-testable without a session.
     */
    static byte[] decodeReplayableSig(String attestation) {
        if (attestation == null || attestation.isBlank()) {
            return null;
        }
        if (!attestation.startsWith(TideAttestor.FIRSTADMIN_SIG_PREFIX)) {
            return null;
        }
        String b64 = attestation.substring(TideAttestor.FIRSTADMIN_SIG_PREFIX.length());
        byte[] sig;
        try {
            sig = java.util.Base64.getDecoder().decode(b64);
        } catch (IllegalArgumentException e) {
            return null;
        }
        if (sig.length != VVK_SIG_LEN) {
            // The firstAdmin STUB shares the prefix but is base64(sha256(...)) = 32 bytes.
            return null;
        }
        return sig;
    }

    /**
     * The stored per-set VVK sig for the user's owner-set: any of the user's
     * {@code USER_ROLE_MAPPING} rows carries the same per-set {@code attestation}, so we
     * read the first non-null one (preferring a real prefixed sig over a bare/null).
     * Returns {@code null} if the user has no attested URM row.
     */
    private String lookupUserRoleMappingSetSig(String userId) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        @SuppressWarnings("unchecked")
        List<String> atts = em.createQuery(
                        "SELECT urm.attestation FROM UserRoleMappingEntity urm "
                                + "WHERE urm.user.id = :owner AND urm.attestation IS NOT NULL")
                .setParameter("owner", userId)
                .setMaxResults(1)
                .getResultList();
        return atts.isEmpty() ? null : atts.get(0);
    }

    private List<AttestationUnit> exportUnits(RealmModel realm, String clientId, String userId, String scope) {
        ExportRequest req = ExportRequest.accessToken(clientId, userId, scope);
        return new RealmAttestationExporter().export(session, realm, req);
    }
}
