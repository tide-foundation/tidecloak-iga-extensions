package org.tidecloak.iga.producer.spi;

import java.util.ArrayList;
import java.util.List;
import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.tide.attestation.AttestationExporterProvider;
import org.keycloak.tide.attestation.SignedUnit;
import org.tidecloak.iga.attestors.TideAttestor;
import org.tidecloak.iga.producer.ExportRequest;
import org.tidecloak.iga.producer.RealmAttestationExporter;
import org.tidecloak.iga.producer.units.AttestationUnit;

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
     * UNIFORM replay-from-column (Design B, PR-B). Every producer unit's final VVK
     * signature is stamped onto its dedicated entity column — at per-CR-commit time
     * (the PR-A / PR-A.2 stampers) and at toggle-on for the provisioning / no-CR
     * closure (the {@code IgaToggleOnBackfill}). On a capable firstAdmin realm each
     * column holds {@code TIDE-FIRSTADMIN-v1:}+base64(64-byte VVK sig) over the EXACT
     * producer {@code unit.serialize()} envelope. Login now REPLAYS every unit's stored
     * sig — it makes NO firstAdmin-pack call (the pack is burned at the multiAdmin
     * flip, so re-signing at login is impossible post-flip).
     *
     * <p><b>Fail-closed, all-or-nothing.</b> If ANY unit's column is missing, a
     * non-replayable stub, or a wrong-length sig, the export throws a clear error
     * naming the unit type + target id. A coverage gap is therefore a LOUD, debuggable
     * failure — never a silent re-sign over divergent bytes.
     */
    @Override
    public List<SignedUnit> exportSignedAccessTokenUnits(RealmModel realm, String clientId, String userId, String scope) {
        // 1. Build the units — the EXACT closure the login emits. Each unit serializes
        //    once to the producer envelope the ork TVE re-derives and verifies.
        List<AttestationUnit> units = exportUnits(realm, clientId, userId, scope);
        if (units.isEmpty()) {
            return new ArrayList<>(0);
        }

        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        // 2. For EACH unit: resolve its PR-A/A.2 column, require a real
        //    TIDE-FIRSTADMIN-v1:+b64(64B) sig, decode it, and attach (serialize(), sig).
        //    No re-sign anywhere — the burned firstAdmin pack is never touched at login.
        //    Self-registered users now have their user_identity unit gVRK-signed AT
        //    REGISTRATION (signAndStampUserIdentity), so every unit's column carries a
        //    replayable sig — there is no accept-unsigned lane; a NULL/stub column is a
        //    fail-closed coverage hole for all unit types alike.
        List<SignedUnit> out = new ArrayList<>(units.size());
        for (AttestationUnit unit : units) {
            String stored = UnitColumnMapping.readStored(em, unit);
            out.add(replayOrFailClosed(unit, stored, realm.getName()));
        }

        log.debugf("IGA signed unit export (uniform replay): %d unit(s) for realm %s "
                + "client %s user %s — all replayed from column.",
                out.size(), realm.getName(), clientId, userId);
        return out;
    }

    /**
     * Attach a unit's verbatim envelope to its replayed 64-byte sig, or FAIL-CLOSED with
     * a clear error naming the unit type + target id when the stored column is missing /
     * a stub / wrong-length. Extracted (package-private + static) so the all-or-nothing
     * read contract is unit-testable without a session.
     */
    static SignedUnit replayOrFailClosed(AttestationUnit unit, String stored, String realmName) {
        byte[] sig = decodeReplayableSig(stored);
        if (sig == null) {
            // The toggle-on backfill + per-CR-commit stampers (and, for self-registered
            // users, signAndStampUserIdentity at registration) must have signed this column
            // already; a NULL/stub here is a coverage hole the read must NOT paper over by
            // re-signing divergent bytes or admitting an unsigned unit.
            throw new RuntimeException("IGA signed unit export (uniform replay): realm "
                    + realmName + " unit " + unit.type().wireName() + " target "
                    + unit.targetId() + " has " + describe(stored)
                    + " — no replayable 64-byte VVK signature in its column. The toggle-on "
                    + "backfill / per-CR-commit stamping did not cover this unit; refusing to "
                    + "ship an unsigned or re-signed attestation unit.");
        }
        return new SignedUnit(unit.serialize(), sig);
    }

    /** Human description of a non-replayable stored attestation for the fail-closed error. */
    private static String describe(String stored) {
        if (stored == null) return "a NULL column";
        if (stored.isBlank()) return "a blank column";
        if (!stored.startsWith(TideAttestor.FIRSTADMIN_SIG_PREFIX)) {
            return "a non-firstAdmin-prefixed value";
        }
        return "a stub / wrong-length sig (not 64 bytes)";
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

    private List<AttestationUnit> exportUnits(RealmModel realm, String clientId, String userId, String scope) {
        ExportRequest req = ExportRequest.accessToken(clientId, userId, scope);
        return new RealmAttestationExporter().export(session, realm, req);
    }
}
