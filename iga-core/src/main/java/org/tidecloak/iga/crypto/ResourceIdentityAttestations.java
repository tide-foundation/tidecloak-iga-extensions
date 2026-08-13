package org.tidecloak.iga.crypto;

import jakarta.persistence.EntityManager;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.tide.attestation.SignedUnit;
import org.tidecloak.iga.entities.IgaServerCertDraftEntity;
import org.tidecloak.iga.producer.RealmAttestationExporter;
import org.tidecloak.iga.producer.spi.IgaAttestationExporterProvider;
import org.tidecloak.iga.producer.spi.UnitColumnMapping;
import org.tidecloak.iga.producer.units.AttestationUnit;

/**
 * Sources the two gVVK-signed attestations {@code ResourceIdentity:1} requires.
 *
 * <h2>Where the signature comes from</h2>
 * The ORK validates each attestation as {@code bytes[..^64]} verified against {@code bytes[^64..]}
 * under the realm's gVVK — so the trailing 64 bytes must be an Ed25519 signature made with a
 * threshold key the cohort holds and Tidecloak never does. Tidecloak cannot sign these locally.
 *
 * <p>It does not have to. Those signatures already exist: every producer unit is signed through the
 * real VVK → Midgard → ORK ceremony at CR commit and the 64-byte result is stamped into that unit's
 * dedicated column ({@code RealmEntity.realmConfigAttestation} for {@code realm_config},
 * {@code ClientEntity.attestation} for {@code client_config} — see {@link UnitColumnMapping}). The
 * login path already replays exactly these bytes: {@code IgaAttestationExporterProvider} pairs each
 * unit's {@code serialize()} envelope with its stored signature and ships the pair. This class does
 * the same for the certificate flow — same unit, same column, same signature the token path uses.
 *
 * <p>Reusing that store rather than inventing a parallel one is what keeps the two consistent: an
 * attestation the ORK accepts here is one it already accepts at login, byte-for-byte.
 *
 * <h2>Fail-closed</h2>
 * The read goes through {@link IgaAttestationExporterProvider#replayOrFailClosed}, so a missing
 * column, a firstAdmin stub, or a wrong-length signature throws with the unit type and target id
 * named — the same all-or-nothing contract the login export obeys. Nothing here re-signs, and
 * nothing ships an unsigned unit: a coverage gap is a loud failure at approval time rather than a
 * request the cohort silently rejects later.
 *
 * <p>Practical consequence: a realm whose {@code realm_config} column has never been stamped cannot
 * request certificates until the toggle-on backfill (or a CR commit touching it) has covered it.
 * That is the correct order — the certificate flow attests to realm state, so that state has to be
 * attested first.
 *
 * @see org.tidecloak.iga.producer.RealmAttestationExporter#realmConfig
 * @see org.tidecloak.iga.producer.RealmAttestationExporter#clientConfig
 */
public final class ResourceIdentityAttestations {

    /** The gVVK signature length the ORK slices off the tail of each attestation. */
    private static final int VVK_SIG_LEN = 64;

    private ResourceIdentityAttestations() {
    }

    /**
     * The {@code realm_config} attestation: unit bytes followed by their 64-byte gVVK signature.
     *
     * <p>The ORK reads {@code RealmConfigAttestationUnit.Name} out of this to build the CA subject
     * ({@code CN=realm_<name>_ca}), to check the realm CSR's own {@code CN=realm_<name>} subject
     * against, and to fall back for the server certificate's frontendUrl. It enforces
     * {@code ^[A-Za-z0-9_-]{1,60}$} on the name.
     *
     * <p>Required by BOTH request modes — the ORK verifies it and takes the realm name from it
     * before it looks at which certificates were asked for.
     */
    public static byte[] realmConfig(KeycloakSession session, RealmModel realm) {
        return signedEnvelope(session, realm,
                RealmAttestationExporter.realmConfig(realm, realm.getId()));
    }

    /**
     * The {@code client_config} attestation for the enrolling client: unit bytes followed by their
     * 64-byte gVVK signature.
     *
     * <p>The ORK reads {@code ClientId} from this and requires the CSR subject to be exactly
     * {@code CN=client_<ClientId>}, and reads {@code ClientIdUuid} to build the certificate's
     * {@code urn:tide:client:<uuid>} SAN — the machine-matchable identity a peer keys on for mTLS.
     * Both are pattern-checked, so the SAN cannot be injected into.
     *
     * <p>The draft stores the human clientId (it comes from the CSR's CN), so the client is
     * resolved by clientId here; the unit carries the UUID separately.
     */
    public static byte[] clientConfig(KeycloakSession session, RealmModel realm,
                                      IgaServerCertDraftEntity draft) {
        ClientModel client = realm.getClientByClientId(draft.getClientId());
        if (client == null) {
            throw new RuntimeException("IGA server-cert: client '" + draft.getClientId()
                    + "' no longer exists in realm " + realm.getName()
                    + " — cannot build its client_config attestation");
        }
        return signedEnvelope(session, realm,
                RealmAttestationExporter.clientConfig(session, client, realm.getId()));
    }

    /**
     * Pair a unit's envelope with the signature stamped in its column, in the {@code unit ‖ sig}
     * layout the ORK slices.
     *
     * <p>The envelope comes back from {@code replayOrFailClosed} rather than from a fresh
     * {@code unit.serialize()} call here, so the bytes returned are the ones that signature was
     * paired with — the same pairing the login path ships.
     */
    private static byte[] signedEnvelope(KeycloakSession session, RealmModel realm,
                                         AttestationUnit unit) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        String stored = UnitColumnMapping.readStored(em, unit);
        SignedUnit signed = IgaAttestationExporterProvider.replayOrFailClosed(
                unit, stored, realm.getName());

        byte[] envelope = signed.getEnvelope();
        byte[] signature = signed.getSignature();
        if (signature == null || signature.length != VVK_SIG_LEN) {
            // replayOrFailClosed already enforces this; re-checked because the ORK slices a fixed
            // 64 bytes off the tail — a short signature would silently eat envelope bytes instead
            // of failing, and the verify would report a corrupt unit rather than a missing sig.
            throw new RuntimeException("IGA server-cert: " + unit.type().wireName() + " attestation "
                    + "for target " + unit.targetId() + " (realm " + realm.getName() + ") has a "
                    + (signature == null ? "null" : signature.length + "-byte")
                    + " signature, expected " + VVK_SIG_LEN);
        }

        byte[] out = new byte[envelope.length + signature.length];
        System.arraycopy(envelope, 0, out, 0, envelope.length);
        System.arraycopy(signature, 0, out, envelope.length, signature.length);
        return out;
    }
}
