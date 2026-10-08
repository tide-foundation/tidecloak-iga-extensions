package org.tidecloak.iga.providers;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.keys.GeneratedEcdsaKeyProviderFactory;
import org.keycloak.keys.KeyProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.tidecloak.iga.crypto.CertificationRequestParser;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.entities.IgaRealmCertEntity;
import org.tidecloak.iga.nginx.NginxGlobalCounterService;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Service for managing pending realm-certificate requests.
 *
 * Sidecar pattern: a parent {@link IgaChangeRequestEntity} drives the approval
 * flow (entity_type = "REALM", action_type = "REQUEST_REALM_CERT") and the
 * {@link IgaRealmCertEntity} sidecar holds the realm P-256 server certificate
 * and the Ed25519 realm root CA.
 *
 * <p>Mirrors {@link IgaServerCertDraftService}, with two differences that follow from the
 * certificates being realm-scoped: the CR is filed against the REALM rather than a client, and
 * rotation appends a row instead of updating one, so {@link #findCurrent} is how callers resolve
 * "the realm's certificates" rather than a per-key fingerprint lookup.
 */
public class IgaRealmCertService {

    /** Action type on the parent CR. The replay dispatcher keys its commit branch on this. */
    public static final String ACTION_TYPE = "REQUEST_REALM_CERT";

    /**
     * Subject CN for the realm CSR: {@code CN=realm_<realmName>}, checked literally by the ORK
     * against the attested realm name.
     *
     * <p>Deliberately WITHOUT the {@code _ca} suffix. That suffix belongs to the root CA — the
     * ISSUER of this certificate — and the ORK keeps the two subjects distinct on purpose. A CSR
     * carrying {@code CN=realm_<name>_ca} is rejected with "Tidecloak realm CSR subject name does
     * not match realm attestation name".
     */
    private static final String REALM_CN_PREFIX = "realm_";

    /**
     * PKCS#10 self-signature algorithm. SHA-256 with ECDSA — the digest pairs with the P-256 key
     * (both 256-bit, per SEC 1 / RFC 5480) and matches ES256, the JOSE algorithm the Keycloak key
     * provider registers the key under.
     */
    private static final String CSR_SIGNATURE_ALGORITHM = "SHA256withECDSA";

    /** Name of the realm key-provider component this class creates when the realm has no P-256 key. */
    private static final String KEY_COMPONENT_NAME = "iga-realm-cert-p256";

    /**
     * Priority of that component — far below anything else a realm carries (Keycloak's own
     * generated-key fallback sits at -100, admin-managed providers default to 0 or higher), so this
     * key never wins provider selection while another ES256 key exists.
     */
    private static final long KEY_COMPONENT_PRIORITY = -1_000_000L;

    /**
     * Passed explicitly to the signer builder rather than looked up by name, so CSR generation does
     * not depend on Bouncy Castle being registered as a JVM security provider — the same reasoning
     * as {@link CertificationRequestParser}.
     */
    private static final BouncyCastleProvider BC = new BouncyCastleProvider();

    private final EntityManager em;
    private final IgaChangeRequestService changeRequestService;

    public IgaRealmCertService(EntityManager em, IgaChangeRequestService changeRequestService) {
        this.em = em;
        this.changeRequestService = changeRequestService;
    }

    // -------------------------------------------------------------------------
    // CSR generation — the realm's own P-256 key
    // -------------------------------------------------------------------------

    /**
     * Build the realm's PKCS#10 certificate signing request over a P-256 key the realm owns,
     * generating that key on first use and reusing it on every call after.
     *
     * <h2>The key</h2>
     * The key comes from Keycloak's own {@code KeyManager} rather than being generated and stored
     * by this module: the realm server certificate is Tidecloak's TLS identity, so its private key
     * belongs in the realm's key store where it is encrypted, rotatable and visible in the admin
     * console — not in an IGA sidecar table. {@code getActiveKey(realm, SIG, ES256)} returns the
     * realm's active P-256 signing key, which is what makes this reuse rather than mint a fresh key
     * per call. When the realm has none (a stock realm ships RSA/HMAC/AES providers but no EC one),
     * an {@code ecdsa-generated} component pinned to the P-256 curve is added to the realm and the
     * lookup retried; Keycloak generates the keypair as part of validating that component.
     *
     * <h2>Proof of possession</h2>
     * A PKCS#10 request is self-signed, so signing the {@code certificationRequestInfo} with the
     * private key half of the key being certified IS the proof of possession. The result is then
     * round-tripped through {@link CertificationRequestParser#parseAndVerify} — the same gate the
     * ORK-facing client enrolment runs — so a CSR is never handed back unless its self-signature
     * has actually been verified, rather than merely assumed from having just built it.
     *
     * @param session the session whose {@code KeyManager} owns the realm's keys
     * @param realm   the realm; its name forms the subject {@code CN=realm_<realmName>}
     * @return the verified CSR — DER encoding, subject SubjectPublicKeyInfo, and subject CN
     * @throws RuntimeException if no P-256 key can be resolved or created, or if the CSR cannot be
     *                          built or fails its own proof-of-possession check
     */
    public static CertificationRequestParser.ParsedCsr CreateRealmCertificateSigningRequest(
            KeycloakSession session, RealmModel realm) {
        KeyWrapper key = resolveOrCreateP256Key(session, realm);

        Object privateKey = key.getPrivateKey();
        Object publicKey = key.getPublicKey();
        if (!(privateKey instanceof PrivateKey) || !(publicKey instanceof PublicKey)) {
            // A provider that exposes no usable private key half (an opaque/external key) cannot
            // produce proof of possession, so there is nothing to fall back to.
            throw new RuntimeException("IGA realm-cert: realm " + realm.getName()
                    + " P-256 key " + key.getKid() + " does not expose a usable keypair for signing");
        }

        String subject = "CN=" + REALM_CN_PREFIX + realm.getName();
        byte[] csrDer;
        try {
            ContentSigner signer = new JcaContentSignerBuilder(CSR_SIGNATURE_ALGORITHM)
                    .setProvider(BC)
                    .build((PrivateKey) privateKey);
            PKCS10CertificationRequest csr = new JcaPKCS10CertificationRequestBuilder(
                    new X500Name(subject), (PublicKey) publicKey).build(signer);
            csrDer = csr.getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("IGA realm-cert: failed to build the " + subject
                    + " CSR for realm " + realm.getName() + ": " + e.getMessage(), e);
        }

        // Verify what was just built rather than trusting it. Also normalises the outputs the
        // caller persists (DER re-encoding + the subject SPKI) into one place.
        return CertificationRequestParser.parseAndVerify(Base64.getEncoder().encodeToString(csrDer));
    }

    /**
     * The realm's active P-256 signing key, creating the key provider if the realm has none.
     *
     * <p>The component is created at {@link #KEY_COMPONENT_PRIORITY} so it loses provider selection
     * to every other ES256 key in the realm and is not picked to sign tokens while any alternative
     * exists. A dedicated component name keeps it identifiable in the admin console.
     */
    private static KeyWrapper resolveOrCreateP256Key(KeycloakSession session, RealmModel realm) {
        // Returns null (it does not throw) when the realm has no matching active key.
        KeyWrapper key = session.keys().getActiveKey(realm, KeyUse.SIG, Algorithm.ES256);
        if (key != null) {
            return key;
        }

        MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
        config.putSingle(GeneratedEcdsaKeyProviderFactory.ECDSA_ELLIPTIC_CURVE_KEY,
                GeneratedEcdsaKeyProviderFactory.DEFAULT_ECDSA_ELLIPTIC_CURVE); // P-256
        config.putSingle("active", "true");
        config.putSingle("enabled", "true");
        config.putSingle("priority", String.valueOf(KEY_COMPONENT_PRIORITY));

        ComponentModel component = new ComponentModel();
        component.setName(KEY_COMPONENT_NAME);
        component.setParentId(realm.getId());
        component.setProviderId(GeneratedEcdsaKeyProviderFactory.ID);
        component.setProviderType(KeyProvider.class.getName());
        component.setConfig(config);
        // addComponentModel (unlike importComponentModel) runs the factory's validateConfiguration,
        // which is what actually generates the keypair into the component config.
        realm.addComponentModel(component);

        key = session.keys().getActiveKey(realm, KeyUse.SIG, Algorithm.ES256);
        if (key == null) {
            throw new RuntimeException("IGA realm-cert: realm " + realm.getName()
                    + " has no active P-256 (ES256) signing key and one could not be created");
        }
        return key;
    }

    /**
     * Create a new realm-certificate request. Inserts BOTH the parent
     * IGA_CHANGE_REQUEST row (entity_type=REALM, action_type=REQUEST_REALM_CERT)
     * AND the IGA_REALM_CERT sidecar linked via the changeRequest FK.
     *
     * <p>Only the server-certificate side is supplied here: the CSR is for Tidecloak's own P-256
     * key (built by {@link #CreateRealmCertificateSigningRequest}), whereas the root CA is signed
     * over the threshold gVVK and has no CSR — the cohort produces it during the same round, so its
     * columns are filled in at {@link #issueCerts} time.
     *
     * Returns the sidecar entity with {@code changeRequest} populated.
     */
    public IgaRealmCertEntity createRequest(RealmModel realm,
                                            String requestedBy,
                                            String serverCsr,
                                            String serverPublicKey,
                                            String serverPublicKeyFingerprint,
                                            String serverSerialNumber) {
        // Build the row payload that the parent CR carries. This is what the
        // replay dispatcher will see when REQUEST_REALM_CERT is approved.
        Map<String, Object> row = new HashMap<>();
        row.put("realm_id", realm.getId());
        row.put("server_public_key", serverPublicKey);
        if (serverPublicKeyFingerprint != null) row.put("server_public_key_fingerprint", serverPublicKeyFingerprint);
        if (serverSerialNumber != null) row.put("server_serial_number", serverSerialNumber);

        IgaChangeRequestEntity cr = changeRequestService.create(
                realm,
                "REALM",
                realm.getId(),
                ACTION_TYPE,
                List.of(row),
                requestedBy);

        long now = System.currentTimeMillis();
        IgaRealmCertEntity entity = new IgaRealmCertEntity();
        entity.setId(UUID.randomUUID().toString());
        entity.setChangeRequest(cr);
        entity.setRealmId(realm.getId());
        entity.setServerCsr(serverCsr);
        entity.setServerPublicKey(serverPublicKey);
        entity.setServerPublicKeyFingerprint(serverPublicKeyFingerprint);
        entity.setServerSerialNumber(serverSerialNumber);
        entity.setRevoked(false);
        entity.setCreatedAt(now);
        em.persist(entity);
        em.flush();
        return entity;
    }

    /**
     * Store the validated certificates from a committed signing round — the P-256 realm server
     * certificate and the Ed25519 root CA, each with its own validity window.
     *
     * <p>Sidecar only — the parent CR's status is NOT touched here, for the same reason as
     * {@link IgaServerCertDraftService#issueCert}: the commit path owns the CR lifecycle.
     *
     * <p>Also advances the global nginx generation, because this is the write that changes what the
     * proxy in front of every replica must serve. It happens here rather than at the caller so the
     * two land in the same transaction: a replica that reacts to the new generation is then
     * guaranteed to read the certificates that caused it. Reading them back is the reconciler's
     * job — this method only records that there is something new to read.
     */
    public IgaRealmCertEntity issueCerts(String id,
                                         String serverCertificate,
                                         Long serverNotBefore,
                                         Long serverNotAfter,
                                         String rootCaCertificate,
                                         String rootCaSerialNumber,
                                         Long rootCaNotBefore,
                                         Long rootCaNotAfter) {
        IgaRealmCertEntity entity = em.find(IgaRealmCertEntity.class, id);
        if (entity == null) {
            throw new IllegalArgumentException("Realm cert not found: " + id);
        }
        entity.setServerCertificate(serverCertificate);
        entity.setServerNotBefore(serverNotBefore);
        entity.setServerNotAfter(serverNotAfter);
        entity.setRootCaCertificate(rootCaCertificate);
        entity.setRootCaSerialNumber(rootCaSerialNumber);
        entity.setRootCaNotBefore(rootCaNotBefore);
        entity.setRootCaNotAfter(rootCaNotAfter);
        entity.setUpdatedAt(System.currentTimeMillis());
        new NginxGlobalCounterService(em).allocateNextGeneration();
        em.flush();
        return entity;
    }

    /**
     * Mark a row as revoked. Both certificates are revoked as a unit — they are issued together
     * and the server certificate is worthless without its anchor.
     */
    public IgaRealmCertEntity revoke(String id) {
        IgaRealmCertEntity entity = em.find(IgaRealmCertEntity.class, id);
        if (entity == null) {
            throw new IllegalArgumentException("Realm cert not found: " + id);
        }
        long now = System.currentTimeMillis();
        entity.setRevoked(true);
        entity.setRevokedAt(now);
        entity.setUpdatedAt(now);
        em.flush();
        return entity;
    }

    /**
     * Find a row by id. Returns null if not found.
     */
    public IgaRealmCertEntity findById(String id) {
        return em.find(IgaRealmCertEntity.class, id);
    }

    /**
     * The realm's current certificates — newest non-revoked, issued row — or null if the realm has
     * none yet. Rotation appends a row, so this is the single resolver every read path should use.
     */
    public IgaRealmCertEntity findCurrent(String realmId) {
        TypedQuery<IgaRealmCertEntity> query = em.createNamedQuery(
                "IgaRealmCert.findCurrent", IgaRealmCertEntity.class);
        query.setParameter("realmId", realmId);
        query.setMaxResults(1);
        List<IgaRealmCertEntity> results = query.getResultList();
        return results.isEmpty() ? null : results.get(0);
    }

    /**
     * The realm's in-flight certificate request — no certificate yet, not revoked, parent CR still
     * PENDING — or null if there is none. Same definition of "pending" as the per-client duplicate
     * guard in {@code ServerIdentityResourceProvider}.
     *
     * <p>Needed alongside {@link #findCurrent}, which only matches ISSUED rows: without this, a
     * realm whose request is sitting in the approval queue looks uncertificated, and every client
     * enrolling in that window would file another duplicate. Callers also use the returned row's
     * change request as the prerequisite to chain a client certificate to.
     */
    public IgaRealmCertEntity findPending(String realmId) {
        for (IgaRealmCertEntity row : listByRealm(realmId)) {
            boolean pending = row.getServerCertificate() == null
                    && !row.isRevoked()
                    && row.getChangeRequest() != null
                    && "PENDING".equals(row.getChangeRequest().getStatus());
            if (pending) {
                return row;
            }
        }
        return null;
    }

    /**
     * List all rows for a realm, ordered by createdAt DESC.
     */
    public List<IgaRealmCertEntity> listByRealm(String realmId) {
        TypedQuery<IgaRealmCertEntity> query = em.createNamedQuery(
                "IgaRealmCert.findByRealm", IgaRealmCertEntity.class);
        query.setParameter("realmId", realmId);
        return query.getResultList();
    }

    /**
     * Rows attached to a change request. The commit path uses this to find the sidecar it must
     * fill in once the CR is approved.
     */
    public List<IgaRealmCertEntity> findByChangeRequestId(String crId) {
        TypedQuery<IgaRealmCertEntity> query = em.createNamedQuery(
                "IgaRealmCert.findByChangeRequestId", IgaRealmCertEntity.class);
        query.setParameter("crId", crId);
        return query.getResultList();
    }

    /**
     * Delete a row by id. No-op if it doesn't exist. Does NOT delete the
     * parent change request (FK is ON DELETE SET NULL).
     */
    public void deleteById(String id) {
        IgaRealmCertEntity existing = em.find(IgaRealmCertEntity.class, id);
        if (existing == null) {
            return;
        }
        em.remove(existing);
        em.flush();
    }
}
