package org.tidecloak.iga.rest;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resource.RealmResourceProvider;
import org.tidecloak.iga.crypto.CertificationRequestParser;
import org.tidecloak.iga.crypto.ServerCertSigner;
import org.tidecloak.iga.entities.IgaRealmCertEntity;
import org.tidecloak.iga.entities.IgaServerCertDraftEntity;
import org.tidecloak.iga.providers.IgaChangeRequestService;
import org.tidecloak.iga.providers.IgaRealmCertService;
import org.tidecloak.iga.providers.IgaServerCertDraftService;
import org.tidecloak.iga.providers.IgaServerCertEnrollmentTokenService;

import jakarta.persistence.EntityManager;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

/**
 * Public realm resource provider for workload server-identity certificate requests.
 * No user session: a request presents a PKCS#10 CSR as its whole body plus a single-use
 * enrolment token, and files a pending IGA change request (action_type = REQUEST_SERVER_CERT)
 * plus its IGA_SERVER_CERT_DRAFT sidecar, which must be approved by the admin quorum
 * (multiAdmin) or the firstAdmin VRK before a certificate is issued. Issuance (VVK signing +
 * cert assembly) runs at CR commit in {@code IgaReplayDispatcher.replayRequestServerCert}.
 *
 * <p>The CSR is the sole source of the enrolled identity: its subject CN is the clientId and its
 * subject public key is the key to be certified, and its self-signature is verified as proof of
 * possession before anything is persisted (see {@link CertificationRequestParser}). Because the
 * enrolment token is bound to a clientId, a CSR naming a different client cannot be enrolled with
 * it.
 *
 * <p>Ported from the {@code add-server-identity} branch
 * ({@code org.tidecloak.base.iga.serveridentity.ServerIdentityResourceProvider}), retargeted
 * onto the consolidated iga-core CR model: instead of persisting a {@code ChangesetRequestEntity}
 * directly, it calls {@link IgaServerCertDraftService#createRequest} which files the
 * {@code IgaChangeRequestEntity} + sidecar. The requestModel is left null (built at sign time
 * by {@code TideAttestor.buildMultiAdminApprovalModel}'s ServerCert branch).
 *
 * URL: /realms/{realm}/tide-server-identity/...
 */
public class ServerIdentityResourceProvider implements RealmResourceProvider {

    private static final Logger logger = Logger.getLogger(ServerIdentityResourceProvider.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();

    /** The conventional media type for a PKCS#10 request body. */
    private static final String CSR_MEDIA_TYPE = "application/pkcs10";

    /** The conventional media type for a PEM certificate bundle download. */
    private static final String PEM_MEDIA_TYPE = "application/x-pem-file";

    /**
     * Algorithm tag on stored public-key fingerprints. Shared by {@link #computeFingerprint} and
     * {@link #normalizeFingerprint} so the value written and the value looked up cannot drift.
     */
    private static final String FINGERPRINT_PREFIX = "SHA256:";

    /** Subject CN prefix the ORK's ResourceIdentitySignRequest requires on a resource CSR. */
    private static final String CLIENT_CN_PREFIX = "client_";

    /**
     * Clients the ORK will accept: it interpolates the id into a subject DN and a SAN URI, so it
     * enforces this pattern to stop a comma or other DN metacharacter being injected.
     */
    private static final java.util.regex.Pattern CLIENT_ID_REGEX =
            java.util.regex.Pattern.compile("^[A-Za-z0-9_-]{1,60}$");

    /**
     * Extract the clientId from a {@code CN=client_<clientId>} subject, or null if the CN does not
     * have that shape or names an id the ORK would reject.
     */
    private static String requireClientCn(String commonName) {
        if (commonName == null || !commonName.startsWith(CLIENT_CN_PREFIX)) {
            return null;
        }
        String clientId = commonName.substring(CLIENT_CN_PREFIX.length());
        return CLIENT_ID_REGEX.matcher(clientId).matches() ? clientId : null;
    }

    /**
     * Upper bound on the accepted CSR blob. A P-256 PKCS#10 request is roughly 300 bytes of DER
     * (~420 as PEM), so this leaves ample room for subject attributes while keeping the
     * unauthenticated ASN.1 parse bounded.
     */
    private static final int MAX_CSR_LENGTH = 8192;

    private final KeycloakSession session;

    public ServerIdentityResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {
    }

    private EntityManager getEm() {
        return session.getProvider(JpaConnectionProvider.class).getEntityManager();
    }

    private IgaServerCertDraftService getService() {
        return new IgaServerCertDraftService(getEm(), new IgaChangeRequestService(getEm(), session));
    }

    private IgaServerCertEnrollmentTokenService getEnrollmentTokenService() {
        return new IgaServerCertEnrollmentTokenService(getEm());
    }

    private IgaRealmCertService getRealmCertService() {
        return new IgaRealmCertService(getEm(), new IgaChangeRequestService(getEm(), session));
    }

    /**
     * File the realm-certificate request if the realm has neither issued certificates nor a request
     * already in flight. No-op otherwise — the realm root CA and Tidecloak's server certificate are
     * realm-wide, so they are requested once and shared by every workload in the realm.
     *
     * <p>Called from the client-enrolment path because that is where the need first surfaces: a
     * client certificate on its own cannot complete an mTLS handshake.
     *
     * <p>The CSR is generated here rather than supplied by a caller: unlike a workload, the subject
     * of the realm certificate is Tidecloak itself, so it holds the key and builds its own request
     * (see {@link IgaRealmCertService#CreateRealmCertificateSigningRequest}). As on the client path
     * the serial is generated NOW, so the value the cohort signs is fixed before the approval
     * window opens.
     *
     * @param requestedBy the enrolling client, recorded as the requester — there is no admin user
     *                    on this path, and the realm request is a side effect of that enrolment
     * @return the id of the realm-certificate CR the caller's client CR must wait on, or null when
     *         the realm is already certificated and there is nothing to wait for. A request already
     *         in flight is returned rather than re-filed, so every client enrolling during the
     *         approval window chains to the SAME prerequisite
     */
    private String ensureRealmCertRequested(RealmModel realm, String requestedBy) {
        IgaRealmCertService realmCertService = getRealmCertService();

        // Anchor already issued — the client certificate has something to chain to at commit and
        // needs no prerequisite.
        if (realmCertService.findCurrent(realm.getId()) != null) {
            return null;
        }

        IgaRealmCertEntity pending = realmCertService.findPending(realm.getId());
        if (pending == null) {
            CertificationRequestParser.ParsedCsr realmCsr =
                    IgaRealmCertService.CreateRealmCertificateSigningRequest(session, realm);

            pending = realmCertService.createRequest(
                    realm,
                    requestedBy,
                    Base64.getUrlEncoder().withoutPadding().encodeToString(realmCsr.derEncoded),
                    Base64.getUrlEncoder().withoutPadding().encodeToString(realmCsr.subjectPublicKeyInfo),
                    computeFingerprint(realmCsr.subjectPublicKeyInfo),
                    HexFormat.of().formatHex(ServerCertSigner.newSerialNumber()));

            logger.infof("IGA server-cert: realm %s has no realm certificate — filed a %s request "
                            + "(CN=%s) alongside the enrolment for client %s",
                    realm.getName(), IgaRealmCertService.ACTION_TYPE, realmCsr.commonName, requestedBy);
        }

        return pending.getChangeRequest() != null ? pending.getChangeRequest().getId() : null;
    }

    /**
     * Extract the bearer token from the {@code Authorization} header, or null if absent/empty.
     */
    private String extractBearerToken() {
        var headers = session.getContext().getHttpRequest().getHttpHeaders();
        if (headers == null) {
            return null;
        }
        String authz = headers.getHeaderString("Authorization");
        if (authz == null) {
            return null;
        }
        authz = authz.trim();
        if (authz.regionMatches(true, 0, "Bearer ", 0, 7)) {
            String token = authz.substring(7).trim();
            return token.isEmpty() ? null : token;
        }
        return null;
    }

    /**
     * Submit a server certificate request. The request body is the workload's PKCS#10 CSR —
     * PEM or bare base64 DER — and nothing else.
     *
     * <p>Everything the flow needs is read out of the CSR: the subject Common Name is the
     * requesting {@code clientId}, and the subject public key is the Ed25519 key to be certified.
     * The CSR's self-signature is verified first ({@link CertificationRequestParser#parseAndVerify}),
     * so a caller can only enrol a key it actually holds the private half of.
     *
     * <p>No user authentication; authorisation is the single-use enrolment token in the
     * {@code Authorization: Bearer} header, which is bound to the clientId the CSR names.
     * Files a pending IGA change request (REQUEST_SERVER_CERT) the admins must approve.
     */
    @POST
    @Path("request")
    @Consumes({CSR_MEDIA_TYPE, MediaType.TEXT_PLAIN, MediaType.APPLICATION_OCTET_STREAM,
               MediaType.WILDCARD})
    @Produces(MediaType.APPLICATION_JSON)
    public Response requestCertificate(String body) {
        try {
            RealmModel realm = session.getContext().getRealm();

            if (body == null || body.isBlank()) {
                return errorResponse(Response.Status.BAD_REQUEST, "Missing CSR");
            }
            // Bound the parse input before touching the ASN.1 reader. A P-256 PKCS#10 request is
            // ~300 bytes DER (~420 as PEM); the ceiling is generous but finite.
            if (body.length() > MAX_CSR_LENGTH) {
                return errorResponse(Response.Status.BAD_REQUEST,
                        "CSR exceeds maximum length of " + MAX_CSR_LENGTH + " characters");
            }

            // Parse + PROOF OF POSSESSION. Throws InvalidCsrException (an IllegalArgumentException)
            // on a malformed, non-Ed25519, CN-less, or unverifiable request -> 400 below.
            CertificationRequestParser.ParsedCsr csr = CertificationRequestParser.parseAndVerify(body);
            byte[] csrDer = csr.derEncoded;

            // The ORK requires the CSR subject to be exactly "CN=client_<clientId>" and compares
            // it literally against the attested clientId, so the prefix is part of the contract —
            // strip it here to get the clientId this realm knows. A CN without the prefix would
            // pass this endpoint and then be rejected by the cohort at commit, long after approval.
            String clientId = requireClientCn(csr.commonName);
            if (clientId == null) {
                return errorResponse(Response.Status.BAD_REQUEST,
                        "CSR subject must be CN=" + CLIENT_CN_PREFIX + "<clientId>");
            }
            // Encode once, here at the persistence boundary: PUBLIC_KEY is a TEXT column.
            String publicKey = Base64.getUrlEncoder().withoutPadding().encodeToString(csr.subjectPublicKeyInfo);

            // Validate the CSR's CN names a real client in this realm. Keyed on clientId, NOT the
            // internal UUID: the ORK compares the CN literally against the attested
            // client_config.ClientId, and takes the UUID from ClientIdUuid on that same attestation
            // to build the urn:tide:client SAN. So the CN is the clientId by contract, and a UUID
            // lookup here would reject every genuine CSR. Indexed either way.
            ClientModel client = realm.getClientByClientId(clientId);

            if (client == null) {
                return errorResponse(Response.Status.BAD_REQUEST,
                        "Client '" + clientId + "' not found in realm");
            }

            // --- Enrollment-token authentication (clientId is now known) ---
            // No/empty token -> 401.
            String enrollmentToken = extractBearerToken();
            if (enrollmentToken == null) {
                return errorResponse(Response.Status.UNAUTHORIZED, "Enrollment token required");
            }
            // Non-consuming validity gate. The actual single-use consume happens AFTER the CR is
            // created, so a token is not burned on a request that fails to file. Opaque on failure
            // (no oracle distinguishing not-found / expired / consumed / clientId-mismatch).
            // The token is bound to a clientId, so a CSR carrying some OTHER client's CN cannot be
            // enrolled with this token.
            IgaServerCertEnrollmentTokenService tokenService = getEnrollmentTokenService();
            if (!tokenService.isValid(realm.getId(), clientId, enrollmentToken)) {
                return errorResponse(Response.Status.FORBIDDEN, "Invalid or expired enrollment token");
            }

            // Compute public key fingerprint straight from the DER — no re-decode.
            String fingerprint = computeFingerprint(csr.subjectPublicKeyInfo);

            // Duplicate-request guard, keyed on the CSR's public key. The consolidated model has
            // no DRAFT status enum on the sidecar — a "pending" request is one whose parent CR is
            // still PENDING (cert not yet issued). Re-submitting the same CSR while its CR awaits
            // approval is a 409 rather than a second queue entry; a genuinely new keypair (another
            // replica of the same client) is unaffected.
            IgaServerCertDraftService service = getService();
            List<IgaServerCertDraftEntity> existingEntries = service.findByRealmAndFingerprint(realm.getId(), fingerprint);
            for (IgaServerCertDraftEntity existing : existingEntries) {
                boolean pending = existing.getCertificate() == null
                        && !existing.isRevoked()
                        && existing.getChangeRequest() != null
                        && "PENDING".equals(existing.getChangeRequest().getStatus());
                if (pending) {
                    return errorResponse(Response.Status.CONFLICT,
                            "A pending certificate request already exists for this public key");
                }
            }

            // FIRST client to enroll in a realm also files the realm-certificate request;
            // every later enrolment finds it already issued or already queued and skips.
            String realmCertCrId = ensureRealmCertRequested(realm, clientId);

            // Chain this request to the realm certificate when one is not issued yet: the leaf is
            // anchored by the realm root CA, so committing it first would issue a certificate that
            // cannot complete a handshake. The dependency gate holds the commit at 412
            // DEPENDENCY_NOT_MET until the realm CR is APPROVED. Null once the realm is
            // certificated — the anchor exists and there is nothing left to wait for.
            IgaServerCertDraftEntity created = service.createRequest(
                    realm,
                    clientId,              // requestedBy: the enrolling client (no admin user)
                    clientId,
                    Base64.getUrlEncoder().withoutPadding().encodeToString(csrDer),
                    publicKey,
                    fingerprint,
                    HexFormat.of().formatHex(ServerCertSigner.newSerialNumber()),
                    realmCertCrId == null ? null : List.of(realmCertCrId));

            // Atomic single-use consume AFTER the CR is filed. The conditional UPDATE is the
            // TOCTOU guard: under a concurrent double-present exactly one caller consumes the
            // row. If it returns false here, a racing request already consumed it -> 403 opaque.
            if (!tokenService.consumeIfValid(realm.getId(), clientId, enrollmentToken)) {
                return errorResponse(Response.Status.FORBIDDEN, "Invalid or expired enrollment token");
            }

            return Response.ok().type(MediaType.APPLICATION_JSON_TYPE).build();


        } catch (IllegalArgumentException e) {
            return errorResponse(Response.Status.BAD_REQUEST, e.getMessage());
        } catch (Exception e) {
            logger.error("Failed to create server certificate request", e);
            return errorResponse(Response.Status.INTERNAL_SERVER_ERROR,
                    "Failed to create certificate request: " + e.getMessage());
        }
    }

    /**
     * Check the status of a certificate request by its subject-public-key fingerprint. No auth
     * required. Returns the signed certificate + trust bundle once the CR has been committed and
     * the cert issued.
     *
     * <p><b>ACTIVE means usable.</b> The certificate and the trust bundle are released together or
     * not at all: they come from two separately-approved change requests (this client's, and the
     * realm's), so the leaf can land first. Until the realm's root CA is also committed the status
     * stays DRAFT and neither is returned — mTLS needs both halves, and a caller that received a
     * leaf alone would stop polling for an anchor it never got.
     *
     * <p>Keyed on the fingerprint rather than a server-issued id because the workload can derive
     * it locally — it is {@code SHA256:base64url(SHA-256(DER SubjectPublicKeyInfo))} over the same
     * key it put in its CSR — so enrolment needs to hand nothing back for the client to poll with.
     *
     * <p>A keypair can have several rows over time (re-enrolled after revocation). The most recent
     * one wins, which is the request the caller just filed.
     */
    @GET
    @Path("status")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getStatus(@QueryParam("fingerprint") String fingerprint) {
        try {
            if (fingerprint == null || fingerprint.isBlank()) {
                return errorResponse(Response.Status.BAD_REQUEST, "Missing fingerprint parameter");
            }

            RealmModel realm = session.getContext().getRealm();

            // Rows come back createdAt DESC, so index 0 is the newest request for this key.
            List<IgaServerCertDraftEntity> drafts = getService()
                    .findByRealmAndFingerprint(realm.getId(), normalizeFingerprint(fingerprint));

            if (drafts.isEmpty()) {
                return errorResponse(Response.Status.NOT_FOUND, "Certificate request not found");
            }
            IgaServerCertDraftEntity draft = drafts.get(0);

            // Derive a status string from the sidecar + parent CR state.
            String status = deriveStatus(draft);

            // The trust anchor is REALM-scoped and committed by its own change request, so this
            // client leaf can be issued while the realm pair is still pending approval. Only look
            // it up once the leaf is ACTIVE: this endpoint is polled, and there is nothing to pair
            // with while the leaf is still a draft.
            String trustBundle = null;
            if ("ACTIVE".equals(status)) {
                IgaRealmCertEntity realmCert = getRealmCertService().findCurrent(realm.getId());
                trustBundle = realmCert != null ? realmCert.getRootCaCertificate() : null;
                // Hold BOTH back until BOTH exist. A leaf with no anchor cannot complete a
                // handshake, so handing it over early gives the workload something unusable and —
                // worse — reporting ACTIVE tells it to stop polling for the half it still needs.
                // DRAFT is the accurate state: approved, not yet fully issued.
                if (trustBundle == null) {
                    status = "DRAFT";
                }
            }

            ObjectNode response = objectMapper.createObjectNode();
            response.put("status", status);

            if ("ACTIVE".equals(status) && draft.getCertificate() != null) {
                response.put("certificate", draft.getCertificate());
                response.put("rootCa", trustBundle);
            }

            return Response.ok(objectMapper.writeValueAsString(response))
                    .type(MediaType.APPLICATION_JSON_TYPE)
                    .build();

        } catch (Exception e) {
            logger.error("Failed to check certificate status", e);
            return errorResponse(Response.Status.INTERNAL_SERVER_ERROR,
                    "Failed to check status: " + e.getMessage());
        }
    }

    /**
     * Accept the fingerprint in the obvious spellings a client might produce and normalise to the
     * stored form ({@code SHA256:} + unpadded base64url). Without this, a caller that base64'd its
     * digest with the standard alphabet, or omitted the algorithm prefix, would get an
     * indistinguishable 404 rather than its status.
     */
    private static String normalizeFingerprint(String fingerprint) {
        String value = fingerprint.trim();
        if (value.regionMatches(true, 0, FINGERPRINT_PREFIX, 0, FINGERPRINT_PREFIX.length())) {
            value = value.substring(FINGERPRINT_PREFIX.length());
        }
        // base64 -> base64url, and drop any padding: the stored digest is unpadded base64url.
        value = value.replace('+', '-').replace('/', '_');
        while (value.endsWith("=")) {
            value = value.substring(0, value.length() - 1);
        }
        return FINGERPRINT_PREFIX + value;
    }

    /**
     * Download the realm's two public certificates as one PEM bundle: the P-256 realm server
     * certificate followed by the Ed25519 realm root CA. No auth required.
     *
     * <h2>Why this is public</h2>
     * Neither certificate is a secret. The root CA is a TRUST ANCHOR whose whole purpose is to be
     * distributed to anyone who needs to verify this realm, and the server certificate is presented
     * in the clear during every TLS handshake with it. Withholding either would prevent a peer from
     * doing exactly what the certificates exist to enable, and gate-keeping them would buy nothing —
     * anything obtainable by opening a TLS connection is not access control.
     *
     * <h2>All or nothing</h2>
     * Served only when BOTH certificates are committed and signed — a row that is issued
     * ({@code findCurrent} requires a stored server certificate and no revocation) AND has its root
     * CA stored. A bundle carrying a leaf with no anchor, or an anchor with no leaf, cannot complete
     * the job it was fetched for, so a partial realm returns 404 rather than half a bundle. Both
     * columns are written together at commit, so in practice they are present or absent as a pair.
     *
     * <h2>Format</h2>
     * Concatenated PEM, server certificate first then the root CA it chains to — the "fullchain"
     * ordering every TLS toolchain expects, so the response can be saved and handed straight to
     * {@code curl --cacert}, a Java truststore import, or an nginx {@code ssl_trusted_certificate}
     * without being split first. A caller that wants only the anchor takes the last block.
     */
    @GET
    @Path("realmCertificate")
    @Produces(PEM_MEDIA_TYPE)
    public Response getRealmCertificate() {
        try {
            RealmModel realm = session.getContext().getRealm();

            IgaRealmCertEntity realmCert = getRealmCertService().findCurrent(realm.getId());
            String serverCertificate = realmCert != null ? realmCert.getServerCertificate() : null;
            String rootCaCertificate = realmCert != null ? realmCert.getRootCaCertificate() : null;

            if (serverCertificate == null || serverCertificate.isBlank()
                    || rootCaCertificate == null || rootCaCertificate.isBlank()) {
                // Opaque on purpose only in the sense of being uniform: an un-issued realm and a
                // half-issued one are the same answer to a caller — there is nothing to install yet.
                return errorResponse(Response.Status.NOT_FOUND,
                        "Realm certificates have not been issued for this realm");
            }

            // Trailing newline after each block: some parsers require the END line to be terminated
            // before the next BEGIN, and toPem() does not emit one.
            String bundle = serverCertificate.stripTrailing() + "\n"
                    + rootCaCertificate.stripTrailing() + "\n";

            return Response.ok(bundle)
                    .type(PEM_MEDIA_TYPE)
                    .header("Content-Disposition",
                            "attachment; filename=\"" + pemFileName(realm.getName()) + "\"")
                    .build();

        } catch (Exception e) {
            logger.error("Failed to serve realm certificates", e);
            return errorResponse(Response.Status.INTERNAL_SERVER_ERROR,
                    "Failed to serve realm certificates: " + e.getMessage());
        }
    }

    /**
     * A filename safe to put in a {@code Content-Disposition} header. Realm names are already
     * constrained to {@code ^[A-Za-z0-9_-]{1,60}$} by the ORK, but this is a header a caller
     * influences, so anything outside that set is replaced rather than trusted — a quote or CRLF
     * here would be header injection.
     */
    private static String pemFileName(String realmName) {
        String safe = realmName == null ? "" : realmName.replaceAll("[^A-Za-z0-9_-]", "_");
        if (safe.isBlank()) {
            safe = "realm";
        }
        return safe + "-tide-realm.pem";
    }

    /**
     * Get the CRL (Certificate Revocation List) for this realm. No auth required.
     * Returns revoked server-cert instances.
     */
    @GET
    @Path("crl")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getCrl() {
        try {
            RealmModel realm = session.getContext().getRealm();
            EntityManager em = getEm();

            List<IgaServerCertDraftEntity> revoked = em.createQuery(
                            "SELECT s FROM IgaServerCertDraftEntity s WHERE s.realmId = :realmId AND s.revoked = true",
                            IgaServerCertDraftEntity.class)
                    .setParameter("realmId", realm.getId())
                    .getResultList();

            var revokedList = objectMapper.createArrayNode();
            for (var cert : revoked) {
                var entry = objectMapper.createObjectNode();
                entry.put("clientId", cert.getClientId());
                entry.put("fingerprint", cert.getPublicKeyFingerprint());
                entry.put("revokedAt", cert.getRevokedAt());
                revokedList.add(entry);
            }

            ObjectNode response = objectMapper.createObjectNode();
            response.put("realm", realm.getName());
            response.set("revoked", revokedList);
            response.put("updatedAt", System.currentTimeMillis());

            return Response.ok(objectMapper.writeValueAsString(response))
                    .type(MediaType.APPLICATION_JSON_TYPE)
                    .build();

        } catch (Exception e) {
            logger.error("Failed to generate CRL", e);
            return errorResponse(Response.Status.INTERNAL_SERVER_ERROR,
                    "Failed to generate CRL: " + e.getMessage());
        }
    }

    // --- Helpers ---

    /**
     * Map the sidecar + parent CR into a coarse public status string, mirroring the
     * source DraftStatus surface (DRAFT/ACTIVE/REVOKED + DENIED).
     */
    private static String deriveStatus(IgaServerCertDraftEntity draft) {
        if (draft.isRevoked()) {
            return "REVOKED";
        }
        if (draft.getCertificate() != null) {
            // An issued certificate that has aged out is EXPIRED, not ACTIVE — reporting ACTIVE
            // would have a workload keep presenting a certificate peers already reject.
            if (draft.getNotAfter() != null && draft.getNotAfter() <= System.currentTimeMillis()) {
                return "EXPIRED";
            }
            return "ACTIVE";
        }
        String crStatus = (draft.getChangeRequest() != null)
                ? draft.getChangeRequest().getStatus() : null;
        if ("DENIED".equals(crStatus) || "CANCELLED".equals(crStatus)) {
            return crStatus;
        }
        // PENDING parent CR (or no cert yet): still a draft awaiting approval/issuance.
        return "DRAFT";
    }

    /**
     * SHA-256 over the DER SubjectPublicKeyInfo — the standard SPKI fingerprint (as used for
     * public-key pinning, RFC 7469), so it is stable and comparable across key algorithms.
     *
     * <p>Does not swallow failures. This value is the duplicate-request dedup key as well as a
     * stored identifier, so a placeholder on error would let two unrelated keys collide onto the
     * same fingerprint and 409 each other. SHA-256 is mandatory on every conformant JVM, so the
     * only way this throws is a broken runtime, which should surface as a 500.
     */
    private String computeFingerprint(byte[] subjectPublicKeyInfoDer) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(subjectPublicKeyInfoDer);
            return FINGERPRINT_PREFIX
                    + Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable in this JVM", e);
        }
    }

    private Response errorResponse(Response.Status status, String message) {
        try {
            ObjectNode error = objectMapper.createObjectNode();
            error.put("error", message);
            return Response.status(status)
                    .entity(objectMapper.writeValueAsString(error))
                    .type(MediaType.APPLICATION_JSON_TYPE)
                    .build();
        } catch (Exception e) {
            return Response.status(status).build();
        }
    }
}
