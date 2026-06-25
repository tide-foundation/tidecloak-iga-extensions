package org.tidecloak.iga.rest;

import com.fasterxml.jackson.databind.JsonNode;
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
import org.tidecloak.iga.entities.IgaServerCertDraftEntity;
import org.tidecloak.iga.providers.IgaChangeRequestService;
import org.tidecloak.iga.providers.IgaServerCertDraftService;
import org.tidecloak.iga.providers.IgaServerCertEnrollmentTokenService;

import jakarta.persistence.EntityManager;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;

/**
 * Public realm resource provider for workload server-identity certificate requests.
 * No authentication required: a request files a pending IGA change request
 * (action_type = REQUEST_SERVER_CERT) plus its IGA_SERVER_CERT_DRAFT sidecar, which
 * must be approved by the admin quorum (multiAdmin) or the firstAdmin VRK before a
 * certificate is issued. Issuance (VVK signing + cert assembly) runs at CR commit in
 * {@code IgaReplayDispatcher.replayRequestServerCert}.
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
     * Submit a server certificate request. No auth required.
     * Files a pending IGA change request (REQUEST_SERVER_CERT) the admins must approve.
     */
    @POST
    @Path("request")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response requestCertificate(String body) {
        try {
            RealmModel realm = session.getContext().getRealm();
            JsonNode request = objectMapper.readTree(body);

            // Validate required fields
            String clientId = getRequiredField(request, "clientId");
            String publicKey = getRequiredField(request, "publicKey");
            String instanceId = getRequiredField(request, "instanceId");
            long requestedLifetime = request.has("requestedLifetime")
                    ? request.get("requestedLifetime").asLong(86400)
                    : 86400;

            // Validate client exists in realm
            ClientModel client = realm.getClientsStream()
                    .filter(c -> c.getClientId().equals(clientId))
                    .findFirst()
                    .orElse(null);

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
            // The bound client must be opted-in to server-identity enrollment. Opaque on failure.
            if (!"true".equals(client.getAttribute("tide.server-identity.enabled"))) {
                return errorResponse(Response.Status.FORBIDDEN, "Invalid or expired enrollment token");
            }
            // Non-consuming validity gate. The actual single-use consume happens AFTER the CR is
            // created, so a token is not burned on a request that fails to file. Opaque on failure
            // (no oracle distinguishing not-found / expired / consumed / clientId-mismatch).
            IgaServerCertEnrollmentTokenService tokenService = getEnrollmentTokenService();
            if (!tokenService.isValid(realm.getId(), clientId, enrollmentToken)) {
                return errorResponse(Response.Status.FORBIDDEN, "Invalid or expired enrollment token");
            }

            // Validate lifetime
            if (requestedLifetime <= 0 || requestedLifetime > 86400) {
                return errorResponse(Response.Status.BAD_REQUEST,
                        "requestedLifetime must be between 1 and 86400 seconds");
            }

            // Build SPIFFE ID
            String spiffeId = "spiffe://tide.realm." + realm.getName()
                    + "/client/" + clientId
                    + "/instance/" + instanceId;

            // Compute public key fingerprint
            String fingerprint = computeFingerprint(publicKey);

            // Check for an existing pending (un-issued, non-revoked) request for the same
            // instance. The consolidated model has no DRAFT status enum on the sidecar — a
            // "pending" request is one whose parent CR is still PENDING (cert not yet issued).
            IgaServerCertDraftService service = getService();
            List<IgaServerCertDraftEntity> existingEntries =
                    service.findByRealmAndInstance(realm.getId(), instanceId);
            for (IgaServerCertDraftEntity existing : existingEntries) {
                boolean pending = existing.getCertificate() == null
                        && !existing.isRevoked()
                        && existing.getChangeRequest() != null
                        && "PENDING".equals(existing.getChangeRequest().getStatus());
                if (pending) {
                    return errorResponse(Response.Status.CONFLICT,
                            "A pending certificate request already exists for instance " + instanceId);
                }
            }

            // File the REQUEST_SERVER_CERT change request + sidecar. requestModel is left
            // null on the CR; the ServerCert:1 approval models are built at sign time.
            IgaServerCertDraftEntity created = service.createRequest(
                    realm,
                    instanceId,            // requestedBy: the workload instance (no admin user)
                    clientId,
                    instanceId,
                    spiffeId,
                    publicKey,
                    fingerprint,
                    requestedLifetime,
                    null);

            // Atomic single-use consume AFTER the CR is filed. The conditional UPDATE is the
            // TOCTOU guard: under a concurrent double-present exactly one caller consumes the
            // row. If it returns false here, a racing request already consumed it -> 403 opaque.
            if (!tokenService.consumeIfValid(realm.getId(), clientId, enrollmentToken)) {
                return errorResponse(Response.Status.FORBIDDEN, "Invalid or expired enrollment token");
            }

            String changeRequestId = created.getChangeRequest() != null
                    ? created.getChangeRequest().getId()
                    : null;

            // Build response
            ObjectNode response = objectMapper.createObjectNode();
            response.put("changeSetId", changeRequestId);
            response.put("status", "PENDING");
            response.put("spiffeId", spiffeId);
            response.put("fingerprint", fingerprint);

            return Response.status(Response.Status.CREATED)
                    .entity(objectMapper.writeValueAsString(response))
                    .type(MediaType.APPLICATION_JSON_TYPE)
                    .build();

        } catch (IllegalArgumentException e) {
            return errorResponse(Response.Status.BAD_REQUEST, e.getMessage());
        } catch (Exception e) {
            logger.error("Failed to create server certificate request", e);
            return errorResponse(Response.Status.INTERNAL_SERVER_ERROR,
                    "Failed to create certificate request: " + e.getMessage());
        }
    }

    /**
     * Check the status of a certificate request by its change-request id. No auth required.
     * Returns the signed certificate + trust bundle once the CR has been committed and the
     * cert issued.
     */
    @GET
    @Path("status")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getStatus(@QueryParam("changeSetId") String changeSetId) {
        try {
            if (changeSetId == null || changeSetId.isEmpty()) {
                return errorResponse(Response.Status.BAD_REQUEST, "Missing changeSetId parameter");
            }

            RealmModel realm = session.getContext().getRealm();
            EntityManager em = getEm();

            List<IgaServerCertDraftEntity> drafts = em.createNamedQuery(
                            "IgaServerCertDraft.findByChangeRequestId", IgaServerCertDraftEntity.class)
                    .setParameter("crId", changeSetId)
                    .getResultList();

            IgaServerCertDraftEntity draft = drafts.isEmpty() ? null : drafts.get(0);
            if (draft == null || !realm.getId().equals(draft.getRealmId())) {
                return errorResponse(Response.Status.NOT_FOUND, "Certificate request not found");
            }

            // Derive a status string from the sidecar + parent CR state.
            String status = deriveStatus(draft);

            ObjectNode response = objectMapper.createObjectNode();
            response.put("status", status);
            response.put("spiffeId", draft.getSpiffeId());
            response.put("fingerprint", draft.getPublicKeyFingerprint());

            if ("ACTIVE".equals(status) && draft.getCertificate() != null) {
                response.put("certificate", draft.getCertificate());
                response.put("trustBundle", draft.getTrustBundle());
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
                entry.put("instanceId", cert.getInstanceId());
                entry.put("spiffeId", cert.getSpiffeId());
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

    private String getRequiredField(JsonNode node, String field) {
        if (!node.has(field) || node.get(field).asText().isEmpty()) {
            throw new IllegalArgumentException("Missing required field: " + field);
        }
        return node.get(field).asText();
    }

    private String computeFingerprint(String publicKeyBase64) {
        try {
            byte[] keyBytes = Base64.getUrlDecoder().decode(publicKeyBase64);
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(keyBytes);
            return "SHA256:" + Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            return "SHA256:unknown";
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
