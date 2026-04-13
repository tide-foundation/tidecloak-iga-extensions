package org.tidecloak.base.iga.serveridentity;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resource.RealmResourceProvider;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.ServerCertDraftEntity;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.UUID;

/**
 * Public realm resource provider for server identity certificate requests.
 * No authentication required - requests create pending IGA change requests
 * that must be approved by admin quorum before a certificate is issued.
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

    /**
     * Submit a server certificate request. No auth required.
     * Creates a pending IGA change request that admins must approve.
     */
    @POST
    @Path("request")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response requestCertificate(String body) {
        try {
            RealmModel realm = session.getContext().getRealm();
            var request = objectMapper.readTree(body);

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

            // Check for existing pending request for same instance
            EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
            try {
                ServerCertDraftEntity existing = em.createNamedQuery("getServerCertByInstanceId", ServerCertDraftEntity.class)
                        .setParameter("realmId", realm.getId())
                        .setParameter("instanceId", instanceId)
                        .getSingleResult();

                if (existing.getDraftStatus() == DraftStatus.DRAFT) {
                    return errorResponse(Response.Status.CONFLICT,
                            "A pending certificate request already exists for instance " + instanceId);
                }
            } catch (NoResultException ignored) {
                // No existing request - good
            }

            // Create draft entity
            String draftId = UUID.randomUUID().toString();
            String changeRequestId = UUID.randomUUID().toString();

            ServerCertDraftEntity draft = new ServerCertDraftEntity();
            draft.setId(draftId);
            draft.setChangeRequestId(changeRequestId);
            draft.setRealmId(realm.getId());
            draft.setClientId(clientId);
            draft.setInstanceId(instanceId);
            draft.setSpiffeId(spiffeId);
            draft.setPublicKey(publicKey);
            draft.setPublicKeyFingerprint(fingerprint);
            draft.setRequestedLifetime(requestedLifetime);
            draft.setDraftStatus(DraftStatus.DRAFT);
            draft.setTimestamp(System.currentTimeMillis());

            em.persist(draft);

            // Build a ModelRequest for enclave approval signing
            // The draft is the cert request metadata, the model is ServerCert:1
            String requestModelB64 = null;
            try {
                org.keycloak.component.ComponentModel componentModel = realm.getComponentsStream()
                        .filter(x -> "tide-vendor-key".equals(x.getProviderId()))
                        .findFirst()
                        .orElse(null);

                if (componentModel != null) {
                    org.keycloak.common.util.MultivaluedHashMap<String, String> config = componentModel.getConfig();
                    String currentSecretKeys = config.getFirst("clientSecret");
                    org.tidecloak.shared.models.SecretKeys secretKeys = objectMapper.readValue(
                            currentSecretKeys, org.tidecloak.shared.models.SecretKeys.class);

                    // Build TBS cert as draft
                    String issuerCn = "tide.realm." + realm.getName();
                    byte[] tbsCert = ServerCertBuilder.buildTbs(
                            publicKey, clientId, realm.getName(), issuerCn, spiffeId, requestedLifetime);

                    ObjectNode metadata = objectMapper.createObjectNode();
                    metadata.put("realm", realm.getName());
                    metadata.put("clientId", clientId);
                    metadata.put("instanceId", instanceId);
                    metadata.put("spiffeId", spiffeId);
                    metadata.put("requestedLifetime", requestedLifetime);

                    org.midgard.models.ModelRequest modelReq = org.midgard.models.ModelRequest.New(
                            "sCert", "1", "VRK:1", tbsCert);
                    modelReq.SetDynamicData(objectMapper.writeValueAsBytes(metadata));

                    String gVRK = config.getFirst("gVRK");
                    String gVRKCertificate = config.getFirst("gVRKCertificate");

                    modelReq.SetAuthorization(org.midgard.Midgard.SignWithVrk(
                            modelReq.GetDataToAuthorize(), secretKeys.activeVrk));
                    modelReq.SetAuthorizer(java.util.HexFormat.of().parseHex(gVRK));
                    modelReq.SetAuthorizerCertificate(java.util.Base64.getDecoder().decode(gVRKCertificate));

                    requestModelB64 = java.util.Base64.getEncoder().encodeToString(modelReq.Encode());
                }
            } catch (Exception e) {
                logger.warn("Could not build model request for SERVER_CERT enclave approval", e);
            }

            // Create changeset request entity (links to IGA approval flow)
            ChangesetRequestEntity changeRequest = new ChangesetRequestEntity();
            changeRequest.setChangesetRequestId(changeRequestId);
            changeRequest.setChangesetType(ChangeSetType.SERVER_CERT);
            changeRequest.setDraftRequest(objectMapper.writeValueAsString(request));
            changeRequest.setRequestModel(requestModelB64);
            changeRequest.setTimestamp(System.currentTimeMillis());
            changeRequest.setRequestedBy("server:" + instanceId);
            changeRequest.setRequestedByUsername(clientId + "/" + instanceId);

            em.persist(changeRequest);
            em.flush();

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

        } catch (Exception e) {
            logger.error("Failed to create server certificate request", e);
            return errorResponse(Response.Status.INTERNAL_SERVER_ERROR,
                    "Failed to create certificate request: " + e.getMessage());
        }
    }

    /**
     * Check the status of a certificate request. No auth required.
     * Returns the signed certificate if approved.
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
            EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

            ServerCertDraftEntity draft;
            try {
                draft = em.createNamedQuery("getServerCertDraftByRequestId", ServerCertDraftEntity.class)
                        .setParameter("requestId", changeSetId)
                        .getSingleResult();
            } catch (NoResultException e) {
                return errorResponse(Response.Status.NOT_FOUND, "Certificate request not found");
            }

            ObjectNode response = objectMapper.createObjectNode();
            response.put("status", draft.getDraftStatus().name());
            response.put("spiffeId", draft.getSpiffeId());
            response.put("fingerprint", draft.getPublicKeyFingerprint());

            if (draft.getDraftStatus() == DraftStatus.ACTIVE && draft.getCertificate() != null) {
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
     * Get the CRL (Certificate Revocation List) for this realm.
     * Returns revoked server certificate serial numbers.
     */
    @GET
    @Path("crl")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getCrl() {
        try {
            RealmModel realm = session.getContext().getRealm();
            EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

            var revoked = em.createQuery(
                            "SELECT s FROM ServerCertDraftEntity s WHERE s.realmId = :realmId AND s.revoked = true",
                            ServerCertDraftEntity.class)
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

    /**
     * Renew a server certificate. Requires the current cert's instanceId and a public key.
     * Auto-approves if an ACTIVE cert exists for this instance (no quorum needed).
     * Triggers VVK signing and returns the new cert directly.
     */
    @POST
    @Path("renew")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response renewCertificate(String body) {
        try {
            RealmModel realm = session.getContext().getRealm();
            var request = objectMapper.readTree(body);

            String instanceId = getRequiredField(request, "instanceId");
            String publicKey = getRequiredField(request, "publicKey");
            long requestedLifetime = request.has("requestedLifetime")
                    ? request.get("requestedLifetime").asLong(86400)
                    : 86400;

            EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

            // Find existing ACTIVE cert for this instance
            ServerCertDraftEntity existing;
            try {
                existing = em.createNamedQuery("getApprovedServerCertByClientAndInstance", ServerCertDraftEntity.class)
                        .setParameter("realmId", realm.getId())
                        .setParameter("clientId", existing_clientId(em, realm, instanceId))
                        .setParameter("instanceId", instanceId)
                        .setParameter("draftStatus", org.tidecloak.shared.enums.DraftStatus.ACTIVE)
                        .getSingleResult();
            } catch (NoResultException e) {
                return errorResponse(Response.Status.FORBIDDEN,
                        "No active certificate found for instance " + instanceId + ". Initial cert requires admin quorum.");
            }

            if (existing.getRevoked()) {
                return errorResponse(Response.Status.FORBIDDEN,
                        "Certificate for instance " + instanceId + " has been revoked. Request a new cert.");
            }

            // Auto-renew: update the existing record with new key and re-sign
            String fingerprint = computeFingerprint(publicKey);
            existing.setPublicKey(publicKey);
            existing.setPublicKeyFingerprint(fingerprint);
            existing.setRequestedLifetime(requestedLifetime);
            existing.setTimestamp(System.currentTimeMillis());

            // Trigger VVK signing via the commit handler
            // Build the TBS and sign it
            org.keycloak.component.ComponentModel componentModel = realm.getComponentsStream()
                    .filter(x -> "tide-vendor-key".equals(x.getProviderId()))
                    .findFirst()
                    .orElseThrow(() -> new RuntimeException("No tide-vendor-key component found"));

            org.keycloak.common.util.MultivaluedHashMap<String, String> config = componentModel.getConfig();
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();

            String currentSecretKeys = config.getFirst("clientSecret");
            org.tidecloak.shared.models.SecretKeys secretKeys = mapper.readValue(currentSecretKeys, org.tidecloak.shared.models.SecretKeys.class);

            org.midgard.models.SignRequestSettingsMidgard settings = new org.midgard.models.SignRequestSettingsMidgard();
            settings.VVKId = config.getFirst("vvkId");
            settings.HomeOrkUrl = config.getFirst("systemHomeOrk");
            settings.PayerPublicKey = config.getFirst("payerPublic");
            settings.ObfuscatedVendorPublicKey = config.getFirst("obfGVVK");
            settings.VendorRotatingPrivateKey = secretKeys.activeVrk;
            settings.Threshold_T = Integer.parseInt(System.getenv("THRESHOLD_T"));
            settings.Threshold_N = Integer.parseInt(System.getenv("THRESHOLD_N"));

            String gVRK = config.getFirst("gVRK");
            String gVRKCertificate = config.getFirst("gVRKCertificate");

            String issuerCn = "tide.realm." + realm.getName();
            byte[] tbsCert = ServerCertBuilder.buildTbs(
                    publicKey, existing.getClientId(), realm.getName(),
                    issuerCn, existing.getSpiffeId(), requestedLifetime);

            com.fasterxml.jackson.databind.node.ObjectNode metadata = mapper.createObjectNode();
            metadata.put("realm", realm.getName());
            metadata.put("clientId", existing.getClientId());
            metadata.put("instanceId", instanceId);
            metadata.put("spiffeId", existing.getSpiffeId());
            metadata.put("requestedLifetime", requestedLifetime);

            org.midgard.models.ModelRequest req = org.midgard.models.ModelRequest.New("sCert", "1", "VRK:1", tbsCert);
            req.SetDynamicData(mapper.writeValueAsBytes(metadata));
            req.SetAuthorization(org.midgard.Midgard.SignWithVrk(req.GetDataToAuthorize(), settings.VendorRotatingPrivateKey));
            req.SetAuthorizer(java.util.HexFormat.of().parseHex(gVRK));
            req.SetAuthorizerCertificate(java.util.Base64.getDecoder().decode(gVRKCertificate));

            org.midgard.models.SignatureResponse signatureResponse = org.midgard.Midgard.SignModel(settings, req);

            byte[] signatureBytes = java.util.Base64.getDecoder().decode(
                    signatureResponse.Signatures[0].replace('-', '+').replace('_', '/'));
            byte[] fullCert = ServerCertBuilder.assembleCertificate(tbsCert, signatureBytes);
            String certPem = ServerCertBuilder.toPem(fullCert);

            // Build trust bundle (self-signed VVK CA cert)
            byte[] vvkPubBytes = java.util.HexFormat.of().parseHex(gVRK);
            byte[] caTbs = ServerCertBuilder.buildVvkCaTbs(vvkPubBytes, realm.getName());
            org.midgard.models.ModelRequest caReq = org.midgard.models.ModelRequest.New("sCert", "1", "VRK:1", caTbs);
            com.fasterxml.jackson.databind.node.ObjectNode caMeta = mapper.createObjectNode();
            caMeta.put("realm", realm.getName());
            caMeta.put("clientId", "VVK-CA");
            caMeta.put("instanceId", "trust-bundle");
            caMeta.put("spiffeId", "spiffe://tide.realm." + realm.getName());
            caMeta.put("requestedLifetime", 315360000L);
            caReq.SetDynamicData(mapper.writeValueAsBytes(caMeta));
            caReq.SetAuthorization(org.midgard.Midgard.SignWithVrk(caReq.GetDataToAuthorize(), settings.VendorRotatingPrivateKey));
            caReq.SetAuthorizer(java.util.HexFormat.of().parseHex(gVRK));
            caReq.SetAuthorizerCertificate(java.util.Base64.getDecoder().decode(gVRKCertificate));
            org.midgard.models.SignatureResponse caSignResp = org.midgard.Midgard.SignModel(settings, caReq);
            byte[] caSignBytes = java.util.Base64.getDecoder().decode(
                    caSignResp.Signatures[0].replace('-', '+').replace('_', '/'));
            String trustBundle = ServerCertBuilder.buildVvkCaCert(vvkPubBytes, realm.getName(), caSignBytes);

            existing.setCertificate(certPem);
            existing.setTrustBundle(trustBundle);
            em.merge(existing);
            em.flush();

            ObjectNode response = objectMapper.createObjectNode();
            response.put("status", "RENEWED");
            response.put("certificate", certPem);
            response.put("trustBundle", trustBundle);
            response.put("spiffeId", existing.getSpiffeId());

            return Response.ok(objectMapper.writeValueAsString(response))
                    .type(MediaType.APPLICATION_JSON_TYPE)
                    .build();

        } catch (Exception e) {
            logger.error("Failed to renew server certificate", e);
            return errorResponse(Response.Status.INTERNAL_SERVER_ERROR,
                    "Failed to renew certificate: " + e.getMessage());
        }
    }

    private String existing_clientId(EntityManager em, RealmModel realm, String instanceId) {
        try {
            ServerCertDraftEntity cert = em.createNamedQuery("getServerCertByInstanceId", ServerCertDraftEntity.class)
                    .setParameter("realmId", realm.getId())
                    .setParameter("instanceId", instanceId)
                    .getSingleResult();
            return cert.getClientId();
        } catch (NoResultException e) {
            return "";
        }
    }

    // --- Helpers ---

    private String getRequiredField(com.fasterxml.jackson.databind.JsonNode node, String field) {
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
