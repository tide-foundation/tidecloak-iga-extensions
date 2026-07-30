package org.tidecloak.iga.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.RealmModel;
import org.keycloak.common.util.MultivaluedHashMap;

import org.midgard.Midgard;
import org.midgard.models.ModelRequest;
import org.midgard.models.Policy.Policy;
import org.midgard.models.SignRequestSettingsMidgard;
import org.midgard.models.SignatureResponse;
import org.tidecloak.iga.attestors.TideAttestor;
import org.tidecloak.iga.entities.IgaServerCertDraftEntity;

import java.util.Base64;
import java.util.HexFormat;

/**
 * Server-identity VVK signing seam, ported from the {@code add-server-identity} branch
 * ({@code MultiAdmin.signWithAuthorizer}'s SERVER_CERT branch + {@code TideIGACommitter.commitServerCert}).
 *
 * <h2>Why ServerCert does NOT ride the producer-unit carrier</h2>
 * The consolidated iga-core multiAdmin path frames a CR's draft as one or more typed
 * producer {@code AttestationUnit}s (user_role_mapping_set, etc.) the ORK re-derives from
 * live model state (see {@code TideAttestor.enumerateLiveCrUnits}). ServerCert signs three
 * OPAQUE blobs (the leaf X.509 TBS, the self-signed VVK-CA TBS, and the raw workload public
 * key) that have no producer envelope and are not re-derivable from model state. So ServerCert
 * keeps the SOURCE BRANCH's shape exactly: three separate {@code ServerCert:1}
 * {@link ModelRequest}s, each its own {@code Midgard.SignModel} call. The three carriers are
 * persisted across the approval window:
 * <ul>
 *   <li>the LEAF model on the parent CR's {@code REQUEST_MODEL} (where the enclave appends dokens);</li>
 *   <li>the CA + PK models on the {@code IgaServerCertDraftEntity} sidecar
 *       ({@code caRequestModel} / {@code pkRequestModel}) — the new-module home of the source
 *       {@code <csId>-ca} / {@code <csId>-pk} sibling carriers.</li>
 * </ul>
 *
 * <h2>Capability / firstAdmin fallback</h2>
 * On a non-real-signing-capable realm (dev/test) the phase-1 build skips the VRK creation-auth
 * (the carrier still round-trips for wiring). At commit, the CA is signed via the ORK network
 * when its enclave-approved carrier is present (multiAdmin) and falls back to a LOCAL
 * {@code Midgard.Sign(VRK, caTbs)} when it is not (firstAdmin), mirroring the source.
 */
public final class ServerCertSigner {

    private static final Logger logger = Logger.getLogger(ServerCertSigner.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String TIDE_VENDOR_KEY_PROVIDER_ID = "tide-vendor-key";
    private static final String CFG_GVRK = "gVRK";
    private static final String CFG_GVRK_CERTIFICATE = "gVRKCertificate";
    // The "clientId" config key stores the gVVK public key (source convention, kept as-is).
    private static final String CFG_GVVK = "clientId";
    private static final String SERVER_CERT_MODEL_ID = "ServerCert:1";
    private static final String SERVER_CERT_NAME = "ServerCert";
    private static final String SERVER_CERT_VERSION = "1";
    private static final String POLICY_AUTH_FLOW = "Policy:1";
    private static final long SERVER_CERT_EXPIRY_SECONDS = 86400L; // 24h, as in the source

    private ServerCertSigner() {
    }

    /** Resolve the realm's tide-vendor-key component (throws if absent). */
    public static ComponentModel requireVendorKey(RealmModel realm) {
        return realm.getComponentsStream()
                .filter(c -> TIDE_VENDOR_KEY_PROVIDER_ID.equals(c.getProviderId()))
                .findFirst()
                .orElseThrow(() -> new RuntimeException(
                        "IGA server-cert: realm " + realm.getName()
                                + " has no tide-vendor-key component (VVK not provisioned)"));
    }

    /**
     * PHASE 1 (sign-time). Build the three enclave-approval {@code ServerCert:1} ModelRequests
     * (leaf / CA / public key) and persist them: the leaf onto the CR's requestModel (returned),
     * the CA + PK onto the sidecar. Mirrors {@code MultiAdmin.signWithAuthorizer}'s SERVER_CERT
     * branch. Returns the Base64 leaf carrier (also the value the caller stores on
     * {@code cr.getRequestModel()}).
     *
     * @param adminPolicyBytes the M0 tide-realm-admin Policy bytes to embed (multiAdmin), or
     *                         {@code null} for a realm with no established admin policy
     *                         (firstAdmin / dev) — resolved by the caller, which holds the session.
     */
    public static String buildApprovalModels(RealmModel realm, IgaServerCertDraftEntity draft,
                                             byte[] adminPolicyBytes) {
        ComponentModel vendorKey = requireVendorKey(realm);
        MultivaluedHashMap<String, String> config = vendorKey.getConfig();
        if (config == null) {
            throw new RuntimeException("IGA server-cert: tide-vendor-key component has no config (realm "
                    + realm.getName() + ")");
        }
        try {
            boolean capable = TideAttestor.isRealSigningCapableRealm(realm);
            SignRequestSettingsMidgard settings = capable
                    ? TideAttestor.constructSignSettings(config) : null;
            byte[] authorizerBytes = null;
            byte[] certBytes = null;
            if (capable) {
                String gVRK = config.getFirst(CFG_GVRK);
                String gVRKCertificate = config.getFirst(CFG_GVRK_CERTIFICATE);
                if (gVRK == null || gVRK.isBlank() || gVRKCertificate == null || gVRKCertificate.isBlank()) {
                    throw new RuntimeException("IGA server-cert: tide-vendor-key component missing "
                            + "gVRK/gVRKCertificate authorizer material for realm " + realm.getName());
                }
                authorizerBytes = HexFormat.of().parseHex(gVRK);
                certBytes = Base64.getDecoder().decode(gVRKCertificate);
            }

            // adminPolicyBytes (caller-resolved): the M0 admin Policy embedded so the ORK's
            // PolicyAuthorizationFlow validates the collected dokens. Null on firstAdmin/dev.
            String issuerCn = "tide.realm." + realm.getName();

            // --- LEAF: ServerCert:1 over the X.509 TBS ---
            byte[] tbsCert = ServerCertBuilder.buildTbs(
                    draft.getPublicKey(),
                    draft.getClientId(),
                    realm.getName(),
                    issuerCn,
                    draft.getSpiffeId(),
                    draft.getRequestedLifetime() == null ? SERVER_CERT_EXPIRY_SECONDS : draft.getRequestedLifetime());
            ModelRequest leafReq = ModelRequest.New(SERVER_CERT_NAME, SERVER_CERT_VERSION, POLICY_AUTH_FLOW, tbsCert);
            leafReq.SetCustomExpiry(nowEpochSeconds() + SERVER_CERT_EXPIRY_SECONDS);
            leafReq.SetDynamicData(metadata("server-cert", realm.getName(), draft.getClientId(), draft.getInstanceId(), draft.getSpiffeId()));
            if (capable) {
                ModelRequest.InitializeTideRequestWithVrk(leafReq, settings, SERVER_CERT_MODEL_ID, authorizerBytes, certBytes);
            }
            attachPolicy(leafReq, adminPolicyBytes);
            String leafCarrier = Base64.getEncoder().encodeToString(leafReq.Encode());

            // --- CA: ServerCert:1 over the self-signed VVK-CA TBS ---
            byte[] gVvkBytes = HexFormat.of().parseHex(requireGvvk(config, realm));
            byte[] caTbs = ServerCertBuilder.buildVvkCaTbs(gVvkBytes, realm.getName());
            ModelRequest caReq = ModelRequest.New(SERVER_CERT_NAME, SERVER_CERT_VERSION, POLICY_AUTH_FLOW, caTbs);
            caReq.SetCustomExpiry(nowEpochSeconds() + SERVER_CERT_EXPIRY_SECONDS);
            if (capable) {
                ModelRequest.InitializeTideRequestWithVrk(caReq, settings, SERVER_CERT_MODEL_ID, authorizerBytes, certBytes);
            }
            attachPolicy(caReq, adminPolicyBytes);
            caReq.SetDynamicData(metadata("ca-cert", realm.getName(), "VVK-CA", null, null));
            draft.setCaRequestModel(Base64.getEncoder().encodeToString(caReq.Encode()));

            // --- PK: ServerCert:1 over the raw workload public key ---
            byte[] pubKeyBytes = Base64.getUrlDecoder().decode(draft.getPublicKey());
            ModelRequest pkReq = ModelRequest.New(SERVER_CERT_NAME, SERVER_CERT_VERSION, POLICY_AUTH_FLOW, pubKeyBytes);
            pkReq.SetCustomExpiry(nowEpochSeconds() + SERVER_CERT_EXPIRY_SECONDS);
            if (capable) {
                ModelRequest.InitializeTideRequestWithVrk(pkReq, settings, SERVER_CERT_MODEL_ID, authorizerBytes, certBytes);
            }
            attachPolicy(pkReq, adminPolicyBytes);
            pkReq.SetDynamicData(metadata("public-key", realm.getName(), draft.getClientId(), draft.getInstanceId(), null));
            draft.setPkRequestModel(Base64.getEncoder().encodeToString(pkReq.Encode()));

            logger.infof("IGA server-cert: built ServerCert:1 approval models for instance %s (realm %s, creation-auth=%s)",
                    draft.getInstanceId(), realm.getName(), capable ? "VRK" : "none(dev)");
            return leafCarrier;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("IGA server-cert: failed to build ServerCert:1 approval models for realm "
                    + realm.getName() + ": " + e.getMessage(), e);
        }
    }

    /** Result of a commit assembly: the issued leaf PEM, trust bundle PEM, and signed public key. */
    public static final class IssuedCert {
        public final String certificatePem;
        public final String trustBundlePem;
        public final String signedPublicKey; // base64(pubKey) + "." + base64(vvkSig), or null

        IssuedCert(String certificatePem, String trustBundlePem, String signedPublicKey) {
            this.certificatePem = certificatePem;
            this.trustBundlePem = trustBundlePem;
            this.signedPublicKey = signedPublicKey;
        }
    }

    /**
     * COMMIT (replay-time). Sign the three blobs via the ORKs (reusing the enclave-approved
     * carriers where present) and assemble the leaf cert + trust bundle + signed public key.
     * Mirrors {@code TideIGACommitter.commitServerCert}: ASSEMBLE FROM {@code req.GetDraft()}
     * (the actually-signed TBS) to avoid a TBS timestamp mismatch.
     */
    public static IssuedCert issue(RealmModel realm, IgaServerCertDraftEntity draft) {
        ComponentModel vendorKey = requireVendorKey(realm);
        MultivaluedHashMap<String, String> config = vendorKey.getConfig();
        if (config == null) {
            throw new RuntimeException("IGA server-cert: tide-vendor-key component has no config (realm "
                    + realm.getName() + ")");
        }
        try {
            SignRequestSettingsMidgard settings = TideAttestor.constructSignSettings(config);
            String gVRK = config.getFirst(CFG_GVRK);
            String gVRKCertificate = config.getFirst(CFG_GVRK_CERTIFICATE);

            String issuerCn = "tide.realm." + realm.getName();

            // --- LEAF: reuse the sign-time carrier (CR.requestModel) if present, else rebuild ---
            ModelRequest leafReq;
            String leafCarrier = draft.getChangeRequest() != null ? draft.getChangeRequest().getRequestModel() : null;
            if (leafCarrier != null && !leafCarrier.isBlank()) {
                leafReq = ModelRequest.FromBytes(Base64.getDecoder().decode(leafCarrier));
            } else {
                byte[] tbsCert = ServerCertBuilder.buildTbs(
                        draft.getPublicKey(), draft.getClientId(), realm.getName(), issuerCn,
                        draft.getSpiffeId(),
                        draft.getRequestedLifetime() == null ? SERVER_CERT_EXPIRY_SECONDS : draft.getRequestedLifetime());
                leafReq = ModelRequest.New(SERVER_CERT_NAME, SERVER_CERT_VERSION, POLICY_AUTH_FLOW, tbsCert);
                leafReq.SetCustomExpiry(nowEpochSeconds() + SERVER_CERT_EXPIRY_SECONDS);
                leafReq.SetDynamicData(metadata("server-cert", realm.getName(), draft.getClientId(), draft.getInstanceId(), draft.getSpiffeId()));
                ModelRequest.InitializeTideRequestWithVrk(leafReq, settings, SERVER_CERT_MODEL_ID,
                        HexFormat.of().parseHex(gVRK), Base64.getDecoder().decode(gVRKCertificate));
            }
            SignatureResponse leafResp = Midgard.SignModel(settings, leafReq);
            byte[] leafSig = decodeSig(leafResp.Signatures[0]);
            byte[] signedTbs = leafReq.GetDraft(); // assemble from what was actually signed
            String certPem = ServerCertBuilder.toPem(ServerCertBuilder.assembleCertificate(signedTbs, leafSig));

            // --- CA: reuse enclave-approved carrier (multiAdmin) OR local VRK fallback (firstAdmin) ---
            byte[] gVvkBytes = HexFormat.of().parseHex(requireGvvk(config, realm));
            byte[] caTbs = ServerCertBuilder.buildVvkCaTbs(gVvkBytes, realm.getName());
            byte[] caTbsForAssembly = caTbs;
            byte[] caSig;
            String caCarrier = draft.getCaRequestModel();
            if (caCarrier != null && !caCarrier.isBlank()) {
                ModelRequest caReq = ModelRequest.FromBytes(Base64.getDecoder().decode(caCarrier));
                caTbsForAssembly = caReq.GetDraft();
                SignatureResponse caResp = Midgard.SignModel(settings, caReq);
                caSig = decodeSig(caResp.Signatures[0]);
                logger.info("[SERVER_CERT] VVK CA cert signed via ORK network (reused from sign time)");
            } else {
                caSig = Midgard.Sign(settings.VendorRotatingPrivateKey, caTbs);
                logger.info("[SERVER_CERT] VVK CA cert signed with VRK (fallback)");
            }
            String trustBundle = ServerCertBuilder.toPem(
                    ServerCertBuilder.assembleCertificate(caTbsForAssembly, caSig));

            // --- PK: sign the raw public key (only when the enclave-approved carrier is present) ---
            String signedPublicKey = null;
            String pkCarrier = draft.getPkRequestModel();
            if (pkCarrier != null && !pkCarrier.isBlank()) {
                ModelRequest pkReq = ModelRequest.FromBytes(Base64.getDecoder().decode(pkCarrier));
                byte[] signedPubKeyDraft = pkReq.GetDraft();
                SignatureResponse pkResp = Midgard.SignModel(settings, pkReq);
                byte[] pkSig = decodeSig(pkResp.Signatures[0]);
                signedPublicKey = Base64.getEncoder().encodeToString(signedPubKeyDraft)
                        + "." + Base64.getEncoder().encodeToString(pkSig);
                logger.info("[SERVER_CERT] Public key signed via ORK network");
            }

            return new IssuedCert(certPem, trustBundle, signedPublicKey);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("IGA server-cert: VVK signing/assembly failed for instance "
                    + draft.getInstanceId() + " (realm " + realm.getName() + "): " + e.getMessage(), e);
        }
    }

    // --- helpers ---

    private static long nowEpochSeconds() {
        return System.currentTimeMillis() / 1000L;
    }

    private static void attachPolicy(ModelRequest req, byte[] adminPolicyBytes) {
        if (adminPolicyBytes != null) {
            req.SetPolicy(adminPolicyBytes);
        }
    }

    private static String requireGvvk(MultivaluedHashMap<String, String> config, RealmModel realm) {
        String gVVK = config.getFirst(CFG_GVVK);
        if (gVVK == null || gVVK.isBlank()) {
            throw new RuntimeException("IGA server-cert: tide-vendor-key component missing gVVK "
                    + "(clientId config key) for realm " + realm.getName());
        }
        return gVVK;
    }

    private static byte[] decodeSig(String sig) {
        // ORK returns base64url; normalize to standard base64 before decoding (source parity).
        return Base64.getDecoder().decode(sig.replace('-', '+').replace('_', '/'));
    }

    private static byte[] metadata(String type, String realmName, String clientId,
                                   String instanceId, String spiffeId) throws Exception {
        ObjectNode metadata = MAPPER.createObjectNode();
        metadata.put("type", type);
        metadata.put("realm", realmName);
        metadata.put("clientId", clientId);
        if (instanceId != null) metadata.put("instanceId", instanceId);
        if (spiffeId != null) metadata.put("spiffeId", spiffeId);
        return MAPPER.writeValueAsBytes(metadata);
    }
}
