package org.tidecloak.tide.iga.authorizer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.persistence.EntityManager;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.services.resources.admin.AdminAuth;
import org.midgard.Midgard;
import org.midgard.models.*;
import org.midgard.models.Policy.*;
import org.midgard.models.RequestExtensions.*;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessorFactory;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.base.iga.serveridentity.ServerCertBuilder;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.jpa.entities.*;
import org.tidecloak.jpa.entities.Licensing.LicenseHistoryEntity;
import org.tidecloak.jpa.entities.drafting.PolicyDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideRoleDraftEntity;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.shared.enums.WorkflowType;
import org.tidecloak.shared.enums.models.WorkflowParams;
import org.tidecloak.shared.models.SecretKeys;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessorFactoryProvider;
import org.tidecloak.base.iga.interfaces.ChangesetRequestAdapter;

import javax.xml.bind.DatatypeConverter;
import java.util.*;
import java.util.HexFormat;

import static org.tidecloak.base.iga.TideRequests.TideRoleRequests.commitRolePolicy;
import static org.tidecloak.base.iga.TideRequests.TideRoleRequests.getDraftRolePolicy;
import static org.tidecloak.base.iga.utils.BasicIGAUtils.isAuthorityAssignment;
import static org.tidecloak.base.iga.utils.BasicIGAUtils.sortAccessProof;

public class MultiAdmin implements Authorizer{

    @Override
    public Response signWithAuthorizer(ChangeSetRequest changeSet,
                                       EntityManager em,
                                       KeycloakSession session,
                                       RealmModel realm,
                                       List<?> draftEntities,
                                       AdminAuth auth,
                                       AuthorizerEntity authorizer,
                                       ComponentModel componentModel) throws Exception {

        ObjectMapper mapper = new ObjectMapper();

        ChangesetRequestEntity changesetRequestEntity = em.find(
                ChangesetRequestEntity.class,
                new ChangesetRequestEntity.Key(changeSet.getChangeSetId(), changeSet.getType())
        );

        if (changesetRequestEntity == null) {
            throw new BadRequestException("No change-set request entity found with this recordId and type "
                    + changeSet.getChangeSetId() + " , " + changeSet.getType());
        }

        // Check if the current user has already approved this request
        String currentUserId = auth.getUser().getId();
        boolean hasAlreadyApproved = changesetRequestEntity.getAdminAuthorizations()
                .stream()
                .anyMatch(authEntity -> authEntity.getUserId().equals(currentUserId) && authEntity.getIsApproval());

        if (hasAlreadyApproved) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("message", "You have already approved this request. Users can only approve a request once.");
            errorResponse.put("requiresApprovalPopup", false);
            String jsonString = mapper.writeValueAsString(errorResponse);
            return Response.status(Response.Status.BAD_REQUEST).entity(jsonString).type(MediaType.APPLICATION_JSON).build();
        }

        Object draftEntity = draftEntities.get(0);

        // --- SERVER_CERT: build the sCert:1 ModelRequest at sign time ---
        // The requestModel is NOT built at creation time (ServerIdentityResourceProvider),
        // so we must build it here so the enclave has something to process.
        if (changeSet.getType() == ChangeSetType.SERVER_CERT && changesetRequestEntity.getRequestModel() == null) {
            if (!(draftEntity instanceof ServerCertDraftEntity draft)) {
                throw new BadRequestException("Expected ServerCertDraftEntity for SERVER_CERT sign");
            }

            MultivaluedHashMap<String, String> config = componentModel.getConfig();

            String currentSecretKeys = config.getFirst("clientSecret");
            SecretKeys secretKeys = mapper.readValue(currentSecretKeys, SecretKeys.class);

            String gVRK = config.getFirst("gVRK");
            String gVRKCertificate = config.getFirst("gVRKCertificate");

            // Build X.509 TBS certificate (same as commitServerCert)
            String issuerCn = "tide.realm." + realm.getName();
            byte[] tbsCert = ServerCertBuilder.buildTbs(
                    draft.getPublicKey(),
                    draft.getClientId(),
                    realm.getName(),
                    issuerCn,
                    draft.getSpiffeId(),
                    draft.getRequestedLifetime()
            );

            // Build DynamicData JSON
            ObjectNode metadata = mapper.createObjectNode();
            metadata.put("type", "server-cert");
            metadata.put("realm", realm.getName());
            metadata.put("clientId", draft.getClientId());
            metadata.put("instanceId", draft.getInstanceId());
            metadata.put("spiffeId", draft.getSpiffeId());
            byte[] dynamicData = mapper.writeValueAsBytes(metadata);

            // Create ServerCert:1 ModelRequest with Policy:1 auth flow
            // Use longer expiry (24h) since this needs admin approval
            ModelRequest sCertReq = ModelRequest.New("ServerCert", "1", "Policy:1", tbsCert);
            sCertReq.SetCustomExpiry((System.currentTimeMillis() / 1000) + 86400);
            sCertReq.SetDynamicData(dynamicData);

            // Build signing settings for InitializeTideRequestWithVrk
            int threshold = Integer.parseInt(System.getenv("THRESHOLD_T"));
            int max = Integer.parseInt(System.getenv("THRESHOLD_N"));

            SignRequestSettingsMidgard settings = new SignRequestSettingsMidgard();
            settings.VVKId = config.getFirst("vvkId");
            settings.HomeOrkUrl = config.getFirst("systemHomeOrk");
            settings.PayerPublicKey = config.getFirst("payerPublic");
            settings.ObfuscatedVendorPublicKey = config.getFirst("obfGVVK");
            settings.VendorRotatingPrivateKey = secretKeys.activeVrk;
            settings.Threshold_T = threshold;
            settings.Threshold_N = max;

            byte[] authorizerBytes = HexFormat.of().parseHex(gVRK);
            byte[] certBytes = java.util.Base64.getDecoder().decode(gVRKCertificate);

            // Initialize the request via VRK: creates TideRequestInitialization:1, signs it,
            // and sets the creation authorization signature on the model
            ModelRequest.InitializeTideRequestWithVrk(sCertReq, settings, "ServerCert:1", authorizerBytes, certBytes);

            // --- Resolve admin policy to attach to policy model requests ---
            String policyRoleIdForCert = changeSet.getPolicyRoleId();
            TideRoleDraftEntity tideAdminForCert = BasicIGAUtils.resolvePolicyRole(em, session, policyRoleIdForCert);
            byte[] adminPolicyBytes = null;
            if (tideAdminForCert != null && tideAdminForCert.getInitCert() != null) {
                Policy adminPolicy = Policy.From(Base64.getDecoder().decode(tideAdminForCert.getInitCert()));
                adminPolicyBytes = adminPolicy.ToBytes();
            }

            // --- Build ServerCert:1 policy ModelRequest (Policy:1 auth, for enclave approval) ---
            String vvkIdForPolicy = config.getFirst("vvkId");

            PolicyParameters sCertPolicyParams = new PolicyParameters();
            sCertPolicyParams.put("realm", realm.getName());
            // Calculate threshold from active tide-realm-admin count
            RoleModel tideAdminRole = session.clients()
                    .getClientByClientId(realm, org.keycloak.models.Constants.REALM_MANAGEMENT_CLIENT_ID)
                    .getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
            int adminCount = ChangesetRequestAdapter.getNumberOfActiveAdmins(session, realm, tideAdminRole, em);
            int approvalThreshold = Math.max(1, (int) (0.7 * Math.max(1, adminCount)));
            sCertPolicyParams.put("threshold", approvalThreshold);
            sCertPolicyParams.put("role", org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
            sCertPolicyParams.put("resource", "realm-management");

            Policy sCertPolicy = new Policy(
                    "ServerCert:1",
                    new String[]{"ServerCert:1"},
                    vvkIdForPolicy,
                    ApprovalType.EXPLICIT,
                    ExecutionType.PUBLIC,
                    sCertPolicyParams
            );

            // Use Policy:1 auth (NOT VRK:1) to avoid VRK revocation
            PolicySignRequest sCertPolicySignReq = new PolicySignRequest(sCertPolicy.ToBytes(), "Policy:1");
            ModelRequest sCertPolicyModelReq = ModelRequest.New(
                    "Policy", "1", "Policy:1",
                    sCertPolicySignReq.GetDraft(),
                    sCertPolicy.ToBytes()
            );
            sCertPolicyModelReq.SetCustomExpiry((System.currentTimeMillis() / 1000) + 86400);
            // Initialize via VRK (sets creation auth) — this does NOT revoke the VRK
            ModelRequest.InitializeTideRequestWithVrk(sCertPolicyModelReq, settings, "Policy:1", authorizerBytes, certBytes);
            // Attach admin policy so the ORK can authorize this Policy:1 request
            if (adminPolicyBytes != null) sCertPolicyModelReq.SetPolicy(adminPolicyBytes);

            // Store as separate entity for enclave approval
            String sCertPolicyKey = changeSet.getChangeSetId() + "-scpo";
            ChangesetRequestEntity sCertPolicyEntity = new ChangesetRequestEntity();
            sCertPolicyEntity.setChangesetRequestId(sCertPolicyKey);
            sCertPolicyEntity.setChangesetType(ChangeSetType.POLICY);
            sCertPolicyEntity.setRequestModel(Base64.getEncoder().encodeToString(sCertPolicyModelReq.Encode()));
            sCertPolicyEntity.setTimestamp(System.currentTimeMillis());
            em.persist(sCertPolicyEntity);

            // Don't attach policy to sCert yet — policies get signed at commit time
            // Store sCert model without policy (policy attached after policies are VVK-signed)
            String encodedModel = Base64.getEncoder().encodeToString(sCertReq.Encode());
            changesetRequestEntity.setRequestModel(encodedModel);

            // --- Build VVK CA cert ModelRequest (for enclave approval) ---
            // The CA cert needs VVK signing (self-signed) so standard TLS verification works
            String gVVKForCa = config.getFirst("clientId");
            byte[] vvkPubBytesForCa = HexFormat.of().parseHex(gVVKForCa);
            byte[] caTbs = ServerCertBuilder.buildVvkCaTbs(vvkPubBytesForCa, realm.getName());

            ModelRequest caReq = ModelRequest.New("ServerCert", "1", "Policy:1", caTbs);
            caReq.SetCustomExpiry((System.currentTimeMillis() / 1000) + 86400);
            ModelRequest.InitializeTideRequestWithVrk(caReq, settings, "ServerCert:1", authorizerBytes, certBytes);
            // Attach admin policy for Policy:1 auth
            if (adminPolicyBytes != null) caReq.SetPolicy(adminPolicyBytes);
            // Set DynamicData for contract validation
            ObjectNode caMetadata = mapper.createObjectNode();
            caMetadata.put("type", "ca-cert");
            caMetadata.put("realm", realm.getName());
            caMetadata.put("clientId", "VVK-CA");
            caReq.SetDynamicData(mapper.writeValueAsBytes(caMetadata));

            String caKey = changeSet.getChangeSetId() + "-ca";
            ChangesetRequestEntity caEntity = new ChangesetRequestEntity();
            caEntity.setChangesetRequestId(caKey);
            caEntity.setChangesetType(ChangeSetType.SERVER_CERT);
            caEntity.setRequestModel(Base64.getEncoder().encodeToString(caReq.Encode()));
            caEntity.setTimestamp(System.currentTimeMillis());
            em.persist(caEntity);

            // --- Build public key signing request (VVK signs the raw public key) ---
            byte[] pubKeyBytes = Base64.getUrlDecoder().decode(draft.getPublicKey());
            ModelRequest pkReq = ModelRequest.New("ServerCert", "1", "Policy:1", pubKeyBytes);
            pkReq.SetCustomExpiry((System.currentTimeMillis() / 1000) + 86400);
            ModelRequest.InitializeTideRequestWithVrk(pkReq, settings, "ServerCert:1", authorizerBytes, certBytes);
            if (adminPolicyBytes != null) pkReq.SetPolicy(adminPolicyBytes);
            ObjectNode pkMetadata = mapper.createObjectNode();
            pkMetadata.put("type", "public-key");
            pkMetadata.put("realm", realm.getName());
            pkMetadata.put("clientId", draft.getClientId());
            pkMetadata.put("instanceId", draft.getInstanceId());
            pkReq.SetDynamicData(mapper.writeValueAsBytes(pkMetadata));

            String pkKey = changeSet.getChangeSetId() + "-pk";
            ChangesetRequestEntity pkEntity = new ChangesetRequestEntity();
            pkEntity.setChangesetRequestId(pkKey);
            pkEntity.setChangesetType(ChangeSetType.SERVER_CERT);
            pkEntity.setRequestModel(Base64.getEncoder().encodeToString(pkReq.Encode()));
            pkEntity.setTimestamp(System.currentTimeMillis());
            em.persist(pkEntity);

            em.flush();

            System.out.println("[MultiAdmin.sign] Built ServerCert:1 + policy + VVK CA cert + public key sig for enclave approval");
        }

        var authorityAssignment = BasicIGAUtils.authorityAssignment(session, draftEntity, em);
        System.out.println("[MultiAdmin.sign] changeSetId=" + changeSet.getChangeSetId() + " authorityAssignment=" + (authorityAssignment != null ? authorityAssignment.getChangesetRequestId() : "null"));

        // Set the VVK-signed custom policy on the stored requestModel
        // The policy in initCert should already be VVK-signed (done by frontend during policy commit, keylessh pattern)
        // Skip for SERVER_CERT — the ServerCert:1 policy was already set above during model construction.
        String policyRoleId = changeSet.getPolicyRoleId();
        TideRoleDraftEntity tideAdmin = BasicIGAUtils.resolvePolicyRole(em, session, policyRoleId);
        if (changeSet.getType() != ChangeSetType.SERVER_CERT && tideAdmin != null && tideAdmin.getInitCert() != null && changesetRequestEntity.getRequestModel() != null) {
            Policy policy = Policy.From(Base64.getDecoder().decode(tideAdmin.getInitCert()));

            // Set the signed policy on the model request
            ModelRequest req = ModelRequest.FromBytes(Base64.getDecoder().decode(changesetRequestEntity.getRequestModel()));
            req.SetPolicy(policy.ToBytes());

            // Inject dynamic data from the changeset request (executor role, previous UC, previous UC sig)
            // Contract's TryReadField expects raw [4-byte LE length][data] pairs without TideMemory version header.
            List<String> dynamicData = changeSet.getDynamicData();
            if (dynamicData != null && !dynamicData.isEmpty()) {
                // Calculate total size: each element = 4-byte length prefix + data bytes
                int totalSize = 0;
                byte[][] parts = new byte[dynamicData.size()][];
                for (int i = 0; i < dynamicData.size(); i++) {
                    String element = dynamicData.get(i);
                    parts[i] = (element != null) ? element.getBytes(java.nio.charset.StandardCharsets.UTF_8) : new byte[0];
                    totalSize += 4 + parts[i].length;
                }
                // Build raw [len][data] pairs — no version header
                byte[] raw = new byte[totalSize];
                int offset = 0;
                for (byte[] part : parts) {
                    raw[offset]     = (byte)(part.length & 0xFF);
                    raw[offset + 1] = (byte)((part.length >> 8) & 0xFF);
                    raw[offset + 2] = (byte)((part.length >> 16) & 0xFF);
                    raw[offset + 3] = (byte)((part.length >> 24) & 0xFF);
                    offset += 4;
                    System.arraycopy(part, 0, raw, offset, part.length);
                    offset += part.length;
                }
                req.SetDynamicData(raw);
            }

            changesetRequestEntity.setRequestModel(Base64.getEncoder().encodeToString(req.Encode()));
        }

        List<Map<String, Object>> responses = new ArrayList<>();

        // --- First ---
        Map<String, Object> firstResponse = new HashMap<>();
        firstResponse.put("message", "Opening Enclave to request approval.");
        firstResponse.put("changesetId", changesetRequestEntity.getChangesetRequestId());
        firstResponse.put("requiresApprovalPopup", true);
        firstResponse.put("changeSetDraftRequests", changesetRequestEntity.getRequestModel());
        firstResponse.put("actionType", changeSet.getActionType() != null ? changeSet.getActionType().name() : null);
        firstResponse.put("changeSetType", changeSet.getType() != null ? changeSet.getType().name() : null);
        responses.add(firstResponse);

        // --- SERVER_CERT policies: send to enclave for admin doken approval ---
        if (changeSet.getType() == ChangeSetType.SERVER_CERT) {
            // ServerCert:1 policy
            String sCertPolicyKey = changeSet.getChangeSetId() + "-scpo";
            ChangesetRequestEntity sCertPolicyReqEntity = em.find(
                    ChangesetRequestEntity.class,
                    new ChangesetRequestEntity.Key(sCertPolicyKey, ChangeSetType.POLICY)
            );
            if (sCertPolicyReqEntity != null) {
                Map<String, Object> sCertPolicyResponse = new HashMap<>();
                sCertPolicyResponse.put("message", "Opening Enclave to request approval.");
                sCertPolicyResponse.put("changesetId", sCertPolicyKey);
                sCertPolicyResponse.put("requiresApprovalPopup", true);
                sCertPolicyResponse.put("changeSetDraftRequests", sCertPolicyReqEntity.getRequestModel());
                sCertPolicyResponse.put("actionType", "NONE");
                sCertPolicyResponse.put("changeSetType", ChangeSetType.POLICY.name());
                responses.add(sCertPolicyResponse);
            }
            // VVK CA cert
            String caKey = changeSet.getChangeSetId() + "-ca";
            ChangesetRequestEntity caReqEntity = em.find(
                    ChangesetRequestEntity.class,
                    new ChangesetRequestEntity.Key(caKey, ChangeSetType.SERVER_CERT)
            );
            if (caReqEntity != null) {
                Map<String, Object> caResponse = new HashMap<>();
                caResponse.put("message", "Opening Enclave to request approval.");
                caResponse.put("changesetId", caKey);
                caResponse.put("requiresApprovalPopup", true);
                caResponse.put("changeSetDraftRequests", caReqEntity.getRequestModel());
                caResponse.put("actionType", "NONE");
                caResponse.put("changeSetType", ChangeSetType.SERVER_CERT.name());
                responses.add(caResponse);
            }
            // Public key signature
            String pkKey = changeSet.getChangeSetId() + "-pk";
            ChangesetRequestEntity pkReqEntity = em.find(
                    ChangesetRequestEntity.class,
                    new ChangesetRequestEntity.Key(pkKey, ChangeSetType.SERVER_CERT)
            );
            if (pkReqEntity != null) {
                Map<String, Object> pkResponse = new HashMap<>();
                pkResponse.put("message", "Opening Enclave to request approval.");
                pkResponse.put("changesetId", pkKey);
                pkResponse.put("requiresApprovalPopup", true);
                pkResponse.put("changeSetDraftRequests", pkReqEntity.getRequestModel());
                pkResponse.put("actionType", "NONE");
                pkResponse.put("changeSetType", ChangeSetType.SERVER_CERT.name());
                responses.add(pkResponse);
            }
        }

        // --- POLICY for authority assignments ---
        if (authorityAssignment != null) {
            System.out.println("[MultiAdmin.sign] Looking for POLICY entity with key=" + authorityAssignment.getChangesetRequestId());
            ChangesetRequestEntity policyReqEntity = em.find(
                    ChangesetRequestEntity.class,
                    new ChangesetRequestEntity.Key(authorityAssignment.getChangesetRequestId(), ChangeSetType.POLICY)
            );
            System.out.println("[MultiAdmin.sign] policyReqEntity found=" + (policyReqEntity != null));

            if (policyReqEntity != null) {
                // Do NOT call SetPolicy on the POLICY model here — send it as-is from
                // createRolePolicyDraft so the enclave can add dokens without corruption.
                // SetPolicy is called later at commit time (matching working individual flow).

                Map<String, Object> secondResponse = new HashMap<>();
                secondResponse.put("message", "Opening Enclave to request approval.");
                secondResponse.put("changesetId", authorityAssignment.getChangesetRequestId());
                secondResponse.put("requiresApprovalPopup", true);
                secondResponse.put("changeSetDraftRequests", policyReqEntity.getRequestModel());
                secondResponse.put("actionType", "NONE");
                secondResponse.put("changeSetType", ChangeSetType.POLICY.name());
                responses.add(secondResponse);
            }
        }

        // Serialize to JSON string
        String jsonString = mapper.writeValueAsString(responses);
        return Response.ok(jsonString, MediaType.APPLICATION_JSON).build();
    }

    @Override
    public Response commitWithAuthorizer(ChangeSetRequest changeSet, EntityManager em, KeycloakSession session, RealmModel realm, Object draftEntity, AdminAuth auth, AuthorizerEntity authorizer, ComponentModel componentModel) throws Exception {
        IdentityProviderModel tideIdp = session.identityProviders().getByAlias("tide");

        boolean isAuthorityAssignment = isAuthorityAssignment(session, draftEntity, em);

        ObjectMapper objectMapper = new ObjectMapper();
        var id = changeSet.getChangeSetId();
        var type = changeSet.getChangeSetId().contains("policy") ? ChangeSetType.POLICY : changeSet.getType();
        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(id, type));

        if (changesetRequestEntity == null){
            throw new BadRequestException("No change-set request entity found with this recordId and type " + changeSet.getChangeSetId() + " , " + changeSet.getType());
        }

        var config = componentModel.getConfig();
        String authorizerType = authorizer.getType();

        if(changeSet.getType().equals(ChangeSetType.REALM_LICENSING)){
            commitLicenseSettingsWithAuthorizer(session, em, changesetRequestEntity, authorizer);
            return Response.ok("Change set approved and committed with authorizer type:  " + authorizerType).build();
        }

        List<AccessProofDetailEntity> proofDetails = BasicIGAUtils.getAccessProofs(em, BasicIGAUtils.getEntityChangeRequestId(draftEntity), changeSet.getType());
        proofDetails.sort(Comparator.comparingLong(AccessProofDetailEntity::getCreatedTimestamp).reversed());

        List<AccessProofDetailEntity> orderedProofDetails = sortAccessProof(proofDetails);

        int threshold = Integer.parseInt(System.getenv("THRESHOLD_T"));
        int max = Integer.parseInt(System.getenv("THRESHOLD_N"));

        if ( threshold == 0 || max == 0){
            throw new RuntimeException("Env variables not set: THRESHOLD_T=" + threshold + ", THRESHOLD_N=" + max);
        }

        String currentSecretKeys = config.getFirst("clientSecret");
        SecretKeys secretKeys = objectMapper.readValue(currentSecretKeys, SecretKeys.class);

        SignRequestSettingsMidgard settings = new SignRequestSettingsMidgard();
        settings.VVKId = config.getFirst("vvkId");
        settings.HomeOrkUrl = config.getFirst("systemHomeOrk");
        settings.PayerPublicKey = config.getFirst("payerPublic");
        settings.ObfuscatedVendorPublicKey = config.getFirst("obfGVVK");
        settings.VendorRotatingPrivateKey = secretKeys.activeVrk;
        settings.Threshold_T = threshold;
        settings.Threshold_N = max;


        ModelRequest req = ModelRequest.FromBytes(Base64.getDecoder().decode(changesetRequestEntity.getRequestModel()));
        var authorityAssignment = BasicIGAUtils.authorityAssignment(session, draftEntity, em);

        if(authorityAssignment != null) {
            PolicyDraftEntity roleInitCert = getDraftRolePolicy(session, changeSet.getChangeSetId());
            if(roleInitCert == null) {
                throw new BadRequestException("Role Init Cert draft not found for changeSet, " + changeSet.getChangeSetId());
            }

            // Sign the UserContext first
            SignatureResponse response = Midgard.SignModel(settings, req);

            for ( int i = 0; i < orderedProofDetails.size() ; i++){
                    orderedProofDetails.get(i).setSignature(response.Signatures[i]);
            }

            // Skip the COMMIT workflow's pending-request recreation to prevent
            // a conflicting InitializeTideRequestWithVrk call for "Policy:1".
            session.setAttribute("skipPolicyDraftRecreation", Boolean.TRUE);

            // Sign POLICY model: load from DB (has dokens from enclave approval),
            // set the existing signed policy, and sign — matching the working individual flow.
            // signWithAuthorizer did NOT SetPolicy on the POLICY model, so the enclave
            // received the clean model from createRolePolicyDraft and added dokens.
            String policyKey = authorityAssignment.getChangesetRequestId();
            System.out.println("[MultiAdmin.commit] Looking for POLICY entity with key=" + policyKey);
            ChangesetRequestEntity policyChangesetReq = em.find(ChangesetRequestEntity.class,
                    new ChangesetRequestEntity.Key(policyKey, ChangeSetType.POLICY));
            if (policyChangesetReq == null) {
                throw new BadRequestException("POLICY ChangesetRequestEntity not found for key=" + policyKey);
            }
            String policyModelB64 = policyChangesetReq.getRequestModel();
            System.out.println("[MultiAdmin.commit] POLICY model length=" + (policyModelB64 != null ? policyModelB64.length() : "null")
                    + " adminAuths=" + policyChangesetReq.getAdminAuthorizations().size());
            ModelRequest pReq = ModelRequest.FromBytes(Base64.getDecoder().decode(policyModelB64));

            String policyRoleId = changeSet.getPolicyRoleId();
            TideRoleDraftEntity tideAdmin = BasicIGAUtils.resolvePolicyRole(em, session, policyRoleId);
            Policy existingPolicy = Policy.From(Base64.getDecoder().decode(tideAdmin.getInitCert()));
            pReq.SetPolicy(existingPolicy.ToBytes());

            SignatureResponse pResp = Midgard.SignModel(settings, pReq);

            // Defer the policy commit until after all UserContext models are signed.
            // Committing the policy now would update the ORK threshold mid-batch,
            // causing subsequent UC signs to fail with "not enough approvals".
            @SuppressWarnings("unchecked")
            List<Object[]> deferred = (List<Object[]>) session.getAttribute("deferredPolicyCommits", List.class);
            if (deferred == null) {
                deferred = new ArrayList<>();
                session.setAttribute("deferredPolicyCommits", deferred);
            }
            deferred.add(new Object[]{changeSet.getChangeSetId(), draftEntity, pResp.Signatures[0]});
        } else {
            // Policy was already set during signWithAuthorizer() and stored with the doken via addReview.
            // Do NOT call SetPolicy here — it would invalidate the doken embedded in the ModelRequest.
            SignatureResponse response = Midgard.SignModel(settings, req);

            for ( int i = 0; i < orderedProofDetails.size(); i++){
                orderedProofDetails.get(i).setSignature(response.Signatures[i]);
            }

        }

        ChangeSetProcessorFactory processorFactory = ChangeSetProcessorFactoryProvider.getFactory();// Initialize the processor factory

        WorkflowParams workflowParams = new WorkflowParams(null, false, null, changeSet.getType());
        processorFactory.getProcessor(changeSet.getType()).executeWorkflow(session, draftEntity, em, WorkflowType.COMMIT, workflowParams, null);

        if (isAuthorityAssignment) {
            if (authorizer.getType().equals(org.tidecloak.shared.Constants.TIDE_INITIAL_AUTHORIZER)){
                authorizer.setType(org.tidecloak.shared.Constants.TIDE_MULTI_ADMIN_AUTHORIZER);

            }
        }
        em.flush();
        return Response.ok("Change set approved and committed with authorizer type:  " + authorizerType).build();
    }

    private void commitLicenseSettingsWithAuthorizer(KeycloakSession session, EntityManager em, ChangesetRequestEntity changesetRequestEntity, AuthorizerEntity authorizer) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        ObjectMapper objectMapper = new ObjectMapper();
        RoleModel tideRole = session.clients().getClientByClientId(realm, Constants.REALM_MANAGEMENT_CLIENT_ID).getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
        RoleEntity role = em.getReference(RoleEntity.class, tideRole.getId());
        TideRoleDraftEntity tideRoleEntity = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class)
                .setParameter("role", role).getSingleResult();

        Policy policy = Policy.From(Base64.getDecoder().decode(tideRoleEntity.getInitCert()));

        ComponentModel componentModel = realm.getComponentsStream()
                .filter(x -> "tide-vendor-key".equals(x.getProviderId()))  // Use .equals for string comparison
                .findFirst()
                .orElse(null);

        if(componentModel == null) {
            throw new BadRequestException("There is no tide-vendor-key component set up for this realm, " + realm.getName());
        }

        MultivaluedHashMap<String, String> config = componentModel.getConfig();
        var req = ModelRequest.FromBytes(Base64.getDecoder().decode(changesetRequestEntity.getRequestModel()));

        req.SetPolicy(policy.ToBytes());
        req.SetCustomExpiry(changesetRequestEntity.getTimestamp() + 2628000); // expiry in 1 month

        int threshold = Integer.parseInt(System.getenv("THRESHOLD_T"));
        int max = Integer.parseInt(System.getenv("THRESHOLD_N"));

        if ( threshold == 0 || max == 0){
            throw new RuntimeException("Env variables not set: THRESHOLD_T=" + threshold + ", THRESHOLD_N=" + max);
        }

        String currentSecretKeys = config.getFirst("clientSecret");
        SecretKeys secretKeys = objectMapper.readValue(currentSecretKeys, SecretKeys.class);

        SignRequestSettingsMidgard settings = new SignRequestSettingsMidgard();
        settings.VVKId = config.getFirst("vvkId");
        settings.HomeOrkUrl = config.getFirst("systemHomeOrk");
        settings.PayerPublicKey = config.getFirst("payerPublic");
        settings.ObfuscatedVendorPublicKey = config.getFirst("obfGVVK");
        settings.VendorRotatingPrivateKey = secretKeys.activeVrk;
        settings.Threshold_T = threshold;
        settings.Threshold_N = max;

        SignatureResponse response = Midgard.SignModel(settings, req);

        // fetch latest history for this draft request (you already have this)
        LicenseHistoryEntity hist =
                em.createNamedQuery("LicenseHistory.findLatestByGvrk", LicenseHistoryEntity.class)
                        .setParameter("gvrk", changesetRequestEntity.getDraftRequest())
                        .setMaxResults(1)
                        .getResultStream()
                        .findFirst()
                        .orElse(null);

        // resolve which GVRK to use
        String draftReq = changesetRequestEntity.getDraftRequest();
        String pendingGvrk = config.getFirst("pendingGVRK"); // null if not set

        if (pendingGvrk.equals(draftReq)) {
            // pending entry matches this draft request – use it
            config.putSingle("pendingGVRKCertificate", response.Signatures[0]);
            componentModel.setConfig(config);
            realm.updateComponent(componentModel);
        } else if (hist != null && hist.getGVRK() != null) {
            hist.setGVRKCertificate(response.Signatures[0]);
        } else {
            // nothing pending and no history – handle as you prefer
            // e.g., throw, return Optional.empty(), or log & default
            throw new IllegalStateException("No GVRK found (no pending match and no history) for draft: " + draftReq);
        }

        LicensingDraftEntity licensingDraftEntity = em
                .createNamedQuery("LicensingDraft.findByChangeRequestId", LicensingDraftEntity.class)
                .setParameter("changeRequestId", changesetRequestEntity.getChangesetRequestId())
                .getSingleResult();

        licensingDraftEntity.setDraftStatus(DraftStatus.ACTIVE);
        licensingDraftEntity.setTimestamp(System.currentTimeMillis());
        em.remove(changesetRequestEntity);
    };
}
