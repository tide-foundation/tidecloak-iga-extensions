package org.tidecloak.tide.iga.authorizer;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import jakarta.persistence.EntityManager;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.core.Response;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.services.resources.admin.AdminAuth;
import org.midgard.Serialization.Tools;
import org.midgard.Midgard;
import org.midgard.models.*;
import org.midgard.models.Policy.*;
import org.midgard.models.RequestExtensions.UserContextSignRequest;
import org.midgard.models.UserContext.UserContext;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessorFactory;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.base.iga.utils.LicenseHistory;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.AuthorizerEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.Licensing.LicenseHistoryEntity;
import org.tidecloak.jpa.entities.LicensingDraftEntity;
import org.tidecloak.jpa.entities.drafting.PolicyDraftEntity;
import org.tidecloak.jpa.entities.drafting.RoleInitializerCertificateDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideRoleDraftEntity;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.shared.enums.WorkflowType;
import org.tidecloak.shared.enums.models.WorkflowParams;
import org.tidecloak.shared.models.SecretKeys;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessorFactoryProvider;
import org.tidecloak.tide.iga.utils.IGAUtils;

import javax.xml.bind.DatatypeConverter;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

import static org.tidecloak.base.iga.TideRequests.TideRoleRequests.commitRolePolicy;
import static org.tidecloak.base.iga.TideRequests.TideRoleRequests.getDraftRolePolicy;
import static org.tidecloak.base.iga.utils.BasicIGAUtils.isAuthorityAssignment;
import static org.tidecloak.base.iga.utils.BasicIGAUtils.sortAccessProof;

public class MultiAdmin implements Authorizer{

    @Override
    public Response signWithAuthorizer(ChangeSetRequest changeSet, EntityManager em, KeycloakSession session, RealmModel realm, List<?> draftEntities, AdminAuth auth, AuthorizerEntity authorizer, ComponentModel componentModel) throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(changeSet.getChangeSetId(), changeSet.getType()));

        if (changesetRequestEntity == null) {
            throw new BadRequestException("No change-set request entity found with this recordId and type " + changeSet.getChangeSetId() + " , " + changeSet.getType());
        }
        Object draftEntity = draftEntities.get(0);

        var authorityAssignment = BasicIGAUtils.authorityAssignment(session, draftEntity, em);

        Map<String, String> response = new HashMap<>();
        response.put("message", "Opening Enclave to request approval.");
        response.put("changesetId", changesetRequestEntity.getChangesetRequestId());
        response.put("changeSetDraftRequests", changesetRequestEntity.getDraftRequest());
        response.put("requiresApprovalPopup", "true");
        List<String> request = new ArrayList<>(List.of(changesetRequestEntity.getRequestModel()));
        if(authorityAssignment != null){
            var id = authorityAssignment.getChangesetRequestId();
            PolicyDraftEntity policyDraftEntity = em.createNamedQuery("getPolicyByChangeSetId", PolicyDraftEntity.class).setParameter("changesetId", id).getSingleResult();
            ChangesetRequestEntity policyReqEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(policyDraftEntity.getId(), ChangeSetType.POLICY));
            request.add(policyReqEntity.getRequestModel());
        }
        response.put("changeSetRequests", objectMapper.writeValueAsString(request));



        return Response.ok(objectMapper.writeValueAsString(response)).build();
    }

    @Override
    public Response commitWithAuthorizer(ChangeSetRequest changeSet, EntityManager em, KeycloakSession session, RealmModel realm, Object draftEntity, AdminAuth auth, AuthorizerEntity authorizer, ComponentModel componentModel) throws Exception {
        IdentityProviderModel tideIdp = session.identityProviders().getByAlias("tide");
        ObjectMapper objectMapper = new ObjectMapper();
        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(changeSet.getChangeSetId(), changeSet.getType()));

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

        boolean isAuthorityAssignment = isAuthorityAssignment(session, draftEntity, em);

        if(isAuthorityAssignment) {
            PolicyDraftEntity roleInitCert = getDraftRolePolicy(session, changeSet.getChangeSetId());
            if(roleInitCert == null) {
                throw new BadRequestException("Role Init Cert draft not found for changeSet, " + changeSet.getChangeSetId());
            }
            SignatureResponse response = Midgard.SignModel(settings, req);

            for ( int i = 0; i < orderedProofDetails.size() ; i++){
                orderedProofDetails.get(i).setSignature(response.Signatures[i]);
            }
            commitRolePolicy(session, changeSet.getChangeSetId(), draftEntity, response.Signatures[response.Signatures.length - 1]); // get the last one

        } else {
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

        Policy policy = new Policy(Base64.getDecoder().decode(tideRoleEntity.getInitCert()));

        ComponentModel componentModel = realm.getComponentsStream()
                .filter(x -> "tide-vendor-key".equals(x.getProviderId()))  // Use .equals for string comparison
                .findFirst()
                .orElse(null);

        if(componentModel == null) {
            throw new BadRequestException("There is no tide-vendor-key component set up for this realm, " + realm.getName());
        }

        MultivaluedHashMap<String, String> config = componentModel.getConfig();
        ModelRequest req =  ModelRequest.New("RotateVRK", "1", "Admin:1", DatatypeConverter.parseHexBinary(changesetRequestEntity.getDraftRequest()));

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
