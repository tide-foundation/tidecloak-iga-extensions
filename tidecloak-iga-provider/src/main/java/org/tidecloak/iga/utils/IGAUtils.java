package org.tidecloak.iga.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.midgard.Midgard;
import org.midgard.models.InitializerCertificateModel.InitializerCertifcate;
import org.midgard.models.RequestExtensions.UserContextSignRequest;
import org.midgard.models.SignRequestSettingsMidgard;
import org.midgard.models.SignatureResponse;
import org.midgard.models.UserContext.UserContext;
import org.tidecloak.iga.changesetprocessors.ChangeSetProcessorFactory;
import org.tidecloak.shared.Constants;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.AuthorizerEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.drafting.TideClientDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideCompositeRoleMappingDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideRoleDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.shared.enums.WorkflowType;
import org.tidecloak.shared.enums.models.WorkflowParams;
import org.tidecloak.shared.models.SecretKeys;

import java.util.*;
import java.util.stream.Collectors;

import static org.tidecloak.iga.interfaces.ChangesetRequestAdapter.getChangeSetStatus;

public class IGAUtils {
    public static boolean isIGAEnabled(RealmModel realm) {
        String isIGAEnabled = realm.getAttribute("isIGAEnabled");
        return isIGAEnabled != null && !isIGAEnabled.isEmpty() && isIGAEnabled.equalsIgnoreCase("true");
    }

    public static List<AccessProofDetailEntity> getAccessProofs(EntityManager em, String recordId) {
        return em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                .setParameter("recordId", recordId)
                .getResultStream()
                .collect(Collectors.toList());
    }

    public static List<String>  signInitialTideAdmin(MultivaluedHashMap<String, String> keyProviderConfig,
                                                      UserContext[] userContexts,
                                                      InitializerCertifcate initCert,
                                                      AuthorizerEntity authorizer,
                                                      ChangesetRequestEntity changesetRequestEntity ) throws Exception {

        String currentSecretKeys = keyProviderConfig.getFirst("clientSecret");
        ObjectMapper objectMapper = new ObjectMapper();
        SecretKeys secretKeys = objectMapper.readValue(currentSecretKeys, SecretKeys.class);
        int threshold = Integer.parseInt(System.getenv("THRESHOLD_T"));
        int max = Integer.parseInt(System.getenv("THRESHOLD_N"));

        if ( threshold == 0 || max == 0){
            throw new RuntimeException("Env variables not set: THRESHOLD_T=" + threshold + ", THRESHOLD_N=" + max);
        }

        SignRequestSettingsMidgard settings = new SignRequestSettingsMidgard();
        settings.VVKId = keyProviderConfig.getFirst("vvkId");
        settings.HomeOrkUrl = keyProviderConfig.getFirst("systemHomeOrk");
        settings.PayerPublicKey = keyProviderConfig.getFirst("payerPublic");
        settings.ObfuscatedVendorPublicKey = keyProviderConfig.getFirst("obfGVVK");
        settings.VendorRotatingPrivateKey = secretKeys.activeVrk;
        settings.Threshold_T = threshold;
        settings.Threshold_N = max;

        UserContextSignRequest req = new UserContextSignRequest("VRK:1");

        req.SetDraft(Base64.getDecoder().decode(changesetRequestEntity.getDraftRequest()));
        req.SetInitializationCertificate(initCert);
        req.SetUserContexts(userContexts);
        req.SetAuthorization(
                Midgard.SignWithVrk(req.GetDataToAuthorize(), settings.VendorRotatingPrivateKey)
        );

        req.SetAuthorizer(HexFormat.of().parseHex(authorizer.getAuthorizer()));
        req.SetAuthorizerCertificate(Base64.getDecoder().decode(authorizer.getAuthorizerCertificate()));

        SignatureResponse response = Midgard.SignModel(settings, req);

        List<String> signatures = new ArrayList<>();
        for ( int i = 0; i <= userContexts.length; i++){
            signatures.add(response.Signatures[i]);
        }
        return signatures;

    }

    public static String getEntityId(Object entity) {
        if (entity instanceof TideUserRoleMappingDraftEntity) {
            return ((TideUserRoleMappingDraftEntity) entity).getId();
        } else if (entity instanceof TideRoleDraftEntity) {
            return ((TideRoleDraftEntity) entity).getId();
        } else if (entity instanceof TideCompositeRoleMappingDraftEntity) {
            return ((TideCompositeRoleMappingDraftEntity) entity).getId();
        } else if (entity instanceof TideClientDraftEntity) {
            return ((TideClientDraftEntity) entity).getId();
        }
        return null;
    }


    public static Object fetchDraftRecordEntity(EntityManager em, ChangeSetType type, String changeSetId) {
        return switch (type) {
            case USER_ROLE -> em.find(TideUserRoleMappingDraftEntity.class, changeSetId);
            case ROLE -> em.find(TideRoleDraftEntity.class, changeSetId);
            case COMPOSITE_ROLE -> em.find(TideCompositeRoleMappingDraftEntity.class, changeSetId);
            case CLIENT_FULLSCOPE, CLIENT -> em.find(TideClientDraftEntity.class, changeSetId);
            default -> null;
        };
    }

    public static void updateDraftStatus(ChangeSetType changeSetType, ActionType changeSetAction, Object draftRecordEntity) throws Exception {
        switch (changeSetType) {
            case USER_ROLE:
                if(changeSetAction == ActionType.CREATE) {
                    ((TideUserRoleMappingDraftEntity) draftRecordEntity).setDraftStatus(DraftStatus.APPROVED);
                } else if (changeSetAction == ActionType.DELETE){
                    ((TideUserRoleMappingDraftEntity) draftRecordEntity).setDeleteStatus(DraftStatus.APPROVED);
                }
                break;
            case ROLE:
                ((TideRoleDraftEntity) draftRecordEntity).setDeleteStatus(DraftStatus.APPROVED);
                break;
            case COMPOSITE_ROLE:
                if(changeSetAction == ActionType.CREATE){
                    ((TideCompositeRoleMappingDraftEntity) draftRecordEntity).setDraftStatus(DraftStatus.APPROVED);
                } else if (changeSetAction == ActionType.DELETE){
                    ((TideCompositeRoleMappingDraftEntity) draftRecordEntity).setDeleteStatus(DraftStatus.APPROVED);
                }
                break;
            case CLIENT_FULLSCOPE:
                if (changeSetAction == ActionType.CREATE) {
                    ((TideClientDraftEntity) draftRecordEntity).setFullScopeEnabled(DraftStatus.APPROVED);
                } else if (changeSetAction == ActionType.DELETE) {
                    ((TideClientDraftEntity) draftRecordEntity).setFullScopeDisabled(DraftStatus.APPROVED);
                }
                break;
        }
    }

    public static void updateDraftStatus(KeycloakSession session, ChangeSetType changeSetType, String changeSetID, ActionType changeSetAction, Object draftRecordEntity) throws Exception {
        DraftStatus draftStatus = getChangeSetStatus(session, changeSetID);

        switch (changeSetType) {
            case USER_ROLE:
                if(changeSetAction == ActionType.CREATE) {
                    ((TideUserRoleMappingDraftEntity) draftRecordEntity).setDraftStatus(draftStatus);
                } else if (changeSetAction == ActionType.DELETE){
                    ((TideUserRoleMappingDraftEntity) draftRecordEntity).setDeleteStatus(draftStatus);
                }
                break;
            case ROLE:
                ((TideRoleDraftEntity) draftRecordEntity).setDeleteStatus(draftStatus);
                break;
            case COMPOSITE_ROLE:
                if(changeSetAction == ActionType.CREATE){
                    ((TideCompositeRoleMappingDraftEntity) draftRecordEntity).setDraftStatus(draftStatus);
                } else if (changeSetAction == ActionType.DELETE){
                    ((TideCompositeRoleMappingDraftEntity) draftRecordEntity).setDeleteStatus(draftStatus);
                }
                break;
            case CLIENT_FULLSCOPE:
                if (changeSetAction == ActionType.CREATE) {
                    ((TideClientDraftEntity) draftRecordEntity).setFullScopeEnabled(draftStatus);
                } else if (changeSetAction == ActionType.DELETE) {
                    ((TideClientDraftEntity) draftRecordEntity).setFullScopeDisabled(draftStatus);
                }
                break;
            case CLIENT:
                ((TideClientDraftEntity) draftRecordEntity).setDraftStatus(draftStatus);
                break;
        }
    }

    public static void processDraftRejections(KeycloakSession session, ChangeSetType changeSetType, ActionType changeSetAction, Object draftRecordEntity, ChangesetRequestEntity changesetRequest) throws Exception {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        RealmModel realm = session.getContext().getRealm();
        ClientModel client = realm.getClientByClientId(org.keycloak.models.Constants.REALM_MANAGEMENT_CLIENT_ID);
        RoleModel tideRealmAdmin = client.getRole(Constants.TIDE_REALM_ADMIN);

        int numberOfAdmins = session.users().getRoleMembersStream(realm, tideRealmAdmin).collect(Collectors.toSet()).size();
        int numberOfRejections = changesetRequest.getAdminAuthorizations().stream().filter(a -> !a.getIsApproval()).collect(Collectors.toSet()).size();

        // Check the count of the remaining admins left to approve. If less than the threshold then just cancel change request
        if((numberOfAdmins - numberOfRejections) < Integer.parseInt(tideRealmAdmin.getFirstAttribute("tideThreshold"))) {
            ChangeSetProcessorFactory processorFactory = new ChangeSetProcessorFactory(); // Initialize the processor factory
            WorkflowParams params = new WorkflowParams(null, false, changeSetAction, changeSetType);
            processorFactory.getProcessor(changeSetType).executeWorkflow(session, draftRecordEntity, em, WorkflowType.CANCEL, params, null);
        }
    }
}

