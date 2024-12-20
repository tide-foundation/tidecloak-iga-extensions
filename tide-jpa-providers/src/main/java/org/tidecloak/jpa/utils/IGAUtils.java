package org.tidecloak.jpa.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.smallrye.config.SecretKeys;
import jakarta.persistence.EntityManager;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.midgard.Midgard;
import org.midgard.models.InitializerCertificateModel.InitializerCertifcate;
import org.midgard.models.ModelRequest;
import org.midgard.models.RequestExtensions.UserContextSignRequest;
import org.midgard.models.SignRequestSettingsMidgard;
import org.midgard.models.SignatureResponse;
import org.midgard.models.UserContext.UserContext;
import org.tidecloak.interfaces.ActionType;
import org.tidecloak.interfaces.ChangeSetType;
import org.tidecloak.interfaces.DraftChangeSetRequest;
import org.tidecloak.interfaces.DraftStatus;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.AuthorizerEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.SignatureEntry;
import org.tidecloak.jpa.entities.drafting.TideClientFullScopeStatusDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideCompositeRoleMappingDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideRoleDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;

import java.util.*;
import java.util.stream.Collectors;

import static org.tidecloak.interfaces.ChangeSetType.*;
import static org.tidecloak.jpa.models.ChangesetRequestAdapter.getChangeSetStatus;

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

    // ONLY WORKS FOR NO TIDE ADMIN. WITH IGA ENABLED TO ALLOW TIDE ADMIN TO EXIST
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

    // TODO: add signing method afer TIDEADMIN EXISTS

    public static String getEntityId(Object entity) {
        if (entity instanceof TideUserRoleMappingDraftEntity) {
            return ((TideUserRoleMappingDraftEntity) entity).getId();
        } else if (entity instanceof TideRoleDraftEntity) {
            return ((TideRoleDraftEntity) entity).getId();
        } else if (entity instanceof TideCompositeRoleMappingDraftEntity) {
            return ((TideCompositeRoleMappingDraftEntity) entity).getId();
        } else if (entity instanceof TideClientFullScopeStatusDraftEntity) {
            return ((TideClientFullScopeStatusDraftEntity) entity).getId();
        }
        return null;
    }


    public static class SecretKeys {
        public String activeVrk;
        public String pendingVrk;
        public String VZK;
        public List<String> history = new ArrayList<>();

        // Method to add a new entry to the history
        public void addToHistory(String newEntry) {
            history.add(newEntry);
        }
    }

    public static Object fetchDraftRecordEntity(EntityManager em, ChangeSetType type, String changeSetId) {
        return switch (type) {
            case USER_ROLE -> em.find(TideUserRoleMappingDraftEntity.class, changeSetId);
            case ROLE -> em.find(TideRoleDraftEntity.class, changeSetId);
            case COMPOSITE_ROLE -> em.find(TideCompositeRoleMappingDraftEntity.class, changeSetId);
            case CLIENT -> em.find(TideClientFullScopeStatusDraftEntity.class, changeSetId);
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
            case CLIENT:
                if (changeSetAction == ActionType.CREATE) {
                    ((TideClientFullScopeStatusDraftEntity) draftRecordEntity).setFullScopeEnabled(DraftStatus.APPROVED);
                } else if (changeSetAction == ActionType.DELETE) {
                    ((TideClientFullScopeStatusDraftEntity) draftRecordEntity).setFullScopeDisabled(DraftStatus.APPROVED);
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
            case CLIENT:
                if (changeSetAction == ActionType.CREATE) {
                    ((TideClientFullScopeStatusDraftEntity) draftRecordEntity).setFullScopeEnabled(draftStatus);
                } else if (changeSetAction == ActionType.DELETE) {
                    ((TideClientFullScopeStatusDraftEntity) draftRecordEntity).setFullScopeDisabled(draftStatus);
                }
                break;
        }
    }
}
