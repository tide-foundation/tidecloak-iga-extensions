package org.tidecloak.jpa.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.smallrye.config.SecretKeys;
import jakarta.persistence.EntityManager;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.models.RealmModel;
import org.midgard.Midgard;
import org.midgard.models.InitializerCertificateModel.InitializerCertifcate;
import org.midgard.models.ModelRequest;
import org.midgard.models.RequestExtensions.UserContextSignRequest;
import org.midgard.models.SignRequestSettingsMidgard;
import org.midgard.models.SignatureResponse;
import org.midgard.models.UserContext.UserContext;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.SignatureEntry;
import org.tidecloak.jpa.entities.drafting.TideClientFullScopeStatusDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideCompositeRoleMappingDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideRoleDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;

import java.util.*;
import java.util.stream.Collectors;

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
    public static SignatureEntry signInitialTideAdmin(MultivaluedHashMap<String, String> keyProviderConfig,
                                                      UserContext userContext,
                                                      String clientId,
                                                      InitializerCertifcate initCert,
                                                      String[] authorizer) throws Exception {

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

        req.SetInitializationCertificate(initCert);
        req.SetUserContext(userContext);
        req.SetAuthorization(
                Midgard.SignWithVrk(req.GetDataToAuthorize(), settings.VendorRotatingPrivateKey)
        );

        req.SetAuthorizer(HexFormat.of().parseHex(authorizer[1]));
        req.SetAuthorizerCertificate(Base64.getDecoder().decode(authorizer[2]));

        SignatureResponse response = Midgard.SignModel(settings, req);
        return new SignatureEntry(response.Signatures[0], "", "");

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
}
