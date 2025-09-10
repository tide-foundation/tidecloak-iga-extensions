package org.tidecloak.tide.iga.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.common.util.MultivaluedHashMap;
import org.midgard.Midgard;
import org.midgard.models.AuthorizerPolicyModel.AuthorizerPolicy;
import org.midgard.models.InitializerCertificateModel.InitializerCertifcate;
import org.midgard.models.RequestExtensions.UserContextSignRequest;
import org.midgard.models.SignRequestSettingsMidgard;
import org.midgard.models.SignatureResponse;
import org.midgard.models.UserContext.UserContext;
import org.tidecloak.jpa.entities.AuthorizerEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.shared.models.SecretKeys;

import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

public class IGAUtils {

    public static List<String>  signInitialTideAdminV2(MultivaluedHashMap<String, String> keyProviderConfig,
                                                     UserContext[] userContexts,
                                                     InitializerCertifcate initCert,
                                                     AuthorizerEntity authorizer,
                                                     ChangesetRequestEntity changesetRequestEntity ) throws Exception {
        String currentSecretKeys = keyProviderConfig.getFirst("clientSecret");
        ObjectMapper objectMapper = new ObjectMapper();
        SecretKeys secretKeys = objectMapper.readValue(currentSecretKeys, SecretKeys.class);
        int threshold = Integer.parseInt(System.getenv("THRESHOLD_T"));
        int max = Integer.parseInt(System.getenv("THRESHOLD_N"));
        int numberOfUserContext = 0;
        for(UserContext userContext : userContexts){
            if(userContext.getInitCertHash() == null) {
                numberOfUserContext++;
            }
        }
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
        req.SetAuthorization(Midgard.SignWithVrk(req.GetDataToAuthorize(), settings.VendorRotatingPrivateKey));
        req.SetAuthorizer(HexFormat.of().parseHex(authorizer.getAuthorizer()));
        req.SetAuthorizerCertificate(Base64.getDecoder().decode(authorizer.getAuthorizerCertificate()));
        req.SetNumberOfUserContexts(numberOfUserContext);

        SignatureResponse response = Midgard.SignModel(settings, req);
        List<String> signatures = new ArrayList<>();
        for ( int i = 0; i < userContexts.length + 1; i++){
            signatures.add(response.Signatures[i]);
        }
        return signatures;
    }

    public static List<String>  signContextsWithVrkV2(MultivaluedHashMap<String, String> keyProviderConfig,
                                                    UserContext[] userContexts,
                                                    AuthorizerEntity authorizer,
                                                    ChangesetRequestEntity changesetRequestEntity ) throws Exception {

        String currentSecretKeys = keyProviderConfig.getFirst("clientSecret");
        ObjectMapper objectMapper = new ObjectMapper();
        SecretKeys secretKeys = objectMapper.readValue(currentSecretKeys, SecretKeys.class);
        int threshold = Integer.parseInt(System.getenv("THRESHOLD_T"));
        int max = Integer.parseInt(System.getenv("THRESHOLD_N"));
        int numberOfUserContext = 0;
        for(UserContext userContext : userContexts){
            if(userContext.getInitCertHash() == null) {
                numberOfUserContext++;
            }
        }
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
        req.SetUserContexts(userContexts);
        req.SetAuthorization(Midgard.SignWithVrk(req.GetDataToAuthorize(), settings.VendorRotatingPrivateKey));
        req.SetAuthorizer(HexFormat.of().parseHex(authorizer.getAuthorizer()));
        req.SetAuthorizerCertificate(Base64.getDecoder().decode(authorizer.getAuthorizerCertificate()));
        req.SetNumberOfUserContexts(numberOfUserContext);

        SignatureResponse response = Midgard.SignModel(settings, req);
        List<String> signatures = new ArrayList<>();
        for ( int i = 0; i < userContexts.length; i++){
            signatures.add(response.Signatures[i]);
        }
        return signatures;
    }


    /**
     * Signs the AuthorizerPolicy ("header.payload") with the VRK and returns a base64url signature
     * that you can persist alongside the compact. This is NOT returned to the client.
     */
    public static String signAuthorizerPolicy(SignRequestSettingsMidgard settings, AuthorizerPolicy ap) throws Exception {
        // midgard.SignWithVrk expects a string; we pass the bytes-for-signing as base64
        String msgB64 = Base64.getEncoder().encodeToString(ap.bytesForSigning());
        byte[] rawSig = Midgard.SignWithVrk(msgB64, settings.VendorRotatingPrivateKey);
        // store as base64url (no padding) for compact 3rd segment
        return Base64.getUrlEncoder().withoutPadding().encodeToString(rawSig);
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
        int numberOfUserContext = 0;
        for(UserContext userContext : userContexts){
            if(userContext.getInitCertHash() == null) {
                numberOfUserContext++;
            }
        }

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
        req.SetNumberOfUserContexts(numberOfUserContext);

        SignatureResponse response = Midgard.SignModel(settings, req);

        List<String> signatures = new ArrayList<>();
        // UserContext length plus initCert
        for ( int i = 0; i < userContexts.length + 1; i++){
            signatures.add(response.Signatures[i]);
        }
        return signatures;

    }

    public static List<String>  signContextsWithVrk(MultivaluedHashMap<String, String> keyProviderConfig,
                                                     UserContext[] userContexts,
                                                     AuthorizerEntity authorizer,
                                                     ChangesetRequestEntity changesetRequestEntity ) throws Exception {

        String currentSecretKeys = keyProviderConfig.getFirst("clientSecret");
        ObjectMapper objectMapper = new ObjectMapper();
        SecretKeys secretKeys = objectMapper.readValue(currentSecretKeys, SecretKeys.class);
        int threshold = Integer.parseInt(System.getenv("THRESHOLD_T"));
        int max = Integer.parseInt(System.getenv("THRESHOLD_N"));
        int numberOfUserContext = 0;
        for(UserContext userContext : userContexts){
            if(userContext.getInitCertHash() == null) {
                numberOfUserContext++;
            }
        }

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
        req.SetUserContexts(userContexts);
        req.SetAuthorization(
                Midgard.SignWithVrk(req.GetDataToAuthorize(), settings.VendorRotatingPrivateKey)
        );

        req.SetAuthorizer(HexFormat.of().parseHex(authorizer.getAuthorizer()));
        req.SetAuthorizerCertificate(Base64.getDecoder().decode(authorizer.getAuthorizerCertificate()));
        req.SetNumberOfUserContexts(numberOfUserContext);

        SignatureResponse response = Midgard.SignModel(settings, req);

        List<String> signatures = new ArrayList<>();
        for ( int i = 0; i < userContexts.length; i++){
            signatures.add(response.Signatures[i]);
        }
        return signatures;

    }
}

