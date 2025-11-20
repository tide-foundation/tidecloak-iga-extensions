package org.tidecloak.tide.iga.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.common.util.MultivaluedHashMap;
import org.midgard.Midgard;
import org.midgard.models.RequestExtensions.UserContextSignRequest;
import org.midgard.models.RequestExtensions.PolicySignRequest;
import org.midgard.models.SignRequestSettingsMidgard;
import org.midgard.models.SignatureResponse;
import org.midgard.models.UserContext.UserContext;
import org.midgard.models.Policy.*;
import org.tidecloak.jpa.entities.AuthorizerEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.shared.models.SecretKeys;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;


public class IGAUtils {


    public static List<String>  signInitialTideAdmin(MultivaluedHashMap<String, String> keyProviderConfig,
                                                      UserContext[] userContexts,
                                                      Policy policy,
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
        req.SetUserContexts(userContexts);

        req.SetAuthorization(
                Midgard.SignWithVrk(req.GetDataToAuthorize(), settings.VendorRotatingPrivateKey)
        );

        req.SetAuthorizer(HexFormat.of().parseHex(authorizer.getAuthorizer()));
        req.SetAuthorizerCertificate(Base64.getDecoder().decode(authorizer.getAuthorizerCertificate()));

        SignatureResponse response = Midgard.SignModel(settings, req);

        List<String> signatures = new ArrayList<>();
        // UserContext length plus initCert
        for ( int i = 0; i < userContexts.length; i++){
            signatures.add(response.Signatures[i]);
        }

        // now sign the admin policy
        PolicySignRequest pSignReq = new PolicySignRequest(policy.ToBytes(), "VRK:1");
        pSignReq.SetAuthorization(
                Midgard.SignWithVrk(pSignReq.GetDataToAuthorize(), settings.VendorRotatingPrivateKey)
        );
        pSignReq.ToString();
        pSignReq.SetAuthorizer(HexFormat.of().parseHex(authorizer.getAuthorizer()));
        pSignReq.SetAuthorizerCertificate(Base64.getDecoder().decode(authorizer.getAuthorizerCertificate()));
        SignatureResponse res = Midgard.SignModel(settings, pSignReq);
        signatures.add(res.Signatures[0]);

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

        SignatureResponse response = Midgard.SignModel(settings, req);

        List<String> signatures = new ArrayList<>();
        for ( int i = 0; i < userContexts.length; i++){
            signatures.add(response.Signatures[i]);
        }
        return signatures;

    }
}

