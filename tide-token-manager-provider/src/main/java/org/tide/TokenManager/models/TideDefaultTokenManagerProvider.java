package org.tide.TokenManager.models;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import org.keycloak.Token;
import org.keycloak.TokenCategory;
import org.keycloak.common.util.Base64;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.common.util.Time;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.*;
import org.keycloak.jose.JOSE;
import org.keycloak.jose.JOSEParser;
import org.keycloak.jose.jwe.JWE;
import org.keycloak.jose.jwe.JWEConstants;
import org.keycloak.jose.jwe.JWEException;
import org.keycloak.jose.jwe.alg.JWEAlgorithmProvider;
import org.keycloak.jose.jwe.enc.JWEEncryptionProvider;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.keys.loader.PublicKeyStorageManager;
import org.keycloak.models.*;
import org.keycloak.models.TokenManager;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.SessionExpirationUtils;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.LogoutToken;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.util.JsonSerialization;
import org.keycloak.util.TokenUtil;

import org.midgard.Midgard;
import org.midgard.models.AuthRequest;
import org.midgard.models.RequestExtensions.UserTokenSignRequest;
import org.midgard.models.SignRequestSettingsMidgard;
import org.midgard.models.SignatureResponse;
import org.midgard.models.TideAuthData;

import org.tidecloak.jpa.entities.UserClientAccessProofEntity;
import org.tidecloak.jpa.entities.drafting.TideClientDraftEntity;
import org.tidecloak.shared.models.SecretKeys;
import org.tidecloak.shared.utils.UserContextUtilBase;
import org.tide.tokenmanager.api.TideTokenInterface;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Duration;
import java.util.*;
import java.util.function.BiConsumer;
import java.util.stream.Stream;
import java.util.HexFormat;

public class TideDefaultTokenManagerProvider implements TokenManager, TideTokenInterface {

    private static final Logger log = Logger.getLogger(TideDefaultTokenManagerProvider.class);
    private final KeycloakSession session;

    public TideDefaultTokenManagerProvider(KeycloakSession session) {
        this.session = session;
    }

    // ------------------- Tide trio signing -------------------

    @Override
    public String[] encode(AccessToken accessToken, IDToken idToken, boolean dokenRequested) {
        TokenCategory cat = (accessToken != null ? accessToken.getCategory() :
                (idToken != null ? idToken.getCategory() : null));
        if (cat == null) throw new RuntimeException("Both accessToken and idToken are null");

        String sigAlg = signatureAlgorithm(cat);
        RealmModel realm = session.getContext().getRealm();
        boolean iga = "true".equalsIgnoreCase(realm.getAttribute("isIGAEnabled"));

        // If not EdDSA or IGA disabled → fallback to stock encoding behavior
        if (!"EdDSA".equalsIgnoreCase(sigAlg) || !iga) {
            return new String[] {
                    accessToken != null ? encode(accessToken)           : null,
                    idToken     != null ? encodeAndEncrypt(idToken)     : null,
                    null
            };
        }

        // We need a user session to access notes
        String sid = accessToken != null ? accessToken.getSessionId() : idToken.getSessionId();
        UserSessionModel userSession = session.sessions().getUserSession(realm, sid);
        if (userSession == null) {
            return new String[] {
                    accessToken != null ? encode(accessToken)       : null,
                    idToken     != null ? encodeAndEncrypt(idToken) : null,
                    null
            };
        }

        try {
            // vendor key component
            ComponentModel vendorKey = realm.getComponentsStream()
                    .filter(c -> "tide-vendor-key".equals(c.getProviderId()))
                    .findFirst().orElse(null);
            if (vendorKey == null) {
                log.warn("tide-vendor-key not found; falling back to stock encode");
                return new String[] {
                        accessToken != null ? encode(accessToken)       : null,
                        idToken     != null ? encodeAndEncrypt(idToken) : null,
                        null
                };
            }
            MultivaluedHashMap<String,String> cfg = vendorKey.getConfig();
            String gVRK = cfg.getFirst("gVRK");
            String gVRKCertificate = cfg.getFirst("gVRKCertificate");

            // session notes
            String prevAuth = userSession.getNote("TidePreviousAuthorization");
            String tideAuth = userSession.getNote("TideAuthData");

            // user context must exist
            UserClientAccessProofEntity proof =
                    UserContextUtilBase.getUserContext(session, session.getContext().getClient().getId(), userSession.getUser());
            TideClientDraftEntity defCtx =
                    UserContextUtilBase.getDefaultUserContext(session, session.getContext().getClient().getId());

            if (proof == null && (defCtx == null || defCtx.getDefaultUserContext() == null)) {
                log.info("No User Client Access proof; removing client session");
                userSession.removeAuthenticatedClientSessions(Collections.singletonList(session.getContext().getClient().getId()));
                return new String[] { null, null, null };
            }

            // Sign settings
            SignRequestSettingsMidgard settings = setupSignSettings(cfg);

            String vuid = null, sessionKey = null;
            var tideIdp = realm.getIdentityProviderByAlias("tide");

            if (tideAuth != null && accessToken != null) {
                var authReq = AuthRequest.From(TideAuthData.From(tideAuth).AuthRequest);
                sessionKey = authReq.Key;
                accessToken.getOtherClaims().put("t.ssk", sessionKey);
                accessToken.getOtherClaims().put("t.uho", tideIdp.getConfig().get("homeORKurl"));
                vuid = (String) accessToken.getOtherClaims().get("vuid");
            }

            // Build sign request
            UserTokenSignRequest req = new UserTokenSignRequest();

            // attach user context
            if (proof != null) {
                req.SetUserContext(proof.getAccessProof());
                req.SetUserContextSignature(Base64.decode(proof.getAccessProofSig()));
            } else {
                req.SetUserContext(defCtx.getDefaultUserContext());
                req.SetUserContextSignature(Base64.decode(defCtx.getDefaultUserContextSig()));
            }

            // attach auth (prev/tide)
            if (prevAuth != null) {
                req.UseRefreshTokenAuthorization(prevAuth);
                req.ProvideRefreshTokenAuthorizationInfo(vuid, sid, getSsoSessionMaxTimeout(), sessionKey);
            }
            if (tideAuth != null) {
                long exp = Long.parseLong(AuthRequest.From(TideAuthData.From(tideAuth).AuthRequest).Expiry);
                if (exp - 2 > Time.currentTime()) {
                    req.SetTideUserAuth(TideAuthData.From(tideAuth));
                    req.ProvideRefreshTokenAuthorizationInfo(vuid, sid, getSsoSessionMaxTimeout(), sessionKey);
                }
            }

            // only ask for doken if user was tide-auth’d (or has prev auth)
            dokenRequested = dokenRequested && (tideAuth != null || prevAuth != null);

            // pre-encode but WITHOUT signing – we need kid-bound signing input for Midgard
            String atEncoded = null, idEncoded = null;
            if (accessToken != null) {
                String alg = signatureAlgorithm(accessToken.getCategory());
                KeyWrapper key = session.keys().getActiveKey(realm, KeyUse.SIG, alg);
                atEncoded = new JWSBuilder().type(type(accessToken.getCategory()))
                        .jsonContent(accessToken)
                        .getEncoded(key.getKid());
                req.SetAccessToken(atEncoded, dokenRequested);
            }
            if (idToken != null) {
                String alg = signatureAlgorithm(idToken.getCategory());
                KeyWrapper key = session.keys().getActiveKey(realm, KeyUse.SIG, alg);
                idEncoded = new JWSBuilder().type(type(idToken.getCategory()))
                        .jsonContent(idToken)
                        .getEncoded(key.getKid());
                req.SetIdToken(idEncoded);
            }

            // authorize with VRK and sign via Midgard
            req.SetAuthorization(Midgard.SignWithVrk(req.GetDataToAuthorize(), settings.VendorRotatingPrivateKey));
            req.SetAuthorizer(HexFormat.of().parseHex(gVRK));
            req.SetAuthorizerCertificate(Base64.decode(gVRKCertificate));

            SignatureResponse rsp = Midgard.SignModel(settings, req);
            var sigs = req.ProcessSignatures(rsp.Signatures);

            // persist refresh signature if present
            if (sigs.GetRefreshSignature() != null) {
                userSession.setNote("TidePreviousAuthorization", sigs.GetRefreshSignature());
            }

            return new String[] {
                    atEncoded != null ? atEncoded + "." + toB64Url(sigs.GetAccessTokenSignature()) : null,
                    idEncoded != null ? idEncoded + "." + toB64Url(sigs.GetIdTokenSignature())     : null,
                    dokenRequested ? buildDoken(accessToken, sigs.GetDokenSignature(), settings.VVKId) : null
            };

        } catch (Exception e) {
            log.error("Tide trio encode failed; falling back", e);
            return new String[] {
                    accessToken != null ? encode(accessToken)       : null,
                    idToken     != null ? encodeAndEncrypt(idToken) : null,
                    null
            };
        }
    }

    @Override
    public String encodeAndEncrypt(IDToken token, String encodedToken) {
        if (!isEncryptRequired(token.getCategory())) return encodedToken;
        return jweWrap(token.getCategory(), encodedToken);
    }

    // ------------------- Stock TokenManager API (mostly delegated/stock) -------------------

    @Override
    public String encode(Token token) {
        String signatureAlgorithm = signatureAlgorithm(token.getCategory());
        SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, signatureAlgorithm);
        SignatureSignerContext signer = signatureProvider.signer();
        return new JWSBuilder().type(type(token.getCategory())).jsonContent(token).sign(signer);
    }

    @Override
    public <T extends Token> T decode(String token, Class<T> clazz) {
        if (token == null) return null;
        try {
            JWSInput jws = new JWSInput(token);
            String signatureAlgorithm = jws.getHeader().getAlgorithm().name();
            SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, signatureAlgorithm);
            if (signatureProvider == null) return null;

            String kid = jws.getHeader().getKeyId();
            if (kid == null) {
                kid = session.keys().getActiveKey(session.getContext().getRealm(), KeyUse.SIG, signatureAlgorithm).getKid();
            }
            boolean valid = signatureProvider.verifier(kid)
                    .verify(jws.getEncodedSignatureInput().getBytes("UTF-8"), jws.getSignature());
            return valid ? jws.readJsonContent(clazz) : null;
        } catch (Exception e) {
            log.debug("Failed to decode token", e);
            return null;
        }
    }

    @Override
    public <T> T decodeClientJWT(String jwt, ClientModel client, BiConsumer<JOSE, ClientModel> jwtValidator, Class<T> clazz) {
        if (jwt == null) return null;

        JOSE joseToken = JOSEParser.parse(jwt);
        jwtValidator.accept(joseToken, client);

        if (joseToken instanceof JWE) {
            try {
                Optional<KeyWrapper> activeKey;
                String kid = joseToken.getHeader().getKeyId();
                Stream<KeyWrapper> keys = session.keys().getKeysStream(session.getContext().getRealm());

                if (kid == null) {
                    activeKey = keys.filter(k -> KeyUse.ENC.equals(k.getUse()) && k.getPublicKey() != null)
                            .sorted(Comparator.comparingLong(KeyWrapper::getProviderPriority).reversed())
                            .findFirst();
                } else {
                    activeKey = keys.filter(k -> KeyUse.ENC.equals(k.getUse()) && k.getKid().equals(kid)).findAny();
                }

                JWE jwe = (JWE) joseToken;
                Key privateKey = activeKey.map(KeyWrapper::getPrivateKey)
                        .orElseThrow(() -> new RuntimeException("Could not find private key for decrypting token"));

                jwe.getKeyStorage().setDecryptionKey(privateKey);
                byte[] content = jwe.verifyAndDecodeJwe().getContent();

                try {
                    JOSE jws = JOSEParser.parse(new String(content));
                    if (jws instanceof JWSInput) {
                        jwtValidator.accept(jws, client);
                        return verifyJWS(client, clazz, (JWSInput) jws);
                    }
                } catch (Exception ignore) { }
                return JsonSerialization.readValue(content, clazz);
            } catch (IOException | JWEException cause) {
                throw new RuntimeException("Failed to handle client JWT", cause);
            }
        }
        return verifyJWS(client, clazz, (JWSInput) joseToken);
    }

    private <T> T verifyJWS(ClientModel client, Class<T> clazz, JWSInput jws) {
        try {
            String signatureAlgorithm = jws.getHeader().getAlgorithm().name();
            ClientSignatureVerifierProvider signatureProvider =
                    session.getProvider(ClientSignatureVerifierProvider.class, signatureAlgorithm);
            if (signatureProvider == null) {
                if (jws.getHeader().getAlgorithm().equals(org.keycloak.jose.jws.Algorithm.none)) {
                    return jws.readJsonContent(clazz);
                }
                return null;
            }
            boolean valid = signatureProvider.verifier(client, jws)
                    .verify(jws.getEncodedSignatureInput().getBytes("UTF-8"), jws.getSignature());
            return valid ? jws.readJsonContent(clazz) : null;
        } catch (Exception e) {
            log.debug("Failed to verify client JWS", e);
            return null;
        }
    }

    @Override
    public String signatureAlgorithm(TokenCategory category) {
        switch (category) {
            case INTERNAL: return Constants.INTERNAL_SIGNATURE_ALGORITHM;
            case ADMIN:    return getSigAlg(null);
            case ACCESS:   return getSigAlg(OIDCConfigAttributes.ACCESS_TOKEN_SIGNED_RESPONSE_ALG);
            case ID:
            case LOGOUT:   return getSigAlg(OIDCConfigAttributes.ID_TOKEN_SIGNED_RESPONSE_ALG);
            case USERINFO: return getSigAlg(OIDCConfigAttributes.USER_INFO_RESPONSE_SIGNATURE_ALG);
            case AUTHORIZATION_RESPONSE:
                return getSigAlg(OIDCConfigAttributes.AUTHORIZATION_SIGNED_RESPONSE_ALG);
            default: throw new RuntimeException("Unknown token type");
        }
    }

    private String getSigAlg(String clientAttr) {
        RealmModel realm = session.getContext().getRealm();
        ClientModel client = session.getContext().getClient();

        String alg = client != null && clientAttr != null ? client.getAttribute(clientAttr) : null;
        if (alg != null && !alg.isBlank()) return alg;

        alg = realm.getDefaultSignatureAlgorithm();
        if (alg != null && !alg.isBlank()) return alg;

        return Constants.DEFAULT_SIGNATURE_ALGORITHM;
    }

    @Override
    public String encodeAndEncrypt(Token token) {
        String encoded = encode(token);
        return isEncryptRequired(token.getCategory()) ? jweWrap(token.getCategory(), encoded) : encoded;
    }

    // helper (no @Override): used by our interface overload too
    public String encodeAndEncrypt(Token token, String encodedToken) {
        return isEncryptRequired(token.getCategory()) ? jweWrap(token.getCategory(), encodedToken) : encodedToken;
    }

    @Override
    public String cekManagementAlgorithm(TokenCategory category) {
        if (category == null) return null;
        switch (category) {
            case INTERNAL: return Algorithm.AES;
            case ID:
            case LOGOUT:   return getCekAlg(OIDCConfigAttributes.ID_TOKEN_ENCRYPTED_RESPONSE_ALG);
            case AUTHORIZATION_RESPONSE:
                return getCekAlg(OIDCConfigAttributes.AUTHORIZATION_ENCRYPTED_RESPONSE_ALG);
            case USERINFO: return getCekAlg(OIDCConfigAttributes.USER_INFO_ENCRYPTED_RESPONSE_ALG);
            default:       return null;
        }
    }

    private String getCekAlg(String clientAttr) {
        ClientModel client = session.getContext().getClient();
        String alg = client != null && clientAttr != null ? client.getAttribute(clientAttr) : null;
        return (alg != null && !alg.isBlank()) ? alg : null;
    }

    @Override
    public String encryptAlgorithm(TokenCategory category) {
        if (category == null) return null;
        switch (category) {
            case ID:       return getEncAlg(OIDCConfigAttributes.ID_TOKEN_ENCRYPTED_RESPONSE_ENC, JWEConstants.A128CBC_HS256);
            case INTERNAL: return JWEConstants.A128CBC_HS256;
            case LOGOUT:   return getEncAlg(OIDCConfigAttributes.ID_TOKEN_ENCRYPTED_RESPONSE_ENC, null);
            case AUTHORIZATION_RESPONSE:
                return getEncAlg(OIDCConfigAttributes.AUTHORIZATION_ENCRYPTED_RESPONSE_ENC, null);
            case USERINFO: return getEncAlg(OIDCConfigAttributes.USER_INFO_ENCRYPTED_RESPONSE_ENC, JWEConstants.A128CBC_HS256);
            default:       return null;
        }
    }

    private String getEncAlg(String clientAttr, String def) {
        ClientModel client = session.getContext().getClient();
        String alg = client != null && clientAttr != null ? client.getAttribute(clientAttr) : null;
        return (alg != null && !alg.isBlank()) ? alg : def;
    }

    @Override
    public LogoutToken initLogoutToken(ClientModel client, UserModel user, AuthenticatedClientSessionModel clientSession) {
        LogoutToken token = new LogoutToken();
        token.id(KeycloakModelUtils.generateId());
        token.issuedNow();
        token.exp(Time.currentTime() + Duration.ofMinutes(2).getSeconds());
        token.issuer(clientSession.getNote(OIDCLoginProtocol.ISSUER));
        token.putEvents(TokenUtil.TOKEN_BACKCHANNEL_LOGOUT_EVENT, JsonSerialization.createObjectNode());
        token.addAudience(client.getClientId());

        OIDCAdvancedConfigWrapper cfg = OIDCAdvancedConfigWrapper.fromClientModel(client);
        if (cfg.isBackchannelLogoutSessionRequired()) {
            token.setSid(clientSession.getUserSession().getId());
        }
        if (cfg.getBackchannelLogoutRevokeOfflineTokens()) {
            token.putEvents(TokenUtil.TOKEN_BACKCHANNEL_LOGOUT_EVENT_REVOKE_OFFLINE_TOKENS, true);
        }
        token.setSubject(user.getId());
        return token;
    }

    // ------------------- helpers -------------------

    private String type(TokenCategory category) {
        return category == TokenCategory.LOGOUT ? TokenUtil.TOKEN_TYPE_JWT_LOGOUT_TOKEN : "JWT";
    }

    private boolean isEncryptRequired(TokenCategory cat) {
        return cekManagementAlgorithm(cat) != null && encryptAlgorithm(cat) != null;
    }

    private String jweWrap(TokenCategory cat, String encodedToken) {
        String alg = cekManagementAlgorithm(cat);
        String enc = encryptAlgorithm(cat);
        CekManagementProvider cek = session.getProvider(CekManagementProvider.class, alg);
        JWEAlgorithmProvider algProv = cek.jweAlgorithmProvider();
        ContentEncryptionProvider cep = session.getProvider(ContentEncryptionProvider.class, enc);
        JWEEncryptionProvider encProv = cep.jweEncryptionProvider();

        ClientModel client = session.getContext().getClient();
        KeyWrapper key = PublicKeyStorageManager.getClientPublicKeyWrapper(session, client, JWK.Use.ENCRYPTION, alg);
        if (key == null) throw new RuntimeException("No client encryption key");
        try {
            return TokenUtil.jweKeyEncryptionEncode(
                    key.getPublicKey(), encodedToken.getBytes("UTF-8"), alg, enc, key.getKid(), algProv, encProv);
        } catch (JWEException | UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    private SignRequestSettingsMidgard setupSignSettings(MultivaluedHashMap<String,String> cfg) throws JsonProcessingException {
        int t = Integer.parseInt(System.getenv("THRESHOLD_T"));
        int n = Integer.parseInt(System.getenv("THRESHOLD_N"));
        if (t == 0 || n == 0) throw new RuntimeException("Missing THRESHOLD_T/THRESHOLD_N");

        String secretJson = cfg.getFirst("clientSecret");
        SecretKeys keys = new ObjectMapper().readValue(secretJson, SecretKeys.class);

        SignRequestSettingsMidgard s = new SignRequestSettingsMidgard();
        s.VVKId = cfg.getFirst("vvkId");
        s.HomeOrkUrl = cfg.getFirst("systemHomeOrk");
        s.PayerPublicKey = cfg.getFirst("payerPublic");
        s.ObfuscatedVendorPublicKey = cfg.getFirst("obfGVVK");
        s.VendorRotatingPrivateKey = keys.activeVrk;
        s.Threshold_T = t;
        s.Threshold_N = n;
        return s;
    }

    private long getSsoSessionMaxTimeout() {
        RealmModel realm = session.getContext().getRealm();
        AuthenticationSessionManager asm = new AuthenticationSessionManager(session);
        UserSessionModel us = asm.getUserSessionFromAuthenticationCookie(realm);
        if (us == null) {
            long now = System.currentTimeMillis();
            long secs = realm.getSsoSessionMaxLifespan();
            if (secs < 0) throw new IllegalStateException("SSO session never expires");
            return now + secs * 1000L;
        }
        long expiresAt = SessionExpirationUtils.calculateUserSessionMaxLifespanTimestamp(
                false, us.isRememberMe(), us.getStarted(), realm);
        if (expiresAt < 0) throw new IllegalStateException("SSO session never expires");
        return expiresAt;
    }

    private static String toB64Url(String b64) {
        return b64.replace('+','-').replace('/','_').replaceAll("=+$","");
    }

    private String buildDoken(AccessToken at, String sigB64, String vvkId) {
        if (at == null) return null;
        String ssk  = (String) at.getOtherClaims().get("t.ssk");
        String ukey = (String) at.getOtherClaims().get("tideuserkey");
        String vuid = (String) at.getOtherClaims().get("vuid");
        if (ssk == null || ukey == null || vuid == null)
            throw new RuntimeException("Missing required claims for doken");

        Map<String,Object> payload = new LinkedHashMap<>();
        payload.put("t.ssk", ssk);
        payload.put("tideuserkey", ukey);
        payload.put("vuid", vuid);
        if (at.getOtherClaims().containsKey("t.uho")) payload.put("t.uho", at.getOtherClaims().get("t.uho"));
        payload.put("exp", at.getExp());
        payload.put("aud", vvkId);

        if (at.getRealmAccess() != null) {
            Map<String,Object> realm = new LinkedHashMap<>();
            realm.put("roles", at.getRealmAccess().getRoles());
            payload.put("realm_access", realm);
        }
        if (at.getResourceAccess() != null) {
            Map<String,Object> resources = new LinkedHashMap<>();
            at.getResourceAccess().forEach((rs,acc) -> {
                Map<String,Object> m = new LinkedHashMap<>();
                m.put("roles", acc.getRoles());
                resources.put(rs, m);
            });
            payload.put("resource_access", resources);
        }

        Map<String,String> header = new LinkedHashMap<>();
        header.put("alg", "EdDSA");
        header.put("typ", "doken");

        try {
            ObjectMapper mapper = new ObjectMapper();
            String h = Base64Url.encode(mapper.writeValueAsBytes(header));
            String p = Base64Url.encode(mapper.writeValueAsBytes(payload));
            return h + "." + p + "." + toB64Url(sigB64);
        } catch (Exception e) {
            throw new RuntimeException("Failed to build doken", e);
        }
    }
}
