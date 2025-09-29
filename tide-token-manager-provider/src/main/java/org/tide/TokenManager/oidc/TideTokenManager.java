package org.tide.TokenManager.oidc;

import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.RefreshToken;
import org.keycloak.util.TokenUtil;
import org.keycloak.crypto.HashProvider;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.TokenCategory;
import org.keycloak.jose.jws.crypto.HashUtils;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class TideTokenManager extends TokenManager {

    @Override
    public AccessTokenResponseBuilder responseBuilder(RealmModel realm,
                                                      ClientModel client,
                                                      EventBuilder event,
                                                      KeycloakSession session,
                                                      UserSessionModel userSession,
                                                      ClientSessionContext clientSessionCtx) {
        return new TideAccessTokenResponseBuilder(realm, client, event, session, userSession, clientSessionCtx);
    }

    public class TideAccessTokenResponseBuilder extends TokenManager.AccessTokenResponseBuilder {
        private final RealmModel realm;
        private final ClientModel client;
        private final EventBuilder event;
        private final KeycloakSession session;
        private final UserSessionModel userSession;
        private final ClientSessionContext clientSessionCtx;

        private String responseTokenType;

        public TideAccessTokenResponseBuilder(RealmModel realm,
                                              ClientModel client,
                                              EventBuilder event,
                                              KeycloakSession session,
                                              UserSessionModel userSession,
                                              ClientSessionContext clientSessionCtx) {
            super(realm, client, event, session, userSession, clientSessionCtx);
            this.realm = realm;
            this.client = client;
            this.event = event;
            this.session = session;
            this.userSession = userSession;
            this.clientSessionCtx = clientSessionCtx;
            this.responseTokenType = formatTokenTypeLocal(client, null);
        }

        private String formatTokenTypeLocal(ClientModel client, AccessToken at) {
            String t = Optional.ofNullable(at).map(AccessToken::getType).orElse(TokenUtil.TOKEN_TYPE_BEARER);
            if (OIDCAdvancedConfigWrapper.fromClientModel(client).isUseLowerCaseInTokenResponse()) return t.toLowerCase();
            return t;
        }

        private String oidcHash(String input) {
            String sigAlg = session.tokens().signatureAlgorithm(TokenCategory.ID);
            SignatureProvider sig = session.getProvider(SignatureProvider.class, sigAlg);
            String hashAlg = sig.signer().getHashAlgorithm();
            HashProvider hash = session.getProvider(HashProvider.class, hashAlg);
            return HashUtils.encodeHashToOIDC(hash.hash(input));
        }

        private boolean hasTideRole(AccessToken token) {
            if (token == null) return false;
            Set<String> realmRoles = token.getRealmAccess() == null ? Set.of() : token.getRealmAccess().getRoles();
            Map<String, AccessToken.Access> res = token.getResourceAccess();
            Set<String> clientRoles = res == null ? Set.of() :
                    res.values().stream().flatMap(a -> a.getRoles().stream()).collect(Collectors.toSet());
            return Stream.concat(realmRoles.stream(), clientRoles.stream()).anyMatch(r -> r.startsWith("_tide_"));
        }

        @Override
        public AccessTokenResponse build() {
            AccessToken accessToken = getAccessToken();
            RefreshToken refreshToken = getRefreshToken();
            IDToken idToken = getIdToken();

            if (accessToken != null) {
                event.detail(Details.TOKEN_ID, accessToken.getId());
                responseTokenType = formatTokenTypeLocal(client, accessToken);
            }
            if (refreshToken != null) {
                if (event.getEvent().getDetails().containsKey(Details.REFRESH_TOKEN_ID)) {
                    event.detail(Details.UPDATED_REFRESH_TOKEN_ID, refreshToken.getId());
                } else {
                    event.detail(Details.REFRESH_TOKEN_ID, refreshToken.getId());
                }
                event.detail(Details.REFRESH_TOKEN_TYPE, refreshToken.getType());
            }

            AccessTokenResponse res = new AccessTokenResponse();
            boolean requestedDoken = hasTideRole(accessToken);

            org.keycloak.models.TokenManager modelTm = session.tokens();
            if (modelTm instanceof org.tide.tokenmanager.api.TideTokenInterface codec) {
                String[] trio = codec.encode(accessToken, idToken, requestedDoken);
                if (accessToken != null) {
                    res.setToken(trio[0]);
                    res.setTokenType(responseTokenType);
                    res.setSessionState(accessToken.getSessionState());
                    if (accessToken.getExp() != 0) {
                        res.setExpiresIn(accessToken.getExp() - org.keycloak.common.util.Time.currentTime());
                    }
                }

                if (idToken != null) {
                    if (res.getToken() != null) {
                        idToken.setAccessTokenHash(oidcHash(res.getToken()));
                    }
                    String idWrapped = codec.encodeAndEncrypt(idToken, trio[1]);
                    res.setIdToken(idWrapped);
                }

                if (refreshToken != null) {
                    // keep standard KC encoding for refresh tokens
                    res.setRefreshToken(session.tokens().encode(refreshToken));
                    Long exp = refreshToken.getExp();
                    if (exp != null && exp > 0) {
                        res.setRefreshExpiresIn(exp - org.keycloak.common.util.Time.currentTime());
                    }
                }

                if (trio[2] != null) {
                    res.getOtherClaims().put("doken", trio[2]);
                }
            } else {
                // Fallback to pure core encoding
                if (accessToken != null) {
                    String at = session.tokens().encode(accessToken);
                    res.setToken(at);
                    res.setTokenType(responseTokenType);
                    res.setSessionState(accessToken.getSessionState());
                    if (accessToken.getExp() != 0) {
                        res.setExpiresIn(accessToken.getExp() - org.keycloak.common.util.Time.currentTime());
                    }
                }
                if (idToken != null) {
                    res.setIdToken(session.tokens().encodeAndEncrypt(idToken));
                }
                if (refreshToken != null) {
                    res.setRefreshToken(session.tokens().encode(refreshToken));
                    Long exp = refreshToken.getExp();
                    if (exp != null && exp > 0) {
                        res.setRefreshExpiresIn(exp - org.keycloak.common.util.Time.currentTime());
                    }
                }
            }

            // not-before policy (copied from core)
            int nb = realm.getNotBefore();
            if (client.getNotBefore() > nb) nb = client.getNotBefore();
            var user = userSession.getUser();
            if (!(user instanceof org.keycloak.models.light.LightweightUserAdapter)) {
                int unb = session.users().getNotBeforeOfUser(realm, user);
                if (unb > nb) nb = unb;
            }
            res.setNotBeforePolicy(nb);

            // mappers on response + scope (same as core)
            res = transformAccessTokenResponse(session, res, userSession, clientSessionCtx);
            String responseScope = clientSessionCtx.getScopeString();
            res.setScope(responseScope);
            event.detail(Details.SCOPE, responseScope);

            return res;
        }
    }
}
