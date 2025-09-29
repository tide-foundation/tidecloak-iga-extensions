package org.tide.tokenmanager.api;

import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

/**
 * Extra hooks our OIDC layer can detect on the model-level TokenManager.
 * Implement this on your custom model TokenManager provider.
 */
public interface TideTokenInterface {

    /**
     * Return a trio: [accessTokenJWT(or null), idTokenJWT(or null), doken(or null)].
     * Caller will drop non-null parts into the AccessTokenResponse.
     */
    String[] encode(AccessToken accessToken, IDToken idToken, boolean requestDoken);

    /**
     * Given a pre-signed ID Token (encoded JWS string), apply Keycloak’s usual encryption path
     * if the client/realm requires it. Otherwise return the encoded string as-is.
     */
    String encodeAndEncrypt(IDToken token, String encodedToken);
}
