package org.tidecloak.iga.producer;

import java.util.List;

/**
 * The capture that a token cannot tell us — mirrors the ork
 * {@code TokenValidationEngine.TokenRequest} (TokenType, ClientId, Scope,
 * RequestedAudience). These four are the OIDC grant parameters the producer
 * issues against the realm token endpoint, not values recoverable from the
 * issued token itself (the design §8 explains why: {@code azp != clientId},
 * scope is the raw requested param, audience-prune is request-driven).
 *
 * @param clientId          the requesting client's {@code clientId} STRING
 *                          (e.g. {@code "tve-client"}). Used both as the OIDC
 *                          grant {@code client_id} and to resolve the
 *                          {@code client_config} / assignment-set closure.
 * @param userId            the subject user's UUID (USER_ENTITY.ID). Resolves
 *                          the {@code user_identity} + role-mapping closure.
 * @param scope             the raw requested {@code scope} grant param (e.g.
 *                          {@code "openid email profile"}); may be {@code null}
 *                          for the client default.
 * @param tokenType         {@code access} or {@code id} (the surface the
 *                          bundle is validated against).
 * @param requestedAudience optional explicit audience list; {@code null} (the
 *                          M1 default) means no audience prune.
 * @param includeSystem     when {@code false} (M1 default), built-in clients /
 *                          scopes / roles are skipped via
 *                          {@link org.tidecloak.iga.services.IgaSystemEntityFilter}.
 */
public record ExportRequest(String clientId,
                            String userId,
                            String scope,
                            TokenType tokenType,
                            List<String> requestedAudience,
                            boolean includeSystem) {

    /** Convenience M1 constructor: access token, no audience, includeSystem=false. */
    public static ExportRequest accessToken(String clientId, String userId, String scope) {
        return new ExportRequest(clientId, userId, scope, TokenType.access, null, false);
    }
}
