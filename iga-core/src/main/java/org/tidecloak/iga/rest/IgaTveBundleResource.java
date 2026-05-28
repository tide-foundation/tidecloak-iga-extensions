package org.tidecloak.iga.rest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.enterprise.inject.Vetoed;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.UserSessionProvider;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.util.DefaultClientSessionContext;
import org.tidecloak.iga.producer.AttestationEnvelope;
import org.tidecloak.iga.producer.BundleWriter;
import org.tidecloak.iga.producer.ExportRequest;
import org.tidecloak.iga.producer.RealmAttestationExporter;
import org.tidecloak.iga.producer.TokenType;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Admin sub-resource at /admin/realms/{realm}/iga-tve providing the M1
 * TVE-bundle producer endpoint (TokenValidationEngine).
 *
 * <p>This is a plain, manually-instantiated Keycloak admin sub-resource — the
 * exact pattern used by {@link IgaAdminResource} and
 * {@link TideAdminCompatResource}. It is created via {@code new ...} inside
 * {@link IgaTveBundleResourceProvider#getResource} and is annotated
 * {@code @Vetoed} so Quarkus ARC never treats it as a CDI bean and never
 * attempts to inject its constructor.</p>
 *
 * <h2>Modes</h2>
 * <ul>
 *   <li><b>synthesize</b> (default): construct an unsigned access/id token via
 *       Keycloak's claim-construction pipeline against a TRANSIENT user
 *       session. No password required. Emits signature-stripped compact JWS
 *       ({@code b64(header).b64(payload).}).</li>
 *   <li><b>pasted</b>: accept a customer-supplied compact JWS, strip its
 *       signature segment, derive {@code request{t,c,s,aud}} from the payload
 *       ({@code typ}, {@code azp}, {@code scope}, {@code aud}, {@code sub}),
 *       and emit the unsigned form alongside the unit envelopes computed from
 *       current realm state for {@code (realm, client=azp, user=sub)}.</li>
 * </ul>
 *
 * <p>Both modes deliberately avoid {@code session.tokens().encode(...)} — that
 * path triggers the Tide-signed branch in
 * {@code DefaultTokenManager.encode} which delegates signing to the Tide IdP.
 * For this prod-debug surface we want the claim set, not the signature, so we
 * stay on {@link TokenManager#createClientAccessToken} (the
 * {@code initToken} + {@code transformAccessToken} pipeline) and serialize the
 * {@link AccessToken}/{@link IDToken} POJO ourselves to base64url.</p>
 */
@Path("iga-tve")
@Vetoed
public class IgaTveBundleResource {

    private static final Logger log = Logger.getLogger(IgaTveBundleResource.class);

    /** Header for the unsigned compact JWS: {"alg":"none","typ":"JWT"}. */
    private static final String UNSIGNED_HEADER_B64URL =
            Base64.getUrlEncoder().withoutPadding().encodeToString(
                    "{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final KeycloakSession session;
    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;

    public IgaTveBundleResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth) {
        this.session = session;
        this.realm = realm;
        this.auth = auth;
    }

    // -------------------------------------------------------------------------
    // POST /iga-tve/tve-bundle — M1 prod-debug TVE-bundle producer.
    // -------------------------------------------------------------------------
    @POST
    @Path("tve-bundle")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response tveBundle(Map<String, Object> body) {
        auth.realm().requireManageRealm();
        if (body == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "Missing JSON body")).build();
        }
        String mode = str(body.get("mode"));
        if (mode == null || mode.isEmpty()) {
            mode = "synthesize";
        }
        String adminUserId = auth.adminAuth() != null && auth.adminAuth().getUser() != null
                ? auth.adminAuth().getUser().getId()
                : "<unknown>";
        try {
            switch (mode) {
                case "synthesize":
                    return handleSynthesize(body, adminUserId);
                case "pasted":
                    return handlePasted(body, adminUserId);
                default:
                    return Response.status(Response.Status.BAD_REQUEST)
                            .entity(Map.of("error",
                                    "mode must be 'synthesize' or 'pasted' (got: " + mode + ")"))
                            .build();
            }
        } catch (IllegalArgumentException iae) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", iae.getMessage())).build();
        } catch (RuntimeException re) {
            log.error("tve-bundle export failed", re);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of("error", re.getMessage())).build();
        }
    }

    // ---- Mode 1: synthesize ------------------------------------------------

    private Response handleSynthesize(Map<String, Object> body, String adminUserId) {
        String clientId = str(body.get("clientId"));
        String userId = str(body.get("userId"));
        String scope = str(body.get("scope"));
        String tokenTypeStr = str(body.get("tokenType"));
        if (tokenTypeStr == null || tokenTypeStr.isEmpty()) {
            tokenTypeStr = "access";
        }
        if (clientId == null || userId == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "synthesize mode requires: clientId, userId (scope, tokenType optional)"))
                    .build();
        }
        TokenType tokenType;
        try {
            tokenType = TokenType.valueOf(tokenTypeStr);
        } catch (IllegalArgumentException iae) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "tokenType must be 'access' or 'id'")).build();
        }

        ClientModel client = realm.getClientByClientId(clientId);
        if (client == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "client not found: " + clientId)).build();
        }
        UserModel user = session.users().getUserById(realm, userId);
        if (user == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "user not found: " + userId)).build();
        }

        log.infof("iga-tve tve-bundle: admin=%s realm=%s mode=synthesize userId=%s clientId=%s",
                adminUserId, realm.getName(), userId, clientId);

        // Build a TRANSIENT user+client session and ClientSessionContext mirroring
        // the ClientCredentialsGrantType pattern (services/.../grants/ClientCredentialsGrantType.java).
        AuthenticationSessionManager asm = new AuthenticationSessionManager(session);
        RootAuthenticationSessionModel rootAuthSession = asm.createAuthenticationSession(realm, false);
        AuthenticationSessionModel authSession = rootAuthSession.createAuthenticationSession(client);
        authSession.setAuthenticatedUser(user);
        authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        if (scope != null && !scope.isEmpty()) {
            authSession.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, scope);
        }

        UserSessionProvider sessions = session.sessions();
        UserSessionModel userSession = null;
        try {
            userSession = sessions.createUserSession(
                    authSession.getParentSession().getId(),
                    realm,
                    user,
                    user.getUsername(),
                    "iga-tve",                       // ipAddress placeholder
                    "iga-tve",                       // authMethod
                    false,                            // rememberMe
                    null, null,
                    UserSessionModel.SessionPersistenceState.TRANSIENT);

            // Attach the auth session as a client session and build the context.
            ClientSessionContext clientSessionCtx =
                    TokenManager.attachAuthenticationSession(session, userSession, authSession);
            clientSessionCtx.setAttribute(Constants.GRANT_TYPE, OAuth2Constants.PASSWORD);

            // Rebuild the context against the (possibly explicit) scope param so
            // requested optional scopes are honored, mirroring TokenManager's
            // refresh-token branch (services/.../oidc/TokenManager.java:1181).
            AuthenticatedClientSessionModel acs = clientSessionCtx.getClientSession();
            if (scope != null) {
                acs.setNote(OAuth2Constants.SCOPE, scope);
            }
            clientSessionCtx = DefaultClientSessionContext.fromClientSessionAndScopeParameter(acs, scope, session);

            TokenManager tokenManager = new TokenManager();
            // services/src/main/java/org/keycloak/protocol/oidc/TokenManager.java:529
            //   public AccessToken createClientAccessToken(KeycloakSession, RealmModel, ClientModel,
            //                                              UserModel, UserSessionModel, ClientSessionContext)
            // This is the claim-construction path (initToken + transformAccessToken) and does NOT
            // call session.tokens().encode(...), so the Tide-signed branch in DefaultTokenManager
            // is never reached.
            AccessToken claims = tokenManager.createClientAccessToken(
                    session, realm, client, user, userSession, clientSessionCtx);

            String unsignedToken;
            if (tokenType == TokenType.id) {
                // Synthesize an IDToken from the access token like generateIDToken in
                // services/.../oidc/TokenManager.java:1272 (transformIDToken applies the
                // id-token-claim gate of the same mapper set).
                IDToken idToken = new IDToken();
                idToken.id(claims.getId());
                idToken.type(org.keycloak.util.TokenUtil.TOKEN_TYPE_ID);
                idToken.subject(user.getId());
                idToken.audience(client.getClientId());
                idToken.issuedNow();
                idToken.issuedFor(claims.getIssuedFor());
                idToken.issuer(claims.getIssuer());
                idToken.setSessionId(claims.getSessionId());
                idToken.exp(claims.getExp());
                idToken.setAcr(claims.getAcr());
                idToken = tokenManager.transformIDToken(session, idToken, userSession, clientSessionCtx);
                unsignedToken = serializeUnsigned(idToken);
            } else {
                unsignedToken = serializeUnsigned(claims);
            }

            ExportRequest req = new ExportRequest(
                    clientId, userId, scope, tokenType, null, false);

            List<AttestationEnvelope> envelopes =
                    new RealmAttestationExporter().export(session, realm, req);

            byte[] bundle = new BundleWriter()
                    .write(realm.getId(), req, unsignedToken, envelopes);

            return Response.ok(new String(bundle, StandardCharsets.UTF_8))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        } finally {
            // Tear down the transient session.
            try {
                if (userSession != null) {
                    sessions.removeUserSession(realm, userSession);
                }
            } catch (RuntimeException tearDown) {
                log.debugf(tearDown, "iga-tve transient session teardown failed (non-fatal)");
            }
            try {
                asm.removeAuthenticationSession(realm, authSession, false);
            } catch (RuntimeException tearDown) {
                log.debugf(tearDown, "iga-tve transient auth-session teardown failed (non-fatal)");
            }
        }
    }

    // ---- Mode 2: pasted ----------------------------------------------------

    private Response handlePasted(Map<String, Object> body, String adminUserId) {
        String token = str(body.get("token"));
        if (token == null || token.isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "pasted mode requires: token (compact JWS)"))
                    .build();
        }
        String[] segments = token.split("\\.", -1);
        if (segments.length != 3 && segments.length != 2) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "token is not a compact JWS (expected 3 segments, got "
                            + segments.length + ")"))
                    .build();
        }
        // Decode payload (no signature verification — this is debug capture).
        JsonNode payload;
        try {
            byte[] payloadBytes = Base64.getUrlDecoder().decode(padBase64(segments[1]));
            payload = MAPPER.readTree(payloadBytes);
        } catch (Exception ex) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "failed to decode token payload: " + ex.getMessage()))
                    .build();
        }

        String typ = textOrNull(payload, "typ");
        String azp = textOrNull(payload, "azp");
        String scope = textOrNull(payload, "scope");
        String sub = textOrNull(payload, "sub");
        // Audience can be a string or array in JWT; ExportRequest.requestedAudience is List<String>.
        List<String> aud = null;
        JsonNode audNode = payload.get("aud");
        if (audNode != null && !audNode.isNull()) {
            aud = new java.util.ArrayList<>();
            if (audNode.isArray()) {
                for (JsonNode n : audNode) {
                    if (n.isTextual()) {
                        aud.add(n.asText());
                    }
                }
            } else if (audNode.isTextual()) {
                aud.add(audNode.asText());
            }
            if (aud.isEmpty()) {
                aud = null;
            }
        }
        if (azp == null) {
            // Some KC tokens omit azp when there's a single audience; fall back to aud[0].
            if (aud != null && !aud.isEmpty()) {
                azp = aud.get(0);
            }
        }
        if (azp == null || sub == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error",
                            "pasted token must contain azp (or aud) and sub claims"))
                    .build();
        }

        // ID-token surfaces typically carry "typ":"ID" or "JWT" with id_token usage; access tokens
        // carry "typ":"Bearer"/"JWT". Treat ID precisely; otherwise default to access.
        TokenType tokenType = "ID".equalsIgnoreCase(typ) ? TokenType.id : TokenType.access;

        log.infof("iga-tve tve-bundle: admin=%s realm=%s mode=pasted userId=%s clientId=%s",
                adminUserId, realm.getName(), sub, azp);

        ExportRequest req = new ExportRequest(azp, sub, scope, tokenType, aud, false);

        List<AttestationEnvelope> envelopes =
                new RealmAttestationExporter().export(session, realm, req);

        String unsignedToken = stripSignature(token, segments);
        byte[] bundle = new BundleWriter()
                .write(realm.getId(), req, unsignedToken, envelopes);
        return Response.ok(new String(bundle, StandardCharsets.UTF_8))
                .type(MediaType.APPLICATION_JSON)
                .build();
    }

    // ---- helpers -----------------------------------------------------------

    /**
     * Serialize an {@link AccessToken}/{@link IDToken} POJO to the
     * signature-stripped compact JWS shape {@code b64(header).b64(payload).}
     * — header rewritten to {@code {"alg":"none","typ":"JWT"}} so downstream
     * JWT parsers see a consistent 3-segment shape with an empty signature
     * segment.
     */
    private static String serializeUnsigned(Object claims) {
        try {
            byte[] payloadJson = MAPPER.writeValueAsBytes(claims);
            String payloadB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson);
            return UNSIGNED_HEADER_B64URL + "." + payloadB64 + ".";
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("failed to serialize claims to JSON: " + e.getMessage(), e);
        }
    }

    /**
     * Strip the signature segment from a compact JWS — keeps the trailing dot so
     * the result is still a parseable 3-segment JWT (empty signature). Header
     * is left as the caller supplied (we do not rewrite alg for pasted tokens
     * — caller may want to inspect the original header).
     */
    private static String stripSignature(String original, String[] segments) {
        if (segments.length == 3) {
            return segments[0] + "." + segments[1] + ".";
        }
        // 2-segment input — append the trailing dot.
        return original.endsWith(".") ? original : original + ".";
    }

    private static String padBase64(String s) {
        int pad = (4 - (s.length() % 4)) % 4;
        if (pad == 0) {
            return s;
        }
        StringBuilder sb = new StringBuilder(s.length() + pad).append(s);
        for (int i = 0; i < pad; i++) {
            sb.append('=');
        }
        return sb.toString();
    }

    private static String textOrNull(JsonNode n, String field) {
        JsonNode v = n == null ? null : n.get(field);
        return (v != null && v.isTextual() && !v.asText().isEmpty()) ? v.asText() : null;
    }

    private static String str(Object o) {
        return o != null ? o.toString() : null;
    }

    // Silence the unused-import warning for LinkedHashMap if the compiler complains
    // (kept available for future extensions of the bundle shape).
    @SuppressWarnings("unused")
    private static Map<String, Object> emptyOrdered() {
        return new LinkedHashMap<>();
    }
}
