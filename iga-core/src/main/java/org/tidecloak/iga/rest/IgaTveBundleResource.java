package org.tidecloak.iga.rest;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import jakarta.enterprise.inject.Vetoed;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.HttpHeaders;
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
import org.keycloak.services.Urls;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.managers.UserSessionManager;
import org.tidecloak.iga.producer.units.AttestationUnit;
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

    /**
     * Dedicated mapper for serializing the unsigned token payload. Configured
     * with {@code NON_NULL} so unset AccessToken/IDToken POJO slots are omitted,
     * matching the byte shape of a real Keycloak-issued JWT payload (which only
     * carries claims that were actually populated by mappers).
     */
    private static final ObjectMapper TOKEN_PAYLOAD_MAPPER =
            new ObjectMapper().setSerializationInclusion(JsonInclude.Include.NON_NULL);

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
    /** Response media type for the CBOR encoding. */
    public static final String APPLICATION_CBOR = "application/cbor";

    @POST
    @Path("tve-bundle")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces({APPLICATION_CBOR, MediaType.APPLICATION_JSON})
    public Response tveBundle(Map<String, Object> body,
                              @HeaderParam(HttpHeaders.ACCEPT) String acceptHeader) {
        auth.realm().requireManageRealm();
        // Content-negotiation: JSON only if the client explicitly asks for application/json;
        // CBOR is the default for application/cbor, */*, missing header, or anything else.
        // Resolved up-front so error responses honour Accept too.
        BundleWriter.Format format = selectFormat(acceptHeader);
        if (body == null) {
            return errorResponse(Response.Status.BAD_REQUEST, "MISSING_BODY",
                    "Missing JSON body", format);
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
                    return handleSynthesize(body, adminUserId, format);
                case "pasted":
                    return handlePasted(body, adminUserId, format);
                default:
                    return errorResponse(Response.Status.BAD_REQUEST, "INVALID_MODE",
                            "mode must be 'synthesize' or 'pasted' (got: " + mode + ")",
                            format);
            }
        } catch (IllegalArgumentException iae) {
            return errorResponse(Response.Status.BAD_REQUEST, "INVALID_ARGUMENT",
                    iae.getMessage(), format);
        } catch (RuntimeException re) {
            log.error("tve-bundle export failed", re);
            return errorResponse(Response.Status.INTERNAL_SERVER_ERROR, "INTERNAL",
                    re.getMessage(), format);
        }
    }

    // ---- Mode 1: synthesize ------------------------------------------------

    private Response handleSynthesize(Map<String, Object> body, String adminUserId,
                                       BundleWriter.Format format) {
        String clientId = str(body.get("clientId"));
        String userId = str(body.get("userId"));
        String scope = str(body.get("scope"));
        String tokenTypeStr = str(body.get("tokenType"));
        if (tokenTypeStr == null || tokenTypeStr.isEmpty()) {
            tokenTypeStr = "access";
        }
        if (clientId == null || userId == null) {
            return errorResponse(Response.Status.BAD_REQUEST, "MISSING_PARAMETERS",
                    "synthesize mode requires: clientId, userId (scope, tokenType optional)",
                    format);
        }
        TokenType tokenType;
        try {
            tokenType = TokenType.valueOf(tokenTypeStr);
        } catch (IllegalArgumentException iae) {
            return errorResponse(Response.Status.BAD_REQUEST, "INVALID_TOKEN_TYPE",
                    "tokenType must be 'access' or 'id'", format);
        }

        ClientModel client = realm.getClientByClientId(clientId);
        if (client == null) {
            return errorResponse(Response.Status.BAD_REQUEST, "CLIENT_NOT_FOUND",
                    "client not found: " + clientId, format);
        }
        UserModel user = session.users().getUserById(realm, userId);
        if (user == null) {
            return errorResponse(Response.Status.BAD_REQUEST, "USER_NOT_FOUND",
                    "user not found: " + userId, format);
        }

        log.infof("iga-tve tve-bundle: admin=%s realm=%s mode=synthesize userId=%s clientId=%s format=%s",
                adminUserId, realm.getName(), userId, clientId, formatLabel(format));

        // Build a TRANSIENT user+client session and ClientSessionContext mirroring
        // the ResourceOwnerPasswordCredentialsGrantType pattern
        // (the ResourceOwnerPasswordCredentialsGrantType session/context setup).
        // Hydration parity with the real password-grant flow is required so the
        // mapper pipeline (transformAccessToken) sees the same inputs and the
        // resulting unsigned token is byte-shape-equivalent to a real
        // password-issued access token (modulo signature + iat/exp/jti).
        AuthenticationSessionManager asm = new AuthenticationSessionManager(session);
        RootAuthenticationSessionModel rootAuthSession = asm.createAuthenticationSession(realm, false);
        AuthenticationSessionModel authSession = rootAuthSession.createAuthenticationSession(client);
        authSession.setAuthenticatedUser(user);
        authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        // Mirrors ResourceOwnerPasswordCredentialsGrantType — the
        // AUTHENTICATE action is what the auth processor sets at the start of
        // the password flow. AcrStore reads no LOA note here so token.acr falls
        // back to the non-step-up "1" branch in initToken.
        authSession.setAction(AuthenticatedClientSessionModel.Action.AUTHENTICATE.name());
        // CRITICAL — mirrors ResourceOwnerPasswordCredentialsGrantType.
        // initToken reads `iss` solely from the client
        // session's OIDCLoginProtocol.ISSUER note, which is transferred from the
        // auth-session client-notes by attachAuthenticationSession.
        // Without this note, the synthesized token
        // emits iss=null.
        authSession.setClientNote(OIDCLoginProtocol.ISSUER,
                Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));
        // Mirrors ResourceOwnerPasswordCredentialsGrantType. Set the
        // scope-param client-note unconditionally so attachAuthenticationSession's
        // scope resolution sees a consistent input.
        // A null scope param resolves to "client default scopes + client itself",
        // matching what `password` grant with no
        // explicit scope= form param produces. The real ROPC code sets this note
        // unconditionally (even with a null scope) — we mirror that exactly.
        authSession.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, scope);

        UserSessionModel userSession = null;
        UserSessionProvider sessions = session.sessions();
        try {
            // Use UserSessionManager (mirrors ClientCredentialsGrantType
            // and the ResourceOwnerPasswordCredentialsGrantType path through
            // AuthenticationProcessor.attachSession) rather than
            // session.sessions().createUserSession(...) directly: it additionally
            // attaches device-activity info, which keeps any DeviceActivityManager
            // mappers happy.
            userSession = new UserSessionManager(session).createUserSession(
                    authSession.getParentSession().getId(),
                    realm,
                    user,
                    user.getUsername(),
                    "iga-tve",                       // ipAddress placeholder
                    "iga-tve",                       // authMethod
                    false,                            // rememberMe
                    null, null,
                    UserSessionModel.SessionPersistenceState.TRANSIENT);
            // Mirrors AuthenticationProcessor. Without LOGGED_IN state
            // some mapper guards short-circuit (e.g. session-status mappers,
            // certain role-resolution edges). Keycloak's password-grant always
            // reaches this state via AuthenticationProcessor.attachSession.
            userSession.setState(UserSessionModel.State.LOGGED_IN);
            session.getContext().setUserSession(userSession);
            // Mirrors the implicit invariant of every token-issuing path: the
            // KeycloakContext's "current client" is the token's target client
            // (not the calling admin client). Mappers like
            // AbstractOIDCProtocolMapper.getShouldUseLightweightToken read
            // `session.getContext().getClient().getAttribute(USE_LIGHTWEIGHT_ACCESS_TOKEN_ENABLED)`
            // — without this override they would read it from the admin UI
            // client, which is unrelated to the synthesize target.
            session.getContext().setClient(client);

            // Mirrors ResourceOwnerPasswordCredentialsGrantType and
            // ClientCredentialsGrantType — MUST be called BEFORE
            // attachAuthenticationSession so the auth-session has its requested
            // client-scope set computed, which downstream code can inspect.
            // AuthenticationManager.setClientScopesInSession calls
            // TokenManager.getRequestedClientScopes(...) using the SCOPE_PARAM
            // client-note and stores the resulting scope ids on the auth-session
            // via authSession.setClientScopes(...).
            AuthenticationManager.setClientScopesInSession(session, authSession);

            // Attach the auth session as a client session and build the context.
            // attachAuthenticationSession does:
            //   - creates the client session (transient, since userSession is transient)
            //   - transfers all auth-session client-notes to the client session
            //     (including OIDCLoginProtocol.ISSUER set above)
            //   - transfers all auth-session user-session-notes to the user session
            //   - resolves scopes from OAuth2Constants.SCOPE client-note (=SCOPE_PARAM)
            //     via getRequestedClientScopes — defaults + optional-when-requested
            //   - builds DefaultClientSessionContext with that resolved scope set
            // So the resulting context already has the right scopes, mappers, and
            // notes; we do NOT need to rebuild it via fromClientSessionAndScopeParameter.
            ClientSessionContext clientSessionCtx =
                    TokenManager.attachAuthenticationSession(session, userSession, authSession);
            // Mirrors ResourceOwnerPasswordCredentialsGrantType. The
            // GRANT_TYPE context attribute is consumed by some mappers (e.g.
            // session-state mappers). We keep this as PASSWORD to match what
            // the real password-grant pipeline reports to mappers. The JTI
            // prefix (which the encoder would otherwise derive from this) is
            // overridden below to the engine-supported "trrtcc:" — see the
            // explanation there.
            clientSessionCtx.setAttribute(Constants.GRANT_TYPE, OAuth2Constants.PASSWORD);
            // Mirror SCOPE note on the client session for symmetry with the
            // password-grant flow — attachAuthenticationSession already transferred
            // it via the client-notes loop, but setting it directly is a safe no-op
            // when scope is null (skip) and idempotent otherwise.
            AuthenticatedClientSessionModel acs = clientSessionCtx.getClientSession();
            if (scope != null) {
                acs.setNote(OAuth2Constants.SCOPE, scope);
            }

            TokenManager tokenManager = new TokenManager();
            // TokenManager.createClientAccessToken:
            //   public AccessToken createClientAccessToken(KeycloakSession, RealmModel, ClientModel,
            //                                              UserModel, UserSessionModel, ClientSessionContext)
            // This is the claim-construction path (initToken + transformAccessToken) and does NOT
            // call session.tokens().encode(...), so the Tide-signed branch in DefaultTokenManager
            // is never reached.

            // Diagnostic — DEBUG log just before the mapper pipeline runs.
            // If mapperCount == 0 the cause is upstream (scope/user filtering
            // in DefaultClientSessionContext.isAllowed). If it's non-zero but
            // mapper-derived claims remain absent in the synth payload, the
            // cause is in mapper execution (user adapter wrong,
            // includeInAccessToken false, etc.). Gated behind isDebugEnabled()
            // so the stream materialization + scope-name join cost is only
            // paid when DEBUG is enabled. The underlying getProtocolMappersStream
            // returns a fresh stream from a cached Set, so counting it does not
            // affect the subsequent createClientAccessToken call.
            if (log.isDebugEnabled()) {
                try {
                    long mapperCount = clientSessionCtx.getProtocolMappersStream().count();
                    String resolvedScopes = clientSessionCtx.getClientScopesStream()
                            .map(org.keycloak.models.ClientScopeModel::getName)
                            .collect(java.util.stream.Collectors.joining(","));
                    log.debugf("synthesize: protocol mappers loaded = %d", mapperCount);
                    log.debugf("synthesize: resolved client scopes = %s", resolvedScopes);
                } catch (RuntimeException diag) {
                    log.warnf(diag, "synthesize: diagnostic logging failed (non-fatal)");
                }
            }

            AccessToken claims = tokenManager.createClientAccessToken(
                    session, realm, client, user, userSession, clientSessionCtx);

            // Force engine-compatible jti prefix "trrtcc:" regardless of whether
            // the resolved TokenContextEncoder chose lightweight (encoded "lt")
            // or regular (encoded "rt"). The TokenValidationEngine only knows
            // {trrtcc, onrtcc, oftcc}; any other prefix is rejected with
            // ATTESTATION_INVALID. We keep the raw 16-char rawTokenId portion the
            // encoder produced after the ':' so the underlying secure-random id
            // is preserved (just the prefix is normalised).
            String currentJti = claims.getId();
            int colon = currentJti == null ? -1 : currentJti.indexOf(':');
            String rawJtiId = (colon > 0) ? currentJti.substring(colon + 1) : currentJti;
            if (rawJtiId == null || rawJtiId.isEmpty()) {
                rawJtiId = org.keycloak.common.util.SecretGenerator.getInstance()
                        .generateSecureID();
            }
            claims.id("trrtcc:" + rawJtiId);

            String unsignedToken;
            if (tokenType == TokenType.id) {
                // Synthesize an IDToken from the access token like TokenManager.generateIDToken
                // (transformIDToken applies the id-token-claim gate of the same mapper set).
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

            List<AttestationUnit> units =
                    new RealmAttestationExporter().export(session, realm, req);

            byte[] bundle = new BundleWriter()
                    .write(realm.getId(), req, unsignedToken, units, format);

            return buildBundleResponse(bundle, format);
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

    private Response handlePasted(Map<String, Object> body, String adminUserId,
                                   BundleWriter.Format format) {
        String token = str(body.get("token"));
        if (token == null || token.isEmpty()) {
            return errorResponse(Response.Status.BAD_REQUEST, "MISSING_TOKEN",
                    "pasted mode requires: token (compact JWS)", format);
        }
        String[] segments = token.split("\\.", -1);
        if (segments.length != 3 && segments.length != 2) {
            return errorResponse(Response.Status.BAD_REQUEST, "INVALID_TOKEN",
                    "token is not a compact JWS (expected 3 segments, got "
                            + segments.length + ")",
                    format);
        }
        // Decode payload (no signature verification — this is debug capture).
        JsonNode payload;
        try {
            byte[] payloadBytes = Base64.getUrlDecoder().decode(padBase64(segments[1]));
            payload = MAPPER.readTree(payloadBytes);
        } catch (Exception ex) {
            return errorResponse(Response.Status.BAD_REQUEST, "INVALID_TOKEN_PAYLOAD",
                    "failed to decode token payload: " + ex.getMessage(), format);
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
            return errorResponse(Response.Status.BAD_REQUEST, "INVALID_TOKEN_CLAIMS",
                    "pasted token must contain azp (or aud) and sub claims", format);
        }

        // ID-token surfaces typically carry "typ":"ID" or "JWT" with id_token usage; access tokens
        // carry "typ":"Bearer"/"JWT". Treat ID precisely; otherwise default to access.
        TokenType tokenType = "ID".equalsIgnoreCase(typ) ? TokenType.id : TokenType.access;

        log.infof("iga-tve tve-bundle: admin=%s realm=%s mode=pasted userId=%s clientId=%s format=%s",
                adminUserId, realm.getName(), sub, azp, formatLabel(format));

        ExportRequest req = new ExportRequest(azp, sub, scope, tokenType, aud, false);

        List<AttestationUnit> units =
                new RealmAttestationExporter().export(session, realm, req);

        String unsignedToken = stripSignature(token, segments);
        byte[] bundle = new BundleWriter()
                .write(realm.getId(), req, unsignedToken, units, format);
        return buildBundleResponse(bundle, format);
    }

    // ---- format negotiation ------------------------------------------------

    /**
     * Pick the bundle output format from the request's {@code Accept} header.
     *
     * <p>Rule: JSON only if the header explicitly names {@code application/json};
     * CBOR is the default for {@code application/cbor}, {@code *&#47;*}, missing
     * header, or anything else. This matches the design intent of "CBOR by
     * default; JSON when client {@code Accept: application/json}".</p>
     */
    static BundleWriter.Format selectFormat(String acceptHeader) {
        if (acceptHeader == null || acceptHeader.isEmpty()) {
            return BundleWriter.Format.CBOR;
        }
        // Case-insensitive substring match — Accept may carry parameters like
        // "application/json; q=0.9, */*; q=0.1". We deliberately do NOT parse
        // q-values: the design says "Accept contains application/json -> JSON".
        return acceptHeader.toLowerCase(java.util.Locale.ROOT).contains("application/json")
                ? BundleWriter.Format.JSON
                : BundleWriter.Format.CBOR;
    }

    private static String formatLabel(BundleWriter.Format f) {
        return f == BundleWriter.Format.JSON ? "json" : "cbor";
    }

    private static Response buildBundleResponse(byte[] bundle, BundleWriter.Format format) {
        if (format == BundleWriter.Format.JSON) {
            return Response.ok(new String(bundle, StandardCharsets.UTF_8))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }
        // CBOR: raw bytes with application/cbor.
        return Response.ok(bundle)
                .type(APPLICATION_CBOR)
                .build();
    }

    // ---- error response (Accept-aware) -------------------------------------

    /** Jackson mapper for JSON error bodies. */
    private static final ObjectMapper ERROR_JSON_MAPPER = new ObjectMapper();
    /** Jackson mapper for CBOR error bodies. */
    private static final ObjectMapper ERROR_CBOR_MAPPER = new ObjectMapper(new CBORFactory());

    /**
     * Build an error response whose Content-Type matches the negotiated bundle
     * {@code format}. The body is a small map {@code {"error": message, "code":
     * code}} serialized through the same Jackson mapper family the success path
     * uses, so the response round-trips through whichever encoding the client
     * asked for (or CBOR by default).
     *
     * <p>Without this helper, Jakarta REST defaults to a writer chosen from the
     * {@code @Produces} list and JAX-RS may pick {@code application/cbor} but
     * then serialize a Java {@code Map.toString()} ({@code {error=...}}) — not
     * valid JSON or CBOR. See live smoke notes in the M1 change request.</p>
     */
    private static Response errorResponse(Response.Status status, String code,
                                          String message, BundleWriter.Format format) {
        Map<String, String> body = new LinkedHashMap<>();
        body.put("error", message == null ? "" : message);
        body.put("code", code == null ? "UNKNOWN" : code);
        try {
            if (format == BundleWriter.Format.JSON) {
                byte[] bytes = ERROR_JSON_MAPPER.writeValueAsBytes(body);
                return Response.status(status)
                        .type(MediaType.APPLICATION_JSON)
                        .entity(bytes)
                        .build();
            }
            byte[] bytes = ERROR_CBOR_MAPPER.writeValueAsBytes(body);
            return Response.status(status)
                    .type(APPLICATION_CBOR)
                    .entity(bytes)
                    .build();
        } catch (com.fasterxml.jackson.core.JsonProcessingException jpe) {
            // Last-resort: serialization of the error itself failed. Fall back to
            // a plaintext message so the client still sees *something* sensible.
            log.error("iga-tve errorResponse: failed to serialize error body", jpe);
            return Response.status(status)
                    .type(MediaType.TEXT_PLAIN)
                    .entity("error: " + (message == null ? "" : message))
                    .build();
        }
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
            // NON_NULL mapper — match the byte shape of a real password-grant
            // token payload (only populated claims appear). Default Jackson
            // serializes every AccessToken/IDToken POJO field including null,
            // which adds ~30 keys not present in a real KC-issued token.
            byte[] payloadJson = TOKEN_PAYLOAD_MAPPER.writeValueAsBytes(claims);
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
