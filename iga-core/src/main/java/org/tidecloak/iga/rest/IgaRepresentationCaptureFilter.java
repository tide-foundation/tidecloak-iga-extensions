package org.tidecloak.iga.rest;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.container.PreMatching;
import jakarta.ws.rs.ext.Provider;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Resteasy;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import java.io.ByteArrayInputStream;

/**
 * JAX-RS request/response filter that captures the FULL representation on every
 * {@code CREATE_*} admin REST call so the IGA approval workflow can replay the
 * complete entity configuration (all fields, mappers, attributes, credentials,
 * flow flags, …) instead of only the bare identity.
 *
 * <h2>Why this is needed</h2>
 * The IGA interceptor throws {@code IgaPendingApprovalException} inside the
 * model-layer {@code add*}/{@code create*} call, which Keycloak invokes BEFORE
 * it applies the rest of the representation. By the time interception fires,
 * only the identity (id / name) is known. This filter runs earlier (at the
 * JAX-RS layer, {@code @PreMatching}), before the resource method deserializes
 * the body, and stashes the raw representation as a {@link KeycloakSession}
 * attribute so the model-layer capture site can fold it into the change request
 * as {@code REP_JSON}.
 *
 * <h2>Endpoints matched (POST only)</h2>
 * Matched on trailing path segments so it is robust to the {@code /admin} and
 * {@code /realms/{realm}} prefixes and to {@code {id}} path params:
 * <ul>
 *   <li>{@code POST .../users}                  → {@code UserRepresentation}</li>
 *   <li>{@code POST .../roles}                  → {@code RoleRepresentation}
 *       (covers BOTH realm roles {@code .../roles} and client roles
 *       {@code .../clients/{id}/roles} — both end in {@code roles})</li>
 *   <li>{@code POST .../groups}                 → {@code GroupRepresentation}
 *       (top-level)</li>
 *   <li>{@code POST .../groups/{id}/children}   → {@code GroupRepresentation}
 *       (child group — ends in {@code children})</li>
 *   <li>{@code POST .../client-scopes}          → {@code ClientScopeRepresentation}</li>
 *   <li>{@code POST .../clients}                 → {@code ClientRepresentation}</li>
 * </ul>
 * Client-update ({@code PUT .../clients/{id}}) is still matched and captured
 * (unchanged from the original client filter) so the existing client behaviour
 * does not regress. UPDATE_* of other types is intentionally NOT captured here —
 * those stay as targeted deltas.
 *
 * <h2>Body buffering</h2>
 * The request entity stream is consumed to read the body, then a fresh
 * {@link ByteArrayInputStream} over the same bytes is set back on the context
 * so the normal resource pipeline still deserializes the body unchanged.
 *
 * <h2>Session attribute lifecycle</h2>
 * A single attribute {@link #SESSION_ATTR} holds a small JSON envelope
 * {@code {"type":"USER|ROLE|GROUP|CLIENT_SCOPE|CLIENT","json":"<raw rep json>"}}.
 * One attribute (set once, cleared once) is cleaner and leak-safer than one
 * attribute per type. The model-layer capture site reads {@code type} to know
 * which {@code CREATE_*} it belongs to and folds {@code json} verbatim into the
 * change request as {@code REP_JSON}. The attribute is ALWAYS removed in the
 * response filter (regardless of outcome: 202 pending, 201 created, error) so
 * it cannot leak into an unrelated subsequent request on the same session.
 *
 * <h2>Failure handling</h2>
 * Every capture failure is swallowed (debug-logged only) so a capture problem
 * never breaks entity creation — the change request just won't carry
 * {@code REP_JSON} and replay falls back to the bare safety net.
 *
 * <h2>Registration</h2>
 * Annotated {@code @Provider}; Keycloak's RESTEasy runtime auto-discovers
 * {@code @Provider} classes on the provider classpath (same mechanism as
 * {@link IgaPendingApprovalExceptionMapper}, which has no services file).
 * {@code @PreMatching} guarantees we see the body before resource matching /
 * body consumption.
 */
@Provider
@PreMatching
public class IgaRepresentationCaptureFilter
        implements ContainerRequestFilter, ContainerResponseFilter {

    private static final Logger log = Logger.getLogger(IgaRepresentationCaptureFilter.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Single session attribute holding the {@code {type,json}} envelope. */
    public static final String SESSION_ATTR = "IGA_PENDING_REP";

    /** Envelope type discriminators (also the {@code CREATE_*} suffix). */
    public static final String TYPE_USER = "USER";
    public static final String TYPE_ROLE = "ROLE";
    public static final String TYPE_GROUP = "GROUP";
    public static final String TYPE_CLIENT_SCOPE = "CLIENT_SCOPE";
    public static final String TYPE_CLIENT = "CLIENT";

    @Override
    public void filter(ContainerRequestContext ctx) {
        try {
            String type = matchType(ctx);
            if (type == null) {
                return;
            }
            if (!ctx.hasEntity()) {
                return;
            }

            // Buffer the body so we can read it AND let normal processing
            // re-read it. Restore the stream for the downstream resource
            // pipeline so deserialization is unaffected.
            byte[] body = ctx.getEntityStream().readAllBytes();
            ctx.setEntityStream(new ByteArrayInputStream(body));
            if (body.length == 0) {
                return;
            }

            KeycloakSession session = Resteasy.getContextData(KeycloakSession.class);
            if (session == null) {
                // Without a session we cannot stash the attribute; the bare
                // create still works, just without full-config replay.
                log.debug("IGA rep capture: no KeycloakSession in context; skipping");
                return;
            }

            // Validate it parses as the expected representation type, then
            // re-serialize to canonical JSON (rowsJson values are safest as
            // strings). Storing the canonical form (not the raw bytes) keeps
            // it consistent with the original client filter.
            String repJson = serializeCanonical(type, body);
            if (repJson == null) {
                return;
            }
            Envelope env = new Envelope(type, repJson);
            session.setAttribute(SESSION_ATTR, MAPPER.writeValueAsString(env));
            log.debugf("IGA rep capture: stashed %s representation", type);
        } catch (Exception e) {
            // Never break the request because capture failed — fall back to
            // bare-entity behaviour. The change request just won't carry
            // REP_JSON.
            log.debugf(e, "IGA rep capture: failed to capture representation; "
                    + "proceeding without full-config capture");
        }
    }

    @Override
    public void filter(ContainerRequestContext requestCtx, ContainerResponseContext responseCtx) {
        // Always clear, regardless of how the request resolved (202 pending,
        // 201 created, error), so the attribute cannot leak.
        try {
            KeycloakSession session = Resteasy.getContextData(KeycloakSession.class);
            if (session != null && session.getAttribute(SESSION_ATTR) != null) {
                session.removeAttribute(SESSION_ATTR);
            }
        } catch (Exception e) {
            log.debugf(e, "IGA rep capture: failed to clear session attribute");
        }
    }

    /**
     * Re-serialize the captured body to canonical JSON after validating it
     * parses as the representation type for {@code type}. Returns {@code null}
     * (capture skipped) if it does not parse.
     */
    private static String serializeCanonical(String type, byte[] body) throws Exception {
        Object rep = switch (type) {
            case TYPE_USER -> MAPPER.readValue(body, UserRepresentation.class);
            case TYPE_ROLE -> MAPPER.readValue(body, RoleRepresentation.class);
            case TYPE_GROUP -> MAPPER.readValue(body, GroupRepresentation.class);
            case TYPE_CLIENT_SCOPE -> MAPPER.readValue(body, ClientScopeRepresentation.class);
            case TYPE_CLIENT -> MAPPER.readValue(body, ClientRepresentation.class);
            default -> null;
        };
        if (rep == null) {
            return null;
        }
        return MAPPER.writeValueAsString(rep);
    }

    /**
     * Determine which CREATE_* representation type (if any) this request
     * carries. POST-only, matched on trailing path segments so it is robust to
     * the {@code /admin/realms/{realm}} prefix and {@code {id}} path params.
     * Also returns {@link #TYPE_CLIENT} for {@code PUT .../clients/{id}}
     * (client update) to preserve the original client filter behaviour.
     */
    private static String matchType(ContainerRequestContext ctx) {
        String method = ctx.getMethod();
        String path = ctx.getUriInfo().getPath();
        if (path == null) {
            return null;
        }
        String p = path.startsWith("/") ? path.substring(1) : path;
        // Trim a trailing slash so the last segment is meaningful.
        if (p.endsWith("/")) {
            p = p.substring(0, p.length() - 1);
        }
        if (p.isEmpty()) {
            return null;
        }
        String[] seg = p.split("/");
        String last = seg[seg.length - 1];
        String prev = seg.length >= 2 ? seg[seg.length - 2] : null;

        if ("POST".equalsIgnoreCase(method)) {
            switch (last) {
                case "users":
                    return TYPE_USER;
                case "roles":
                    // realm role: .../roles ; client role: .../clients/{id}/roles
                    return TYPE_ROLE;
                case "groups":
                    return TYPE_GROUP;
                case "children":
                    // .../groups/{id}/children → child group create
                    return TYPE_GROUP;
                case "client-scopes":
                    return TYPE_CLIENT_SCOPE;
                case "clients":
                    return TYPE_CLIENT;
                default:
                    return null;
            }
        }
        // PUT .../clients/{id} → client update (unchanged legacy behaviour).
        if ("PUT".equalsIgnoreCase(method) && "clients".equals(prev)) {
            return TYPE_CLIENT;
        }
        return null;
    }

    /**
     * Read the captured representation JSON for {@code expectedType} from the
     * session, or {@code null} if nothing was captured / the captured type does
     * not match (e.g. a programmatic non-REST caller, or a capture failure).
     * Capture sites call this from the model layer when IGA is active.
     */
    public static String pendingRepJson(KeycloakSession session, String expectedType) {
        if (session == null) {
            return null;
        }
        Object raw = session.getAttribute(SESSION_ATTR);
        if (!(raw instanceof String s) || s.isEmpty()) {
            return null;
        }
        try {
            Envelope env = MAPPER.readValue(s, Envelope.class);
            if (env != null && expectedType.equals(env.type)
                    && env.json != null && !env.json.isEmpty()) {
                return env.json;
            }
        } catch (Exception e) {
            log.debugf(e, "IGA rep capture: failed to decode pending envelope");
        }
        return null;
    }

    /** Minimal {@code {type,json}} envelope serialized as the session attr. */
    public static final class Envelope {
        public String type;
        public String json;

        public Envelope() {
        }

        public Envelope(String type, String json) {
            this.type = type;
            this.json = json;
        }
    }
}
