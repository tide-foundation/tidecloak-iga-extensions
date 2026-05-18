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

import java.io.ByteArrayInputStream;

/**
 * JAX-RS request/response filter that captures the FULL
 * {@link ClientRepresentation} on a client-create (and client-update) admin
 * REST call so the IGA approval workflow can replay the complete client
 * configuration — redirect URIs, web origins, attributes, protocol mappers,
 * default/optional scopes, flow flags — instead of only the bare identity.
 *
 * <h2>Why this is needed</h2>
 * The IGA interceptor throws {@code IgaPendingApprovalException} inside
 * {@code RealmModel.addClient(...)}, which Keycloak invokes from
 * {@code RepresentationToModel.createClient} BEFORE it applies the rest of the
 * representation. By the time interception fires, only {@code id} and
 * {@code clientId} are known. This filter runs earlier (at the JAX-RS layer),
 * before the resource method deserializes the body, and stashes the raw
 * representation as a {@link KeycloakSession} attribute so
 * {@code IgaRealmProvider.addClient} can fold it into the change request as
 * {@code REP_JSON}.
 *
 * <h2>Body buffering</h2>
 * The request entity stream is consumed to read the body, then a fresh
 * {@link ByteArrayInputStream} over the same bytes is set back on the context
 * so the normal resource pipeline still deserializes the body unchanged.
 *
 * <h2>Session attribute lifecycle</h2>
 * The attribute {@code IGA_PENDING_CLIENT_REP} is set in the request filter and
 * always removed in the response filter (regardless of outcome) so it cannot
 * leak into an unrelated subsequent request served on the same session.
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
public class IgaClientRepresentationCaptureFilter
        implements ContainerRequestFilter, ContainerResponseFilter {

    private static final Logger log = Logger.getLogger(IgaClientRepresentationCaptureFilter.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    public static final String SESSION_ATTR = "IGA_PENDING_CLIENT_REP";

    @Override
    public void filter(ContainerRequestContext ctx) {
        try {
            if (!isClientWrite(ctx)) {
                return;
            }
            if (!ctx.hasEntity()) {
                return;
            }

            // Buffer the body so we can read it AND let normal processing
            // re-read it.
            byte[] body = ctx.getEntityStream().readAllBytes();
            // Restore the stream for the downstream resource pipeline.
            ctx.setEntityStream(new ByteArrayInputStream(body));
            if (body.length == 0) {
                return;
            }

            KeycloakSession session = Resteasy.getContextData(KeycloakSession.class);
            if (session == null) {
                // Without a session we cannot stash the attribute; the bare
                // create still works, just without full-config replay.
                log.debug("IGA client-rep capture: no KeycloakSession in context; skipping");
                return;
            }

            // Validate it parses as a ClientRepresentation, then store the
            // canonical JSON string (rowsJson values are safest as strings).
            ClientRepresentation rep =
                    MAPPER.readValue(body, ClientRepresentation.class);
            String repJson = MAPPER.writeValueAsString(rep);
            session.setAttribute(SESSION_ATTR, repJson);
            log.debugf("IGA client-rep capture: stashed ClientRepresentation (clientId=%s)",
                    rep.getClientId());
        } catch (Exception e) {
            // Never break the request because capture failed — fall back to
            // bare-client behaviour. The change request just won't carry
            // REP_JSON.
            log.debugf(e, "IGA client-rep capture: failed to capture ClientRepresentation; "
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
            log.debugf(e, "IGA client-rep capture: failed to clear session attribute");
        }
    }

    /**
     * True for {@code POST .../clients} (client create) and
     * {@code PUT .../clients/{id}} (client update) on the admin API. Path is
     * matched on the trailing segments so it is robust to the {@code /admin}
     * and {@code /realms/{realm}} prefixes.
     */
    private static boolean isClientWrite(ContainerRequestContext ctx) {
        String method = ctx.getMethod();
        String path = ctx.getUriInfo().getPath();
        if (path == null) {
            return false;
        }
        // Normalise: drop any leading slash.
        String p = path.startsWith("/") ? path.substring(1) : path;
        String[] seg = p.split("/");
        // POST .../clients   → create
        if ("POST".equalsIgnoreCase(method)
                && seg.length >= 1 && "clients".equals(seg[seg.length - 1])) {
            return true;
        }
        // PUT .../clients/{id}   → update
        if ("PUT".equalsIgnoreCase(method)
                && seg.length >= 2 && "clients".equals(seg[seg.length - 2])) {
            return true;
        }
        return false;
    }
}
