package org.tidecloak.iga.rest;

import jakarta.enterprise.inject.Vetoed;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.tidecloak.iga.producer.AttestationEnvelope;
import org.tidecloak.iga.producer.BundleWriter;
import org.tidecloak.iga.producer.ExportRequest;
import org.tidecloak.iga.producer.OidcTokenClient;
import org.tidecloak.iga.producer.RealmAttestationExporter;

import java.nio.charset.StandardCharsets;
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
 * attempts to inject its constructor. Its constructor params
 * ({@link KeycloakSession}, {@link RealmModel}, {@link AdminPermissionEvaluator})
 * are NOT CDI-injectable and must never be — keep this class @Vetoed and free
 * of any {@code @Inject}/scope annotation.</p>
 *
 * <p>The endpoint was originally drafted as a method on {@link IgaAdminResource}
 * but was moved here so the M1 producer wiring cannot perturb the bean status
 * of the much larger, in-production approval-workflow resource.</p>
 */
@Path("iga-tve")
@Vetoed
public class IgaTveBundleResource {

    private static final Logger log = Logger.getLogger(IgaTveBundleResource.class);

    private final KeycloakSession session;
    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;

    public IgaTveBundleResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth) {
        this.session = session;
        this.realm = realm;
        this.auth = auth;
    }

    // -------------------------------------------------------------------------
    // POST /iga-tve/tve-bundle — M1 role-only producer (TokenValidationEngine).
    //
    // Emits the closure of attestation-unit envelopes for (realm, client, user,
    // scope) plus a REAL issued token (fetched via ROPC) and the TokenRequest,
    // serialized as the compact bundle the ork TVE consumes. Temporary admin
    // entry to run the org.tidecloak.iga.producer.RealmAttestationExporter
    // against live realm state (design §"Running it to emit a REAL bundle",
    // transport option a).
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
        String clientId = str(body.get("clientId"));
        String userId = str(body.get("userId"));
        String scope = str(body.get("scope"));
        // ROPC token fetch parameters (IGA-side token capture, design §8).
        String baseUrl = str(body.get("baseUrl"));        // e.g. http://localhost:8080
        String username = str(body.get("username"));      // resource owner
        String password = str(body.get("password"));
        String clientSecret = str(body.get("clientSecret")); // optional (public client -> null)
        if (clientId == null || userId == null || baseUrl == null
                || username == null || password == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error",
                            "Required: clientId, userId, baseUrl, username, password (scope, clientSecret optional)"))
                    .build();
        }
        try {
            ExportRequest req = ExportRequest.accessToken(clientId, userId, scope);

            List<AttestationEnvelope> envelopes =
                    new RealmAttestationExporter().export(session, realm, req);

            OidcTokenClient tokenClient = new OidcTokenClient(baseUrl);
            OidcTokenClient.TokenResponse tok =
                    tokenClient.passwordGrant(realm.getName(), clientId, clientSecret,
                            username, password, scope);

            byte[] bundle = new BundleWriter()
                    .write(realm.getId(), req, tok.accessToken(), envelopes);

            return Response.ok(new String(bundle, StandardCharsets.UTF_8))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        } catch (IllegalArgumentException iae) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", iae.getMessage())).build();
        } catch (RuntimeException re) {
            log.error("tve-bundle export failed", re);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of("error", re.getMessage())).build();
        }
    }

    private static String str(Object o) {
        return o != null ? o.toString() : null;
    }
}
