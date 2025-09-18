//  ─────────────────────────────────────────────────────────────────────────────
//  IGARealmResource – toggle IGA, auto-draft replay endpoints, sign & commit
//  ─────────────────────────────────────────────────────────────────────────────
package org.tidecloak.base.iga.IGARealmResource;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.tidecloak.base.iga.ChangeSetCommitter.ChangeSetCommitter;
import org.tidecloak.base.iga.ChangeSetCommitter.ChangeSetCommitterFactory;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequestList;
import org.tidecloak.base.iga.interfaces.ChangesetRequestAdapter;
import org.tidecloak.base.iga.utils.BasicIGAUtils;

import java.util.*;

/**
 * Mounted by the admin-realm-restapi-extension factory (id: tide-admin).
 *
 * Endpoints:
 *  - POST   toggle-iga
 *  - POST   add-rejection
 *  - POST   replay/{rest:.+}
 *  - PUT    replay/{rest:.+}
 *  - PATCH  replay/{rest:.+}
 *  - DELETE replay/{rest:.+}
 *  - POST   change-set/sign
 *  - POST   change-set/sign/batch
 *  - POST   change-set/commit
 *  - POST   change-set/commit/batch
 */
public class IGARealmResource {

    private static final Logger LOG = Logger.getLogger(IGARealmResource.class);
    private static final ObjectMapper M = new ObjectMapper();

    private final KeycloakSession session;
    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;

    public IGARealmResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth) {
        this.session = session;
        this.realm = realm;
        this.auth = auth;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // IGA toggle
    // ─────────────────────────────────────────────────────────────────────────
    @POST
    @Path("toggle-iga")
    @Produces(MediaType.TEXT_PLAIN)
    public Response toggleIGA(@FormParam("isIGAEnabled") boolean isEnabled) throws Exception {
        try {
            RealmModel masterRealm = session.realms().getRealmByName(Config.getAdminRealm());
            if (realm.equals(masterRealm)) {
                return buildResponse(400, "Master realm does not support IGA.");
            }

            auth.realm().requireManageRealm();
            realm.setAttribute("isIGAEnabled", isEnabled);
            LOG.infof("IGA has been toggled to : %s", isEnabled);

            IdentityProviderModel tideIdp = session.identityProviders().getByAlias("tide");
            ComponentModel componentModel = realm.getComponentsStream()
                    .filter(x -> "tide-vendor-key".equals(x.getProviderId()))
                    .findFirst()
                    .orElse(null);

            if (tideIdp != null && componentModel != null) {
                String currentAlg = realm.getDefaultSignatureAlgorithm();
                if (isEnabled) {
                    if (!"EdDSA".equalsIgnoreCase(currentAlg)) {
                        realm.setDefaultSignatureAlgorithm("EdDSA");
                        LOG.info("IGA enabled, default signature algorithm set to EdDSA");
                    }
                } else {
                    if ("EdDSA".equalsIgnoreCase(currentAlg)) {
                        realm.setDefaultSignatureAlgorithm("RS256");
                        LOG.info("IGA disabled, default signature algorithm reset to RS256");
                    }
                }
            }
            return buildResponse(200, "IGA has been toggled to : " + isEnabled);
        } catch (Exception e) {
            LOG.error("Error toggling IGA on realm", e);
            throw e;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Record an admin rejection on a change set
    // ─────────────────────────────────────────────────────────────────────────
    @POST
    @Path("add-rejection")
    @Produces(MediaType.TEXT_PLAIN)
    public Response addRejection(@FormParam("changeSetId") String changeSetId,
                                 @FormParam("actionType") String actionType,
                                 @FormParam("changeSetType") String changeSetType) {
        try {
            auth.realm().requireManageRealm();
            ChangesetRequestAdapter.saveAdminRejection(session, changeSetType, changeSetId, actionType, auth.adminAuth().getUser());
            return buildResponse(200, "Successfully added admin rejection to changeSetRequest with id " + changeSetId);
        } catch (Exception e) {
            LOG.errorf(e, "Error adding rejection to change set request with ID: %s", changeSetId);
            return buildResponse(500, "Error adding rejection to change set request with ID: " + changeSetId + " ." + e.getMessage());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Auto-draft replay endpoints (the PreMatching filter rewrites into these)
    // Expect body wrapper: { "action": "CREATE|UPDATE|DELETE", "rep": {...} }
    // ─────────────────────────────────────────────────────────────────────────
    @GET
    @Path("replay/{rest:.+}") @Consumes(MediaType.APPLICATION_JSON) @Produces(MediaType.APPLICATION_JSON)
    public Response replayGET(@PathParam("rest") String restPath, Map<String, Object> wrapper)   { return replayRouter(restPath, "GET",   wrapper); }

    @POST
    @Path("replay/{rest:.+}") @Consumes(MediaType.APPLICATION_JSON) @Produces(MediaType.APPLICATION_JSON)
    public Response replayPost(@PathParam("rest") String restPath, Map<String, Object> wrapper)   { return replayRouter(restPath, "POST",   wrapper); }

    @jakarta.ws.rs.PUT
    @Path("replay/{rest:.+}") @Consumes(MediaType.APPLICATION_JSON) @Produces(MediaType.APPLICATION_JSON)
    public Response replayPut(@PathParam("rest") String restPath, Map<String, Object> wrapper)    { return replayRouter(restPath, "PUT",    wrapper); }

    @PATCH
    @Path("replay/{rest:.+}") @Consumes(MediaType.APPLICATION_JSON) @Produces(MediaType.APPLICATION_JSON)
    public Response replayPatch(@PathParam("rest") String restPath, Map<String, Object> wrapper)  { return replayRouter(restPath, "PATCH",  wrapper); }

    @jakarta.ws.rs.DELETE
    @Path("replay/{rest:.+}") @Consumes(MediaType.APPLICATION_JSON) @Produces(MediaType.APPLICATION_JSON)
    public Response replayDelete(@PathParam("rest") String restPath, Map<String, Object> wrapper) { return replayRouter(restPath, "DELETE", wrapper); }

    private Response replayRouter(String restPath, String httpMethod, Map<String, Object> wrapper) {
        try {
            auth.realm().requireManageRealm();

            String action = string(wrapper.get("action"));
            if (action.isBlank()) action = httpToAction(httpMethod);

            @SuppressWarnings("unchecked")
            Map<String, Object> rep = asMap(wrapper.get("rep"));
            if (rep == null) rep = Map.of();

            EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
            String changeSetId = stageDraftFromRestPath(em, restPath, action, rep);

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("changeSetId", changeSetId);
            out.put("action", action);
            out.put("path", restPath);
            return Response.accepted(out).build(); // 202 Accepted
        } catch (BadRequestException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
        } catch (Exception e) {
            LOG.errorf(e, "Replay staging failed for path=%s", restPath);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(e.getMessage()).build();
        }
    }

    /**
     * Decide the change-set "type" from admin subpath and stage a draft via helper hooks.
     * Uses the helper you added in BasicIGAUtils first; falls back to an optional adapter if present.
     */
    private String stageDraftFromRestPath(EntityManager em, String restPath, String action, Map<String, Object> rep) throws Exception {
        String[] seg = (restPath == null ? "" : restPath).split("/");
        if (seg.length == 0 || seg[0].isBlank()) {
            throw new BadRequestException("Invalid replay path");
        }

        final String head = seg[0];
        final String type;
        switch (head) {
            case "roles":
            case "roles-by-id":
                type = "ROLE"; break;
            case "groups":
                type = "GROUP"; break;
            case "clients":
                type = "CLIENT"; break;
            case "client-scopes":
                type = "CLIENT_SCOPE"; break;
            case "users":
                type = restPath.contains("/role-mappings") ? "USER_ROLE_MAPPING" : "USER";
                break;
            case "realm":
                type = "REALM_SETTINGS"; break;
            default:
                throw new BadRequestException("Unsupported replay path: " + head);
        }

        // Prefer your new helper first
        String id = tryStageViaReflection(
                "org.tidecloak.base.iga.utils.BasicIGAUtils",
                "stageFromRep",
                new Class[]{KeycloakSession.class, RealmModel.class, EntityManager.class, String.class, String.class, Map.class},
                new Object[]{session, realm, em, type, action, rep}
        );
        if (id != null) return id;

        // Optional: if you later add a generic adapter
        id = tryStageViaReflection(
                "org.tidecloak.base.iga.interfaces.ChangesetRequestAdapter",
                "stageFromRep",
                new Class[]{KeycloakSession.class, RealmModel.class, EntityManager.class, String.class, String.class, Map.class},
                new Object[]{session, realm, em, type, action, rep}
        );
        if (id != null) return id;

        // Optional specialized hook if you expose one for user role mappings
        if ("USER_ROLE_MAPPING".equals(type)) {
            id = tryStageViaReflection(
                    "org.tidecloak.base.iga.utils.BasicIGAUtils",
                    "stageUserRoleMappingDraft",
                    new Class[]{KeycloakSession.class, RealmModel.class, EntityManager.class, String.class, Map.class},
                    new Object[]{session, realm, em, action, rep}
            );
            if (id != null) return id;
        }

        throw new BadRequestException(
                "Replay staging not wired for type=" + type + ". " +
                        "Implement one of:\n" +
                        " - BasicIGAUtils.stageFromRep(KeycloakSession, RealmModel, EntityManager, String type, String action, Map<String,Object> rep)\n" +
                        ("USER_ROLE_MAPPING".equals(type)
                                ? " - BasicIGAUtils.stageUserRoleMappingDraft(KeycloakSession, RealmModel, EntityManager, String action, Map<String,Object> rep)\n"
                                : "") +
                        " - ChangesetRequestAdapter.stageFromRep(KeycloakSession, RealmModel, EntityManager, String type, String action, Map<String,Object> rep)"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Sign
    // ─────────────────────────────────────────────────────────────────────────
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("change-set/sign")
    public Response signChangeset(ChangeSetRequest changeSet) {
        try {
            List<String> result = signChangeSets(Collections.singletonList(changeSet));
            return Response.ok(result.get(0)).build();
        } catch (Exception ex) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(ex.getMessage()).build();
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("change-set/sign/batch")
    public Response signMultipleChangeSets(ChangeSetRequestList changeSets) {
        try {
            List<String> result = signChangeSets(changeSets.getChangeSets());
            return Response.ok(M.writeValueAsString(result)).build();
        } catch (Exception ex) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(ex.getMessage()).build();
        }
    }

    public List<String> signChangeSets(List<ChangeSetRequest> changeSets) throws Exception {
        auth.realm().requireManageRealm();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        RealmModel realm = session.getContext().getRealm();
        var signer = org.tidecloak.base.iga.ChangeSetSigner.ChangeSetSignerFactory.getSigner(session);

        List<String> signedJsonList = new ArrayList<>();
        for (ChangeSetRequest changeSet : changeSets) {
            Object draftRecordEntity = BasicIGAUtils
                    .fetchDraftRecordEntityByRequestId(em, changeSet.getType(), changeSet.getChangeSetId())
                    .stream().findFirst().orElse(null);
            if (draftRecordEntity == null)
                throw new BadRequestException("Unsupported change set type for ID: " + changeSet.getChangeSetId());
            Response singleResp = signer.sign(changeSet, em, session, realm, draftRecordEntity, auth.adminAuth());
            signedJsonList.add(singleResp.readEntity(String.class));
        }
        return signedJsonList;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Commit
    // ─────────────────────────────────────────────────────────────────────────
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("change-set/commit")
    public Response commitChangeSet(ChangeSetRequest change) {
        try {
            return commitChangeSets(Collections.singletonList(change));
        } catch (Exception ex) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(ex.getMessage()).build();
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("change-set/commit/batch")
    public Response commitMultipleChangeSets(ChangeSetRequestList changeSets) {
        try {
            return commitChangeSets(changeSets.getChangeSets());
        } catch (Exception ex) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(ex.getMessage()).build();
        }
    }

    private Response commitChangeSets(List<ChangeSetRequest> changeSets) throws Exception {
        auth.realm().requireManageRealm();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        RealmModel realm = session.getContext().getRealm();

        for (ChangeSetRequest changeSet : changeSets) {
            Object draftRecordEntity = BasicIGAUtils
                    .fetchDraftRecordEntityByRequestId(em, changeSet.getType(), changeSet.getChangeSetId())
                    .stream().findFirst().orElse(null);
            if (draftRecordEntity == null) {
                return Response.status(Response.Status.BAD_REQUEST).entity("Unsupported change set type").build();
            }
            ChangeSetCommitter committer = ChangeSetCommitterFactory.getCommitter(session);
            committer.commit(changeSet, em, session, realm, draftRecordEntity, auth.adminAuth());
        }
        return Response.ok("Change sets approved and committed").build();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────
    private Response buildResponse(int status, String message) {
        return Response.status(status).entity(message).type(MediaType.TEXT_PLAIN).build();
    }

    private static String string(Object o) { return o == null ? "" : String.valueOf(o).trim(); }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object o) {
        return (o instanceof Map<?, ?> m) ? (Map<String, Object>) m : null;
    }

    private static String httpToAction(String method) {
        return switch (method) {
            case "POST" -> "CREATE";
            case "PUT", "PATCH" -> "UPDATE";
            case "DELETE" -> "DELETE";
            default -> "NONE";
        };
    }

    /**
     * Try to invoke a static staging helper via reflection:
     *   String method(...args) → returns changeSetId or null
     */
    private static String tryStageViaReflection(String fqcn, String method, Class<?>[] sig, Object[] args) {
        try {
            Class<?> cls = Class.forName(fqcn);
            var m = cls.getMethod(method, sig);
            Object out = m.invoke(null, args);
            if (out == null) return null;
            String s = String.valueOf(out);
            return s.isBlank() ? null : s;
        } catch (ClassNotFoundException | NoSuchMethodException e) {
            // helper not present – ignore
            return null;
        } catch (Throwable t) {
            // present but failed → surface so you can fix the helper
            throw new RuntimeException("Error in " + fqcn + "." + method + ": " + t.getMessage(), t);
        }
    }
}
