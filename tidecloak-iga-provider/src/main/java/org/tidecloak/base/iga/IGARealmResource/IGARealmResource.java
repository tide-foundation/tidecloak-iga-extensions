package org.tidecloak.base.iga.IGARealmResource;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.persistence.EntityManager;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.tidecloak.base.iga.ChangeSetCommitter.ChangeSetCommitter;
import org.tidecloak.base.iga.ChangeSetCommitter.ChangeSetCommitterFactory;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequestList;
import org.tidecloak.base.iga.UserContextBuilder;
import org.tidecloak.base.iga.interfaces.ChangesetRequestAdapter;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.jpa.entities.AdminAuthorizationEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.shared.enums.ChangeSetType;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.Base64;

/**
 * Mounted by the admin-realm-restapi-extension factory (id: tide-admin).
 *
 * Endpoints:
 *  - POST   toggle-iga
 *  - POST   add-rejection
 *  - GET/POST/PUT/PATCH/DELETE replay/{rest:.+}
 *  - POST   change-set/sign
 *  - POST   change-set/sign/batch
 *  - POST   change-set/commit
 *  - POST   change-set/commit/batch
 *  - GET/POST change-set/{scope}/requests
 *  - GET     change-set/{scope}/requests/{id}
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
    // Auto-draft replay endpoints
    // ─────────────────────────────────────────────────────────────────────────
    @GET
    @Path("replay/{rest:.+}") @Consumes(MediaType.APPLICATION_JSON) @Produces(MediaType.APPLICATION_JSON)
    public Response replayGET(@PathParam("rest") String restPath, Object body)   { return replayRouter(restPath, "GET",   body); }

    @POST
    @Path("replay/{rest:.+}") @Consumes(MediaType.APPLICATION_JSON) @Produces(MediaType.APPLICATION_JSON)
    public Response replayPost(@PathParam("rest") String restPath, Object body)  { return replayRouter(restPath, "POST",  body); }

    @jakarta.ws.rs.PUT
    @Path("replay/{rest:.+}") @Consumes(MediaType.APPLICATION_JSON) @Produces(MediaType.APPLICATION_JSON)
    public Response replayPut(@PathParam("rest") String restPath, Object body)   { return replayRouter(restPath, "PUT",   body); }

    @PATCH
    @Path("replay/{rest:.+}") @Consumes(MediaType.APPLICATION_JSON) @Produces(MediaType.APPLICATION_JSON)
    public Response replayPatch(@PathParam("rest") String restPath, Object body) { return replayRouter(restPath, "PATCH", body); }

    @jakarta.ws.rs.DELETE
    @Path("replay/{rest:.+}") @Consumes(MediaType.APPLICATION_JSON) @Produces(MediaType.APPLICATION_JSON)
    public Response replayDelete(@PathParam("rest") String restPath, Object body){ return replayRouter(restPath, "DELETE", body); }

    @SuppressWarnings("unchecked")
    private Response replayRouter(String restPath, String httpMethod, Object body) {
        try {
            auth.realm().requireManageRealm();

            String action = httpToAction(httpMethod);

            // Do NOT stage on GET/reads — prevents empty envelopes like {"roles":[]}
            if ("NONE".equals(action)) {
                return Response.status(Response.Status.NO_CONTENT).build();
            }

            Map<String,Object> rep = Map.of(); // default empty

            if (body == null) {
                // keep defaults
            } else if (body instanceof Map<?,?> m) {
                Object maybeAction = m.get("action");
                Object maybeRep    = m.get("rep");

                if (maybeAction != null) action = String.valueOf(maybeAction);
                if (maybeRep instanceof Map<?,?> rm) {
                    rep = (Map<String, Object>) rm;
                } else if (maybeRep instanceof List<?> rl) {
                    rep = Map.of("roles", rl);
                } else if (maybeRep == null) {
                    rep = (Map<String, Object>) m;
                } else {
                    rep = M.convertValue(maybeRep, Map.class);
                }

            } else if (body instanceof List<?> list) {
                rep = Map.of("roles", list);

            } else {
                var node = M.valueToTree(body);
                if (node.isArray()) {
                    rep = Map.of("roles", M.convertValue(node, List.class));
                } else if (node.isObject()) {
                    rep = M.convertValue(node, Map.class);
                }
            }

            // Stamp who requested this draft
            try {
                String requesterId = auth.adminAuth().getUser().getId();
                rep = put(rep, "_requestedBy", requesterId);
            } catch (Throwable ignored) {}

            EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
            String changeSetId = stageDraftFromRestPath(em, restPath, action, rep);

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("changeSetId", changeSetId);
            out.put("action", action);
            out.put("path", restPath);
            return Response.accepted(out).build(); // 202 Accepted

        } catch (BadRequestException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error","bad_request", "error_description", e.getMessage()))
                    .build();
        } catch (Exception e) {
            LOG.errorf(e, "Replay staging failed for path=%s", restPath);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of("error","unknown_error", "error_description", e.getMessage()))
                    .build();
        }
    }

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

        // Enrich USER_ROLE_MAPPING envelopes with path-derived fields
        if ("USER_ROLE_MAPPING".equals(type)) {
            rep = put(rep, "_replayPath", restPath);
            String[] parts = (restPath == null ? "" : restPath).split("/");
            for (int i = 0; i < parts.length; i++) {
                if ("users".equals(parts[i]) && i + 1 < parts.length) {
                    rep = put(rep, "userId", parts[i + 1]);
                }
                if ("clients".equals(parts[i]) && i + 1 < parts.length) {
                    rep = put(rep, "clientId", parts[i + 1]);
                }
            }
        }

        String id = tryStageViaReflection(
                "org.tidecloak.base.iga.utils.BasicIGAUtils",
                "stageFromRep",
                new Class[]{KeycloakSession.class, RealmModel.class, EntityManager.class, String.class, String.class, Map.class},
                new Object[]{session, realm, em, type, action, rep}
        );
        if (id != null) return id;

        id = tryStageViaReflection(
                "org.tidecloak.base.iga.interfaces.ChangesetRequestAdapter",
                "stageFromRep",
                new Class[]{KeycloakSession.class, RealmModel.class, EntityManager.class, String.class, String.class, Map.class},
                new Object[]{session, realm, em, type, action, rep}
        );
        if (id != null) return id;

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
            Object envelope = BasicIGAUtils.getEnvelope(em, changeSet);
            if (envelope == null) {
                throw new BadRequestException("No envelope found for " + changeSet.getType() + " / " + changeSet.getChangeSetId());
            }
            Response singleResp = signer.sign(changeSet, em, session, realm, envelope, auth.adminAuth());
            signedJsonList.add(singleResp.readEntity(String.class));
        }
        return signedJsonList;
    }

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
            Object envelope = BasicIGAUtils.getEnvelope(em, changeSet);
            if (envelope == null) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("No envelope found for " + changeSet.getType() + " / " + changeSet.getChangeSetId())
                        .build();
            }
            ChangeSetCommitter committer = ChangeSetCommitterFactory.getCommitter(session);
            committer.commit(changeSet, em, session, realm, envelope, auth.adminAuth());
        }
        return Response.ok("Change sets approved and committed").build();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Change-set listing & details for Admin UI
    // ─────────────────────────────────────────────────────────────────────────
    @GET
    @Path("change-set/{scope}/requests")
    @Produces(MediaType.APPLICATION_JSON)
    public Response listChangeSetRequests(@PathParam("scope") String scope) {
        try {
            auth.realm().requireViewRealm();

            var type = mapScopeToChangeSetType(scope);
            if (type == null) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(Map.of("error","bad_scope","error_description","Unsupported scope: " + scope))
                        .build();
            }

            EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

            List<ChangesetRequestEntity> rows = em.createQuery(
                            "SELECT c FROM ChangesetRequestEntity c WHERE c.changesetType = :t ORDER BY c.timestamp DESC",
                            ChangesetRequestEntity.class)
                    .setParameter("t", type)
                    .getResultList();

            List<Map<String,Object>> out = new ArrayList<>(rows.size());
            for (var c : rows) {
                var status = ChangesetRequestAdapter.getChangeSetStatus(session, c.getChangesetRequestId(), c.getChangesetType());
                long approvals  = c.getAdminAuthorizations().stream().filter(AdminAuthorizationEntity::getIsApproval).count();
                long rejections = c.getAdminAuthorizations().size() - approvals;

                Map<String,Object> dto = new LinkedHashMap<>();
                dto.put("changeSetId",  c.getChangesetRequestId());
                dto.put("type",         c.getChangesetType().name());
                dto.put("status",       status.name());
                dto.put("approvals",    approvals);
                dto.put("rejections",   rejections);
                dto.put("timestamp",    c.getTimestamp());
                dto.put("draft",        c.getDraftRequest());

                // Requested by (from draft)
                attachRequestedBy(dto, c.getDraftRequest());

                // Affected users & preview
                var preview = computePreviewForEnvelope(c);
                dto.put("affectedUsers", preview.affectedUsers);
                dto.put("userContextsPreview", preview.userContextsPreview);
                dto.put("affectedUsersDetailed", resolveUsers(preview.affectedUsers));

                // Rich authorization history
                attachAuthorizationHistory(dto, c.getAdminAuthorizations());

                out.add(dto);
            }

            return Response.ok(out).build();
        } catch (Exception e) {
            LOG.errorf(e, "Failed to list change-set requests for scope=%s", scope);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of("error","unknown_error","error_description", e.getMessage()))
                    .build();
        }
    }

    @POST
    @Path("change-set/{scope}/requests")
    @Produces(MediaType.APPLICATION_JSON)
    public Response listChangeSetRequestsPOST(@PathParam("scope") String scope) {
        return listChangeSetRequests(scope);
    }

    @GET
    @Path("change-set/{scope}/requests/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getChangeSetRequest(@PathParam("scope") String scope, @PathParam("id") String id) {
        try {
            auth.realm().requireViewRealm();

            var type = mapScopeToChangeSetType(scope);
            if (type == null) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(Map.of("error","bad_scope","error_description","Unsupported scope: " + scope))
                        .build();
            }
            EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
            var env = BasicIGAUtils.getEnvelope(em, type, id);
            if (env == null) {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity(Map.of("error","not_found","error_description","No change-set found for id="+id))
                        .build();
            }

            var status = ChangesetRequestAdapter.getChangeSetStatus(session, env.getChangesetRequestId(), env.getChangesetType());
            long approvals  = env.getAdminAuthorizations().stream().filter(AdminAuthorizationEntity::getIsApproval).count();
            long rejections = env.getAdminAuthorizations().size() - approvals;

            Map<String,Object> dto = new LinkedHashMap<>();
            dto.put("changeSetId", env.getChangesetRequestId());
            dto.put("type",        env.getChangesetType().name());
            dto.put("status",      status.name());
            dto.put("approvals",   approvals);
            dto.put("rejections",  rejections);
            dto.put("timestamp",   env.getTimestamp());
            dto.put("draft",       env.getDraftRequest());

            // Requested by (from draft)
            attachRequestedBy(dto, env.getDraftRequest());

            // Add affected users + preview
            var preview = computePreviewForEnvelope(env);
            dto.put("affectedUsers", preview.affectedUsers);
            dto.put("userContextsPreview", preview.userContextsPreview);
            dto.put("affectedUsersDetailed", resolveUsers(preview.affectedUsers));

            // Rich authorization history
            attachAuthorizationHistory(dto, env.getAdminAuthorizations());

            return Response.ok(dto).build();
        } catch (Exception e) {
            LOG.errorf(e, "Failed to fetch change-set %s/%s", scope, id);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of("error","unknown_error","error_description", e.getMessage()))
                    .build();
        }
    }

    /** Map UI scope segment → ChangeSetType */
    private static ChangeSetType mapScopeToChangeSetType(String scope) {
        if (scope == null) return null;
        String s = scope.trim().toLowerCase(Locale.ROOT);
        switch (s) {
            case "users":
            case "user-role-mappings":
            case "role-mappings":
                return ChangeSetType.USER_ROLE_MAPPING;
            case "roles":          return ChangeSetType.ROLE;
            case "groups":         return ChangeSetType.GROUP;
            case "clients":        return ChangeSetType.CLIENT;
            case "client-scopes":  return ChangeSetType.CLIENT_SCOPE;
            case "realm":
            case "realm-settings": return ChangeSetType.REALM_SETTINGS;
            default: return null;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────
    private Response buildResponse(int status, String message) {
        return Response.status(status).entity(message).type(MediaType.TEXT_PLAIN).build();
    }

    private static String httpToAction(String method) {
        return switch (method) {
            case "POST" -> "CREATE";
            case "PUT", "PATCH" -> "UPDATE";
            case "DELETE" -> "DELETE";
            default -> "NONE";
        };
    }

    private static String tryStageViaReflection(String fqcn, String method, Class<?>[] sig, Object[] args) {
        try {
            Class<?> cls = Class.forName(fqcn);
            var m = cls.getMethod(method, sig);
            Object out = m.invoke(null, args);
            if (out == null) return null;
            String s = String.valueOf(out);
            return s.isBlank() ? null : s;
        } catch (ClassNotFoundException | NoSuchMethodException e) {
            return null;
        } catch (Throwable t) {
            throw new RuntimeException("Error in " + fqcn + "." + method + ": " + t.getMessage(), t);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String,Object> put(Map<String,Object> rep, String k, Object v) {
        if (!(rep instanceof LinkedHashMap)) {
            rep = new LinkedHashMap<>(rep);
        }
        ((Map<String,Object>)rep).put(k, v);
        return rep;
    }

    private static String decodeMaybeBase64(String s) {
        if (s == null || s.isBlank()) return s;
        String t = s.trim();
        if (!t.startsWith("{") && !t.startsWith("[")) {
            try {
                byte[] raw = Base64.getDecoder().decode(t);
                String decoded = new String(raw, StandardCharsets.UTF_8);
                if (decoded.trim().startsWith("{") || decoded.trim().startsWith("[")) return decoded;
            } catch (IllegalArgumentException ignored) { }
        }
        return s;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Affected users & preview computation
    // ─────────────────────────────────────────────────────────────────────────
    private static final class Preview {
        final List<String> affectedUsers;
        final List<Map<String, Object>> userContextsPreview;
        Preview(List<String> u, List<Map<String,Object>> p) { this.affectedUsers = u; this.userContextsPreview = p; }
    }

    private Preview computePreviewForEnvelope(ChangesetRequestEntity env) {
        try {
            String draftJson = decodeMaybeBase64(env.getDraftRequest());
            String userId = null;
            String clientId = null;

            if (draftJson != null && !draftJson.isBlank()) {
                JsonNode n = M.readTree(draftJson);
                // Prefer explicit userId/clientId
                userId   = optText(n, "userId");
                clientId = optText(n, "clientId");

                // Fallback: parse from _replayPath if present
                if ((userId == null || userId.isBlank()) && n.has("_replayPath")) {
                    String rp = optText(n, "_replayPath");
                    if (rp != null) {
                        String[] parts = rp.split("/");
                        for (int i = 0; i < parts.length; i++) {
                            if ("users".equals(parts[i]) && i + 1 < parts.length) userId = parts[i + 1];
                            if ("clients".equals(parts[i]) && i + 1 < parts.length) clientId = parts[i + 1];
                        }
                    }
                }
            }

            List<String> affected = new ArrayList<>();
            List<Map<String,Object>> previews = new ArrayList<>();

            if (userId != null && !userId.isBlank()) {
                affected.add(userId);

                UserProvider users = session.users();
                UserModel user = users.getUserById(realm, userId);
                if (user != null) {
                    ClientModel client = resolveClient(clientId);

                    // BUILD WITH DELTA → applies realm/client role changes to the preview
                    ObjectNode ctx = UserContextBuilder.buildAccessTokenPreviewWithDelta(
                            session, realm, user, client, draftJson
                    );

                    Map<String,Object> one = new LinkedHashMap<>();
                    one.put("userId", userId);
                    one.put("clientId", client != null ? client.getId() : null);
                    one.put("context", ctx.toString());
                    previews.add(one);
                }
            }

            return new Preview(affected, previews);
        } catch (Exception e) {
            // Non-fatal – just return empty preview
            LOG.debugf(e, "Preview computation failed for envelope %s/%s",
                    env.getChangesetType(), env.getChangesetRequestId());
            return new Preview(List.of(), List.of());
        }
    }

    private ClientModel resolveClient(String clientIdMaybe) {
        if (clientIdMaybe == null || clientIdMaybe.isBlank()) return null;
        // Try as internal KC id first
        ClientModel c = session.clients().getClientById(realm, clientIdMaybe);
        if (c != null) return c;
        // Then try by clientId (alias)
        return session.clients().getClientByClientId(realm, clientIdMaybe);
    }

    private static String optText(JsonNode n, String field) {
        if (n == null) return null;
        JsonNode v = n.get(field);
        return (v != null && v.isTextual()) ? v.asText() : null;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Enrichment helpers: users, requestedBy, approvals/rejections
    // ─────────────────────────────────────────────────────────────────────────
    private Map<String, Object> resolveUserBasic(String userId) {
        if (userId == null || userId.isBlank()) return null;
        try {
            UserModel u = session.users().getUserById(realm, userId);
            if (u == null) return Map.of("id", userId);
            Map<String,Object> m = new LinkedHashMap<>();
            m.put("id", u.getId());
            m.put("username", u.getUsername());
            m.put("email", u.getEmail());
            m.put("firstName", u.getFirstName());
            m.put("lastName", u.getLastName());
            return m;
        } catch (Exception e) {
            return Map.of("id", userId);
        }
    }

    private List<Map<String,Object>> resolveUsers(List<String> ids) {
        if (ids == null) return List.of();
        List<Map<String,Object>> out = new ArrayList<>(ids.size());
        for (String id : ids) {
            var m = resolveUserBasic(id);
            if (m != null) out.add(m);
        }
        return out;
    }

    private static String jsonTextOrNull(com.fasterxml.jackson.databind.JsonNode n, String field) {
        if (n == null) return null;
        var v = n.get(field);
        return (v != null && v.isTextual()) ? v.asText() : null;
    }

    private void attachRequestedBy(Map<String,Object> dto, String draftRaw) {
        try {
            String draftJson = decodeMaybeBase64(draftRaw);
            String requestedById = null;
            if (draftJson != null && !draftJson.isBlank()) {
                var n = M.readTree(draftJson);
                requestedById = jsonTextOrNull(n, "_requestedBy");
            }
            if (requestedById != null) {
                dto.put("requestedBy", resolveUserBasic(requestedById));
            }
        } catch (Exception ignored) { }
    }

    private void attachAuthorizationHistory(Map<String,Object> dto, List<AdminAuthorizationEntity> authz) {
        List<Map<String,Object>> approvals = new ArrayList<>();
        List<Map<String,Object>> rejections = new ArrayList<>();
        if (authz != null) {
            for (var a : authz) {
                Map<String,Object> row = new LinkedHashMap<>();
                row.put("user", resolveUserBasic(a.getUserId()));
                if (Boolean.TRUE.equals(a.getIsApproval())) {
                    approvals.add(row);
                } else {
                    rejections.add(row);
                }
            }
        }
        dto.put("adminApprovals", approvals);
        dto.put("adminRejections", rejections);
    }
}
