package org.tidecloak.base.iga.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.persistence.EntityManager;
import jakarta.ws.rs.BadRequestException;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.*;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.base.iga.interfaces.ChangesetRequestAdapter;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.shared.models.UserContext;
import org.tidecloak.tide.replay.ReplayMetaStore;
import org.tidecloak.tide.replay.UserContextPolicyHashUtil;

import java.io.UncheckedIOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import static org.tidecloak.base.iga.interfaces.ChangesetRequestAdapter.getChangeSetStatus;

public class BasicIGAUtils {

    private static final ObjectMapper M = new ObjectMapper();

    // ─────────────────────────────────────────────────────────────────────────
    // New-engine primitives (envelope + proofs; no Tide draft wrapper deps)
    // ─────────────────────────────────────────────────────────────────────────

    /** Look up the replay envelope (ChangesetRequestEntity) by (type,id). */
    public static ChangesetRequestEntity getEnvelope(EntityManager em,
                                                     ChangeSetType type,
                                                     String changeSetId) {
        if (em == null || type == null || changeSetId == null || changeSetId.isBlank()) return null;
        return em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(changeSetId, type));
    }

    /** Convenience overload. */
    public static ChangesetRequestEntity getEnvelope(EntityManager em, ChangeSetRequest req) {
        return (req == null) ? null : getEnvelope(em, req.getType(), req.getChangeSetId());
    }

    /**
     * Resolve changeSetId:
     * 1) From ChangeSetRequest (preferred)
     * 2) From ChangesetRequestEntity
     * 3) Best-effort via common getters/fields (legacy)
     */
    public static String resolveChangeSetId(ChangeSetRequest changeSet, Object maybeDraftOrEnv) {
        if (changeSet != null && notBlank(changeSet.getChangeSetId())) return changeSet.getChangeSetId();

        if (maybeDraftOrEnv instanceof ChangesetRequestEntity env) {
            return env.getChangesetRequestId();
        }

        if (maybeDraftOrEnv != null) {
            String[] getters = {"getChangeSetId","getChangeRequestId","getReplayId","getRecordId","getId"};
            for (String g : getters) {
                try {
                    Method m = maybeDraftOrEnv.getClass().getMethod(g);
                    Object v = m.invoke(maybeDraftOrEnv);
                    if (v != null && notBlank(String.valueOf(v))) return String.valueOf(v);
                } catch (NoSuchMethodException ignored) {
                } catch (Throwable t) {
                    throw new RuntimeException("Failed resolving changeSetId via " + g + ": " + t.getMessage(), t);
                }
            }
            String[] fields = {"changeSetId","changeRequestId","replayId","recordId","id"};
            for (String f : fields) {
                try {
                    Field fld = maybeDraftOrEnv.getClass().getDeclaredField(f);
                    fld.setAccessible(true);
                    Object v = fld.get(maybeDraftOrEnv);
                    if (v != null && notBlank(String.valueOf(v))) return String.valueOf(v);
                } catch (NoSuchFieldException ignored) {
                } catch (Throwable t) {
                    throw new RuntimeException("Failed resolving changeSetId via field " + f + ": " + t.getMessage(), t);
                }
            }
        }
        return null;
    }

    /** Legacy shim (if some code still calls it). */
    public static String getEntityChangeRequestId(Object legacyDraftOrEnv) {
        return resolveChangeSetId(null, legacyDraftOrEnv);
    }

    /** Update *envelope* status via the central adapter. */
    public static DraftStatus updateEnvelopeStatus(KeycloakSession session,
                                                   EntityManager em,
                                                   ChangeSetType type,
                                                   String changeSetId,
                                                   ActionType actionType) throws Exception {
        if (type == null || !notBlank(changeSetId)) {
            throw new BadRequestException("Missing change set type/id.");
        }
        DraftStatus status = getChangeSetStatus(session, changeSetId, type);
        ChangesetRequestEntity env = getEnvelope(em, type, changeSetId);
        if (env != null) {
            // If you persist status on the envelope, do it here (no-op by default).
            em.merge(env);
        }
        return status;
    }

    /** Is this an authority assignment? (new engine: keyed by changeSetId via ReplayMetaStore) */
    public static boolean isAuthorityAssignment(KeycloakSession session, Object draftOrEnv, EntityManager em) {
        String csId = resolveChangeSetId(null, draftOrEnv);
        if (!notBlank(csId)) return false;
        String initCertCompact = getDraftRoleInitCert(session, csId);
        return notBlank(initCertCompact);
    }

    /** Retrieve compact AP/init-cert currently staged for this changeSetId (via ReplayMetaStore). */
    public static String getDraftRoleInitCert(final KeycloakSession session, final String changeSetId) {
        return ReplayMetaStore.getRoleInitCert(session, changeSetId);
    }

    /** Load proofs for a given changeSetId and (possibly related) types. */
    public static List<AccessProofDetailEntity> getAccessProofs(EntityManager em, String recordId, ChangeSetType changeSetType) {
        if (em == null || !notBlank(recordId) || changeSetType == null) return List.of();

        List<ChangeSetType> types = new ArrayList<>();
        if (changeSetType == ChangeSetType.COMPOSITE_ROLE || changeSetType == ChangeSetType.DEFAULT_ROLES) {
            types.add(ChangeSetType.DEFAULT_ROLES);
            types.add(ChangeSetType.COMPOSITE_ROLE);
        } else if (changeSetType == ChangeSetType.CLIENT_FULLSCOPE || changeSetType == ChangeSetType.CLIENT_DEFAULT_USER_CONTEXT) {
            types.add(ChangeSetType.CLIENT_DEFAULT_USER_CONTEXT);
            types.add(ChangeSetType.CLIENT_FULLSCOPE);
        } else {
            types.add(changeSetType);
        }

        return em.createNamedQuery("getProofDetailsForDraftByChangeSetTypesAndId", AccessProofDetailEntity.class)
                .setParameter("recordId", recordId)
                .setParameter("changesetTypes", types)
                .getResultStream()
                .collect(Collectors.toList());
    }

    /** Sort proofs: “admins” (UC.allow has sha256:* OR legacy InitCertHash) first, then normal users. */
    public static List<AccessProofDetailEntity> sortAccessProof(List<AccessProofDetailEntity> proofs) {
        if (proofs == null || proofs.isEmpty()) return List.of();

        Stream<AccessProofDetailEntity> admin = proofs.stream().filter(p -> {
            String json = p.getProofDraft();
            if (UserContextPolicyHashUtil.isAllowAnySha256(json)) return true;
            UserContext uc = new UserContext(json);
            return uc.getInitCertHash() != null; // legacy admin shape
        });

        Stream<AccessProofDetailEntity> normal = proofs.stream().filter(p -> {
            String json = p.getProofDraft();
            if (UserContextPolicyHashUtil.isAllowAnySha256(json)) return false;
            UserContext uc = new UserContext(json);
            return uc.getInitCertHash() == null;
        });

        return Stream.concat(admin, normal).toList();
    }

    /** Basic flag read. */
    public static boolean isIGAEnabled(RealmModel realm) {
        String v = (realm == null) ? null : realm.getAttribute("isIGAEnabled");
        return v != null && v.equalsIgnoreCase("true");
    }

    /** Approval helper used only when NO Tide keys exist in the realm. */
    public static void approveChangeRequest(KeycloakSession session,
                                            UserModel adminUser,
                                            List<AccessProofDetailEntity> proofDetails,
                                            EntityManager em,
                                            ChangeSetRequest changeSet) throws Exception {

        RealmModel realm = session.getContext().getRealm();
        ClientModel realmMgmt = session.clients().getClientByClientId(realm, org.keycloak.models.Constants.REALM_MANAGEMENT_CLIENT_ID);
        RoleModel realmAdminRole = session.roles().getClientRole(realmMgmt, AdminRoles.REALM_ADMIN);

        int adminCount = ChangesetRequestAdapter.getNumberOfActiveAdmins(session, realm, realmAdminRole, em);
        boolean isTemp = "true".equalsIgnoreCase(adminUser.getFirstAttribute("is_temporary_admin"));

        ComponentModel tideKey = realm.getComponentsStream()
                .filter(x -> "tide-vendor-key".equals(x.getProviderId()))
                .findFirst()
                .orElse(null);

        if (tideKey != null) {
            throw new BadRequestException("This method can only be run without Tide keys.");
        }
        if (isTemp && adminCount > 0) {
            throw new BadRequestException("Temporary admin cannot approve when realm-admins exist. User: " + adminUser.getId());
        }
        if (!isTemp && !adminUser.hasRole(realmAdminRole)) {
            throw new BadRequestException("User is not authorized to approve requests.");
        }

        for (AccessProofDetailEntity pd : proofDetails) {
            pd.setSignature(adminUser.getId());
        }

        ChangesetRequestAdapter.saveAdminAuthorizaton(
                session,
                changeSet.getType().name(),
                changeSet.getChangeSetId(),
                changeSet.getActionType().name(),
                adminUser,
                "", "", ""
        );
    }

    /**
     * Kept as no-op to avoid breaking older call sites that still pass a draft entity.
     * New engine: status should be updated on the envelope (use updateEnvelopeStatus).
     */
    public static void updateDraftStatus(ChangeSetType type, ActionType actionType, Object draftEntity) { /* no-op */ }

    // ─────────────────────────────────────────────────────────────────────────
    // Affected-user detection (used by authorizers to drop approver UC if not affected)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Determine if a given user is affected by the change described by a draft/env.
     * Heuristics:
     *  - If the draft targets a specific user (userId / target.userId / users[].id / users[] string), match it.
     *  - Realm- / client-wide changes (DEFAULT_ROLES, COMPOSITE_ROLE, CLIENT_FULLSCOPE, CLIENT_DEFAULT_USER_CONTEXT) → true.
     *  - Fallback: if the approver’s UC appears among the proofs for this changeSet, treat as affected.
     */
    public static boolean isUserAffectedByChange(Object draftOrEnv, String userId) {
        if (!notBlank(userId) || draftOrEnv == null) return false;

        // Try to recover changeSet type & id and envelope JSON
        ChangeSetType type = null;
        String csId = null;
        String draftJson = null;

        if (draftOrEnv instanceof ChangesetRequestEntity env) {
            type = env.getChangesetType();
            csId = env.getChangesetRequestId();
            draftJson = decodeMaybeBase64(env.getDraftRequest());
        } else if (draftOrEnv instanceof String s) {
            draftJson = decodeMaybeBase64(s);
        } else {
            // best-effort via getters
            csId = tryGetString(draftOrEnv, "getChangeSetId");
            if (!notBlank(csId)) csId = tryGetString(draftOrEnv, "getChangeRequestId");
            String typeStr = tryGetString(draftOrEnv, "getType");
            type = safeType(typeStr);
            if (draftJson == null) {
                draftJson = decodeMaybeBase64(tryGetString(draftOrEnv, "getDraftRequest"));
                if (!notBlank(draftJson)) draftJson = decodeMaybeBase64(tryGetString(draftOrEnv, "getPayload"));
            }
        }

        // Realm/client wide changes always affect approver
        if (type == ChangeSetType.DEFAULT_ROLES
                || type == ChangeSetType.COMPOSITE_ROLE
                || type == ChangeSetType.CLIENT_FULLSCOPE
                || type == ChangeSetType.CLIENT_DEFAULT_USER_CONTEXT) {
            return true;
        }

        // If we have JSON, inspect for targeted users
        if (notBlank(draftJson)) {
            try {
                JsonNode n = M.readTree(draftJson);

                // userId fields
                String one = optText(n, "userId");
                if (userId.equals(one)) return true;

                // { "target": { "userId": "..." } }
                JsonNode target = n.get("target");
                if (target != null) {
                    String tid = optText(target, "userId");
                    if (userId.equals(tid)) return true;
                }

                // { "user": { "id": "..." } }
                JsonNode user = n.get("user");
                if (user != null) {
                    String uid = optText(user, "id");
                    if (userId.equals(uid)) return true;
                }

                // flat "sub"/"subject"
                String sub = optText(n, "sub");
                if (userId.equals(sub)) return true;
                String subject = optText(n, "subject");
                if (userId.equals(subject)) return true;

                // arrays of users, either strings or objects with id field
                JsonNode arr = n.get("users");
                if (arr != null && arr.isArray()) {
                    for (JsonNode el : arr) {
                        if (el.isTextual() && userId.equals(el.asText())) return true;
                        String id = optText(el, "id");
                        if (userId.equals(id)) return true;
                        String u2 = optText(el, "userId");
                        if (userId.equals(u2)) return true;
                    }
                }

                // { "add":[{userId/id}], "remove":[{userId/id}] } patterns
                if (arrayContainsUser(n.get("add"), userId)) return true;
                if (arrayContainsUser(n.get("remove"), userId)) return true;

            } catch (Exception ignored) { /* fallthrough to fallback */ }
        }

        // Fallback left as false; callers already have proofs at hand if they want to infer further.
        return false;
    }

    private static boolean arrayContainsUser(JsonNode node, String userId) {
        if (node == null || !node.isArray()) return false;
        for (JsonNode el : node) {
            if (el.isTextual() && userId.equals(el.asText())) return true;
            String id = optText(el, "id");
            if (userId.equals(id)) return true;
            String u2 = optText(el, "userId");
            if (userId.equals(u2)) return true;
        }
        return false;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Replay staging entrypoints (reflection to your adapter)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Generic staging entrypoint used by the /tide-admin/replay/* endpoint.
     * Tries, in order:
     *   1) ChangesetRequestAdapter.stageFromRep(session, realm, em, String type, String action, Map rep)
     *   2) ChangesetRequestAdapter.stageFromRep(session, realm, em, ChangeSetType, ActionType, Map rep)
     *
     * Return value MUST be the changeSetId (String).
     */
    public static String stageFromRep(KeycloakSession session,
                                      RealmModel realm,
                                      EntityManager em,
                                      String type,
                                      String action,
                                      Map<String, Object> rep) throws Exception {

        // 1) String signature (preferred)
        String out = tryStageViaReflection(
                "org.tidecloak.base.iga.interfaces.ChangesetRequestAdapter",
                "stageFromRep",
                new Class<?>[]{ KeycloakSession.class, RealmModel.class, EntityManager.class, String.class, String.class, Map.class },
                new Object[]{ session, realm, em, type, action, rep }
        );
        if (notBlank(out)) return out;

        // 2) Enum signature (fallback)
        ChangeSetType cst = safeType(type);
        ActionType act    = safeAction(action);
        out = tryStageViaReflection(
                "org.tidecloak.base.iga.interfaces.ChangesetRequestAdapter",
                "stageFromRep",
                new Class<?>[]{ KeycloakSession.class, RealmModel.class, EntityManager.class, ChangeSetType.class, ActionType.class, Map.class },
                new Object[]{ session, realm, em, cst, act, rep }
        );
        if (notBlank(out)) return out;

        throw new BadRequestException(
                "Replay staging not wired for type=" + type + ". " +
                        "Implement ChangesetRequestAdapter.stageFromRep(...) with either " +
                        "(KeycloakSession, RealmModel, EntityManager, String, String, Map) or " +
                        "(KeycloakSession, RealmModel, EntityManager, ChangeSetType, ActionType, Map)."
        );
    }

    /**
     * Optional specialization used by some flows for user↔role mapping drafts.
     * If absent, routes back to stageFromRep with a canonical USER_ROLE_MAPPING tag.
     */
    public static String stageUserRoleMappingDraft(KeycloakSession session,
                                                   RealmModel realm,
                                                   EntityManager em,
                                                   String action,
                                                   Map<String, Object> rep) throws Exception {
        String out = tryStageViaReflection(
                "org.tidecloak.base.iga.interfaces.ChangesetRequestAdapter",
                "stageUserRoleMappingDraft",
                new Class<?>[]{ KeycloakSession.class, RealmModel.class, EntityManager.class, String.class, Map.class },
                new Object[]{ session, realm, em, action, rep }
        );
        if (notBlank(out)) return out;

        return stageFromRep(session, realm, em, "USER_ROLE_MAPPING", action, rep);
    }

    private static String tryStageViaReflection(String fqcn, String method, Class<?>[] sig, Object[] args) {
        try {
            Class<?> cls = Class.forName(fqcn);
            Method m = cls.getMethod(method, sig);
            Object result = m.invoke(null, args);
            return (result == null) ? null : String.valueOf(result);
        } catch (ClassNotFoundException | NoSuchMethodException e) {
            return null; // helper not present — try next shape
        } catch (Throwable t) {
            throw new RuntimeException("Error in " + fqcn + "." + method + ": " + t.getMessage(), t);
        }
    }

    private static ChangeSetType safeType(String t) {
        if (!notBlank(t)) return null;
        String s = t.trim().toUpperCase(Locale.ROOT)
                .replace('-', '_')
                .replace(' ', '_');
        try { return ChangeSetType.valueOf(s); }
        catch (IllegalArgumentException ex) { return null; }
    }

    private static ActionType safeAction(String a) {
        if (!notBlank(a)) return null;
        String s = a.trim().toUpperCase(Locale.ROOT);
        try { return ActionType.valueOf(s); }
        catch (IllegalArgumentException ex) {
            if ("POST".equalsIgnoreCase(s)) return ActionType.CREATE;
            if ("PUT".equalsIgnoreCase(s) || "PATCH".equalsIgnoreCase(s)) return ActionType.UPDATE;
            if ("DELETE".equalsIgnoreCase(s)) return ActionType.DELETE;
            return null;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // JSON helpers
    // ─────────────────────────────────────────────────────────────────────────

    /** Shallow, idempotent merge for JWT-like objects. */
    public static void mergeInPlace(ObjectNode mainNode, ObjectNode update) {
        Iterator<Map.Entry<String, JsonNode>> fields = update.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            String key = entry.getKey();
            JsonNode value = entry.getValue();

            if (!mainNode.has(key)) {
                mainNode.set(key, value);
            } else {
                JsonNode existing = mainNode.get(key);
                if (existing.isObject() && value.isObject()) {
                    mergeInPlace((ObjectNode) existing, (ObjectNode) value);
                } else if (existing.isArray() && value.isArray()) {
                    ArrayNode array = (ArrayNode) existing;
                    Set<JsonNode> seen = new LinkedHashSet<>();
                    array.forEach(seen::add);
                    value.forEach(seen::add);
                    array.removeAll();
                    seen.forEach(array::add);
                } else if ("aud".equalsIgnoreCase(key)) {
                    ArrayNode merged = JsonNodeFactory.instance.arrayNode();
                    Stream<JsonNode> fromExisting = asStream(existing);
                    Stream<JsonNode> fromUpdate   = asStream(value);
                    Set<JsonNode> seen = new LinkedHashSet<>();
                    Stream.concat(fromExisting, fromUpdate).forEach(seen::add);
                    seen.forEach(merged::add);
                    merged.add(mainNode.get("azp"));
                    mainNode.set(key, merged);
                }
            }
        }
    }

    private static Stream<JsonNode> asStream(JsonNode node) {
        if (node != null && node.isArray()) {
            return StreamSupport.stream(node.spliterator(), false);
        }
        return Stream.ofNullable(node);
    }

    public static ObjectNode parseNode(ObjectMapper objectMapper, String json) {
        try {
            return (ObjectNode) objectMapper.readTree(json);
        } catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Optional helpers referenced by authorizers (reflection-safe entrypoints)
    // These parse the envelope’s draftRequest JSON to discover target role/AP.
    // ─────────────────────────────────────────────────────────────────────────

    /** Attempt to resolve the *target role id* from a draft/env object. */
    public static String resolveTargetRoleIdFromDraft(Object draftOrEnv, EntityManager em) {
        if (draftOrEnv instanceof ChangesetRequestEntity env) {
            return extractRoleIdFromDraft(env.getDraftRequest());
        }
        if (draftOrEnv instanceof String json && notBlank(json)) {
            return extractRoleIdFromDraft(json);
        }
        String json = tryGetString(draftOrEnv, "getDraftRequest");
        if (!notBlank(json)) json = tryGetString(draftOrEnv, "getPayload");
        if (notBlank(json)) return extractRoleIdFromDraft(json);
        return null;
    }

    /** Attempt to resolve the *AP compact* from a draft/env object. */
    public static String resolveApCompactFromDraft(Object draftOrEnv, EntityManager em) {
        if (draftOrEnv instanceof ChangesetRequestEntity env) {
            return extractApCompactFromDraft(env.getDraftRequest());
        }
        if (draftOrEnv instanceof String json && notBlank(json)) {
            return extractApCompactFromDraft(json);
        }
        String json = tryGetString(draftOrEnv, "getDraftRequest");
        if (!notBlank(json)) json = tryGetString(draftOrEnv, "getPayload");
        if (notBlank(json)) return extractApCompactFromDraft(json);

        // Also accept AP staged into ReplayMetaStore keyed by changeSetId
        String csId = resolveChangeSetId(null, draftOrEnv);
        if (notBlank(csId)) {
            String ap = ReplayMetaStore.getRoleInitCert(null, csId); // session unused by your store impl
            if (notBlank(ap)) return ap;
        }
        return null;
    }

    private static String extractRoleIdFromDraft(String draftJsonB64OrPlain) {
        if (!notBlank(draftJsonB64OrPlain)) return null;
        String json = decodeMaybeBase64(draftJsonB64OrPlain);
        try {
            JsonNode n = M.readTree(json);
            String v = optText(n, "roleId");
            if (v != null) return v;
            JsonNode role = n.get("role");
            if (role != null) {
                v = optText(role, "id");
                if (v != null) return v;
            }
            JsonNode target = n.get("target");
            if (target != null) {
                v = optText(target, "roleId");
                if (v != null) return v;
            }
        } catch (Exception ignored) { }
        return null;
    }

    private static String extractApCompactFromDraft(String draftJsonB64OrPlain) {
        if (!notBlank(draftJsonB64OrPlain)) return null;
        String json = decodeMaybeBase64(draftJsonB64OrPlain);
        try {
            JsonNode n = M.readTree(json);
            String v = optText(n, "apCompact");
            if (v != null) return v;
            JsonNode ap = n.get("authorizerPolicy");
            if (ap != null) {
                v = optText(ap, "compact");
                if (v != null) return v;
            }
            v = optText(n, "ap");
            if (v != null) return v;
        } catch (Exception ignored) { }
        return null;
    }

    private static String decodeMaybeBase64(String s) {
        if (!notBlank(s)) return s;
        String t = s.trim();
        if (!t.startsWith("{") && !t.startsWith("[")) {
            try {
                byte[] raw = java.util.Base64.getDecoder().decode(t);
                String decoded = new String(raw, StandardCharsets.UTF_8);
                if (decoded.trim().startsWith("{") || decoded.trim().startsWith("[")) return decoded;
            } catch (IllegalArgumentException ignored) { }
        }
        return s;
    }

    private static String tryGetString(Object obj, String method) {
        if (obj == null) return null;
        try {
            Method m = obj.getClass().getMethod(method);
            Object out = m.invoke(obj);
            return (out == null) ? null : String.valueOf(out);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static String optText(JsonNode n, String field) {
        if (n == null) return null;
        JsonNode v = n.get(field);
        return (v != null && v.isTextual()) ? v.asText() : null;
    }

    private static boolean notBlank(String s) {
        return s != null && !s.isBlank();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Small POJO still used by callers
    // ─────────────────────────────────────────────────────────────────────────
    public static class UserRecordKey {
        public final String draftId;
        public final String username;
        public final String clientId;

        public UserRecordKey(String draftId, String username, String clientId) {
            this.draftId = draftId;
            this.username = username;
            this.clientId = clientId;
        }
        @Override public boolean equals(Object o) {
            if (!(o instanceof UserRecordKey k)) return false;
            return Objects.equals(draftId, k.draftId)
                    && Objects.equals(username, k.username)
                    && Objects.equals(clientId, k.clientId);
        }
        @Override public int hashCode() {
            return Objects.hash(draftId, username, clientId);
        }
    }
}
