package org.tidecloak.base.iga;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.rar.AuthorizationRequestContext;
import org.keycloak.representations.AccessToken;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Access-token preview that:
 *  1) Computes effective roles (realm + client) and applies a "delta" from draft JSON.
 *  2) Runs Keycloak TokenManager.transformAccessToken(...) so protocol mappers/scopes behave as KC would.
 *  3) Re-injects the computed roles AFTER transform so deltas are preserved.
 *  4) Normalizes client resource key to client alias (e.g. "broker") and prunes empty/null claims.
 *
 * Version-safe: avoids KC internals; inner ClientSessionContext has no @Override annotations.
 */
public final class UserContextBuilder {

    private static final ObjectMapper M = new ObjectMapper();

    private UserContextBuilder() {}

    /* ───────────────────── Back-compat API (used elsewhere) ───────────────────── */

    public static ObjectNode build(KeycloakSession session,
                                   RealmModel realm,
                                   UserModel user,
                                   ClientModel client) {
        return buildAccessTokenPreview(session, realm, user, client);
    }

    public static ObjectNode buildWithDelta(KeycloakSession session,
                                            RealmModel realm,
                                            UserModel user,
                                            ClientModel client,
                                            Map<String, Object> delta) {
        String draftJson = (delta == null || delta.isEmpty()) ? null : toJson(delta);
        return buildAccessTokenPreviewWithDelta(session, realm, user, client, draftJson);
    }

    public static void attachAuthorizerPolicies(KeycloakSession session,
                                                RealmModel realm,
                                                UserModel user,
                                                ClientModel client,
                                                ObjectNode ctx) {
        // No-op here; APs (if you want them) can be attached by the caller/UI.
    }

    /* ───────────────────────── Public preview API ───────────────────────── */

    public static ObjectNode buildAccessTokenPreview(KeycloakSession session,
                                                     RealmModel realm,
                                                     UserModel user,
                                                     ClientModel client) {
        return buildAccessTokenPreviewWithDelta(session, realm, user, client, null);
    }

    /**
     * @param draftJson optional JSON or Base64(JSON) with any of:
     *                  - "clientId" (alias) or "_replayPath" (/role-mappings/clients/{UUID})
     *                  - "roles": [ "name" ]                → REPLACE target scope
     *                  - "addRoles": [ "name" ], "removeRoles": [ "name" ] → MUTATE target scope
     */
    public static ObjectNode buildAccessTokenPreviewWithDelta(KeycloakSession session,
                                                              RealmModel realm,
                                                              UserModel user,
                                                              ClientModel client,
                                                              String draftJson) {
        // 1) Parse delta & normalize the client key to the client alias used in resource_access
        Delta delta = Delta.parse(draftJson, client);

        // 2) Compute base effective roles and apply delta
        Set<String> realmRoles = readEffectiveRealmRoleNames(user);
        Map<String, Set<String>> clientRoles = readEffectiveClientRoleNames(user);

        if (delta.scope == Delta.Scope.REALM) {
            realmRoles = delta.apply(realmRoles);
        } else if (delta.scope == Delta.Scope.CLIENT && delta.clientKey != null) {
            Set<String> base = clientRoles.getOrDefault(delta.clientKey, new TreeSet<>());
            clientRoles.put(delta.clientKey, delta.apply(base));
        }

        // 3) Build AccessToken skeleton; leave 'aud' shaping to Keycloak
        AccessToken at = new AccessToken();
        at.setSubject(user.getId());
        at.issuer(realm.getName());
        if (client != null) {
            at.issuedFor(client.getClientId());
        }

        // 4) Let KC run protocol mappers/scopes (may reset roles)
        try {
            new TokenManager().transformAccessToken(session, at, null, new MinimalClientSessionContext(realm, client));
        } catch (Throwable ignore) {
            // If not available in this KC variant, keep the skeleton as-is.
        }

        // 5) Re-inject our computed roles AFTER transform so the delta persists
        if (!realmRoles.isEmpty()) {
            AccessToken.Access ra = new AccessToken.Access();
            for (String r : realmRoles) ra.addRole(r);
            at.setRealmAccess(ra);
        } else {
            at.setRealmAccess(null);
        }

        if (!clientRoles.isEmpty()) {
            Map<String, AccessToken.Access> res = new TreeMap<>();
            for (Map.Entry<String, Set<String>> e : clientRoles.entrySet()) {
                Set<String> set = e.getValue();
                if (set == null || set.isEmpty()) continue;
                AccessToken.Access acc = new AccessToken.Access();
                for (String r : set) acc.addRole(r);
                res.put(e.getKey(), acc); // key MUST be alias (e.g., "broker")
            }
            at.setResourceAccess(res.isEmpty() ? null : res);
        } else {
            at.setResourceAccess(null);
        }

        // 6) Serialize + prune (don’t show empty/null claims in preview)
        ObjectNode json = M.valueToTree(at);
        finalizeForPreview(json, client);
        return json;
    }

    /* ───────────────────────── Role readers ───────────────────────── */

    private static Set<String> readEffectiveRealmRoleNames(UserModel user) {
        return user.getRoleMappingsStream()
                .filter(r -> r.getContainer() instanceof RealmModel)
                .map(RoleModel::getName)
                .filter(n -> n != null && !n.isBlank())
                .collect(Collectors.toCollection(TreeSet::new));
    }

    private static Map<String, Set<String>> readEffectiveClientRoleNames(UserModel user) {
        Map<String, Set<String>> out = new TreeMap<>();
        user.getRoleMappingsStream()
                .filter(r -> r.getContainer() instanceof ClientModel)
                .forEach(r -> {
                    String alias = ((ClientModel) r.getContainer()).getClientId(); // e.g. "broker"
                    if (alias == null || alias.isBlank()) return;
                    out.computeIfAbsent(alias, k -> new TreeSet<>()).add(r.getName());
                });
        return out;
    }

    /* ───────────────────────── Pruning (UI cosmetics) ───────────────────────── */

    private static void finalizeForPreview(ObjectNode token, ClientModel client) {
        // Ensure azp populated (aud left to KC; it may be string/array per version and scopes)
        if (client != null && (!token.has("azp") || token.get("azp").isNull() || token.get("azp").asText().isBlank())) {
            token.put("azp", client.getClientId());
        }

        // Remove resource_access children with empty roles, then drop the object if empty
        pruneResourceAccess(token);

        // Remove empty roles object under realm_access, then drop if empty
        removeEmpty(token, "realm_access", "roles");

        // Drop empty groups and any null-valued scalars (cosmetic)
        if (token.has("groups") && token.get("groups").isArray() && token.get("groups").size() == 0) {
            token.remove("groups");
        }
        pruneNullScalars(token);
    }

    private static void removeEmpty(ObjectNode node, String obj, String innerArray) {
        if (!node.has(obj) || !node.get(obj).isObject()) return;
        ObjectNode o = (ObjectNode) node.get(obj);
        if (o.has(innerArray) && o.get(innerArray).isArray() && o.get(innerArray).size() == 0) {
            o.remove(innerArray);
        }
        if (o.isEmpty()) node.remove(obj);
    }

    private static void pruneResourceAccess(ObjectNode token) {
        if (!token.has("resource_access") || !token.get("resource_access").isObject()) return;
        ObjectNode ra = (ObjectNode) token.get("resource_access");
        List<String> toDrop = new ArrayList<>();
        ra.fields().forEachRemaining(e -> {
            if (e.getValue().isObject()) {
                ObjectNode c = (ObjectNode) e.getValue();
                if (c.has("roles") && c.get("roles").isArray() && c.get("roles").size() == 0) {
                    c.remove("roles");
                }
                if (c.isEmpty()) toDrop.add(e.getKey());
            }
        });
        toDrop.forEach(ra::remove);
        if (ra.isEmpty()) token.remove("resource_access");
    }

    private static void pruneNullScalars(ObjectNode node) {
        List<String> toRemove = new ArrayList<>();
        node.fields().forEachRemaining(e -> {
            var v = e.getValue();
            if (v.isNull()) {
                toRemove.add(e.getKey());
            } else if (v.isObject()) {
                pruneNullScalars((ObjectNode) v);
                if (((ObjectNode) v).isEmpty()) toRemove.add(e.getKey());
            }
        });
        toRemove.forEach(node::remove);
    }

    /* ───────────────────────── Minimal ClientSessionContext ───────────────────────── */

    /**
     * Minimal context: provides client, protocol and safe defaults. We don’t rely on
     * DefaultClientScopes to avoid classpath differences; KC will still transform static mappers.
     */
    private static final class MinimalClientSessionContext implements ClientSessionContext {
        private final RealmModel realm;
        private final ClientModel client;

        MinimalClientSessionContext(RealmModel realm, ClientModel client) {
            this.realm = realm;
            this.client = client;
        }

        public ClientModel getClient() { return client; }
        public Set<ClientScopeModel> getClientScopes() { return Collections.emptySet(); }
        public Map<String, Object> getAttributes() { return Collections.emptyMap(); }
        public RealmModel getRealm() { return realm; }
        public String getProtocol() { return "openid-connect"; }
        public boolean isUserSessionInitialized() { return false; }
        public UserSessionModel getUserSession() { return null; }
        public AuthenticatedClientSessionModel getClientSession() { return null; }
        public Set<String> getClientScopeIds() { return Set.of(); }
        public AuthorizationRequestContext getAuthorizationRequestContext() { return null; }

        // These exist on some KC versions; we leave them without @Override for cross-version compatibility
        public Stream<ClientScopeModel> getClientScopesStream() { return Stream.empty(); }
        public boolean isOfflineTokenRequested() { return false; }
        public Stream<RoleModel> getRolesStream() { return Stream.empty(); }
        public Stream<ProtocolMapperModel> getProtocolMappersStream() { return Stream.empty(); }
        public String getScopeString() { return ""; }
        public String getScopeString(boolean ignoreIncludeInTokenScope) { return ""; }
        public void setAttribute(String name, Object value) { /* no-op */ }
        public <T> T getAttribute(String attribute, Class<T> clazz) { return null; }
    }

    /* ───────────────────────── Delta model ───────────────────────── */

    private static final class Delta {
        enum Scope { NONE, REALM, CLIENT }

        final Scope scope;
        /** Key for resource_access — always client alias (e.g. "broker") when client model is available. */
        final String clientKey;
        final Set<String> replace, add, remove;

        private Delta(Scope scope, String clientKey, Set<String> replace, Set<String> add, Set<String> remove) {
            this.scope = scope;
            this.clientKey = clientKey;
            this.replace = (replace == null) ? Set.of() : new TreeSet<>(replace);
            this.add = (add == null) ? Set.of() : new TreeSet<>(add);
            this.remove = (remove == null) ? Set.of() : new TreeSet<>(remove);
        }

        static Delta parse(String draftJson, ClientModel defaultClient) {
            if (draftJson == null || draftJson.isBlank()) {
                return (defaultClient == null)
                        ? new Delta(Scope.REALM, null, null, null, null)
                        : new Delta(Scope.CLIENT, defaultClient.getClientId(), null, null, null);
            }
            try {
                String s = decodeMaybeBase64(draftJson);
                var n = M.readTree(s);

                String cid = text(n, "clientId"); // may be alias or UUID; we prefer model when available
                String path = text(n, "_replayPath");

                Scope sc;
                if (cid != null && !cid.isBlank()) sc = Scope.CLIENT;
                else if (path != null && path.contains("/role-mappings/clients/")) sc = Scope.CLIENT;
                else if (path != null && path.contains("/role-mappings/realm")) sc = Scope.REALM;
                else sc = (defaultClient == null) ? Scope.REALM : Scope.CLIENT;

                String clientKey = (sc == Scope.CLIENT && defaultClient != null)
                        ? defaultClient.getClientId()      // alias like "broker"
                        : (sc == Scope.CLIENT ? cid : null);

                Set<String> replace = readRoleNames(n.get("roles"));
                Set<String> add     = readRoleNames(n.get("addRoles"));
                Set<String> remove  = readRoleNames(n.get("removeRoles"));

                return new Delta(sc, clientKey, replace, add, remove);
            } catch (Exception ignore) {
                return (defaultClient == null)
                        ? new Delta(Scope.REALM, null, null, null, null)
                        : new Delta(Scope.CLIENT, defaultClient.getClientId(), null, null, null);
            }
        }

        Set<String> apply(Set<String> base) {
            Set<String> out = (replace != null && !replace.isEmpty())
                    ? new TreeSet<>(replace)
                    : new TreeSet<>(base == null ? Set.of() : base);
            if (add != null) out.addAll(add);
            if (remove != null) out.removeAll(remove);
            return out;
        }

        private static Set<String> readRoleNames(com.fasterxml.jackson.databind.JsonNode node) {
            if (node == null || !node.isArray()) return Collections.emptySet();
            Set<String> out = new TreeSet<>();
            node.forEach(el -> {
                if (el.isTextual()) {
                    String v = el.asText();
                    if (!v.isBlank()) out.add(v);
                } else if (el.isObject()) {
                    var name = el.get("name");
                    if (name != null && name.isTextual() && !name.asText().isBlank()) {
                        out.add(name.asText());
                    }
                }
            });
            return out;
        }
    }

    /* ───────────────────────── Small utils ───────────────────────── */

    private static String text(com.fasterxml.jackson.databind.JsonNode n, String field) {
        if (n == null) return null;
        var v = n.get(field);
        return (v != null && v.isTextual()) ? v.asText() : null;
    }

    private static String decodeMaybeBase64(String s) {
        if (s == null) return null;
        String t = s.trim();
        if (t.isEmpty()) return t;
        if (!t.startsWith("{") && !t.startsWith("[")) {
            try {
                byte[] raw = Base64.getDecoder().decode(t);
                String decoded = new String(raw, StandardCharsets.UTF_8);
                String dt = decoded.trim();
                if (dt.startsWith("{") || dt.startsWith("[")) return decoded;
            } catch (IllegalArgumentException ignored) {}
        }
        return t;
    }

    private static String toJson(Map<String, Object> m) {
        try { return M.writeValueAsString(m); }
        catch (Exception e) { return "{}"; }
    }
}
