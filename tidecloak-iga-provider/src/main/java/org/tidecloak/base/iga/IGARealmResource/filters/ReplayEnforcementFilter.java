package org.tidecloak.base.iga.IGARealmResource.filters;

import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Resteasy;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Set;

@Provider
@Priority(Priorities.AUTHORIZATION)
public class ReplayEnforcementFilter implements ContainerRequestFilter {

    private static final Logger LOG = Logger.getLogger(ReplayEnforcementFilter.class);

    private static final Set<String> MUTATING = Set.of("POST","PUT","PATCH","DELETE");

    // broad resources under /admin/realms/{realm}/...
    private static final String[] PROTECTED = {
            "users","groups","roles","clients","client-scopes","role-mappings","groups-by-path","realm"
    };

    // segments/areas that always affect tokens or user effective access – force replay
    private static final String[] ALWAYS_BLOCK_SEGMENTS = {
            "role-mappings", "default-roles", "protocol-mappers",
            "client-scopes", "scope-mappings", "default-client-scopes",
            "optional-client-scopes", "groups-by-path"
    };

    // areas that are *often* safe (metadata only) – we still guard with tokenAffecting(..)
    private static final String[] SAFE_PREFIXES = {
            "identity-provider", // idp CRUD
            "roles",             // role metadata (not mappings)
            "groups",            // group metadata (not members)
            "clients",           // client metadata (not mappers/scopes)
            "realm"              // many realm settings are safe; token-affecting subpaths are blocked below
    };

    @Override
    public void filter(ContainerRequestContext ctx) {
        try {
            final URI uri = ctx.getUriInfo().getRequestUri();
            final String path = normalize(uri.getPath());
            final String method = ctx.getMethod();

            LOG.debugf("[Enforce] IN method=%s path=%s", method, path);

            if (!MUTATING.contains(method)) {
                LOG.debug("[Enforce] skip: non-mutating");
                return;
            }
            if (!path.startsWith("/admin/realms/")) {
                LOG.debug("[Enforce] skip: not admin path");
                return;
            }
            if (path.contains("/tide-admin/replay")) {
                LOG.debug("[Enforce] allow: already replay path");
                return;
            }

            String realmName = extractRealmName(path);
            LOG.debugf("[Enforce] realmName=%s", realmName);
            if (realmName == null || realmName.isBlank()) {
                LOG.debug("[Enforce] skip: realm cannot be resolved");
                return;
            }

            KeycloakSession session = Resteasy.getContextData(KeycloakSession.class);
            if (session == null) {
                LOG.debug("[Enforce] skip: KC session missing");
                return;
            }
            RealmModel realm = session.realms().getRealmByName(realmName);
            if (realm == null) {
                LOG.debug("[Enforce] skip: realm not found");
                return;
            }

            boolean igaEnabled = "true".equalsIgnoreCase(realm.getAttribute("isIGAEnabled"));
            LOG.debugf("[Enforce] isIGAEnabled=%s", igaEnabled);
            if (!igaEnabled) {
                LOG.debug("[Enforce] skip: IGA disabled");
                return;
            }

            String afterRealm = tailAfterRealm(path);

            if ("POST".equalsIgnoreCase(ctx.getMethod()) && "users".equals(afterRealm)) {
                LOG.infof("[Enforce] allow direct user creation: %s", path);
                return;
            }
            // If the subpath obviously touches effective permissions, force replay
            if (tokenAffecting(afterRealm)) {
                LOG.infof("[Enforce] BLOCK (token-affecting) %s → must go via /tide-admin/replay", path);
                ctx.abortWith(forbidden());
                return;
            }

            // If it looks like safe metadata (and not tripping tokenAffecting above), allow
            if (isSafe(afterRealm, method)) {
                LOG.debugf("[Enforce] allow (safe) subpath=%s", afterRealm);
                return;
            }

            // Fallback: protect known admin roots when mutating
            boolean prot = isProtected(afterRealm);
            LOG.debugf("[Enforce] subpath=%s protected=%s", afterRealm, prot);
            if (prot) {
                LOG.infof("[Enforce] BLOCK %s (must go via /tide-admin/replay)", path);
                ctx.abortWith(forbidden());
            }
        } catch (Throwable t) {
            // Fail-open to avoid bricking admin in case of misconfig
            LOG.debug("[Enforce] non-fatal error; not blocking", t);
        }
    }

    private static Response forbidden() {
        return Response.status(Response.Status.FORBIDDEN)
                .type(MediaType.TEXT_PLAIN)
                .entity("Tide IGA is enforcing replay: mutating admin calls must be sent to /tide-admin/replay")
                .build();
    }

    private static boolean tokenAffecting(String subpath) {
        // always-block segments anywhere in the subpath
        for (String s : ALWAYS_BLOCK_SEGMENTS) {
            if (subpath.equals(s) || subpath.startsWith(s + "/") || subpath.contains("/" + s + "/")) {
                return true;
            }
        }
        // Clients: block protocol/scope-ish subpaths
        if (subpath.startsWith("clients/") &&
                (subpath.contains("/protocol-mappers") ||
                        subpath.contains("/scope-mappings") ||
                        subpath.contains("/default-client-scopes") ||
                        subpath.contains("/optional-client-scopes"))) {
            return true;
        }
        // Groups membership operations
        if (subpath.startsWith("groups/") && (subpath.contains("/members") || subpath.contains("/role-mappings"))) return true;

        // Users: anything under /users/{id}/role-mappings or group membership touches tokens
        if (subpath.startsWith("users/") &&
                (subpath.contains("/role-mappings") || subpath.contains("/groups"))) {
            return true;
        }

        // Realm defaults directly affect tokens
        if (subpath.startsWith("realm/") &&
                (subpath.contains("/default-roles") || subpath.contains("/default-client-scopes"))) {
            return true;
        }

        return false;
    }

    private static boolean isSafe(String subpath, String method) {
        // Safe *metadata* CRUD on these roots, provided tokenAffecting(...) didn't trip above
        if (startsWithAny(subpath, SAFE_PREFIXES)) {
            // Further guard a couple of common mapping tails
            if (subpath.contains("/role-mappings") || subpath.contains("/members")) return false;
            // Creating a role/group/client without assigning it is allowed
            return true;
        }
        return false;
    }

    private static boolean isProtected(String subpath) {
        for (String pref : PROTECTED) {
            if (subpath.equals(pref) || subpath.startsWith(pref + "/")) return true;
        }
        return false;
    }

    private static boolean startsWithAny(String s, String[] prefixes) {
        for (String p : prefixes) if (s.startsWith(p + "/") || s.equals(p)) return true;
        return false;
    }

    private static String normalize(String p) {
        if (p == null) return "/";
        p = p.trim();
        return p.startsWith("/") ? p : "/" + p;
    }

    private static String extractRealmName(String full) {
        String marker = "/admin/realms/";
        int i = full.indexOf(marker);
        if (i < 0) return null;
        String tail = full.substring(i + marker.length());
        int slash = tail.indexOf('/');
        String raw = (slash < 0) ? tail : tail.substring(0, slash);
        return URLDecoder.decode(raw, StandardCharsets.UTF_8);
    }

    static String tailAfterRealm(String full) {
        String marker = "/admin/realms/";
        int i = full.indexOf(marker);
        if (i < 0) return full;
        String tail = full.substring(i + marker.length());
        int slash = tail.indexOf('/');
        if (slash < 0) return "";
        return tail.substring(slash + 1);
    }
}
