package org.tidecloak.base.iga.IGARealmResource.filters;

import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.PreMatching;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.jboss.logging.Logger;

import java.net.URI;
import java.util.*;

import static org.tidecloak.base.iga.IGARealmResource.filters.ReplayEnforcementFilter.tailAfterRealm;

@Provider
@PreMatching
@Priority(Priorities.AUTHENTICATION)
public class ReplayAutoDraftFilter implements ContainerRequestFilter {
    private static final Logger LOG = Logger.getLogger(ReplayAutoDraftFilter.class);
    private static final Set<String> MUTATING = Set.of("POST","PUT","PATCH","DELETE");

    @Override
    public void filter(ContainerRequestContext ctx) {
        try {
            final var uri   = ctx.getUriInfo().getRequestUri();
            final var path  = normalize(uri.getPath());
            final var q     = uri.getRawQuery();
            final var meth  = ctx.getMethod();

            final String afterRealm = tailAfterRealm(path);
            if ("POST".equalsIgnoreCase(meth) && "users".equals(afterRealm)) {
                LOG.debug("[AutoDraft] allow direct user creation; skipping rewrite");
                return;
            }
            if (!tokenAffecting(afterRealm)) {
                LOG.infof("[Decision] tokenAffecting=%s safe=%s path=%s",
                        tokenAffecting(afterRealm), isSafe(afterRealm, ctx.getMethod()), afterRealm);

                return;
            }
            if (!MUTATING.contains(meth)) return;
            if (!path.startsWith("/admin/realms/")) return;
            if (path.contains("/tide-admin/replay")) return;

            // only decide from raw path — no KC session lookups here
            final String replayPath = injectReplay(path);
            final String withQuery  = replayPath + (q == null ? "" : "?" + q);

            LOG.infof("[AutoDraft] rewrite %s -> %s", path, withQuery);

            // mark for diagnostics
            ctx.getHeaders().putSingle("X-Tide-Auto-Drafted", "true");

            // 307 keeps method+body; avoids RESTEasy internal re-match issues
            ctx.abortWith(Response.status(307).location(URI.create(withQuery)).build());
        } catch (Throwable t) {
            LOG.warn("[AutoDraft] non-fatal error; leaving request unchanged", t);
        }
    }

    private static String injectReplay(String full) {
        final String marker = "/admin/realms/";
        final int i = full.indexOf(marker);
        if (i < 0) return full;
        final String tail = full.substring(i + marker.length());   // {realm}/rest
        final int s = tail.indexOf('/');
        if (s < 0) return full; // nothing after realm
        final String realm = tail.substring(0, s);
        final String rest  = tail.substring(s + 1);
        return "/admin/realms/" + realm + "/tide-admin/replay/" + rest;
    }

    private static String normalize(String p) { return (p == null || p.isBlank()) ? "/" : (p.startsWith("/") ? p : "/" + p); }

    // --- helpers (top of class) ---
    private static final String[] ALWAYS_BLOCK_SEGMENTS = {
            "role-mappings","default-roles","protocol-mappers",
            "client-scopes","scope-mappings","default-client-scopes",
            "users/","groups-by-path" // broad user touchpoints
    };

    private static final String[] SAFE_PREFIXES = {
            "identity-provider","roles","groups","realm","clients"
    };

    private static boolean tokenAffecting(String subpath) {
        for (String s : ALWAYS_BLOCK_SEGMENTS) {
            if (subpath.startsWith(s) || subpath.contains("/" + s)) return true;
        }
        if (subpath.startsWith("clients/") &&
                (subpath.contains("/protocol-mappers")
                        || subpath.contains("/scope-mappings")
                        || subpath.contains("/default-client-scopes")
                        || subpath.contains("/optional-client-scopes"))) {
            return true;
        }
        if (subpath.startsWith("groups/") && subpath.contains("/members")) return true;
        return false;
    }

    private static boolean isSafe(String subpath, String method) {
        if (startsWithAny(subpath, SAFE_PREFIXES)) {
            if (subpath.contains("/role-mappings") || subpath.contains("/members")) return false;
            return true;
        }
        return false;
    }

    private static boolean startsWithAny(String s, String[] prefixes) {
        for (String p : prefixes) if (s.startsWith(p)) return true;
        return false;
    }

}
