package org.tidecloak.base.iga.IGARealmResource;

import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.PreMatching;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.jboss.logging.Logger;

import java.net.URI;
import java.util.Set;

import static org.tidecloak.base.iga.IGARealmResource.ReplayEnforcementFilter.tailAfterRealm;

@Provider
@PreMatching
@Priority(Priorities.AUTHENTICATION)
public class ReplayAutoDraftFilter implements ContainerRequestFilter {
    private static final Logger LOG = Logger.getLogger(ReplayAutoDraftFilter.class);

    private static final Set<String> MUTATING = Set.of("POST","PUT","PATCH","DELETE");

    // segments that always affect effective tokens → must go via replay
    private static final String[] ALWAYS_BLOCK_SEGMENTS = {
            "role-mappings","default-roles","protocol-mappers",
            "client-scopes","scope-mappings","default-client-scopes",
            "optional-client-scopes","groups-by-path"
    };

    @Override
    public void filter(ContainerRequestContext ctx) {
        try {
            final var uri   = ctx.getUriInfo().getRequestUri(); // absolute
            final var path  = normalize(uri.getPath());         // /admin/realms/...
            final var query = uri.getRawQuery();
            final var meth  = ctx.getMethod();

            if (!path.startsWith("/admin/realms/")) return;
            if (!MUTATING.contains(meth)) return;
            if (path.contains("/tide-admin/replay/")) return; // already replay

            final String afterRealm = tailAfterRealm(path);

            // allow direct user creation to pass through (admin UI flow)
            if ("POST".equalsIgnoreCase(meth) && "users".equals(afterRealm)) {
                LOG.debug("[AutoDraft] allow direct user creation; skipping rewrite");
                return;
            }

            if (!isTokenAffecting(afterRealm)) return;

            // Build replay path
            final String replayPath = injectReplay(path); // /admin/realms/{realm}/tide-admin/replay/...
            final String location   = replayPath + (query == null ? "" : "?" + query);
            final URI absoluteLoc   = uri.resolve(location); // absolute URL

            LOG.infof("[AutoDraft] rewrite %s -> %s", path, absoluteLoc);
            ctx.getHeaders().putSingle("X-Tide-Auto-Drafted", "true");

            // 307 keeps method + body and avoids RR internal URI offset bugs
            ctx.abortWith(Response.status(307).location(absoluteLoc).build());
        } catch (Throwable t) {
            LOG.warn("[AutoDraft] non-fatal; leaving request unchanged", t);
        }
    }

    /** Insert '/tide-admin/replay/' right after '/admin/realms/{realm}/' */
    private static String injectReplay(String full) {
        final String marker = "/admin/realms/";
        final int i = full.indexOf(marker);
        if (i < 0) return full;

        final String tail  = full.substring(i + marker.length()); // {realm}/rest...
        final int slash    = tail.indexOf('/');
        if (slash < 0) return full; // nothing after realm

        final String realm = tail.substring(0, slash);
        final String rest  = tail.substring(slash + 1);
        return marker + realm + "/tide-admin/replay/" + rest;
    }

    private static boolean isTokenAffecting(String subpath) {
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
        if (subpath.startsWith("groups/") &&
                (subpath.contains("/members") || subpath.contains("/role-mappings"))) {
            return true;
        }
        if (subpath.startsWith("users/") &&
                (subpath.contains("/role-mappings") || subpath.contains("/groups"))) {
            return true;
        }
        if (subpath.startsWith("realm/") &&
                (subpath.contains("/default-roles") || subpath.contains("/default-client-scopes"))) {
            return true;
        }
        return false;
    }

    private static String normalize(String p) {
        if (p == null || p.isBlank()) return "/";
        return p.startsWith("/") ? p : "/" + p;
    }
}
