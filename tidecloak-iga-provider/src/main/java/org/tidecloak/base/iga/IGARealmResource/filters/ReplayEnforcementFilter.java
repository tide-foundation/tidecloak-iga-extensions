package org.tidecloak.base.iga.IGARealmResource.filters;

import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.PreMatching;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;

import java.net.URI;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Lightweight enforcement: when IGA Replay is enabled in ENFORCE mode,
 * block direct mutating calls to core admin endpoints so they must go
 * through /tide/replay instead.
 *
 * For ease of rollout, this version reads headers:
 *   - X-Tide-IGA-Enabled: "true" | "false" (default false)
 *   - X-Tide-Replay-Mode: "preview" | "enforce" (default preview)
 *   - X-Tide-Replay-Bypass: "true" to allow internal applier
 *
 * Swap these to realm attributes if preferred.
 */
@Provider
@PreMatching
@Priority(Priorities.AUTHENTICATION)
public class ReplayEnforcementFilter implements ContainerRequestFilter {

    private static final Set<String> MUTATING_METHODS = new HashSet<>(Arrays.asList("POST", "PUT", "PATCH", "DELETE"));

    // Endpoints to protect below /admin/realms/{realm}/
    private static final String[] PROTECTED_PREFIXES = new String[]{
            "users",
            "groups",
            "roles",
            "clients",
            "client-scopes",
            "role-mappings",
            "groups-by-path"
    };

    @Override
    public void filter(ContainerRequestContext ctx) {
        try {
            final String method = ctx.getMethod();
            if (!MUTATING_METHODS.contains(method)) {
                // allow GET/HEAD/OPTIONS
                return;
            }

            final URI uri = ctx.getUriInfo().getRequestUri();
            final String path = normalize(uri.getPath());

            // Only consider admin realm endpoints
            if (!path.startsWith("/admin/realms/")) {
                return;
            }

            // Always allow replay endpoints
            if (path.contains("/tide/replay")) {
                return;
            }

            // Bypass header for the internal applier
            final String bypass = header(ctx, "X-Tide-Replay-Bypass");
            if ("true".equalsIgnoreCase(bypass)) {
                return;
            }

            // Toggle via headers (replace with realm attributes as needed)
            final boolean igaEnabled = "true".equalsIgnoreCase(header(ctx, "X-Tide-IGA-Enabled"));
            final String replayMode = header(ctx, "X-Tide-Replay-Mode"); // "preview" | "enforce"

            if (!igaEnabled || !"enforce".equalsIgnoreCase(replayMode)) {
                return;
            }

            // Inspect the segment under /admin/realms/{realm}/
            final String afterRealm = stripToAfterRealm(path);

            if (isProtected(afterRealm)) {
                ctx.abortWith(Response.status(Response.Status.FORBIDDEN)
                    .entity("Tide IGA is enforcing replay: mutate operations must be submitted via /tide/replay")
                    .build());
            }
        } catch (Exception ignored) {
            // Fail open: enforcement should not break admin when misconfigured
        }
    }

    private static String header(ContainerRequestContext ctx, String name) {
        var v = ctx.getHeaders().getFirst(name);
        return v == null ? "" : v.trim();
    }

    private static String normalize(String p) {
        if (p == null) return "/";
        p = p.trim();
        if (!p.startsWith("/")) p = "/" + p;
        return p;
    }

    private static String stripToAfterRealm(String full) {
        // /admin/realms/{realm}/<this part>
        String marker = "/admin/realms/";
        int i = full.indexOf(marker);
        if (i < 0) return full;
        String tail = full.substring(i + marker.length());
        int slash = tail.indexOf('/');
        if (slash < 0) return "";
        return tail.substring(slash + 1); // after realm name '/'
    }

    private static boolean isProtected(String subpath) {
        for (String pref : PROTECTED_PREFIXES) {
            if (subpath.startsWith(pref + "/") || subpath.equals(pref)) {
                return true;
            }
        }
        return false;
    }
}
