package org.tidecloak.tidecustom.filters;

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

@Provider
@PreMatching
@Priority(Priorities.AUTHENTICATION)
public class ReplayEnforcementFilter implements ContainerRequestFilter {

    private static final Set<String> MUTATING_METHODS = new HashSet<>(Arrays.asList("POST", "PUT", "PATCH", "DELETE"));

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
                return;
            }

            final URI uri = ctx.getUriInfo().getRequestUri();
            final String path = normalize(uri.getPath());

            if (!path.startsWith("/admin/realms/")) {
                return;
            }

            if (path.contains("/tide/replay")) {
                return;
            }

            final String bypass = header(ctx, "X-Tide-Replay-Bypass");
            if ("true".equalsIgnoreCase(bypass)) {
                return;
            }

            final boolean igaEnabled = "true".equalsIgnoreCase(header(ctx, "X-Tide-IGA-Enabled"));
            final String replayMode = header(ctx, "X-Tide-Replay-Mode");

            if (!igaEnabled || !"enforce".equalsIgnoreCase(replayMode)) {
                return;
            }

            final String afterRealm = stripToAfterRealm(path);

            if (isProtected(afterRealm)) {
                ctx.abortWith(Response.status(Response.Status.FORBIDDEN)
                    .entity("Tide IGA is enforcing replay: mutate operations must be submitted via /tide/replay")
                    .build());
            }
        } catch (Exception ignored) {
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
        String marker = "/admin/realms/";
        int i = full.indexOf(marker);
        if (i < 0) return full;
        String tail = full.substring(i + marker.length());
        int slash = tail.indexOf('/');
        if (slash < 0) return "";
        return tail.substring(slash + 1);
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
