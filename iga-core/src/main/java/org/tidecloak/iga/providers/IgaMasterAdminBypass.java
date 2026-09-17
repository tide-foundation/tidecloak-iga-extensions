package org.tidecloak.iga.providers;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AdminRoles;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ImpersonationSessionNote;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;

import java.util.function.BooleanSupplier;

/**
 * Lets a master super admin delete an IGA-on realm directly, with no DELETE_REALM
 * change request. This is the recovery path for a realm that can no longer reach
 * its approval quorum.
 *
 * <p>Realm DELETE only. It is consulted from {@code IgaRealmProvider.removeRealm}
 * and nowhere else, so every other master admin write stays governed. Anything
 * unexpected (no caller, wrong realm, an exception) answers "no" and the delete
 * falls back to the normal 202.
 */
public final class IgaMasterAdminBypass {

    private static final Logger log = Logger.getLogger(IgaMasterAdminBypass.class);

    /** SPI config key, read by {@code IgaRealmProviderFactory.init}. Default on. */
    public static final String CONFIG_KEY = "masterAdminRealmDeleteBypass";

    private static final String REPLAY_FLAG = "IGA_REPLAY_ACTIVE";

    private static volatile boolean enabled = true;

    private IgaMasterAdminBypass() {
    }

    static void setEnabled(boolean value) {
        enabled = value;
    }

    static boolean isEnabled() {
        return enabled;
    }

    /** Who triggered the bypass, kept for the log line and the audit row. */
    public record Caller(String userId, String username, String clientId,
                         boolean temporaryAdmin, boolean serviceAccount, RealmModel adminRealm) {
    }

    public static boolean allowsRealmDelete(KeycloakSession session, RealmModel target) {
        return resolveCaller(session, target) != null;
    }

    /**
     * The verified master super admin behind the current DELETE request, or null
     * when the delete must stay governed.
     */
    public static Caller resolveCaller(KeycloakSession session, RealmModel target) {
        try {
            return doResolve(session, target);
        } catch (RuntimeException e) {
            log.debugf(e, "Master admin realm-delete check failed, staying governed");
            return null;
        }
    }

    /**
     * Run {@code work} with {@code IGA_REPLAY_ACTIVE} set, then put back whatever was
     * there before, also when {@code work} throws.
     */
    static boolean runUnderReplayFlag(KeycloakSession session, BooleanSupplier work) {
        Object prior = session.getAttribute(REPLAY_FLAG);
        session.setAttribute(REPLAY_FLAG, "true");
        try {
            return work.getAsBoolean();
        } finally {
            if (prior == null) {
                session.removeAttribute(REPLAY_FLAG);
            } else {
                session.setAttribute(REPLAY_FLAG, prior);
            }
        }
    }

    private static Caller doResolve(KeycloakSession session, RealmModel target) {
        if (!enabled || session == null || target == null) return null;
        KeycloakContext ctx = session.getContext();
        if (ctx == null) return null;

        // Only a validated bearer token sets this. Cookie auth, imports and jobs have none.
        if (ctx.getBearerToken() == null) return null;

        UserSessionModel userSession = ctx.getUserSession();
        if (userSession == null) return null;
        RealmModel adminRealm = userSession.getRealm();
        if (adminRealm == null || !Config.getAdminRealm().equals(adminRealm.getName())) return null;

        // An impersonated session is not the admin themselves.
        if (userSession.getNote(ImpersonationSessionNote.IMPERSONATOR_ID.toString()) != null) return null;

        UserModel user = userSession.getUser();
        if (user == null || !user.isEnabled()) return null;

        // Live, effective check: composites and groups count, manage-realm or create-realm alone do not.
        RoleModel adminRole = adminRealm.getRole(AdminRoles.ADMIN);
        if (adminRole == null || !user.hasRole(adminRole)) return null;

        // The calling client must be allowed to carry the admin role.
        ClientModel client = ctx.getClient();
        if (client == null) return null;
        if (!client.isFullScopeAllowed() && !client.hasScope(adminRole)) return null;

        HttpRequest request = ctx.getHttpRequest();
        if (request == null || !"DELETE".equalsIgnoreCase(request.getHttpMethod())) return null;

        // The request must be addressed to the realm being removed.
        RealmModel contextRealm = ctx.getRealm();
        if (contextRealm == null || target.getId() == null
                || !target.getId().equals(contextRealm.getId())) {
            return null;
        }

        boolean temporaryAdmin = "true".equalsIgnoreCase(
                user.getFirstAttribute(UserModel.IS_TEMP_ADMIN_ATTR_NAME));
        boolean serviceAccount = user.getServiceAccountClientLink() != null;
        return new Caller(user.getId(), user.getUsername(), client.getClientId(),
                temporaryAdmin, serviceAccount, adminRealm);
    }
}
