package org.tidecloak.iga.rest;

import jakarta.enterprise.inject.Vetoed;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.tidecloak.iga.services.IgaAdoptScan;

import jakarta.persistence.EntityManager;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Backwards-compat admin resource at /admin/realms/{realm}/tide-admin
 * Replaces the old IGA's IGARealmResource.toggleIga endpoint so the existing admin UI works.
 *
 * <p>Phase 6b — on OFF→ON the handler triggers a one-shot {@link IgaAdoptScan}
 * in its own {@code runJobInTransaction} so a scan failure cannot abort the
 * toggle attribute write that just succeeded.</p>
 */
@Path("tide-admin")
@Vetoed
public class TideAdminCompatResource {

    private static final Logger logger = Logger.getLogger(TideAdminCompatResource.class);
    private static final String IGA_ATTRIBUTE = "isIGAEnabled";
    private static final String INCLUDE_SYSTEM_ATTRIBUTE = "iga.adopt.includeSystem";

    private final KeycloakSession session;
    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;

    public TideAdminCompatResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth) {
        this.session = session;
        this.realm = realm;
        this.auth = auth;
    }

    @POST
    @Path("toggle-iga")
    @Produces(MediaType.APPLICATION_JSON)
    public Response toggleIga() {
        auth.realm().requireManageRealm();
        boolean current = "true".equals(realm.getAttribute(IGA_ATTRIBUTE));
        boolean next = !current;
        realm.setAttribute(IGA_ATTRIBUTE, Boolean.toString(next));
        logger.infof("IGA has been toggled to : %s for realm %s", next, realm.getName());

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("enabled", next);

        // Phase 6b — OFF→ON: run the one-shot ADOPT scan inside its own
        // transaction. Master is excluded by design — the master-realm
        // escape hatch must remain unconditionally usable for recovery.
        if (!current && next && !"master".equals(realm.getName())) {
            boolean includeSystem = "true".equals(realm.getAttribute(INCLUDE_SYSTEM_ATTRIBUTE));
            String requestedBy = currentUserId();
            String realmId = realm.getId();

            IgaAdoptScan.ScanResult[] resultHolder = new IgaAdoptScan.ScanResult[1];
            Throwable[] errHolder = new Throwable[1];
            try {
                KeycloakModelUtils.runJobInTransaction(
                        session.getKeycloakSessionFactory(),
                        scanSession -> {
                            RealmModel scanRealm = scanSession.realms().getRealm(realmId);
                            if (scanRealm == null) {
                                throw new IllegalStateException(
                                        "IGA toggle-on scan: realm " + realmId + " not loadable in scan session");
                            }
                            resultHolder[0] = IgaAdoptScan.scan(scanSession, scanRealm, requestedBy, includeSystem);
                        });
            } catch (RuntimeException ex) {
                // Scan failed entirely — toggle ALREADY committed in the
                // outer transaction. Surface the error in the response but
                // do NOT roll back the toggle (per locked design: scan
                // failure must not block the toggle).
                errHolder[0] = ex;
                logger.errorf(ex, "IGA toggle-on scan FAILED for realm %s — toggle " +
                        "remains enabled, no ADOPT CRs were emitted.", realm.getName());
            }

            if (resultHolder[0] != null) {
                body.put("scan", resultHolder[0].toMap());
                String warning = buildAdminCoverageWarning(session, realm);
                if (warning != null) {
                    body.put("warning", warning);
                }
            } else if (errHolder[0] != null) {
                Map<String, Object> scanErr = new LinkedHashMap<>();
                scanErr.put("error", errHolder[0].getClass().getSimpleName());
                scanErr.put("message", String.valueOf(errHolder[0].getMessage()));
                body.put("scan", scanErr);
            }
        }

        return Response.ok(body).build();
    }

    @GET
    @Path("iga-status")
    @Produces(MediaType.APPLICATION_JSON)
    public Response status() {
        auth.realm().requireViewRealm();
        boolean enabled = "true".equals(realm.getAttribute(IGA_ATTRIBUTE));
        return Response.ok(Map.of("enabled", enabled)).build();
    }

    /**
     * Best-effort current admin id for stamping the emitted CRs' requestedBy
     * column. Mirrors {@code IgaAdminResource#currentUserId}.
     */
    private String currentUserId() {
        try {
            if (auth != null && auth.adminAuth() != null && auth.adminAuth().getUser() != null) {
                return auth.adminAuth().getUser().getId();
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    /**
     * Heuristic admin-coverage check. The Phase 6b scan is non-quarantining
     * (Phase 6c will add quarantine), but the warning is still useful: once
     * 6c lands, a realm whose only admin holder is the realm's first
     * (governance-only) user will lock itself out the moment we start
     * enforcing PENDING ADOPT_USER. We warn now so the operator can
     * provision a second admin / configure approver-roles BEFORE 6c lands.
     *
     * <p>Heuristic: count distinct holders of {@code realm-management:
     * manage-realm} + any role named by an existing {@code iga.approverRole}
     * realm attribute. If the union is &lt; 2, emit the warning. We
     * deliberately do NOT 4xx — the user can still proceed; the warning is
     * advisory and the master-realm escape hatch is the supported recovery
     * path.</p>
     */
    private static String buildAdminCoverageWarning(KeycloakSession session, RealmModel realm) {
        try {
            int holders = 0;
            // realm-management:manage-realm holders
            var rm = realm.getClientByClientId("realm-management");
            if (rm != null) {
                RoleModel manageRealm = rm.getRole("manage-realm");
                if (manageRealm != null) {
                    long count = session.users().getRoleMembersStream(realm, manageRealm).count();
                    holders = (int) Math.min(Integer.MAX_VALUE, count);
                }
            }
            // approver-role holders (additive — the approver role is the
            // ONLY way a non-manage-realm admin can authorize in Tideless).
            String approverRoleAttr = realm.getAttribute("iga.approverRole");
            if (approverRoleAttr != null && !approverRoleAttr.isEmpty()) {
                for (String roleName : approverRoleAttr.split(",")) {
                    roleName = roleName.trim();
                    if (roleName.isEmpty()) continue;
                    RoleModel approver = realm.getRole(roleName);
                    if (approver != null) {
                        long count = session.users().getRoleMembersStream(realm, approver).count();
                        holders += (int) Math.min(Integer.MAX_VALUE, count);
                    }
                }
            }
            if (holders < 2) {
                return "Fewer than 2 distinct admin holders detected for realm '"
                        + realm.getName() + "' (manage-realm + iga.approverRole "
                        + "candidates: " + holders + "). Phase 6c will enforce ADOPT "
                        + "approval before admin actions — provision a second "
                        + "manage-realm admin (or configure iga.approverRole) NOW. "
                        + "Recovery path if locked out: the master-realm admin can "
                        + "always disable IGA on this realm via the master realm "
                        + "(escape hatch) — there is no other recovery.";
            }
        } catch (RuntimeException ex) {
            logger.warnf(ex, "buildAdminCoverageWarning: heuristic failed for realm %s — " +
                    "warning suppressed.", realm.getName());
        }
        return null;
    }
}
