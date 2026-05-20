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
import org.keycloak.models.cache.UserCache;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.keycloak.storage.UserStorageUtil;
import org.tidecloak.iga.replay.SidecarCapExceededException;
import org.tidecloak.iga.services.IgaAdoptCancel;
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
 *
 * <p>Phase 6d — on ON→OFF the handler triggers a one-shot {@link IgaAdoptCancel}
 * in its own {@code runJobInTransaction} that cancels every PENDING ADOPT_*
 * CR and clears the entire sidecar register for the realm. The toggle-on path
 * also gains a sidecar cap check: if the realm already has more than
 * {@link IgaAdoptScan#SIDECAR_CAP_DEFAULT} unattested rows at scan-start, the
 * toggle is refused with 409 SIDECAR_CAP_EXCEEDED and the realm-attribute
 * write rolled back.</p>
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
        // The toggle endpoint IS the governing action (gated by
        // requireManageRealm); routing the toggle attribute write through the
        // IGA capture interceptor would create a SET_REALM_ATTRIBUTE CR
        // instead of actually flipping the flag — leaving the realm in a
        // "lying" state (response says enabled=false but isIGAEnabled still
        // "true" pending CR approval) and arming a one-pending-CR-per-realm
        // 409 trap on the next toggle. IGA_REPLAY_ACTIVE bypasses the
        // wrapper for the duration of the attribute write so the realm
        // attribute is actually flipped (matching the Phase 6b/6d cancel +
        // scan contracts that assume the attribute is real after toggle).
        writeIgaAttributeDirect(IGA_ATTRIBUTE, Boolean.toString(next));
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
            SidecarCapExceededException[] capHolder = new SidecarCapExceededException[1];
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
            } catch (SidecarCapExceededException cap) {
                // Phase 6d cap (design risk #6). Roll back the realm-attribute
                // write so IGA stays OFF — half-enabling is more confusing
                // than refusing — and 409 SIDECAR_CAP_EXCEEDED with the
                // numbers in the body. One INFO log line, no stack.
                capHolder[0] = cap;
                logger.infof("IGA toggle-on refused for realm %s — sidecar cap %d exceeded (current=%d); " +
                                "isIGAEnabled rolled back to false.",
                        realm.getName(), cap.getCap(), cap.getCurrent());
            } catch (RuntimeException ex) {
                // Scan failed entirely — toggle ALREADY committed in the
                // outer transaction. Surface the error in the response but
                // do NOT roll back the toggle (per locked design: scan
                // failure must not block the toggle).
                errHolder[0] = ex;
                logger.errorf(ex, "IGA toggle-on scan FAILED for realm %s — toggle " +
                        "remains enabled, no ADOPT CRs were emitted.", realm.getName());
            }

            if (capHolder[0] != null) {
                // Roll back the realm-attribute write — same outer
                // transaction, so this resets isIGAEnabled to its pre-toggle
                // value (false) before the response is sent. Bypass the
                // IGA capture (the just-written "true" would otherwise make
                // isIgaActive() route this revert through SET_REALM_ATTRIBUTE
                // CR creation instead of an actual rollback).
                writeIgaAttributeDirect(IGA_ATTRIBUTE, Boolean.toString(current));
                Map<String, Object> capBody = new LinkedHashMap<>();
                capBody.put("error", "SIDECAR_CAP_EXCEEDED");
                capBody.put("realmId", capHolder[0].getRealmId());
                capBody.put("cap", capHolder[0].getCap());
                capBody.put("current", capHolder[0].getCurrent());
                return Response.status(Response.Status.CONFLICT).entity(capBody).build();
            }

            if (resultHolder[0] != null) {
                // Phase 6c — invalidate every live user session on the realm
                // so any user newly quarantined by the OFF→ON scan cannot
                // ride an existing cookie/refresh token past the toggle. The
                // design memo's recommendation (accept the re-login storm —
                // simpler than tracking which users were just quarantined and
                // strictly correct) is implemented here as a single bulk
                // removeUserSessions(realm) call against the request-scoped
                // session.sessions() provider. Surface the count in the
                // response so operators see exactly how many sessions were
                // dropped. The bulk method exists in KC 26.5.5
                // (UserSessionProvider.java:190 — verified vs source).
                long invalidated = invalidateRealmSessions(session, realm);
                // Phase 6c regression fix (direct-grant miss): also evict the
                // infinispan user-cache for this realm. KC's UserCacheSession
                // (model/infinispan UserCacheSession.java:262-319) returns a
                // CachedUser-backed UserAdapter whose isEnabled() reads the
                // snapshot stored at cache-load time
                // (model/infinispan UserAdapter.java:166-168) and does NOT
                // delegate to the underlying IgaUserAdapter on each call. If a
                // user was loaded BEFORE the OFF→ON toggle (e.g. a pre-IGA
                // direct-grant seeded the cache with enabled=true), the cache
                // entry keeps returning enabled=true after the toggle even
                // though the IGA quarantine guards on IgaUserAdapter.isEnabled
                // would have refused. Symmetric to removeUserSessions(realm)
                // (login-session invalidation), evict the user-cache so the
                // next session.users() lookup re-loads through
                // IgaUserProvider → IgaUserAdapter and the quarantine override
                // fires. The eviction is per-realm and best-effort: a failure
                // must never abort the toggle (the attribute is already
                // committed and the response is about to be sent).
                evictRealmUserCache(session, realm);
                body.put("scan", resultHolder[0]
                        .withSessionsInvalidated(invalidated).toMap());
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

        // Phase 6d — ON→OFF: cancel PENDING ADOPT CRs + clear sidecar inside
        // its own transaction (mirror of the OFF→ON pattern above). Master
        // is excluded by symmetry: IGA is never enabled on master, so an
        // ON→OFF for master is impossible in practice; the guard is
        // defensive.
        if (current && !next && !"master".equals(realm.getName())) {
            String realmId = realm.getId();
            IgaAdoptCancel.CancelResult[] offHolder = new IgaAdoptCancel.CancelResult[1];
            Throwable[] offErrHolder = new Throwable[1];
            try {
                KeycloakModelUtils.runJobInTransaction(
                        session.getKeycloakSessionFactory(),
                        cancelSession -> {
                            RealmModel cancelRealm = cancelSession.realms().getRealm(realmId);
                            if (cancelRealm == null) {
                                throw new IllegalStateException(
                                        "IGA toggle-off cancel: realm " + realmId + " not loadable in cancel session");
                            }
                            offHolder[0] = IgaAdoptCancel.cancel(cancelSession, cancelRealm);
                        });
            } catch (RuntimeException ex) {
                // Same policy as the scan: toggle attribute ALREADY committed
                // in the outer transaction. Surface the error in the
                // response but do NOT roll back — a half-cleared realm is
                // recoverable; a stuck toggle is not.
                offErrHolder[0] = ex;
                logger.errorf(ex, "IGA toggle-off cancel FAILED for realm %s — toggle remains " +
                        "disabled, sidecar/ADOPT-CR state may be partial.", realm.getName());
            }

            if (offHolder[0] != null) {
                body.put("scanOff", offHolder[0].toMap());
            } else if (offErrHolder[0] != null) {
                Map<String, Object> err = new LinkedHashMap<>();
                err.put("error", offErrHolder[0].getClass().getSimpleName());
                err.put("message", String.valueOf(offErrHolder[0].getMessage()));
                body.put("scanOff", err);
            }
            // Phase 6c regression fix (symmetric): evict the user-cache on
            // ON→OFF too. While IGA was ON, a quarantined user's cached
            // UserAdapter held enabled=false (snapshot of IgaUserAdapter
            // returning false). After ON→OFF the IGA quarantine no longer
            // applies (IgaQuarantineCache.isUserUnsignedWithRoles short-circuits
            // when !isIgaActive), but the stale cache snapshot would still
            // report enabled=false until the entry happened to expire. Evict
            // so the next session.users() lookup re-loads through
            // IgaUserProvider → IgaUserAdapter and reflects the IGA-off state.
            evictRealmUserCache(session, realm);
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
     * Write the realm IGA attribute while bypassing the IGA realm-adapter
     * capture interceptor.
     *
     * <p>{@link org.tidecloak.iga.providers.IgaRealmAdapter#setAttribute}
     * intercepts every realm-attribute write when IGA is currently ON and
     * routes it through a {@code SET_REALM_ATTRIBUTE} change request instead
     * of writing directly. That behaviour is correct for arbitrary realm
     * attributes but fatal for the toggle attribute itself: turning IGA OFF
     * via this endpoint would emit a CR (response lies "enabled=false" while
     * isIGAEnabled stays "true"), the Phase 6d cancel runs against a still-ON
     * realm, and the next toggle hits {@code checkNoPendingCr} → 500 because
     * the prior toggle-off CR is still PENDING.</p>
     *
     * <p>The toggle endpoint IS the governing action (gated by
     * requireManageRealm), so the {@link
     * org.tidecloak.iga.replay.IgaReplayExtension} bypass token
     * {@code IGA_REPLAY_ACTIVE=true} is the correct, established way to
     * declare "this write is the act of governance itself; do not capture
     * it". The wrapper checks the session attribute and short-circuits to
     * {@code super.setAttribute}.</p>
     *
     * <p>try/finally is mandatory — the session is request-scoped and a
     * lingering IGA_REPLAY_ACTIVE on this thread/session would silently
     * disable ALL subsequent IGA capture for the rest of the request,
     * including any nested provider calls invoked by the scan/cancel
     * follow-ups.</p>
     */
    private void writeIgaAttributeDirect(String name, String value) {
        Object prior = session.getAttribute("IGA_REPLAY_ACTIVE");
        session.setAttribute("IGA_REPLAY_ACTIVE", "true");
        try {
            realm.setAttribute(name, value);
        } finally {
            if (prior == null) {
                session.removeAttribute("IGA_REPLAY_ACTIVE");
            } else {
                session.setAttribute("IGA_REPLAY_ACTIVE", prior);
            }
        }
    }

    /**
     * Phase 6c — bulk-invalidate every live user session on the realm after a
     * successful OFF→ON ADOPT scan, returning the number of sessions that
     * were dropped.
     *
     * <p>The brief's design memo recommends invalidating ALL user sessions in
     * the realm and accepting the re-login storm rather than tracking which
     * users were just quarantined: it is simpler, strictly correct (any user
     * whose roles/groups were quarantined will reflect the new state on their
     * next token issuance), and the alternative would require a per-user
     * walk on the same session that just did the scan. KC 26.5.5
     * UserSessionProvider exposes {@code removeUserSessions(RealmModel)} as
     * the bulk primitive (UserSessionProvider.java:190 — used by
     * RealmAdminResource.java:714 for the realm-wide "logout all" admin
     * endpoint), which is exactly the call we need.</p>
     *
     * <p>Counting: KC's bulk method returns void, so we count by streaming the
     * pre-existing sessions per user via {@code getUserSessionsStream} before
     * the bulk removal — but that would be a full table scan. Instead we
     * count by iterating {@code session.users().getUsersStream} and summing
     * the per-user session count via
     * {@code session.sessions().getActiveUserSessions(realm, /*client*&#x2f;null)}
     * — actually the cleanest portable count uses
     * {@code getUserSessionsCount(realm, /*client*&#x2f;null)} but KC 26.5.5
     * only exposes a per-client variant. So the pragmatic, low-overhead
     * approach: call {@code getActiveClientSessionStats(realm, false)} to get
     * the total active count across clients (sum of values), then call the
     * bulk remove. The count is best-effort (logged on overflow) — its
     * primary purpose is operator visibility, not byte-accurate accounting.
     * </p>
     *
     * <p>NB: this method is called on the REQUEST session ({@link #session}),
     * NOT the fresh scan session — the scan-session is closed before the
     * scan returns to its caller, and a fresh runJobInTransaction session
     * does not have a UserSessionProvider wired (it is JPA-only). The
     * request session here is the admin token's session, which has both
     * the JPA provider and the user-session provider.</p>
     */
    private static long invalidateRealmSessions(KeycloakSession session, RealmModel realm) {
        long count = 0L;
        try {
            // Best-effort count BEFORE invalidation. KC's active-client stats
            // returns Map<String,Long> per-client active-session counts;
            // summing approximates the realm-wide live count. If the call
            // raises (some providers don't implement it on every storage
            // backend) we still proceed with the bulk remove and report 0.
            try {
                Map<String, Long> stats =
                        session.sessions().getActiveClientSessionStats(realm, false);
                if (stats != null) {
                    for (Long v : stats.values()) {
                        if (v != null) count += v;
                    }
                }
            } catch (RuntimeException counts) {
                logger.debugf(counts,
                        "invalidateRealmSessions: pre-count failed (best-effort) — proceeding with bulk remove");
            }
            session.sessions().removeUserSessions(realm);
            logger.infof("IGA toggle-on session invalidation: realm=%s sessionsInvalidated~=%d",
                    realm.getName(), count);
        } catch (RuntimeException ex) {
            // Never let a session-invalidation failure abort the toggle —
            // the realm attribute is already committed and the response is
            // about to be sent. Log and return whatever we counted.
            logger.errorf(ex,
                    "IGA toggle-on session invalidation FAILED for realm %s — toggle remains enabled; existing sessions may persist past quarantine.",
                    realm.getName());
        }
        return count;
    }

    /**
     * Phase 6c regression fix (direct-grant miss) — evict every cached user
     * entry for the realm so subsequent {@code session.users().getUserBy*}
     * lookups re-load through {@code IgaUserProvider} and the
     * {@code IgaUserAdapter#isEnabled} quarantine override fires.
     *
     * <p>The infinispan user-cache ({@code model/infinispan UserCacheSession})
     * returns a {@code CachedUser}-backed {@code UserAdapter} whose
     * {@code isEnabled()} reads the snapshot recorded at cache-load time
     * ({@code model/infinispan UserAdapter.java:166-168}) and does NOT delegate
     * to the underlying {@code IgaUserAdapter} on each call. Without an
     * eviction, the OFF→ON toggle does not affect users whose cache entry was
     * seeded before the toggle (e.g. a pre-IGA direct-grant or admin REST read
     * cached {@code enabled=true}); KC's quarantine override is then never
     * consulted on the next direct-grant and an unsigned user incorrectly
     * receives a token.</p>
     *
     * <p>The eviction primitive is {@link UserCache#evict(RealmModel)}
     * ({@code UserCache.java:43} — bulk per-realm eviction). It is the right
     * grain because the OFF→ON scan may have quarantined any number of users
     * in the realm (no per-user information is plumbed back from the scan)
     * and the toggle is a rare admin action — the re-warm cost is acceptable
     * and bounded.</p>
     *
     * <p>Best-effort: if the cache provider isn't installed
     * ({@code UserStorageUtil.userCache(session)} returns {@code null} when
     * the deployment runs without infinispan) or the eviction throws, log
     * and continue. The toggle attribute is already committed and the
     * response is about to be sent — a cache-eviction failure must never
     * abort the toggle.</p>
     */
    private static void evictRealmUserCache(KeycloakSession session, RealmModel realm) {
        try {
            UserCache cache = UserStorageUtil.userCache(session);
            if (cache == null) {
                logger.debugf("IGA toggle user-cache eviction: realm=%s — UserCache provider not installed (skipped)",
                        realm.getName());
                return;
            }
            cache.evict(realm);
            logger.infof("IGA toggle user-cache eviction: realm=%s — evicted (next user lookup will re-load through IgaUserProvider so the quarantine override fires)",
                    realm.getName());
        } catch (RuntimeException ex) {
            // Never let a cache-eviction failure abort the toggle — the
            // realm attribute is already committed and the response is
            // about to be sent. Subsequent reads may show stale isEnabled
            // until the entry expires, but the toggle stays consistent.
            logger.errorf(ex,
                    "IGA toggle user-cache eviction FAILED for realm %s — quarantine reads may be stale until cache entries expire.",
                    realm.getName());
        }
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
