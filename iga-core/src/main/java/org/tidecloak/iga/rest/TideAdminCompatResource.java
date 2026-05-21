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
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.cache.CacheRealmProvider;
import org.keycloak.models.cache.UserCache;
import org.keycloak.models.OrganizationModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.organization.OrganizationProvider;
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
                // Phase 6c regression fix (CLIENT quarantine miss, symmetric to
                // the user-cache eviction above). KC's RealmCacheSession
                // (model/infinispan RealmCacheSession.java:1170-1192,
                // 1215-1248) caches client snapshots as CachedClient and the
                // resulting ClientAdapter.isEnabled() returns
                // cached.isEnabled() (ClientAdapter.java:150-152) rather than
                // delegating to IgaClientAdapter.isEnabled() (quarantine REFUSE
                // hook at IgaClientAdapter.java:634). A confidential client
                // whose entry was loaded pre-IGA (e.g. a pre-toggle
                // client_credentials call) keeps returning enabled=true after
                // the OFF→ON toggle, so the unsigned-client client_credentials
                // is wrongly granted a 200 (observed in
                // iga-phase6c-client-e2e CASE 3). Evict the per-realm
                // client/role/group/scope cache entries so the next read
                // re-loads through the IGA wrappers and the quarantine fires.
                // Same best-effort contract as the user-cache eviction — never
                // abort the toggle on cache failure.
                evictRealmCache(session, realm);
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
            // Phase 6c regression fix (symmetric, client/role/group/scope
            // realm-cache). While IGA was ON, the cached ClientAdapter for a
            // client that toggled-on hit the quarantine path may hold
            // enabled=false from the IgaClientAdapter snapshot. After ON→OFF
            // the quarantine no longer applies, but the realm-cache snapshot
            // would still report enabled=false until the entry expires. Evict
            // so the next session.clients()/realm.getRole/group/scope read
            // re-loads through the IGA providers and reflects the IGA-off
            // state. Symmetric to the OFF→ON call above and the user-cache
            // eviction on this same branch.
            evictRealmCache(session, realm);
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
     * Phase 6c regression fix (CLIENT quarantine, symmetric to
     * {@link #evictRealmUserCache}) — evict every cached client / role / group
     * / client-scope entry for the realm so subsequent
     * {@code session.clients()} / {@code realm.getRole*} / {@code realm.getGroup*}
     * / {@code realm.getClientScopes*} reads re-load through the IGA wrappers
     * ({@link org.tidecloak.iga.providers.IgaClientAdapter} and friends) and
     * the quarantine overrides ({@code isEnabled()} REFUSE on clients,
     * {@code getScopeMappingsStream} STRIP on client scopes, etc.) fire on
     * the next call.
     *
     * <p>KC's realm-cache ({@code model/infinispan RealmCacheSession.java:1170-1192,
     * 1215-1248}) returns a {@code CachedClient}-backed {@link
     * org.keycloak.models.cache.infinispan.ClientAdapter} whose
     * {@code isEnabled()} reads the snapshot recorded at cache-load time
     * ({@code ClientAdapter.java:150-152}) and does NOT delegate to the
     * underlying {@link org.tidecloak.iga.providers.IgaClientAdapter} on each
     * call. Without an eviction, the OFF→ON toggle does not affect clients
     * whose realm-cache entry was seeded before the toggle (e.g. a pre-IGA
     * {@code client_credentials} call cached {@code enabled=true}); the
     * quarantine REFUSE hook is then never consulted on the next
     * {@code client_credentials} and the unsigned client incorrectly receives
     * a token. The same snapshot-bypass applies to cached
     * {@code CachedRole}/{@code CachedGroup}/{@code CachedClientScope} for the
     * realm: each has an IGA wrapper whose enforcement is skipped when the
     * realm-cache returns its own adapter.</p>
     *
     * <p>API choice: {@code CacheRealmProvider.registerRealmInvalidation(id, name)}
     * ({@code keycloak-model-storage-private/.../CacheRealmProvider.java:34};
     * impl at {@code RealmCacheSession.java:239-246} via
     * {@code RealmCacheManager.realmUpdated:56-59}) invalidates only the
     * realm entry + its by-name key — it does NOT cascade to clients/roles/
     * groups/scopes (verified against the impl: {@code realmUpdated}
     * adds only {@code id} and {@code getRealmByNameCacheKey(name)}). The
     * coarser primitive {@code RealmCacheSession.evictRealmOnRemoval} sweeps
     * everything in-realm but emits a {@link
     * org.keycloak.models.cache.infinispan.events.RealmRemovedEvent} that
     * would falsely tell the cluster the realm is gone — not safe to reuse.
     * The surgical correct primitive is per-entity:
     * {@code registerClientInvalidation(uuid, clientId, realmId)} +
     * {@code registerRoleInvalidation(id, name, containerId)} +
     * {@code registerGroupInvalidation(id)} +
     * {@code registerClientScopeInvalidation(id, realmId)}, each of which
     * drops the corresponding cache entry on transaction commit (see the
     * {@code registerXInvalidation} bodies at {@code RealmCacheSession.java:
     * 248-279, 261-272, 330-348}). We iterate the four entity collections on
     * the realm and call each. The iterators
     * ({@code realm.getClientsStream}, {@code session.roles().getRealmRolesStream},
     * {@code realm.getGroupsStream}, {@code realm.getClientScopesStream}) all
     * delegate past the cache (verified at
     * {@code RealmCacheSession.java:648-654, 1026-1062}) so iteration does
     * not re-warm what we are about to evict.</p>
     *
     * <p>The toggle is a rare admin action; the re-warm cost is bounded by
     * the realm's entity counts and acceptable. Best-effort wrapping: if the
     * {@link CacheRealmProvider} is not installed (deployment running without
     * the infinispan realm-cache layer) the lookup returns {@code null} and
     * we log and return. If any individual register-invalidation throws, we
     * catch and continue with the next entity — the toggle attribute is
     * already committed and the response is about to be sent; a partial
     * eviction is preferable to an aborted toggle.</p>
     */
    private static void evictRealmCache(KeycloakSession session, RealmModel realm) {
        CacheRealmProvider cache;
        try {
            cache = session.getProvider(CacheRealmProvider.class);
        } catch (RuntimeException lookupEx) {
            logger.warnf(lookupEx,
                    "IGA toggle realm-cache eviction: realm=%s — CacheRealmProvider lookup failed (skipped); quarantine reads on cached clients/roles/groups/scopes may be stale until entries expire.",
                    realm.getName());
            return;
        }
        if (cache == null) {
            logger.debugf("IGA toggle realm-cache eviction: realm=%s — CacheRealmProvider not installed (skipped)",
                    realm.getName());
            return;
        }

        String realmId = realm.getId();
        int clients = 0, roles = 0, groups = 0, scopes = 0, orgs = 0, idps = 0;

        // Clients — the immediate Phase 6c CASE 3 fix surface.
        try {
            for (ClientModel client : realm.getClientsStream().toList()) {
                try {
                    cache.registerClientInvalidation(client.getId(), client.getClientId(), realmId);
                    clients++;
                } catch (RuntimeException ex) {
                    logger.debugf(ex,
                            "IGA toggle realm-cache eviction: client=%s (uuid=%s) realm=%s — registerClientInvalidation failed (continuing).",
                            client.getClientId(), client.getId(), realm.getName());
                }
            }
        } catch (RuntimeException ex) {
            logger.warnf(ex,
                    "IGA toggle realm-cache eviction: realm=%s — client iteration failed after evicting %d (continuing with roles/groups/scopes).",
                    realm.getName(), clients);
        }

        // Realm-level roles + per-client roles. IgaRoleAdapter holds the
        // role-side IGA hooks; a cached RoleAdapter snapshot would bypass them.
        try {
            for (RoleModel role : session.roles().getRealmRolesStream(realm).toList()) {
                try {
                    cache.registerRoleInvalidation(role.getId(), role.getName(), realmId);
                    roles++;
                } catch (RuntimeException ex) {
                    logger.debugf(ex,
                            "IGA toggle realm-cache eviction: realm-role=%s (id=%s) realm=%s — registerRoleInvalidation failed (continuing).",
                            role.getName(), role.getId(), realm.getName());
                }
            }
            for (ClientModel client : realm.getClientsStream().toList()) {
                try {
                    for (RoleModel role : session.roles().getClientRolesStream(client).toList()) {
                        try {
                            cache.registerRoleInvalidation(role.getId(), role.getName(), client.getId());
                            roles++;
                        } catch (RuntimeException ex) {
                            logger.debugf(ex,
                                    "IGA toggle realm-cache eviction: client-role=%s (id=%s) container=%s realm=%s — registerRoleInvalidation failed (continuing).",
                                    role.getName(), role.getId(), client.getId(), realm.getName());
                        }
                    }
                } catch (RuntimeException ex) {
                    logger.debugf(ex,
                            "IGA toggle realm-cache eviction: realm=%s client=%s — client-roles iteration failed (continuing).",
                            realm.getName(), client.getClientId());
                }
            }
        } catch (RuntimeException ex) {
            logger.warnf(ex,
                    "IGA toggle realm-cache eviction: realm=%s — role iteration failed after evicting %d (continuing with groups/scopes).",
                    realm.getName(), roles);
        }

        // Groups.
        try {
            for (GroupModel group : realm.getGroupsStream().toList()) {
                try {
                    cache.registerGroupInvalidation(group.getId());
                    groups++;
                } catch (RuntimeException ex) {
                    logger.debugf(ex,
                            "IGA toggle realm-cache eviction: group=%s (id=%s) realm=%s — registerGroupInvalidation failed (continuing).",
                            group.getName(), group.getId(), realm.getName());
                }
            }
        } catch (RuntimeException ex) {
            logger.warnf(ex,
                    "IGA toggle realm-cache eviction: realm=%s — group iteration failed after evicting %d (continuing with scopes).",
                    realm.getName(), groups);
        }

        // Client scopes.
        try {
            for (ClientScopeModel scope : realm.getClientScopesStream().toList()) {
                try {
                    cache.registerClientScopeInvalidation(scope.getId(), realmId);
                    scopes++;
                } catch (RuntimeException ex) {
                    logger.debugf(ex,
                            "IGA toggle realm-cache eviction: scope=%s (id=%s) realm=%s — registerClientScopeInvalidation failed (continuing).",
                            scope.getName(), scope.getId(), realm.getName());
                }
            }
        } catch (RuntimeException ex) {
            logger.warnf(ex,
                    "IGA toggle realm-cache eviction: realm=%s — client-scope iteration failed after evicting %d.",
                    realm.getName(), scopes);
        }

        // Phase 7b — organizations. KC's CacheRealmProvider has no public
        // registerOrgInvalidation primitive (the InfinispanOrganizationProvider's
        // registerOrganizationInvalidation is package-private), but the cached
        // CachedOrganization is keyed on the org id alone
        // (InfinispanOrganizationProvider.java:94 in KC 26.5.5) and that key
        // is invalidated via the public CacheRealmProvider.registerInvalidation(id)
        // call — see the same primitive used in
        // IgaReplayExtension.evictCacheForAdopt's ADOPT_ORGANIZATION branch.
        //
        // Iterate via OrganizationProvider (the SPI surface KC uses everywhere
        // else); skip silently if the realm doesn't have orgs feature on
        // (provider returns empty stream) or the provider isn't installed at
        // all. Best-effort wrapping mirrors the clients/roles/groups/scopes
        // branches above.
        try {
            OrganizationProvider orgProvider = session.getProvider(OrganizationProvider.class);
            if (orgProvider != null) {
                for (OrganizationModel org : orgProvider.getAllStream().toList()) {
                    try {
                        cache.registerInvalidation(org.getId());
                        orgs++;
                    } catch (RuntimeException ex) {
                        logger.debugf(ex,
                                "IGA toggle realm-cache eviction: org=%s (id=%s) realm=%s — registerInvalidation failed (continuing).",
                                org.getName(), org.getId(), realm.getName());
                    }
                }
            }
        } catch (RuntimeException ex) {
            logger.warnf(ex,
                    "IGA toggle realm-cache eviction: realm=%s — organization iteration failed after evicting %d.",
                    realm.getName(), orgs);
        }

        // Phase 7d — identity providers. IdPs aren't quarantineable entities
        // (toggle-on doesn't scan IdPs, no IGA_UNSIGNED_ENTITY rows) but the
        // Phase 7d IdP-aware scope resolver reads iga.approverRole /
        // iga.threshold off IdentityProviderModel.getConfig() via
        // session.identityProviders().getByAlias(...). That path goes through
        // InfinispanIdentityProviderStorageProvider which caches the
        // CachedIdentityProvider snapshot under two keys: the internalId and
        // realmId + "." + alias + ".idp.alias" (see
        // InfinispanIdentityProviderStorageProvider.cacheKeyIdpAlias:69 in
        // KC 26.5.5 — both suffix constants are private). Without invalidating
        // those entries, an iga.approverRole / iga.threshold edit on an IdP
        // made BEFORE toggle-on could remain stale post-toggle, letting an
        // ORG_ADD_IDP / ORG_REMOVE_IDP CR resolve against pre-edit config and
        // produce the wrong gate verdict. We reconstruct the alias key here
        // (KC's suffix string is identical and the realmId-prefixed shape is
        // stable across the cache lifecycle).
        //
        // Iterate via realm.getIdentityProvidersStream() — the deprecated
        // accessor is still the simplest surface; the canonical
        // IdentityProviderStorageProvider.getAllStream() requires constructing
        // an IdentityProviderQuery which adds noise for no functional gain
        // here.
        try {
            for (IdentityProviderModel idp : realm.getIdentityProvidersStream().toList()) {
                try {
                    if (idp.getInternalId() != null) {
                        cache.registerInvalidation(idp.getInternalId());
                    }
                    if (idp.getAlias() != null) {
                        cache.registerInvalidation(realmId + "." + idp.getAlias() + ".idp.alias");
                    }
                    idps++;
                } catch (RuntimeException ex) {
                    logger.debugf(ex,
                            "IGA toggle realm-cache eviction: idp=%s (id=%s) realm=%s — registerInvalidation failed (continuing).",
                            idp.getAlias(), idp.getInternalId(), realm.getName());
                }
            }
        } catch (RuntimeException ex) {
            logger.warnf(ex,
                    "IGA toggle realm-cache eviction: realm=%s — idp iteration failed after evicting %d.",
                    realm.getName(), idps);
        }

        logger.infof("IGA toggle realm-cache eviction: realm=%s — evicted clients=%d roles=%d groups=%d scopes=%d orgs=%d idps=%d (next client/role/group/scope/org/idp read will re-load through IGA providers so the quarantine override fires)",
                realm.getName(), clients, roles, groups, scopes, orgs, idps);
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
