package org.tidecloak.iga.replay;

import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.cache.CacheRealmProvider;
import org.keycloak.models.cache.UserCache;
import org.keycloak.storage.UserStorageUtil;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.services.IgaUnsignedEntityService;

/**
 * Phase 6a replay extension for the capture-then-veto ADOPT workflow.
 *
 * <p>Unlike the existing CREATE_* actions (which create the entity at commit),
 * ADOPT_* actions are about retroactively attesting an entity that ALREADY
 * exists. Replay therefore:
 * <ol>
 *   <li>Verifies the underlying entity still exists. If it was deleted
 *       out-of-band between ADOPT create and ADOPT commit we throw
 *       {@link EntityVanishedException} so the commit endpoint can translate
 *       it into a clean {@code 404 ENTITY_VANISHED} response rather than a
 *       misleading 204/200 on a vanished entity (or, worse, a generic 500
 *       with a full stack trace at ERROR severity).</li>
 *   <li>Performs no entity-model write — that is the whole point of ADOPT
 *       semantics.</li>
 *   <li>Stamps the final attestation onto the entity's {@code ATTESTATION}
 *       column via a JPQL {@code UPDATE} keyed on
 *       {@code WHERE e.id = :id AND e.attestation IS NULL} — borrowing the
 *       same per-table idiom the BASELINE_APPROVAL stamping step uses today
 *       (the BASELINE codepath is being deleted in the same commit; the idiom
 *       lives on as the per-entity ADOPT stamp).</li>
 *   <li>Deletes the matching sidecar row from {@code IGA_UNSIGNED_ENTITY}
 *       (one row per ADOPT_CR_ID — see {@link IgaUnsignedEntityService}).</li>
 *   <li>Marks the change request {@code APPROVED} + sets {@code resolvedAt} —
 *       mirroring the tail-end of {@link IgaReplayDispatcher#replay} for every
 *       other action type, so the commit endpoint's "managed.status =
 *       APPROVED" expectation holds.</li>
 * </ol>
 *
 * <p>Wired into {@link org.tidecloak.iga.rest.IgaAdminResource#commit} via a
 * thin two-line guard BEFORE the existing {@code IgaReplayDispatcher.replay}
 * call: when {@link #tryReplay} returns {@code true} the extension has fully
 * handled the CR; otherwise the dispatcher's switch handles it as before.</p>
 *
 * <p>The dispatcher itself is intentionally NOT touched for ADOPT_* — keeping
 * the new action types out of the giant switch keeps the dispatcher diff to
 * the BASELINE-delete only, and the routing layer becomes the single point of
 * truth for "does Phase 6+ own this action type or not".</p>
 */
public final class IgaReplayExtension {

    private static final Logger log = Logger.getLogger(IgaReplayExtension.class);

    public static final String ACTION_ADOPT_USER = "ADOPT_USER";
    public static final String ACTION_ADOPT_ROLE = "ADOPT_ROLE";
    public static final String ACTION_ADOPT_GROUP = "ADOPT_GROUP";
    public static final String ACTION_ADOPT_CLIENT = "ADOPT_CLIENT";
    public static final String ACTION_ADOPT_CLIENT_SCOPE = "ADOPT_CLIENT_SCOPE";

    public static final String ENTITY_TYPE_USER = "USER";
    public static final String ENTITY_TYPE_ROLE = "ROLE";
    public static final String ENTITY_TYPE_GROUP = "GROUP";
    public static final String ENTITY_TYPE_CLIENT = "CLIENT";
    public static final String ENTITY_TYPE_CLIENT_SCOPE = "CLIENT_SCOPE";

    private IgaReplayExtension() {
    }

    /**
     * Attempt to replay a CR via the Phase 6+ extension. Returns {@code true}
     * iff the extension fully handled the CR (caller skips the dispatcher).
     * Returns {@code false} for any action type the extension does not own.
     */
    public static boolean tryReplay(KeycloakSession session, IgaChangeRequestEntity cr, String finalAttestation) {
        if (cr == null || cr.getActionType() == null) return false;
        switch (cr.getActionType()) {
            case ACTION_ADOPT_USER:
            case ACTION_ADOPT_ROLE:
            case ACTION_ADOPT_GROUP:
            case ACTION_ADOPT_CLIENT:
            case ACTION_ADOPT_CLIENT_SCOPE:
                session.setAttribute("IGA_REPLAY_ACTIVE", "true");
                try {
                    replayAdopt(session, cr, finalAttestation);
                } finally {
                    session.removeAttribute("IGA_REPLAY_ACTIVE");
                }
                return true;
            default:
                return false;
        }
    }

    /**
     * Replay an ADOPT_<type> change request: verify the entity still exists,
     * stamp the attestation on its row, clear the sidecar, then mark the CR
     * APPROVED.
     */
    private static void replayAdopt(KeycloakSession session, IgaChangeRequestEntity cr,
                                     String finalAttestation) {
        RealmModel realm = session.realms().getRealm(cr.getRealmId());
        if (realm == null) {
            throw new IllegalStateException(
                    "ADOPT replay: realm " + cr.getRealmId() + " no longer exists");
        }
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        String entityType = cr.getEntityType();
        String entityId = cr.getEntityId();
        String actionType = cr.getActionType();

        // 1. Verify the entity still exists at replay time. We resolve through
        // KC's own model APIs (not raw JPA) so the existence check honours
        // user-storage federation, client-scope resolution, etc. — anything
        // visible to a stock admin tool. This must NOT silently no-op: a
        // missing entity here means it was deleted out-of-band between ADOPT
        // create and ADOPT commit, and the operator deserves a real error.
        assertEntityExists(session, realm, entityType, entityId, actionType);

        // 2. No entity-model write — that's the whole point of ADOPT.

        // 3. Stamp the attestation onto the entity's row via JPQL UPDATE.
        // Borrowing the per-table idiom from the BASELINE_APPROVAL stamping
        // step (which is being deleted in the same commit; the idiom lives on
        // here as the per-entity ADOPT stamp).
        if (finalAttestation != null && !finalAttestation.isEmpty()) {
            String jpql = stampJpqlFor(actionType);
            int updated = em.createQuery(jpql)
                    .setParameter("sig", finalAttestation)
                    .setParameter("id", entityId)
                    .executeUpdate();
            log.debugf("ADOPT replay: stamped %d row(s) in %s for entity %s/%s",
                    updated, actionType, entityType, entityId);
        }

        // 4. Delete the sidecar row(s) for this CR.
        IgaUnsignedEntityService.clearByAdoptCr(em, cr.getId());

        // 5. Evict KC's cache entry for the just-attested entity so the next
        // read goes through the IGA provider chain and sees the post-ADOPT
        // state (attestation set, sidecar cleared, quarantine satisfied).
        //
        // Without this, a request that previously failed the quarantine check
        // (e.g. a direct-grant against an unsigned user — Phase 6c case 1)
        // leaves KC's UserCacheSession holding a snapshot with enabled=false.
        // The post-toggle realm-wide UserCache eviction in
        // TideAdminCompatResource only clears the cache once at toggle time;
        // any read between toggle and ADOPT-commit can re-populate it with
        // the stale "disabled" snapshot. We must evict per-entity here so
        // that snapshot is replaced on the next lookup.
        //
        // Best-effort: per-entity API where one exists, RuntimeException
        // swallowed and logged at WARN. The CR has been stamped + sidecar
        // cleared by this point; a cache-eviction failure must not abort the
        // replay (caches expire on their own and the post-condition will
        // converge — we just lose a brief window of stale reads).
        evictCacheForAdopt(session, realm, actionType, entityId);

        // 6. Mark APPROVED + resolvedAt on the managed CR — same tail as
        // IgaReplayDispatcher.doReplay.
        IgaChangeRequestEntity managed = em.find(IgaChangeRequestEntity.class, cr.getId());
        if (managed != null) {
            managed.setStatus("APPROVED");
            managed.setResolvedAt(System.currentTimeMillis());
        }
    }

    /**
     * Best-effort per-entity cache eviction for the just-attested ADOPT
     * target. Per-action mapping:
     *
     * <ul>
     *   <li>{@code ADOPT_USER}: {@link UserCache#evict(RealmModel, UserModel)}
     *       — {@code keycloak-model-storage} {@code UserCache.java:36}. The
     *       per-user variant (not the realm-wide {@code evict(RealmModel)})
     *       so a single ADOPT commit doesn't blow the entire realm's user
     *       cache.</li>
     *   <li>{@code ADOPT_CLIENT}: {@link CacheRealmProvider#registerClientInvalidation}
     *       — {@code keycloak-model-storage-private} {@code CacheRealmProvider.java:36};
     *       implementation in {@code RealmCacheSession.java:252} invalidates
     *       the cached client adapter + sends a cluster invalidation event.</li>
     *   <li>{@code ADOPT_GROUP}: {@link CacheRealmProvider#registerGroupInvalidation}
     *       — {@code CacheRealmProvider.java:41}; {@code RealmCacheSession.java:334}.</li>
     *   <li>{@code ADOPT_ROLE}: {@link CacheRealmProvider#registerRoleInvalidation}
     *       — {@code CacheRealmProvider.java:39}; {@code RealmCacheSession.java:278}.
     *       Requires the role name and container id, which we resolve via the
     *       model API (same lookup the assertEntityExists path uses).</li>
     *   <li>{@code ADOPT_CLIENT_SCOPE}:
     *       {@link CacheRealmProvider#registerClientScopeInvalidation}
     *       — {@code CacheRealmProvider.java:37}; {@code RealmCacheSession.java:265}.</li>
     * </ul>
     *
     * <p>If either cache provider isn't installed (deployments without the
     * infinispan model — {@code session.getProvider(...)} returns {@code null})
     * we log a WARN and continue. The CR is still APPROVED; the cache will
     * converge as entries expire on their own.</p>
     *
     * <p>Wraps the whole body in a try/catch on {@link RuntimeException}: the
     * eviction is a post-commit convenience, not a correctness requirement
     * for the attestation itself (the JPQL stamp + sidecar delete have
     * already committed by this point on the same JPA transaction). A failure
     * here must not abort the replay or leave the CR PENDING.</p>
     */
    private static void evictCacheForAdopt(KeycloakSession session, RealmModel realm,
                                            String actionType, String entityId) {
        try {
            switch (actionType) {
                case ACTION_ADOPT_USER: {
                    UserCache userCache = UserStorageUtil.userCache(session);
                    if (userCache == null) {
                        log.warnf("IGA ADOPT cache eviction: type=USER id=%s realm=%s — UserCache provider not installed (skipped)",
                                entityId, realm.getId());
                        return;
                    }
                    UserModel u = session.users().getUserById(realm, entityId);
                    if (u == null) {
                        log.warnf("IGA ADOPT cache eviction: type=USER id=%s realm=%s — user vanished between stamp and evict (skipped)",
                                entityId, realm.getId());
                        return;
                    }
                    userCache.evict(realm, u);
                    log.infof("IGA ADOPT cache eviction: type=USER id=%s realm=%s — evicted",
                            entityId, realm.getId());
                    return;
                }
                case ACTION_ADOPT_CLIENT: {
                    CacheRealmProvider realmCache = session.getProvider(CacheRealmProvider.class);
                    if (realmCache == null) {
                        log.warnf("IGA ADOPT cache eviction: type=CLIENT id=%s realm=%s — CacheRealmProvider not installed (skipped)",
                                entityId, realm.getId());
                        return;
                    }
                    ClientModel c = session.clients().getClientById(realm, entityId);
                    String clientId = (c != null ? c.getClientId() : entityId);
                    realmCache.registerClientInvalidation(entityId, clientId, realm.getId());
                    log.infof("IGA ADOPT cache eviction: type=CLIENT id=%s realm=%s — evicted",
                            entityId, realm.getId());
                    return;
                }
                case ACTION_ADOPT_GROUP: {
                    CacheRealmProvider realmCache = session.getProvider(CacheRealmProvider.class);
                    if (realmCache == null) {
                        log.warnf("IGA ADOPT cache eviction: type=GROUP id=%s realm=%s — CacheRealmProvider not installed (skipped)",
                                entityId, realm.getId());
                        return;
                    }
                    realmCache.registerGroupInvalidation(entityId);
                    // ADOPT_GROUP may unblock users currently quarantined via
                    // group-membership fan-out (IgaUserAdapter.getGroupsStream
                    // silent-strip). The user-cache snapshots each user's
                    // group set + isEnabled() at load time, so realm-wide
                    // user-cache eviction is required for the change to be
                    // observable on the next direct-grant. No cheap per-user
                    // evict exists (KC offers no group→user reverse index in
                    // the cache APIs).
                    evictRealmUserCacheFallback(session, realm, "ADOPT_GROUP", entityId);
                    log.infof("IGA ADOPT cache eviction: type=GROUP id=%s realm=%s — evicted",
                            entityId, realm.getId());
                    return;
                }
                case ACTION_ADOPT_ROLE: {
                    CacheRealmProvider realmCache = session.getProvider(CacheRealmProvider.class);
                    if (realmCache == null) {
                        log.warnf("IGA ADOPT cache eviction: type=ROLE id=%s realm=%s — CacheRealmProvider not installed (skipped)",
                                entityId, realm.getId());
                        return;
                    }
                    RoleModel r = session.roles().getRoleById(realm, entityId);
                    if (r == null) {
                        log.warnf("IGA ADOPT cache eviction: type=ROLE id=%s realm=%s — role vanished between stamp and evict (skipped)",
                                entityId, realm.getId());
                        return;
                    }
                    String roleName = r.getName();
                    String containerId = (r.getContainerId() != null ? r.getContainerId() : realm.getId());
                    realmCache.registerRoleInvalidation(entityId, roleName, containerId);
                    // ADOPT_ROLE unblocks every user mapped to this role
                    // (IgaQuarantineCache.isUserUnsignedWithRoles role
                    // fan-out). UserCacheSession holds each user's isEnabled()
                    // snapshot computed when the role was still unsigned; per-
                    // user evict isn't feasible (no role→user reverse index
                    // cheaper than walking all role members), so we fall back
                    // to a realm-wide user-cache eviction — the same lever
                    // the toggle-on path uses (TideAdminCompatResource
                    // .evictRealmUserCache).
                    evictRealmUserCacheFallback(session, realm, "ADOPT_ROLE", entityId);
                    log.infof("IGA ADOPT cache eviction: type=ROLE id=%s realm=%s — evicted",
                            entityId, realm.getId());
                    return;
                }
                case ACTION_ADOPT_CLIENT_SCOPE: {
                    CacheRealmProvider realmCache = session.getProvider(CacheRealmProvider.class);
                    if (realmCache == null) {
                        log.warnf("IGA ADOPT cache eviction: type=CLIENT_SCOPE id=%s realm=%s — CacheRealmProvider not installed (skipped)",
                                entityId, realm.getId());
                        return;
                    }
                    realmCache.registerClientScopeInvalidation(entityId, realm.getId());
                    log.infof("IGA ADOPT cache eviction: type=CLIENT_SCOPE id=%s realm=%s — evicted",
                            entityId, realm.getId());
                    return;
                }
                default:
                    log.warnf("IGA ADOPT cache eviction: unknown action type %s — no eviction performed",
                            actionType);
            }
        } catch (RuntimeException ex) {
            // Best-effort. CR is already stamped + sidecar cleared on this
            // transaction; the next admin write or natural TTL will refresh
            // the cache. Log and move on — do not propagate.
            log.warnf(ex, "IGA ADOPT cache eviction FAILED: action=%s id=%s realm=%s — stale read window until cache entry expires",
                    actionType, entityId, realm.getId());
        }
    }

    /**
     * Realm-wide user-cache eviction lever shared by ADOPT_ROLE / ADOPT_GROUP.
     * The user's quarantine verdict
     * ({@link org.tidecloak.iga.providers.IgaUserAdapter#isEnabled}) depends
     * on the signed status of every role/group the user holds (the role/group
     * fan-out branch of {@link org.tidecloak.iga.services.IgaQuarantineCache
     * #isUserUnsignedWithRoles}). When a role/group just transitioned from
     * unsigned to signed, every user mapped to it has a stale
     * {@code enabled=false} snapshot in KC's UserCacheSession. Per-user evict
     * isn't reachable from here (KC offers no cheap role→user / group→user
     * reverse index — walking all members would defeat the point of caching)
     * so we evict the realm-wide user cache, the same lever
     * {@link org.tidecloak.iga.rest.TideAdminCompatResource} uses on the
     * OFF→ON toggle path. Best-effort: catches all RuntimeExceptions and
     * logs at WARN — eviction failure must not abort the replay.
     */
    private static void evictRealmUserCacheFallback(KeycloakSession session, RealmModel realm,
                                                     String actionType, String entityId) {
        try {
            UserCache userCache = UserStorageUtil.userCache(session);
            if (userCache == null) {
                log.warnf("IGA ADOPT realm-user-cache fallback: action=%s id=%s realm=%s — UserCache provider not installed (skipped)",
                        actionType, entityId, realm.getId());
                return;
            }
            userCache.evict(realm);
            log.infof("IGA ADOPT realm-user-cache fallback: action=%s id=%s realm=%s — realm user cache evicted (role/group fan-out)",
                    actionType, entityId, realm.getId());
        } catch (RuntimeException ex) {
            log.warnf(ex, "IGA ADOPT realm-user-cache fallback FAILED: action=%s id=%s realm=%s",
                    actionType, entityId, realm.getId());
        }
    }

    /**
     * Resolve the entity through KC's model APIs. Throws
     * {@link EntityVanishedException} when missing — the commit endpoint
     * catches it and returns a structured {@code 404 ENTITY_VANISHED}
     * response with a single INFO log line, far preferable to either a silent
     * no-op (leaving a stale APPROVED CR pointing at a vanished entity) or a
     * generic 500 with a full stack trace at ERROR severity (which is what a
     * raw {@code IllegalStateException} would produce via KC's catch-all
     * uncaught-exception handler).
     */
    private static void assertEntityExists(KeycloakSession session, RealmModel realm,
                                            String entityType, String entityId, String actionType) {
        boolean exists;
        switch (actionType) {
            case ACTION_ADOPT_USER: {
                UserModel u = session.users().getUserById(realm, entityId);
                exists = u != null;
                break;
            }
            case ACTION_ADOPT_ROLE: {
                RoleModel r = session.roles().getRoleById(realm, entityId);
                exists = r != null;
                break;
            }
            case ACTION_ADOPT_GROUP: {
                GroupModel g = session.groups().getGroupById(realm, entityId);
                exists = g != null;
                break;
            }
            case ACTION_ADOPT_CLIENT: {
                ClientModel c = session.clients().getClientById(realm, entityId);
                exists = c != null;
                break;
            }
            case ACTION_ADOPT_CLIENT_SCOPE: {
                ClientScopeModel cs = session.clientScopes().getClientScopeById(realm, entityId);
                exists = cs != null;
                break;
            }
            default:
                throw new IllegalStateException("ADOPT replay: unknown action type " + actionType);
        }
        if (!exists) {
            throw new EntityVanishedException(entityType, entityId, realm.getId());
        }
    }

    /**
     * Per-action JPQL stamp template. Same shape used today by every CREATE_*
     * replay (and previously by replayBaselineApproval) — UPDATE
     * &lt;entity&gt; e SET e.attestation = :sig WHERE e.id = :id AND
     * e.attestation IS NULL.
     */
    private static String stampJpqlFor(String actionType) {
        switch (actionType) {
            case ACTION_ADOPT_USER:
                return "UPDATE UserEntity e SET e.attestation = :sig WHERE e.id = :id AND e.attestation IS NULL";
            case ACTION_ADOPT_ROLE:
                return "UPDATE RoleEntity e SET e.attestation = :sig WHERE e.id = :id AND e.attestation IS NULL";
            case ACTION_ADOPT_GROUP:
                return "UPDATE GroupEntity e SET e.attestation = :sig WHERE e.id = :id AND e.attestation IS NULL";
            case ACTION_ADOPT_CLIENT:
                return "UPDATE ClientEntity e SET e.attestation = :sig WHERE e.id = :id AND e.attestation IS NULL";
            case ACTION_ADOPT_CLIENT_SCOPE:
                return "UPDATE ClientScopeEntity e SET e.attestation = :sig WHERE e.id = :id AND e.attestation IS NULL";
            default:
                throw new IllegalStateException("ADOPT replay: no stamp JPQL for action " + actionType);
        }
    }
}
