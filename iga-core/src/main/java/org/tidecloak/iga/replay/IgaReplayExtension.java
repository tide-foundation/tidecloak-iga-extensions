package org.tidecloak.iga.replay;

import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OrganizationModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.cache.CacheRealmProvider;
import org.keycloak.models.cache.UserCache;
import org.keycloak.organization.OrganizationProvider;
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
    /**
     * Phase 7b — retroactive ADOPT for KC organizations.
     *
     * <p>Sidecar-only governance: orgs reuse the existing
     * {@code IGA_UNSIGNED_ENTITY} table with {@code entity_type='ORGANIZATION'}.
     * Unlike the other five entity types, {@code OrganizationEntity} has NO
     * {@code attestation} column (see {@link IgaReplayDispatcher} line 496-497
     * for the design choice). Replay therefore performs NO JPQL stamp; the
     * commit is signalled entirely by the sidecar-row deletion + the CR's
     * {@code status=APPROVED} transition.</p>
     */
    public static final String ACTION_ADOPT_ORGANIZATION = "ADOPT_ORGANIZATION";

    // -------------------------------------------------------------------------
    // Commit 2 — EDGE ADOPT actions. These attest admin-configured pre-existing
    // EDGE rows (not nodes) on the toggle-on scan. Unlike the node ADOPTs, the
    // stamp is keyed by the edge's composite keys (carried in rowsJson), not by
    // a single entityId. They share the SAME threshold/approver bypass and the
    // SAME no-model-write semantics as the node ADOPTs.
    // -------------------------------------------------------------------------
    public static final String ACTION_ADOPT_COMPOSITE_ROLE = "ADOPT_COMPOSITE_ROLE";
    public static final String ACTION_ADOPT_CLIENT_SCOPE_CLIENT = "ADOPT_CLIENT_SCOPE_CLIENT";
    public static final String ACTION_ADOPT_CLIENT_SCOPE_ROLE = "ADOPT_CLIENT_SCOPE_ROLE";
    public static final String ACTION_ADOPT_PROTOCOL_MAPPER = "ADOPT_PROTOCOL_MAPPER";
    /**
     * Commit 3 — retroactive ADOPT for realm default-default / default-optional
     * client-scope assignments ({@code DEFAULT_CLIENT_SCOPE} rows). An edge
     * keyed (realmId, scopeId), stamped on the {@code ATTESTATION} column added
     * by iga-changelog-2.3.0. Built-in default-scope rows (those pointing at a
     * KC default scope — profile/email/roles/...) are SKIPPED by the scan's
     * owning-SCOPE built-in classification; only admin-authored custom scopes
     * set as realm defaults are adopted.
     */
    public static final String ACTION_ADOPT_DEFAULT_CLIENT_SCOPE = "ADOPT_DEFAULT_CLIENT_SCOPE";

    public static final String ENTITY_TYPE_USER = "USER";
    public static final String ENTITY_TYPE_ROLE = "ROLE";
    public static final String ENTITY_TYPE_GROUP = "GROUP";
    public static final String ENTITY_TYPE_CLIENT = "CLIENT";
    public static final String ENTITY_TYPE_CLIENT_SCOPE = "CLIENT_SCOPE";
    public static final String ENTITY_TYPE_ORGANIZATION = "ORGANIZATION";

    // Commit 2 — edge entity types (sidecar entity_type + CR entityType).
    public static final String ENTITY_TYPE_COMPOSITE_ROLE = "COMPOSITE_ROLE";
    public static final String ENTITY_TYPE_CLIENT_SCOPE_CLIENT = "CLIENT_SCOPE_CLIENT";
    public static final String ENTITY_TYPE_CLIENT_SCOPE_ROLE = "CLIENT_SCOPE_ROLE";
    public static final String ENTITY_TYPE_PROTOCOL_MAPPER = "PROTOCOL_MAPPER";
    // Commit 3 — realm default-scope edge (DEFAULT_CLIENT_SCOPE row, keyed
    // realmId+scopeId; owning node is the client-SCOPE for built-in skip).
    public static final String ENTITY_TYPE_REALM_DEFAULT_SCOPE = "REALM_DEFAULT_SCOPE";

    private IgaReplayExtension() {
    }

    /**
     * Single source of truth for "is this action type one of the five ADOPT_*
     * variants owned by the Phase 6+ extension router". Used by the
     * {@link org.tidecloak.iga.rest.IgaAdminResource} resume-from-CANCELLED
     * lane and by {@link org.tidecloak.iga.attestors.IgaScopeResolver} to
     * short-circuit the threshold + approver-role gates: ADOPT_* CRs are a
     * system-bootstrap onramp (the entity already exists in production
     * pre-IGA), so applying the realm's governance threshold + approver-role
     * gate to them creates a chicken-and-egg deadlock where high-threshold
     * realms with pre-IGA admins can't bootstrap. Any caller with
     * {@code manage-realm} (already enforced by
     * {@code IgaAdminResource.authorize}/{@code commit}) can authorize + commit
     * an ADOPT_* in one signature.
     */
    public static boolean isAdoptAction(String actionType) {
        if (actionType == null) return false;
        return ACTION_ADOPT_USER.equals(actionType)
                || ACTION_ADOPT_ROLE.equals(actionType)
                || ACTION_ADOPT_GROUP.equals(actionType)
                || ACTION_ADOPT_CLIENT.equals(actionType)
                || ACTION_ADOPT_CLIENT_SCOPE.equals(actionType)
                || ACTION_ADOPT_ORGANIZATION.equals(actionType)
                // Commit 2 — edge ADOPTs share the same bootstrap-onramp
                // bypass: an edge admin-configured pre-IGA cannot be subjected
                // to the realm threshold/approver gate without the same
                // chicken-and-egg deadlock the node ADOPTs avoid.
                || ACTION_ADOPT_COMPOSITE_ROLE.equals(actionType)
                || ACTION_ADOPT_CLIENT_SCOPE_CLIENT.equals(actionType)
                || ACTION_ADOPT_CLIENT_SCOPE_ROLE.equals(actionType)
                || ACTION_ADOPT_PROTOCOL_MAPPER.equals(actionType)
                || ACTION_ADOPT_DEFAULT_CLIENT_SCOPE.equals(actionType);
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
            case ACTION_ADOPT_ORGANIZATION:
                session.setAttribute("IGA_REPLAY_ACTIVE", "true");
                try {
                    replayAdopt(session, cr, finalAttestation);
                } finally {
                    session.removeAttribute("IGA_REPLAY_ACTIVE");
                }
                return true;
            case ACTION_ADOPT_COMPOSITE_ROLE:
            case ACTION_ADOPT_CLIENT_SCOPE_CLIENT:
            case ACTION_ADOPT_CLIENT_SCOPE_ROLE:
            case ACTION_ADOPT_PROTOCOL_MAPPER:
            case ACTION_ADOPT_DEFAULT_CLIENT_SCOPE:
                session.setAttribute("IGA_REPLAY_ACTIVE", "true");
                try {
                    replayAdoptEdge(session, cr, finalAttestation);
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
        //
        // Phase 7b — ADOPT_ORGANIZATION SKIPS this step: OrganizationEntity
        // has no `attestation` column (see IgaReplayDispatcher.java:496-497
        // for the design choice — orgs are governed by the sidecar row alone
        // because cross-repo schema changes were out of scope). The sidecar
        // delete in step 4 + the APPROVED status in step 6 are the entire
        // "signed" post-condition for an org.
        if (finalAttestation != null && !finalAttestation.isEmpty()
                && !ACTION_ADOPT_ORGANIZATION.equals(actionType)) {
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
     * Replay an edge ADOPT (commit 2). Like {@link #replayAdopt} this performs
     * NO model write — the edge already exists. It stamps the attestation onto
     * the edge row(s) via JPQL keyed on the edge's COMPOSITE keys (carried in
     * the CR's rowsJson, NOT the single entityId), then clears the sidecar and
     * marks the CR APPROVED. The stamp JPQL mirrors the existing edge stamps in
     * {@link IgaReplayDispatcher} exactly:
     * <ul>
     *   <li>COMPOSITE_ROLE keyed (parent, child) — like ADD_COMPOSITE;</li>
     *   <li>CLIENT_SCOPE_CLIENT keyed (client, scope) — like ASSIGN_SCOPE;</li>
     *   <li>CLIENT_SCOPE_ROLE_MAPPING keyed (scope, role) — like SCOPE_ADD_ROLE;</li>
     *   <li>PROTOCOL_MAPPER keyed (id) — like ADD_PROTOCOL_MAPPER's stamp.</li>
     * </ul>
     * Each row carries an {@code AND e.attestation IS NULL} guard so a re-toggle
     * never re-stamps an already-attested edge.
     */
    private static void replayAdoptEdge(KeycloakSession session, IgaChangeRequestEntity cr,
                                        String finalAttestation) {
        RealmModel realm = session.realms().getRealm(cr.getRealmId());
        if (realm == null) {
            throw new IllegalStateException(
                    "ADOPT edge replay: realm " + cr.getRealmId() + " no longer exists");
        }
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        String actionType = cr.getActionType();
        java.util.List<java.util.Map<String, Object>> rows = parseRows(cr.getRowsJson());

        if (finalAttestation != null && !finalAttestation.isEmpty()) {
            for (java.util.Map<String, Object> row : rows) {
                int updated = stampEdgeRow(em, actionType, row, finalAttestation);
                log.debugf("ADOPT edge replay: stamped %d row(s) in %s (row=%s)",
                        updated, actionType, row);
            }
        }

        // Clear the sidecar row(s) for this CR and mark APPROVED — identical
        // tail to replayAdopt. No per-edge cache eviction: edge attestation is
        // not part of the node-quarantine isEnabled snapshot (the node ADOPTs
        // own that), and KC's edge-backed caches (scope/role mapping sets)
        // converge on their own TTL — matching the best-effort eviction policy
        // for the auxiliary entries in the node path.
        IgaUnsignedEntityService.clearByAdoptCr(em, cr.getId());

        IgaChangeRequestEntity managed = em.find(IgaChangeRequestEntity.class, cr.getId());
        if (managed != null) {
            managed.setStatus("APPROVED");
            managed.setResolvedAt(System.currentTimeMillis());
        }
    }

    /**
     * Stamp a single edge row's attestation by its composite keys. Returns the
     * number of rows updated (0 if the edge vanished out-of-band between ADOPT
     * create and commit — logged at WARN by the caller's debug line; we do NOT
     * throw, mirroring the node path's tolerance plus the IS NULL guard).
     */
    private static int stampEdgeRow(EntityManager em, String actionType,
                                    java.util.Map<String, Object> row, String sig) {
        switch (actionType) {
            case ACTION_ADOPT_COMPOSITE_ROLE: {
                String parentId = str(row, "COMPOSITE");
                String childId = str(row, "CHILD_ROLE");
                if (parentId == null || childId == null) return 0;
                return em.createQuery(
                        "UPDATE CompositeRoleEntity e SET e.attestation = :sig " +
                                "WHERE e.parentRole.id = :k1 AND e.childRole.id = :k2 " +
                                "AND e.attestation IS NULL")
                        .setParameter("sig", sig)
                        .setParameter("k1", parentId)
                        .setParameter("k2", childId)
                        .executeUpdate();
            }
            case ACTION_ADOPT_CLIENT_SCOPE_CLIENT: {
                String clientUuid = str(row, "CLIENT_UUID");
                String scopeId = str(row, "SCOPE_ID");
                if (clientUuid == null || scopeId == null) return 0;
                return em.createQuery(
                        "UPDATE ClientScopeClientMappingEntity e SET e.attestation = :sig " +
                                "WHERE e.clientId = :k1 AND e.clientScopeId = :k2 " +
                                "AND e.attestation IS NULL")
                        .setParameter("sig", sig)
                        .setParameter("k1", clientUuid)
                        .setParameter("k2", scopeId)
                        .executeUpdate();
            }
            case ACTION_ADOPT_CLIENT_SCOPE_ROLE: {
                String scopeId = str(row, "SCOPE_ID");
                String roleId = str(row, "ROLE_ID");
                if (scopeId == null || roleId == null) return 0;
                return em.createQuery(
                        "UPDATE ClientScopeRoleMappingEntity e SET e.attestation = :sig " +
                                "WHERE e.clientScope.id = :k1 AND e.role.id = :k2 " +
                                "AND e.attestation IS NULL")
                        .setParameter("sig", sig)
                        .setParameter("k1", scopeId)
                        .setParameter("k2", roleId)
                        .executeUpdate();
            }
            case ACTION_ADOPT_PROTOCOL_MAPPER: {
                String mapperId = str(row, "ID");
                if (mapperId == null) return 0;
                return em.createQuery(
                        "UPDATE ProtocolMapperEntity e SET e.attestation = :sig " +
                                "WHERE e.id = :id AND e.attestation IS NULL")
                        .setParameter("sig", sig)
                        .setParameter("id", mapperId)
                        .executeUpdate();
            }
            case ACTION_ADOPT_DEFAULT_CLIENT_SCOPE: {
                // DEFAULT_CLIENT_SCOPE row keyed (REALM_ID, SCOPE_ID). The entity
                // fields are DefaultClientScopeRealmMappingEntity.realm
                // (RealmEntity, column REALM_ID) and .clientScopeId (String,
                // column SCOPE_ID) — NOT a clientScope association.
                String realmId = str(row, "REALM_ID");
                String scopeId = str(row, "SCOPE_ID");
                if (realmId == null || scopeId == null) return 0;
                return em.createQuery(
                        "UPDATE DefaultClientScopeRealmMappingEntity e SET e.attestation = :sig " +
                                "WHERE e.realm.id = :k1 AND e.clientScopeId = :k2 " +
                                "AND e.attestation IS NULL")
                        .setParameter("sig", sig)
                        .setParameter("k1", realmId)
                        .setParameter("k2", scopeId)
                        .executeUpdate();
            }
            default:
                throw new IllegalStateException("ADOPT edge replay: no stamp JPQL for action " + actionType);
        }
    }

    private static final com.fasterxml.jackson.databind.ObjectMapper EDGE_MAPPER =
            new com.fasterxml.jackson.databind.ObjectMapper();
    private static final com.fasterxml.jackson.core.type.TypeReference<
            java.util.List<java.util.Map<String, Object>>> EDGE_LIST_MAP_REF =
            new com.fasterxml.jackson.core.type.TypeReference<>() {};

    private static java.util.List<java.util.Map<String, Object>> parseRows(String rowsJson) {
        try {
            return EDGE_MAPPER.readValue(rowsJson, EDGE_LIST_MAP_REF);
        } catch (Exception e) {
            throw new RuntimeException("ADOPT edge replay: failed to parse rowsJson", e);
        }
    }

    private static String str(java.util.Map<String, Object> row, String key) {
        Object v = row.get(key);
        return v != null ? v.toString() : null;
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
                case ACTION_ADOPT_ORGANIZATION: {
                    // Phase 7b — per-org cache eviction. KC's
                    // CacheRealmProvider has no public registerOrgInvalidation
                    // primitive (the InfinispanOrganizationProvider's
                    // registerOrganizationInvalidation is package-private), but
                    // InfinispanOrganizationProvider.getById keys the cached
                    // CachedOrganization on the org id alone
                    // ({@code realmCache.getCache().get(id, CachedOrganization.class)}
                    // — KC 26.5.5 InfinispanOrganizationProvider.java:94), and
                    // {@code registerOrganizationInvalidation} (line 371-372)
                    // invalidates that key via the public
                    // {@code CacheRealmProvider.registerInvalidation(id)}
                    // method. Calling that public method here drops the
                    // CachedOrganization for this org so the next getById
                    // re-loads through the IGA provider chain and observes
                    // the post-ADOPT sidecar absence — i.e. the (future
                    // Phase 7c) IgaOrganizationModel.isEnabled quarantine
                    // override sees the just-cleared sidecar on the very next
                    // request.
                    //
                    // We deliberately do NOT iterate the org's domains or
                    // member-related cache keys here: those are populated by
                    // CREATE/UPDATE replay paths and not by ADOPT (which does
                    // not mutate the org). Dropping the primary id-keyed
                    // entry is sufficient for the per-org isEnabled signal,
                    // and the auxiliary domain/member entries converge on
                    // their own as their TTLs expire — matching the
                    // best-effort policy of every other ADOPT eviction
                    // branch in this file.
                    CacheRealmProvider realmCache = session.getProvider(CacheRealmProvider.class);
                    if (realmCache == null) {
                        log.warnf("IGA ADOPT cache eviction: type=ORGANIZATION id=%s realm=%s — CacheRealmProvider not installed (skipped)",
                                entityId, realm.getId());
                        return;
                    }
                    realmCache.registerInvalidation(entityId);
                    log.infof("IGA ADOPT cache eviction: type=ORGANIZATION id=%s realm=%s — evicted",
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
            case ACTION_ADOPT_ORGANIZATION: {
                // Phase 7b — resolve through KC's OrganizationProvider SPI so
                // federation / cache layers are honoured (same idiom as the
                // other ADOPT existence probes). If the OrganizationProvider
                // factory isn't installed (deployment without the orgs
                // feature) getProvider returns null — treat as vanished so
                // the commit endpoint surfaces 404 ENTITY_VANISHED.
                OrganizationProvider orgs = session.getProvider(OrganizationProvider.class);
                if (orgs == null) {
                    log.warnf("ADOPT_ORGANIZATION replay: OrganizationProvider not installed (id=%s realm=%s) — treating as vanished",
                            entityId, realm.getId());
                    exists = false;
                } else {
                    OrganizationModel o = orgs.getById(entityId);
                    exists = o != null;
                }
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
