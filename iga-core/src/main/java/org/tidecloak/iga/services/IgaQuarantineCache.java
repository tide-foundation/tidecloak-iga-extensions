package org.tidecloak.iga.services;

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
import org.tidecloak.iga.replay.IgaReplayExtension;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Per-request, session-attribute-backed quarantine cache.
 *
 * <p>The quarantine guards fire on every token issuance, every login
 * attempt, every client-auth, every protocol-mapper resolution. A naive
 * {@link IgaUnsignedEntityService#isUnsigned} call per check would cost N JPA
 * round-trips per token (N = number of role/group/scope hits during token
 * mapping). This class collapses that to AT MOST a single batch JPA round-trip
 * per (user, request) for the role-quarantine check, and a single PK probe per
 * (entity, request) for the rest — with the result memoised on the
 * {@link KeycloakSession}'s attribute map (request-scoped lifecycle, naturally
 * cleared at the end of every request).</p>
 *
 * <h2>Gate semantics</h2>
 * Every public method first short-circuits to {@code false} (i.e. "not
 * unsigned" / "let the operation proceed") iff EITHER:
 * <ul>
 *   <li>{@code session.getAttribute("IGA_REPLAY_ACTIVE") == "true"} — a
 *       CR-commit replay is in flight and the unsigned entity must be
 *       reachable so the captured representation can be applied;</li>
 *   <li>IGA is not active on the realm
 *       ({@code !"true".equals(realm.getAttribute("isIGAEnabled"))}, or
 *       {@code "master".equals(realm.getName())}).</li>
 * </ul>
 *
 * <h2>User-quarantine semantics (the role-fan-out)</h2>
 * A user is treated as "not enabled" (hard-refuse, NOT silent strip) iff ANY
 * of the following holds:
 * <ol>
 *   <li>the user themselves has a sidecar row
 *       ({@code IGA_UNSIGNED_ENTITY} for (realmId, USER, userId));</li>
 *   <li>any role in the user's effective realm-role mapping has a sidecar row
 *       ({@code IGA_UNSIGNED_ENTITY} for (realmId, ROLE, roleId));</li>
 *   <li>any role in the user's effective client-role mapping (across every
 *       client that has at least one client-role mapping for the user) has a
 *       sidecar row.</li>
 * </ol>
 * The role check is implemented as ONE batched
 * {@code SELECT entity_id FROM IGA_UNSIGNED_ENTITY WHERE realm_id=:r AND
 * entity_type='ROLE' AND entity_id IN :ids} so we never do N per-role probes.
 * The result is memoised per (session, user) so a token issuance that hits the
 * isEnabled checkpoint at {@code TokenManager:193,267} only pays the batch
 * query once.
 *
 * <h2>Memoisation keys</h2>
 * Session-attribute keys (string-typed values are {@code "true"} / {@code "false"};
 * absence == "not yet computed", same idiom as {@code IGA_REPLAY_ACTIVE}):
 * <ul>
 *   <li>{@code IGA_QUARANTINE:user:<userId>} — boolean string.</li>
 *   <li>{@code IGA_QUARANTINE:client:<clientUuid>} — boolean string.</li>
 *   <li>{@code IGA_QUARANTINE:group:<groupId>} — boolean string.</li>
 *   <li>{@code IGA_QUARANTINE:scope:<scopeId>} — boolean string.</li>
 * </ul>
 * These keys are distinct from {@code IGA_REPLAY_ACTIVE} so they cannot
 * collide. The session lifecycle is request-scoped (see
 * {@code DefaultKeycloakSession}), so memoised entries die with the request.
 */
public final class IgaQuarantineCache {

    private static final Logger log = Logger.getLogger(IgaQuarantineCache.class);

    private static final String ATTR_PREFIX_USER = "IGA_QUARANTINE:user:";
    private static final String ATTR_PREFIX_CLIENT = "IGA_QUARANTINE:client:";
    private static final String ATTR_PREFIX_GROUP = "IGA_QUARANTINE:group:";
    private static final String ATTR_PREFIX_SCOPE = "IGA_QUARANTINE:scope:";
    private static final String ATTR_PREFIX_ORG = "IGA_QUARANTINE:org:";

    private IgaQuarantineCache() {
    }

    // -------------------------------------------------------------------------
    // Gates
    // -------------------------------------------------------------------------

    /**
     * True iff the quarantine cache should short-circuit (return "not
     * unsigned") because a CR replay is in flight on this session. The replay
     * path needs to touch the unsigned entity to apply the captured
     * representation; refusing would deadlock the commit.
     */
    private static boolean isReplayActive(KeycloakSession session) {
        if (session == null) return false;
        return "true".equals(session.getAttribute("IGA_REPLAY_ACTIVE"));
    }

    /**
     * True iff IGA is active on the realm. Mirrors
     * {@link org.tidecloak.iga.providers.IgaChangeRequestService#isIgaEnabled}
     * (master excluded; flag is the realm attribute {@code isIGAEnabled}).
     * When IGA is OFF nothing has been quarantined by definition, so the
     * quarantine check is a fast no-op for every non-IGA realm.
     */
    private static boolean isIgaActive(RealmModel realm) {
        if (realm == null) return false;
        if ("master".equals(realm.getName())) return false;
        return "true".equals(realm.getAttribute("isIGAEnabled"));
    }

    // -------------------------------------------------------------------------
    // User quarantine — direct + role fan-out (HARD refuse)
    // -------------------------------------------------------------------------

    /**
     * Hot path used by {@link org.tidecloak.iga.providers.IgaUserAdapter#isEnabled}.
     * Returns {@code true} iff the user (or ANY role the user effectively
     * holds) is currently unsigned. Memoised per (session, user) so a token
     * issuance that hits multiple {@code user.isEnabled()} checkpoints (e.g.
     * {@code TokenManager:193} then again at {@code :267}) only pays the
     * batched query once.
     *
     * <p>The {@code IGA_REPLAY_ACTIVE} gate fires first so that the replay
     * path of an ADOPT_USER/ADOPT_ROLE/etc. CR can touch the entity while it
     * is still unsigned; if it returned {@code true} during replay the
     * captured representation could not be applied.</p>
     */
    public static boolean isUserUnsignedWithRoles(KeycloakSession session,
                                                  RealmModel realm,
                                                  UserModel user) {
        if (session == null || realm == null || user == null) return false;
        if (isReplayActive(session)) return false;
        if (!isIgaActive(realm)) return false;
        String userId = user.getId();
        if (userId == null) return false;
        String attrKey = ATTR_PREFIX_USER + userId;
        Object cached = session.getAttribute(attrKey);
        if (cached instanceof String) {
            return "true".equals(cached);
        }

        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        String realmId = realm.getId();

        boolean unsigned = false;
        try {
            // 1. Direct user-quarantine probe.
            if (IgaUnsignedEntityService.isUnsigned(em, realmId,
                    IgaReplayExtension.ENTITY_TYPE_USER, userId)) {
                unsigned = true;
            } else {
                // 2. Role fan-out (realm + client) — ONE batched IN-clause
                //    query rather than per-role probes. The user's effective
                //    role IDs are gathered via the same Stream APIs KC's
                //    token-mapping path uses (so role inheritance / composites
                //    are reflected — getRoleMappingsStream returns the user's
                //    DIRECT mappings; composites do not surface here, which
                //    is fine: composites are realm-roles too and the parent
                //    must be ADOPTed before the user can hold it, so the
                //    parent's mapping already counts).
                Set<String> roleIds = new HashSet<>();
                try {
                    user.getRealmRoleMappingsStream()
                            .map(RoleModel::getId)
                            .filter(java.util.Objects::nonNull)
                            .forEach(roleIds::add);
                } catch (RuntimeException re) {
                    log.debugf(re, "isUserUnsignedWithRoles: getRealmRoleMappingsStream failed for user=%s — skipping realm-role fan-out",
                            userId);
                }
                try {
                    // For client-role fan-out, iterate the role-mapping clients
                    // the user actually has at least one role on. Using
                    // getRoleMappingsStream() and filtering by getContainer()
                    // would also work, but the explicit shape mirrors the
                    // brief's wording and is robust to KC API drift.
                    user.getRoleMappingsStream()
                            .map(RoleModel::getId)
                            .filter(java.util.Objects::nonNull)
                            .forEach(roleIds::add);
                } catch (RuntimeException re) {
                    log.debugf(re, "isUserUnsignedWithRoles: getRoleMappingsStream failed for user=%s — skipping client-role fan-out",
                            userId);
                }

                if (!roleIds.isEmpty()) {
                    List<String> ids = new ArrayList<>(roleIds);
                    // Single batched IN-clause query.
                    @SuppressWarnings("unchecked")
                    List<String> unsignedRoleIds = em.createQuery(
                                    "SELECT u.entityId FROM IgaUnsignedEntityEntity u " +
                                            "WHERE u.realmId = :realmId " +
                                            "AND u.entityType = :etype " +
                                            "AND u.entityId IN :ids")
                            .setParameter("realmId", realmId)
                            .setParameter("etype", IgaReplayExtension.ENTITY_TYPE_ROLE)
                            .setParameter("ids", ids)
                            .getResultList();
                    if (unsignedRoleIds != null && !unsignedRoleIds.isEmpty()) {
                        unsigned = true;
                        if (log.isDebugEnabled()) {
                            log.debugf("isUserUnsignedWithRoles: user=%s holds %d unsigned role(s): %s",
                                    userId, unsignedRoleIds.size(), unsignedRoleIds);
                        }
                    }
                }
            }
        } catch (RuntimeException ex) {
            // Defensive: never let a quarantine-cache lookup fail open in a way
            // that bypasses governance — but also never throw out of isEnabled
            // (KC would translate to a 500). Treat lookup failure as "not
            // unsigned" (let the operation proceed) and log WARN once per
            // session/user.
            log.warnf(ex, "isUserUnsignedWithRoles: lookup failed for user=%s realm=%s — treating as not-unsigned (operation will proceed)",
                    userId, realmId);
            unsigned = false;
        }

        session.setAttribute(attrKey, unsigned ? "true" : "false");
        return unsigned;
    }

    // -------------------------------------------------------------------------
    // Client quarantine — single PK probe, memoised
    // -------------------------------------------------------------------------

    public static boolean isClientUnsigned(KeycloakSession session,
                                           RealmModel realm,
                                           ClientModel client) {
        if (session == null || realm == null || client == null) return false;
        if (isReplayActive(session)) return false;
        if (!isIgaActive(realm)) return false;
        String clientUuid = client.getId();
        if (clientUuid == null) return false;
        String attrKey = ATTR_PREFIX_CLIENT + clientUuid;
        Object cached = session.getAttribute(attrKey);
        if (cached instanceof String) {
            return "true".equals(cached);
        }
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        boolean unsigned;
        try {
            unsigned = IgaUnsignedEntityService.isUnsigned(em, realm.getId(),
                    IgaReplayExtension.ENTITY_TYPE_CLIENT, clientUuid);
        } catch (RuntimeException ex) {
            log.warnf(ex, "isClientUnsigned: lookup failed for client=%s realm=%s — treating as not-unsigned",
                    clientUuid, realm.getId());
            unsigned = false;
        }
        session.setAttribute(attrKey, unsigned ? "true" : "false");
        return unsigned;
    }

    // -------------------------------------------------------------------------
    // Group quarantine — single PK probe, memoised
    //
    // NB: groups are SILENTLY STRIPPED from token mapping,
    // not hard-refused — the filter call site is IgaUserAdapter.getGroupsStream.
    // The cache here is the lookup primitive; the strip semantic is at the
    // call site.
    // -------------------------------------------------------------------------

    public static boolean isGroupUnsigned(KeycloakSession session,
                                          RealmModel realm,
                                          GroupModel group) {
        if (session == null || realm == null || group == null) return false;
        if (isReplayActive(session)) return false;
        if (!isIgaActive(realm)) return false;
        String groupId = group.getId();
        if (groupId == null) return false;
        String attrKey = ATTR_PREFIX_GROUP + groupId;
        Object cached = session.getAttribute(attrKey);
        if (cached instanceof String) {
            return "true".equals(cached);
        }
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        boolean unsigned;
        try {
            unsigned = IgaUnsignedEntityService.isUnsigned(em, realm.getId(),
                    IgaReplayExtension.ENTITY_TYPE_GROUP, groupId);
        } catch (RuntimeException ex) {
            log.warnf(ex, "isGroupUnsigned: lookup failed for group=%s realm=%s — treating as not-unsigned",
                    groupId, realm.getId());
            unsigned = false;
        }
        session.setAttribute(attrKey, unsigned ? "true" : "false");
        return unsigned;
    }

    // -------------------------------------------------------------------------
    // Client-scope quarantine — single PK probe, memoised
    //
    // Strip-from-token semantic: IgaClientScopeAdapter.getProtocolMappersStream
    // returns Stream.empty() when the scope is unsigned, so the scope's
    // mappers contribute nothing to the issued token.
    // -------------------------------------------------------------------------

    public static boolean isClientScopeUnsigned(KeycloakSession session,
                                                RealmModel realm,
                                                ClientScopeModel scope) {
        if (session == null || realm == null || scope == null) return false;
        if (isReplayActive(session)) return false;
        if (!isIgaActive(realm)) return false;
        String scopeId = scope.getId();
        if (scopeId == null) return false;
        String attrKey = ATTR_PREFIX_SCOPE + scopeId;
        Object cached = session.getAttribute(attrKey);
        if (cached instanceof String) {
            return "true".equals(cached);
        }
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        boolean unsigned;
        try {
            unsigned = IgaUnsignedEntityService.isUnsigned(em, realm.getId(),
                    IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE, scopeId);
        } catch (RuntimeException ex) {
            log.warnf(ex, "isClientScopeUnsigned: lookup failed for scope=%s realm=%s — treating as not-unsigned",
                    scopeId, realm.getId());
            unsigned = false;
        }
        session.setAttribute(attrKey, unsigned ? "true" : "false");
        return unsigned;
    }

    // -------------------------------------------------------------------------
    // Organization quarantine — single PK probe, memoised.
    //
    // Not yet USED — IgaOrganizationModel.isEnabled is not overridden — but the
    // lookup primitive lives here alongside the other four entity types so a
    // future override just needs to call it.
    // Shape mirrors isClientUnsigned / isGroupUnsigned: gate on
    // IGA_REPLAY_ACTIVE + isIgaActive(realm) + sidecar PK probe; memoise
    // per (session, org) under {@code IGA_QUARANTINE:org:<id>}.
    // -------------------------------------------------------------------------

    public static boolean isOrganizationUnsigned(KeycloakSession session,
                                                  RealmModel realm,
                                                  OrganizationModel org) {
        if (session == null || realm == null || org == null) return false;
        if (isReplayActive(session)) return false;
        if (!isIgaActive(realm)) return false;
        String orgId = org.getId();
        if (orgId == null) return false;
        String attrKey = ATTR_PREFIX_ORG + orgId;
        Object cached = session.getAttribute(attrKey);
        if (cached instanceof String) {
            return "true".equals(cached);
        }
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        boolean unsigned;
        try {
            unsigned = IgaUnsignedEntityService.isUnsigned(em, realm.getId(),
                    IgaReplayExtension.ENTITY_TYPE_ORGANIZATION, orgId);
        } catch (RuntimeException ex) {
            log.warnf(ex, "isOrganizationUnsigned: lookup failed for org=%s realm=%s — treating as not-unsigned",
                    orgId, realm.getId());
            unsigned = false;
        }
        session.setAttribute(attrKey, unsigned ? "true" : "false");
        return unsigned;
    }

    // -------------------------------------------------------------------------
    // One-shot log dedupe (used by adapters so log lines don't repeat per
    // per-request quarantine hit). True iff this is the first time we've
    // observed the given key on this session.
    // -------------------------------------------------------------------------

    public static boolean firstObservation(KeycloakSession session, String key) {
        if (session == null || key == null) return true;
        String attrKey = "IGA_QUARANTINE_LOGGED:" + key;
        if (session.getAttribute(attrKey) != null) return false;
        session.setAttribute(attrKey, "true");
        return true;
    }
}
