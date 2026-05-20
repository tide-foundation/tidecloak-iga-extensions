package org.tidecloak.iga.services;

import org.keycloak.models.RealmModel;
import org.tidecloak.iga.replay.IgaReplayExtension;

import java.util.Set;

/**
 * Phase 6b — system-entity skip rules for the toggle-on ADOPT scan.
 *
 * <p>The toggle-on scan ({@link IgaAdoptScan}) walks every unattested row in
 * the realm and (by default) emits a per-entity ADOPT_X change request. Two
 * categories of entities must NOT be quarantined under default settings,
 * because doing so locks the realm out of its own bootstrap:</p>
 * <ol>
 *   <li><b>Hard-pinned skips</b> — entities the scan MUST NEVER quarantine
 *       even with {@code iga.adopt.includeSystem=true}: the realm composite
 *       role {@code default-roles-&lt;realm&gt;} and the bookkeeping client
 *       {@code default-roles-&lt;realm&gt;} that backs it. Any user created in
 *       the realm receives the composite automatically — pending-quarantining
 *       it would freeze every subsequent login/create.</li>
 *   <li><b>Soft skips</b> (default on, can be opted out of with
 *       {@code iga.adopt.includeSystem=true}) — KC's built-in per-realm admin
 *       clients ({@code realm-management}, {@code account},
 *       {@code account-console}, {@code security-admin-console},
 *       {@code broker}, {@code admin-cli}) AND their client-roles. These can
 *       be brought under governance by an operator that explicitly wants to,
 *       but the default avoids quarantining the very surface used to commit
 *       change requests.</li>
 * </ol>
 *
 * <p>The {@code master} realm is filtered earlier — at the toggle handler —
 * because Tide's master-realm escape hatch must remain unconditionally usable
 * for recovery. This class does NOT need to re-filter master: the toggle
 * handler refuses to enable IGA on master at all.</p>
 *
 * <p>Stateless utility. Lookups are cheap (string compare against a small
 * constant set); the scan invokes one call per row.</p>
 */
public final class IgaSystemEntityFilter {

    /**
     * KC's per-realm built-in clients. Mirrors
     * {@code RepresentationToModel#getBuiltinClients} / the master-realm setup
     * in stock KC 26.5.x — these clients are auto-created at realm creation
     * and back the admin/account/CLI surfaces.
     */
    public static final Set<String> BUILTIN_CLIENT_IDS = Set.of(
            "realm-management",
            "account",
            "account-console",
            "security-admin-console",
            "broker",
            "admin-cli"
    );

    private IgaSystemEntityFilter() {
    }

    /**
     * @param realm        the realm being scanned (its name supplies the
     *                     {@code default-roles-&lt;realm&gt;} hard-pin string).
     * @param entityType   USER | ROLE | GROUP | CLIENT | CLIENT_SCOPE (the
     *                     five Phase 6b scan targets).
     * @param entityId     the entity's own UUID (unused today but kept on the
     *                     surface so future rules can pivot on it without
     *                     re-threading callers).
     * @param entityName   the entity's human-readable name (USERNAME for
     *                     USER, ROLE name, GROUP name, CLIENT_SCOPE name); for
     *                     CLIENT this is the {@code clientId} string. May be
     *                     {@code null} when the scanner cannot resolve it.
     * @param parentClientId for client-roles, the {@code clientId} string of
     *                     the role's owning client (used to soft-skip every
     *                     role under a built-in client when {@code
     *                     includeSystem=false}). {@code null} for realm roles
     *                     and non-ROLE entity types.
     * @param includeSystem if {@code true}, soft-skip rules are LIFTED.
     *                     Hard-pinned skips remain.
     * @return {@code true} when this entity must be skipped by the scan.
     */
    public static boolean shouldSkip(RealmModel realm,
                                      String entityType,
                                      String entityId,
                                      String entityName,
                                      String parentClientId,
                                      boolean includeSystem) {
        if (realm == null || entityType == null) {
            return false;
        }
        String defaultRolesName = "default-roles-" + realm.getName();

        // -------------------------------------------------------------------
        // HARD-PINNED skips — regardless of includeSystem.
        // -------------------------------------------------------------------
        if (IgaReplayExtension.ENTITY_TYPE_ROLE.equals(entityType)) {
            // The realm composite role default-roles-<realm>. KC binds every
            // new user to this composite at create-time, so quarantining it
            // would brick the realm. Pin even when the operator asks to
            // include system entities.
            if (defaultRolesName.equals(entityName)) {
                return true;
            }
        }
        if (IgaReplayExtension.ENTITY_TYPE_CLIENT.equals(entityType)) {
            // The bookkeeping client default-roles-<realm> exists alongside
            // the role and is similarly pinned.
            if (defaultRolesName.equals(entityName)) {
                return true;
            }
        }

        // -------------------------------------------------------------------
        // SOFT skips — lifted when includeSystem=true.
        // -------------------------------------------------------------------
        if (includeSystem) {
            return false;
        }
        if (IgaReplayExtension.ENTITY_TYPE_CLIENT.equals(entityType)) {
            return entityName != null && BUILTIN_CLIENT_IDS.contains(entityName);
        }
        if (IgaReplayExtension.ENTITY_TYPE_ROLE.equals(entityType)) {
            // Client-roles whose parent client is built-in: skip them as a
            // unit with their parent. Realm roles (parentClientId == null)
            // are NOT soft-skipped here.
            return parentClientId != null && BUILTIN_CLIENT_IDS.contains(parentClientId);
        }
        return false;
    }
}
