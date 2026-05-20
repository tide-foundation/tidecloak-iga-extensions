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
 *       {@link IllegalStateException} so the commit endpoint surfaces a real
 *       error rather than a misleading 204/200 on a vanished entity.</li>
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

        // 5. Mark APPROVED + resolvedAt on the managed CR — same tail as
        // IgaReplayDispatcher.doReplay.
        IgaChangeRequestEntity managed = em.find(IgaChangeRequestEntity.class, cr.getId());
        if (managed != null) {
            managed.setStatus("APPROVED");
            managed.setResolvedAt(System.currentTimeMillis());
        }
    }

    /**
     * Resolve the entity through KC's model APIs. Throws
     * {@link IllegalStateException} when missing — the commit endpoint's
     * standard error path turns this into a 5xx with a meaningful message, far
     * preferable to a silent no-op that leaves a stale APPROVED CR pointing at
     * a vanished entity.
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
            throw new IllegalStateException(
                    "ADOPT replay: entity " + entityType + "/" + entityId
                            + " no longer exists in realm " + realm.getId());
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
