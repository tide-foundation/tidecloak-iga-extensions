package org.tidecloak.iga.services;

import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Phase 6d — one-shot toggle-OFF cancel + sidecar clear.
 *
 * <p>When IGA flips ON→OFF for a realm, this routine performs two bulk JPQL
 * updates inside the surrounding {@code runJobInTransaction}:</p>
 * <ol>
 *   <li><b>Cancel pending ADOPTs</b> — every {@code IgaChangeRequestEntity}
 *       with {@code status='PENDING'} and {@code actionType LIKE 'ADOPT_%'} is
 *       flipped to {@code status='CANCELLED'} with {@code resolvedAt=now}. The
 *       {@code IDX_IGA_CR_REALM_ACTION_STATUS} index added in Phase 6a backs
 *       this lookup. Other PENDING CR types (CREATE_*, UPDATE_*, DELETE_*,
 *       etc.) are left untouched — only the toggle-on-emitted ADOPTs are
 *       reaped here.</li>
 *   <li><b>Clear sidecar</b> — every {@code IgaUnsignedEntityEntity} row for
 *       this realm is bulk-deleted via {@link
 *       IgaUnsignedEntityService#clearByRealm}. Sidecar rows always pair with
 *       a PENDING ADOPT CR (Phase 6a invariant), so cancelling the CRs
 *       without clearing their sidecars would leave dangling rows; conversely
 *       clearing the sidecar without cancelling the CRs would leave PENDING
 *       ADOPTs with no enforcement point. Both must happen — atomically — in
 *       the same transaction.</li>
 * </ol>
 *
 * <p><b>Committed ADOPTs are NOT touched</b>: any CR already in {@code
 * APPROVED} status remains as audit + becomes the idempotent-re-toggle skip
 * set on the next OFF→ON. {@code DENIED} CRs are likewise untouched. The
 * {@code CANCELLED} status is a new terminal status — non-PENDING, so the
 * existing {@code authorize}/{@code commit} 409 guards naturally reject it,
 * and the existing PENDING-only named queries naturally exclude it.</p>
 *
 * <p>The caller (see {@code TideAdminCompatResource#toggleIga}) wraps this in
 * its own {@code KeycloakModelUtils.runJobInTransaction} so a cancel failure
 * cannot abort the toggle attribute write that just succeeded — mirror of the
 * Phase 6b OFF→ON pattern.</p>
 */
public final class IgaAdoptCancel {

    private static final Logger log = Logger.getLogger(IgaAdoptCancel.class);

    /**
     * Result of one toggle-off cancel. All counters are non-negative and the
     * counts are independent (sidecar rows and ADOPT CRs are distinct tables,
     * even if 1:1-paired by Phase 6a's invariant).
     */
    public static final class CancelResult {
        public final String realmId;
        public final long durationMs;
        public final long cancelledAdoptCrs;
        public final long sidecarRowsCleared;

        CancelResult(String realmId, long durationMs, long cancelledAdoptCrs, long sidecarRowsCleared) {
            this.realmId = realmId;
            this.durationMs = durationMs;
            this.cancelledAdoptCrs = cancelledAdoptCrs;
            this.sidecarRowsCleared = sidecarRowsCleared;
        }

        /** Map shape for the toggle response body — matches the locked contract. */
        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("realmId", realmId);
            m.put("cancelledAdoptCrs", cancelledAdoptCrs);
            m.put("sidecarRowsCleared", sidecarRowsCleared);
            m.put("durationMs", durationMs);
            return m;
        }
    }

    private IgaAdoptCancel() {
    }

    /**
     * Run the one-shot cancel + sidecar-clear for a single realm.
     *
     * @param session a fresh {@link KeycloakSession} bound to its own
     *                transaction (caller must wrap in {@code
     *                KeycloakModelUtils.runJobInTransaction}).
     * @param realm   the realm to cancel — must be loaded through {@code
     *                session.realms()} on the SAME session.
     * @return the {@link CancelResult} counters; never {@code null}.
     */
    public static CancelResult cancel(KeycloakSession session, RealmModel realm) {
        if (session == null || realm == null) {
            throw new IllegalArgumentException("cancel requires non-null session + realm");
        }
        long t0 = System.currentTimeMillis();
        // Bind the realm onto the session's context for symmetry with the
        // toggle-on scan path (org cache lookups, audit logging hooks, etc.
        // expect a realm-bound session). Cheap and safer than reasoning about
        // which downstream call might assume it.
        session.getContext().setRealm(realm);
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        long now = System.currentTimeMillis();

        // 1. Cancel PENDING ADOPT_* CRs. Single bulk UPDATE backed by
        //    IDX_IGA_CR_REALM_ACTION_STATUS (realmId, actionType, status).
        //    actionType LIKE 'ADOPT_%' covers every per-entity ADOPT variant
        //    (USER/ROLE/GROUP/CLIENT/CLIENT_SCOPE) in one statement.
        int cancelled = em.createQuery(
                        "UPDATE IgaChangeRequestEntity cr " +
                                "SET cr.status = 'CANCELLED', cr.resolvedAt = :now " +
                                "WHERE cr.realmId = :rid " +
                                "AND cr.actionType LIKE 'ADOPT_%' " +
                                "AND cr.status = 'PENDING'")
                .setParameter("now", now)
                .setParameter("rid", realm.getId())
                .executeUpdate();

        // 2. Clear sidecar — single bulk DELETE on REALM_ID. The
        //    IgaUnsignedEntityService helper performs the JPQL DELETE and
        //    logs at DEBUG; we need the count, so we run the JPQL inline
        //    rather than calling clearByRealm() (which is void). Functionally
        //    identical query.
        int sidecarCleared = em.createQuery(
                        "DELETE FROM IgaUnsignedEntityEntity u WHERE u.realmId = :rid")
                .setParameter("rid", realm.getId())
                .executeUpdate();

        long durationMs = System.currentTimeMillis() - t0;
        log.infof("IGA toggle-off cancel: realm=%s durationMs=%d cancelledAdoptCrs=%d sidecarRowsCleared=%d",
                realm.getName(), durationMs, cancelled, sidecarCleared);
        return new CancelResult(realm.getId(), durationMs, cancelled, sidecarCleared);
    }
}
