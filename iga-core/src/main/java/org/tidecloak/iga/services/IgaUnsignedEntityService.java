package org.tidecloak.iga.services;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceException;
import org.jboss.logging.Logger;
import org.tidecloak.iga.entities.IgaUnsignedEntityEntity;

/**
 * Sidecar-table operations for the Phase 6a capture-then-veto ADOPT workflow.
 *
 * <p>{@link IgaUnsignedEntityEntity} is the per-entity register of rows that
 * exist in the underlying entity table (USER_ENTITY, KEYCLOAK_ROLE,
 * KEYCLOAK_GROUP, CLIENT, CLIENT_SCOPE) but whose ATTESTATION column is still
 * NULL. The hot read path ({@link #isUnsigned}) is a single-PK probe — every
 * downstream "quarantine" enforcement (Phase 6c) sits behind it.</p>
 *
 * <p>Stateless: every operation takes its {@link EntityManager} as a parameter
 * to match the existing static-utility style of the {@code IgaReplayDispatcher}
 * write paths (the dispatcher already resolves the EM from the session). The
 * caller is responsible for transaction boundaries.</p>
 */
public final class IgaUnsignedEntityService {

    private static final Logger log = Logger.getLogger(IgaUnsignedEntityService.class);

    private IgaUnsignedEntityService() {
    }

    /**
     * Insert a sidecar row for {@code (realmId, entityType, entityId)} pointing
     * at the per-entity ADOPT change request {@code adoptCrId}. Idempotent: if
     * a row for the same PK already exists the call is a no-op (existing row
     * is left untouched — including its {@code adoptCrId} pointer, which the
     * caller can subsequently rewire via a {@code merge}).
     *
     * <p>Implementation note: we probe with {@code em.find} first and INSERT
     * only when absent. This is preferable to "INSERT then catch
     * PersistenceException" because Hibernate's autoflush would leave the
     * transaction in a poisoned state on the duplicate-key violation, breaking
     * subsequent writes in the same unit of work.</p>
     */
    public static void markUnsigned(EntityManager em, String realmId, String entityType,
                                     String entityId, String adoptCrId) {
        if (em == null || realmId == null || entityType == null || entityId == null) {
            throw new IllegalArgumentException(
                    "markUnsigned requires non-null em + (realmId, entityType, entityId)");
        }
        IgaUnsignedEntityEntity.Pk pk = new IgaUnsignedEntityEntity.Pk(realmId, entityType, entityId);
        IgaUnsignedEntityEntity existing = em.find(IgaUnsignedEntityEntity.class, pk);
        if (existing != null) {
            log.debugf("markUnsigned: sidecar row already exists for (%s, %s, %s) — no-op",
                    realmId, entityType, entityId);
            return;
        }
        IgaUnsignedEntityEntity row = new IgaUnsignedEntityEntity();
        row.setRealmId(realmId);
        row.setEntityType(entityType);
        row.setEntityId(entityId);
        row.setAdoptCrId(adoptCrId);
        row.setCreatedAt(System.currentTimeMillis());
        try {
            em.persist(row);
        } catch (PersistenceException pe) {
            // A race window between find and persist can still produce a
            // unique-key violation under concurrent toggle-on scans; treat as
            // idempotent.
            log.debugf(pe, "markUnsigned: persist raced for (%s, %s, %s) — treating as no-op",
                    realmId, entityType, entityId);
        }
    }

    /**
     * Single-PK probe — the hot path used by the Phase 6c quarantine guards.
     * Returns {@code true} when an unattested sidecar row exists for the given
     * triple.
     */
    public static boolean isUnsigned(EntityManager em, String realmId, String entityType, String entityId) {
        if (em == null || realmId == null || entityType == null || entityId == null) {
            return false;
        }
        IgaUnsignedEntityEntity.Pk pk = new IgaUnsignedEntityEntity.Pk(realmId, entityType, entityId);
        return em.find(IgaUnsignedEntityEntity.class, pk) != null;
    }

    /**
     * Delete every sidecar row whose {@code adoptCrId} matches the supplied
     * value. The index {@code IDX_IGA_UNSIGNED_BY_CR} backs this lookup. Used
     * by the ADOPT replay path (Phase 6a) and by the toggle-off cancel (Phase
     * 6d) when the per-entity CR is itself being deleted.
     */
    public static void clearByAdoptCr(EntityManager em, String adoptCrId) {
        if (em == null || adoptCrId == null) return;
        int deleted = em.createQuery(
                        "DELETE FROM IgaUnsignedEntityEntity u WHERE u.adoptCrId = :crId")
                .setParameter("crId", adoptCrId)
                .executeUpdate();
        if (deleted > 0) {
            log.debugf("clearByAdoptCr: deleted %d sidecar rows for CR %s", deleted, adoptCrId);
        }
    }

    /**
     * Bulk-delete every sidecar row for a realm — used by the Phase 6d
     * toggle-off path to atomically clear the unattested register when IGA is
     * disabled.
     */
    public static void clearByRealm(EntityManager em, String realmId) {
        if (em == null || realmId == null) return;
        int deleted = em.createQuery(
                        "DELETE FROM IgaUnsignedEntityEntity u WHERE u.realmId = :realmId")
                .setParameter("realmId", realmId)
                .executeUpdate();
        if (deleted > 0) {
            log.debugf("clearByRealm: deleted %d sidecar rows for realm %s", deleted, realmId);
        }
    }

    /**
     * Count the unattested entities for a realm. Used by the Phase 6d cap
     * check (toggle-on must refuse if the realm already exceeds the configured
     * sidecar ceiling).
     */
    public static long countByRealm(EntityManager em, String realmId) {
        if (em == null || realmId == null) return 0L;
        Long n = em.createQuery(
                        "SELECT COUNT(u) FROM IgaUnsignedEntityEntity u WHERE u.realmId = :realmId",
                        Long.class)
                .setParameter("realmId", realmId)
                .getSingleResult();
        return n == null ? 0L : n;
    }
}
