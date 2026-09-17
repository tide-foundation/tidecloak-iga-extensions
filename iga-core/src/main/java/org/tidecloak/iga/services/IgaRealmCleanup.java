package org.tidecloak.iga.services;

import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;

/**
 * Removes a deleted realm's IGA rows. No IGA table has a foreign key to REALM, so
 * without this every realm delete leaves its change requests, policies, authorizers
 * and jobs behind, and a realm re-created with the same id would inherit them.
 */
public final class IgaRealmCleanup {

    private static final Logger log = Logger.getLogger(IgaRealmCleanup.class);

    private static final String OTHER_CRS_OF_REALM =
            "(SELECT cr.id FROM IgaChangeRequestEntity cr WHERE cr.realmId = :realmId AND cr.id <> :keep)";

    private IgaRealmCleanup() {
    }

    /**
     * Delete every IGA row of {@code realmId}, children before parents. Runs in the
     * caller's transaction, so it rolls back together with the realm delete.
     *
     * @param excludeCrId a change request to keep (with its approvals and comments),
     *                    or null. The DELETE_REALM commit passes its own CR because
     *                    the commit tail still resolves it after the replay.
     * @return how many rows were deleted
     */
    public static int purge(EntityManager em, String realmId, String excludeCrId) {
        if (em == null || realmId == null) return 0;
        // CR ids are never empty, so "" excludes nothing.
        String keep = excludeCrId == null ? "" : excludeCrId;
        int n = 0;

        // Rows hanging off a change request go first (FKs to IGA_CHANGE_REQUEST).
        n += em.createQuery("DELETE FROM IgaAuthorizationEntity a WHERE a.changeRequest.id IN "
                        + OTHER_CRS_OF_REALM)
                .setParameter("realmId", realmId).setParameter("keep", keep).executeUpdate();
        n += em.createQuery("DELETE FROM IgaCommentEntity c WHERE c.changeRequest.id IN "
                        + OTHER_CRS_OF_REALM)
                .setParameter("realmId", realmId).setParameter("keep", keep).executeUpdate();
        n += byRealm(em, "IgaServerCertDraft.deleteByRealm", realmId);
        n += byRealm(em, "IgaLicensingDraft.deleteByRealm", realmId);
        n += em.createQuery("DELETE FROM IgaUnsignedEntityEntity u WHERE u.realmId = :realmId")
                .setParameter("realmId", realmId).executeUpdate();

        n += em.createQuery("DELETE FROM IgaChangeRequestEntity cr "
                        + "WHERE cr.realmId = :realmId AND cr.id <> :keep")
                .setParameter("realmId", realmId).setParameter("keep", keep).executeUpdate();

        // Role policies reference Forseti contracts, so policies go first.
        n += byRealm(em, "IgaRolePolicy.deleteByRealm", realmId);
        n += byRealm(em, "IgaForsetiContract.deleteByRealm", realmId);

        n += em.createQuery("DELETE FROM IgaAuthorizerEntity a WHERE a.realmId = :realmId")
                .setParameter("realmId", realmId).executeUpdate();
        n += byRealm(em, "IgaLicenseHistory.deleteByRealm", realmId);
        n += em.createQuery("DELETE FROM IgaToggleJobEntity j WHERE j.realmId = :realmId")
                .setParameter("realmId", realmId).executeUpdate();

        log.debugf("IGA cleanup: removed %d row(s) of deleted realm %s", n, realmId);
        return n;
    }

    private static int byRealm(EntityManager em, String namedQuery, String realmId) {
        return em.createNamedQuery(namedQuery).setParameter("realmId", realmId).executeUpdate();
    }
}
