package org.tidecloak.iga.tasks;

import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.timer.ScheduledTask;
import org.tidecloak.iga.entities.IgaRolePolicyEntity;
import org.tidecloak.iga.providers.IgaRolePolicyService;

import java.util.List;

/**
 * Clears out policies whose expiry has passed.
 *
 * <h3>This is housekeeping, and nothing depends on it running</h3>
 *
 * An expired policy already grants nothing. Every ork runs
 * {@code PolicyAuthorizationFlow}, which rejects an expired policy after verifying its signature,
 * and {@code PolicySignRequest} refuses to sign one that has already expired. Enforcement is the
 * network's, on a rule it owns. So this task removes rows that no longer do anything; it does not
 * end access, and if it stopped running nothing would become more permissive. That distinction is
 * worth keeping, because the moment a sweep is treated as the thing that revokes, a server that
 * fails to run it becomes a server that fails to revoke.
 *
 * <h3>What it will not touch</h3>
 *
 * A standing policy - one with no expiry - is never selected. That is what keeps the reserved
 * tide-realm-admin row out of the sweep without naming it: the admin policy carries no expiry, so
 * a query that only matches expiries cannot reach it. It is not excluded by a rule that could be
 * got around; it is not eligible in the first place.
 *
 * <h3>Deleting the row deletes a signature</h3>
 *
 * The row holds the signed policy and the signature over it. Deleting it is deliberate: the grant
 * it described is spent, and an application that wants the round trip keeps its own copy of the
 * signature alongside the columns the policy was built from. If a realm ever needs realm-side
 * history of spent grants, this is the place that would have to become a stamp rather than a
 * delete - the query and the schedule would not change.
 */
public class IgaExpiredPolicySweepTask implements ScheduledTask {

    private static final Logger log = Logger.getLogger(IgaExpiredPolicySweepTask.class);

    /** Also the timer key, so a second schedule of the same task replaces rather than duplicates. */
    public static final String TASK_NAME = "tide:iga:expired-policy-sweep";

    @Override
    public String getTaskName() {
        return TASK_NAME;
    }

    /**
     * The session, transaction and cluster lock are all supplied by the runner; this only does the
     * work. Deliberately NOT per realm: an expired policy is expired in every realm at once, so one
     * query answers for all of them and there is no realm context to get wrong.
     */
    @Override
    public void run(KeycloakSession session) {
        // SECONDS, because that is the unit a policy signs its expiry in - an int64 at index 7 of
        // its DataToVerify. Comparing in any other unit would silently sweep the wrong rows.
        long now = System.currentTimeMillis() / 1000L;

        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        IgaRolePolicyService policies = new IgaRolePolicyService(em);

        List<IgaRolePolicyEntity> expired = policies.findExpired(now);
        if (expired.isEmpty()) {
            log.debugf("IGA expired-policy sweep: nothing expired at %d.", now);
            return;
        }

        int removed = 0;
        for (IgaRolePolicyEntity policy : expired) {
            // Per policy, so one row that cannot be removed does not strand the rest. A sweep that
            // gives up on its first bad row leaves the backlog to grow behind it.
            try {
                log.infof("IGA expired-policy sweep: removing '%s' (realm %s, expired %d, %d seconds ago).",
                        policy.getName(), policy.getRealmId(), policy.getExpiry(),
                        now - policy.getExpiry());
                policies.deleteById(policy.getId());
                removed++;
            } catch (RuntimeException e) {
                log.warnf(e, "IGA expired-policy sweep: could not remove '%s' (realm %s); "
                        + "leaving it for the next run.", policy.getName(), policy.getRealmId());
            }
        }

        log.infof("IGA expired-policy sweep: removed %d of %d expired policies.", removed, expired.size());
    }
}
