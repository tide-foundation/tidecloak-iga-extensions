package org.tidecloak.iga.nginx;

import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;

/** Reads and advances the cluster-wide desired nginx configuration generation. */
public class NginxGlobalCounterService {

    /**
     * What a replica initialises its node-local applied generation to. Not 0 — a fresh cluster sits
     * at desired 0, and a node starting at 0 would call itself converged without ever having
     * rendered or validated anything.
     */
    public static final long UNAPPLIED_GENERATION = -1L;

    private final EntityManager em;

    public NginxGlobalCounterService(EntityManager em) {
        this.em = em;
    }

    /** The generation the cluster wants every replica to be serving. Takes no lock. */
    public long readDesiredGeneration() {
        return require().getCounter();
    }

    /**
     * Advance the generation and return the new value.
     *
     * <p>Must run inside the transaction that makes the change it describes. A new generation is a
     * promise that the state behind it is already durable; if the two committed separately, a
     * replica reacting to generation N could load state that lacks the change and — having recorded
     * N as applied — never look again. Notifying the cluster is separate, and happens after commit.
     *
     * <p>The row is locked and re-read so two nodes changing unrelated realms at the same moment get
     * distinct generations, rather than both reading N and both writing N+1.
     */
    public long allocateNextGeneration() {
        NginxGlobalCounterEntity row = require();
        em.refresh(row, LockModeType.PESSIMISTIC_WRITE);

        long next = row.getCounter() + 1;
        row.setCounter(next);
        row.setUpdatedAt(System.currentTimeMillis());
        return next;
    }

    /** Fails rather than creating the row: a missing row means the changelog has not been applied. */
    private NginxGlobalCounterEntity require() {
        NginxGlobalCounterEntity row =
                em.find(NginxGlobalCounterEntity.class, NginxGlobalCounterEntity.SINGLETON_ID);
        if (row == null) {
            throw new IllegalStateException("NGINX_GLOBAL_COUNTER row '"
                    + NginxGlobalCounterEntity.SINGLETON_ID + "' is missing; the nginx changelog "
                    + "has not been applied to this database");
        }
        return row;
    }
}
