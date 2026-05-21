package org.tidecloak.iga.rest;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Phase 6e — per-realm in-memory mutex for the bulk-authorize endpoint.
 *
 * <p>Single-node only: a concurrent bulk-authorize call against the SAME realm
 * from a SECOND HTTP request acquires {@code AtomicBoolean.compareAndSet}; if
 * the slot is already held the caller is rejected with HTTP 429 so the second
 * request can retry once the in-flight bulk drains. Cross-realm bulk calls are
 * independent (per-realm key isolation).</p>
 *
 * <p><strong>Single-node limitation.</strong> The lock lives in the JVM's heap
 * and is not visible to other KC nodes in a multi-node cluster. The Phase 6e
 * design accepts this scope: bulk-authorize is an operator one-shot, the
 * per-CR gate inside the loop is the real safety net (idempotent: a CR
 * already-resolved by a concurrent caller is detected as non-PENDING and
 * skipped — see IgaAdminResource#bulkAuthorize), and the dev/test stack is
 * single-node KC. A distributed advisory lock (JPA / Infinispan) is a
 * post-Phase-6 hardening item not required by the contract.</p>
 *
 * <p>The {@link AtomicBoolean} is intentionally NOT removed from the map on
 * release — the same realm typically receives multiple bulk calls over its
 * lifetime, so leaving the (one-flag-per-realm) entry in place avoids the
 * remove/insert race that would otherwise be possible without a second-level
 * lock. The map's total memory footprint is bounded by the realm count and
 * is negligible (one entry of ~32 bytes per realm).</p>
 */
public final class IgaBulkLock {

    private static final Map<String, AtomicBoolean> LOCKS = new ConcurrentHashMap<>();

    private IgaBulkLock() {
        // static utility
    }

    /**
     * Attempt to acquire the bulk-authorize lock for {@code realmId}.
     * Returns {@code true} when this caller now holds the lock; the caller
     * MUST invoke {@link #release(String)} in a finally block.
     * Returns {@code false} when another caller is already running a bulk
     * against the same realm — the caller should respond 429.
     */
    public static boolean tryAcquire(String realmId) {
        if (realmId == null) {
            throw new IllegalArgumentException("realmId must not be null");
        }
        AtomicBoolean flag = LOCKS.computeIfAbsent(realmId, k -> new AtomicBoolean(false));
        return flag.compareAndSet(false, true);
    }

    /**
     * Release a previously-acquired lock. Idempotent: a release on an
     * already-released slot is a no-op (the flag is simply set to false).
     */
    public static void release(String realmId) {
        if (realmId == null) return;
        AtomicBoolean flag = LOCKS.get(realmId);
        if (flag != null) {
            flag.set(false);
        }
    }
}
