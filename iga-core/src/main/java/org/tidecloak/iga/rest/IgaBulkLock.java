package org.tidecloak.iga.rest;

import java.util.concurrent.Callable;

import org.keycloak.cluster.ClusterProvider;
import org.keycloak.cluster.ExecutionResult;
import org.keycloak.models.KeycloakSession;

/**
 * Per-realm cluster-safe mutex for the bulk-authorize endpoint.
 *
 * <p>This is a thin wrapper around KC's canonical cluster-wide
 * single-execution primitive
 * {@link ClusterProvider#executeIfNotExecuted(String, int, Callable)}. The
 * {@code taskKey} is namespaced as {@code "iga-bulk:" + realmId}, so two
 * simultaneous bulk-authorize calls against the SAME realm — whether they
 * land on the same JVM or different cluster nodes — race for the same
 * Infinispan-backed lock. The winner runs the callable; the loser observes
 * {@link ExecutionResult#isExecuted()} = {@code false} and the caller is
 * expected to respond with HTTP 429.</p>
 *
 * <p><strong>Why a SPI wrapper and not a plain {@code ConcurrentHashMap}.
 * </strong> An in-JVM
 * {@code ConcurrentHashMap<String, AtomicBoolean>} would be a single-node
 * shortcut. In a multi-node KC cluster, however, two simultaneous bulks
 * hitting different nodes wouldn't see each other's locks and could race
 * the per-CR loop. {@code ClusterProvider} is the same SPI KC itself uses
 * for cluster-safe single-shot tasks (e.g. expiration sweeps, key
 * rotation); in single-node dev mode the SPI is still wired through the
 * Infinispan local-cache implementation, so the API contract is identical
 * — the lock just lives in a local-only cache rather than a replicated
 * one. The per-CR gate inside the bulk loop remains the real
 * correctness floor (idempotent re-fetch + non-PENDING skip), but the
 * cluster lock prevents the wasted work and the 429 contract surfaces
 * normally to the second caller.</p>
 *
 * <p><strong>Timeout semantics.</strong> The {@code taskTimeoutInSeconds}
 * is the upper bound on how long ANY single bulk-authorize is allowed to
 * hold the lock. If the holding node crashes or the JVM hangs longer than
 * the timeout, the lock entry auto-expires and the next caller can take
 * over. We choose 600 seconds (10 minutes), which is well above the worst
 * realistic drain time for a {@code limit=1000} bulk (per-CR
 * authorize+commit + replay; ADOPT_* short-circuits to ~tens of ms each
 * — 1000 CRs &lt;&lt; 600 s) yet short enough that a dead-node lock
 * recovers within a typical incident-response window. See the
 * {@code BULK_LOCK_TIMEOUT_SECONDS} constant.</p>
 *
 * <p><strong>Result.</strong> When the callable runs to completion the
 * wrapper returns its result; when another node already holds the lock
 * the wrapper returns {@code null} via {@link Result#notHeld()} — the
 * caller distinguishes the two via {@link Result#isHeld()}.</p>
 */
public final class IgaBulkLock {

    /**
     * Upper bound on how long any single bulk-authorize is allowed to
     * hold the cluster lock before the lock entry auto-expires. See the
     * class-level doc for the choice of 600 s.
     */
    public static final int BULK_LOCK_TIMEOUT_SECONDS = 600;

    /** Task-key prefix; the realm id is appended for per-realm isolation. */
    private static final String TASK_KEY_PREFIX = "iga-bulk:";

    private IgaBulkLock() {
        // static utility
    }

    /**
     * Run {@code task} under the per-realm cluster mutex. Returns a
     * {@link Result} carrying either the task's return value (lock held
     * by this caller) or a "not held" marker (another node is already
     * running a bulk against the same realm — caller should respond
     * 429).
     *
     * <p>Any exception raised by {@code task} propagates to the caller
     * (the lock is still released by the underlying SPI's finally
     * block). Callers that need REJECTED-vs-EXCEPTION semantics should
     * convert exceptions inside the callable itself, as the existing
     * {@code processOneCr} loop already does.</p>
     *
     * @param session  the KeycloakSession used to look up the ClusterProvider
     * @param realmId  the per-realm key (non-null)
     * @param task     the callable to run under the lock
     */
    public static <T> Result<T> runIfNotRunning(KeycloakSession session, String realmId, Callable<T> task) {
        if (session == null) {
            throw new IllegalArgumentException("session must not be null");
        }
        if (realmId == null) {
            throw new IllegalArgumentException("realmId must not be null");
        }
        if (task == null) {
            throw new IllegalArgumentException("task must not be null");
        }
        ClusterProvider cluster = session.getProvider(ClusterProvider.class);
        if (cluster == null) {
            throw new IllegalStateException(
                    "ClusterProvider is not available on this KeycloakSession; cannot acquire IGA bulk lock");
        }
        ExecutionResult<T> exec = cluster.executeIfNotExecuted(
                TASK_KEY_PREFIX + realmId,
                BULK_LOCK_TIMEOUT_SECONDS,
                task);
        if (exec.isExecuted()) {
            return Result.held(exec.getResult());
        }
        return Result.notHeld();
    }

    /**
     * Outcome of {@link #runIfNotRunning(KeycloakSession, String, Callable)}.
     *
     * <p>{@link #isHeld()} = {@code true} means this caller acquired the
     * lock and {@link #getValue()} is the task's return value.
     * {@code false} means another node is already running a bulk against
     * the same realm; the caller should respond with HTTP 429.</p>
     */
    public static final class Result<T> {
        private final boolean held;
        private final T value;

        private Result(boolean held, T value) {
            this.held = held;
            this.value = value;
        }

        static <T> Result<T> held(T value) {
            return new Result<>(true, value);
        }

        static <T> Result<T> notHeld() {
            return new Result<>(false, null);
        }

        public boolean isHeld() {
            return held;
        }

        public T getValue() {
            return value;
        }
    }
}
