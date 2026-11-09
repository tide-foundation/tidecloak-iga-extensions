package org.tidecloak.iga.nginx;

import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Brings this replica's nginx state in line with what the cluster wants.
 *
 * <p>Driven from three places — startup, a cluster generation event, and the repair timer — all of
 * which call {@link #requestReconcile}. They are wired up in {@link NginxBootstrap}.
 *
 * <p>Split in two on purpose. The database work — reading the counter, writing certificate material
 * — runs in a transaction; rendering, reloading nginx and waiting for it to acknowledge do not. A
 * subprocess and a poll loop have no business holding a database transaction open.
 */
public final class NginxReconciler {

    /**
     * Node-local, not cluster-wide. Every replica has to update its own nginx, so a distributed lock
     * would let exactly one node do the work and leave the rest stale. This only stops one replica
     * from running two passes over its own filesystem at once.
     */
    private static final ReentrantLock LOCK = new ReentrantLock();

    /**
     * Set by every request, cleared by the pass that will honour it. A request arriving while a pass
     * is running cannot simply be dropped: that pass may have already read the counter, so it would
     * miss the change that prompted the request.
     */
    private static final AtomicBoolean PENDING = new AtomicBoolean();

    /**
     * What this replica last managed to do. Node-local and in memory on purpose: it describes this
     * JVM's own nginx, so persisting or sharing it would let one replica answer for another.
     *
     * <p>Not a substitute for {@link NginxRuntimeClient#readAppliedGeneration()}. That is what nginx
     * is actually serving and stays the authority for deciding whether to reconcile; this is the
     * record of what this replica believes it achieved, which is what readiness is asked about. They
     * disagree exactly when something went wrong outside our control — nginx restarted, or was
     * reloaded by something other than us — and the difference is the signal.
     */
    /** Kept out of {@link Status} because it exists only to tell cleanup what to spare. */
    private static volatile long previousApplied = NginxGlobalCounterService.UNAPPLIED_GENERATION;

    private static volatile Status status =
            new Status(NginxGlobalCounterService.UNAPPLIED_GENERATION,
                    NginxGlobalCounterService.UNAPPLIED_GENERATION, null, 0L);

    private static final Logger log = Logger.getLogger(NginxReconciler.class);

    private NginxReconciler() {
    }

    /**
     * Reconcile, unless a pass is already running — in which case that pass picks the request up
     * before it finishes. Never blocks the caller, so cluster-event and timer threads are not held
     * behind a slow pass.
     */
    public static void requestReconcile(KeycloakSessionFactory sessionFactory) {
        if (!NginxConfigRenderer.isPrivateTlsConfigured()) {
            return;
        }
        PENDING.set(true);
        if (!LOCK.tryLock()) {
            return;
        }
        try {
            while (PENDING.getAndSet(false)) {
                try {
                    Plan plan = KeycloakModelUtils.runJobInTransactionWithResult(
                            sessionFactory, NginxReconciler::plan);
                    if (plan != null) {
                        apply(plan);
                    }
                } catch (Exception e) {
                    log.error("nginx reconcile failed; this replica may be serving stale private TLS "
                            + "state until the next attempt.", e);
                    Status last = status;
                    record(last.desired(), last.applied(), String.valueOf(e));
                }

                // Only when converged and healthy. Tidying up while this replica is unsure what it
                // is serving is how a generation still in use gets deleted.
                if (status.isReady()) {
                    try {
                        NginxCleanup.clean(status.applied(), previousApplied);
                    } catch (Exception e) {
                        log.warn("nginx cleanup failed; stale local projections remain.", e);
                    }
                }
            }
        } finally {
            LOCK.unlock();
        }
    }

    /** This replica's private-TLS position, for health and diagnostics. */
    public record Status(long desired, long applied, String lastError, long updatedAt) {

        /**
         * Whether this replica's private endpoint can be trusted to serve what the cluster expects.
         * Public traffic is unaffected either way — a replica that cannot reconcile its private TLS
         * should degrade, not fall over.
         */
        public boolean isReady() {
            return applied >= 0 && applied == desired && lastError == null;
        }
    }

    /** Never null. Before the first pass it reports an unapplied generation. */
    public static Status status() {
        return status;
    }

    private static void record(long desired, long applied, String lastError) {
        Status last = status;
        if (last.applied() >= 0 && last.applied() != applied) {
            previousApplied = last.applied();
        }
        status = new Status(desired, applied, lastError, System.currentTimeMillis());
    }

    /** What this replica has to do, decided against the database. */
    private record Plan(long desired, long applied, List<NginxConfigRenderer.RealmBlock> realms) {
    }

    /** Returns null when there is nothing to do. */
    private static Plan plan(KeycloakSession session) {
        long desired = new NginxGlobalCounterService(
                session.getProvider(JpaConnectionProvider.class).getEntityManager())
                .readDesiredGeneration();
        long applied = NginxRuntimeClient.readAppliedGeneration();

        if (applied == desired) {
            record(desired, applied, null);
            return null;
        }
        if (applied > desired) {
            String problem = "nginx is serving generation " + applied
                    + " but the database has only issued " + desired;
            log.errorf("%s. Not reconciling — this is a restored backup or an edited counter, not "
                    + "drift.", problem);
            record(desired, applied, problem);
            return null;
        }

        log.infof("nginx is at generation %d, cluster wants %d — reconciling.", applied, desired);

        // Material is written here, inside the transaction, because it is read out of the database
        // and the realm key store. The config that names these paths is rendered afterwards: nginx
        // fails to load a config pointing at a certificate that is not there yet, and takes every
        // other realm down with it.
        return new Plan(desired, applied, materialize(session));
    }

    private static void apply(Plan plan) {
        NginxConfigRenderer.render(plan.desired(), plan.realms());

        if (!NginxRuntimeClient.activate(plan.desired())) {
            log.errorf("Could not activate nginx generation %d. This replica stays on generation %d "
                    + "and will retry on the next event or repair tick.", plan.desired(), plan.applied());
            record(plan.desired(), plan.applied(),
                    "could not activate generation " + plan.desired());
            return;
        }

        // Recorded only here. activate() has already required nginx to report this generation on a
        // fresh connection, so this is an acknowledgement, never an assumption.
        record(plan.desired(), plan.desired(), null);
        log.infof("nginx generation %d is active on this replica, serving %d private realm(s).",
                plan.desired(), plan.realms().size());
    }

    /**
     * Write each realm's certificates and collect what the config needs to name them.
     *
     * <p>Realms are handled independently so one of them — no certificate issued yet, a missing
     * keypair, a name that cannot be a hostname — cannot stop the rest from being projected.
     */
    private static List<NginxConfigRenderer.RealmBlock> materialize(KeycloakSession session) {
        Map<String, List<RealmModel>> byHostname = new HashMap<>();
        for (RealmModel realm : session.realms().getRealmsStream().toList()) {
            String hostname = NginxConfigRenderer.privateHostname(realm);
            if (hostname != null) {
                byHostname.computeIfAbsent(hostname, ignored -> new ArrayList<>()).add(realm);
            }
        }

        List<NginxConfigRenderer.RealmBlock> blocks = new ArrayList<>();
        for (Map.Entry<String, List<RealmModel>> entry : byHostname.entrySet()) {
            List<RealmModel> claimants = entry.getValue();

            // Realm names differing only by case land on one hostname. Dropping all claimants rather
            // than picking one keeps every replica at the same answer — choosing a winner would
            // depend on iteration order, and replicas could disagree about whose endpoint it is.
            if (claimants.size() > 1) {
                log.errorf("Private hostname %s is claimed by %d realms; none of them will get a "
                        + "private endpoint.", entry.getKey(), claimants.size());
                continue;
            }

            RealmModel realm = claimants.get(0);
            try {
                NginxMaterialWriter.Material material = NginxMaterialWriter.materializeRealm(
                        session, realm,
                        session.getProvider(JpaConnectionProvider.class).getEntityManager());
                if (material == null) {
                    continue;
                }
                blocks.add(new NginxConfigRenderer.RealmBlock(
                        realm.getId(), entry.getKey(), material.cryptoGeneration()));
            } catch (Exception e) {
                log.errorf(e, "Could not materialize private TLS material for realm %s.",
                        realm.getName());
            }
        }

        // Stable order so two replicas render byte-identical configs for the same generation.
        blocks.sort((a, b) -> a.hostname().compareTo(b.hostname()));
        return blocks;
    }
}
