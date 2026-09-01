package org.tidecloak.iga.rest;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderEvent;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory;
import org.keycloak.services.scheduled.ClusterAwareScheduledTaskRunner;
import org.keycloak.timer.TimerProvider;
import org.tidecloak.iga.tasks.IgaExpiredPolicySweepTask;

public class IgaAdminResourceProviderFactory implements AdminRealmResourceProviderFactory {

    private static final Logger log = Logger.getLogger(IgaAdminResourceProviderFactory.class);

    public static final String ID = "iga";

    /**
     * How often to clear out policies whose expiry has passed.
     *
     * An hour, because nothing waits on it. The rows this removes already grant nothing - the orks
     * refuse an expired policy on their own - so the interval decides how long spent rows linger,
     * not how long access does. Sweeping more often would buy tidiness and cost a query.
     *
     * Configurable rather than fixed, so a realm with a lot of short-lived grants can sweep more
     * often without a rebuild. Zero or less turns the sweep off, which is a supportable thing to
     * want: the rows are harmless, and an operator who would rather keep them should not have to
     * patch code to do it.
     */
    static final String SWEEP_INTERVAL_KEY = "expiredPolicySweepIntervalSeconds";
    static final long SWEEP_INTERVAL_DEFAULT_SECONDS = 3600L;

    private long sweepIntervalMs;

    @Override
    public IgaAdminResourceProvider create(KeycloakSession session) {
        return new IgaAdminResourceProvider(session);
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public void init(Config.Scope config) {
        long seconds = config == null
                ? SWEEP_INTERVAL_DEFAULT_SECONDS
                : config.getLong(SWEEP_INTERVAL_KEY, SWEEP_INTERVAL_DEFAULT_SECONDS);
        sweepIntervalMs = seconds * 1000L;
    }

    /**
     * Scheduled on PostMigrationEvent rather than here, because the sweep reads a table that
     * Liquibase may not have created yet when factories initialise. Waiting for migration to finish
     * is the difference between a first run that works and one that fails on a missing column.
     */
    @Override
    public void postInit(KeycloakSessionFactory factory) {
        factory.register((ProviderEvent event) -> {
            if (event instanceof PostMigrationEvent) {
                scheduleExpiredPolicySweep(factory);
            }
        });
    }

    private void scheduleExpiredPolicySweep(KeycloakSessionFactory factory) {
        if (sweepIntervalMs <= 0) {
            log.infof("IGA expired-policy sweep disabled (%s <= 0).", SWEEP_INTERVAL_KEY);
            return;
        }

        try (KeycloakSession session = factory.create()) {
            TimerProvider timer = session.getProvider(TimerProvider.class);
            if (timer == null) {
                log.warn("IGA expired-policy sweep not scheduled: no TimerProvider on this session.");
                return;
            }

            // Cluster-aware: the timer fires on every node, and the runner takes a cluster lock so
            // only one node does the work in each interval. Without it every node would sweep the
            // same rows at the same moment and contend over deleting them.
            timer.schedule(
                    new ClusterAwareScheduledTaskRunner(factory, new IgaExpiredPolicySweepTask(), sweepIntervalMs),
                    sweepIntervalMs,
                    IgaExpiredPolicySweepTask.TASK_NAME);

            log.infof("IGA expired-policy sweep scheduled every %d seconds.", sweepIntervalMs / 1000L);
        } catch (RuntimeException e) {
            // Never fail startup for housekeeping. A realm that comes up without the sweep still
            // enforces every expiry, because expiry was never this server's to enforce.
            log.warn("IGA expired-policy sweep could not be scheduled; continuing without it.", e);
        }
    }

    @Override
    public void close() {
    }
}
