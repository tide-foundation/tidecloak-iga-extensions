package org.tidecloak.iga.nginx;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.cluster.ClusterProvider;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.timer.TimerProvider;

import java.util.List;

/**
 * Wires the private-nginx subsystem into the server: its schema, its cluster listener, and its
 * repair timer.
 *
 * <p>It rides on {@code JpaEntityProviderFactory} because that gives it a {@code postInit}, which is
 * the hook Keycloak offers extensions for one-off startup work. Registering the schema here rather
 * than on the IGA entity provider keeps these tables on their own version line — none of them are
 * governed objects. Keycloak merges all entity providers into one persistence unit, so they still
 * share a transaction and an {@code EntityManager} with the IGA entities.
 */
public class NginxBootstrap implements JpaEntityProviderFactory, JpaEntityProvider {

    public static final String ID = "nginx-entity-provider";

    /**
     * Missed-event repair only — cluster notification is what normally makes a change immediate.
     * Deliberately coarse: a shorter period would not make convergence faster, only noisier.
     */
    private static final long REPAIR_INTERVAL_MILLIS = 30 * 60 * 1000L;

    private static final String REPAIR_TASK_NAME = "tidecloak-nginx-reconcile";

    private static final Logger log = Logger.getLogger(NginxBootstrap.class);

    @Override
    public List<Class<?>> getEntities() {
        return List.of(NginxGlobalCounterEntity.class);
    }

    @Override
    public String getChangelogLocation() {
        return "META-INF/nginx-changelog.xml";
    }

    @Override
    public String getFactoryId() {
        return ID;
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public NginxBootstrap create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {
    }

    /**
     * Nothing here may throw: a replica that cannot set up its private TLS path must still start and
     * serve public traffic.
     */
    @Override
    public void postInit(KeycloakSessionFactory sessionFactory) {
        if (!NginxConfigRenderer.isPrivateTlsConfigured()) {
            log.debugf("Private nginx is off: %s is not set. No listener, timer or reconcile.",
                    "TIDECLOAK_PRIVATE_DOMAIN_SUFFIX");
            return;
        }

        // Registered separately. Sharing a try block meant a missing ClusterProvider also cost this
        // replica its repair timer, which is the very thing that recovers from a dead event path.
        try {
            KeycloakModelUtils.runJobInTransaction(sessionFactory, session -> {
                // Fan-out, not single-execution: every replica has its own nginx to update, so this
                // is registerListener and NOT executeIfNotExecuted.
                session.getProvider(ClusterProvider.class).registerListener(
                        NginxGenerationNotifier.TASK_KEY,
                        event -> NginxReconciler.requestReconcile(sessionFactory));
            });
        } catch (Exception e) {
            log.error("Could not register the private-nginx cluster listener; this replica will only "
                    + "pick up generation changes on the repair timer.", e);
        }

        try {
            KeycloakModelUtils.runJobInTransaction(sessionFactory, session ->
                    session.getProvider(TimerProvider.class).scheduleTask(
                            ignored -> NginxReconciler.requestReconcile(sessionFactory),
                            REPAIR_INTERVAL_MILLIS, REPAIR_TASK_NAME));
        } catch (Exception e) {
            log.error("Could not schedule the private-nginx repair timer; a missed cluster event "
                    + "will leave this replica stale until it restarts.", e);
        }

        // A replica that has just started has an empty /run and knows nothing about what it missed
        // while it was down or before it existed.
        //
        // Off the boot thread. postInit runs during server startup, and a replica joining a cluster
        // that is already at some generation would materialize, render, run the reload helper and
        // then wait for nginx to acknowledge — up to 40 seconds of startup spent on something the
        // public listener does not depend on. Daemon, so it can never hold up shutdown either.
        Thread startup = new Thread(() -> {
            try {
                NginxReconciler.requestReconcile(sessionFactory);
            } catch (Exception e) {
                log.error("Startup private-nginx reconcile failed; the repair timer will retry.", e);
            }
        }, "tidecloak-nginx-startup-reconcile");
        startup.setDaemon(true);
        startup.start();
    }

    @Override
    public void close() {
    }
}
