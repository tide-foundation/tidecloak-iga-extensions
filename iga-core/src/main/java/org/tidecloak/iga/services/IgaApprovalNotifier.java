package org.tidecloak.iga.services;

import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.tidecloak.iga.entities.IgaPushSubscriptionEntity;
import org.tidecloak.iga.providers.IgaPushSubscriptionService;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Tells a realm's approvers that a change request is waiting.
 *
 * <h3>Why this lives in TideCloak</h3>
 *
 * <p>A change request is born in TideCloak's database and nowhere else. The ORKs
 * never observe its creation, so they cannot be the thing that notices it -
 * they could only be told, which puts TideCloak back in the path. The trigger
 * is therefore unavoidably here.</p>
 *
 * <p>That is not a new single point of failure. If TideCloak is unreachable
 * there are no change requests being created and no {@code /approve} endpoint to
 * call, so notifications failing with it costs nothing that was not already
 * lost. Redundancy belongs on the delivery side, which is why a device
 * registers its subscription with every node it knows rather than one: any node
 * that is up can send, and the browser collapses duplicates on the shared
 * notification tag.</p>
 *
 * <h3>Best effort, always</h3>
 *
 * <p>Every failure here is swallowed. A push service being slow, a realm having
 * no VAPID keys yet, an admin with no devices registered - none of these may
 * affect whether the change request was created. A governance write that
 * succeeded must not be rolled back because a notification did not go out.</p>
 */
public final class IgaApprovalNotifier {

    private static final Logger log = Logger.getLogger(IgaApprovalNotifier.class);

    /** Turns notification sending off for a realm without uninstalling anything. */
    public static final String DISABLED_ATTR = "iga.push.disabled";

    /** Overrides the RFC 8292 {@code sub} claim; defaults to {@link #DEFAULT_SUBJECT}. */
    public static final String SUBJECT_ATTR = "iga.push.subject";
    private static final String DEFAULT_SUBJECT = "mailto:admin@tide.org";

    private IgaApprovalNotifier() {
    }

    /**
     * Notify approvers after the transaction that created the change request has
     * committed.
     *
     * <p>Deferring past commit is the whole point of this entry: sending from
     * inside the creating transaction would announce change requests that then
     * roll back, and an admin who opens the app to find nothing there learns to
     * ignore the notification.</p>
     *
     * <p>The send runs in its own session and its own transaction, because the
     * caller's is finished by then.</p>
     */
    public static void notifyAfterCommit(KeycloakSession session, RealmModel realm) {
        if (session == null || realm == null) {
            return;
        }
        if (Boolean.parseBoolean(realm.getAttribute(DISABLED_ATTR))) {
            return;
        }

        final String realmId = realm.getId();
        final KeycloakSessionFactory factory = session.getKeycloakSessionFactory();

        try {
            session.getTransactionManager().enlistAfterCompletion(
                    new AfterCommitTask(() -> notifyNow(factory, realmId)));
        } catch (RuntimeException e) {
            log.debugf(e, "Could not enlist approval notification for realm %s", realmId);
        }
    }

    /** Resolve approvers, load their devices, send. Never throws. */
    private static void notifyNow(KeycloakSessionFactory factory, String realmId) {
        try {
            KeycloakModelUtils.runJobInTransaction(factory, session -> {
                RealmModel realm = session.realms().getRealm(realmId);
                if (realm == null) {
                    return;
                }
                // Binding the realm is required before any user-stream lookup:
                // getRoleMembersStream reaches for session.getContext().getRealm()
                // and throws "Session not bound to a realm" without it.
                session.getContext().setRealm(realm);

                EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

                IgaVapidKeys keys = IgaVapidKeys.find(em, realmId);
                if (keys == null) {
                    // No device has ever subscribed in this realm, so there is
                    // nobody to tell and no reason to generate keys here.
                    return;
                }

                Set<String> approvers = approverUserIds(session, realm);
                if (approvers.isEmpty()) {
                    return;
                }

                IgaPushSubscriptionService subscriptions = new IgaPushSubscriptionService(em);

                List<IgaPushSubscriptionEntity> devices = subscriptions.findForUsers(realmId, approvers);
                if (devices.isEmpty()) {
                    return;
                }

                String subject = realm.getAttribute(SUBJECT_ATTR);
                IgaWebPushSender sender = new IgaWebPushSender(keys,
                        subject == null || subject.isBlank() ? DEFAULT_SUBJECT : subject);

                int delivered = 0;
                int forgotten = 0;
                for (IgaPushSubscriptionEntity device : devices) {
                    switch (sender.send(device)) {
                        case DELIVERED -> delivered++;
                        case GONE -> {
                            subscriptions.deleteByEndpoint(device.getEndpoint());
                            forgotten++;
                        }
                        case FAILED -> device.setLastFailureAt(System.currentTimeMillis());
                    }
                }

                log.debugf("Approval notification for realm %s: %d delivered, %d stale subscriptions dropped, "
                        + "%d devices considered", realm.getName(), delivered, forgotten, devices.size());
            });
        } catch (RuntimeException e) {
            // The change request is already committed and correct. A failed
            // notification must not surface as a governance error.
            log.warnf(e, "Approval notification failed for realm %s (change request unaffected)", realmId);
        }
    }

    /**
     * Who may approve in this realm.
     *
     * <p>Mirrors how the rest of IGA decides this: holders of
     * {@code realm-management:manage-realm}, plus holders of any role named in
     * the {@code iga.approverRole} realm attribute - which is the only way a
     * non-manage-realm admin can authorize.</p>
     */
    private static Set<String> approverUserIds(KeycloakSession session, RealmModel realm) {
        Set<String> ids = new LinkedHashSet<>();

        ClientModel realmManagement = realm.getClientByClientId("realm-management");
        if (realmManagement != null) {
            addMembers(session, realm, realmManagement.getRole("manage-realm"), ids);
            // The Tide approver role, created when IGA is toggled on.
            addMembers(session, realm, realmManagement.getRole("tide-realm-admin"), ids);
        }

        String approverRoles = realm.getAttribute("iga.approverRole");
        if (approverRoles != null && !approverRoles.isBlank()) {
            for (String roleName : approverRoles.split(",")) {
                String trimmed = roleName.trim();
                if (!trimmed.isEmpty()) {
                    addMembers(session, realm, realm.getRole(trimmed), ids);
                }
            }
        }
        return ids;
    }

    private static void addMembers(KeycloakSession session, RealmModel realm, RoleModel role, Set<String> into) {
        if (role == null) {
            return;
        }
        try {
            session.users().getRoleMembersStream(realm, role)
                    .forEach(user -> into.add(user.getId()));
        } catch (RuntimeException e) {
            log.debugf(e, "Could not enumerate members of role %s in realm %s",
                    role.getName(), realm.getName());
        }
    }

    /**
     * Runs work once the surrounding transaction has finished.
     *
     * <p>{@code enlistAfterCompletion} calls {@link #commit()} on success and
     * {@link #rollback()} on failure, which is exactly the discrimination
     * needed: a rolled-back change request must announce nothing.</p>
     */
    private static final class AfterCommitTask implements org.keycloak.models.KeycloakTransaction {

        private final Runnable onCommit;
        private boolean active = true;
        private boolean rollbackOnly;

        private AfterCommitTask(Runnable onCommit) {
            this.onCommit = onCommit;
        }

        @Override
        public void begin() {
            active = true;
        }

        @Override
        public void commit() {
            active = false;
            try {
                onCommit.run();
            } catch (RuntimeException e) {
                log.debug("Post-commit approval notification threw", e);
            }
        }

        @Override
        public void rollback() {
            active = false;
        }

        @Override
        public void setRollbackOnly() {
            rollbackOnly = true;
        }

        @Override
        public boolean getRollbackOnly() {
            return rollbackOnly;
        }

        @Override
        public boolean isActive() {
            return active;
        }
    }
}
