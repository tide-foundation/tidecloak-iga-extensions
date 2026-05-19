package org.tidecloak.iga.providers;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import jakarta.persistence.EntityManager;

import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakTransaction;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;

/**
 * Phase 4 — true batch governance for {@code partialImport}.
 *
 * <h2>Why this exists</h2>
 * The single-entity capture seams (Phases 1–3:
 * {@code IgaRoleAdapter#getName}, {@code IgaGroupAdapter#setDescription},
 * {@code IgaClientAdapter#updateClient}, {@code IgaClientScopeAdapter#getId},
 * {@code IgaUserAdapter#getId}) each emit ONE CR and then
 * {@code setRollbackOnly()} + throw {@link IgaPendingApprovalException}
 * mid-flow. Inside {@code POST /admin/realms/{realm}/partialImport} that means
 * the FIRST captured entity aborts the whole import (the rest never run) and,
 * worse, the 5-arg local-storage {@code addUser} that
 * {@code DefaultExportImportManager.createUser} uses is NOT a Phase-3 seam at
 * all, so partial-import users were created UNGOVERNED.
 *
 * <h2>Mechanism (source-proven against KC 26.5.5)</h2>
 * {@code RealmAdminResource#partialImport} (RealmAdminResource.java:1304) runs
 * the whole import inside
 * {@code KeycloakModelUtils.runJobInTransactionWithResult}
 * (KeycloakModelUtils.java:453-472): a fresh nested {@link KeycloakSession}
 * with its own {@code KeycloakTransactionManager}. The nested JPA scratch tx
 * is enlisted into that manager's MAIN {@code transactions} list
 * ({@code DefaultJpaConnectionProviderFactory.java:108}
 * {@code getTransactionManager().enlist(new JpaKeycloakTransaction(em))}).
 *
 * <p>{@code DefaultKeycloakTransactionManager#commit}
 * (DefaultKeycloakTransactionManager.java:113-167) commits the
 * {@code prepare} list FIRST (:124-130), strictly BEFORE the main
 * {@code transactions} list (:135-141). If a {@code prepare} tx's
 * {@code commit()} throws a {@code RuntimeException} it is captured (:127-128)
 * and {@code if (exception != null) { rollback(exception); return; }}
 * (:131-134) runs: {@code rollback(RuntimeException)} (:187-208) rolls back
 * ALL main {@code transactions} (:190-196 → {@code JpaKeycloakTransaction
 * .rollback()} → scratch JPA DISCARDED) then {@code throw exception} (:205-207)
 * rethrows. The throw propagates:
 * {@code DefaultKeycloakSession#closeTransactionManager} (:393 commit, :395-396
 * catch+return) → {@code close()} rethrows (:379-381) → out of the
 * try-with-resources in {@code runJobInTransactionWithResult} (:457-470, the
 * {@code finally} only restores the session util — does NOT swallow) → out of
 * {@code partialImport} (catches only {@code ModelDuplicateException}) →
 * JAX-RS → {@link org.tidecloak.iga.rest.IgaPendingApprovalExceptionMapper}
 * → 202.
 *
 * <p>So: enlist a {@link KeycloakTransaction} on the NESTED import session via
 * {@code getTransactionManager().enlistPrepare(...)} the first time an entity
 * is accumulated in import mode. Its {@link KeycloakTransaction#commit()}
 * runs AFTER the whole {@code PartialImportManager.saveResources} callable has
 * completed (every entity built + accumulated) but BEFORE the scratch JPA
 * commit; it writes all N accumulated per-type CRs in ONE separate
 * {@code KeycloakModelUtils.runJobInTransaction} (an independent tx that
 * commits and survives) and then throws one
 * {@link IgaPendingApprovalException} → the scratch JPA tx is rolled back
 * (every imported entity discarded atomically) and the mapper returns a single
 * 202 carrying the batch.
 *
 * <p><b>CRITICAL constraint:</b> {@code closeTransactionManager} (:390) checks
 * {@code getRollbackOnly()} BEFORE deciding commit-vs-rollback; the
 * {@code rollback()} path NEVER iterates the {@code prepare} list. Therefore
 * in import mode the capture seams MUST NOT call
 * {@code session.getTransactionManager().setRollbackOnly()} (the single-entity
 * Phases 1–3 branches still do — that path is byte-unchanged). The
 * prepare-tx's own throw is what causes the discard.
 *
 * <p>{@code enlistPrepare} called mid-callable is safe: the manager is
 * {@code active} so it calls {@code transaction.begin()}
 * (DefaultKeycloakTransactionManager.java:69-75) — {@link BatchEmitTransaction
 * #begin()} is a no-op.
 *
 * <h2>Replay contract</h2>
 * Each accumulated row is the EXACT same per-type CR
 * ({@code CREATE_ROLE/CREATE_GROUP/CREATE_CLIENT/CREATE_CLIENT_SCOPE/
 * CREATE_USER} with the same {@code REP_JSON}/row contract) that the
 * single-entity seams already write and that
 * {@code IgaReplayDispatcher.replayCreate*} already consumes one CR at a time.
 * {@code IgaReplayDispatcher} is byte-unchanged.
 */
public final class IgaImportMode {

    private static final Logger log = Logger.getLogger(IgaImportMode.class);

    /** Nested-session attribute holding the per-import accumulator. */
    private static final String ACCUMULATOR_ATTR = "IGA_IMPORT_ACCUMULATOR";

    /**
     * KC 26.5.5 frames that prove we are servicing a {@code partialImport}.
     * The StackWalker matches if ANY of these is present ANYWHERE on the stack
     * (not just the immediate caller), so it fires for clients/roles/groups
     * and the 5-arg local-storage {@code addUser} alike — and is ABSENT for a
     * normal single-entity admin create (RoleContainerResource/UsersResource/
     * ClientsResource straight off the JAX-RS invoker), so Phases 1–3 are
     * untouched.
     */
    private static final String FRAME_REALM_ADMIN_RESOURCE =
            "org.keycloak.services.resources.admin.RealmAdminResource";
    private static final String FRAME_PARTIAL_IMPORT_METHOD = "partialImport";
    private static final String FRAME_PARTIAL_IMPORT_PKG =
            "org.keycloak.partialimport.";
    private static final String FRAME_EXPORTIMPORT_UTIL_PKG =
            "org.keycloak.exportimport.util.";
    private static final String FRAME_PARTIAL_IMPORT_MANAGER =
            "org.keycloak.partialimport.PartialImportManager";

    private IgaImportMode() {
    }

    /**
     * One accumulated entity = one per-type CR exactly as the single-entity
     * seam would have written it.
     */
    static final class PendingCr {
        final String entityType;   // CR entityType: ROLE/GROUP/CLIENT/CLIENT_SCOPE/USER
        final String entityId;
        final String actionType;   // CREATE_ROLE/CREATE_GROUP/...
        final List<Map<String, Object>> rows;
        final String requestedBy;

        PendingCr(String entityType, String entityId, String actionType,
                  List<Map<String, Object>> rows, String requestedBy) {
            this.entityType = entityType;
            this.entityId = entityId;
            this.actionType = actionType;
            this.rows = rows;
            this.requestedBy = requestedBy;
        }
    }

    /**
     * Per-import accumulator, held as a nested-session attribute. Also tracks
     * the realm id so the batch-emit tx (which runs on a SEPARATE session)
     * can re-resolve the realm.
     */
    static final class Accumulator {
        final String realmId;
        final List<PendingCr> pending = new ArrayList<>();
        // Capture-mode user adapters created on the 5-arg import path. They
        // have no per-entity terminal seam during import (DefaultExport
        // ImportManager.createUser returns without a final unconditional
        // model read), so their row is harvested at batch-emit time AFTER
        // every setter/joinGroup has been applied.
        final List<IgaUserAdapter> pendingUsers = new ArrayList<>();
        boolean prepareEnlisted = false;

        Accumulator(String realmId) {
            this.realmId = realmId;
        }
    }

    /**
     * True iff a {@code partialImport} frame is present ANYWHERE on the
     * current stack. Deterministic, no allocation beyond the StackWalker.
     */
    public static boolean inPartialImport() {
        return StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames.anyMatch(f -> {
                    String cn = f.getDeclaringClass().getName();
                    String mn = f.getMethodName();
                    if (FRAME_REALM_ADMIN_RESOURCE.equals(cn)
                            && FRAME_PARTIAL_IMPORT_METHOD.equals(mn)) {
                        return true;
                    }
                    if (FRAME_PARTIAL_IMPORT_MANAGER.equals(cn)) {
                        return true;
                    }
                    return cn.startsWith(FRAME_PARTIAL_IMPORT_PKG)
                            || cn.startsWith(FRAME_EXPORTIMPORT_UTIL_PKG);
                }));
    }

    /**
     * Import-mode predicate for a capture seam: IGA enabled for the realm,
     * NOT replay, and a {@code partialImport} frame on the stack.
     * {@code IGA_REPLAY_ACTIVE} short-circuits this so commit-time replay (a
     * single per-type CR run, NOT a partialImport) is never batched and the
     * single-entity replay path is provably untouched.
     */
    public static boolean isImportMode(KeycloakSession session, RealmModel realm) {
        Object replay = session.getAttribute("IGA_REPLAY_ACTIVE");
        if ("true".equals(replay)) {
            return false;
        }
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        IgaChangeRequestService svc = new IgaChangeRequestService(em, session);
        if (!svc.isIgaEnabled(realm)) {
            return false;
        }
        return inPartialImport();
    }

    private static Accumulator accumulator(KeycloakSession session, RealmModel realm) {
        Object existing = session.getAttribute(ACCUMULATOR_ATTR);
        if (existing instanceof Accumulator acc) {
            return acc;
        }
        Accumulator acc = new Accumulator(realm.getId());
        session.setAttribute(ACCUMULATOR_ATTR, acc);
        log.infof("IGA multi-entity: import mode ENTERED for realm=%s — a "
                + "partialImport frame is present on the stack (batch "
                + "governance armed; per-entity throw/setRollbackOnly "
                + "suppressed for this import)", realm.getName());
        return acc;
    }

    private static void enlistPrepareOnce(KeycloakSession session, RealmModel realm,
                                          Accumulator acc) {
        if (acc.prepareEnlisted) {
            return;
        }
        acc.prepareEnlisted = true;
        session.getTransactionManager()
                .enlistPrepare(new BatchEmitTransaction(session, realm.getId()));
        log.infof("IGA multi-entity: batch-emit transaction enlisted on the "
                + "nested import session (enlistPrepare) — it commits AFTER "
                + "the import callable, BEFORE the scratch JPA commit "
                + "(DefaultKeycloakTransactionManager.commit:124-130)");
    }

    /**
     * Accumulate a fully-built per-type CR (the SAME row contract the
     * single-entity seam writes). Returns normally — NO throw, NO
     * {@code setRollbackOnly()} (see class javadoc CRITICAL note). Lazily
     * enlists the batch-emit prepare-tx on first use.
     */
    public static void accumulate(KeycloakSession session, RealmModel realm,
                                  String entityType, String entityId,
                                  String actionType, List<Map<String, Object>> rows,
                                  String requestedBy) {
        Accumulator acc = accumulator(session, realm);
        enlistPrepareOnce(session, realm, acc);
        acc.pending.add(new PendingCr(entityType, entityId, actionType, rows, requestedBy));
        log.infof("IGA multi-entity ACCUM: %s %s (entityId=%s, rows=%d) — "
                + "accumulated, no per-entity CR/throw (batch on import "
                + "complete)", actionType, shortName(rows), entityId,
                rows == null ? 0 : rows.size());
    }

    /**
     * Register a capture-mode user adapter built on the 5-arg local-storage
     * {@code addUser} import path. Its row is harvested at batch-emit time
     * (after every setter/joinGroup has been applied by
     * {@code DefaultExportImportManager.createUser}).
     */
    public static void registerImportUser(KeycloakSession session, RealmModel realm,
                                          IgaUserAdapter user) {
        Accumulator acc = accumulator(session, realm);
        enlistPrepareOnce(session, realm, acc);
        acc.pendingUsers.add(user);
        log.infof("IGA multi-entity ACCUM: CREATE_USER (deferred-harvest) "
                + "registered for the 5-arg local-storage addUser import path "
                + "— row built at batch emit (no per-entity throw)");
    }

    private static String shortName(List<Map<String, Object>> rows) {
        if (rows == null || rows.isEmpty()) {
            return "?";
        }
        Object n = rows.get(0).get("NAME");
        if (n == null) {
            n = rows.get(0).get("USERNAME");
        }
        if (n == null) {
            n = rows.get(0).get("CLIENT_ID");
        }
        return n == null ? "?" : String.valueOf(n);
    }

    /**
     * The {@code enlistPrepare}'d transaction. Its {@link #commit()} is the
     * pre-scratch-commit hook proven sound in the class javadoc: it writes
     * all accumulated CRs in one independent tx then throws so the scratch
     * import tx is rolled back and the mapper returns one 202.
     */
    static final class BatchEmitTransaction implements KeycloakTransaction {

        private final KeycloakSession importSession;
        private final String realmId;
        private boolean active = true;

        BatchEmitTransaction(KeycloakSession importSession, String realmId) {
            this.importSession = importSession;
            this.realmId = realmId;
        }

        @Override
        public void begin() {
            // No-op: there is no real resource here. enlistPrepare on an
            // already-active manager calls begin()
            // (DefaultKeycloakTransactionManager.java:69-75); nothing to do.
        }

        @Override
        public void commit() {
            // Runs in DefaultKeycloakTransactionManager#commit's `prepare`
            // loop (:124-130), AFTER the partialImport callable completed
            // (every entity built + accumulated) and BEFORE the scratch JPA
            // `transactions` commit (:135). Throwing here triggers
            // rollback(exception) (:131-134 → :187-208): the scratch JPA tx
            // is rolled back (every imported entity discarded atomically) and
            // the exception is rethrown → mapper → single 202.
            active = false;

            Object a = importSession.getAttribute(ACCUMULATOR_ATTR);
            if (!(a instanceof Accumulator acc)) {
                // No entity was ever accumulated (e.g. an empty import, or an
                // import with only non-governed types). Nothing to emit; let
                // the scratch tx commit normally.
                log.info("IGA multi-entity EMIT: no accumulated entities — "
                        + "batch-emit tx is a no-op, scratch import commits "
                        + "normally");
                return;
            }

            // Harvest the deferred-harvest user rows now (every
            // DefaultExportImportManager.createUser setter/joinGroup has run).
            for (IgaUserAdapter u : acc.pendingUsers) {
                PendingCr cr = u.buildImportUserPendingCr();
                if (cr != null) {
                    acc.pending.add(cr);
                }
            }

            List<PendingCr> batch = acc.pending;
            if (batch.isEmpty()) {
                log.info("IGA multi-entity EMIT: accumulator present but "
                        + "empty — batch-emit tx is a no-op");
                return;
            }

            // Write every accumulated CR in ONE independent tx that commits
            // and survives the scratch rollback (runJobInTransaction =
            // factory.create() → its own tx, decoupled from this nested
            // import session — exactly the survives-rollback idiom the
            // single-entity seams already use).
            List<String> crIds = new ArrayList<>();
            KeycloakModelUtils.runJobInTransaction(
                    importSession.getKeycloakSessionFactory(), newSession -> {
                RealmModel newRealm = newSession.realms().getRealm(realmId);
                EntityManager newEm = newSession
                        .getProvider(JpaConnectionProvider.class).getEntityManager();
                IgaChangeRequestService newService =
                        new IgaChangeRequestService(newEm, newSession);
                for (PendingCr cr : batch) {
                    crIds.add(newService.create(newRealm, cr.entityType, cr.entityId,
                            cr.actionType, cr.rows, cr.requestedBy).getId());
                }
            });

            String types = batch.stream()
                    .map(p -> p.actionType)
                    .collect(Collectors.toList()).toString();
            log.infof("IGA multi-entity EMIT: %d CRs %s — nested import tx "
                    + "rolled back, scratch discarded (crIds=%s)",
                    batch.size(), types, crIds);

            // Carry the dominant action type so the mapper/E2E can assert a
            // single batch 202. entityType=BATCH, actionType=PARTIAL_IMPORT.
            String firstCrId = crIds.isEmpty() ? null : crIds.get(0);
            throw new IgaPendingApprovalException(firstCrId, "BATCH",
                    "PARTIAL_IMPORT");
        }

        @Override
        public void rollback() {
            // The scratch import tx was rolled back (commit() above threw, or
            // the import callable itself failed). Nothing of ours to undo —
            // the CRs (if commit() reached them) were written on a separate,
            // already-committed session.
            active = false;
        }

        @Override
        public void setRollbackOnly() {
            // Not used: we never mark the nested import tx rollback-only (see
            // class javadoc CRITICAL note — that would skip the prepare list).
        }

        @Override
        public boolean getRollbackOnly() {
            return false;
        }

        @Override
        public boolean isActive() {
            return active;
        }
    }

    // Visible for any future diagnostics; not used by the hot path.
    static Set<String> accumulatedTypes(KeycloakSession session) {
        Object a = session.getAttribute(ACCUMULATOR_ATTR);
        if (a instanceof Accumulator acc) {
            return acc.pending.stream().map(p -> p.actionType)
                    .collect(Collectors.toSet());
        }
        return Set.of();
    }
}
