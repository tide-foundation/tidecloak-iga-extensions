package org.tidecloak.iga.services;

import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.tidecloak.iga.providers.IgaChangeRequestService;
import org.tidecloak.iga.replay.IgaReplayExtension;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Phase 6b — one-shot toggle-on ADOPT scan.
 *
 * <p>When IGA flips OFF→ON for a realm, this scan walks every unattested
 * "info" row ({@link IgaUnsignedRowScanner#allInfoEntities}) and emits a
 * per-entity {@code ADOPT_X} change request via
 * {@link IgaChangeRequestService#createAdoptCr}. The intent is that a realm
 * that has been operating with IGA disabled (or that was imported pre-IGA)
 * can be brought under governance in one step: every existing user, role,
 * group, client, and client-scope appears as a PENDING ADOPT CR until an
 * admin commits it.</p>
 *
 * <p>Three skip lanes filter the input before {@code createAdoptCr} is
 * called:</p>
 * <ol>
 *   <li><b>System filter</b> ({@link IgaSystemEntityFilter}): default-on,
 *       opt-out via realm attribute {@code iga.adopt.includeSystem=true}.
 *       Skips the realm's built-in admin clients and their roles, and
 *       hard-pins the {@code default-roles-&lt;realm&gt;} role/client.</li>
 *   <li><b>Already-committed ADOPT</b>: any entity that already has a CR with
 *       status APPROVED and action ADOPT_X (built into a per-type set ONCE at
 *       scan start via the {@code IDX_IGA_CR_REALM_ACTION_STATUS} index).
 *       This makes a re-toggle safe: no duplicate ADOPT CRs.</li>
 *   <li><b>Pending CREATE_* race</b>: an entity that currently has a PENDING
 *       {@code CREATE_X} CR is mid-flight. Its own commit will stamp the
 *       attestation; we must NOT enqueue an ADOPT alongside or the two will
 *       race. Built once at scan start per type.</li>
 * </ol>
 *
 * <p>The scan never aborts on a per-entity error: a row that exists in the
 * DB but can't be loaded as a model, an entity that races with a delete, or
 * a model-level capture failure are logged as WARN and counted under
 * {@code errors}. The toggle response surfaces all counters.</p>
 *
 * <p>One CR per entity (per-entity granularity — locked from prior design
 * rounds). No batch CR; every approval is independent.</p>
 *
 * <p>This class is invoked inside a fresh {@code KeycloakModelUtils
 * .runJobInTransaction} so that a scan failure CANNOT abort the toggle
 * attribute write that immediately preceded it.</p>
 */
public final class IgaAdoptScan {

    private static final Logger log = Logger.getLogger(IgaAdoptScan.class);

    /**
     * Result of one toggle-on scan. All counters are non-negative; the
     * {@link #adoptCrsCreated} keys are the five info-table entity types
     * (USER, ROLE, GROUP, CLIENT, CLIENT_SCOPE) and every key is always
     * present (zero-valued when nothing was created for that type).
     */
    public static final class ScanResult {
        public final String realmId;
        public final long durationMs;
        public final long totalEntitiesScanned;
        public final Map<String, Long> adoptCrsCreated;
        public final long skippedSystemFilter;
        public final long skippedAlreadyCommittedAdopt;
        public final long skippedPendingCreateCr;
        public final long skippedAlreadyAttested;
        public final long errors;

        ScanResult(String realmId, long durationMs, long totalEntitiesScanned,
                   Map<String, Long> adoptCrsCreated, long skippedSystemFilter,
                   long skippedAlreadyCommittedAdopt, long skippedPendingCreateCr,
                   long skippedAlreadyAttested, long errors) {
            this.realmId = realmId;
            this.durationMs = durationMs;
            this.totalEntitiesScanned = totalEntitiesScanned;
            this.adoptCrsCreated = adoptCrsCreated;
            this.skippedSystemFilter = skippedSystemFilter;
            this.skippedAlreadyCommittedAdopt = skippedAlreadyCommittedAdopt;
            this.skippedPendingCreateCr = skippedPendingCreateCr;
            this.skippedAlreadyAttested = skippedAlreadyAttested;
            this.errors = errors;
        }

        /** Map shape for the toggle response body — matches the locked contract. */
        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("realmId", realmId);
            m.put("durationMs", durationMs);
            m.put("totalEntitiesScanned", totalEntitiesScanned);
            m.put("adoptCrsCreated", adoptCrsCreated);
            Map<String, Long> skipped = new LinkedHashMap<>();
            skipped.put("systemFilter", skippedSystemFilter);
            skipped.put("alreadyCommittedAdopt", skippedAlreadyCommittedAdopt);
            skipped.put("pendingCreateCr", skippedPendingCreateCr);
            skipped.put("alreadyAttested", skippedAlreadyAttested);
            m.put("skipped", skipped);
            m.put("errors", errors);
            return m;
        }
    }

    private IgaAdoptScan() {
    }

    /**
     * Run the one-shot scan for a single realm.
     *
     * @param session       a fresh {@link KeycloakSession} bound to its own
     *                      transaction (caller must wrap in
     *                      {@code KeycloakModelUtils.runJobInTransaction}).
     * @param realm         the realm to scan — must be loaded through
     *                      {@code session.realms()} on the SAME session.
     * @param requestedBy   admin user id stamped on every emitted CR.
     * @param includeSystem if {@code true}, lift the {@link IgaSystemEntityFilter}
     *                      soft skips for built-in clients/roles. The hard
     *                      pin on {@code default-roles-&lt;realm&gt;} is
     *                      preserved regardless.
     * @return the {@link ScanResult} counters; never {@code null}.
     */
    public static ScanResult scan(KeycloakSession session, RealmModel realm,
                                   String requestedBy, boolean includeSystem) {
        if (session == null || realm == null) {
            throw new IllegalArgumentException("scan requires non-null session + realm");
        }
        long t0 = System.currentTimeMillis();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        IgaUnsignedRowScanner scanner = new IgaUnsignedRowScanner(em);
        IgaChangeRequestService crService = new IgaChangeRequestService(em, session);

        if (includeSystem) {
            log.warnf("IGA toggle-on scan: realm=%s started with includeSystem=true — "
                            + "built-in admin clients and their roles WILL be quarantined; "
                            + "default-roles-%s is still hard-pinned.",
                    realm.getName(), realm.getName());
        }

        // Build per-type "already committed ADOPT" skip sets ONCE at scan
        // start. Uses the IDX_IGA_CR_REALM_ACTION_STATUS index added in 6a.
        Map<String, Set<String>> committedAdoptByType = Map.of(
                IgaReplayExtension.ENTITY_TYPE_USER,
                queryEntityIdsByCr(em, realm.getId(), IgaReplayExtension.ACTION_ADOPT_USER, "APPROVED"),
                IgaReplayExtension.ENTITY_TYPE_ROLE,
                queryEntityIdsByCr(em, realm.getId(), IgaReplayExtension.ACTION_ADOPT_ROLE, "APPROVED"),
                IgaReplayExtension.ENTITY_TYPE_GROUP,
                queryEntityIdsByCr(em, realm.getId(), IgaReplayExtension.ACTION_ADOPT_GROUP, "APPROVED"),
                IgaReplayExtension.ENTITY_TYPE_CLIENT,
                queryEntityIdsByCr(em, realm.getId(), IgaReplayExtension.ACTION_ADOPT_CLIENT, "APPROVED"),
                IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE,
                queryEntityIdsByCr(em, realm.getId(), IgaReplayExtension.ACTION_ADOPT_CLIENT_SCOPE, "APPROVED")
        );

        // Build per-type "pending CREATE_*" race skip sets. CREATE actions
        // are literal strings (no central constants in the IgaReplayExtension
        // surface today — see IgaGroupAdapter / IgaUserProvider / etc).
        Map<String, Set<String>> pendingCreateByType = Map.of(
                IgaReplayExtension.ENTITY_TYPE_USER,
                queryEntityIdsByCr(em, realm.getId(), "CREATE_USER", "PENDING"),
                IgaReplayExtension.ENTITY_TYPE_ROLE,
                queryEntityIdsByCr(em, realm.getId(), "CREATE_ROLE", "PENDING"),
                IgaReplayExtension.ENTITY_TYPE_GROUP,
                queryEntityIdsByCr(em, realm.getId(), "CREATE_GROUP", "PENDING"),
                IgaReplayExtension.ENTITY_TYPE_CLIENT,
                queryEntityIdsByCr(em, realm.getId(), "CREATE_CLIENT", "PENDING"),
                IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE,
                queryEntityIdsByCr(em, realm.getId(), "CREATE_CLIENT_SCOPE", "PENDING")
        );

        // Tallies — per-type CR counts initialized to 0 so the response shape
        // is stable even when nothing was created.
        Map<String, Long> created = new LinkedHashMap<>();
        created.put(IgaReplayExtension.ENTITY_TYPE_USER, 0L);
        created.put(IgaReplayExtension.ENTITY_TYPE_ROLE, 0L);
        created.put(IgaReplayExtension.ENTITY_TYPE_GROUP, 0L);
        created.put(IgaReplayExtension.ENTITY_TYPE_CLIENT, 0L);
        created.put(IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE, 0L);

        long[] counters = new long[5]; // total, sysSkip, committedSkip, pendingSkip, errors
        long[] alreadyAttestedCounter = new long[1];

        // Deterministic order — locked: USER → ROLE → GROUP → CLIENT →
        // CLIENT_SCOPE. The scanner returns rows in DB insertion order; we
        // process each list independently so per-type counts are clean.
        for (IgaUnsignedRowScanner.InfoRow row : scanner.usersWithNames(realm.getId())) {
            processOne(crService, realm, IgaReplayExtension.ENTITY_TYPE_USER, row, null,
                    requestedBy, includeSystem, committedAdoptByType, pendingCreateByType,
                    created, counters, alreadyAttestedCounter);
        }
        for (IgaUnsignedRowScanner.InfoRow row : scanner.rolesWithNames(realm.getId())) {
            processOne(crService, realm, IgaReplayExtension.ENTITY_TYPE_ROLE, row, row.parentClientId(),
                    requestedBy, includeSystem, committedAdoptByType, pendingCreateByType,
                    created, counters, alreadyAttestedCounter);
        }
        for (IgaUnsignedRowScanner.InfoRow row : scanner.groupsWithNames(realm.getId())) {
            processOne(crService, realm, IgaReplayExtension.ENTITY_TYPE_GROUP, row, null,
                    requestedBy, includeSystem, committedAdoptByType, pendingCreateByType,
                    created, counters, alreadyAttestedCounter);
        }
        for (IgaUnsignedRowScanner.InfoRow row : scanner.clientsWithNames(realm.getId())) {
            processOne(crService, realm, IgaReplayExtension.ENTITY_TYPE_CLIENT, row, null,
                    requestedBy, includeSystem, committedAdoptByType, pendingCreateByType,
                    created, counters, alreadyAttestedCounter);
        }
        for (IgaUnsignedRowScanner.InfoRow row : scanner.clientScopesWithNames(realm.getId())) {
            processOne(crService, realm, IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE, row, null,
                    requestedBy, includeSystem, committedAdoptByType, pendingCreateByType,
                    created, counters, alreadyAttestedCounter);
        }

        long durationMs = System.currentTimeMillis() - t0;
        ScanResult result = new ScanResult(
                realm.getId(),
                durationMs,
                counters[0],
                created,
                counters[1],
                counters[2],
                counters[3],
                alreadyAttestedCounter[0],
                counters[4]
        );
        log.infof("IGA toggle-on scan: realm=%s durationMs=%d scanned=%d created=%s "
                        + "skippedSystem=%d skippedCommittedAdopt=%d skippedPendingCreate=%d "
                        + "skippedAlreadyAttested=%d errors=%d",
                realm.getName(), durationMs, counters[0], created, counters[1], counters[2],
                counters[3], alreadyAttestedCounter[0], counters[4]);
        return result;
    }

    /**
     * Per-entity processing. Wrapped in a try/catch so one bad row never
     * aborts the scan — every other counter is per-entity, mutually
     * exclusive, and only one is incremented per invocation.
     */
    private static void processOne(IgaChangeRequestService crService,
                                    RealmModel realm,
                                    String entityType,
                                    IgaUnsignedRowScanner.InfoRow row,
                                    String parentClientId,
                                    String requestedBy,
                                    boolean includeSystem,
                                    Map<String, Set<String>> committedAdoptByType,
                                    Map<String, Set<String>> pendingCreateByType,
                                    Map<String, Long> created,
                                    long[] counters,
                                    long[] alreadyAttestedCounter) {
        counters[0]++; // total scanned
        try {
            // 1. System-entity filter.
            if (IgaSystemEntityFilter.shouldSkip(realm, entityType, row.entityId(),
                    row.entityName(), parentClientId, includeSystem)) {
                counters[1]++;
                log.debugf("IGA scan skip(systemFilter): realm=%s type=%s id=%s name=%s parent=%s",
                        realm.getName(), entityType, row.entityId(), row.entityName(), parentClientId);
                return;
            }
            // 2. Already-committed ADOPT skip.
            Set<String> committed = committedAdoptByType.get(entityType);
            if (committed != null && committed.contains(row.entityId())) {
                counters[2]++;
                log.debugf("IGA scan skip(alreadyCommittedAdopt): realm=%s type=%s id=%s",
                        realm.getName(), entityType, row.entityId());
                return;
            }
            // 3. Pending CREATE_* race skip.
            Set<String> pending = pendingCreateByType.get(entityType);
            if (pending != null && pending.contains(row.entityId())) {
                counters[3]++;
                log.debugf("IGA scan skip(pendingCreateCr): realm=%s type=%s id=%s",
                        realm.getName(), entityType, row.entityId());
                return;
            }
            // 4. Emit the ADOPT CR. createAdoptCr's already-attested guard
            //    won't fire here (the scan only sees attestation IS NULL
            //    rows) but we defensively catch it for symmetry.
            crService.createAdoptCr(realm, entityType, row.entityId(), requestedBy);
            created.merge(entityType, 1L, Long::sum);
        } catch (IgaChangeRequestService.AlreadyAttestedException aae) {
            alreadyAttestedCounter[0]++;
            log.debugf("IGA scan skip(alreadyAttested): realm=%s type=%s id=%s",
                    realm.getName(), entityType, row.entityId());
        } catch (RuntimeException ex) {
            counters[4]++;
            log.warnf(ex,
                    "IGA scan ERROR on realm=%s type=%s id=%s name=%s — continuing",
                    realm.getName(), entityType, row.entityId(), row.entityName());
        }
    }

    /**
     * Project (entityId) for CRs matching (realmId, actionType, status). Uses
     * the {@code IDX_IGA_CR_REALM_ACTION_STATUS} index added in 6a. Returns a
     * HashSet for O(1) contains() checks during the per-entity loop.
     */
    private static Set<String> queryEntityIdsByCr(EntityManager em, String realmId,
                                                   String actionType, String status) {
        @SuppressWarnings("unchecked")
        List<String> ids = em.createQuery(
                "SELECT cr.entityId FROM IgaChangeRequestEntity cr " +
                        "WHERE cr.realmId = :realmId " +
                        "AND cr.actionType = :actionType " +
                        "AND cr.status = :status")
                .setParameter("realmId", realmId)
                .setParameter("actionType", actionType)
                .setParameter("status", status)
                .getResultList();
        return new HashSet<>(ids);
    }
}
