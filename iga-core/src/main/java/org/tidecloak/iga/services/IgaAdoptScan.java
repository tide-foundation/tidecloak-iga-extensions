package org.tidecloak.iga.services;

import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.tidecloak.iga.providers.IgaChangeRequestService;
import org.tidecloak.iga.replay.IgaReplayExtension;
import org.tidecloak.iga.replay.SidecarCapExceededException;

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
     * Phase 6d sidecar soft-cap. If at scan-start the realm already has more
     * than this many unattested sidecar rows, the toggle-on refuses with
     * {@link SidecarCapExceededException} and the caller rolls back the
     * realm-attribute write so IGA stays OFF. "Soft" here means the cap can
     * be raised by editing this constant (and rebuilding) — it is NOT a
     * realm attribute by design (so a misbehaving admin cannot lift it on
     * their own realm).
     *
     * <p>To raise: change the constant and redeploy. For E2E only, the
     * system property {@code iga.adopt.sidecarCap} overrides the constant —
     * this is a test-only escape hatch (not documented for operators).</p>
     */
    public static final long SIDECAR_CAP_DEFAULT = 100_000L;

    private static long sidecarCap() {
        String prop = System.getProperty("iga.adopt.sidecarCap");
        if (prop == null || prop.isEmpty()) return SIDECAR_CAP_DEFAULT;
        try {
            long parsed = Long.parseLong(prop.trim());
            return parsed > 0 ? parsed : SIDECAR_CAP_DEFAULT;
        } catch (NumberFormatException nfe) {
            return SIDECAR_CAP_DEFAULT;
        }
    }

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
        /**
         * Phase 6c — number of live user sessions invalidated on this
         * toggle-on so newly-quarantined users do NOT retain their existing
         * cookies / refresh tokens past the OFF→ON transition. Surfaced in
         * the toggle response as {@code scan.sessionsInvalidated}. Populated
         * by {@link #withSessionsInvalidated(long)} after
         * {@link IgaAdoptScan#scan} returns — the scan itself does NOT touch
         * sessions, the toggle-on caller does (see
         * {@link org.tidecloak.iga.rest.TideAdminCompatResource#toggleIga}).
         */
        public final long sessionsInvalidated;
        /**
         * Commit 2 — count of EDGE rows (composite-role / scope↔client /
         * scope→role / protocol-mapper) skipped because their owning NODE is a
         * built-in (KC default scope, built-in admin client, or the
         * {@code default-roles-<realm>} composite). Surfaced under
         * {@code skipped.systemEdges} so an operator can confirm the
         * skip-built-ins invariant held on toggle-on.
         */
        public final long skippedSystemEdges;

        ScanResult(String realmId, long durationMs, long totalEntitiesScanned,
                   Map<String, Long> adoptCrsCreated, long skippedSystemFilter,
                   long skippedAlreadyCommittedAdopt, long skippedPendingCreateCr,
                   long skippedAlreadyAttested, long errors,
                   long sessionsInvalidated, long skippedSystemEdges) {
            this.realmId = realmId;
            this.durationMs = durationMs;
            this.totalEntitiesScanned = totalEntitiesScanned;
            this.adoptCrsCreated = adoptCrsCreated;
            this.skippedSystemFilter = skippedSystemFilter;
            this.skippedAlreadyCommittedAdopt = skippedAlreadyCommittedAdopt;
            this.skippedPendingCreateCr = skippedPendingCreateCr;
            this.skippedAlreadyAttested = skippedAlreadyAttested;
            this.errors = errors;
            this.sessionsInvalidated = sessionsInvalidated;
            this.skippedSystemEdges = skippedSystemEdges;
        }

        /**
         * Return a new ScanResult with the supplied {@code sessionsInvalidated}
         * count folded in. Immutability-preserving so the scan itself (which
         * has no session/sessions provider on its scan-session) can return a
         * zero-count result that the caller then enriches.
         */
        public ScanResult withSessionsInvalidated(long count) {
            return new ScanResult(realmId, durationMs, totalEntitiesScanned,
                    adoptCrsCreated, skippedSystemFilter,
                    skippedAlreadyCommittedAdopt, skippedPendingCreateCr,
                    skippedAlreadyAttested, errors, count, skippedSystemEdges);
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
            skipped.put("systemEdges", skippedSystemEdges);
            m.put("skipped", skipped);
            m.put("errors", errors);
            m.put("sessionsInvalidated", sessionsInvalidated);
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
        // Bind the realm onto the scan session's KeycloakContext so downstream
        // model lookups (e.g. session.users().getUserById → org cache layer
        // that calls session.getContext().getRealm()) don't throw "Session not
        // bound to a realm". The fresh runJobInTransaction session has no
        // realm bound by default; without this, every USER row in
        // createAdoptCr → ModelToRepresentation.toRepresentation fails with
        // IllegalArgumentException ("Session not bound to a realm") at the
        // InfinispanOrganizationProvider#getRealm guard. Phase 6a's tests
        // happened not to exercise this path because they never pre-create
        // users with IGA off — Phase 6b's happy/race/already cases all do.
        session.getContext().setRealm(realm);
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        // Phase 6d sidecar cap (design risk #6). Reject before doing any work
        // so a runaway realm cannot exhaust memory by emitting hundreds of
        // thousands of ADOPT CRs in one scan. The caller catches the
        // exception, restores isIGAEnabled=false on the realm, and returns
        // 409 SIDECAR_CAP_EXCEEDED — see TideAdminCompatResource#toggleIga.
        long cap = sidecarCap();
        long current = IgaUnsignedEntityService.countByRealm(em, realm.getId());
        if (current > cap) {
            throw new SidecarCapExceededException(realm.getId(), cap, current);
        }

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
        // Phase 7b — adds ORGANIZATION (Map.of caps at 10 entries so we
        // switch to a builder-style LinkedHashMap once we have 6 keys).
        Map<String, Set<String>> committedAdoptByType = new LinkedHashMap<>();
        committedAdoptByType.put(IgaReplayExtension.ENTITY_TYPE_USER,
                queryEntityIdsByCr(em, realm.getId(), IgaReplayExtension.ACTION_ADOPT_USER, "APPROVED"));
        committedAdoptByType.put(IgaReplayExtension.ENTITY_TYPE_ROLE,
                queryEntityIdsByCr(em, realm.getId(), IgaReplayExtension.ACTION_ADOPT_ROLE, "APPROVED"));
        committedAdoptByType.put(IgaReplayExtension.ENTITY_TYPE_GROUP,
                queryEntityIdsByCr(em, realm.getId(), IgaReplayExtension.ACTION_ADOPT_GROUP, "APPROVED"));
        committedAdoptByType.put(IgaReplayExtension.ENTITY_TYPE_CLIENT,
                queryEntityIdsByCr(em, realm.getId(), IgaReplayExtension.ACTION_ADOPT_CLIENT, "APPROVED"));
        committedAdoptByType.put(IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE,
                queryEntityIdsByCr(em, realm.getId(), IgaReplayExtension.ACTION_ADOPT_CLIENT_SCOPE, "APPROVED"));
        committedAdoptByType.put(IgaReplayExtension.ENTITY_TYPE_ORGANIZATION,
                queryEntityIdsByCr(em, realm.getId(), IgaReplayExtension.ACTION_ADOPT_ORGANIZATION, "APPROVED"));
        // Commit 2 — edge entity types. The synthetic entityId (key1|key2) is
        // the same value stored on both the CR and the sidecar, so the
        // already-committed-ADOPT skip-set keys match across re-toggles.
        committedAdoptByType.put(IgaReplayExtension.ENTITY_TYPE_COMPOSITE_ROLE,
                queryEntityIdsByCr(em, realm.getId(), IgaReplayExtension.ACTION_ADOPT_COMPOSITE_ROLE, "APPROVED"));
        committedAdoptByType.put(IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE_CLIENT,
                queryEntityIdsByCr(em, realm.getId(), IgaReplayExtension.ACTION_ADOPT_CLIENT_SCOPE_CLIENT, "APPROVED"));
        committedAdoptByType.put(IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE_ROLE,
                queryEntityIdsByCr(em, realm.getId(), IgaReplayExtension.ACTION_ADOPT_CLIENT_SCOPE_ROLE, "APPROVED"));
        committedAdoptByType.put(IgaReplayExtension.ENTITY_TYPE_PROTOCOL_MAPPER,
                queryEntityIdsByCr(em, realm.getId(), IgaReplayExtension.ACTION_ADOPT_PROTOCOL_MAPPER, "APPROVED"));
        // Commit 3 — realm default-scope edge.
        committedAdoptByType.put(IgaReplayExtension.ENTITY_TYPE_REALM_DEFAULT_SCOPE,
                queryEntityIdsByCr(em, realm.getId(), IgaReplayExtension.ACTION_ADOPT_DEFAULT_CLIENT_SCOPE, "APPROVED"));
        // Commit 4 — client scope-mapping edge.
        committedAdoptByType.put(IgaReplayExtension.ENTITY_TYPE_SCOPE_MAPPING,
                queryEntityIdsByCr(em, realm.getId(), IgaReplayExtension.ACTION_ADOPT_SCOPE_MAPPING, "APPROVED"));

        // Build per-type "pending CREATE_*" race skip sets. CREATE actions
        // are literal strings (no central constants in the IgaReplayExtension
        // surface today — see IgaGroupAdapter / IgaUserProvider / etc).
        // Phase 7b adds CREATE_ORGANIZATION (the literal action type emitted
        // by IgaOrganizationModel.setDomains when captureCreate=true).
        Map<String, Set<String>> pendingCreateByType = new LinkedHashMap<>();
        pendingCreateByType.put(IgaReplayExtension.ENTITY_TYPE_USER,
                queryEntityIdsByCr(em, realm.getId(), "CREATE_USER", "PENDING"));
        pendingCreateByType.put(IgaReplayExtension.ENTITY_TYPE_ROLE,
                queryEntityIdsByCr(em, realm.getId(), "CREATE_ROLE", "PENDING"));
        pendingCreateByType.put(IgaReplayExtension.ENTITY_TYPE_GROUP,
                queryEntityIdsByCr(em, realm.getId(), "CREATE_GROUP", "PENDING"));
        pendingCreateByType.put(IgaReplayExtension.ENTITY_TYPE_CLIENT,
                queryEntityIdsByCr(em, realm.getId(), "CREATE_CLIENT", "PENDING"));
        pendingCreateByType.put(IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE,
                queryEntityIdsByCr(em, realm.getId(), "CREATE_CLIENT_SCOPE", "PENDING"));
        pendingCreateByType.put(IgaReplayExtension.ENTITY_TYPE_ORGANIZATION,
                queryEntityIdsByCr(em, realm.getId(), "CREATE_ORGANIZATION", "PENDING"));

        // Tallies — per-type CR counts initialized to 0 so the response shape
        // is stable even when nothing was created.
        Map<String, Long> created = new LinkedHashMap<>();
        created.put(IgaReplayExtension.ENTITY_TYPE_USER, 0L);
        created.put(IgaReplayExtension.ENTITY_TYPE_ROLE, 0L);
        created.put(IgaReplayExtension.ENTITY_TYPE_GROUP, 0L);
        created.put(IgaReplayExtension.ENTITY_TYPE_CLIENT, 0L);
        created.put(IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE, 0L);
        created.put(IgaReplayExtension.ENTITY_TYPE_ORGANIZATION, 0L);
        // Commit 2 — edge entity-type counters (always present, zero by default).
        created.put(IgaReplayExtension.ENTITY_TYPE_COMPOSITE_ROLE, 0L);
        created.put(IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE_CLIENT, 0L);
        created.put(IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE_ROLE, 0L);
        created.put(IgaReplayExtension.ENTITY_TYPE_PROTOCOL_MAPPER, 0L);
        // Commit 3 — realm default-scope edge counter (own key; existing
        // per-type ADOPT test counts are untouched).
        created.put(IgaReplayExtension.ENTITY_TYPE_REALM_DEFAULT_SCOPE, 0L);
        // Commit 4 — client scope-mapping edge counter (own key; existing
        // per-type ADOPT test counts are untouched).
        created.put(IgaReplayExtension.ENTITY_TYPE_SCOPE_MAPPING, 0L);

        long[] counters = new long[5]; // total, sysSkip, committedSkip, pendingSkip, errors
        long[] alreadyAttestedCounter = new long[1];
        long[] systemEdgesCounter = new long[1]; // commit 2 — built-in edges skipped

        // The committed-ADOPT skip set is the contract's idempotent-re-toggle
        // key: every entity in this realm that already has an APPROVED
        // ADOPT_X CR is "already governed" and MUST NOT be re-emitted. Seed
        // the skipped.alreadyCommittedAdopt counter with the total skip-set
        // size BEFORE the per-entity loop, because the scanner's
        // attestation-IS-NULL filter (in IgaUnsignedRowScanner.usersWithNames
        // et al.) typically excludes these entities outright — a successful
        // ADOPT replay stamps the entity row's attestation, so the row no
        // longer surfaces in the per-type lists. Without this pre-tally the
        // counter stays at 0 even when N entities are correctly being
        // skipped: the per-entity branch at processOne can only fire when
        // the scanner did surface the entity (the race-window case).
        //
        // The per-entity branch at processOne therefore no longer
        // increments counters[2] — it just short-circuits to avoid emitting
        // a duplicate CR for an attestation-NULL race row. The
        // pre-tally above is the single source of truth for the counter.
        for (Set<String> ids : committedAdoptByType.values()) {
            counters[2] += ids.size();
        }

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
        // Phase 7b — orgs. The scanner enumerates EVERY org in the realm
        // (no attestation-IS-NULL filter; OrganizationEntity has no such
        // column — see IgaUnsignedRowScanner.organizationsWithNames). The
        // committedAdoptByType skip-set is the sole "already governed"
        // filter; the pendingCreateByType skip-set covers a mid-flight
        // CREATE_ORGANIZATION CR's target. IgaSystemEntityFilter has no
        // ORGANIZATION rules today (no built-in/default orgs in stock KC),
        // so shouldSkip returns false for every entity-type-mismatched
        // branch — i.e. the filter is a no-op for orgs by design. If KC
        // ever introduces a default "platform" org we'll add the rule then;
        // for now an explicit skip would be invented complexity.
        for (IgaUnsignedRowScanner.InfoRow row : scanner.organizationsWithNames(realm.getId())) {
            processOne(crService, realm, IgaReplayExtension.ENTITY_TYPE_ORGANIZATION, row, null,
                    requestedBy, includeSystem, committedAdoptByType, pendingCreateByType,
                    created, counters, alreadyAttestedCounter);
        }

        // ---------------------------------------------------------------------
        // Commit 2 — EDGE enumeration. Admin-configured composite-role links,
        // scope↔client attaches, scope→role mappings, and custom protocol-
        // mappers that pre-date the toggle-on are attested here. Built-in
        // edges (owned by a KC default scope / built-in admin client / the
        // default-roles-<realm> composite) are SKIPPED via the SAME node rules
        // the node scan uses (IgaSystemEntityFilter.shouldSkipEdge) and counted
        // under systemEdgesCounter — never enumerated.
        // ---------------------------------------------------------------------
        // Edge emits run in their OWN child transactions (see processOneEdge),
        // so enumerate them only AFTER all node-ADOPT inserts are staged on the
        // parent transaction. A child-txn edge failure can no longer roll back
        // the node work.
        for (IgaUnsignedRowScanner.EdgeRow e : scanner.compositeRoleEdges(realm.getId())) {
            processOneEdge(session, realm, IgaReplayExtension.ENTITY_TYPE_COMPOSITE_ROLE,
                    IgaReplayExtension.ACTION_ADOPT_COMPOSITE_ROLE, e,
                    requestedBy, includeSystem, committedAdoptByType,
                    created, counters, systemEdgesCounter);
        }
        for (IgaUnsignedRowScanner.EdgeRow e : scanner.clientScopeClientEdges(realm.getId())) {
            processOneEdge(session, realm, IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE_CLIENT,
                    IgaReplayExtension.ACTION_ADOPT_CLIENT_SCOPE_CLIENT, e,
                    requestedBy, includeSystem, committedAdoptByType,
                    created, counters, systemEdgesCounter);
        }
        for (IgaUnsignedRowScanner.EdgeRow e : scanner.clientScopeRoleEdges(realm.getId())) {
            processOneEdge(session, realm, IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE_ROLE,
                    IgaReplayExtension.ACTION_ADOPT_CLIENT_SCOPE_ROLE, e,
                    requestedBy, includeSystem, committedAdoptByType,
                    created, counters, systemEdgesCounter);
        }
        for (IgaUnsignedRowScanner.EdgeRow e : scanner.protocolMapperEdges(realm.getId())) {
            processOneEdge(session, realm, IgaReplayExtension.ENTITY_TYPE_PROTOCOL_MAPPER,
                    IgaReplayExtension.ACTION_ADOPT_PROTOCOL_MAPPER, e,
                    requestedBy, includeSystem, committedAdoptByType,
                    created, counters, systemEdgesCounter);
        }
        // Commit 3 — realm default-scope edges (DEFAULT_CLIENT_SCOPE rows). The
        // EdgeRow's ownerNodeType is CLIENT_SCOPE (the scope decides built-in
        // status), so a row pointing at a KC default scope soft-skips via
        // shouldSkipEdge exactly as the scope node would; the CR/sidecar
        // entity-type is REALM_DEFAULT_SCOPE. In a fresh realm ALL default-scope
        // rows point at built-in scopes → the scan skips ~all of them (expected;
        // only admin-created custom scopes set as realm defaults get adopted).
        for (IgaUnsignedRowScanner.EdgeRow e : scanner.defaultClientScopeEdges(realm.getId())) {
            processOneEdge(session, realm, IgaReplayExtension.ENTITY_TYPE_REALM_DEFAULT_SCOPE,
                    IgaReplayExtension.ACTION_ADOPT_DEFAULT_CLIENT_SCOPE, e,
                    requestedBy, includeSystem, committedAdoptByType,
                    created, counters, systemEdgesCounter);
        }
        // Commit 4 — client scope-mapping edges (SCOPE_MAPPING rows). The
        // EdgeRow's ownerNodeType is CLIENT (the owning client decides built-in
        // status), so a row on a KC bootstrap client (account / broker /
        // realm-management / security-admin-console / ...) soft-skips via
        // shouldSkipEdge exactly as that client node would; the CR/sidecar
        // entity-type is SCOPE_MAPPING. Only admin-authored custom clients with
        // a scope-mapping get adopted.
        for (IgaUnsignedRowScanner.EdgeRow e : scanner.scopeMappingEdges(realm.getId())) {
            processOneEdge(session, realm, IgaReplayExtension.ENTITY_TYPE_SCOPE_MAPPING,
                    IgaReplayExtension.ACTION_ADOPT_SCOPE_MAPPING, e,
                    requestedBy, includeSystem, committedAdoptByType,
                    created, counters, systemEdgesCounter);
        }

        long durationMs = System.currentTimeMillis() - t0;
        // sessionsInvalidated is populated by the toggle-on caller AFTER this
        // scan returns — see ScanResult.withSessionsInvalidated. The scan
        // session has no live UserSessionProvider (fresh runJobInTransaction
        // session bound to its own JPA-only transaction); the caller's
        // request-bound session is the one with sessions().
        ScanResult result = new ScanResult(
                realm.getId(),
                durationMs,
                counters[0],
                created,
                counters[1],
                counters[2],
                counters[3],
                alreadyAttestedCounter[0],
                counters[4],
                0L,
                systemEdgesCounter[0]
        );
        log.infof("IGA toggle-on scan: realm=%s durationMs=%d scanned=%d created=%s "
                        + "skippedSystem=%d skippedCommittedAdopt=%d skippedPendingCreate=%d "
                        + "skippedAlreadyAttested=%d skippedSystemEdges=%d errors=%d",
                realm.getName(), durationMs, counters[0], created, counters[1], counters[2],
                counters[3], alreadyAttestedCounter[0], systemEdgesCounter[0], counters[4]);
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
            //    counters[2] (skippedAlreadyCommittedAdopt) is pre-tallied
            //    from the skip-set size at scan start — see the scan() body
            //    just above the per-type processing loop. We do NOT
            //    increment again here to avoid double-counting the race
            //    case where the scanner surfaces an entity that also lives
            //    in the skip set (entity row's attestation is NULL but its
            //    ADOPT CR is APPROVED). The short-circuit still returns so
            //    we don't emit a duplicate ADOPT CR.
            Set<String> committed = committedAdoptByType.get(entityType);
            if (committed != null && committed.contains(row.entityId())) {
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
     * Commit 2 — per-EDGE processing. Mirrors {@link #processOne} but:
     * <ul>
     *   <li>built-in classification goes through
     *       {@link IgaSystemEntityFilter#shouldSkipEdge} (owning-node rules),
     *       counted under {@code systemEdgesCounter} (surfaced as
     *       {@code skipped.systemEdges});</li>
     *   <li>the already-committed-ADOPT skip keys on the synthetic
     *       {@code key1|key2} entityId (same value the CR + sidecar store);</li>
     *   <li>there is no pending-CREATE race lane for edges (an edge has no
     *       CREATE_* CR of its own — it is created as part of a node CREATE or
     *       a relationship action whose own commit stamps it);</li>
     *   <li>emission goes through {@link IgaChangeRequestService#createAdoptEdgeCr}.</li>
     * </ul>
     * The {@code total scanned} counter (counters[0]) is incremented for edges
     * too, so the response's {@code totalEntitiesScanned} reflects all rows the
     * scan considered (nodes + edges).
     */
    private static void processOneEdge(KeycloakSession scanSession,
                                       RealmModel realm,
                                       String entityType,
                                       String actionType,
                                       IgaUnsignedRowScanner.EdgeRow edge,
                                       String requestedBy,
                                       boolean includeSystem,
                                       Map<String, Set<String>> committedAdoptByType,
                                       Map<String, Long> created,
                                       long[] counters,
                                       long[] systemEdgesCounter) {
        counters[0]++; // total scanned (nodes + edges)
        // FIX (ENTITY_ID overflow): the skip-key MUST be the same deterministic
        // 36-char synthetic id the CR + sidecar store (NOT key1|key2, which is
        // ~73 chars and overflowed VARCHAR(36)). Compute it via the shared
        // helper so this skip lookup matches what createAdoptEdgeCr wrote.
        String syntheticEntityId =
                IgaChangeRequestService.edgeSyntheticId(entityType, edge.key1(), edge.key2());
        // 1. Built-in skip — owning-node classification (NOT a parallel
        //    filter). A composite whose parent is default-roles-<realm>, an
        //    edge owned by a KC default scope, or a mapper on a built-in
        //    admin client is skipped exactly as its node would be.
        if (IgaSystemEntityFilter.shouldSkipEdge(realm, edge.ownerNodeType(),
                edge.ownerNodeName(), edge.ownerParentClientId(), includeSystem)) {
            systemEdgesCounter[0]++;
            log.debugf("IGA scan skip(systemEdge): realm=%s type=%s key1=%s key2=%s ownerType=%s ownerName=%s",
                    realm.getName(), entityType, edge.key1(), edge.key2(),
                    edge.ownerNodeType(), edge.ownerNodeName());
            return;
        }
        // 2. Already-committed ADOPT skip (re-toggle idempotency). Pre-
        //    tallied into counters[2] at scan start (the skip-set size loop
        //    already includes the edge types), so we only short-circuit
        //    here without re-incrementing — matching the node path.
        Set<String> committed = committedAdoptByType.get(entityType);
        if (committed != null && committed.contains(syntheticEntityId)) {
            log.debugf("IGA scan skip(alreadyCommittedAdopt edge): realm=%s type=%s id=%s",
                    realm.getName(), entityType, syntheticEntityId);
            return;
        }
        // 3. Emit the edge ADOPT CR — in its OWN child transaction.
        //
        // FIX (transaction isolation): the node-ADOPT inserts are pending on
        // the parent scan transaction. If an edge INSERT throws (constraint
        // violation, vanished endpoint, …) inside that SAME transaction, the
        // whole transaction — including every node-ADOPT insert — rolls back
        // (the original 11-test regression). We run each edge emit in its own
        // KeycloakModelUtils.runJobInTransaction: a child failure rolls back
        // ONLY that child, the parent node-ADOPT work is untouched. Invariant:
        // node ADOPT behavior is byte-for-byte unchanged whether edges succeed
        // or fail.
        try {
            KeycloakModelUtils.runJobInTransaction(
                    scanSession.getKeycloakSessionFactory(),
                    edgeSession -> {
                        RealmModel edgeRealm = edgeSession.realms().getRealm(realm.getId());
                        if (edgeRealm == null) {
                            throw new IllegalStateException(
                                    "edge ADOPT: realm " + realm.getId() + " not loadable in edge session");
                        }
                        edgeSession.getContext().setRealm(edgeRealm);
                        EntityManager edgeEm =
                                edgeSession.getProvider(JpaConnectionProvider.class).getEntityManager();
                        IgaChangeRequestService edgeCrService =
                                new IgaChangeRequestService(edgeEm, edgeSession);
                        edgeCrService.createAdoptEdgeCr(edgeRealm, entityType,
                                edge.key1(), edge.key2(), actionType, requestedBy);
                    });
            created.merge(entityType, 1L, Long::sum);
        } catch (RuntimeException ex) {
            counters[4]++;
            log.warnf(ex,
                    "IGA scan ERROR on edge realm=%s type=%s key1=%s key2=%s — child txn rolled "
                            + "back, node-ADOPT work preserved; continuing",
                    realm.getName(), entityType, edge.key1(), edge.key2());
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
