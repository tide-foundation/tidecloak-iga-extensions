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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * One-shot toggle-on ADOPT scan.
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
     * Sidecar soft-cap. If at scan-start the realm already has more
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
        /**
         * Count of entities skipped because they already have a PENDING
         * (unsigned, not-yet-committed) ADOPT_X CR. A re-toggle re-runs the
         * full ADOPT scan; an entity that is MISSING its adopt CR is healed
         * (recreated), but an entity that already has a PENDING adopt CR is
         * already signable and MUST NOT get a duplicate second PENDING CR
         * stacked on it. Surfaced under {@code skipped.pendingAdopt}.
         * Analogous to {@link #skippedAlreadyCommittedAdopt} but keyed on
         * status PENDING rather than APPROVED.
         */
        public final long skippedPendingAdopt;
        public final long skippedPendingCreateCr;
        public final long skippedAlreadyAttested;
        public final long errors;
        /**
         * Number of live user sessions invalidated on this
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
        /**
         * The per-entity ADOPT failures behind the {@link #errors} count. Each
         * map is {@code {type, id, error}} (entity type, entity / synthetic-edge
         * id, and a short error string). Best-effort processing CONTINUES past
         * each failure (one poison row must not abort the rest), but the failed
         * entities are now collected here so the toggle response can LIST them in
         * its warnings summary rather than reporting only a count. Always
         * non-null (empty when {@code errors == 0}); an unmodifiable view.
         */
        public final List<Map<String, Object>> failedEntities;

        ScanResult(String realmId, long durationMs, long totalEntitiesScanned,
                   Map<String, Long> adoptCrsCreated, long skippedSystemFilter,
                   long skippedAlreadyCommittedAdopt, long skippedPendingAdopt,
                   long skippedPendingCreateCr,
                   long skippedAlreadyAttested, long errors,
                   long sessionsInvalidated, long skippedSystemEdges,
                   List<Map<String, Object>> failedEntities) {
            this.realmId = realmId;
            this.durationMs = durationMs;
            this.totalEntitiesScanned = totalEntitiesScanned;
            this.adoptCrsCreated = adoptCrsCreated;
            this.skippedSystemFilter = skippedSystemFilter;
            this.skippedAlreadyCommittedAdopt = skippedAlreadyCommittedAdopt;
            this.skippedPendingAdopt = skippedPendingAdopt;
            this.skippedPendingCreateCr = skippedPendingCreateCr;
            this.skippedAlreadyAttested = skippedAlreadyAttested;
            this.errors = errors;
            this.sessionsInvalidated = sessionsInvalidated;
            this.skippedSystemEdges = skippedSystemEdges;
            this.failedEntities = failedEntities == null
                    ? Collections.emptyList()
                    : Collections.unmodifiableList(failedEntities);
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
                    skippedAlreadyCommittedAdopt, skippedPendingAdopt,
                    skippedPendingCreateCr,
                    skippedAlreadyAttested, errors, count, skippedSystemEdges,
                    failedEntities);
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
            skipped.put("pendingAdopt", skippedPendingAdopt);
            skipped.put("pendingCreateCr", skippedPendingCreateCr);
            skipped.put("alreadyAttested", skippedAlreadyAttested);
            skipped.put("systemEdges", skippedSystemEdges);
            m.put("skipped", skipped);
            m.put("errors", errors);
            // The LIST of per-entity failures behind the errors count ({type,
            // id, error} each), so the toggle warnings summary can name the
            // entities that did not adopt rather than only reporting how many.
            m.put("failedEntities", failedEntities);
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
        // InfinispanOrganizationProvider#getRealm guard. This matters whenever
        // users are pre-created with IGA off (the happy/race/already cases).
        session.getContext().setRealm(realm);
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        // Sidecar cap. Reject before doing any work
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
        // start. Uses the IDX_IGA_CR_REALM_ACTION_STATUS index.
        // Includes ORGANIZATION (Map.of caps at 10 entries so we
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

        // Build per-type "already PENDING ADOPT" skip sets ONCE at scan start,
        // exactly like the committed/APPROVED set above but keyed on status
        // PENDING. A re-toggle re-runs the full ADOPT scan; an entity MISSING
        // its adopt CR is healed (recreated), but an entity that already has a
        // PENDING (unsigned, not-yet-committed) adopt CR is already signable —
        // re-emitting would stack a DUPLICATE second PENDING adopt CR on it.
        // Same entity types + the same synthetic-edge id form as
        // committedAdoptByType, so the dedup keys match across re-toggles. The
        // realm-node path (below) already does this APPROVED+PENDING skip
        // inline; nodes and edges did not — this set gives them the parity.
        Map<String, Set<String>> pendingAdoptByType = new LinkedHashMap<>();
        pendingAdoptByType.put(IgaReplayExtension.ENTITY_TYPE_USER,
                queryEntityIdsByCr(em, realm.getId(), IgaReplayExtension.ACTION_ADOPT_USER, "PENDING"));
        pendingAdoptByType.put(IgaReplayExtension.ENTITY_TYPE_ROLE,
                queryEntityIdsByCr(em, realm.getId(), IgaReplayExtension.ACTION_ADOPT_ROLE, "PENDING"));
        pendingAdoptByType.put(IgaReplayExtension.ENTITY_TYPE_GROUP,
                queryEntityIdsByCr(em, realm.getId(), IgaReplayExtension.ACTION_ADOPT_GROUP, "PENDING"));
        pendingAdoptByType.put(IgaReplayExtension.ENTITY_TYPE_CLIENT,
                queryEntityIdsByCr(em, realm.getId(), IgaReplayExtension.ACTION_ADOPT_CLIENT, "PENDING"));
        pendingAdoptByType.put(IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE,
                queryEntityIdsByCr(em, realm.getId(), IgaReplayExtension.ACTION_ADOPT_CLIENT_SCOPE, "PENDING"));
        pendingAdoptByType.put(IgaReplayExtension.ENTITY_TYPE_ORGANIZATION,
                queryEntityIdsByCr(em, realm.getId(), IgaReplayExtension.ACTION_ADOPT_ORGANIZATION, "PENDING"));
        // Edge entity types — synthetic (key1|key2) id form, same as the
        // committed set, so the PENDING skip keys match what createAdoptEdgeCr wrote.
        pendingAdoptByType.put(IgaReplayExtension.ENTITY_TYPE_COMPOSITE_ROLE,
                queryEntityIdsByCr(em, realm.getId(), IgaReplayExtension.ACTION_ADOPT_COMPOSITE_ROLE, "PENDING"));
        pendingAdoptByType.put(IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE_CLIENT,
                queryEntityIdsByCr(em, realm.getId(), IgaReplayExtension.ACTION_ADOPT_CLIENT_SCOPE_CLIENT, "PENDING"));
        pendingAdoptByType.put(IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE_ROLE,
                queryEntityIdsByCr(em, realm.getId(), IgaReplayExtension.ACTION_ADOPT_CLIENT_SCOPE_ROLE, "PENDING"));
        pendingAdoptByType.put(IgaReplayExtension.ENTITY_TYPE_PROTOCOL_MAPPER,
                queryEntityIdsByCr(em, realm.getId(), IgaReplayExtension.ACTION_ADOPT_PROTOCOL_MAPPER, "PENDING"));
        pendingAdoptByType.put(IgaReplayExtension.ENTITY_TYPE_REALM_DEFAULT_SCOPE,
                queryEntityIdsByCr(em, realm.getId(), IgaReplayExtension.ACTION_ADOPT_DEFAULT_CLIENT_SCOPE, "PENDING"));
        pendingAdoptByType.put(IgaReplayExtension.ENTITY_TYPE_SCOPE_MAPPING,
                queryEntityIdsByCr(em, realm.getId(), IgaReplayExtension.ACTION_ADOPT_SCOPE_MAPPING, "PENDING"));

        // Build per-type "pending CREATE_*" race skip sets. CREATE actions
        // are literal strings (no central constants in the IgaReplayExtension
        // surface today — see IgaGroupAdapter / IgaUserProvider / etc).
        // Includes CREATE_ORGANIZATION (the literal action type emitted
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
        created.put(IgaReplayExtension.ENTITY_TYPE_REALM, 0L);
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
        // PENDING-ADOPT dedup skips. Counted at the per-entity short-circuit
        // (NOT pre-tallied like the committed/APPROVED set): a PENDING adopt CR
        // does NOT stamp the entity's attestation, so the scanner's
        // attestation-IS-NULL filter still surfaces these rows and the skip
        // fires in processOne/processOneEdge. Surfaced under skipped.pendingAdopt.
        long[] pendingAdoptCounter = new long[1];
        // Best-effort failure LIST behind counters[4] (errors): every per-entity
        // catch (node / realm-node / edge) appends a {type, id, error} descriptor
        // here AND increments counters[4]. The two stay in lockstep so the
        // ScanResult.errors count and the failedEntities list agree. The list is
        // surfaced in the toggle warnings summary so the admin can see WHICH
        // entities failed, not just how many.
        List<Map<String, Object>> failedEntities = new ArrayList<>();

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
                    requestedBy, includeSystem, committedAdoptByType, pendingAdoptByType,
                    pendingCreateByType,
                    created, counters, alreadyAttestedCounter, pendingAdoptCounter, failedEntities);
        }
        for (IgaUnsignedRowScanner.InfoRow row : scanner.rolesWithNames(realm.getId())) {
            processOne(crService, realm, IgaReplayExtension.ENTITY_TYPE_ROLE, row, row.parentClientId(),
                    requestedBy, includeSystem, committedAdoptByType, pendingAdoptByType,
                    pendingCreateByType,
                    created, counters, alreadyAttestedCounter, pendingAdoptCounter, failedEntities);
        }
        for (IgaUnsignedRowScanner.InfoRow row : scanner.groupsWithNames(realm.getId())) {
            processOne(crService, realm, IgaReplayExtension.ENTITY_TYPE_GROUP, row, null,
                    requestedBy, includeSystem, committedAdoptByType, pendingAdoptByType,
                    pendingCreateByType,
                    created, counters, alreadyAttestedCounter, pendingAdoptCounter, failedEntities);
        }
        for (IgaUnsignedRowScanner.InfoRow row : scanner.clientsWithNames(realm.getId())) {
            processOne(crService, realm, IgaReplayExtension.ENTITY_TYPE_CLIENT, row, null,
                    requestedBy, includeSystem, committedAdoptByType, pendingAdoptByType,
                    pendingCreateByType,
                    created, counters, alreadyAttestedCounter, pendingAdoptCounter, failedEntities);
        }
        for (IgaUnsignedRowScanner.InfoRow row : scanner.clientScopesWithNames(realm.getId())) {
            processOne(crService, realm, IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE, row, null,
                    requestedBy, includeSystem, committedAdoptByType, pendingAdoptByType,
                    pendingCreateByType,
                    created, counters, alreadyAttestedCounter, pendingAdoptCounter, failedEntities);
        }
        // Orgs. The org is a first-class NODE in the attested
        // set; the scanner enumerates only UNSIGNED orgs (the
        // organizationsWithNames query carries the same `attestation IS NULL`
        // filter as every other node lane, against the ORG.ATTESTATION column
        // added by iga-changelog-2.4.0 — see
        // IgaUnsignedRowScanner.organizationsWithNames). The
        // committedAdoptByType skip-set is a second, CR-level "already
        // governed" defence; the pendingCreateByType skip-set covers a
        // mid-flight CREATE_ORGANIZATION CR's target. IgaSystemEntityFilter has no
        // ORGANIZATION rules today (no built-in/default orgs in stock KC),
        // so shouldSkip returns false for every entity-type-mismatched
        // branch — i.e. the filter is a no-op for orgs by design. If KC
        // ever introduces a default "platform" org we'll add the rule then;
        // for now an explicit skip would be invented complexity.
        for (IgaUnsignedRowScanner.InfoRow row : scanner.organizationsWithNames(realm.getId())) {
            processOne(crService, realm, IgaReplayExtension.ENTITY_TYPE_ORGANIZATION, row, null,
                    requestedBy, includeSystem, committedAdoptByType, pendingAdoptByType,
                    pendingCreateByType,
                    created, counters, alreadyAttestedCounter, pendingAdoptCounter, failedEntities);
        }

        // ---------------------------------------------------------------------
        // Manual-signing redesign — REALM NODE attestation-only ADOPT CR. The realm
        // contributes two login-emitted producer units (realm_config #0,
        // realm_default_groups_set #15) keyed on the realmId. They have no per-entity
        // scanner row (the realm is not an "info" entity), so emit exactly one
        // attestation-only ADOPT_REALM CR per scan, idempotently: skip if an APPROVED or
        // PENDING ADOPT_REALM CR already exists for this realm (re-toggle safety).
        // ---------------------------------------------------------------------
        try {
            counters[0]++; // total scanned (the realm node)
            boolean realmAlreadyHasAdopt =
                    !queryEntityIdsByCr(em, realm.getId(), IgaReplayExtension.ACTION_ADOPT_REALM, "APPROVED").isEmpty()
                            || !queryEntityIdsByCr(em, realm.getId(), IgaReplayExtension.ACTION_ADOPT_REALM, "PENDING").isEmpty();
            if (realmAlreadyHasAdopt) {
                log.debugf("IGA scan skip(realmAlreadyAdopt): realm=%s", realm.getName());
            } else {
                crService.createAdoptRealmCr(realm, requestedBy);
                created.merge(IgaReplayExtension.ENTITY_TYPE_REALM, 1L, Long::sum);
            }
        } catch (RuntimeException ex) {
            counters[4]++;
            failedEntities.add(failure(IgaReplayExtension.ENTITY_TYPE_REALM, realm.getId(), ex));
            log.warnf(ex, "IGA scan ERROR on realm-node ADOPT realm=%s — continuing", realm.getName());
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
                    requestedBy, includeSystem, committedAdoptByType, pendingAdoptByType,
                    created, counters, systemEdgesCounter, pendingAdoptCounter, failedEntities);
        }
        for (IgaUnsignedRowScanner.EdgeRow e : scanner.clientScopeClientEdges(realm.getId())) {
            processOneEdge(session, realm, IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE_CLIENT,
                    IgaReplayExtension.ACTION_ADOPT_CLIENT_SCOPE_CLIENT, e,
                    requestedBy, includeSystem, committedAdoptByType, pendingAdoptByType,
                    created, counters, systemEdgesCounter, pendingAdoptCounter, failedEntities);
        }
        for (IgaUnsignedRowScanner.EdgeRow e : scanner.clientScopeRoleEdges(realm.getId())) {
            processOneEdge(session, realm, IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE_ROLE,
                    IgaReplayExtension.ACTION_ADOPT_CLIENT_SCOPE_ROLE, e,
                    requestedBy, includeSystem, committedAdoptByType, pendingAdoptByType,
                    created, counters, systemEdgesCounter, pendingAdoptCounter, failedEntities);
        }
        for (IgaUnsignedRowScanner.EdgeRow e : scanner.protocolMapperEdges(realm.getId())) {
            processOneEdge(session, realm, IgaReplayExtension.ENTITY_TYPE_PROTOCOL_MAPPER,
                    IgaReplayExtension.ACTION_ADOPT_PROTOCOL_MAPPER, e,
                    requestedBy, includeSystem, committedAdoptByType, pendingAdoptByType,
                    created, counters, systemEdgesCounter, pendingAdoptCounter, failedEntities);
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
                    requestedBy, includeSystem, committedAdoptByType, pendingAdoptByType,
                    created, counters, systemEdgesCounter, pendingAdoptCounter, failedEntities);
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
                    requestedBy, includeSystem, committedAdoptByType, pendingAdoptByType,
                    created, counters, systemEdgesCounter, pendingAdoptCounter, failedEntities);
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
                pendingAdoptCounter[0],
                counters[3],
                alreadyAttestedCounter[0],
                counters[4],
                0L,
                systemEdgesCounter[0],
                failedEntities
        );
        log.infof("IGA toggle-on scan: realm=%s durationMs=%d scanned=%d created=%s "
                        + "skippedSystem=%d skippedCommittedAdopt=%d skippedPendingAdopt=%d "
                        + "skippedPendingCreate=%d "
                        + "skippedAlreadyAttested=%d skippedSystemEdges=%d errors=%d",
                realm.getName(), durationMs, counters[0], created, counters[1], counters[2],
                pendingAdoptCounter[0], counters[3], alreadyAttestedCounter[0],
                systemEdgesCounter[0], counters[4]);
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
                                    Map<String, Set<String>> pendingAdoptByType,
                                    Map<String, Set<String>> pendingCreateByType,
                                    Map<String, Long> created,
                                    long[] counters,
                                    long[] alreadyAttestedCounter,
                                    long[] pendingAdoptCounter,
                                    List<Map<String, Object>> failedEntities) {
        counters[0]++; // total scanned
        try {
            // 1. System-entity classification. The manual-signing redesign (2026-06-06)
            //    NO LONGER skips system entities outright: the uniform login read is
            //    all-or-nothing, so every login-emitted unit (incl. the built-in admin
            //    clients + their roles, KC default scopes, default/composite realm roles)
            //    must carry a signed producer column or the login fail-closes. System
            //    entities therefore still get an ADOPT CR — but an ATTESTATION-ONLY one:
            //    committing it stamps the entity's producer column(s) WITHOUT writing the
            //    IGA_UNSIGNED_ENTITY sidecar, so the entity is signed but NEVER quarantined
            //    (quarantining a built-in admin client / default scope / system role would
            //    brick KC internals + the surface used to commit CRs). counters[1]
            //    (skipped.systemFilter) now counts attestation-only system CRs for
            //    observability.
            boolean attestationOnly = IgaSystemEntityFilter.shouldSkip(realm, entityType,
                    row.entityId(), row.entityName(), parentClientId, includeSystem);
            if (attestationOnly) {
                counters[1]++;
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
            // 2b. Already-PENDING ADOPT skip (re-toggle dedup). The entity
            //     already has an unsigned, not-yet-committed ADOPT CR — it is
            //     already signable, so short-circuit WITHOUT creating a
            //     duplicate second PENDING adopt CR. Unlike the APPROVED set
            //     this IS counted here (a PENDING adopt CR does not stamp the
            //     entity's attestation, so the scanner still surfaces the row).
            Set<String> pendingAdopt = pendingAdoptByType.get(entityType);
            if (pendingAdopt != null && pendingAdopt.contains(row.entityId())) {
                pendingAdoptCounter[0]++;
                log.debugf("IGA scan skip(pendingAdopt): realm=%s type=%s id=%s",
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
            //    rows) but we defensively catch it for symmetry. System
            //    entities (attestationOnly=true) get a CR that signs without
            //    a quarantine sidecar.
            crService.createAdoptCr(realm, entityType, row.entityId(), requestedBy, attestationOnly);
            created.merge(entityType, 1L, Long::sum);
        } catch (IgaChangeRequestService.AlreadyAttestedException aae) {
            alreadyAttestedCounter[0]++;
            log.debugf("IGA scan skip(alreadyAttested): realm=%s type=%s id=%s",
                    realm.getName(), entityType, row.entityId());
        } catch (RuntimeException ex) {
            counters[4]++;
            failedEntities.add(failure(entityType, row.entityId(), ex));
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
                                       Map<String, Set<String>> pendingAdoptByType,
                                       Map<String, Long> created,
                                       long[] counters,
                                       long[] systemEdgesCounter,
                                       long[] pendingAdoptCounter,
                                       List<Map<String, Object>> failedEntities) {
        counters[0]++; // total scanned (nodes + edges)
        // FIX (ENTITY_ID overflow): the skip-key MUST be the same deterministic
        // 36-char synthetic id the CR + sidecar store (NOT key1|key2, which is
        // ~73 chars and overflowed VARCHAR(36)). Compute it via the shared
        // helper so this skip lookup matches what createAdoptEdgeCr wrote.
        String syntheticEntityId =
                IgaChangeRequestService.edgeSyntheticId(entityType, edge.key1(), edge.key2());
        // 1. Built-in classification — owning-node rules (NOT a parallel filter). A
        //    composite whose parent is default-roles-<realm>, an edge owned by a KC
        //    default scope, or a mapper on a built-in admin client is classified exactly
        //    as its node would be. Per the manual-signing redesign these are NO LONGER
        //    skipped: a built-in edge that contributes to the login closure (notably a
        //    PROTOCOL_MAPPER on a built-in admin client / default scope — its
        //    protocol_mapper unit IS emitted at login) gets an ATTESTATION-ONLY edge CR
        //    (signs on commit, no quarantine sidecar). systemEdgesCounter still counts
        //    them for observability.
        boolean attestationOnly = IgaSystemEntityFilter.shouldSkipEdge(realm, edge.ownerNodeType(),
                edge.ownerNodeName(), edge.ownerParentClientId(), includeSystem);
        if (attestationOnly) {
            systemEdgesCounter[0]++;
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
        // 2b. Already-PENDING ADOPT skip (re-toggle dedup). Keyed on the SAME
        //     synthetic (key1|key2) entityId the CR + sidecar store, so the
        //     dedup matches what createAdoptEdgeCr wrote. Counted here (a
        //     PENDING edge adopt CR does not stamp the edge attestation, so the
        //     scanner still surfaces it), mirroring the node path.
        Set<String> pendingAdopt = pendingAdoptByType.get(entityType);
        if (pendingAdopt != null && pendingAdopt.contains(syntheticEntityId)) {
            pendingAdoptCounter[0]++;
            log.debugf("IGA scan skip(pendingAdopt edge): realm=%s type=%s id=%s",
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
                                edge.key1(), edge.key2(), actionType, requestedBy, attestationOnly);
                    });
            created.merge(entityType, 1L, Long::sum);
        } catch (RuntimeException ex) {
            counters[4]++;
            failedEntities.add(failure(entityType, syntheticEntityId, ex));
            log.warnf(ex,
                    "IGA scan ERROR on edge realm=%s type=%s key1=%s key2=%s — child txn rolled "
                            + "back, node-ADOPT work preserved; continuing",
                    realm.getName(), entityType, edge.key1(), edge.key2());
        }
    }

    /**
     * Build one {@code {type, id, error}} failure descriptor for the
     * best-effort failedEntities list. {@code error} is the exception simple
     * name plus its message, kept short and serializable for the toggle
     * warnings summary. Never throws.
     */
    private static Map<String, Object> failure(String entityType, String entityId, Throwable ex) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("type", entityType);
        m.put("id", entityId);
        m.put("error", ex == null
                ? "unknown"
                : ex.getClass().getSimpleName() + ": " + ex.getMessage());
        return m;
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
