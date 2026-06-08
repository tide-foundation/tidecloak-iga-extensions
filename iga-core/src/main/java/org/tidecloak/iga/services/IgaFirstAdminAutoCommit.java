package org.tidecloak.iga.services;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.tidecloak.iga.attestors.TideAttestor;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;

/**
 * firstAdmin baseline-config auto-commit sweep (Option A).
 *
 * <p>On a fresh realm while it is still in <b>firstAdmin</b> mode, the
 * default/baseline settings &amp; configuration captured as PENDING change
 * requests during provisioning should be auto-approved + auto-committed instead
 * of waiting for the firstAdmin to manually {@code authorize} then {@code commit}
 * each one. firstAdmin is a 1-of-1 single-signer bootstrap (the approver-role
 * check is bypassed and the threshold is hardcoded to 1 — see
 * {@code TideAttestor.getThreshold} and {@code IgaScopeResolver.requireApprover}),
 * so the only thing standing between a baseline-config CR and its commit is two
 * manual REST round-trips. This sweep removes them for the baseline-config subset
 * ONLY; everything else (user creation, role grants, privileged composites) stays
 * PENDING for the normal manual / governed flow.</p>
 *
 * <h2>Two gates (both must hold or the sweep is a no-op)</h2>
 * <ol>
 *   <li><b>firstAdmin gate</b> — {@link TideAttestor#isFirstAdminMode}. Once the
 *       realm flips to multiAdmin (the first {@code tide-realm-admin} grant rewrites
 *       {@code IGA_AUTHORIZER.MODE} atomically), this returns false and the sweep
 *       does nothing — the normal manual approval flow resumes unchanged.</li>
 *   <li><b>VRK-active gate</b> — {@link TideAttestor#isRealSigningCapableRealm}.
 *       This is the SAME signer-active probe the firstAdmin commit's producer-column
 *       stamp path uses ({@code TideAttestor.signProducerEnvelope}'s
 *       {@code MODE_FIRST_ADMIN && isRealSigningCapable} branch). If the firstAdmin
 *       VRK pack is NOT active, the sweep is SKIPPED entirely (the CRs stay PENDING
 *       for later manual / auto handling) — we never produce stub stamps and never
 *       let a commit fail-closed / rollback mid-sweep on a realm that cannot really
 *       sign.</li>
 * </ol>
 *
 * <h2>Allow-list, never deny-list</h2>
 * The set of auto-committable action types is an explicit ALLOW-LIST
 * ({@link #BASELINE_CONFIG_ACTION_TYPES}). An unknown / unlisted action type is
 * treated as governed → it stays PENDING. The privileged actions (user creation,
 * role grants/revokes, group membership, org membership) are deliberately excluded
 * so an unsigned firstAdmin can never auto-confer privilege.
 *
 * <h2>MF2 — default-role composite guard</h2>
 * An {@code ADD_COMPOSITE} CR is auto-committable ONLY when its composite PARENT is
 * the realm default-role ({@code default-roles-<realm>}) AND the resulting composite
 * is still benign per {@link DefaultRoleCompositeGuard}. A composite whose parent is
 * any other role is NOT baseline config (stays PENDING); a default-role composite
 * that introduces a privileged child ({@code realm-management} / {@code tide-realm-admin}
 * / {@code realm-admin}) fails the MF2 guard and is NOT auto-committed — it stays
 * PENDING and fail-closes exactly as the login closure would.
 *
 * <p>The sweep itself reuses the hardened, mutex-guarded bulk authorize+commit engine
 * ({@code IgaAdminResource.bulkAuthorize} → {@code processOneCr}) verbatim via an
 * injected {@link BulkEngine} — it does NOT reinvent authorize/commit/replay. The
 * engine re-checks PENDING-state per CR inside its transaction, and this class layers
 * a commit-time {@code isFirstAdminMode} re-check (defense in depth) so a CR lingering
 * across the flip is never auto-committed post-flip.</p>
 */
public final class IgaFirstAdminAutoCommit {

    private static final Logger log = Logger.getLogger(IgaFirstAdminAutoCommit.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<List<Map<String, Object>>> LIST_MAP_REF =
            new TypeReference<List<Map<String, Object>>>() {};

    /** {@code ROWS_JSON} key carrying the {@code ADD_COMPOSITE} parent role id. */
    private static final String ROWS_KEY_COMPOSITE_PARENT = "COMPOSITE";

    /**
     * The baseline / default configuration action types that are safe to
     * auto-commit while the realm is in firstAdmin mode.
     *
     * <p>ALLOW-LIST (authoritative + auditable in one place). Anything NOT in this
     * set — most importantly {@code CREATE_USER}, {@code GRANT_ROLES},
     * {@code REVOKE_ROLES}, {@code JOIN_GROUPS}, {@code LEAVE_GROUPS},
     * {@code ADD_ORG_MEMBER} — is governed and stays PENDING. {@code ADD_COMPOSITE}
     * is in the list but additionally gated by {@link #isDefaultRoleComposite}
     * + the MF2 {@link DefaultRoleCompositeGuard} (see {@link #isAutoCommittable}):
     * only a benign default-role composite qualifies.</p>
     *
     * <p>Action-type strings are verified verbatim against the replay dispatcher
     * switch ({@code IgaReplayDispatcher.doReplay}) and the ADOPT family
     * ({@code IgaReplayExtension}).</p>
     */
    public static final Set<String> BASELINE_CONFIG_ACTION_TYPES = Set.of(
            // ADOPT_* — the toggle-on scan's attestation of pre-existing baseline state.
            "ADOPT_REALM",
            "ADOPT_ROLE",
            "ADOPT_GROUP",
            "ADOPT_CLIENT",
            "ADOPT_CLIENT_SCOPE",
            "ADOPT_ORGANIZATION",
            "ADOPT_COMPOSITE_ROLE",
            "ADOPT_CLIENT_SCOPE_CLIENT",
            "ADOPT_CLIENT_SCOPE_ROLE",
            "ADOPT_PROTOCOL_MAPPER",
            "ADOPT_DEFAULT_CLIENT_SCOPE",
            "ADOPT_SCOPE_MAPPING",

            // Realm attribute / config writes (baseline realm settings).
            "SET_REALM_ATTRIBUTE",
            "REMOVE_REALM_ATTRIBUTE",
            "SET_REALM_CONFIG",

            // Default client-scope assignment to the realm.
            "REALM_DEFAULT_SCOPE_ADD",
            "REALM_DEFAULT_SCOPE_REMOVE",

            // Client-scope creation + default/optional assignment to clients.
            "CREATE_CLIENT_SCOPE",
            "ASSIGN_SCOPE",
            "SCOPE_ADD_ROLE",
            "SCOPE_MAPPING_ADD",

            // Client + role + group structural creation.
            "CREATE_CLIENT",
            "CREATE_ROLE",
            "CREATE_GROUP",

            // Protocol mappers (baseline token-shaping config).
            "ADD_PROTOCOL_MAPPER",

            // Realm default groups.
            "ADD_REALM_DEFAULT_GROUP",
            "REMOVE_REALM_DEFAULT_GROUP",

            // Default-role composite — ONLY when the parent is default-roles-<realm>
            // AND it stays benign (MF2). See isAutoCommittable.
            "ADD_COMPOSITE"
    );

    private IgaFirstAdminAutoCommit() {
    }

    /**
     * Pure allow-list membership test for an action-type string. An unknown /
     * unlisted action type is NOT baseline config (governed → stays PENDING).
     */
    public static boolean isBaselineConfigActionType(String actionType) {
        return actionType != null && BASELINE_CONFIG_ACTION_TYPES.contains(actionType);
    }

    /**
     * Is this {@code ADD_COMPOSITE} CR a composite whose PARENT is the realm
     * default-role ({@code default-roles-<realm>})? The parent role id lives in the
     * CR's {@code ROWS_JSON} under the {@code COMPOSITE} key (the same key the
     * replay dispatcher reads in {@code addCompositeDirect}). Returns false for any
     * other composite (those are not baseline config).
     */
    static boolean isDefaultRoleComposite(KeycloakSession session, RealmModel realm,
                                          IgaChangeRequestEntity cr) {
        if (cr == null || realm == null) {
            return false;
        }
        RoleModel defaultRole = realm.getDefaultRole();
        if (defaultRole == null || defaultRole.getId() == null) {
            return false;
        }
        String parentRoleId = compositeParentRoleId(cr);
        return defaultRole.getId().equals(parentRoleId);
    }

    /** Extract the {@code COMPOSITE} (parent role id) from an ADD_COMPOSITE CR's rows. */
    private static String compositeParentRoleId(IgaChangeRequestEntity cr) {
        String rowsJson = cr.getRowsJson();
        if (rowsJson == null || rowsJson.isBlank()) {
            return null;
        }
        try {
            List<Map<String, Object>> rows = MAPPER.readValue(rowsJson, LIST_MAP_REF);
            if (rows == null) {
                return null;
            }
            for (Map<String, Object> row : rows) {
                if (row == null) continue;
                Object v = row.get(ROWS_KEY_COMPOSITE_PARENT);
                if (v != null) {
                    return v.toString();
                }
            }
        } catch (Exception parseFail) {
            log.debugf(parseFail, "IGA firstAdmin auto-commit: failed to parse ADD_COMPOSITE rows for CR %s",
                    cr.getId());
        }
        return null;
    }

    /**
     * Full per-CR auto-commit eligibility decision. A CR is auto-committable iff:
     * <ul>
     *   <li>its action type is on the {@link #BASELINE_CONFIG_ACTION_TYPES} allow-list; AND</li>
     *   <li>if {@code ADD_COMPOSITE}: its parent is the realm default-role AND the
     *       resulting default-role composite is still benign per
     *       {@link DefaultRoleCompositeGuard} (MF2 fail-closed — a privileged child
     *       leaves the CR governed/PENDING).</li>
     * </ul>
     */
    public static boolean isAutoCommittable(KeycloakSession session, RealmModel realm,
                                            IgaChangeRequestEntity cr) {
        if (cr == null) {
            return false;
        }
        String actionType = cr.getActionType();
        if (!isBaselineConfigActionType(actionType)) {
            return false;
        }
        if ("ADD_COMPOSITE".equals(actionType)) {
            // Only a default-role composite is baseline config...
            if (!isDefaultRoleComposite(session, realm, cr)) {
                return false;
            }
            // ...and only while the default-role composite is benign (MF2 fail-closed).
            if (!DefaultRoleCompositeGuard.isBenignDefaultRoleComposite(realm)) {
                log.warnf("IGA firstAdmin auto-commit: ADD_COMPOSITE CR %s on the default-role of "
                        + "realm %s is NOT auto-committed — the default-role composite is non-benign "
                        + "(MF2 guard). It stays PENDING for governed handling.", cr.getId(), realm.getName());
                return false;
            }
        }
        return true;
    }

    /**
     * The injected authorize+commit engine. Implemented by the REST layer as a thin
     * delegate to {@code IgaAdminResource.bulkAuthorize(actionTypeIn=...)} so the sweep
     * reuses the hardened, mutex-guarded {@code processOneCr} engine verbatim (the
     * per-realm {@code IgaBulkLock}, the per-CR PENDING re-check, the
     * {@code stampProducerUnitColumns} producer-column signing, and the
     * {@code convergeAfterCommit} full-closure backfill) without this service taking a
     * compile dependency on the REST resource.
     */
    @FunctionalInterface
    public interface BulkEngine {
        /**
         * Run the bulk authorize+commit over the PENDING CRs whose action type is in
         * {@code actionTypeIn}. Returns the engine's per-CR results array (each entry a
         * map with at least {@code crId} and {@code status} = COMMITTED/REJECTED/SKIPPED),
         * or an empty list if nothing matched.
         */
        List<Map<String, Object>> runBulk(List<String> actionTypeIn);
    }

    /** Outcome summary for the toggle response + logging. */
    public static final class SweepResult {
        public final boolean ran;
        public final String skipReason;     // null when ran
        public final int eligible;          // CRs that passed isAutoCommittable
        public final int committed;
        public final int rejected;
        public final int skipped;

        private SweepResult(boolean ran, String skipReason, int eligible,
                            int committed, int rejected, int skipped) {
            this.ran = ran;
            this.skipReason = skipReason;
            this.eligible = eligible;
            this.committed = committed;
            this.rejected = rejected;
            this.skipped = skipped;
        }

        static SweepResult skipped(String reason) {
            return new SweepResult(false, reason, 0, 0, 0, 0);
        }

        static SweepResult ran(int eligible, int committed, int rejected, int skipped) {
            return new SweepResult(true, null, eligible, committed, rejected, skipped);
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ran", ran);
            if (skipReason != null) m.put("skipReason", skipReason);
            m.put("eligible", eligible);
            m.put("committed", committed);
            m.put("rejected", rejected);
            m.put("skipped", skipped);
            return m;
        }
    }

    /**
     * Run the firstAdmin baseline-config auto-commit sweep.
     *
     * <p>No-op (returns {@link SweepResult#skipped}) unless BOTH gates hold:
     * the realm is in firstAdmin mode ({@link TideAttestor#isFirstAdminMode}) AND the
     * firstAdmin VRK pack is active ({@link TideAttestor#isRealSigningCapableRealm}).
     * When it runs, it computes the auto-committable allow-list subset of the realm's
     * PENDING action types (filtered per-CR by {@link #isAutoCommittable}, so a tainted
     * default-role composite never enters the bulk request), then drives the injected
     * {@link BulkEngine} over exactly those action types.</p>
     *
     * <p>The {@code admin} is the firstAdmin user the engine signs on behalf of (the
     * bulk endpoint's {@code currentUser}). The {@code pendingCrSupplier} yields the
     * realm's PENDING CRs to classify; the REST caller passes
     * {@code IgaChangeRequestService.listPending...}.</p>
     */
    public static SweepResult sweep(KeycloakSession session, RealmModel realm, UserModel admin,
                                    List<IgaChangeRequestEntity> pendingCrs, BulkEngine engine) {
        // Gate 1 — firstAdmin only. Post-flip (multiAdmin) this is a no-op.
        if (!TideAttestor.isFirstAdminMode(session, realm)) {
            log.debugf("IGA firstAdmin auto-commit: realm %s is not in firstAdmin mode — sweep is a no-op.",
                    realm.getName());
            return SweepResult.skipped("NOT_FIRST_ADMIN");
        }
        // Gate 2 — VRK active. If the firstAdmin signer is not active, SKIP entirely
        // (leave the CRs PENDING). Never stub-stamp, never fail-closed mid-sweep.
        if (!TideAttestor.isRealSigningCapableRealm(realm)) {
            log.infof("IGA firstAdmin auto-commit: realm %s VRK not active — baseline-config sweep SKIPPED; "
                    + "the baseline CRs remain PENDING for later (manual/auto) handling.", realm.getName());
            return SweepResult.skipped("VRK_NOT_ACTIVE");
        }

        // Per-CR allow-list filter (incl. the ADD_COMPOSITE default-role + MF2 gate),
        // collapsed to the distinct action-type set the engine is driven over.
        List<String> autoActionTypes = new ArrayList<>();
        int eligible = 0;
        if (pendingCrs != null) {
            for (IgaChangeRequestEntity cr : pendingCrs) {
                if (isAutoCommittable(session, realm, cr)) {
                    eligible++;
                    String at = cr.getActionType();
                    if (!autoActionTypes.contains(at)) {
                        autoActionTypes.add(at);
                    }
                }
            }
        }

        if (autoActionTypes.isEmpty()) {
            log.infof("IGA firstAdmin auto-commit: realm %s — no auto-committable baseline-config CRs pending.",
                    realm.getName());
            return SweepResult.ran(0, 0, 0, 0);
        }

        log.infof("IGA firstAdmin auto-commit: realm %s — sweeping %d baseline-config CR(s) across action types %s.",
                realm.getName(), eligible, autoActionTypes);

        List<Map<String, Object>> results = engine.runBulk(autoActionTypes);

        int committed = 0, rejected = 0, skipped = 0;
        if (results != null) {
            for (Map<String, Object> r : results) {
                String status = r == null ? null : String.valueOf(r.get("status"));
                if ("COMMITTED".equals(status)) committed++;
                else if ("REJECTED".equals(status)) rejected++;
                else skipped++;
            }
        }
        log.infof("IGA firstAdmin auto-commit: realm %s — sweep done: committed=%d rejected=%d skipped=%d (eligible=%d).",
                realm.getName(), committed, rejected, skipped, eligible);
        return SweepResult.ran(eligible, committed, rejected, skipped);
    }
}
