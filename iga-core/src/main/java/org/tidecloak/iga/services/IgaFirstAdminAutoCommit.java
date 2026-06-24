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
     * {@code ROWS_JSON} key the toggle-on ADOPT scan writes (value {@code true})
     * when, and only when, the ADOPT target is a SYSTEM/stock-default entity per
     * {@link IgaSystemEntityFilter} ({@code shouldSkip}/{@code shouldSkipEdge}).
     * A system ADOPT CR is "attestation-only" (signs on commit, no quarantine
     * sidecar); an ADOPT CR for a manually-added (admin-authored) entity has NO
     * such marker (it writes a quarantine sidecar). This is the exact, already-
     * persisted classification the sweep needs — we do NOT re-resolve the target
     * to the filter at sweep time; the scan recorded it. See
     * {@code IgaChangeRequestService.createAdoptCr/createAdoptEdgeCr/createAdoptRealmCr}.
     */
    static final String ROWS_KEY_ATTESTATION_ONLY = "ATTESTATION_ONLY";

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
            // ADOPT_* — the toggle-on scan's attestation of pre-existing state. ON THE
            // ALLOW-LIST and, under firstAdmin, ALL auto-committable (sign-at-toggle
            // relaxation 2026-06-24): the whole ADOPT closure (system AND admin-authored)
            // is the firstAdmin's initial attested baseline, committed + signed in one
            // pass at toggle. The ATTESTATION_ONLY=true system marker the scan writes via
            // IgaSystemEntityFilter is STILL read (it drives the quarantine sidecar — a
            // system ADOPT signs without one, an admin-authored ADOPT writes one); it no
            // longer gates auto-commit eligibility. sweep() runs only in firstAdmin mode,
            // so multiAdmin ADOPT sets keep the manual approve/commit flow.
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

            // Realm attribute / config writes (realm-level settings + registration/login).
            "SET_REALM_ATTRIBUTE",
            "REMOVE_REALM_ATTRIBUTE",
            "SET_REALM_CONFIG",

            // Realm default client-scopes (which scope is a realm default — config, not
            // scope creation).
            "REALM_DEFAULT_SCOPE_ADD",
            "REALM_DEFAULT_SCOPE_REMOVE",

            // Realm default groups (which group is a realm default).
            "ADD_REALM_DEFAULT_GROUP",
            "REMOVE_REALM_DEFAULT_GROUP",

            // Default-role composite — ONLY when the parent is default-roles-<realm>
            // AND it stays benign (MF2). See isAutoCommittable.
            "ADD_COMPOSITE",

            // tide-claims scope attach to a SYSTEM/stock client — ON THE ALLOW-LIST but
            // additionally gated PER CR by isSystemTideClaimsAssignScope: only an ASSIGN_SCOPE
            // CR that attaches the tide-claims scope to a built-in client (account, account-
            // console, admin-cli, broker, realm-management, security-admin-console) auto-commits.
            // These are SYSTEM/baseline config filed by IgaSystemProvisioner during provisioning,
            // NOT admin-authored — and they wedge VRK keygen (confirmInitialVRK's "any pending
            // ASSIGN_SCOPE-on-CLIENT" guard) if they linger PENDING. An ASSIGN_SCOPE CR for ANY
            // other scope, or for a CUSTOM (non-built-in) client, stays MANUAL.
            "ASSIGN_SCOPE"

            // DELIBERATELY EXCLUDED (narrowed scope, user correction 2026-06-08): the
            // action types that create ADMIN-AUTHORED custom entities —
            //   CREATE_CLIENT, CREATE_ROLE, CREATE_GROUP, CREATE_CLIENT_SCOPE,
            //   ADD_PROTOCOL_MAPPER, SCOPE_ADD_ROLE, SCOPE_MAPPING_ADD.
            // These stay MANUAL even during firstAdmin (only realm DEFAULTS auto-sign).
            // Stock default entities are normally created IGA-OFF and surface via ADOPT_*
            // (covered above, system-gated); we do NOT special-case a stock entity that an
            // admin happens to create under IGA-on — default to manual. ASSIGN_SCOPE is on the
            // list but TIGHTLY per-CR gated (system client + tide-claims scope only).
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
     * Is this action type an {@code ADOPT_*} action? Local prefix check (the
     * ADOPT family is enumerated in {@code IgaReplayExtension}; every member is
     * prefixed {@code ADOPT_}). Used to apply the system-default per-CR gate.
     */
    static boolean isAdoptAction(String actionType) {
        return actionType != null && actionType.startsWith("ADOPT_");
    }

    /**
     * Per-CR system-default gate for an {@code ADOPT_*} CR. Auto-eligibility
     * requires the ADOPT target to be a SYSTEM/stock-default entity — exactly
     * the entities the toggle-on scan marked {@link #ROWS_KEY_ATTESTATION_ONLY}
     * ({@code = true}) in the CR's {@code ROWS_JSON} (account/account-console,
     * stock realm-management/account/offline_access/uma_authorization roles,
     * stock client scopes + their mappers, the realm/realm-config, the
     * default-roles composite, default groups). An ADOPT CR for a MANUALLY-ADDED
     * (non-system, admin-authored) entity has NO marker → returns false → stays
     * manual.
     *
     * <p>Reads the already-persisted classification rather than re-resolving the
     * target through {@link IgaSystemEntityFilter}: the scan resolved
     * {@code (entityType, entityName, parentClientId)} → {@code shouldSkip} at
     * scan time and stamped the boolean onto the CR, so the sweep is a pure read
     * of the CR's own rows.</p>
     *
     * <p>NOTE (sign-at-toggle relaxation, 2026-06-24): this is NO LONGER the
     * auto-commit gate for ADOPT_* — under firstAdmin ALL ADOPT_* CRs auto-commit
     * (see {@link #isAutoCommittable}). It is retained as the canonical reader of
     * the {@link #ROWS_KEY_ATTESTATION_ONLY} system marker, which still classifies
     * a system vs admin-authored ADOPT for the quarantine sidecar.</p>
     */
    @SuppressWarnings("unused")
    static boolean isSystemDefaultAdopt(IgaChangeRequestEntity cr) {
        if (cr == null) {
            return false;
        }
        String rowsJson = cr.getRowsJson();
        if (rowsJson == null || rowsJson.isBlank()) {
            return false;
        }
        try {
            List<Map<String, Object>> rows = MAPPER.readValue(rowsJson, LIST_MAP_REF);
            if (rows == null) {
                return false;
            }
            for (Map<String, Object> row : rows) {
                if (row == null) continue;
                Object v = row.get(ROWS_KEY_ATTESTATION_ONLY);
                if (Boolean.TRUE.equals(v)
                        || (v != null && "true".equalsIgnoreCase(v.toString()))) {
                    return true;
                }
            }
        } catch (Exception parseFail) {
            log.debugf(parseFail, "IGA firstAdmin auto-commit: failed to parse ADOPT rows for CR %s",
                    cr.getId());
        }
        return false;
    }

    /**
     * Per-CR system gate for an {@code ASSIGN_SCOPE} CR. Auto-eligibility requires BOTH:
     * <ul>
     *   <li>the assigned scope is the Tide-identity {@code tide-claims} scope — matched either by
     *       resolving the CR's {@code SCOPE_ID} to a live {@link org.keycloak.models.ClientScopeModel}
     *       whose name is {@link IgaSystemEntityFilter#TIDE_CLAIMS_SCOPE_NAME}, OR (for the one-pass
     *       provisioning case where the scope's CREATE_CLIENT_SCOPE has not committed yet) the
     *       {@code SCOPE_ID} equals the deterministic tide-claims scope id
     *       ({@link IgaSystemProvisioner#deterministicTideClaimsScopeId}); AND</li>
     *   <li>the target client is a BUILT-IN / stock client
     *       ({@link IgaSystemEntityFilter#BUILTIN_CLIENT_IDS} — account, account-console, admin-cli,
     *       broker, realm-management, security-admin-console), matched on the CR's {@code CLIENT_ID}
     *       (human client id).</li>
     * </ul>
     * Any ASSIGN_SCOPE of a different scope, or onto a custom (non-built-in) client, returns
     * {@code false} → stays MANUAL. These tide-claims-on-system-client assignments are SYSTEM
     * baseline config filed by {@link IgaSystemProvisioner}, not admin-authored; leaving them
     * PENDING wedges VRK keygen ({@code confirmInitialVRK}).
     */
    static boolean isSystemTideClaimsAssignScope(KeycloakSession session, RealmModel realm,
                                                 IgaChangeRequestEntity cr) {
        if (cr == null || realm == null) {
            return false;
        }
        String rowsJson = cr.getRowsJson();
        if (rowsJson == null || rowsJson.isBlank()) {
            return false;
        }
        try {
            List<Map<String, Object>> rows = MAPPER.readValue(rowsJson, LIST_MAP_REF);
            if (rows == null) {
                return false;
            }
            String deterministicTideClaimsId =
                    IgaSystemProvisioner.deterministicTideClaimsScopeId(realm.getId());
            for (Map<String, Object> row : rows) {
                if (row == null) continue;
                Object scopeIdObj = row.get("SCOPE_ID");
                Object clientIdObj = row.get("CLIENT_ID");
                if (scopeIdObj == null || clientIdObj == null) {
                    return false;
                }
                String scopeId = scopeIdObj.toString();
                String clientId = clientIdObj.toString();
                // Client must be a built-in/stock client.
                if (!IgaSystemEntityFilter.BUILTIN_CLIENT_IDS.contains(clientId)) {
                    return false;
                }
                // Scope must be tide-claims: live-resolve by id, else match the deterministic id.
                boolean isTideClaims = deterministicTideClaimsId.equals(scopeId);
                if (!isTideClaims) {
                    var scope = realm.getClientScopeById(scopeId);
                    isTideClaims = scope != null
                            && IgaSystemEntityFilter.TIDE_CLAIMS_SCOPE_NAME.equals(scope.getName());
                }
                if (!isTideClaims) {
                    return false;
                }
            }
            // All rows passed (tide-claims scope onto a built-in client).
            return !rows.isEmpty();
        } catch (Exception parseFail) {
            log.debugf(parseFail, "IGA firstAdmin auto-commit: failed to parse ASSIGN_SCOPE rows for CR %s",
                    cr.getId());
            return false;
        }
    }

    /**
     * Full per-CR auto-commit eligibility decision. A CR is auto-committable iff:
     * <ul>
     *   <li>its action type is on the {@link #BASELINE_CONFIG_ACTION_TYPES} allow-list; AND</li>
     *   <li>if {@code ADOPT_*}: ALWAYS auto-committable under firstAdmin
     *       (sign-at-toggle relaxation, 2026-06-24) — the WHOLE ADOPT closure,
     *       system AND admin-authored, is the firstAdmin's initial attested baseline.
     *       The {@link #ROWS_KEY_ATTESTATION_ONLY} system marker is still read elsewhere
     *       (it drives the quarantine sidecar, not auto-commit eligibility). {@code sweep}
     *       gates the whole pass on firstAdmin mode, so this never relaxes multiAdmin; AND</li>
     *   <li>if {@code ASSIGN_SCOPE}: the assigned scope is {@code tide-claims} AND the target
     *       client is a built-in/stock client ({@link #isSystemTideClaimsAssignScope}). Any other
     *       scope assignment (custom client, or any non-tide-claims scope) stays manual; AND</li>
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
        if (isAdoptAction(actionType)) {
            // firstAdmin relaxation (sign-at-toggle, 2026-06-24): under firstAdmin
            // mode ALL ADOPT_* CRs are auto-committable — admin-authored / non-system
            // entities included, NOT only the system/stock-default ones the toggle-on
            // scan marked ATTESTATION_ONLY. firstAdmin is a 1-of-1 bootstrap signer;
            // the whole ADOPT closure (system + admin-authored) is the realm's initial
            // attested baseline and is committed + signed in one firstAdmin pass at
            // toggle. The ATTESTATION_ONLY / system distinction is PRESERVED everywhere
            // it drives OTHER behavior (the quarantine sidecar: a system ADOPT signs
            // without a quarantine sidecar, an admin-authored ADOPT writes one) — only
            // the AUTO-COMMIT ELIGIBILITY for ADOPT_* is relaxed here. {@code sweep}
            // already gates the whole pass on firstAdmin mode, so this relaxation never
            // applies in multiAdmin (where the manual approve/commit flow governs the
            // ADOPT set). Governed mutations (CREATE_USER / GRANT_ROLES / JOIN_GROUPS /
            // REVOKE_ROLES / …) are NOT ADOPT_* and remain off the allow-list above, so
            // they stay PENDING regardless.
            return true;
        }
        if ("ASSIGN_SCOPE".equals(actionType)) {
            // Only the tide-claims scope onto a built-in/stock client is baseline config; any
            // other scope assignment (custom client / non-tide-claims scope) stays manual.
            if (!isSystemTideClaimsAssignScope(session, realm, cr)) {
                return false;
            }
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
     * delegate to {@code IgaAdminResource.bulkAuthorizeInternal(admin, crIdIn, limit)}
     * (run inside a dedicated {@code runJobInTransaction} for sign-at-toggle rollback
     * scoping) so the sweep reuses the hardened, mutex-guarded {@code processOneCr}
     * engine verbatim (the per-realm {@code IgaBulkLock}, the per-CR PENDING re-check,
     * the {@code stampProducerUnitColumns} producer-column signing, and the
     * {@code convergeAfterCommit} full-closure backfill) without this service taking a
     * compile dependency on the REST resource. A converge ORK-sign failure propagates out
     * of {@code runBulk} so the REST caller's dedicated sweep tx rolls back every APPROVED
     * flip to PENDING (Option 1) without un-enabling IGA.
     */
    @FunctionalInterface
    public interface BulkEngine {
        /**
         * Run the bulk authorize+commit over EXACTLY the PENDING CRs whose id is in
         * {@code crIdIn}. The sweep selects CRs by id (not by action type) because
         * eligibility is decided PER CR — a single action type may hold both eligible
         * and ineligible CRs (e.g. a system {@code ADOPT_CLIENT} vs a manually-added
         * {@code ADOPT_CLIENT}, or a benign vs non-default {@code ADD_COMPOSITE}), so an
         * action-type drain would over-commit. Returns the engine's per-CR results array
         * (each entry a map with at least {@code crId} and {@code status} =
         * COMMITTED/REJECTED/SKIPPED), or an empty list if nothing matched.
         */
        List<Map<String, Object>> runBulk(List<String> crIdIn);
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

        // Per-CR allow-list filter (incl. the ADOPT system-default gate AND the
        // ADD_COMPOSITE default-role + MF2 gate). We collect the exact eligible CR
        // IDS — NOT action types — because the narrowed scope means a single action
        // type can hold both eligible and ineligible CRs (a system ADOPT vs an
        // admin-authored ADOPT; a benign default-role composite vs a non-default
        // composite). Driving the engine by id guarantees an ineligible sibling is
        // never swept in.
        List<String> autoCrIds = new ArrayList<>();
        if (pendingCrs != null) {
            for (IgaChangeRequestEntity cr : pendingCrs) {
                if (isAutoCommittable(session, realm, cr)) {
                    String id = cr.getId();
                    if (id != null && !autoCrIds.contains(id)) {
                        autoCrIds.add(id);
                    }
                }
            }
        }
        int eligible = autoCrIds.size();

        if (autoCrIds.isEmpty()) {
            log.infof("IGA firstAdmin auto-commit: realm %s — no auto-committable baseline-config CRs pending.",
                    realm.getName());
            return SweepResult.ran(0, 0, 0, 0);
        }

        log.infof("IGA firstAdmin auto-commit: realm %s — sweeping %d baseline-config CR(s) by id.",
                realm.getName(), eligible);

        List<Map<String, Object>> results = engine.runBulk(autoCrIds);

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
