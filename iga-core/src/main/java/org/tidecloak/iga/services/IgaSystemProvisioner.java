package org.tidecloak.iga.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.providers.IgaChangeRequestService;
import org.tidecloak.iga.replay.IgaReplayExtension;

import jakarta.persistence.EntityManager;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * State-aware, idempotent auto-enqueuer for the {@code tide-claims} client
 * scope (+ {@code t.uho} mapper) provisioning chain on IGA-ON realms.
 *
 * <p>Invoked on server start (by the idp-extensions startup hook) once per
 * IGA-enabled realm. Files the PENDING change requests needed to (1) create
 * the {@code tide-claims} client scope with its inline {@code t.uho} mapper,
 * (2) wire it as a realm-default scope, and (3) attach it to every existing
 * client that lacks it. The chain is governed exactly like any other admin
 * mutation — nothing applies until an admin commits each CR.</p>
 *
 * <h3>Why a CR chain rather than a direct write</h3>
 * On an IGA-ON realm a direct {@code realm.addClientScope(...)} would itself
 * be captured into a CR (or, worse, suppressed). We instead file the CRs
 * explicitly so the operator sees and approves the provisioning the same way
 * they approve everything else.
 *
 * <h3>One-pass filing &rarr; the dependency contract</h3>
 * All three CRs are filed in a SINGLE pass. When the scope does NOT yet exist
 * we file the {@code CREATE_CLIENT_SCOPE} CR AND, in the same pass, the
 * {@code REALM_DEFAULT_SCOPE_ADD} CR plus one {@code ASSIGN_SCOPE} CR per
 * existing client — each referencing the <em>deterministic</em> scope id (the
 * id the create CR pins the scope to) by {@code SCOPE_ID}, and each carrying
 * {@code dependsOn = [createScopeCrId]}. The dependents reference a scope that
 * does not physically exist yet; that is fine — the {@code blocked}/fail-closed
 * machinery holds them until the create CR commits, and at their replay time
 * (post-commit) {@code getClientScopeById(deterministicId)} resolves.
 *
 * <p>This is what makes the dependency live. Without it (the old two-pass
 * behaviour) the dependents were filed only AFTER the create committed, with
 * empty {@code dependsOn}, so the whole {@code dependsOn}/{@code blocked}/
 * fail-closed/grey-out machinery never engaged.</p>
 *
 * <p>The {@code REALM_DEFAULT_SCOPE_ADD} and {@code ASSIGN_SCOPE} replays
 * <em>silently no-op</em> if the scope does not exist yet
 * (see {@code IgaReplayDispatcher.replayAddRealmDefaultScope} /
 * {@code assignScopeDirect}); the {@code dependsOn} gate (commit refuses 412
 * until the prerequisite is APPROVED) is exactly what prevents a dependent from
 * replaying before the scope exists.</p>
 *
 * <h3>Self-heal</h3>
 * When the scope ALREADY exists (committed) but the realm-default and/or some
 * clients are not yet wired (and not pending), the same pass files those
 * dependents with an <em>empty</em> {@code dependsOn} — the prerequisite is
 * already satisfied, so no blocking is needed.
 *
 * <h3>Idempotency</h3>
 * Every step is guarded by a state check (scope-exists / already-default /
 * client-already-has-it) AND a pending-CR check, so re-running on the next
 * server start files nothing new. The {@code CREATE_CLIENT_SCOPE} CR also uses
 * a deterministic {@code entityId} (the {@code edgeSyntheticId} idiom over
 * {@code "tide-claims|" + realm.getId()}) so the pending-create dedup is stable
 * across restarts even before the scope is committed.
 */
public final class IgaSystemProvisioner {

    private static final Logger log = Logger.getLogger(IgaSystemProvisioner.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Deterministic-id namespace prefix for the tide-claims CREATE_CLIENT_SCOPE CR. */
    private static final String TIDE_CLAIMS_ID_PREFIX = "tide-claims|";

    private final KeycloakSession session;
    private final IgaChangeRequestService service;

    public IgaSystemProvisioner(KeycloakSession session, EntityManager em) {
        this.session = session;
        this.service = new IgaChangeRequestService(em, session);
    }

    /**
     * Test/seam constructor: inject the {@link IgaChangeRequestService} directly
     * so unit tests can drive the one-pass enqueue / idempotency / self-heal
     * logic against a mocked service (and a mocked session) without a live
     * EntityManager. Production code uses {@link #IgaSystemProvisioner(KeycloakSession, EntityManager)}.
     */
    IgaSystemProvisioner(KeycloakSession session, IgaChangeRequestService service) {
        this.session = session;
        this.service = service;
    }

    /**
     * Outcome of {@link #enqueueTideClaimsScopeProvisioning}. All ids are CR
     * ids (or {@code null} when the corresponding step was skipped because it
     * was already satisfied / already pending).
     */
    public static final class TideUhoEnqueueResult {
        /** CR id of the filed CREATE_CLIENT_SCOPE, or null if the scope already exists / a create CR was already pending. */
        public final String createScopeCrId;
        /** CR id of the filed REALM_DEFAULT_SCOPE_ADD, or null if skipped. */
        public final String realmDefaultCrId;
        /** CR ids of the filed per-client ASSIGN_SCOPE CRs (one per client newly enqueued). */
        public final List<String> assignScopeCrIds;
        /** True when the scope already existed at enqueue time (so dependents have no prerequisite). */
        public final boolean scopeAlreadyExisted;

        TideUhoEnqueueResult(String createScopeCrId, String realmDefaultCrId,
                             List<String> assignScopeCrIds, boolean scopeAlreadyExisted) {
            this.createScopeCrId = createScopeCrId;
            this.realmDefaultCrId = realmDefaultCrId;
            this.assignScopeCrIds = assignScopeCrIds;
            this.scopeAlreadyExisted = scopeAlreadyExisted;
        }

        @Override
        public String toString() {
            return "TideUhoEnqueueResult{createScopeCrId=" + createScopeCrId
                    + ", realmDefaultCrId=" + realmDefaultCrId
                    + ", assignScopeCrIds=" + assignScopeCrIds
                    + ", scopeAlreadyExisted=" + scopeAlreadyExisted + "}";
        }
    }

    /**
     * State-aware, idempotent enqueue of the tide-claims scope provisioning
     * chain for {@code realm}. See class javadoc. Safe to call repeatedly.
     *
     * @param realm       the IGA-enabled target realm (caller checks enablement)
     * @param scopeRep    the {@code tide-claims} {@link ClientScopeRepresentation},
     *                    INCLUDING its inline {@code t.uho} protocol mapper. Its
     *                    {@code name} is used for scope-existence checks; the full
     *                    rep is serialized verbatim into the CREATE_CLIENT_SCOPE
     *                    CR's {@code REP_JSON}. The caller is responsible for the
     *                    mapper's {@code claim.name} being the literal
     *                    {@code t\.uho} (a backslash-escaped dot, Keycloak's
     *                    convention for a literal-dot claim key) — Jackson
     *                    round-trips the escaped string unchanged.
     * @param requestedBy the {@code REQUESTED_BY} stamp (use {@code "system"} for
     *                    the server-start path)
     * @return a {@link TideUhoEnqueueResult} describing which CRs were filed
     */
    public TideUhoEnqueueResult enqueueTideClaimsScopeProvisioning(
            RealmModel realm, ClientScopeRepresentation scopeRep, String requestedBy) {
        if (realm == null || scopeRep == null || scopeRep.getName() == null) {
            throw new IllegalArgumentException(
                    "enqueueTideClaimsScopeProvisioning requires non-null realm + scopeRep + scopeRep.name");
        }
        final String scopeName = scopeRep.getName();
        final String realmId = realm.getId();

        // The deterministic scope id is the linchpin of the one-pass contract:
        // it is what the CREATE_CLIENT_SCOPE CR pins the scope to (REP_JSON.id /
        // row ID), so every dependent CR can reference it by SCOPE_ID BEFORE the
        // scope physically exists. At the dependents' replay time (post-commit
        // of the create) getClientScopeById(deterministicId) resolves.
        final String deterministicId = deterministicScopeId(realmId);

        // ----- Resolve current scope state once -----
        ClientScopeModel existingScope = findScopeByName(realm, scopeName);
        final boolean scopeExists = existingScope != null;

        // ----- (1) Scope step -----
        // createScopeCrId != null  -> we just filed (or found pending) the create
        //                             this pass; dependents depend on it.
        // createScopeCrId == null  -> scope already exists & committed; dependents
        //                             have an already-satisfied prerequisite.
        String createScopeCrId = null;
        if (!scopeExists) {
            // Pending-create dedup: a CREATE_CLIENT_SCOPE CR keyed on the same
            // deterministic entityId already PENDING means a prior server start
            // already enqueued it.
            IgaChangeRequestEntity pendingCreate = service.findPending(
                    realmId, IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE, deterministicId);
            if (pendingCreate == null) {
                Map<String, Object> row = buildCreateClientScopeRow(realm, deterministicId, scopeRep);
                IgaChangeRequestEntity cr = service.create(realm,
                        IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE, deterministicId,
                        "CREATE_CLIENT_SCOPE", List.of(row), requestedBy);
                createScopeCrId = cr.getId();
                log.infof("IGA system-provision: filed CREATE_CLIENT_SCOPE CR %s for scope '%s' in realm %s (deterministicId=%s)",
                        createScopeCrId, scopeName, realmId, deterministicId);
            } else {
                createScopeCrId = pendingCreate.getId();
                log.debugf("IGA system-provision: CREATE_CLIENT_SCOPE for '%s' in realm %s already PENDING (CR %s); reusing as prerequisite",
                        scopeName, realmId, createScopeCrId);
            }
        }

        // ----- Resolve the SCOPE_ID the dependents reference + their dependsOn -----
        // When the create is in flight this pass, the dependents reference the
        // deterministic id (not yet a physical row) and block on the create CR.
        // When the scope is already committed, they reference the live scope id
        // (which equals the deterministic id when this scope was itself created
        // through our CREATE_CLIENT_SCOPE CR, but we use the resolved live id to
        // be correct even for a scope created some other way) and have NO
        // prerequisite (empty dependsOn).
        final String dependentScopeId = scopeExists ? existingScope.getId() : deterministicId;
        final List<String> prereq = createScopeCrId == null
                ? List.of()
                : List.of(createScopeCrId);

        // ----- (2) Realm-default step -----
        // Filed in the SAME pass as the create (one-pass contract). When the
        // scope already exists we additionally state-check (already-default?)
        // and self-heal if missing. When we just filed the create, the scope is
        // not yet a default (it doesn't exist) so we always file, blocked on the
        // create CR — modulo the pending-dedup guard.
        String realmDefaultCrId = null;
        boolean alreadyDefault = scopeExists && realm.getDefaultClientScopesStream(true)
                .anyMatch(s -> s.getId().equals(existingScope.getId()));
        if (!alreadyDefault && !hasPendingRealmDefaultAdd(realmId, dependentScopeId)) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("REALM_ID", realmId);
            row.put("SCOPE_ID", dependentScopeId);
            row.put("DEFAULT_SCOPE", true);
            IgaChangeRequestEntity cr = service.create(realm, "REALM", realmId,
                    "REALM_DEFAULT_SCOPE_ADD", List.of(row), requestedBy, prereq);
            realmDefaultCrId = cr.getId();
            log.infof("IGA system-provision: filed REALM_DEFAULT_SCOPE_ADD CR %s for scope '%s' in realm %s (scopeId=%s, dependsOn=%s)",
                    realmDefaultCrId, scopeName, realmId, dependentScopeId, prereq);
        }

        // ----- (3) Per-client attach step -----
        // Also filed in the SAME pass as the create. One ASSIGN_SCOPE CR per
        // existing client that lacks the scope and has no pending assign for it.
        List<String> assignScopeCrIds = new ArrayList<>();
        // Pending ASSIGN_SCOPE CRs already in flight for THIS scope, indexed by
        // client UUID, so re-running does not double-file for a client. The
        // dedup key is (realm, CLIENT, clientUuid, action=ASSIGN_SCOPE,
        // scope=dependentScopeId): findPendingByAction gives us (realm, CLIENT,
        // ASSIGN_SCOPE) and we narrow to the scope discriminator by inspecting
        // each pending row's SCOPE_ID (findPendingByAction cannot express it),
        // bucketed by the CR's entityId (== client UUID). This both prevents
        // duplicates AND avoids colliding with unrelated scope-assign CRs for
        // other scopes on the same client.
        java.util.Set<String> clientsWithPendingAssign =
                pendingAssignScopeClientUuids(realmId, dependentScopeId);
        List<ClientModel> clients = session.clients()
                .getClientsStream(realm).collect(java.util.stream.Collectors.toList());
        for (ClientModel client : clients) {
            // clientHasScope only resolves when the scope physically exists
            // (scopeExists branch). When the create is still pending no client
            // can have it yet, so this is a no-op there — correct.
            if (scopeExists && clientHasScope(client, dependentScopeId)) continue;
            if (clientsWithPendingAssign.contains(client.getId())) continue;
            Map<String, Object> row = new LinkedHashMap<>();
            // Row shape MUST match IgaReplayDispatcher.assignScopeDirect +
            // IgaRealmProvider.addClientScopes capture:
            //   CLIENT_UUID, CLIENT_ID, SCOPE_ID, DEFAULT_SCOPE
            row.put("CLIENT_UUID", client.getId());
            row.put("CLIENT_ID", client.getClientId());
            row.put("SCOPE_ID", dependentScopeId);
            row.put("DEFAULT_SCOPE", true);
            IgaChangeRequestEntity cr = service.create(realm,
                    IgaReplayExtension.ENTITY_TYPE_CLIENT, client.getId(),
                    "ASSIGN_SCOPE", List.of(row), requestedBy, prereq);
            assignScopeCrIds.add(cr.getId());
            log.infof("IGA system-provision: filed ASSIGN_SCOPE CR %s for client %s (uuid=%s) scope '%s' in realm %s (scopeId=%s, dependsOn=%s)",
                    cr.getId(), client.getClientId(), client.getId(), scopeName, realmId, dependentScopeId, prereq);
        }

        return new TideUhoEnqueueResult(createScopeCrId, realmDefaultCrId,
                assignScopeCrIds, scopeExists);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Deterministic scope id for the tide-claims scope in {@code realmId}:
     * {@code UUID.nameUUIDFromBytes("tide-claims|" + realmId)}. This is the id
     * the CREATE_CLIENT_SCOPE CR pins the scope to (REP_JSON.id / row ID) AND
     * the SCOPE_ID every dependent CR references, so the dependency is live
     * before the scope physically exists.
     */
    private static String deterministicScopeId(String realmId) {
        return UUID.nameUUIDFromBytes(
                (TIDE_CLAIMS_ID_PREFIX + realmId).getBytes(StandardCharsets.UTF_8)).toString();
    }

    private ClientScopeModel findScopeByName(RealmModel realm, String name) {
        return realm.getClientScopesStream()
                .filter(s -> name.equals(s.getName()))
                .findFirst()
                .orElse(null);
    }

    /**
     * CREATE_CLIENT_SCOPE row matching {@code replayCreateClientScope}: ID =
     * scope UUID, NAME = scope name, REALM_ID = realm UUID, REP_JSON = the full
     * ClientScopeRepresentation (incl. inline t.uho mapper). PROTOCOL /
     * DESCRIPTION are bare-create safety-net fields; replay prefers REP_JSON.
     */
    private Map<String, Object> buildCreateClientScopeRow(RealmModel realm, String scopeId,
                                                          ClientScopeRepresentation scopeRep) {
        // Pin the rep's id to our deterministic id so replay's
        // RepresentationToModel.createClientScope honours it (id-bearing
        // realm.addClientScope) and the committed scope's UUID is stable.
        scopeRep.setId(scopeId);
        String repJson;
        try {
            repJson = MAPPER.writeValueAsString(scopeRep);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(
                    "IGA system-provision: failed to serialize tide-claims ClientScopeRepresentation", e);
        }
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("ID", scopeId);
        row.put("NAME", scopeRep.getName());
        row.put("REALM_ID", realm.getId());
        if (scopeRep.getProtocol() != null) row.put("PROTOCOL", scopeRep.getProtocol());
        if (scopeRep.getDescription() != null) row.put("DESCRIPTION", scopeRep.getDescription());
        row.put("REP_JSON", repJson);
        return row;
    }

    private boolean hasPendingRealmDefaultAdd(String realmId, String scopeId) {
        for (IgaChangeRequestEntity cr :
                service.findPendingByAction(realmId, "REALM", "REALM_DEFAULT_SCOPE_ADD")) {
            if (rowsReferenceScope(cr, scopeId)) return true;
        }
        return false;
    }

    private java.util.Set<String> pendingAssignScopeClientUuids(String realmId, String scopeId) {
        java.util.Set<String> clientUuids = new java.util.HashSet<>();
        for (IgaChangeRequestEntity cr :
                service.findPendingByAction(realmId, IgaReplayExtension.ENTITY_TYPE_CLIENT, "ASSIGN_SCOPE")) {
            if (rowsReferenceScope(cr, scopeId)) {
                clientUuids.add(cr.getEntityId());
            }
        }
        return clientUuids;
    }

    /** True if any row in the CR's ROWS_JSON carries SCOPE_ID == scopeId. */
    private boolean rowsReferenceScope(IgaChangeRequestEntity cr, String scopeId) {
        try {
            for (Map<String, Object> row : service.parseRows(cr.getRowsJson())) {
                if (scopeId.equals(row.get("SCOPE_ID"))) return true;
            }
        } catch (RuntimeException ignored) {
            // Malformed rows: treat as non-matching so we don't suppress a
            // legitimately-needed enqueue on a parse hiccup.
        }
        return false;
    }

    private boolean clientHasScope(ClientModel client, String scopeId) {
        for (ClientScopeModel s : client.getClientScopes(true).values()) {
            if (s.getId().equals(scopeId)) return true;
        }
        for (ClientScopeModel s : client.getClientScopes(false).values()) {
            if (s.getId().equals(scopeId)) return true;
        }
        return false;
    }
}
