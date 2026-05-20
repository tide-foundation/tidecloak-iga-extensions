package org.tidecloak.iga.providers;

import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.jpa.ClientScopeAdapter;
import org.keycloak.models.jpa.entities.ClientScopeEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.persistence.EntityManager;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Wraps ClientScopeAdapter and intercepts scope operations for IGA.
 *
 * <h2>Two modes (same design as {@link IgaRoleAdapter} / {@link IgaClientAdapter}
 * / {@link IgaGroupAdapter})</h2>
 * <ul>
 *   <li><b>Inline mode</b> ({@code captureMode == false}, default): wraps an
 *       already-approved, already-persisted client scope returned by
 *       {@code IgaRealmProvider.getClientScopeById}. Mutating calls
 *       (addScopeMapping/setAttribute/addProtocolMapper/…) record targeted
 *       delta change requests — the original inline interception behaviour,
 *       unchanged.</li>
 *   <li><b>Capture mode</b> ({@code captureMode == true}): wraps a
 *       <em>scratch</em> {@link ClientScopeEntity} that
 *       {@code IgaRealmProvider.addClientScope} just persisted. Per-setter /
 *       per-mapper calls still pass through to the real
 *       {@link ClientScopeAdapter} so {@code RepresentationToModel
 *       .createClientScope} builds the complete real model, but each one is
 *       ALSO <b>accumulated</b> into an in-memory
 *       {@link ClientScopeRepresentation} builder (same idea as
 *       {@link IgaRoleAdapter}'s composite accumulation). The accumulated rep
 *       is emitted as the {@code CREATE_CLIENT_SCOPE} change request at the
 *       terminal seam.
 *
 *       <h3>Why a live-model snapshot at a single {@code getId()} seam was
 *       wrong (runtime-proven)</h3>
 *       The previous design snapshotted the live model at the FIRST
 *       {@code getId()} call, assuming (statically) that the only
 *       {@code getId()} on the scope adapter was
 *       {@code ClientScopesResource.createClientScope#getId} (KC 26.5.5
 *       ClientScopesResource.java:133, after {@code RepresentationToModel
 *       .createClientScope} returns). Runtime contradicted this: the snapshot
 *       fired with {@code protocol=null, protocolMappers=0, attributes=0} —
 *       i.e. BEFORE {@code RepresentationToModel.createClientScope}
 *       (RepresentationToModel.java:715-740) applied
 *       setName(719)/setDescription(720)/setProtocol(721)/addProtocolMapper
 *       loop(722-730)/setAttribute loop(732-736).
 *
 *       The reason is structural and unavoidable for client scope:
 *       {@code ClientScopeAdapter.equals()} (KC 26.5.5
 *       ClientScopeAdapter.java:303-310), {@code hashCode()} (313-315) and
 *       {@code toString()} (317-320) ALL call the overridable
 *       {@code getId()}. The scratch adapter is created by
 *       {@code IgaRealmProvider.addClientScope} and returned into
 *       {@code RepresentationToModel.createClientScope} line 718
 *       ({@code realm.addClientScope(rep.getName())}); between line 718 and the
 *       first config setter at line 719 the adapter takes part in the JPA
 *       persistence context, the {@code ClientScopeModel.ClientScopeCreatedEvent}
 *       publication ({@code JpaRealmProvider.addClientScope},
 *       JpaRealmProvider.java:1179) and debug logging — any of which invokes
 *       {@code equals/hashCode/toString} → {@code getId()} <i>before any field
 *       is set</i>. A fire-once-on-FIRST-getId guard then latched that empty
 *       snapshot. Unlike role (whose terminal seam {@code getName()} is a
 *       distinct method the resource calls only AFTER full build, and which
 *       {@code RoleAdapter} never calls internally), client scope's resource
 *       terminal call is {@code getId()} <i>itself</i> — the very method that
 *       fires early — so there is NO single late-only model method to seam on.
 *
 *       <h3>Mechanism: accumulate, emit at the post-build {@code getId()}</h3>
 *       Every {@code setName/setDescription/setProtocol/addProtocolMapper/
 *       setAttribute} call (capture mode) is recorded into a builder
 *       (mappers WITH their full {@code config} map). Emission happens at
 *       {@code getId()} but is GATED on {@code nameObserved} — the builder has
 *       seen {@code setName}. {@code RepresentationToModel.createClientScope}
 *       calls {@code setName} at line 719 (always, the resource validates a
 *       non-null name at ClientScopesResource.java:123) as the FIRST config
 *       call, strictly AFTER {@code realm.addClientScope} (718) and strictly
 *       BEFORE every early {@code equals/hashCode/toString}-driven
 *       {@code getId()} (which all happen during the 718→719 persistence-context
 *       window, before any setter). So {@code nameObserved} cleanly partitions
 *       the early racy {@code getId()} calls (no setter seen yet → fall
 *       through to {@code super.getId()}) from the resource-level terminal
 *       {@code getId()} at ClientScopesResource.createClientScope:133 (every
 *       setter the rep carries already applied → emit). Because the rep is
 *       rebuilt from the ACCUMULATOR (not a live snapshot), even a {@code
 *       getId()} that lands inside the 719→736 window still carries every
 *       field observed up to that point, and the fire-once guard then latches
 *       the final emit; in practice the create path runs synchronously to
 *       completion (RepresentationToModel:739 {@code return clientScope}) and
 *       the next model touch is the resource's terminal {@code getId()} at
 *       :133 with the accumulator fully populated.
 *
 *       <h3>REP_JSON faithfulness vs. replay</h3>
 *       {@code IgaReplayDispatcher.replayCreateClientScope} (full-config path)
 *       deserializes {@code REP_JSON} into a {@code ClientScopeRepresentation},
 *       {@code rep.setId(id)}, {@code rep.setName(name)} then
 *       {@code RepresentationToModel.createClientScope(realm, rep)} — which
 *       reads exactly name(719)/description(720)/protocol(721)/protocolMappers
 *       +config(722-728)/attributes(732-734). The accumulated rep carries
 *       precisely those fields (protocol mappers retain their full {@code
 *       config} map), so the round-trip is byte-faithful. Replay is UNCHANGED.
 *
 *       The {@code CREATE_CLIENT_SCOPE} change request is written in a SEPARATE
 *       transaction ({@code runJobInTransaction}, survives the rollback), the
 *       REQUEST tx is marked rollback-only and {@link IgaPendingApprovalException}
 *       is thrown (→ HTTP 202 + Location). The scratch scope, its protocol
 *       mappers and its attributes die with the rolled-back request
 *       transaction — identical lifecycle proof to
 *       {@link IgaClientAdapter#updateClient}.</li>
 * </ul>
 */
public class IgaClientScopeAdapter extends ClientScopeAdapter {

    private static final Logger log = Logger.getLogger(IgaClientScopeAdapter.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final KeycloakSession igaSession;

    /**
     * When true this adapter wraps a scratch entity mid-{@code
     * createClientScope}; per-setter/per-mapper calls pass through to the real
     * adapter AND are accumulated into {@link #capturedRep}; {@link #getId()}
     * is the terminal snapshot-and-throw seam (gated on {@link #nameObserved}).
     */
    private final boolean captureMode;

    /**
     * The representation accumulated from the pass-through
     * setName/setDescription/setProtocol/addProtocolMapper/setAttribute calls
     * during {@code RepresentationToModel.createClientScope}. This is the
     * authoritative capture (the live model can be read empty if {@code
     * getId()} fires early via equals/hashCode/toString — see class javadoc).
     */
    private final ClientScopeRepresentation capturedRep = new ClientScopeRepresentation();
    private final Map<String, String> capturedAttributes = new LinkedHashMap<>();
    private final List<ProtocolMapperRepresentation> capturedMappers = new ArrayList<>();

    /**
     * True once {@code setName} has been observed via the capture path — i.e.
     * {@code RepresentationToModel.createClientScope} has started applying the
     * representation (line 719) and we are PAST the 718→719 persistence-context
     * window in which early equals/hashCode/toString {@code getId()} calls
     * fire. Until then {@code getId()} falls through to {@code super.getId()}.
     */
    private boolean nameObserved = false;

    /** One-line trace of observed capture events (cheap; logged at emit). */
    private final StringBuilder observedTrace = new StringBuilder();

    /** Fire-once guard: only the first post-build getId() emits. */
    private boolean captureEmitted = false;

    /**
     * Phase 4 — true when this capture-mode adapter was created on a
     * {@code partialImport} (or any multi-entity import) path that calls
     * {@code realm.addClientScope(...)}
     * ({@code IgaRealmProvider.addClientScope} registered it with
     * {@link IgaImportMode#registerImportClientScope}). The
     * {@code CREATE_CLIENT_SCOPE} row is then harvested ONCE at batch-emit
     * time by {@link #buildImportClientScopePendingCr()} from the same
     * {@link #capturedRep}/{@link #capturedMappers}/{@link #capturedAttributes}
     * accumulator the single-entity {@link #getId()} seam emits from (so
     * REP_JSON is byte-identical and {@code IgaReplayDispatcher
     * .replayCreateClientScope} is byte-unchanged). For an import-deferred
     * scope {@link #getId()} is a pure pass-through to {@code super.getId()}
     * (no per-entity accumulate-emit, no throw, no setRollbackOnly — the
     * BatchEmit prepare-tx owns the veto). Defaults false → the single-entity
     * admin-create path is byte-unchanged.
     *
     * <p><b>Defensive parity:</b> KC 26.5.5 has no
     * {@code ClientScopesPartialImport} (verified — {@code PartialImportManager
     * .partialImports} registers only Clients/Roles/IdPs/IdP-mappers/Groups/
     * Users; see {@code IgaImportMode#registerImportClientScope} javadoc), so
     * the import path does not call this branch today; the wiring is cheap
     * insurance against future KC versions or any indirect multi-entity import
     * that one day adds it.
     */
    private boolean importDeferred = false;

    public IgaClientScopeAdapter(RealmModel realm, EntityManager em, KeycloakSession session, ClientScopeEntity clientScopeEntity) {
        this(realm, em, session, clientScopeEntity, false);
    }

    public IgaClientScopeAdapter(RealmModel realm, EntityManager em, KeycloakSession session,
                                 ClientScopeEntity clientScopeEntity, boolean captureMode) {
        super(realm, em, session, clientScopeEntity);
        this.igaSession = session;
        this.captureMode = captureMode;
    }

    /**
     * Mark this capture-mode adapter for partialImport deferred-harvest. Called
     * once by {@code IgaRealmProvider.addClientScope} immediately after
     * {@link IgaImportMode#registerImportClientScope}.
     */
    void markImportDeferred() {
        this.importDeferred = true;
    }

    private IgaChangeRequestService getService() {
        EntityManager em = igaSession.getProvider(JpaConnectionProvider.class).getEntityManager();
        return new IgaChangeRequestService(em, igaSession);
    }

    private boolean isIgaActive() {
        // In capture mode every per-setter/per-mapper override falls through to
        // the real ClientScopeAdapter (so RepresentationToModel.createClientScope
        // builds the complete model) AND accumulates into capturedRep;
        // interception/emit is concentrated at the terminal seam getId().
        if (captureMode) return false;
        IgaChangeRequestService service = getService();
        if (!service.isIgaEnabled(realm)) return false;
        Object replay = igaSession.getAttribute("IGA_REPLAY_ACTIVE");
        return !"true".equals(replay);
    }

    private void trace(String ev) {
        if (observedTrace.length() > 0) observedTrace.append(',');
        observedTrace.append(ev);
    }

    // -------------------------------------------------------------------------
    // Terminal seam for CREATE_CLIENT_SCOPE (capture mode only):
    // clientScope.getId(), GATED on nameObserved.
    //
    // getId() is invoked early and unpredictably on the scratch adapter via
    // ClientScopeAdapter.equals()/hashCode()/toString() (KC 26.5.5
    // ClientScopeAdapter.java:303-320) during the JPA persistence context /
    // ClientScopeCreatedEvent publish (JpaRealmProvider.java:1179) BEFORE
    // RepresentationToModel.createClientScope (RepresentationToModel.java:
    // 715-740) applies any field. Those early calls happen in the 718→719
    // window — BEFORE setName(719) — so nameObserved is false for them and we
    // fall straight through to super.getId(). The resource-level terminal
    // getId() (ClientScopesResource.createClientScope:133, after createClientScope
    // returns at RepresentationToModel:739) happens AFTER setName + every other
    // setter the rep carries, so nameObserved is true and we emit from the
    // ACCUMULATED rep (not a live snapshot).
    // -------------------------------------------------------------------------
    @Override
    public String getId() {
        if (!captureMode || captureEmitted || !nameObserved) {
            return super.getId();
        }
        // Phase 4 — partialImport deferred-harvest. When this capture-mode
        // adapter was created on an import path (IgaRealmProvider
        // .addClientScope registered it with IgaImportMode), the
        // CREATE_CLIENT_SCOPE row is harvested ONCE at batch-emit time by
        // buildImportClientScopePendingCr(). This seam must then be inert
        // (pass straight through to super.getId() — exactly what the
        // single-entity admin-create branch would do in inline mode for a
        // non-captured scope) and MUST NOT accumulate (the batch harvest is
        // the single source of truth) and MUST NOT throw (the batch-emit
        // prepare-tx owns the veto). The single-entity admin-create branch
        // below is byte-unchanged. (Note: KC 26.5.5 has no
        // ClientScopesPartialImport — see IgaImportMode#registerImportClientScope
        // javadoc — so this branch is defensive parity with addClient, not
        // exercised by current partialImport call paths.)
        if (importDeferred) {
            return super.getId();
        }
        // Arm the fire-once guard BEFORE any further model/service call so the
        // emit path cannot re-enter this seam and the second getId() at
        // ClientScopesResource.createClientScope:135 falls through.
        captureEmitted = true;
        trace("getId#emit");

        Map<String, Object> row = buildCapturedClientScopeRow();
        String scopeId = (String) row.get("ID");

        // Phase 4 — partialImport batch governance: accumulate + return the
        // real scope id (NO per-entity CR/setRollbackOnly/throw). Sole
        // behavioural change vs Phases 1–3; single-entity branch unchanged.
        if (IgaImportMode.isImportMode(igaSession, realm)) {
            IgaImportMode.accumulate(igaSession, realm, "CLIENT_SCOPE", scopeId,
                    "CREATE_CLIENT_SCOPE", List.of(row), null);
            return scopeId;
        }

        String[] crIdHolder = new String[1];
        KeycloakModelUtils.runJobInTransaction(igaSession.getKeycloakSessionFactory(), newSession -> {
            RealmModel newRealm = newSession.realms().getRealm(realm.getId());
            EntityManager newEm = newSession.getProvider(JpaConnectionProvider.class).getEntityManager();
            IgaChangeRequestService newService = new IgaChangeRequestService(newEm, newSession);
            crIdHolder[0] = newService.create(newRealm, "CLIENT_SCOPE", scopeId,
                    "CREATE_CLIENT_SCOPE", List.of(row), null).getId();
        });

        // Mark the REQUEST KeycloakTransaction rollback-only so
        // DefaultKeycloakSession#close() rolls back (not commits) and the
        // scratch scope + its protocol mappers + attributes are discarded. The
        // CR survives because it was written on a separate session/tx by
        // runJobInTransaction. Same idiom and lifecycle proof as
        // IgaRoleAdapter#getName / IgaClientAdapter#updateClient.
        igaSession.getTransactionManager().setRollbackOnly();

        throw new IgaPendingApprovalException(crIdHolder[0], "CLIENT_SCOPE", "CREATE_CLIENT_SCOPE");
    }

    /**
     * Build the {@code CREATE_CLIENT_SCOPE} CR row from the accumulator — the
     * SINGLE source of truth shared by the single-entity terminal seam
     * ({@link #getId()}) and the Phase 4 partialImport deferred-harvest path
     * ({@link #buildImportClientScopePendingCr()}). Identical rep/row contract
     * in both cases (so {@code IgaReplayDispatcher.replayCreateClientScope} is
     * byte-unchanged). NO side effects (no CR write, no throw, no
     * rollback-only). Reads {@link #capturedRep}/{@link #capturedMappers}/
     * {@link #capturedAttributes} (authoritative — see class javadoc for why
     * the live model can read empty if {@code getId()} fires early).
     */
    private Map<String, Object> buildCapturedClientScopeRow() {
        String scopeId = super.getId();
        String scopeName = capturedRep.getName();

        ClientScopeRepresentation rep = new ClientScopeRepresentation();
        rep.setId(scopeId);
        rep.setName(scopeName);
        if (capturedRep.getDescription() != null) rep.setDescription(capturedRep.getDescription());
        if (capturedRep.getProtocol() != null) rep.setProtocol(capturedRep.getProtocol());
        if (!capturedMappers.isEmpty()) {
            // Deep-copy each mapper rep + its config so later mutation of the
            // live model (impossible here, but defensive) cannot alias the CR.
            List<ProtocolMapperRepresentation> mappers = new ArrayList<>();
            for (ProtocolMapperRepresentation m : capturedMappers) {
                ProtocolMapperRepresentation c = new ProtocolMapperRepresentation();
                c.setId(m.getId());
                c.setName(m.getName());
                c.setProtocol(m.getProtocol());
                c.setProtocolMapper(m.getProtocolMapper());
                if (m.getConfig() != null) c.setConfig(new LinkedHashMap<>(m.getConfig()));
                mappers.add(c);
            }
            rep.setProtocolMappers(mappers);
        }
        if (!capturedAttributes.isEmpty()) {
            rep.setAttributes(new LinkedHashMap<>(capturedAttributes));
        }

        String repJson;
        try {
            repJson = MAPPER.writeValueAsString(rep);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new RuntimeException(
                    "IGA capture CREATE_CLIENT_SCOPE: failed to serialize captured "
                    + "ClientScopeRepresentation for scope=" + scopeName, e);
        }

        int mappersCount = rep.getProtocolMappers() == null ? 0 : rep.getProtocolMappers().size();
        int attrs = rep.getAttributes() == null ? 0 : rep.getAttributes().size();
        log.infof("IGA capture CREATE_CLIENT_SCOPE: accumulated-rep path for scope=%s (uuid=%s, "
                + "protocol=%s, description=%s, protocolMappers=%d, attributes=%d, %d chars) "
                + "captured at the post-build terminal seam "
                + "(ClientScopesResource.createClientScope#getId, gated on setName-observed / "
                + "partialImport deferred-harvest); observed order=[%s]; full config will "
                + "replay on commit",
                scopeName, scopeId, rep.getProtocol(), rep.getDescription() != null,
                mappersCount, attrs, repJson.length(), observedTrace);

        // rowsJson contract (must match IgaReplayDispatcher.replayCreateClientScope):
        // ID = scope UUID, NAME = scope name, REALM_ID = realm UUID,
        // PROTOCOL/DESCRIPTION = bare-create safety-net fields (replay prefers
        // the REP_JSON full-config path when REP_JSON is present), REP_JSON =
        // the full ClientScopeRepresentation JSON.
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("ID", scopeId);
        row.put("NAME", scopeName);
        row.put("REALM_ID", realm.getId());
        if (rep.getProtocol() != null) row.put("PROTOCOL", rep.getProtocol());
        if (rep.getDescription() != null) row.put("DESCRIPTION", rep.getDescription());
        row.put("REP_JSON", repJson);
        return row;
    }

    /**
     * Phase 4 — partialImport batch path (defensive parity with addClient).
     * Build this scope's {@code CREATE_CLIENT_SCOPE}
     * {@link IgaImportMode.PendingCr} from the accumulator. Called by
     * {@link IgaImportMode.BatchEmitTransaction#commit} AFTER every observed
     * {@code setName}/{@code setDescription}/{@code setProtocol}/
     * {@code addProtocolMapper}/{@code setAttribute} has run (so the
     * accumulator is complete) and BEFORE the scratch JPA tx commits. Uses
     * the SAME {@link #buildCapturedClientScopeRow()} contract as the
     * single-entity {@link #getId()} seam — replay is identical,
     * {@code IgaReplayDispatcher} byte-unchanged. NO throw, NO rollback-only
     * here — the batch-emit tx owns that.
     *
     * <p>If {@code setName} was never observed (e.g. a programmatic caller
     * that bypassed the resource flow), the accumulator is empty and we
     * skip — there is nothing meaningful to govern.
     */
    IgaImportMode.PendingCr buildImportClientScopePendingCr() {
        if (!captureMode || !importDeferred) {
            return null;
        }
        if (!nameObserved) {
            log.warnf("IGA multi-entity ACCUM: CREATE_CLIENT_SCOPE deferred-"
                    + "harvest SKIPPED (uuid=%s) — setName never observed, so "
                    + "the accumulator is empty; no CR row will be emitted "
                    + "for this scope (the scratch scope is still discarded "
                    + "by the import rollback)", super.getId());
            return null;
        }
        Map<String, Object> row = buildCapturedClientScopeRow();
        String scopeId = (String) row.get("ID");
        log.infof("IGA multi-entity ACCUM: CREATE_CLIENT_SCOPE %s (uuid=%s) — "
                + "row harvested at batch emit (defensive parity — KC 26.5.5 "
                + "has no ClientScopesPartialImport but the wiring covers any "
                + "future multi-entity import that reaches addClientScope)",
                row.get("NAME"), scopeId);
        return new IgaImportMode.PendingCr("CLIENT_SCOPE", scopeId,
                "CREATE_CLIENT_SCOPE", List.of(row), null);
    }

    // -------------------------------------------------------------------------
    // Capture-mode accumulators: pass through to the real adapter (so the model
    // is built for the snapshot's lifecycle proof) AND record into capturedRep.
    // -------------------------------------------------------------------------

    @Override
    public void setName(String name) {
        super.setName(name);
        if (captureMode) {
            // entity.getName() reflects KeycloakModelUtils.convertClientScopeName
            // — capture the canonical persisted name so REP_JSON matches what
            // a committed scope (and replay's createClientScope) would carry.
            capturedRep.setName(super.getName());
            nameObserved = true;
            trace("setName");
        }
    }

    @Override
    public void setDescription(String description) {
        super.setDescription(description);
        if (captureMode) {
            capturedRep.setDescription(description);
            trace("setDescription");
        }
    }

    @Override
    public void setProtocol(String protocol) {
        super.setProtocol(protocol);
        if (captureMode) {
            capturedRep.setProtocol(protocol);
            trace("setProtocol");
        }
    }

    @Override
    public void addScopeMapping(RoleModel role) {
        if (!isIgaActive()) {
            super.addScopeMapping(role);
            return;
        }
        IgaChangeRequestService service = getService();
        String scopeId = getId();
        service.create(realm, "CLIENT", scopeId, "SCOPE_ADD_ROLE",
                List.of(Map.of("SCOPE_ID", scopeId, "ROLE_ID", role.getId())),
                null);
    }

    @Override
    public void deleteScopeMapping(RoleModel role) {
        if (!isIgaActive()) {
            super.deleteScopeMapping(role);
            return;
        }
        IgaChangeRequestService service = getService();
        String scopeId = getId();
        service.create(realm, "CLIENT", scopeId, "SCOPE_REMOVE_ROLE",
                List.of(Map.of("SCOPE_ID", scopeId, "ROLE_ID", role.getId())),
                null);
    }

    // -------------------------------------------------------------------------
    // Attribute interception (CLIENT_SCOPE_ATTRIBUTES).
    //
    // In capture mode these pass through to the real ClientScopeAdapter so
    // RepresentationToModel.createClientScope's attribute loop builds the
    // complete model, AND are accumulated into capturedAttributes (the
    // authoritative source for REP_JSON). In inline mode the
    // one-pending-CR-per-entity rule applies.
    //
    // Note: client scope CRs reuse the entityType "CLIENT_SCOPE" for the
    // pending-CR check so we do not collide with same-id-but-different-entity
    // rows (the `findPending` query filters by entity type).
    // -------------------------------------------------------------------------

    @Override
    public void setAttribute(String name, String value) {
        if (captureMode) {
            super.setAttribute(name, value);
            capturedAttributes.put(name, value);
            trace("setAttribute:" + name);
            return;
        }
        if (!isIgaActive()) {
            super.setAttribute(name, value);
            return;
        }
        IgaChangeRequestService service = getService();
        String scopeId = getId();
        checkNoPendingCr(service, scopeId);
        Map<String, Object> row = new HashMap<>();
        row.put("SCOPE_ID", scopeId);
        row.put("NAME", name);
        row.put("VALUE", value);
        service.create(realm, "CLIENT_SCOPE", scopeId, "SET_CLIENT_SCOPE_ATTRIBUTE",
                List.of(row), null);
    }

    @Override
    public void removeAttribute(String name) {
        if (captureMode) {
            super.removeAttribute(name);
            capturedAttributes.remove(name);
            trace("removeAttribute:" + name);
            return;
        }
        if (!isIgaActive()) {
            super.removeAttribute(name);
            return;
        }
        IgaChangeRequestService service = getService();
        String scopeId = getId();
        checkNoPendingCr(service, scopeId);
        Map<String, Object> row = new HashMap<>();
        row.put("SCOPE_ID", scopeId);
        row.put("NAME", name);
        service.create(realm, "CLIENT_SCOPE", scopeId, "REMOVE_CLIENT_SCOPE_ATTRIBUTE",
                List.of(row), null);
    }

    private void checkNoPendingCr(IgaChangeRequestService service, String scopeId) {
        var existing = service.findPending(realm.getId(), "CLIENT_SCOPE", scopeId);
        if (existing != null) {
            throw new IgaConflictException(existing.getId());
        }
    }

    // -------------------------------------------------------------------------
    // Protocol mappers on a CLIENT_SCOPE.
    //
    // In capture mode addProtocolMapper passes through to the real adapter so
    // RepresentationToModel.createClientScope's removeProtocolMapper /
    // addProtocolMapper loop builds the complete model, AND records the mapper
    // (name + protocol + protocolMapper + FULL config) into capturedMappers —
    // the authoritative source for REP_JSON's protocolMappers (with config).
    // removeProtocolMapper keeps the accumulator consistent (createClientScope
    // removes built-in mappers before re-adding). In inline mode they record
    // targeted delta CRs; the parent entity_type is "CLIENT_SCOPE" so
    // IgaScopeResolver can resolve scope rules against the parent scope.
    // -------------------------------------------------------------------------

    @Override
    public ProtocolMapperModel addProtocolMapper(ProtocolMapperModel model) {
        if (captureMode) {
            ProtocolMapperModel added = super.addProtocolMapper(model);
            ProtocolMapperRepresentation pm = new ProtocolMapperRepresentation();
            pm.setId(added != null ? added.getId() : model.getId());
            pm.setName(model.getName());
            pm.setProtocol(model.getProtocol());
            pm.setProtocolMapper(model.getProtocolMapper());
            if (model.getConfig() != null) {
                pm.setConfig(new LinkedHashMap<>(model.getConfig()));
            }
            capturedMappers.add(pm);
            trace("addProtocolMapper:" + model.getName());
            return added;
        }
        if (!isIgaActive()) {
            return super.addProtocolMapper(model);
        }
        IgaChangeRequestService service = getService();
        String scopeId = getId();
        String mapperId = model.getId() != null ? model.getId() : java.util.UUID.randomUUID().toString();
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("ID", mapperId);
        row.put("NAME", model.getName());
        row.put("PROTOCOL", model.getProtocol());
        row.put("PROTOCOL_MAPPER_NAME", model.getProtocolMapper());
        row.put("CLIENT_SCOPE_ID", scopeId);
        // Capture the FULL mapper config map (same shape as
        // UPDATE_PROTOCOL_MAPPER) so replay can faithfully recreate the mapper
        // instead of an empty-config one.
        if (model.getConfig() != null) {
            row.put("config", new LinkedHashMap<>(model.getConfig()));
        }
        service.create(realm, "CLIENT_SCOPE", scopeId, "ADD_PROTOCOL_MAPPER",
                List.of(row),
                null);
        model.setId(mapperId);
        return model;
    }

    @Override
    public void updateProtocolMapper(ProtocolMapperModel mapping) {
        if (captureMode) {
            super.updateProtocolMapper(mapping);
            // Keep the accumulator consistent if createClientScope ever
            // updates a mapper mid-build (it does not in KC 26.5.5, but be
            // robust): replace by id, else append.
            ProtocolMapperRepresentation pm = new ProtocolMapperRepresentation();
            pm.setId(mapping.getId());
            pm.setName(mapping.getName());
            pm.setProtocol(mapping.getProtocol());
            pm.setProtocolMapper(mapping.getProtocolMapper());
            if (mapping.getConfig() != null) pm.setConfig(new LinkedHashMap<>(mapping.getConfig()));
            boolean replaced = false;
            for (int i = 0; i < capturedMappers.size(); i++) {
                if (mapping.getId() != null && mapping.getId().equals(capturedMappers.get(i).getId())) {
                    capturedMappers.set(i, pm);
                    replaced = true;
                    break;
                }
            }
            if (!replaced) capturedMappers.add(pm);
            trace("updateProtocolMapper:" + mapping.getName());
            return;
        }
        if (!isIgaActive()) {
            super.updateProtocolMapper(mapping);
            return;
        }
        IgaChangeRequestService service = getService();
        String scopeId = getId();
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("ID", mapping.getId());
        row.put("NAME", mapping.getName());
        row.put("PROTOCOL", mapping.getProtocol());
        row.put("PROTOCOL_MAPPER_NAME", mapping.getProtocolMapper());
        row.put("CLIENT_SCOPE_ID", scopeId);
        if (mapping.getConfig() != null) {
            row.put("config", new LinkedHashMap<>(mapping.getConfig()));
        }
        service.create(realm, "CLIENT_SCOPE", scopeId, "UPDATE_PROTOCOL_MAPPER",
                List.of(row), null);
    }

    @Override
    public void removeProtocolMapper(ProtocolMapperModel mapping) {
        if (captureMode) {
            super.removeProtocolMapper(mapping);
            // createClientScope removes all built-in/default mappers before
            // re-adding the incoming ones (RepresentationToModel.java:724).
            // Keep the accumulator consistent so REP_JSON carries exactly the
            // surviving mappers.
            if (mapping.getId() != null) {
                capturedMappers.removeIf(m -> mapping.getId().equals(m.getId()));
            }
            trace("removeProtocolMapper:" + mapping.getName());
            return;
        }
        if (!isIgaActive()) {
            super.removeProtocolMapper(mapping);
            return;
        }
        IgaChangeRequestService service = getService();
        String scopeId = getId();
        Map<String, Object> row = new HashMap<>();
        row.put("ID", mapping.getId());
        row.put("CLIENT_SCOPE_ID", scopeId);
        service.create(realm, "CLIENT_SCOPE", scopeId, "REMOVE_PROTOCOL_MAPPER",
                List.of(row), null);
    }
}
