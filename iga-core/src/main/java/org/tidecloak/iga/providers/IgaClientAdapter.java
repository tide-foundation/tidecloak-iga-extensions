package org.tidecloak.iga.providers;

import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.jpa.ClientAdapter;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.ClientRepresentation;
import org.tidecloak.iga.services.IgaQuarantineCache;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.persistence.EntityManager;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Wraps ClientAdapter and intercepts scope/mapper operations for IGA.
 *
 * <h2>Two modes</h2>
 * <ul>
 *   <li><b>Inline mode</b> ({@code captureMode == false}, the default): the
 *       adapter wraps an already-approved, already-persisted client returned by
 *       {@code IgaRealmProvider.getClientById/getClientByClientId}. Every
 *       mutating call (setAttribute, addProtocolMapper, setWebOrigins, …)
 *       records a targeted delta change request and (for the
 *       SET/REMOVE-attribute path) throws to interrupt the write — the original
 *       inline interception behaviour, unchanged.</li>
 *   <li><b>Capture mode</b> ({@code captureMode == true}): the adapter wraps a
 *       <em>scratch</em> {@link ClientEntity} that {@code IgaRealmProvider
 *       .addClient} just persisted. Per-setter interception is fully bypassed so
 *       Keycloak's {@code RepresentationToModel.createClient} can apply the
 *       <em>complete</em> incoming {@link ClientRepresentation} to the real
 *       model (web origins, redirect URIs, attributes, protocol mappers, flow
 *       flags, …). The LAST mutation Keycloak makes in that path,
 *       {@code ClientModel.updateClient()}
 *       ({@code RepresentationToModel.createClient} line 404, KC 26.5.5), is the
 *       <b>terminal seam</b>: at that point every admin-supplied field is on the
 *       model, so {@link #updateClient()} snapshots the live model into a
 *       {@link ClientRepresentation} via
 *       {@link ModelToRepresentation#toRepresentation(org.keycloak.models.ClientModel, KeycloakSession)},
 *       persists the {@code CREATE_CLIENT} change request (with the full
 *       {@code REP_JSON}) in a SEPARATE transaction, marks the REQUEST
 *       transaction rollback-only, and throws
 *       {@link IgaPendingApprovalException} → HTTP 202. The scratch entity is
 *       never committed: mapping the exception to a 202 fully CONSUMES it (it
 *       does NOT propagate to {@code DefaultKeycloakSession#close()}), so the
 *       request tx is NOT auto-rolled-back by exception propagation — it would
 *       in fact be {@code commit()}ed and leak the scratch client (the original
 *       throw-at-{@code addClient} only escaped this because it threw BEFORE
 *       {@code super.addClient}, persisting nothing). The explicit
 *       {@code getTransactionManager().setRollbackOnly()} on the request
 *       session is what makes {@code DefaultKeycloakSession#closeTransaction
 *       Manager()} call {@code rollback()} instead of {@code commit()}, so
 *       nothing the create flow touched reaches the DB while the already-built
 *       202 still stands (same idiom as {@code KeycloakErrorHandler#getResponse}).
 *       Because the throw happens LATE — after the full entity graph is built —
 *       there are no transient references at the (possible) auto-flush, which is
 *       why this avoids the {@code TransientPropertyValueException}/cascade that
 *       made the original throw-at-{@code addClient} design necessary.</li>
 * </ul>
 */
public class IgaClientAdapter extends ClientAdapter {

    private static final Logger log = Logger.getLogger(IgaClientAdapter.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final KeycloakSession igaSession;

    /**
     * When true this adapter wraps a scratch entity mid-{@code createClient}
     * and the only special behaviour is {@link #updateClient()} (the terminal
     * snapshot-and-throw seam); all per-setter interception is bypassed so
     * Keycloak's builder can apply the full representation to the real model.
     */
    private final boolean captureMode;

    /**
     * Phase 4 — true when this capture-mode adapter was created on the
     * {@code partialImport} {@code ClientsPartialImport.create} →
     * {@code RepresentationToModel.createClient} path
     * ({@code IgaRealmProvider.addClient} registered it with
     * {@link IgaImportMode#registerImportClient}). The
     * {@code CREATE_CLIENT} row is then harvested ONCE at batch-emit time by
     * {@link #buildImportClientPendingCr()} (after
     * {@code RepresentationToModel.createClient} has called its terminal
     * {@code updateClient()} on the pass-through scratch model, KC 26.5.5
     * RepresentationToModel.java:404), so {@link #updateClient()} is a pure
     * pass-through to {@code super.updateClient()} for this client (no
     * per-entity accumulate, no throw, no setRollbackOnly — the BatchEmit
     * prepare-tx owns the veto). Defaults false → the single-entity
     * admin-create path is byte-unchanged.
     */
    private boolean importDeferred = false;

    /**
     * Phase 4 (CME fix) — pre-built {@code CREATE_CLIENT} row cached at the
     * eager-harvest seam ({@link #updateClient()} in {@code importDeferred}
     * mode), so {@link IgaImportMode.BatchEmitTransaction#commit} can read it
     * WITHOUT calling {@link ModelToRepresentation#toRepresentation
     * (org.keycloak.models.ClientModel, KeycloakSession)} during the parent
     * session's prepare-list iteration. See {@link #updateClient()} for the
     * full root-cause analysis.
     */
    private Map<String, Object> cachedImportRow;

    public IgaClientAdapter(RealmModel realm, EntityManager em, KeycloakSession session, ClientEntity clientEntity) {
        this(realm, em, session, clientEntity, false);
    }

    public IgaClientAdapter(RealmModel realm, EntityManager em, KeycloakSession session,
                            ClientEntity clientEntity, boolean captureMode) {
        super(realm, em, session, clientEntity);
        this.igaSession = session;
        this.captureMode = captureMode;
    }

    /**
     * Mark this capture-mode adapter for partialImport deferred-harvest. Called
     * once by {@code IgaRealmProvider.addClient} immediately after
     * {@link IgaImportMode#registerImportClient}.
     */
    void markImportDeferred() {
        this.importDeferred = true;
    }

    private IgaChangeRequestService getService() {
        EntityManager em = igaSession.getProvider(JpaConnectionProvider.class).getEntityManager();
        return new IgaChangeRequestService(em, igaSession);
    }

    private boolean isIgaActive() {
        // In capture mode every per-setter override must fall straight through
        // to the real ClientAdapter so RepresentationToModel.createClient can
        // build the complete model; interception is concentrated at the single
        // terminal seam updateClient() instead.
        if (captureMode) return false;
        IgaChangeRequestService service = getService();
        if (!service.isIgaEnabled(realm)) return false;
        Object replay = igaSession.getAttribute("IGA_REPLAY_ACTIVE");
        return !"true".equals(replay);
    }

    /**
     * Terminal seam for CREATE_CLIENT (capture mode only).
     *
     * <p>{@code RepresentationToModel.createClient} (KC 26.5.5,
     * {@code org.keycloak.models.utils.RepresentationToModel:404}) calls
     * {@code client.updateClient()} as its FINAL model mutation, AFTER
     * {@code updateClientProperties} (name/enabled/flows/redirectUris/
     * webOrigins/attributes — line 347), the protocol-mapper rebuild (line 391)
     * and {@code updateClientScopes} (line 402). So when this fires every
     * admin-supplied field is already on the live model. We snapshot the
     * complete model into a {@link ClientRepresentation} with Keycloak's own
     * {@link ModelToRepresentation#toRepresentation}, fold it into the
     * {@code CREATE_CLIENT} change request as {@code REP_JSON} (persisted in a
     * separate transaction so it survives the rollback), and throw
     * {@link IgaPendingApprovalException}. {@code IgaReplayDispatcher
     * .replayCreateClient} deserializes exactly this {@code ClientRepresentation}
     * and feeds it back through {@code RepresentationToModel.createClient} under
     * {@code IGA_REPLAY_ACTIVE}, so the round-trip is faithful.</p>
     *
     * <p>We deliberately do NOT call {@code super.updateClient()}: that would
     * publish a {@code ClientUpdatedEvent} for a client that is about to be
     * rolled back. Nothing here is committed — after writing the CR we call
     * {@code igaSession.getTransactionManager().setRollbackOnly()} on the
     * REQUEST transaction, so {@code DefaultKeycloakSession#close()} rolls back
     * (not commits) and the scratch entity dies with the rolled-back request
     * transaction. The CR survives because it was written on a separate
     * session/tx by {@code runJobInTransaction}.</p>
     */
    @Override
    public void updateClient() {
        if (!captureMode) {
            super.updateClient();
            return;
        }

        // Phase 4 (CME fix) — partialImport EAGER-HARVEST at the terminal
        // create seam. When this capture-mode adapter was created on the
        // ClientsPartialImport.create → RepresentationToModel.createClient
        // path (IgaRealmProvider.addClient registered it with IgaImportMode),
        // the CREATE_CLIENT row MUST be harvested HERE — inside KC's
        // create-callable — not later in BatchEmitTransaction.commit().
        //
        // ROOT CAUSE (the bug we are fixing): the earlier deferred-harvest
        // built the row inside BatchEmitTransaction.commit(), which runs
        // INSIDE DefaultKeycloakTransactionManager.commit()'s prepare-list
        // iteration (KC 26.5.5 DefaultKeycloakTransactionManager.java:124,
        // `for (KeycloakTransaction tx : prepare)`). buildCapturedClientRow
        // calls ModelToRepresentation.toRepresentation(this, igaSession). KC
        // 26.5.5 ModelToRepresentation.java:901 does
        // `session.getProvider(AuthorizationProvider.class)` and
        // `authorization.getStoreFactory().findByClient(clientModel)` — the
        // first call lazily constructs StoreFactoryCacheSession (tidecloak
        // fork model/infinispan/.../authorization/StoreFactoryCacheSession
        // .java:122) whose constructor calls
        // `session.getTransactionManager().enlistPrepare(getPrepareTransaction())`
        // on the parent session's TM — the SAME `prepare` LinkedList that
        // is currently being iterated. The next `iterator.next()` then fails
        // the modCount check (LinkedList$ListItr.checkForComodification:977
        // → ConcurrentModificationException at TM.lambda$commit$0:124). The
        // 5 CRs are already written successfully by runJobInTransaction
        // before the throw, but the CME bypasses the
        // IgaPendingApprovalException → 202 mapping and bubbles a 500.
        //
        // FIX (Option A — eager harvest at the terminal create-stack seam,
        // per source-confirmed instructions): build the row HERE, while
        // RepresentationToModel.createClient is still on the call stack and
        // the parent TM is NOT yet iterating prepare. The
        // StoreFactoryCacheSession's enlistPrepare therefore happens BEFORE
        // TM.commit() begins iterating, so the prepare list is stable for the
        // iteration. BatchEmitTransaction.commit() then just reads the
        // pre-built `cachedImportRow` — zero model traversal, zero provider
        // lookups, zero prepare-time mutation.
        //
        // updateClient() is the correct seam: KC 26.5.5
        // RepresentationToModel.createClient (line 404) calls
        // `client.updateClient()` as its FINAL unconditional model mutation
        // — AFTER updateClientProperties (line 347), the protocol-mapper
        // rebuild (line 391) and updateClientScopes (line 402). So every
        // updateClientProperties field / protocol-mapper / scope link is on
        // the live model when we serialize. The row is byte-faithful with
        // the prior deferred-harvest path (identical buildCapturedClientRow,
        // identical IgaReplayDispatcher consumption — byte-unchanged).
        //
        // The seam still calls super.updateClient() so KC's createClient
        // finishes normally and ClientsPartialImport.getModelId — `realm
        // .getClientByClientId(clientId).getId()` — resolves on the real
        // persisted client. NO per-entity accumulate, NO throw, NO
        // setRollbackOnly (the BatchEmit prepare-tx still owns the veto).
        // The single-entity admin-create branch below is byte-unchanged.
        if (importDeferred) {
            cachedImportRow = buildCapturedClientRow();
            log.infof("IGA multi-entity HARVEST: REP_JSON built at "
                    + "register-time for CREATE_CLIENT (size=%d chars) — "
                    + "prepare-time traversal eliminated",
                    ((String) cachedImportRow.get("REP_JSON")).length());
            super.updateClient();
            return;
        }

        Map<String, Object> row = buildCapturedClientRow();
        String clientUuid = (String) row.get("ID");

        // Phase 4 — partialImport batch governance: accumulate + return
        // normally (NO per-entity CR/setRollbackOnly/throw). Sole behavioural
        // change vs Phases 1–3; the single-entity branch below is unchanged.
        if (IgaImportMode.isImportMode(igaSession, realm)) {
            IgaImportMode.accumulate(igaSession, realm, "CLIENT", clientUuid,
                    "CREATE_CLIENT", List.of(row), null);
            return;
        }

        String[] crIdHolder = new String[1];
        KeycloakModelUtils.runJobInTransaction(igaSession.getKeycloakSessionFactory(), newSession -> {
            RealmModel newRealm = newSession.realms().getRealm(realm.getId());
            EntityManager newEm = newSession.getProvider(JpaConnectionProvider.class).getEntityManager();
            IgaChangeRequestService newService = new IgaChangeRequestService(newEm, newSession);
            crIdHolder[0] = newService.create(newRealm, "CLIENT", clientUuid,
                    "CREATE_CLIENT", List.of(row), null).getId();
        });

        // CRITICAL (the actual draft-no-persist guarantee): the CR has now been
        // committed on a SEPARATE session/transaction by runJobInTransaction
        // (KeycloakModelUtils.runJobInTransactionWithResult does
        // factory.create() → its own KeycloakTransactionManager + EntityManager,
        // begin()/commit() decoupled from the request tx; rollback-only is set
        // there ONLY if its task throws — it survives a request-tx rollback).
        //
        // Now mark the REQUEST KeycloakTransaction rollback-only. igaSession is
        // the thread-bound request session (bound by
        // resteasy.TransactionalSessionHandler#handle →
        // KeycloakSessionUtil.setKeycloakSession, with the request tx already
        // begun); igaSession.getTransactionManager() is therefore the REQUEST
        // DefaultKeycloakTransactionManager, NOT the runJobInTransaction job tx
        // (that session was closed when its try-with-resources exited).
        //
        // Why this deterministically discards the scratch ClientEntity AND
        // still returns 202 (KC 26.5.5 tx lifecycle, traced):
        //   * DefaultKeycloakSession#close() (invoked by
        //     jaxrs.CloseSessionFilter#closeSession at the end of the response
        //     pipeline) calls closeTransactionManager(), which does
        //     `if (transactionManager.getRollbackOnly()) rollback(); else
        //     commit();`. With this flag set, getRollbackOnly() returns true so
        //     rollback() runs — JpaKeycloakTransaction#rollback() →
        //     em.getTransaction().rollback(): the scratch CLIENT INSERT (and
        //     every row RepresentationToModel.createClient produced) is
        //     discarded. ZERO client rows reach the DB at draft time.
        //   * The 202 is unaffected: IgaPendingApprovalExceptionMapper builds
        //     the 202 Response BEFORE CloseSessionFilter runs, and rollback
        //     never escalates to a 500 (JpaKeycloakTransaction#rollback cannot
        //     throw a mapped error; only commit() can). This is the exact idiom
        //     KeycloakErrorHandler#getResponse uses (tx.setRollbackOnly() then
        //     return a response) — here applied to a 2xx instead of a 4xx/5xx.
        //   * Without this flag getRollbackOnly() is false, so close() would
        //     commit() the request tx and leak the scratch client — the
        //     observed duplicate-key bug. This is the fix.
        igaSession.getTransactionManager().setRollbackOnly();

        throw new IgaPendingApprovalException(crIdHolder[0], "CLIENT", "CREATE_CLIENT");
    }

    /**
     * Build the {@code CREATE_CLIENT} CR row — the SINGLE source of truth
     * shared by the single-entity terminal seam ({@link #updateClient()}) and
     * the Phase 4 partialImport deferred-harvest path
     * ({@link #buildImportClientPendingCr()}). Identical rep/row contract in
     * both cases, so {@code IgaReplayDispatcher.replayCreateClient} is
     * byte-unchanged. NO side effects (no CR write, no throw, no
     * rollback-only). Reads the live (pass-through) scratch model via
     * {@link ModelToRepresentation#toRepresentation(org.keycloak.models.ClientModel, KeycloakSession)},
     * which serializes the complete client (name, enabled, protocol, flow
     * flags, redirectUris, webOrigins, attributes, protocol mappers WITH
     * config, default/optional client scopes) — exactly the fields
     * {@code IgaReplayDispatcher.replayCreateClient} feeds back into
     * {@code RepresentationToModel.createClient} on commit.
     */
    private Map<String, Object> buildCapturedClientRow() {
        ClientRepresentation rep = ModelToRepresentation.toRepresentation(this, igaSession);
        // Pin identity so replay recreates the client with the SAME UUID and
        // human clientId the admin's create flow allocated. (replay also
        // re-pins from the row's ID/CLIENT_ID, but keeping the rep self
        // consistent avoids any ambiguity.)
        String clientUuid = super.getId();
        String clientId = super.getClientId();
        rep.setId(clientUuid);
        rep.setClientId(clientId);

        String repJson;
        try {
            repJson = MAPPER.writeValueAsString(rep);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new RuntimeException(
                    "IGA capture CREATE_CLIENT: failed to serialize captured ClientRepresentation "
                    + "for clientId=" + clientId, e);
        }

        int webOrigins = rep.getWebOrigins() == null ? 0 : rep.getWebOrigins().size();
        int redirectUris = rep.getRedirectUris() == null ? 0 : rep.getRedirectUris().size();
        log.infof("IGA capture CREATE_CLIENT: full-rep path for clientId=%s "
                + "(webOrigins=%d, redirectUris=%d, %d chars) captured at the model-layer "
                + "terminal seam (RepresentationToModel.createClient#updateClient / "
                + "partialImport deferred-harvest); full config will replay on commit",
                clientId, webOrigins, redirectUris, repJson.length());

        // rowsJson contract (must match IgaReplayDispatcher.replayCreateClient):
        // ID = own client UUID, CLIENT_ID = human clientId,
        // CLIENT_UUID = same UUID (referenced-client alias so replay's
        // resolveClient works uniformly), REALM_ID = realm UUID,
        // REP_JSON = the full ClientRepresentation JSON.
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("ID", clientUuid);
        row.put("CLIENT_UUID", clientUuid);
        row.put("CLIENT_ID", clientId);
        row.put("REALM_ID", realm.getId());
        row.put("REP_JSON", repJson);
        return row;
    }

    /**
     * Phase 4 — partialImport batch path. Build this client's
     * {@code CREATE_CLIENT} {@link IgaImportMode.PendingCr} from the live
     * (pass-through) scratch model. Called by
     * {@link IgaImportMode.BatchEmitTransaction#commit} AFTER
     * {@code RepresentationToModel.createClient} has called its terminal
     * {@code updateClient()} on the scratch client (so every
     * updateClientProperties field, every rebuilt protocol mapper, every
     * default/optional client scope link has been applied to the live model)
     * and BEFORE the scratch JPA tx commits. Uses the SAME
     * {@link #buildCapturedClientRow()} contract as the single-entity seam —
     * replay is identical, {@code IgaReplayDispatcher} byte-unchanged. NO
     * throw, NO rollback-only here — the batch-emit tx owns that.
     */
    IgaImportMode.PendingCr buildImportClientPendingCr() {
        if (!captureMode || !importDeferred) {
            return null;
        }
        // Phase 4 (CME fix) — prefer the pre-built row that updateClient()
        // captured at the terminal create seam (see updateClient() javadoc
        // for the root-cause analysis: building the row HERE during the
        // parent TM's prepare-list iteration causes
        // StoreFactoryCacheSession.enlistPrepare to mutate the list under
        // the iterator → ConcurrentModificationException at
        // DefaultKeycloakTransactionManager.lambda$commit$0:124). The
        // fallback to buildCapturedClientRow() only fires if updateClient()
        // was never called on this client during the import — that should
        // be impossible on the ClientsPartialImport.create path
        // (RepresentationToModel.createClient:404 always calls it), but is
        // retained as a defensive last resort that keeps the CR shape
        // identical (and is logged so any drift is visible in production).
        Map<String, Object> row = cachedImportRow;
        if (row == null) {
            log.warnf("IGA multi-entity HARVEST: pre-built row missing for "
                    + "CREATE_CLIENT uuid=%s — falling back to batch-time "
                    + "build (updateClient seam was never reached; this is "
                    + "unexpected on the partialImport path and indicates a "
                    + "control-flow regression — investigate)",
                    super.getId());
            row = buildCapturedClientRow();
        }
        String clientUuid = (String) row.get("ID");
        log.infof("IGA multi-entity ACCUM: CREATE_CLIENT %s (uuid=%s) — row "
                + "harvested at batch emit from the partialImport "
                + "ClientsPartialImport.create → RepresentationToModel."
                + "createClient path (source=%s)",
                row.get("CLIENT_ID"), clientUuid,
                cachedImportRow == row ? "pre-built (updateClient seam)"
                                       : "batch-time fallback");
        return new IgaImportMode.PendingCr("CLIENT", clientUuid, "CREATE_CLIENT",
                List.of(row), null);
    }

    // -------------------------------------------------------------------------
    // Client-scope attach/detach capture has MOVED to the provider layer:
    // org.tidecloak.iga.providers.IgaRealmProvider#addClientScopes /
    // #removeClientScope. With the infinispan cache ON (production), the admin
    // routes and KC's own create flow route scope attach/detach through
    // CacheClientAdapter → RealmCacheSession.addClientScopes/removeClientScope →
    // getClientDelegate() (== IgaRealmProvider), which BYPASSES this ClientModel
    // adapter entirely. The former IgaClientAdapter#addClientScope /
    // #removeClientScope overrides here were therefore dead code (never hit at
    // runtime) and have been removed to avoid misleading a future maintainer
    // into thinking scope-attach capture lives on the adapter. See
    // IgaRealmProvider's "CLIENT-SCOPE ATTACH / DETACH" section for the live
    // ASSIGN_SCOPE / REMOVE_SCOPE capture seam.
    // -------------------------------------------------------------------------

    // -------------------------------------------------------------------------
    // Attribute interception (CLIENT_ATTRIBUTES).
    //
    // Same one-pending-CR-per-entity rule as the rest of the inline-pattern
    // operations: admins must drain a client's pending CR before issuing
    // another one for that client.
    // -------------------------------------------------------------------------

    @Override
    public void setAttribute(String name, String value) {
        if (!isIgaActive()) {
            super.setAttribute(name, value);
            return;
        }
        IgaChangeRequestService service = getService();
        String clientUuid = getId();
        checkNoPendingCr(service, clientUuid);
        Map<String, Object> row = new HashMap<>();
        row.put("CLIENT_UUID", clientUuid);
        row.put("CLIENT_ID", getClientId());
        row.put("NAME", name);
        row.put("VALUE", value);
        service.create(realm, "CLIENT", clientUuid, "SET_CLIENT_ATTRIBUTE",
                List.of(row), null);
    }

    @Override
    public void removeAttribute(String name) {
        if (!isIgaActive()) {
            super.removeAttribute(name);
            return;
        }
        IgaChangeRequestService service = getService();
        String clientUuid = getId();
        checkNoPendingCr(service, clientUuid);
        Map<String, Object> row = new HashMap<>();
        row.put("CLIENT_UUID", clientUuid);
        row.put("CLIENT_ID", getClientId());
        row.put("NAME", name);
        service.create(realm, "CLIENT", clientUuid, "REMOVE_CLIENT_ATTRIBUTE",
                List.of(row), null);
    }

    private void checkNoPendingCr(IgaChangeRequestService service, String clientUuid) {
        var existing = service.findPending(realm.getId(), "CLIENT", clientUuid);
        if (existing != null) {
            throw new IgaConflictException(existing.getId());
        }
    }

    @Override
    public ProtocolMapperModel addProtocolMapper(ProtocolMapperModel model) {
        if (!isIgaActive()) {
            return super.addProtocolMapper(model);
        }
        IgaChangeRequestService service = getService();
        String clientUuid = getId();
        String mapperId = model.getId() != null ? model.getId() : java.util.UUID.randomUUID().toString();
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("ID", mapperId);
        row.put("NAME", model.getName());
        row.put("PROTOCOL", model.getProtocol());
        row.put("PROTOCOL_MAPPER_NAME", model.getProtocolMapper());
        row.put("CLIENT_UUID", clientUuid);
        row.put("CLIENT_ID", getClientId());
        // Capture the FULL mapper config map (same shape as
        // UPDATE_PROTOCOL_MAPPER) so replay can faithfully recreate the mapper
        // instead of an empty-config one.
        if (model.getConfig() != null) {
            row.put("config", new LinkedHashMap<>(model.getConfig()));
        }
        service.create(realm, "CLIENT", clientUuid, "ADD_PROTOCOL_MAPPER",
                List.of(row),
                null);
        // Return a stub model with the assigned id
        model.setId(mapperId);
        return model;
    }

    @Override
    public void updateProtocolMapper(ProtocolMapperModel mapping) {
        if (!isIgaActive()) {
            super.updateProtocolMapper(mapping);
            return;
        }
        IgaChangeRequestService service = getService();
        String clientUuid = getId();
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("ID", mapping.getId());
        row.put("NAME", mapping.getName());
        row.put("PROTOCOL", mapping.getProtocol());
        row.put("PROTOCOL_MAPPER_NAME", mapping.getProtocolMapper());
        row.put("CLIENT_UUID", clientUuid);
        row.put("CLIENT_ID", getClientId());
        if (mapping.getConfig() != null) {
            row.put("config", new LinkedHashMap<>(mapping.getConfig()));
        }
        service.create(realm, "CLIENT", clientUuid, "UPDATE_PROTOCOL_MAPPER",
                List.of(row), null);
    }

    @Override
    public void removeProtocolMapper(ProtocolMapperModel mapping) {
        if (!isIgaActive()) {
            super.removeProtocolMapper(mapping);
            return;
        }
        IgaChangeRequestService service = getService();
        String clientUuid = getId();
        Map<String, Object> row = new HashMap<>();
        row.put("ID", mapping.getId());
        row.put("CLIENT_UUID", clientUuid);
        row.put("CLIENT_ID", getClientId());
        service.create(realm, "CLIENT", clientUuid, "REMOVE_PROTOCOL_MAPPER",
                List.of(row), null);
    }

    // -------------------------------------------------------------------------
    // Web origins / redirect URIs — full set replacement.
    //
    // The CLIENT_WEB_ORIGINS and CLIENT_REDIRECT_URIS tables are list-collection
    // tables and have no entity class for per-row attestation. Coverage is
    // provided by the change request snapshot in rows_json; on replay we apply
    // the full set.
    // -------------------------------------------------------------------------

    @Override
    public void setWebOrigins(Set<String> webOrigins) {
        if (!isIgaActive()) {
            super.setWebOrigins(webOrigins);
            return;
        }
        IgaChangeRequestService service = getService();
        String clientUuid = getId();
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("CLIENT_UUID", clientUuid);
        row.put("CLIENT_ID", getClientId());
        row.put("values", webOrigins == null ? new ArrayList<String>() : new ArrayList<>(webOrigins));
        service.create(realm, "CLIENT", clientUuid, "UPDATE_CLIENT_WEB_ORIGINS",
                List.of(row), null);
    }

    @Override
    public void setRedirectUris(Set<String> redirectUris) {
        if (!isIgaActive()) {
            super.setRedirectUris(redirectUris);
            return;
        }
        IgaChangeRequestService service = getService();
        String clientUuid = getId();
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("CLIENT_UUID", clientUuid);
        row.put("CLIENT_ID", getClientId());
        row.put("values", redirectUris == null ? new ArrayList<String>() : new ArrayList<>(redirectUris));
        service.create(realm, "CLIENT", clientUuid, "UPDATE_CLIENT_REDIRECT_URIS",
                List.of(row), null);
    }

    // -------------------------------------------------------------------------
    // Phase 6c — client quarantine hook (HARD refuse).
    //
    // KC checkpoints surfaced by client.isEnabled() (cross-checked vs
    // /tmp/kc-all-src/...):
    //   ClientIdAndSecretAuthenticator.java:114  (client_secret_basic/post)
    //   AbstractJWTClientValidator.java:124      (client JWT auth)
    //   AccessTokenIntrospectionProvider.java:267 (introspection)
    //
    // Defers to super.isEnabled() first so an admin-disabled client stays
    // disabled regardless. If super reports enabled, the quarantine cache
    // refuses the operation when the client has an unattested sidecar row,
    // making client_credentials / client-auth / introspection requests fail
    // until the ADOPT_CLIENT CR commits.
    // -------------------------------------------------------------------------

    @Override
    public boolean isEnabled() {
        boolean superEnabled = super.isEnabled();
        if (!superEnabled) {
            return false;
        }
        if (IgaQuarantineCache.isClientUnsigned(igaSession, realm, this)) {
            if (IgaQuarantineCache.firstObservation(igaSession,
                    "client:" + super.getId())) {
                log.infof("IGA quarantine REFUSE: client=%s (uuid=%s) realm=%s — "
                        + "ADOPT pending; treating as not-enabled.",
                        super.getClientId(), super.getId(), realm.getName());
            }
            return false;
        }
        return true;
    }
}
