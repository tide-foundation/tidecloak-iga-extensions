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
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.ClientScopeRepresentation;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.persistence.EntityManager;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Wraps ClientScopeAdapter and intercepts scope mapping operations for IGA.
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
 *       per-mapper interception is bypassed so Keycloak's
 *       {@code RepresentationToModel.createClientScope} can apply the COMPLETE
 *       incoming {@link ClientScopeRepresentation} (name, description, protocol,
 *       protocol mappers WITH full config AND attributes) to the real model.
 *
 *       <h3>KC 26.5.5 client-scope create path (verified)</h3>
 *       {@code ClientScopesResource.createClientScope} (verified, lines
 *       121-139) →
 *       {@code RepresentationToModel.createClientScope(realm, rep)} (verified,
 *       lines 715-740):
 *       <pre>
 *       718  ClientScopeModel cs = realm.addClientScope(id, name);  // → IgaRealmProvider.addClientScope (scratch + this adapter)
 *       719  if (rep.getName()!=null)        cs.setName(...)         // conditional
 *       720  if (rep.getDescription()!=null) cs.setDescription(...)  // conditional
 *       721  if (rep.getProtocol()!=null)    cs.setProtocol(...)     // conditional
 *       722-730 if (rep.getProtocolMappers()!=null) {                // conditional
 *                 cs.removeProtocolMapper(...) loop;                  // conditional
 *                 for (..) cs.addProtocolMapper(toModel(mapper));     // conditional, mappers precede attrs
 *               }
 *       732-736 if (rep.getAttributes()!=null)                       // conditional, LAST in createClientScope
 *                 for (..) cs.setAttribute(k, v);
 *       739  return clientScope;                                     // NO unconditional terminal MUTATOR
 *       ----- back in ClientScopesResource.createClientScope -----
 *       133  adminEvent...resourcePath(uri, clientScope.getId())     // clientScope.getId() — UNCONDITIONAL, FIRST model call after build
 *       135  Response.created(... path(clientScope.getId()) ...)     // clientScope.getId() again
 *       </pre>
 *       Exactly like {@code RoleContainerResource.createRole}, there is NO
 *       unconditional last <i>mutating</i> model call inside
 *       {@code createClientScope}: setName/setDescription/setProtocol are each
 *       conditional, the protocol-mapper loop is conditional, and the attribute
 *       loop (last) is conditional too.
 *
 *       <h3>Terminal seam chosen: {@code getId()} at
 *       ClientScopesResource.createClientScope line 133</h3>
 *       {@code clientScope.getId()} (ClientScopesResource.createClientScope
 *       line 133, then 135) is the FIRST {@code getId()} call the resource
 *       makes after {@code createClientScope} returns and it is UNCONDITIONAL
 *       and strictly AFTER every conditional mutation in the create path — i.e.
 *       the model is fully built when it fires, whether the scope has mappers /
 *       attributes or not. It is therefore the exact client-scope analogue of
 *       role's {@code getName()} / client's {@code updateClient()} / group's
 *       {@code setDescription()}. {@code ClientScopeAdapter.getId()}
 *       (verified, KC 26.5.5 ClientScopeAdapter.java:66-68) returns
 *       {@code entity.getId()} directly and
 *       {@code setName/setDescription/setProtocol/addProtocolMapper/
 *       removeProtocolMapper/setAttribute} plus the
 *       {@code ModelToRepresentation.toRepresentation} getters
 *       ({@code getName/getDescription/getProtocol/getProtocolMappersStream/
 *       getAttributes}, verified ClientScopeAdapter.java:76-300) NEVER call the
 *       overridable {@code getId()} internally, so the seam cannot fire
 *       prematurely; a fire-once guard additionally protects against the second
 *       {@code getId()} at line 135 and any defensive re-entrancy.
 *
 *       <h3>Lossiness verdict — NO accumulation needed (unlike role)</h3>
 *       {@code ModelToRepresentation.toRepresentation(ClientScopeModel)}
 *       (verified, KC 26.5.5 ModelToRepresentation.java:821-835) serializes
 *       EVERYTHING {@code IgaReplayDispatcher.replayCreateClientScope} consumes:
 *       {@code setId}(823), {@code setName}(824), {@code setDescription}(825),
 *       {@code setProtocol}(826), {@code setProtocolMappers}(827-830 — via
 *       {@code toRepresentation(ProtocolMapperModel)} which copies the FULL
 *       config map, ModelToRepresentation.java:985-992) and
 *       {@code setAttributes}(832). Replay does
 *       {@code RepresentationToModel.createClientScope(realm, rep)} which reads
 *       exactly name(719)/description(720)/protocol(721)/protocolMappers+config
 *       (722-728)/attributes(732-734) — a faithful round-trip with the snapshot
 *       alone, so (in contrast to role's dropped composites) there is nothing
 *       to intercept-and-merge. The {@code CREATE_CLIENT_SCOPE} change request
 *       (with full {@code REP_JSON}) is written in a SEPARATE transaction
 *       ({@code runJobInTransaction}, survives the rollback), the REQUEST tx is
 *       marked rollback-only and {@link IgaPendingApprovalException} is thrown
 *       (→ HTTP 202 + Location). The scratch scope, its protocol mappers and
 *       its attributes die with the rolled-back request transaction —
 *       identical lifecycle proof to {@link IgaClientAdapter#updateClient}.
 *       Replay is UNCHANGED.</li>
 * </ul>
 */
public class IgaClientScopeAdapter extends ClientScopeAdapter {

    private static final Logger log = Logger.getLogger(IgaClientScopeAdapter.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final KeycloakSession igaSession;

    /**
     * When true this adapter wraps a scratch entity mid-{@code
     * createClientScope}; the only special behaviour is {@link #getId()} (the
     * terminal snapshot-and-throw seam). All other per-setter/per-mapper
     * interception is bypassed so Keycloak's builder applies the full
     * representation to the real model.
     */
    private final boolean captureMode;

    /** Fire-once guard: only the first getId() at createClientScope:133 emits. */
    private boolean captureEmitted = false;

    public IgaClientScopeAdapter(RealmModel realm, EntityManager em, KeycloakSession session, ClientScopeEntity clientScopeEntity) {
        this(realm, em, session, clientScopeEntity, false);
    }

    public IgaClientScopeAdapter(RealmModel realm, EntityManager em, KeycloakSession session,
                                 ClientScopeEntity clientScopeEntity, boolean captureMode) {
        super(realm, em, session, clientScopeEntity);
        this.igaSession = session;
        this.captureMode = captureMode;
    }

    private IgaChangeRequestService getService() {
        EntityManager em = igaSession.getProvider(JpaConnectionProvider.class).getEntityManager();
        return new IgaChangeRequestService(em, igaSession);
    }

    private boolean isIgaActive() {
        // In capture mode every per-setter/per-mapper override falls straight
        // through to the real ClientScopeAdapter so
        // RepresentationToModel.createClientScope builds the complete model;
        // interception is concentrated at the single terminal seam getId().
        if (captureMode) return false;
        IgaChangeRequestService service = getService();
        if (!service.isIgaEnabled(realm)) return false;
        Object replay = igaSession.getAttribute("IGA_REPLAY_ACTIVE");
        return !"true".equals(replay);
    }

    // -------------------------------------------------------------------------
    // Terminal seam for CREATE_CLIENT_SCOPE (capture mode only):
    // clientScope.getId().
    //
    // ClientScopesResource.createClientScope calls clientScope.getId() at line
    // 133 (adminEvent.resourcePath) and 135 (Response.created) — the FIRST and
    // only getId() calls the resource makes after the conditional-only
    // RepresentationToModel.createClientScope (lines 715-740) returns. So when
    // this fires the model is fully built (name, description, protocol,
    // protocol mappers WITH full config, attributes) for ALL scopes. We
    // snapshot it via ModelToRepresentation.toRepresentation(ClientScopeModel)
    // — which serializes ALL of those fields (no accumulation needed, unlike
    // role's composites) — and emit the CREATE_CLIENT_SCOPE CR + rollback-only
    // + throw exactly as IgaRoleAdapter#getName / IgaClientAdapter#updateClient.
    // -------------------------------------------------------------------------
    @Override
    public String getId() {
        if (!captureMode || captureEmitted) {
            return super.getId();
        }
        // Arm the fire-once guard BEFORE any further model/service call so the
        // emit path (which itself reads the model) cannot re-enter this seam,
        // and the second getId() at createClientScope:135 falls through.
        captureEmitted = true;

        String scopeId = super.getId();
        String scopeName = super.getName();

        // Base (and only) snapshot via Keycloak's own serializer: id, name,
        // description, protocol, protocolMappers (WITH full config) AND
        // attributes — KC 26.5.5 ModelToRepresentation:821-835. Unlike
        // RoleModel (composites dropped) this is COMPLETE, so there is nothing
        // to reconstruct from intercepted calls.
        ClientScopeRepresentation rep = ModelToRepresentation.toRepresentation(this);
        // Pin identity so replay recreates the scope with the SAME UUID the
        // admin's create flow allocated (replayCreateClientScope also re-pins
        // from the row ID, but a self-consistent rep avoids ambiguity).
        rep.setId(scopeId);
        if (scopeName != null) rep.setName(scopeName);

        String repJson;
        try {
            repJson = MAPPER.writeValueAsString(rep);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new RuntimeException(
                    "IGA capture CREATE_CLIENT_SCOPE: failed to serialize captured "
                    + "ClientScopeRepresentation for scope=" + scopeName, e);
        }

        int mappers = rep.getProtocolMappers() == null ? 0 : rep.getProtocolMappers().size();
        int attrs = rep.getAttributes() == null ? 0 : rep.getAttributes().size();
        log.infof("IGA capture CREATE_CLIENT_SCOPE: full-rep path for scope=%s (uuid=%s, "
                + "protocol=%s, protocolMappers=%d, attributes=%d, %d chars) captured at the "
                + "model-layer terminal seam (ClientScopesResource.createClientScope#getId); CR "
                + "written in a separate tx, request tx marked rollback-only so the scratch "
                + "scope + its mappers + attributes are discarded (zero rows persisted at "
                + "draft); full config will replay on commit",
                scopeName, scopeId, rep.getProtocol(), mappers, attrs, repJson.length());

        // rowsJson contract (must match IgaReplayDispatcher.replayCreateClientScope:
        // ID = scope UUID, NAME = scope name, REALM_ID = realm UUID,
        // PROTOCOL/DESCRIPTION = bare-create safety-net fields (replay prefers
        // the REP_JSON full-config path when REP_JSON is present), REP_JSON =
        // the full ClientScopeRepresentation JSON).
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("ID", scopeId);
        row.put("NAME", scopeName);
        row.put("REALM_ID", realm.getId());
        if (rep.getProtocol() != null) row.put("PROTOCOL", rep.getProtocol());
        if (rep.getDescription() != null) row.put("DESCRIPTION", rep.getDescription());
        row.put("REP_JSON", repJson);

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
    // In capture mode these fall straight through to the real ClientScopeAdapter
    // so RepresentationToModel.createClientScope's attribute loop builds the
    // complete model (the snapshot at getId() then serializes them faithfully).
    // In inline mode the one-pending-CR-per-entity rule applies.
    //
    // Note: client scope CRs reuse the entityType "CLIENT_SCOPE" for the
    // pending-CR check so we do not collide with same-id-but-different-entity
    // rows (the `findPending` query filters by entity type).
    // -------------------------------------------------------------------------

    @Override
    public void setAttribute(String name, String value) {
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
    // In capture mode these fall straight through to the real ClientScopeAdapter
    // so RepresentationToModel.createClientScope's removeProtocolMapper /
    // addProtocolMapper loop builds the complete model (the snapshot at getId()
    // then serializes the mappers WITH full config faithfully). In inline mode
    // they record targeted delta CRs; the parent entity_type is "CLIENT_SCOPE"
    // so IgaScopeResolver can resolve scope rules against the parent scope
    // attributes when one is configured.
    // -------------------------------------------------------------------------

    @Override
    public ProtocolMapperModel addProtocolMapper(ProtocolMapperModel model) {
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
