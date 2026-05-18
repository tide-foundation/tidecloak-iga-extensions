package org.tidecloak.iga.providers;

import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.jpa.ClientAdapter;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.ClientRepresentation;

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
 *       {@code REP_JSON}) in a SEPARATE transaction, and throws
 *       {@link IgaPendingApprovalException} → HTTP 202. The scratch entity is
 *       never committed: the exception propagates out, the main Keycloak
 *       transaction is rolled back (the exact same rollback that already
 *       produced the 202 when the throw used to happen at {@code addClient}),
 *       so nothing the create flow touched reaches the DB. Because the throw
 *       happens LATE — after the full entity graph is built — there are no
 *       transient references at the (possible) auto-flush, which is precisely
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

    public IgaClientAdapter(RealmModel realm, EntityManager em, KeycloakSession session, ClientEntity clientEntity) {
        this(realm, em, session, clientEntity, false);
    }

    public IgaClientAdapter(RealmModel realm, EntityManager em, KeycloakSession session,
                            ClientEntity clientEntity, boolean captureMode) {
        super(realm, em, session, clientEntity);
        this.igaSession = session;
        this.captureMode = captureMode;
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
     * rolled back. Nothing here is committed — the scratch entity dies with the
     * rolled-back main transaction.</p>
     */
    @Override
    public void updateClient() {
        if (!captureMode) {
            super.updateClient();
            return;
        }

        ClientRepresentation rep = ModelToRepresentation.toRepresentation(this, igaSession);
        // Pin identity so replay recreates the client with the SAME UUID and
        // human clientId the admin's create flow allocated. (replay also
        // re-pins from the row's ID/CLIENT_ID, but keeping the rep self
        // consistent avoids any ambiguity.)
        String clientUuid = getId();
        rep.setId(clientUuid);
        rep.setClientId(getClientId());

        String repJson;
        try {
            repJson = MAPPER.writeValueAsString(rep);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new RuntimeException(
                    "IGA capture CREATE_CLIENT: failed to serialize captured ClientRepresentation "
                    + "for clientId=" + getClientId(), e);
        }

        int webOrigins = rep.getWebOrigins() == null ? 0 : rep.getWebOrigins().size();
        int redirectUris = rep.getRedirectUris() == null ? 0 : rep.getRedirectUris().size();
        log.infof("IGA capture CREATE_CLIENT: full-rep path for clientId=%s "
                + "(webOrigins=%d, redirectUris=%d, %d chars) captured at the model-layer "
                + "terminal seam (RepresentationToModel.createClient#updateClient); full config "
                + "will replay on commit", getClientId(), webOrigins, redirectUris, repJson.length());

        // rowsJson contract (must match IgaReplayDispatcher.replayCreateClient):
        // ID = own client UUID, CLIENT_ID = human clientId,
        // CLIENT_UUID = same UUID (referenced-client alias so replay's
        // resolveClient works uniformly), REALM_ID = realm UUID,
        // REP_JSON = the full ClientRepresentation JSON.
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("ID", clientUuid);
        row.put("CLIENT_UUID", clientUuid);
        row.put("CLIENT_ID", getClientId());
        row.put("REALM_ID", realm.getId());
        row.put("REP_JSON", repJson);

        String[] crIdHolder = new String[1];
        KeycloakModelUtils.runJobInTransaction(igaSession.getKeycloakSessionFactory(), newSession -> {
            RealmModel newRealm = newSession.realms().getRealm(realm.getId());
            EntityManager newEm = newSession.getProvider(JpaConnectionProvider.class).getEntityManager();
            IgaChangeRequestService newService = new IgaChangeRequestService(newEm, newSession);
            crIdHolder[0] = newService.create(newRealm, "CLIENT", clientUuid,
                    "CREATE_CLIENT", List.of(row), null).getId();
        });
        throw new IgaPendingApprovalException(crIdHolder[0], "CLIENT", "CREATE_CLIENT");
    }

    @Override
    public void addClientScope(ClientScopeModel scope, boolean defaultScope) {
        if (!isIgaActive()) {
            super.addClientScope(scope, defaultScope);
            return;
        }
        IgaChangeRequestService service = getService();
        // getId() returns the client's UUID primary key — NOT the human
        // clientId. rowsJson contract: CLIENT_UUID = uuid, CLIENT_ID = human.
        String clientUuid = getId();
        service.create(realm, "CLIENT", clientUuid, "ASSIGN_SCOPE",
                List.of(Map.of(
                        "CLIENT_UUID", clientUuid,
                        "CLIENT_ID", getClientId(),
                        "SCOPE_ID", scope.getId(),
                        "DEFAULT_SCOPE", defaultScope
                )),
                null);
    }

    @Override
    public void removeClientScope(ClientScopeModel scope) {
        if (!isIgaActive()) {
            super.removeClientScope(scope);
            return;
        }
        IgaChangeRequestService service = getService();
        String clientUuid = getId();
        service.create(realm, "CLIENT", clientUuid, "REMOVE_SCOPE",
                List.of(Map.of(
                        "CLIENT_UUID", clientUuid,
                        "CLIENT_ID", getClientId(),
                        "SCOPE_ID", scope.getId())),
                null);
    }

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
}
