package org.tidecloak.iga.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakTransaction;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.idm.ClientRepresentation;
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
 * Files the governed CREATE_CLIENT change request for the default
 * {@code tide-mcp-login} client on an IGA-enabled Tide realm.
 *
 * <p>The client exists only for Tide MCP server login: public, PKCE S256,
 * DPoP bound, redirect {@code http://localhost:18433/*}, enabled, no
 * {@code fullScopeAllowed}, and no roles. It keeps the realm default scopes.</p>
 *
 * <p>Creation goes through the normal CREATE_CLIENT capture path (a plain
 * {@link IgaChangeRequestService#create}), so it is subject to the same
 * approval gate as any other client. It does not use the vendor-provisioning
 * bypass. IGA-off realms are not handled here; the key-provider side creates
 * the client directly.</p>
 *
 * <p>The client id is deterministic per realm, so repeated calls (server
 * start, backfill re-runs) dedupe on the pending CR instead of filing a second
 * one. If a client with this clientId already exists, nothing is filed and the
 * caller gets {@link Outcome#CLIENT_EXISTS} so it can repair the client through
 * the normal governed setters.</p>
 */
public final class TideMcpClientProvisioner {

    private static final Logger log = Logger.getLogger(TideMcpClientProvisioner.class);

    /** Public client id of the Tide MCP login client. */
    public static final String TIDE_MCP_CLIENT_ID = "tide-mcp-login";

    /** The only redirect URI the Tide MCP server login accepts. */
    public static final String TIDE_MCP_REDIRECT_URI = "http://localhost:18433/*";

    /** Stock client scope the tide-mcp-login client must never carry. */
    public static final String ROLES_SCOPE_NAME = "roles";

    /** The Tide identity scope the client must have as a realm default before it is filed. */
    private static final String TIDE_CLAIMS_SCOPE_NAME = "tide-claims";

    private static final String ID_PREFIX = "tide-mcp-login|";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** What {@link #ensureTideMcpLoginClient} did. */
    public enum Outcome {
        /** Realm is not IGA-enabled. Nothing filed; the key-provider side creates the client directly. */
        IGA_OFF_SKIPPED,
        /** A client with clientId {@code tide-mcp-login} already exists. Nothing filed; caller repairs it. */
        CLIENT_EXISTS,
        /** A CREATE_CLIENT CR for this client is already PENDING. Nothing new filed. */
        CR_ALREADY_PENDING,
        /** A new CREATE_CLIENT CR was filed. */
        CR_FILED,
        /**
         * tide-claims is not committed yet (its scope or realm-default add is still
         * PENDING, or the scope does not exist). Nothing filed; call again later.
         */
        DEFERRED
    }

    /** Result of {@link #ensureTideMcpLoginClient}. */
    public static final class EnsureResult {
        private final Outcome outcome;
        private final String clientUuid;
        private final String crId;

        EnsureResult(Outcome outcome, String clientUuid, String crId) {
            this.outcome = outcome;
            this.clientUuid = clientUuid;
            this.crId = crId;
        }

        /** The outcome. Never null. */
        public Outcome getOutcome() { return outcome; }

        /**
         * The client UUID the CR targets (deterministic), or the existing client's
         * UUID for {@link Outcome#CLIENT_EXISTS}. Null for {@link Outcome#IGA_OFF_SKIPPED}.
         */
        public String getClientUuid() { return clientUuid; }

        /** The pending or newly filed CR id. Null unless the outcome is CR_FILED or CR_ALREADY_PENDING. */
        public String getCrId() { return crId; }

        @Override
        public String toString() {
            return "EnsureResult{outcome=" + outcome + ", clientUuid=" + clientUuid + ", crId=" + crId + "}";
        }
    }

    private final KeycloakSession session;
    private final IgaChangeRequestService service;

    public TideMcpClientProvisioner(KeycloakSession session, EntityManager em) {
        this.session = session;
        this.service = new IgaChangeRequestService(em, session);
    }

    /**
     * Deterministic UUID of the {@code tide-mcp-login} client in {@code realmId}.
     * Stable across runs, so it is the CR entity id and the dedupe key.
     */
    public static String deterministicClientId(String realmId) {
        return UUID.nameUUIDFromBytes(
                (ID_PREFIX + realmId).getBytes(StandardCharsets.UTF_8)).toString();
    }

    /**
     * Ensure the {@code tide-mcp-login} client is filed for {@code realm}.
     *
     * @param realm       the target realm
     * @param requestedBy the {@code REQUESTED_BY} stamp (use {@code "system"} for
     *                    startup and backfill calls)
     * @return what happened; see {@link Outcome}
     */
    public EnsureResult ensureTideMcpLoginClient(RealmModel realm, String requestedBy) {
        if (realm == null) {
            throw new IllegalArgumentException("ensureTideMcpLoginClient requires a non-null realm");
        }
        final String realmId = realm.getId();

        if (!service.isIgaEnabled(realm)) {
            log.infof("IGA tide-mcp-login: realm %s is not IGA-enabled; skipping (key-provider creates the client directly)",
                    realm.getName());
            return new EnsureResult(Outcome.IGA_OFF_SKIPPED, null, null);
        }

        final String clientUuid = deterministicClientId(realmId);

        ClientModel existing = realm.getClientByClientId(TIDE_MCP_CLIENT_ID);
        if (existing != null) {
            log.infof("IGA tide-mcp-login: client %s already exists in realm %s (id=%s); not filing, caller repairs",
                    TIDE_MCP_CLIENT_ID, realm.getName(), existing.getId());
            return new EnsureResult(Outcome.CLIENT_EXISTS, existing.getId(), null);
        }

        IgaChangeRequestEntity pending = service.findPending(realmId, IgaReplayExtension.ENTITY_TYPE_CLIENT, clientUuid);
        if (pending != null) {
            log.debugf("IGA tide-mcp-login: CREATE_CLIENT for %s already PENDING in realm %s (CR %s)",
                    TIDE_MCP_CLIENT_ID, realm.getName(), pending.getId());
            return new EnsureResult(Outcome.CR_ALREADY_PENDING, clientUuid, pending.getId());
        }

        // Defer only while a tide-claims CREATE_CLIENT_SCOPE or REALM_DEFAULT_SCOPE_ADD
        // is PENDING. The commit hook (onCommitted) and the startup pass re-run this.
        // A realm where tide-claims never exists is not blocked.
        String tideClaimsBlocker = tideClaimsBlockingCrId(realm);
        if (tideClaimsBlocker != null) {
            log.infof("IGA tide-mcp-login: deferring CREATE_CLIENT in realm %s; tide-claims CR %s is pending",
                    realm.getName(), tideClaimsBlocker);
            return new EnsureResult(Outcome.DEFERRED, clientUuid, tideClaimsBlocker);
        }

        Map<String, Object> row = buildCreateClientRow(realm, clientUuid);
        IgaChangeRequestEntity cr = service.create(realm, IgaReplayExtension.ENTITY_TYPE_CLIENT,
                clientUuid, "CREATE_CLIENT", List.of(row), requestedBy);
        log.infof("IGA tide-mcp-login: filed CREATE_CLIENT CR %s for %s in realm %s (clientUuid=%s)",
                cr.getId(), TIDE_MCP_CLIENT_ID, realm.getName(), clientUuid);
        return new EnsureResult(Outcome.CR_FILED, clientUuid, cr.getId());
    }

    /**
     * The PENDING tide-claims CR that blocks this client, or null when none is
     * pending. Checks the scope create first, then the realm-default add. The
     * scope id is the live scope when it exists, else the deterministic id.
     */
    private String tideClaimsBlockingCrId(RealmModel realm) {
        final String realmId = realm.getId();
        final String deterministicId = IgaSystemProvisioner.deterministicTideClaimsScopeId(realmId);
        IgaChangeRequestEntity pendingCreate = service.findPending(realmId,
                IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE, deterministicId);
        if (pendingCreate != null) return pendingCreate.getId();
        ClientScopeModel tc = findTideClaims(realm);
        final String scopeId = tc != null ? tc.getId() : deterministicId;
        for (IgaChangeRequestEntity cr :
                service.findPendingByAction(realmId, "REALM", "REALM_DEFAULT_SCOPE_ADD")) {
            if (rowsReferenceScope(cr, scopeId)) return cr.getId();
        }
        return null;
    }

    /**
     * Commit hook. Call after a CR has been replayed and marked APPROVED. When it
     * was the tide-claims scope create or its realm-default add, file the
     * tide-mcp-login CREATE_CLIENT once the request transaction has committed.
     *
     * <p>Mechanism: the work is registered with
     * {@code KeycloakTransactionManager.enlistAfterCompletion}, which runs it only
     * after the request transaction commits (never on rollback). It then runs in its
     * own transaction through {@code KeycloakModelUtils.runJobInTransaction}, so a
     * failure there cannot roll back the tide-claims commit. Failures are logged and
     * the startup pass retries.</p>
     *
     * @param session the request session the commit runs in
     * @param realm   the realm the CR belongs to
     * @param cr      the CR that was just committed
     */
    public static void onCommitted(KeycloakSession session, RealmModel realm, IgaChangeRequestEntity cr) {
        if (!isTideClaimsCr(realm, cr)) return;
        final KeycloakSessionFactory factory = session.getKeycloakSessionFactory();
        final String realmId = realm.getId();
        final String realmName = realm.getName();
        final String crId = cr.getId();
        session.getTransactionManager().enlistAfterCompletion(new AfterCommitHook() {
            @Override
            public void commit() {
                runCommittedHook(factory, realmId, realmName, crId);
            }
        });
    }

    private static void runCommittedHook(KeycloakSessionFactory factory, String realmId,
                                         String realmName, String crId) {
        try {
            KeycloakModelUtils.runJobInTransaction(factory, newSession -> {
                RealmModel fresh = newSession.realms().getRealm(realmId);
                if (fresh == null) return;
                EntityManager em = newSession.getProvider(JpaConnectionProvider.class).getEntityManager();
                EnsureResult result = new TideMcpClientProvisioner(newSession, em)
                        .ensureTideMcpLoginClient(fresh, "system");
                log.infof("IGA tide-mcp-login: commit hook for CR %s in realm %s -> %s",
                        crId, realmName, result.getOutcome());
            });
        } catch (RuntimeException e) {
            log.warnf(e, "IGA tide-mcp-login: commit hook failed for CR %s in realm %s; startup pass will retry",
                    crId, realmName);
        }
    }

    /** Only {@code commit()} matters; the rest of KeycloakTransaction is inert for an after-hook. */
    private abstract static class AfterCommitHook implements KeycloakTransaction {
        @Override public void begin() { }
        @Override public void rollback() { }
        @Override public void setRollbackOnly() { }
        @Override public boolean getRollbackOnly() { return false; }
        @Override public boolean isActive() { return true; }
    }

    private static boolean isTideClaimsCr(RealmModel realm, IgaChangeRequestEntity cr) {
        final String deterministicId = IgaSystemProvisioner.deterministicTideClaimsScopeId(realm.getId());
        if (IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE.equals(cr.getEntityType())
                && "CREATE_CLIENT_SCOPE".equals(cr.getActionType())) {
            return deterministicId.equals(cr.getEntityId());
        }
        if ("REALM_DEFAULT_SCOPE_ADD".equals(cr.getActionType())) {
            ClientScopeModel tc = findTideClaims(realm);
            return rowsReferenceScope(cr, deterministicId)
                    || (tc != null && rowsReferenceScope(cr, tc.getId()));
        }
        return false;
    }

    private static ClientScopeModel findTideClaims(RealmModel realm) {
        return realm.getClientScopesStream()
                .filter(s -> TIDE_CLAIMS_SCOPE_NAME.equals(s.getName()))
                .findFirst().orElse(null);
    }

    private static boolean rowsReferenceScope(IgaChangeRequestEntity cr, String scopeId) {
        if (cr.getRowsJson() == null) return false;
        try {
            for (JsonNode row : MAPPER.readTree(cr.getRowsJson())) {
                if (scopeId.equals(row.path("SCOPE_ID").asText())) return true;
            }
        } catch (JsonProcessingException e) {
            log.warnf("IGA tide-mcp-login: unreadable ROWS_JSON on CR %s; treating as not referencing tide-claims",
                    cr.getId());
        }
        return false;
    }

    /**
     * Build the CREATE_CLIENT row. The shape matches the row the normal capture
     * path produces (ID, CLIENT_UUID, CLIENT_ID, REALM_ID, REP_JSON), so
     * IgaReplayDispatcher.rebuildCreateClientFromRow consumes it unchanged.
     */
    private Map<String, Object> buildCreateClientRow(RealmModel realm, String clientUuid) {
        ClientRepresentation rep = new ClientRepresentation();
        rep.setId(clientUuid);
        rep.setClientId(TIDE_MCP_CLIENT_ID);
        rep.setName(TIDE_MCP_CLIENT_ID);
        rep.setEnabled(true);
        rep.setPublicClient(true);
        rep.setProtocol("openid-connect");
        rep.setStandardFlowEnabled(true);
        rep.setImplicitFlowEnabled(false);
        rep.setDirectAccessGrantsEnabled(false);
        rep.setServiceAccountsEnabled(false);
        rep.setFullScopeAllowed(false);
        rep.setRedirectUris(List.of(TIDE_MCP_REDIRECT_URI));

        // Keep the realm defaults, as stock client creation does, except "roles".
        // Replay goes through RepresentationToModel.createClient, which only
        // attaches scopes named in the REP, so they have to be listed here.
        List<String> defaults = new ArrayList<>();
        realm.getDefaultClientScopesStream(true).map(ClientScopeModel::getName)
                .filter(n -> !ROLES_SCOPE_NAME.equals(n)).forEach(defaults::add);
        List<String> optional = new ArrayList<>();
        realm.getDefaultClientScopesStream(false).map(ClientScopeModel::getName)
                .filter(n -> !ROLES_SCOPE_NAME.equals(n)).forEach(optional::add);
        rep.setDefaultClientScopes(defaults);
        rep.setOptionalClientScopes(optional);

        Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put("pkce.code.challenge.method", "S256");
        attributes.put("dpop.bound.access.tokens", "true");
        rep.setAttributes(attributes);

        String repJson;
        try {
            repJson = MAPPER.writeValueAsString(rep);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(
                    "tide-mcp-login: failed to serialize ClientRepresentation for realm " + realm.getName(), e);
        }

        Map<String, Object> row = new LinkedHashMap<>();
        row.put("ID", clientUuid);
        row.put("CLIENT_UUID", clientUuid);
        row.put("CLIENT_ID", TIDE_MCP_CLIENT_ID);
        row.put("REALM_ID", realm.getId());
        row.put("REP_JSON", repJson);
        return row;
    }
}
