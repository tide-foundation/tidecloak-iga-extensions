package org.tidecloak.iga.providers;

import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.tidecloak.iga.services.IgaMigrationContext;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.jpa.RoleAdapter;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.persistence.EntityManager;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Wraps RoleAdapter and intercepts composite role / attribute operations for IGA.
 *
 * <h2>Two modes (same design as {@link IgaClientAdapter} / {@link IgaGroupAdapter})</h2>
 * <ul>
 *   <li><b>Inline mode</b> ({@code captureMode == false}, default): wraps an
 *       already-approved, already-persisted role returned by
 *       {@code IgaRealmProvider.getRoleById}. Mutating calls
 *       (addCompositeRole/removeCompositeRole/setAttribute/…) record targeted
 *       delta change requests — the original inline interception behaviour,
 *       unchanged.</li>
 *   <li><b>Capture mode</b> ({@code captureMode == true}): wraps a
 *       <em>scratch</em> {@link RoleEntity} that
 *       {@code IgaRealmProvider.addRealmRole}/{@code addClientRole} just
 *       persisted. Per-setter interception is bypassed so Keycloak's
 *       {@code RoleContainerResource.createRole} can apply the COMPLETE incoming
 *       {@link RoleRepresentation} (description, attributes AND composites) to
 *       the real model.
 *
 *       <h3>Why there is no clean single terminal seam (and why
 *       enlist-synchronization is unsound here)</h3>
 *       KC 26.5.5 {@code RoleContainerResource.createRole} (verified, lines
 *       159-227):
 *       <pre>
 *       167  RoleModel role = roleContainer.addRole(rep.getName());   // → IgaRealmProvider.add{Realm,Client}Role
 *       168  role.setDescription(rep.getDescription());               // UNCONDITIONAL, but NOT last
 *       170-175  for (...) role.setAttribute(k, v);                   // conditional (attributes != null)
 *       177  rep.setId(role.getId());
 *       186-222  if (rep.isComposite() &amp;&amp; rep.getComposites()!=null) // conditional
 *                  ... role.addCompositeRole(child) ...               // conditional, last WHEN present
 *       225  adminEvent...resourcePath(uriInfo, role.getName())...    // role.getName() — UNCONDITIONAL, LAST
 *       227  return Response.created(... role.getName() ...)          // role.getName() again
 *       </pre>
 *       Unlike {@code RepresentationToModel.createClient} (terminal
 *       {@code updateClient()}) or {@code GroupResource.updateGroup} (terminal
 *       {@code setDescription()}), <b>there is NO unconditional last
 *       <i>mutating</i> model call for role</b>: {@code setDescription} fires
 *       first, the attribute loop and composite loop are both optional, and the
 *       composite loop (last when present) is conditional. A request-completion
 *       enlist-synchronization was considered (the design doc's
 *       {@code DefaultKeycloakTransactionManager#enlistAfterCompletion} idea)
 *       but is UNSOUND in KC 26.5.5: {@code DefaultKeycloakTransactionManager
 *       #commit()} commits the main {@code
 *       transactions} list (which holds the request {@code JpaKeycloakTransaction}
 *       enlisted by {@code DefaultJpaConnectionProviderFactory}) FIRST and
 *       only then iterates {@code afterCompletion} — so an afterCompletion hook
 *       cannot veto the already-committed scratch role, and it also runs at
 *       session-close, far too late to turn the response into a 202.
 *
 *       <h3>Terminal seam chosen: {@code getName()} at createRole</h3>
 *       {@code role.getName()} (RoleContainerResource.createRole) is the FIRST
 *       and only {@code getName()} call in {@code createRole}
 *       and it is UNCONDITIONAL and strictly AFTER {@code setDescription},
 *       the attribute loop and the composite loop — i.e.
 *       the model is fully built when it fires, for BOTH composite and
 *       non-composite roles. It is therefore the exact role analogue of
 *       client's {@code updateClient()} / group's {@code setDescription()}.
 *       {@code RoleAdapter.setDescription/setAttribute/addCompositeRole}
 *       (verified) never call {@code getName()} internally, so the seam cannot
 *       fire prematurely; a once-guard additionally protects against any
 *       defensive re-entrancy and against the second {@code getName()} at line
 *       227.
 *
 *       <h3>What the seam does</h3>
 *       {@link #getName()} (capture mode, first call): snapshots the
 *       now-complete model into a {@link RoleRepresentation} via
 *       {@link ModelToRepresentation#toRepresentation(RoleModel)} (name,
 *       description, attributes, clientRole, containerId) and — because
 *       {@code ModelToRepresentation.toRepresentation(RoleModel)} sets only the
 *       {@code composite} boolean and NEVER {@code setComposites(...)}
 *       (verified, KC 26.5.5 ModelToRepresentation) — ALSO sets
 *       {@code setComposite(true)} + {@code setComposites(Composites{realm,
 *       client})} reconstructed from the {@link #addCompositeRole} calls this
 *       adapter intercepted. The {@code CREATE_ROLE} change request (with full
 *       {@code REP_JSON}) is written in a SEPARATE transaction
 *       ({@code runJobInTransaction}, survives the rollback), the REQUEST tx is
 *       marked rollback-only and {@link IgaPendingApprovalException} is thrown
 *       (→ HTTP 202 + Location). The scratch role and its composite links die
 *       with the rolled-back request transaction — identical lifecycle proof to
 *       {@link IgaClientAdapter#updateClient} (DefaultKeycloakSession#close →
 *       closeTransactionManager → {@code getRollbackOnly()? rollback():
 *       commit()}). {@code IgaReplayDispatcher.replayCreateRole} deserializes
 *       exactly this {@code RoleRepresentation} and rebuilds
 *       description+attributes+composites under {@code IGA_REPLAY_ACTIVE}, so
 *       the round-trip is faithful and replay is UNCHANGED.</li>
 * </ul>
 */
public class IgaRoleAdapter extends RoleAdapter {

    private static final Logger log = Logger.getLogger(IgaRoleAdapter.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final KeycloakSession session;

    /**
     * When true this adapter wraps a scratch entity mid-{@code createRole} and
     * the only special behaviour is {@link #getName()} (the terminal
     * snapshot-and-throw seam) plus recording composites on
     * {@link #addCompositeRole}; all other per-setter interception is bypassed
     * so Keycloak's builder applies the full representation to the real model.
     */
    private final boolean captureMode;

    /** For a captured client role: owning client UUID / human clientId (replay rowsJson contract). Null for realm roles. */
    private final String captureClientUuid;
    private final String captureClientId;

    /**
     * Composites observed via {@link #addCompositeRole} during capture, in
     * insertion order, reconstructed into {@code RoleRepresentation.Composites}
     * at the terminal seam exactly as {@code IgaReplayDispatcher.replayCreateRole}
     * expects to consume them.
     */
    private final Set<String> capturedRealmComposites = new LinkedHashSet<>();
    private final Map<String, List<String>> capturedClientComposites = new LinkedHashMap<>();

    /** Fire-once guard: only the first getName() at createRole emits. */
    private boolean captureEmitted = false;

    /**
     * True when this capture-mode adapter was created on the
     * {@code partialImport} {@code RepresentationToModel.importRoles}/
     * {@code createRole} path ({@code IgaRealmProvider.add{Realm,Client}Role}
     * registered it with {@link IgaImportMode#registerImportRole}). The
     * {@code CREATE_ROLE} row is then harvested ONCE at batch-emit time by
     * {@link #buildImportRolePendingCr()} (after {@code importRoles} has
     * applied description/attributes and the second-pass {@code addComposites}),
     * so {@link #getName()} is a pure pass-through for this role (no per-entity
     * accumulate/throw — and {@code createRole}/{@code importRoles} never calls
     * {@code getName()} on the returned adapter anyway). Defaults false → the
     * single-entity admin-create path is byte-unchanged.
     */
    private boolean importDeferred = false;

    public IgaRoleAdapter(KeycloakSession session, RealmModel realm, EntityManager em, RoleEntity role) {
        this(session, realm, em, role, false, null, null);
    }

    public IgaRoleAdapter(KeycloakSession session, RealmModel realm, EntityManager em, RoleEntity role,
                          boolean captureMode, String captureClientUuid, String captureClientId) {
        super(session, realm, em, role);
        this.session = session;
        this.captureMode = captureMode;
        this.captureClientUuid = captureClientUuid;
        this.captureClientId = captureClientId;
    }

    /**
     * Mark this capture-mode adapter for partialImport deferred-harvest. Called
     * once by {@code IgaRealmProvider.add{Realm,Client}Role} immediately after
     * {@link IgaImportMode#registerImportRole}.
     */
    void markImportDeferred() {
        this.importDeferred = true;
    }

    private IgaChangeRequestService getService() {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        return new IgaChangeRequestService(em, session);
    }

    private boolean isIgaActive() {
        // In capture mode every per-setter override falls straight through to
        // the real RoleAdapter so RoleContainerResource.createRole builds the
        // complete model; interception is concentrated at the single terminal
        // seam getName() (plus composite RECORDING in addCompositeRole) instead.
        if (captureMode) return false;
        IgaChangeRequestService service = getService();
        if (!service.isIgaEnabled(realm)) return false;
        // Scoped vendor/system provisioning bypass (see
        // IgaChangeRequestService.IGA_VENDOR_PROVISIONING): apply directly, no capture.
        if (service.isVendorProvisioning()) return false;
        // TIDECLOAK: Keycloak's own model migration must apply directly — never
        // captured as a governance CR (would 409 on a realm with a pending CR
        // and abort boot). See IgaMigrationContext.
        if (IgaMigrationContext.isOnKeycloakMigrationPath()) return false;
        Object replay = session.getAttribute("IGA_REPLAY_ACTIVE");
        return !"true".equals(replay);
    }

    // -------------------------------------------------------------------------
    // Terminal seam for CREATE_ROLE (capture mode only): role.getName().
    //
    // RoleContainerResource.createRole calls role.getName()
    // (adminEvent.resourcePath, then Response.created) — the FIRST and only
    // getName() in the method, UNCONDITIONAL and strictly AFTER setDescription,
    // the attribute loop and the composite loop. So
    // when this fires the model is fully built for BOTH composite and
    // non-composite roles. We snapshot it, fold the recorded composites in, and
    // emit the CREATE_ROLE CR + rollback-only + throw exactly as
    // IgaClientAdapter#updateClient.
    // -------------------------------------------------------------------------
    @Override
    public String getName() {
        if (!captureMode || captureEmitted) {
            return super.getName();
        }
        // partialImport deferred-harvest. When this capture-mode
        // adapter was created on the RepresentationToModel.importRoles/
        // createRole path (IgaRealmProvider.add{Realm,Client}Role registered it
        // with IgaImportMode), the CREATE_ROLE row is harvested ONCE at
        // batch-emit time by buildImportRolePendingCr() AFTER importRoles has
        // applied description/attributes and the second-pass addComposites.
        // RepresentationToModel.createRole/importRoles never calls getName() on
        // the returned adapter anyway, so this guard is belt-and-braces: keep
        // getName() a pure pass-through for an import-registered role (no
        // accumulate, no throw — the batch-emit prepare-tx owns the veto). The
        // single-entity admin-create branch below is byte-unchanged.
        if (importDeferred) {
            return super.getName();
        }
        // Arm the fire-once guard BEFORE any further model/service call so the
        // emit path (which may itself read the model) cannot re-enter this seam.
        captureEmitted = true;

        Map<String, Object> row = buildCapturedRoleRow();
        String roleId = (String) row.get("ID");
        String roleName = (String) row.get("NAME");

        // partialImport batch governance. If a partialImport frame is
        // on the stack (and IGA on, not replay) accumulate this fully-built CR
        // and RETURN NORMALLY (getName() yields the real name): NO per-entity
        // CR write, NO setRollbackOnly, NO throw. The batch-emit prepare-tx
        // writes all accumulated CRs at once and rolls the scratch import back.
        // This is the ONLY behavioural change vs Phases 1–3 — the
        // single-entity branch below is byte-unchanged.
        if (IgaImportMode.isImportMode(session, realm)) {
            IgaImportMode.accumulate(session, realm, "ROLE", roleId,
                    "CREATE_ROLE", List.of(row), null);
            return roleName;
        }

        String[] crIdHolder = new String[1];
        KeycloakModelUtils.runJobInTransaction(session.getKeycloakSessionFactory(), newSession -> {
            RealmModel newRealm = newSession.realms().getRealm(realm.getId());
            EntityManager newEm = newSession.getProvider(JpaConnectionProvider.class).getEntityManager();
            IgaChangeRequestService newService = new IgaChangeRequestService(newEm, newSession);
            crIdHolder[0] = newService.create(newRealm, "ROLE", roleId,
                    "CREATE_ROLE", List.of(row), null).getId();
        });

        // Mark the REQUEST KeycloakTransaction rollback-only so
        // DefaultKeycloakSession#close() rolls back (not commits) and the
        // scratch role + composite links are discarded. The CR survives because
        // it was written on a separate session/tx by runJobInTransaction. Same
        // idiom and lifecycle proof as IgaClientAdapter#updateClient
        // (KeycloakErrorHandler#getResponse uses the very same setRollbackOnly
        // -then-return-a-response idiom).
        session.getTransactionManager().setRollbackOnly();

        throw new IgaPendingApprovalException(crIdHolder[0], "ROLE", "CREATE_ROLE");
    }

    /**
     * Build the {@code CREATE_ROLE} CR row — the SINGLE source of truth shared
     * by the single-entity terminal seam ({@link #getName()}) and the
     * partialImport deferred-harvest path
     * ({@link #buildImportRolePendingCr()}). Identical rep/row contract in both
     * cases, so {@code IgaReplayDispatcher.replayCreateRole} is byte-unchanged.
     * NO side effects (no CR write, no throw, no rollback-only). Reads the live
     * (pass-through) scratch model + the composites recorded via
     * {@link #addCompositeRole}.
     */
    private Map<String, Object> buildCapturedRoleRow() {
        String roleId = super.getId();
        String roleName = super.getName();
        boolean clientRole = super.isClientRole();

        // Base snapshot via Keycloak's own serializer: name, description,
        // attributes, clientRole, containerId. NOTE: this sets only the
        // `composite` boolean (role.isComposite()) and NEVER setComposites(...)
        // (KC 26.5.5 ModelToRepresentation) — so we MUST reconstruct
        // the composites from the addCompositeRole calls we intercepted.
        RoleRepresentation rep = ModelToRepresentation.toRepresentation(this);
        // Pin identity so replay recreates the role with the SAME UUID the
        // create flow allocated (replayCreateRole also re-pins from the row ID,
        // but a self-consistent rep avoids ambiguity).
        rep.setId(roleId);
        rep.setName(roleName);
        rep.setClientRole(clientRole);

        boolean composite = !capturedRealmComposites.isEmpty() || !capturedClientComposites.isEmpty();
        if (composite) {
            // Exactly the structure IgaReplayDispatcher.replayCreateRole
            // consumes: it guards on `rep.isComposite() && rep.getComposites()
            // != null`, reads composites.getRealm() (Set<String> of REALM ROLE
            // NAMES, resolved via realm.getRole(name)) and
            // composites.getClient() (Map<HUMAN clientId, List<role name>>,
            // resolved via realm.getClientByClientId(clientId).getRole(name)).
            rep.setComposite(true);
            RoleRepresentation.Composites composites = new RoleRepresentation.Composites();
            if (!capturedRealmComposites.isEmpty()) {
                composites.setRealm(new LinkedHashSet<>(capturedRealmComposites));
            }
            if (!capturedClientComposites.isEmpty()) {
                Map<String, List<String>> clientMap = new LinkedHashMap<>();
                for (Map.Entry<String, List<String>> e : capturedClientComposites.entrySet()) {
                    clientMap.put(e.getKey(), new ArrayList<>(e.getValue()));
                }
                composites.setClient(clientMap);
            }
            rep.setComposites(composites);
        }

        String repJson;
        try {
            repJson = MAPPER.writeValueAsString(rep);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new RuntimeException(
                    "IGA capture CREATE_ROLE: failed to serialize captured RoleRepresentation "
                    + "for role=" + roleName, e);
        }

        int attrs = rep.getAttributes() == null ? 0 : rep.getAttributes().size();
        int realmComp = capturedRealmComposites.size();
        int clientComp = capturedClientComposites.values().stream().mapToInt(List::size).sum();
        log.infof("IGA capture CREATE_ROLE: full-rep path for role=%s (uuid=%s, clientRole=%s, "
                + "attributes=%d, realmComposites=%d, clientComposites=%d, %d chars) captured at "
                + "the model-layer terminal seam (RoleContainerResource.createRole#getName / "
                + "partialImport deferred-harvest); full config will replay on commit",
                roleName, roleId, clientRole, attrs, realmComp, clientComp, repJson.length());

        // rowsJson contract (must match IgaReplayDispatcher.replayCreateRole +
        // resolveClient): ID = role UUID, NAME = role name, REALM_ID = realm
        // UUID, CLIENT_ROLE = boolean (replay branches on it). For client roles
        // CLIENT_UUID = owning client UUID (resolveClient prefers it), CLIENT_ID
        // = human clientId. REP_JSON = the full RoleRepresentation JSON.
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("ID", roleId);
        row.put("NAME", roleName);
        row.put("REALM_ID", realm.getId());
        row.put("CLIENT_ROLE", clientRole);
        if (clientRole) {
            if (captureClientUuid != null) row.put("CLIENT_UUID", captureClientUuid);
            if (captureClientId != null) row.put("CLIENT_ID", captureClientId);
            row.put("CLIENT_REALM_CONSTRAINT", realm.getId());
        }
        row.put("REP_JSON", repJson);
        return row;
    }

    /**
     * partialImport batch path. Build this role's
     * {@code CREATE_ROLE} {@link IgaImportMode.PendingCr} from the live
     * (pass-through) scratch model + recorded composites. Called by
     * {@link IgaImportMode.BatchEmitTransaction#commit} AFTER
     * {@code RepresentationToModel.importRoles} has applied
     * description/attributes and the second-pass {@code addComposites} (so the
     * model + recorded composites are complete) and BEFORE the scratch JPA tx
     * commits. Uses the SAME {@link #buildCapturedRoleRow()} contract as the
     * single-entity seam — replay is identical, {@code IgaReplayDispatcher}
     * byte-unchanged. NO throw, NO rollback-only here — the batch-emit tx owns
     * that.
     */
    IgaImportMode.PendingCr buildImportRolePendingCr() {
        if (!captureMode || !importDeferred) {
            return null;
        }
        Map<String, Object> row = buildCapturedRoleRow();
        String roleId = (String) row.get("ID");
        log.infof("IGA multi-entity ACCUM: CREATE_ROLE %s (uuid=%s, clientRole=%s) "
                + "— row harvested at batch emit from the partialImport "
                + "RepresentationToModel.importRoles/createRole path",
                row.get("NAME"), roleId, row.get("CLIENT_ROLE"));
        return new IgaImportMode.PendingCr("ROLE", roleId, "CREATE_ROLE",
                List.of(row), null);
    }

    @Override
    public void addCompositeRole(RoleModel role) {
        if (captureMode) {
            // Record the composite child's identity EXACTLY as
            // IgaReplayDispatcher.replayCreateRole resolves it: realm composites
            // by realm-role NAME (realm.getRole(name)); client composites keyed
            // by the owning client's HUMAN clientId →
            // realm.getClientByClientId(clientId).getRole(name). RoleModel
            // exposes isClientRole(), getName(), and getContainerId() (clientId
            // UUID for client roles); we resolve the human clientId from it.
            if (role != null) {
                if (role.isClientRole()) {
                    String childClientId = null;
                    try {
                        ClientModel owning = realm.getClientById(role.getContainerId());
                        if (owning != null) childClientId = owning.getClientId();
                    } catch (RuntimeException ignored) {
                        // fall through: cannot resolve owning client; skip this
                        // composite from REP_JSON (the real link is still
                        // applied on the scratch model via super, so behaviour
                        // is no worse than a bare create for this one link).
                    }
                    if (childClientId != null) {
                        capturedClientComposites
                                .computeIfAbsent(childClientId, k -> new ArrayList<>())
                                .add(role.getName());
                    }
                } else {
                    capturedRealmComposites.add(role.getName());
                }
            }
            // Pass through so the real scratch model gets the composite link
            // (kept consistent with the snapshot; discarded with the rollback).
            super.addCompositeRole(role);
            return;
        }
        if (!isIgaActive()) {
            super.addCompositeRole(role);
            return;
        }
        IgaChangeRequestService service = getService();
        String roleId = getId();
        service.create(realm, "ROLE", roleId, "ADD_COMPOSITE",
                List.of(Map.of("COMPOSITE", roleId, "CHILD_ROLE", role.getId())),
                null);
    }

    @Override
    public void removeCompositeRole(RoleModel role) {
        if (captureMode) {
            // createRole only ADDs composites; if KC ever removes one mid-create
            // keep the recorded set consistent, then pass through.
            if (role != null) {
                if (role.isClientRole()) {
                    try {
                        ClientModel owning = realm.getClientById(role.getContainerId());
                        if (owning != null) {
                            List<String> names = capturedClientComposites.get(owning.getClientId());
                            if (names != null) {
                                names.remove(role.getName());
                                if (names.isEmpty()) {
                                    capturedClientComposites.remove(owning.getClientId());
                                }
                            }
                        }
                    } catch (RuntimeException ignored) {
                    }
                } else {
                    capturedRealmComposites.remove(role.getName());
                }
            }
            super.removeCompositeRole(role);
            return;
        }
        if (!isIgaActive()) {
            super.removeCompositeRole(role);
            return;
        }
        IgaChangeRequestService service = getService();
        String roleId = getId();
        service.create(realm, "ROLE", roleId, "REMOVE_COMPOSITE",
                List.of(Map.of("COMPOSITE", roleId, "CHILD_ROLE", role.getId())),
                null);
    }

    // -------------------------------------------------------------------------
    // Attribute interception (ROLE_ATTRIBUTE).
    //
    // In capture mode these fall straight through to the real RoleAdapter so
    // RoleContainerResource.createRole's attribute loop builds the complete
    // model (the snapshot at getName() then serializes them faithfully). In
    // inline mode the one-pending-CR-per-entity rule applies; concurrent
    // attribute writes on the same role while a CR is pending throw
    // IgaConflictException (409).
    // -------------------------------------------------------------------------

    @Override
    public void setSingleAttribute(String name, String value) {
        if (!isIgaActive()) {
            super.setSingleAttribute(name, value);
            return;
        }
        // No-op guard (see IgaClientAdapter.setAttribute): KC re-applies attributes
        // unconditionally on every PUT; suppress the phantom SET_ROLE_ATTRIBUTE CR
        // when the single value is unchanged.
        if (java.util.Objects.equals(value, super.getFirstAttribute(name))) {
            return;
        }
        IgaChangeRequestService service = getService();
        String roleId = getId();
        checkNoPendingCr(service, roleId);
        Map<String, Object> row = new HashMap<>();
        row.put("ROLE_ID", roleId);
        row.put("NAME", name);
        row.put("VALUE", value);
        service.create(realm, "ROLE", roleId, "SET_ROLE_ATTRIBUTE",
                List.of(row), null);
    }

    @Override
    public void setAttribute(String name, List<String> values) {
        if (!isIgaActive()) {
            super.setAttribute(name, values);
            return;
        }
        // No-op guard: suppress the phantom SET_ROLE_ATTRIBUTE CR when the incoming
        // value list equals the current stored list (null-tolerant, order-insensitive).
        if (sameAttrValues(values, super.getAttributeStream(name))) {
            return;
        }
        IgaChangeRequestService service = getService();
        String roleId = getId();
        checkNoPendingCr(service, roleId);
        List<Map<String, Object>> rows = new ArrayList<>();
        if (values != null) {
            for (String v : values) {
                Map<String, Object> row = new HashMap<>();
                row.put("ROLE_ID", roleId);
                row.put("NAME", name);
                row.put("VALUE", v);
                rows.add(row);
            }
        }
        if (rows.isEmpty()) {
            Map<String, Object> row = new HashMap<>();
            row.put("ROLE_ID", roleId);
            row.put("NAME", name);
            row.put("VALUE", null);
            rows.add(row);
        }
        service.create(realm, "ROLE", roleId, "SET_ROLE_ATTRIBUTE", rows, null);
    }

    @Override
    public void removeAttribute(String name) {
        if (!isIgaActive()) {
            super.removeAttribute(name);
            return;
        }
        // No-op guard: removing an attribute that is already absent is not a
        // change; suppress the phantom REMOVE_ROLE_ATTRIBUTE CR.
        if (super.getFirstAttribute(name) == null) {
            return;
        }
        IgaChangeRequestService service = getService();
        String roleId = getId();
        checkNoPendingCr(service, roleId);
        Map<String, Object> row = new HashMap<>();
        row.put("ROLE_ID", roleId);
        row.put("NAME", name);
        service.create(realm, "ROLE", roleId, "REMOVE_ROLE_ATTRIBUTE",
                List.of(row), null);
    }

    /**
     * Null-tolerant, order-insensitive equality between an incoming attribute
     * value list and the current stored values (as a stream). Mirrors
     * {@code IgaClientAdapter.sameStringSet}: a null/empty incoming list equals an
     * absent/empty stored value, so re-applying the current values never looks
     * like a change.
     */
    private static boolean sameAttrValues(List<String> incoming, java.util.stream.Stream<String> current) {
        java.util.Set<String> a = incoming == null ? java.util.Collections.emptySet()
                : new java.util.HashSet<>(incoming);
        java.util.Set<String> b = current == null ? java.util.Collections.emptySet()
                : current.collect(java.util.stream.Collectors.toSet());
        return a.equals(b);
    }

    private void checkNoPendingCr(IgaChangeRequestService service, String roleId) {
        var existing = service.findPending(realm.getId(), "ROLE", roleId);
        if (existing != null) {
            throw new IgaConflictException(existing.getId());
        }
    }
}
