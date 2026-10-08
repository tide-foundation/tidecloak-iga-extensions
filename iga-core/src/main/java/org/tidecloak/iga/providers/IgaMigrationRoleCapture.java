package org.tidecloak.iga.providers;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.idm.RoleRepresentation;
import org.tidecloak.iga.services.IgaMigrationContext;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Boot-safe migration-capture seam for governed role/composite creates that Keycloak's
 * own model-version migration performs on an IGA-enabled realm.
 *
 * <h2>The problem</h2>
 * Keycloak 26.7.0's {@code MigrateTo26_7_0.addOrganizationAdminRoles} adds three
 * org-admin roles ({@code view-/manage-/query-organizations}) to admin clients on every
 * realm, plus composite edges ({@code realm-admin ⊃ each}, {@code admin ⊃ each},
 * {@code view ⊃ query}). Those writes resolve to the IGA-wrapped provider/adapter. If
 * they are applied DIRECTLY during migration they land UNSIGNED (null {@code attestation}
 * column); the login-time attestation closure then fails closed and nobody can log in.
 * If they are captured through the ordinary REST seam they throw
 * {@code IgaPendingApprovalException}/{@code IgaConflictException}, which is uncaught at
 * boot and aborts startup.
 *
 * <h2>The design</h2>
 * During migration, do NOT apply these governed creates. Capture each as a pending
 * change request WITHOUT persisting the role/composite:
 * <ul>
 *   <li>{@code addRole} → a {@code CREATE_ROLE} CR + a {@link MigrationCaptureRoleModel}
 *       phantom handle that persists no {@code RoleEntity} (invisible to the login
 *       closure at first boot).</li>
 *   <li>{@code existingRole.addCompositeRole(newRole)} → a dependent {@code ADD_COMPOSITE}
 *       CR (via {@link #captureComposite}) keyed on the existing parent, depending on the
 *       child's {@code CREATE_ROLE} CR so commit ordering is enforced.</li>
 *   <li>The migrator's null-guarded {@code view ⊃ query} edge is skipped by core (its
 *       {@code getRole} re-query returns null for the phantom); {@link #captureClientRole}
 *       re-creates it as a dependent {@code ADD_COMPOSITE} CR.</li>
 * </ul>
 * An admin later approves+commits the CR set through the normal multiAdmin ceremony;
 * {@code IgaReplayDispatcher.replayCreateRole} stamps {@code RoleEntity.attestation} and
 * the composite edges — proper VVK signature, no new crypto.
 *
 * <h2>Invariants</h2>
 * All CRs are written on a SEPARATE {@code runJobInTransaction} session so the inner tx
 * commits independently while the outer migration tx (and its stored-version bump) run to
 * completion. Nothing here throws and nothing calls {@code setRollbackOnly()} — the
 * migration MUST finish. Idempotency/dedup via {@code findMigrationCreateRoleCr}
 * (by role name + owning client, so a re-run with freshly-generated ids does not pile up
 * duplicates) and {@code findDuplicatePending} for the composite edges.
 */
public final class IgaMigrationRoleCapture {

    private static final Logger log = Logger.getLogger(IgaMigrationRoleCapture.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Author stamped on migration-authored CRs. Not an admin identity; it carries no
     *  authorization and never satisfies a commit quorum — the CR still needs the realm's
     *  ordinary multiAdmin approvals before {@code IgaReplayDispatcher} applies it. */
    private static final String REQUESTED_BY = "system";

    // 26.7.0 addOrganizationAdminRoles / addQueryCompositeRoles role names.
    private static final String VIEW_ORGANIZATIONS_ROLE = "view-organizations";
    private static final String QUERY_ORGANIZATIONS_ROLE = "query-organizations";

    private final KeycloakSession session;

    public IgaMigrationRoleCapture(KeycloakSession session) {
        this.session = session;
    }

    /**
     * True iff a governed role/composite create should be captured (rather than applied)
     * right now: we are on Keycloak's model-migration call path AND IGA is enabled for the
     * realm. When IGA is off, migration writes apply directly (there is nothing to sign).
     */
    public static boolean isActive(KeycloakSession session, RealmModel realm) {
        if (realm == null) {
            return false;
        }
        if (!IgaMigrationContext.isOnKeycloakMigrationPath()) {
            return false;
        }
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        return new IgaChangeRequestService(em, session).isIgaEnabled(realm);
    }

    // -------------------------------------------------------------------------
    // SITE 1 — role create (IgaRealmProvider.addRealmRole / addClientRole)
    // -------------------------------------------------------------------------

    /** Capture a REALM role create (defensive — no known 26.7.0 realm-role migration write,
     *  but any future migrator that adds a realm role on an IGA-on realm is covered). */
    public RoleModel captureRealmRole(RealmModel realm, String id, String name) {
        String roleId = (id != null) ? id : KeycloakModelUtils.generateId();
        MigrationCaptureRoleModel phantom = new MigrationCaptureRoleModel(
                this, realm, realm, roleId, name, /*clientRole=*/false,
                /*containerId=*/realm.getId(), /*clientUuid=*/null, /*clientId=*/null);
        writeCreateRoleCrIfAbsent(realm, phantom);
        return phantom;
    }

    /** Capture a CLIENT role create (the 26.7.0 org-admin roles land here). */
    public RoleModel captureClientRole(RealmModel realm, ClientModel client, String id, String name) {
        String roleId = (id != null) ? id : KeycloakModelUtils.generateId();
        MigrationCaptureRoleModel phantom = new MigrationCaptureRoleModel(
                this, realm, client, roleId, name, /*clientRole=*/true,
                /*containerId=*/client.getId(), /*clientUuid=*/client.getId(),
                /*clientId=*/client.getClientId());
        writeCreateRoleCrIfAbsent(realm, phantom);

        // Core's addQueryCompositeRoles wires view-organizations ⊃ query-organizations,
        // but it re-queries both via ClientModel.getRole(...), which returns null for our
        // not-yet-committed phantoms, so core skips it. query-organizations is created
        // AFTER view-organizations in the migrator, so by the time we capture query the
        // view CR already exists — re-create the edge as a dependent ADD_COMPOSITE CR.
        if (QUERY_ORGANIZATIONS_ROLE.equals(name)) {
            synthesizeViewQueryComposite(realm, client.getId(), roleId);
        }
        return phantom;
    }

    /**
     * Fold a phantom's later {@code setDescription}/{@code setAttribute} mutations back into
     * its pending {@code CREATE_ROLE} CR so the captured representation matches what vanilla
     * Keycloak would have persisted. No-op if the CR was deduped away (a prior pending CR for
     * the same role name already exists).
     */
    void onRoleUpdated(MigrationCaptureRoleModel phantom) {
        RealmModel realm = phantom.realm();
        String roleId = phantom.getId();
        runInSideTransaction(realm, (newRealm, service) -> {
            IgaChangeRequestEntity cr = service.findPending(newRealm.getId(), "ROLE", roleId);
            if (cr != null && "CREATE_ROLE".equals(cr.getActionType())) {
                service.updateRows(cr.getId(), List.of(buildCreateRoleRow(phantom)));
            }
        });
    }

    // -------------------------------------------------------------------------
    // SITE 2 — composite add on an EXISTING role (IgaRoleAdapter.addCompositeRole)
    // -------------------------------------------------------------------------

    /**
     * Capture {@code parent.addCompositeRole(child)} performed by the migrator on an EXISTING
     * (committed) parent role — e.g. {@code realm-admin}/{@code admin} gaining a new org-admin
     * role. Recorded as an {@code ADD_COMPOSITE} CR (role name/id as DATA, never an FK) that
     * depends on the child's {@code CREATE_ROLE} CR so the child exists before the edge is
     * replayed. Never persists a {@code CompositeRoleEntity} (the phantom child has no
     * {@code RoleEntity}; a direct persist would FK-fail at the outer flush).
     */
    public void captureComposite(RealmModel realm, RoleModel parent, RoleModel child) {
        if (parent == null || child == null) {
            return;
        }
        String parentId = parent.getId();
        String childId = child.getId();
        if (parentId == null || childId == null) {
            return;
        }
        runInSideTransaction(realm, (newRealm, service) -> {
            List<Map<String, Object>> rows = List.of(compositeRow(parentId, childId));
            if (service.findDuplicatePending(newRealm.getId(), "ROLE", parentId, "ADD_COMPOSITE", rows) != null) {
                log.debugf("IGA migration-capture ADD_COMPOSITE already pending: parent=%s child=%s — skip",
                        parentId, childId);
                return;
            }
            List<String> dependsOn = null;
            IgaChangeRequestEntity childCreate = service.findPending(newRealm.getId(), "ROLE", childId);
            if (childCreate != null && "CREATE_ROLE".equals(childCreate.getActionType())) {
                dependsOn = List.of(childCreate.getId());
            }
            service.create(newRealm, "ROLE", parentId, "ADD_COMPOSITE", rows, REQUESTED_BY, dependsOn);
            log.infof("IGA migration-capture: ADD_COMPOSITE parent=%s child=%s (dependsOn=%s)",
                    parentId, childId, dependsOn);
        });
    }

    // -------------------------------------------------------------------------
    // Internals
    // -------------------------------------------------------------------------

    private void writeCreateRoleCrIfAbsent(RealmModel realm, MigrationCaptureRoleModel phantom) {
        runInSideTransaction(realm, (newRealm, service) -> {
            IgaChangeRequestEntity existing = findMigrationCreateRoleCr(
                    service, newRealm.getId(), phantom.clientUuid(), phantom.getName());
            if (existing != null) {
                log.debugf("IGA migration-capture CREATE_ROLE already pending for name=%s "
                        + "(client=%s) — skip (idempotent)", phantom.getName(), phantom.clientUuid());
                return;
            }
            service.create(newRealm, "ROLE", phantom.getId(), "CREATE_ROLE",
                    List.of(buildCreateRoleRow(phantom)), REQUESTED_BY);
            log.infof("IGA migration-capture: CREATE_ROLE name=%s (uuid=%s, clientRole=%s, client=%s) "
                    + "— captured as pending CR, no RoleEntity persisted",
                    phantom.getName(), phantom.getId(), phantom.clientRole(), phantom.clientId());
        });
    }

    private void synthesizeViewQueryComposite(RealmModel realm, String clientUuid, String queryRoleId) {
        runInSideTransaction(realm, (newRealm, service) -> {
            IgaChangeRequestEntity viewCreate = findMigrationCreateRoleCr(
                    service, newRealm.getId(), clientUuid, VIEW_ORGANIZATIONS_ROLE);
            if (viewCreate == null) {
                return; // view-organizations not captured on this client — nothing to wire
            }
            String viewRoleId = viewCreate.getEntityId();
            List<Map<String, Object>> rows = List.of(compositeRow(viewRoleId, queryRoleId));
            if (service.findDuplicatePending(newRealm.getId(), "ROLE", viewRoleId, "ADD_COMPOSITE", rows) != null) {
                return;
            }
            List<String> dependsOn = new ArrayList<>();
            dependsOn.add(viewCreate.getId());
            IgaChangeRequestEntity queryCreate = service.findPending(newRealm.getId(), "ROLE", queryRoleId);
            if (queryCreate != null && "CREATE_ROLE".equals(queryCreate.getActionType())) {
                dependsOn.add(queryCreate.getId());
            }
            service.create(newRealm, "ROLE", viewRoleId, "ADD_COMPOSITE", rows, REQUESTED_BY, dependsOn);
            log.infof("IGA migration-capture: ADD_COMPOSITE view-organizations(%s) ⊃ query-organizations(%s) "
                    + "(dependsOn=%s)", viewRoleId, queryRoleId, dependsOn);
        });
    }

    /**
     * Find a pending {@code CREATE_ROLE} CR by role NAME + owning client UUID (not by the
     * freshly-generated role id), so a migration re-run — which allocates new ids — resolves
     * the already-captured CR instead of piling up a duplicate.
     */
    private IgaChangeRequestEntity findMigrationCreateRoleCr(IgaChangeRequestService service,
                                                             String realmId, String clientUuid,
                                                             String roleName) {
        for (IgaChangeRequestEntity cr : service.findPendingByAction(realmId, "ROLE", "CREATE_ROLE")) {
            for (Map<String, Object> row : service.parseRows(cr.getRowsJson())) {
                if (roleName.equals(row.get("NAME"))
                        && java.util.Objects.equals(clientUuid, row.get("CLIENT_UUID"))) {
                    return cr;
                }
            }
        }
        return null;
    }

    private Map<String, Object> buildCreateRoleRow(MigrationCaptureRoleModel phantom) {
        RoleRepresentation rep = new RoleRepresentation();
        rep.setId(phantom.getId());
        rep.setName(phantom.getName());
        rep.setDescription(phantom.description());
        rep.setClientRole(phantom.clientRole());
        rep.setContainerId(phantom.getContainerId());
        if (!phantom.attributesView().isEmpty()) {
            Map<String, List<String>> attrs = new LinkedHashMap<>();
            phantom.attributesView().forEach((k, v) -> attrs.put(k, new ArrayList<>(v)));
            rep.setAttributes(attrs);
        }
        // NOTE: no composites folded here. The only phantom-parent edge in this migration
        // (view ⊃ query) is emitted as its own dependent ADD_COMPOSITE CR (see
        // synthesizeViewQueryComposite), keeping replay uniform with the existing
        // IgaReplayDispatcher.replayCreateRole / addCompositeDirect contract.
        String repJson;
        try {
            repJson = MAPPER.writeValueAsString(rep);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new RuntimeException("IGA migration-capture: failed to serialize RoleRepresentation "
                    + "for role=" + phantom.getName(), e);
        }

        // Row contract must match IgaReplayDispatcher.rebuildCreateRoleFromRow / resolveClient:
        // ID, NAME, REALM_ID, CLIENT_ROLE, and for client roles CLIENT_UUID/CLIENT_ID/
        // CLIENT_REALM_CONSTRAINT, plus REP_JSON.
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("ID", phantom.getId());
        row.put("NAME", phantom.getName());
        row.put("REALM_ID", phantom.realm().getId());
        row.put("CLIENT_ROLE", phantom.clientRole());
        if (phantom.clientRole()) {
            if (phantom.clientUuid() != null) row.put("CLIENT_UUID", phantom.clientUuid());
            if (phantom.clientId() != null) row.put("CLIENT_ID", phantom.clientId());
            row.put("CLIENT_REALM_CONSTRAINT", phantom.realm().getId());
        }
        row.put("REP_JSON", repJson);
        return row;
    }

    private static Map<String, Object> compositeRow(String parentId, String childId) {
        // Row contract must match IgaReplayDispatcher.addCompositeDirect (resolves both by id).
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("COMPOSITE", parentId);
        row.put("CHILD_ROLE", childId);
        return row;
    }

    @FunctionalInterface
    private interface CaptureJob {
        void run(RealmModel realm, IgaChangeRequestService service);
    }

    /**
     * Run a CR write on a SEPARATE Keycloak session/transaction so it commits independently
     * of the outer migration transaction (whose stored-version bump must still commit).
     */
    private void runInSideTransaction(RealmModel realm, CaptureJob job) {
        KeycloakModelUtils.runJobInTransaction(session.getKeycloakSessionFactory(), newSession -> {
            RealmModel newRealm = newSession.realms().getRealm(realm.getId());
            if (newRealm == null) {
                return;
            }
            EntityManager newEm = newSession.getProvider(JpaConnectionProvider.class).getEntityManager();
            IgaChangeRequestService service = new IgaChangeRequestService(newEm, newSession);
            job.run(newRealm, service);
        });
    }
}
