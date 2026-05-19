package org.tidecloak.iga.providers;

import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.jpa.GroupAdapter;
import org.keycloak.models.jpa.entities.GroupEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.persistence.EntityManager;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Wraps GroupAdapter and intercepts role mapping operations for IGA.
 *
 * <h2>Two modes (same design as {@link IgaClientAdapter})</h2>
 * <ul>
 *   <li><b>Inline mode</b> ({@code captureMode == false}, default): wraps an
 *       already-approved, already-persisted group. Mutating calls record
 *       targeted delta change requests / inline-throw — unchanged behaviour.</li>
 *   <li><b>Capture mode</b> ({@code captureMode == true}): wraps a
 *       <em>scratch</em> {@link GroupEntity} that
 *       {@code IgaRealmProvider.createGroup} just persisted. Per-setter
 *       interception is bypassed so Keycloak's
 *       {@code GroupResource.updateGroup(rep, model, realm, session)} can apply
 *       the COMPLETE incoming {@link GroupRepresentation} (name, attributes,
 *       description) to the real model. The LAST mutation that path makes,
 *       {@code GroupModel.setDescription(rep.getDescription())}
 *       (KC 26.5.5 {@code GroupResource.updateGroup}, line 300 — called
 *       unconditionally for BOTH the top-level
 *       {@code GroupsResource.addTopLevelGroup} (line 221) and child
 *       {@code GroupResource.addChild} (line 251) create paths, strictly AFTER
 *       the optional {@code setName} (line 280) and the attribute
 *       set/remove loop (lines 288-298)), is the <b>terminal seam</b>:
 *       {@link #setDescription(String)} snapshots the now-complete model into a
 *       {@link GroupRepresentation} via
 *       {@link ModelToRepresentation#toRepresentation(GroupModel, boolean)},
 *       writes the {@code CREATE_GROUP} change request (with full
 *       {@code REP_JSON}) in a SEPARATE transaction, marks the REQUEST tx
 *       rollback-only and throws {@link IgaPendingApprovalException} → HTTP 202.
 *       The scratch entity is discarded by the request-tx rollback exactly as in
 *       {@link IgaClientAdapter}. {@code IgaReplayDispatcher.replayCreateGroup}
 *       deserializes this same {@code GroupRepresentation} and applies
 *       {@code rep.getAttributes()} + {@code rep.getDescription()} under
 *       {@code IGA_REPLAY_ACTIVE}, so the round-trip is faithful (replay does
 *       NOT recurse into subGroups — each sub-group is its own child-create
 *       request / CR — matching {@code ModelToRepresentation.toRepresentation}
 *       which only emits this group's own fields).</li>
 * </ul>
 */
public class IgaGroupAdapter extends GroupAdapter {

    private static final Logger log = Logger.getLogger(IgaGroupAdapter.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final KeycloakSession session;

    /**
     * When true this adapter wraps a scratch entity mid-{@code createGroup} and
     * the only special behaviour is {@link #setDescription(String)} (the
     * terminal snapshot-and-throw seam); all per-setter interception is
     * bypassed so Keycloak's builder applies the full representation.
     */
    private final boolean captureMode;

    /**
     * Phase 4 — true when this capture-mode adapter was created on the
     * {@code partialImport} {@code RepresentationToModel.importGroup} path
     * ({@code IgaRealmProvider.createGroup} registered it with
     * {@link IgaImportMode#registerImportGroup}). The {@code CREATE_GROUP} row
     * is then harvested ONCE at batch-emit time by
     * {@link #buildImportGroupPendingCr()} (after {@code importGroup} has
     * applied every conditional setter), so {@link #setDescription(String)} is
     * inert for this group (no per-entity accumulate/throw). Defaults false →
     * the single-entity admin-create path is byte-unchanged.
     */
    private boolean importDeferred = false;

    public IgaGroupAdapter(KeycloakSession session, RealmModel realm, EntityManager em, GroupEntity group) {
        this(session, realm, em, group, false);
    }

    public IgaGroupAdapter(KeycloakSession session, RealmModel realm, EntityManager em,
                           GroupEntity group, boolean captureMode) {
        super(session, realm, em, group);
        this.session = session;
        this.captureMode = captureMode;
    }

    /**
     * Mark this capture-mode adapter for partialImport deferred-harvest. Called
     * once by {@code IgaRealmProvider.createGroup} immediately after
     * {@link IgaImportMode#registerImportGroup}.
     */
    void markImportDeferred() {
        this.importDeferred = true;
    }

    /**
     * Build the {@code CREATE_GROUP} CR row — the SINGLE source of truth shared
     * by the single-entity terminal seam ({@link #setDescription(String)}) and
     * the Phase 4 partialImport deferred-harvest path
     * ({@link #buildImportGroupPendingCr()}). Identical rep/row contract in
     * both cases, so {@code IgaReplayDispatcher.replayCreateGroup} is
     * byte-unchanged. NO side effects (no CR write, no throw, no
     * rollback-only).
     *
     * @param description the description to fold into REP_JSON. The
     *                     single-entity seam passes the inbound argument (it
     *                     fires BEFORE super.setDescription); the import
     *                     deferred-harvest passes the live model value
     *                     (importGroup already applied it via the pass-through
     *                     setter).
     */
    private Map<String, Object> buildCapturedGroupRow(String description) {
        GroupRepresentation rep = ModelToRepresentation.toRepresentation(this, true);
        // Pin identity so replay recreates the group with the SAME UUID the
        // create flow allocated (replay also re-pins from the row ID, but a
        // self-consistent rep avoids ambiguity).
        String groupId = getId();
        rep.setId(groupId);
        rep.setDescription(description);

        String repJson;
        try {
            repJson = MAPPER.writeValueAsString(rep);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new RuntimeException(
                    "IGA capture CREATE_GROUP: failed to serialize captured GroupRepresentation "
                    + "for group=" + getName(), e);
        }

        String parentId = getParentId();
        int attrs = rep.getAttributes() == null ? 0 : rep.getAttributes().size();
        log.infof("IGA capture CREATE_GROUP: full-rep path for group=%s (uuid=%s, parent=%s, "
                + "attributes=%d, %d chars) captured at the model-layer terminal seam "
                + "(GroupResource.updateGroup#setDescription / partialImport deferred-harvest); "
                + "full config will replay on commit",
                getName(), groupId, parentId, attrs, repJson.length());

        // rowsJson contract (must match IgaReplayDispatcher.replayCreateGroup):
        // ID = group UUID, NAME = group name, REALM_ID = realm UUID,
        // PARENT_GROUP = parent UUID (only for child groups),
        // REP_JSON = the full GroupRepresentation JSON.
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("ID", groupId);
        row.put("NAME", getName());
        row.put("REALM_ID", realm.getId());
        if (parentId != null) {
            row.put("PARENT_GROUP", parentId);
        }
        row.put("REP_JSON", repJson);
        return row;
    }

    /**
     * Phase 4 — partialImport batch path. Build this group's
     * {@code CREATE_GROUP} {@link IgaImportMode.PendingCr} from the live
     * (pass-through) scratch model. Called by
     * {@link IgaImportMode.BatchEmitTransaction#commit} AFTER
     * {@code RepresentationToModel.importGroup} has applied every conditional
     * {@code setDescription}/{@code setAttribute}/{@code grantRole} call (so
     * the model is complete) and BEFORE the scratch JPA tx commits. Uses the
     * SAME {@link #buildCapturedGroupRow(String)} contract as the single-entity
     * seam — replay is identical, {@code IgaReplayDispatcher} byte-unchanged.
     * NO throw, NO rollback-only here — the batch-emit tx owns that.
     */
    IgaImportMode.PendingCr buildImportGroupPendingCr() {
        if (!captureMode || !importDeferred) {
            return null;
        }
        // importGroup already applied the (possibly null) description via the
        // pass-through setter, so the live model value is authoritative.
        Map<String, Object> row = buildCapturedGroupRow(getDescription());
        String groupId = (String) row.get("ID");
        log.infof("IGA multi-entity ACCUM: CREATE_GROUP %s (uuid=%s) — row "
                + "harvested at batch emit from the partialImport "
                + "RepresentationToModel.importGroup path", row.get("NAME"),
                groupId);
        return new IgaImportMode.PendingCr("GROUP", groupId, "CREATE_GROUP",
                List.of(row), null);
    }

    private IgaChangeRequestService getService() {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        return new IgaChangeRequestService(em, session);
    }

    private boolean isIgaActive(RealmModel realm) {
        // In capture mode every per-setter override falls straight through to
        // the real GroupAdapter so GroupResource.updateGroup builds the
        // complete model; interception is concentrated at the single terminal
        // seam setDescription() instead.
        if (captureMode) return false;
        IgaChangeRequestService service = getService();
        if (!service.isIgaEnabled(realm)) return false;
        Object replay = session.getAttribute("IGA_REPLAY_ACTIVE");
        return !"true".equals(replay);
    }

    /**
     * Terminal seam for CREATE_GROUP (capture mode only).
     *
     * <p>{@code GroupResource.updateGroup} (KC 26.5.5,
     * {@code org.keycloak.services.resources.admin.GroupResource:300}) calls
     * {@code model.setDescription(rep.getDescription())} as its FINAL model
     * mutation, AFTER the optional {@code setName} (line 280) and the attribute
     * set/remove loop (lines 288-298). Both create entrypoints route here:
     * {@code GroupsResource.addTopLevelGroup} calls {@code realm.createGroup(name)}
     * then {@code GroupResource.updateGroup(rep, child, ...)} (line 221), and
     * {@code GroupResource.addChild} calls {@code realm.createGroup(name, parent)}
     * then {@code updateGroup(rep, child, ...)} (line 251). So when this fires
     * every admin-supplied group field is on the live model. We snapshot it to a
     * {@link GroupRepresentation} with Keycloak's own
     * {@link ModelToRepresentation#toRepresentation(GroupModel, boolean)}, fold
     * it into the {@code CREATE_GROUP} CR as {@code REP_JSON} (persisted in a
     * separate transaction so it survives the request-tx rollback) and throw
     * {@link IgaPendingApprovalException}. We deliberately do NOT call
     * {@code super.setDescription()} — nothing here is committed; after the CR
     * is written we mark the REQUEST transaction rollback-only so the scratch
     * group dies with it, exactly as documented in {@link IgaClientAdapter}.</p>
     */
    @Override
    public void setDescription(String description) {
        if (!captureMode) {
            super.setDescription(description);
            return;
        }

        // Phase 4 — partialImport deferred-harvest. When this capture-mode
        // adapter was created on the RepresentationToModel.importGroup path
        // (IgaRealmProvider.createGroup registered it with IgaImportMode), the
        // CREATE_GROUP row is harvested ONCE at batch-emit time by
        // buildImportGroupPendingCr() AFTER importGroup has applied the
        // conditional setDescription/setAttribute/grantRole calls. This seam
        // must then be inert (pass straight through to the real scratch model
        // exactly like inline mode would for a non-captured group) — it must
        // NOT accumulate (the batch harvest is the single source of truth, so
        // a row is emitted even when importGroup never calls setDescription)
        // and must NOT throw (the batch-emit prepare-tx owns the veto). The
        // single-entity admin-create branch below is byte-unchanged.
        if (importDeferred) {
            super.setDescription(description);
            return;
        }

        // The terminal seam fires BEFORE super.setDescription, so the model's
        // description has NOT been written yet; reflect the admin-supplied
        // argument into the snapshot. Single source of truth shared with the
        // import deferred-harvest path (which passes the live, already-applied
        // description) is buildCapturedGroupRow().
        Map<String, Object> row = buildCapturedGroupRow(description);
        String groupId = (String) row.get("ID");

        // Phase 4 — partialImport batch governance: accumulate + return
        // normally (NO per-entity CR/setRollbackOnly/throw). Sole behavioural
        // change vs Phases 1–3; the single-entity branch below is unchanged.
        if (IgaImportMode.isImportMode(session, realm)) {
            IgaImportMode.accumulate(session, realm, "GROUP", groupId,
                    "CREATE_GROUP", List.of(row), null);
            return;
        }

        String[] crIdHolder = new String[1];
        KeycloakModelUtils.runJobInTransaction(session.getKeycloakSessionFactory(), newSession -> {
            RealmModel newRealm = newSession.realms().getRealm(realm.getId());
            EntityManager newEm = newSession.getProvider(JpaConnectionProvider.class).getEntityManager();
            IgaChangeRequestService newService = new IgaChangeRequestService(newEm, newSession);
            crIdHolder[0] = newService.create(newRealm, "GROUP", groupId,
                    "CREATE_GROUP", List.of(row), null).getId();
        });

        // Mark the REQUEST KeycloakTransaction rollback-only so
        // DefaultKeycloakSession#close() rolls back (not commits) and the
        // scratch group entity is discarded. The CR survives because it was
        // written on a separate session/tx by runJobInTransaction. Same idiom
        // and lifecycle proof as IgaClientAdapter#updateClient.
        session.getTransactionManager().setRollbackOnly();

        throw new IgaPendingApprovalException(crIdHolder[0], "GROUP", "CREATE_GROUP");
    }

    @Override
    public void grantRole(RoleModel role) {
        if (!isIgaActive(realm)) {
            super.grantRole(role);
            return;
        }
        IgaChangeRequestService service = getService();
        String groupId = getId();
        service.create(realm, "GROUP", groupId, "GROUP_GRANT_ROLES",
                List.of(Map.of("GROUP", groupId, "ROLE", role.getId())),
                null);
    }

    @Override
    public void deleteRoleMapping(RoleModel role) {
        if (!isIgaActive(realm)) {
            super.deleteRoleMapping(role);
            return;
        }
        IgaChangeRequestService service = getService();
        String groupId = getId();
        service.create(realm, "GROUP", groupId, "GROUP_REVOKE_ROLES",
                List.of(Map.of("GROUP", groupId, "ROLE", role.getId())),
                null);
    }

    // -------------------------------------------------------------------------
    // Attribute interception (GROUP_ATTRIBUTE).
    //
    // The one-pending-CR-per-entity rule applies; consecutive attribute writes
    // on the same group while a CR is pending throw IgaConflictException (409).
    // -------------------------------------------------------------------------

    @Override
    public void setSingleAttribute(String name, String value) {
        if (!isIgaActive(realm)) {
            super.setSingleAttribute(name, value);
            return;
        }
        IgaChangeRequestService service = getService();
        String groupId = getId();
        checkNoPendingCr(service, groupId);
        Map<String, Object> row = new HashMap<>();
        row.put("GROUP_ID", groupId);
        row.put("NAME", name);
        row.put("VALUE", value);
        service.create(realm, "GROUP", groupId, "SET_GROUP_ATTRIBUTE",
                List.of(row), null);
    }

    @Override
    public void setAttribute(String name, List<String> values) {
        if (!isIgaActive(realm)) {
            super.setAttribute(name, values);
            return;
        }
        IgaChangeRequestService service = getService();
        String groupId = getId();
        checkNoPendingCr(service, groupId);
        List<Map<String, Object>> rows = new ArrayList<>();
        if (values != null) {
            for (String v : values) {
                Map<String, Object> row = new HashMap<>();
                row.put("GROUP_ID", groupId);
                row.put("NAME", name);
                row.put("VALUE", v);
                rows.add(row);
            }
        }
        if (rows.isEmpty()) {
            Map<String, Object> row = new HashMap<>();
            row.put("GROUP_ID", groupId);
            row.put("NAME", name);
            row.put("VALUE", null);
            rows.add(row);
        }
        service.create(realm, "GROUP", groupId, "SET_GROUP_ATTRIBUTE", rows, null);
    }

    @Override
    public void removeAttribute(String name) {
        if (!isIgaActive(realm)) {
            super.removeAttribute(name);
            return;
        }
        IgaChangeRequestService service = getService();
        String groupId = getId();
        checkNoPendingCr(service, groupId);
        Map<String, Object> row = new HashMap<>();
        row.put("GROUP_ID", groupId);
        row.put("NAME", name);
        service.create(realm, "GROUP", groupId, "REMOVE_GROUP_ATTRIBUTE",
                List.of(row), null);
    }

    private void checkNoPendingCr(IgaChangeRequestService service, String groupId) {
        var existing = service.findPending(realm.getId(), "GROUP", groupId);
        if (existing != null) {
            throw new IgaConflictException(existing.getId());
        }
    }
}
