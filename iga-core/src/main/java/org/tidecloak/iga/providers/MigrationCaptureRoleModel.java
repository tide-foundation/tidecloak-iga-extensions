package org.tidecloak.iga.providers;

import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleContainerModel;
import org.keycloak.models.RoleModel;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * In-memory, NON-persisting {@link RoleModel} handle returned to Keycloak's own
 * model-version migration when a governed role create is intercepted on an
 * IGA-enabled realm (see {@link IgaMigrationRoleCapture}).
 *
 * <h2>Why this is not a {@code RoleAdapter}</h2>
 * The migration-capture design requires that the create be recorded as a pending
 * {@code CREATE_ROLE} change request while NO {@code RoleEntity} is written to the
 * database — a role that exists only as a pending CR is invisible to the login
 * attestation closure (which walks the live committed model), so first-boot login
 * still works; an admin later approves the CR through the normal multiAdmin
 * ceremony which stamps the attestation. A real {@code RoleAdapter} is backed by a
 * {@code RoleEntity}; even a transient one risks being flushed into the outer
 * migration transaction's persistence context ({@code RealmMigration.migrate} runs
 * {@code EntityManagers.flush(session, true)} once per realm), which would turn the
 * phantom into a real, un-attested row. This class holds NO entity at all, so there
 * is nothing the outer EM can ever persist.
 *
 * <h2>What the migrator does with this handle</h2>
 * {@code MigrationUtils.addAdminRole} calls {@code client.addRole(name)} (→ here),
 * then {@code role.setDescription(...)}, then hands the role to
 * {@code existingAdminRole.addCompositeRole(role)} (captured separately at the
 * {@link IgaRoleAdapter#addCompositeRole} seam). {@code setDescription} /
 * {@code setAttribute} mutations are folded back into the pending CR's REP_JSON via
 * {@link IgaMigrationRoleCapture#onRoleUpdated} so the captured representation matches
 * what vanilla Keycloak would have persisted. Composite-add ON this phantom is a
 * no-op: the only such edge in the 26.7.0 migrator (view ⊃ query) is re-queried by
 * {@code ClientModel.getRole(...)}, which returns null for a phantom, so the migrator
 * skips it and {@link IgaMigrationRoleCapture} re-creates that edge as a dependent
 * {@code ADD_COMPOSITE} CR instead.
 */
final class MigrationCaptureRoleModel implements RoleModel {

    private final IgaMigrationRoleCapture capture;
    private final RealmModel realm;
    private final RoleContainerModel container;
    private final String id;
    private final boolean clientRole;
    private final String containerId;
    private final String clientUuid;
    private final String clientId;

    private String name;
    private String description;
    private final Map<String, List<String>> attributes = new LinkedHashMap<>();

    MigrationCaptureRoleModel(IgaMigrationRoleCapture capture, RealmModel realm,
                              RoleContainerModel container, String id, String name,
                              boolean clientRole, String containerId,
                              String clientUuid, String clientId) {
        this.capture = capture;
        this.realm = realm;
        this.container = container;
        this.id = id;
        this.name = name;
        this.clientRole = clientRole;
        this.containerId = containerId;
        this.clientUuid = clientUuid;
        this.clientId = clientId;
    }

    RealmModel realm() { return realm; }
    boolean clientRole() { return clientRole; }
    String clientUuid() { return clientUuid; }
    String clientId() { return clientId; }
    String description() { return description; }
    Map<String, List<String>> attributesView() { return attributes; }

    @Override
    public String getId() { return id; }

    @Override
    public String getName() { return name; }

    @Override
    public void setName(String name) {
        this.name = name;
        capture.onRoleUpdated(this);
    }

    @Override
    public String getDescription() { return description; }

    @Override
    public void setDescription(String description) {
        this.description = description;
        capture.onRoleUpdated(this);
    }

    @Override
    public boolean isComposite() { return false; }

    @Override
    public void addCompositeRole(RoleModel role) {
        // No-op by design. Core never reaches this on a phantom: the sole
        // phantom-parent edge in the 26.7.0 migrator (view ⊃ query) is guarded by
        // a ClientModel.getRole(...) re-query that returns null for phantoms, so
        // the migrator skips it; IgaMigrationRoleCapture re-creates it as a
        // dependent ADD_COMPOSITE CR. Persisting anything here would defeat the
        // "no committed row during migration" invariant.
    }

    @Override
    public void removeCompositeRole(RoleModel role) {
        // No-op — see addCompositeRole.
    }

    @Override
    public Stream<RoleModel> getCompositesStream() { return Stream.empty(); }

    @Override
    public Stream<RoleModel> getCompositesStream(String search, Integer first, Integer max) {
        return Stream.empty();
    }

    @Override
    public boolean isClientRole() { return clientRole; }

    @Override
    public String getContainerId() { return containerId; }

    @Override
    public RoleContainerModel getContainer() { return container; }

    @Override
    public boolean hasRole(RoleModel role) { return this.equals(role); }

    @Override
    public void setSingleAttribute(String name, String value) {
        List<String> values = new ArrayList<>();
        values.add(value);
        attributes.put(name, values);
        capture.onRoleUpdated(this);
    }

    @Override
    public void setAttribute(String name, List<String> values) {
        attributes.put(name, values == null ? new ArrayList<>() : new ArrayList<>(values));
        capture.onRoleUpdated(this);
    }

    @Override
    public void removeAttribute(String name) {
        attributes.remove(name);
        capture.onRoleUpdated(this);
    }

    @Override
    public String getFirstAttribute(String name) {
        List<String> values = attributes.get(name);
        return (values == null || values.isEmpty()) ? null : values.get(0);
    }

    @Override
    public Stream<String> getAttributeStream(String name) {
        List<String> values = attributes.get(name);
        return values == null ? Stream.empty() : values.stream();
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        return new LinkedHashMap<>(attributes);
    }

    // Container may be a ClientModel (client role) or a RealmModel (realm role).
    @SuppressWarnings("unused")
    ClientModel containerAsClient() {
        return (container instanceof ClientModel c) ? c : null;
    }
}
