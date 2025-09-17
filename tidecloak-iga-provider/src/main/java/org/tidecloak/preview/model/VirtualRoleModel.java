package org.tidecloak.preview.model;

import org.keycloak.models.ClientModel;
import org.keycloak.models.RoleContainerModel;
import org.keycloak.models.RoleModel;

import java.util.*;
import java.util.stream.Stream;

/**
 * Minimal virtual role that compiles across multiple Keycloak RoleModel API variants.
 * - Implements legacy hasRole(RoleModel)
 * - Implements newer getAttributeStream(String)
 * - Avoids @Override on version-variant methods
 */
public class VirtualRoleModel implements RoleModel {

    private final String id;
    private String name;
    private final RoleContainerModel container;
    private String description;
    private final Map<String, List<String>> attributes = new HashMap<>();

    public VirtualRoleModel(String id, String name, RoleContainerModel container) {
        this.id = id;
        this.name = name;
        this.container = container;
    }

    // ---- identity ----
    public String getId() { return id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    // ---- composites (none for a virtual role) ----
    public boolean isComposite() { return false; }
    public void addCompositeRole(RoleModel role) { /* no-op */ }
    public void removeCompositeRole(RoleModel role) { /* no-op */ }
    public Stream<RoleModel> getCompositesStream() { return Stream.empty(); }

    // Some KC versions declare this overload; harmless if extra.
    public Stream<RoleModel> getCompositesStream(String search, Integer first, Integer max) {
        return Stream.empty();
    }

    // ---- container ----
    public boolean isClientRole() { return container instanceof ClientModel; }
    public String getContainerId() { return container.getId(); }
    public RoleContainerModel getContainer() { return container; }

    // ---- description ----
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    // ---- attributes ----
    public Map<String, List<String>> getAttributes() { return attributes; }

    public List<String> getAttribute(String name) {
        return attributes.getOrDefault(name, List.of());
    }

    // Present on newer KC versions. Safe to include without @Override.
    public Stream<String> getAttributeStream(String name) {
        return getAttribute(name).stream();
    }

    public void setAttribute(String name, List<String> values) {
        attributes.put(name, values == null ? new ArrayList<>() : new ArrayList<>(values));
    }

    public void setSingleAttribute(String name, String value) {
        attributes.put(name, value == null ? new ArrayList<>() : new ArrayList<>(List.of(value)));
    }

    public void removeAttribute(String name) { attributes.remove(name); }

    // ---- legacy API (older KC) ----
    /** Some RoleModel versions require this method. Implement a sensible equality check. */
    public boolean hasRole(RoleModel role) {
        if (role == null) return false;
        if (role == this) return true;
        // Prefer id equality if available; otherwise fall back to name + container
        if (this.id != null && this.id.equals(role.getId())) return true;
        return Objects.equals(this.name, role.getName())
                && Objects.equals(this.getContainerId(), role.getContainerId());
    }
}
