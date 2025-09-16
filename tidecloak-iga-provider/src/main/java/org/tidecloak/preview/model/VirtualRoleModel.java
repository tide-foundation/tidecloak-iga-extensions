package org.tidecloak.preview.model;

import org.keycloak.models.RoleContainerModel;
import org.keycloak.models.RoleModel;

import java.util.*;
import java.util.stream.Stream;

public class VirtualRoleModel implements RoleModel {
    private final String id;
    private String name;
    private final RoleContainerModel container;
    private final boolean clientRole;
    private final Map<String, List<String>> attrs = new HashMap<>();

    public VirtualRoleModel(String id, String name, RoleContainerModel container, boolean clientRole) {
        this.id = id;
        this.name = name;
        this.container = container;
        this.clientRole = clientRole;
    }

    @Override public String getId() { return id; }
    @Override public String getName() { return name; }
    @Override public void setName(String name) { this.name = name; }
    @Override public String getDescription() { return null; }
    @Override public void setDescription(String description) { /* no-op */ }
    @Override public boolean isComposite() { return false; }
    @Override public void addCompositeRole(RoleModel role) { /* no-op */ }
    @Override public void removeCompositeRole(RoleModel role) { /* no-op */ }
    @Override public Stream<RoleModel> getCompositesStream() { return Stream.empty(); }
    @Override public boolean hasRole(RoleModel role) { return this.equals(role); }
    @Override public boolean isClientRole() { return clientRole; }
    @Override public String getContainerId() { return container.getId(); }
    @Override public RoleContainerModel getContainer() { return container; }

    @Override public String getFirstAttribute(String name) {
        List<String> v = attrs.get(name);
        return (v == null || v.isEmpty()) ? null : v.get(0);
    }

    @Override public Stream<String> getAttributeStream(String name) {
        List<String> v = attrs.get(name);
        return v == null ? Stream.empty() : v.stream();
    }

    @Override public Map<String, List<String>> getAttributes() { return attrs; }

    @Override public void setSingleAttribute(String name, String value) {
        attrs.put(name, new ArrayList<>(Collections.singletonList(value)));
    }

    @Override public void setAttribute(String name, List<String> values) {
        attrs.put(name, new ArrayList<>(values));
    }

    @Override public void removeAttribute(String name) { attrs.remove(name); }
}
