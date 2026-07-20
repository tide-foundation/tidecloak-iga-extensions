package org.tidecloak.iga.producer.units;

/**
 * {@code parent_type} discriminator used by units 4 ({@code protocol_mapper})
 * and 15 ({@code scope_role_allowlist_set}). Enum names are the exact ork wire
 * strings — {@code name()} round-trips the value.
 */
public enum ParentType {
    client,
    client_scope
}
