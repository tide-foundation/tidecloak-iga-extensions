package org.tidecloak.iga.producer.units;

/**
 * {@code KEYCLOAK_GROUP.type} (unit 6). Enum names are the exact ork wire
 * strings — {@code name()} round-trips the value. Mirrors KC's
 * {@code GroupModel.Type} names ({@code REALM} / {@code ORGANIZATION}).
 */
public enum GroupType {
    REALM,
    ORGANIZATION
}
