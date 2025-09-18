package org.tidecloak.shared.enums;

public enum ChangeSetType {
    // Roles
    ROLE,
    COMPOSITE_ROLE,
    DEFAULT_ROLES,
    GROUP_ROLE,

    // Users & memberships
    USER,
    USER_GROUP_MEMBERSHIP,
    USER_ROLE,
    USER_ROLE_MAPPING,

    // Groups
    GROUP,

    // Clients & scopes
    CLIENT,
    CLIENT_SCOPE,
    CLIENT_FULLSCOPE,
    CLIENT_DEFAULT_USER_CONTEXT,

    // Realm settings
    REALM_SETTINGS
}
