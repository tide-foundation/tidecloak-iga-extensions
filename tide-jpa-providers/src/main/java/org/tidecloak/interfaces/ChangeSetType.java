package org.tidecloak.interfaces;

//// Enum for Change-set type
//public enum ChangeSetType {
//    USER, USER_ROLE, ROLE, GROUP, COMPOSITE_ROLE, GROUP_ROLE
//}

public enum ChangeSetType {
    USER("USER_ENTITY_DRAFT"),
    USER_ROLE("USER_ROLE_MAPPING_DRAFT"),
    GROUP("KEYCLOAK_GROUP_DRAFT"),
    USER_GROUP_MEMBERSHIP("USER_GROUP_MEMBERSHIP_DRAFT"),
    COMPOSITE_ROLE("COMPOSITE_ROLE_MAPPING_DRAFT"),
    GROUP_ROLE("GROUP_ROLE_MAPPING_DRAFT");

    private final String tableName;

    // Constructor that sets the table name for each enum instance
    ChangeSetType(String tableName) {
        this.tableName = tableName;
    }

    // Getter method to retrieve the table name
    public String getTableName() {
        return tableName;
    }
}