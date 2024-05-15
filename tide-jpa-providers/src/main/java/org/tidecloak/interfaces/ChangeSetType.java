package org.tidecloak.interfaces;
import org.tidecloak.jpa.entities.drafting.*;

public enum ChangeSetType {
    USER("USER_ENTITY_DRAFT", TideUserDraftEntity.class),
    USER_ROLE("USER_ROLE_MAPPING_DRAFT", TideUserRoleMappingDraftEntity.class),
    GROUP("KEYCLOAK_GROUP_DRAFT", TideGroupDraftEntity.class),
    USER_GROUP_MEMBERSHIP("USER_GROUP_MEMBERSHIP_DRAFT", TideUserGroupMembershipEntity.class),
    COMPOSITE_ROLE("COMPOSITE_ROLE_MAPPING_DRAFT", TideCompositeRoleMappingDraftEntity.class),
    GROUP_ROLE("GROUP_ROLE_MAPPING_DRAFT", TideGroupDraftEntity.class);

    private final String tableName;
    private final Class<?> entityClass;

    // Constructor that sets the table name for each enum instance
    ChangeSetType(String tableName, Class<?> entityClass) {
        this.tableName = tableName; this.entityClass = entityClass;
    }

    // Getter method to retrieve the table name
    public String getTableName() {
        return tableName;
    }
    public Class<?> getEntityClass() {
        return entityClass;
    }


}