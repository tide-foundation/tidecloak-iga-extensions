package org.tidecloak.interfaces;

import org.tidecloak.enums.ChangeSetType;
import org.tidecloak.jpa.entities.drafting.*;

public enum ChangeSetTypeEntity {
//    ROLE(ChangeSetType.ROLE, "ROLE_ENTITY_DRAFT", TideRoleDraftEntity.class),
//    USER(ChangeSetType.USER, "USER_ENTITY_DRAFT", TideUserDraftEntity.class),
    USER_ROLE(ChangeSetType.USER_ROLE, "USER_ROLE_MAPPING_DRAFT", TideUserRoleMappingDraftEntity.class),
//    GROUP(ChangeSetType.GROUP, "KEYCLOAK_GROUP_DRAFT", TideGroupDraftEntity.class),
//    USER_GROUP_MEMBERSHIP(ChangeSetType.USER_GROUP_MEMBERSHIP, "USER_GROUP_MEMBERSHIP_DRAFT", TideUserGroupMembershipEntity.class),
    COMPOSITE_ROLE(ChangeSetType.COMPOSITE_ROLE, "COMPOSITE_ROLE_MAPPING_DRAFT", TideCompositeRoleMappingDraftEntity.class),
//    GROUP_ROLE(ChangeSetType.GROUP_ROLE, "GROUP_ROLE_MAPPING_DRAFT", TideGroupDraftEntity.class),
    CLIENT_FULLSCOPE(ChangeSetType.CLIENT_FULLSCOPE, "CLIENT_FULL_SCOPE_STATUS_DRAFT", TideClientFullScopeStatusDraftEntity.class);

    private final ChangeSetType baseType; // Reference to the first enum
    private final String tableName;
    private final Class<?> entityClass;

    // Constructor
    ChangeSetTypeEntity(ChangeSetType baseType, String tableName, Class<?> entityClass) {
        this.baseType = baseType;
        this.tableName = tableName;
        this.entityClass = entityClass;
    }

    public ChangeSetType getBaseType() {
        return baseType;
    }

    public String getTableName() {
        return tableName;
    }

    public Class<?> getEntityClass() {
        return entityClass;
    }
}
