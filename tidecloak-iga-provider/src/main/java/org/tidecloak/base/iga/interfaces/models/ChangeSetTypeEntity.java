package org.tidecloak.base.iga.interfaces.models;

import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessor;
import org.tidecloak.base.iga.ChangeSetProcessors.processors.*;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.jpa.entities.drafting.*;

import java.util.function.Supplier;

public enum ChangeSetTypeEntity {
    DEFAULT_ROLES(ChangeSetType.DEFAULT_ROLES, "COMPOSITE_ROLE_MAPPING_DRAFT", TideCompositeRoleMappingDraftEntity.class, CompositeRoleProcessor::new),
    CLIENT(ChangeSetType.CLIENT, "CLIENT_DRAFT", TideClientDraftEntity.class, ClientProcessor::new),
    CLIENT_DEFAULT_USER_CONTEXT(ChangeSetType.CLIENT_DEFAULT_USER_CONTEXT, "CLIENT_FULLSCOPE_DRAFT", TideClientDraftEntity.class, ClientProcessor::new),
    ROLE(ChangeSetType.ROLE, "ROLE_ENTITY_DRAFT", TideRoleDraftEntity.class, RoleProcessor::new),
    USER_ROLE(ChangeSetType.USER_ROLE, "USER_ROLE_MAPPING_DRAFT", TideUserRoleMappingDraftEntity.class, UserRoleProcessor::new),
    COMPOSITE_ROLE(ChangeSetType.COMPOSITE_ROLE, "COMPOSITE_ROLE_MAPPING_DRAFT", TideCompositeRoleMappingDraftEntity.class, CompositeRoleProcessor::new),
    CLIENT_FULLSCOPE(ChangeSetType.CLIENT_FULLSCOPE, "CLIENT_FULLSCOPE_DRAFT", TideClientDraftEntity.class, ClientFullScopeProcessor::new),
    GROUP_ROLE(ChangeSetType.GROUP_ROLE, "GROUP_ROLE_MAPPING_DRAFT", TideGroupRoleMappingEntity.class, GroupRoleProcessor::new),
    GROUP(ChangeSetType.GROUP, "KEYCLOAK_GROUP_DRAFT", TideGroupDraftEntity.class, GroupProcessor::new),
    USER_GROUP_MEMBERSHIP(ChangeSetType.USER_GROUP_MEMBERSHIP, "USER_GROUP_MEMBERSHIP_DRAFT", TideUserGroupMembershipEntity.class, UserGroupMembershipProcessor::new),
    GROUP_MOVE(ChangeSetType.GROUP_MOVE, "GROUP_MOVE_DRAFT", TideGroupMoveDraftEntity.class, GroupMoveProcessor::new);

    private final ChangeSetType baseType;
    private final String tableName;
    private final Class<?> entityClass;
    private final Supplier<? extends ChangeSetProcessor<?>> processorSupplier;

    ChangeSetTypeEntity(ChangeSetType baseType, String tableName, Class<?> entityClass, Supplier<? extends ChangeSetProcessor<?>> processorSupplier) {
        this.baseType = baseType;
        this.tableName = tableName;
        this.entityClass = entityClass;
        this.processorSupplier = processorSupplier;
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

    public Supplier<? extends ChangeSetProcessor<?>> getProcessorSupplier() {
        return processorSupplier;
    }

    public static ChangeSetTypeEntity fromBaseType(ChangeSetType baseType) {
        for (ChangeSetTypeEntity entity : values()) {
            if (entity.baseType == baseType) {
                return entity;
            }
        }
        throw new IllegalArgumentException("No ChangeSetTypeEntity defined for base type: " + baseType);
    }
}
