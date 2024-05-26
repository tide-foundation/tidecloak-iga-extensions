package org.tidecloak.jpa.models;

import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;
import org.tidecloak.jpa.entities.AccessProofDetailDependencyEntity;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.UserClientAccessProofEntity;
import org.tidecloak.jpa.entities.drafting.*;

import java.util.List;

public class TideEntityProvider implements JpaEntityProvider {
    @Override
    public List<Class<?>> getEntities() {
        return List.of(UserClientAccessProofEntity.class,
                TideUserDraftEntity.class,
                TideUserRoleMappingDraftEntity.class,
                TideCompositeRoleMappingDraftEntity.class,
                TideGroupDraftEntity.class,
                TideUserGroupMembershipEntity.class,
                TideGroupRoleMappingEntity.class,
                TideClientFullScopeStatusDraftEntity.class,
                TideCompositeRoleDraftEntity.class,
                AccessProofDetailDependencyEntity.class,
                AccessProofDetailEntity.class,
                UserClientAccessProofEntity.class
                );
    }

    // This is used to return the location of the Liquibase changelog file.
    // You can return null if you don't want Liquibase to create and update the DB schema.
    // "META-INF/example-changelog.xml"
    @Override
    public String getChangelogLocation() {
        return "META-INF/tide-jpa-changelog-0.0.0.xml";
    }

    // Helper method, which will be used internally by Liquibase.
    @Override
    public String getFactoryId() {
        return TideEntityProviderFactory.ID;
    }

    @Override
    public void close() {

    }
}