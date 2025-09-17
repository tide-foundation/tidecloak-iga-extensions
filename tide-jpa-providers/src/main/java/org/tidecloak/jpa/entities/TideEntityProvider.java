package org.tidecloak.jpa.entities;

import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;
import org.tidecloak.jpa.entities.Licensing.*;
import org.tidecloak.jpa.entities.preview.*;
import org.tidecloak.jpa.entities.*;
import org.tidecloak.jpa.entities.drafting.*;

import java.util.List;

public class TideEntityProvider implements JpaEntityProvider {
    @Override
    public List<Class<?>> getEntities() {
        return List.of(UserClientAccessProofEntity.class,
                AccessProofDetailDependencyEntity.class,
                AccessProofDetailEntity.class,
                UserClientAccessProofEntity.class,
                LicenseHistoryEntity.class,
                AdminAuthorizationEntity.class,
                AuthorizerEntity.class,
                ChangeRequestKey.class,
                ChangesetRequestEntity.class,
                SignatureEntry.class,
                ActiveContextRevisionEntity.class,
                TokenPreviewBundleEntity.class,
                TokenPreviewEntity.class
        );
    }

    // This is used to return the location of the Liquibase changelog file.
    // You can return null if you don't want Liquibase to create and update the DB schema.
    // "META-INF/example-changelog.xml"
    @Override
    public String getChangelogLocation() {
        return "META-INF/tide-jpa-changelog-master.xml";
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