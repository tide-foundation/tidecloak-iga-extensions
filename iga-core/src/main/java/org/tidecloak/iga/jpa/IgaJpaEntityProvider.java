package org.tidecloak.iga.jpa;

import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;
import org.tidecloak.iga.entities.IgaAuthorizationEntity;
import org.tidecloak.iga.entities.IgaAuthorizerEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.entities.IgaCommentEntity;

import java.util.List;

public class IgaJpaEntityProvider implements JpaEntityProvider {

    @Override
    public List<Class<?>> getEntities() {
        return List.of(
                IgaChangeRequestEntity.class,
                IgaAuthorizationEntity.class,
                IgaCommentEntity.class,
                IgaAuthorizerEntity.class
        );
    }

    @Override
    public String getChangelogLocation() {
        return "META-INF/iga-changelog-master.xml";
    }

    @Override
    public String getFactoryId() {
        return IgaJpaEntityProviderFactory.ID;
    }

    @Override
    public void close() {
    }
}
