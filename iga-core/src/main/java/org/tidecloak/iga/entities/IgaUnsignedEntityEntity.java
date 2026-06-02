package org.tidecloak.iga.entities;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;

import java.io.Serializable;
import java.util.Objects;

/**
 * Sidecar registry of entities that exist in the underlying Keycloak entity
 * tables (USER_ENTITY, KEYCLOAK_ROLE, KEYCLOAK_GROUP, CLIENT, CLIENT_SCOPE)
 * but have NOT yet been attested. A sidecar row links back to the per-entity
 * ADOPT change request that will, once approved, stamp the entity's
 * ATTESTATION column and delete the sidecar row.
 *
 * <p>{@code ADOPT_CR_ID} is nullable so a sidecar row can briefly exist
 * without a CR pointer during the mid-toggle window. The
 * composite primary key (REALM_ID, ENTITY_TYPE, ENTITY_ID) guarantees at
 * most one sidecar row per entity.</p>
 *
 * <p>Defined under JPA's {@code @IdClass} contract (rather than
 * {@code @EmbeddedId}) to keep the entity flat and the columns directly
 * navigable from JPQL — matching the style used by the existing tidecloak-iga
 * entities.</p>
 */
@Entity
@Table(name = "IGA_UNSIGNED_ENTITY")
@IdClass(IgaUnsignedEntityEntity.Pk.class)
public class IgaUnsignedEntityEntity {

    @Id
    @Column(name = "REALM_ID", length = 36, nullable = false)
    private String realmId;

    @Id
    @Column(name = "ENTITY_TYPE", length = 32, nullable = false)
    private String entityType;

    @Id
    @Column(name = "ENTITY_ID", length = 36, nullable = false)
    private String entityId;

    @Column(name = "ADOPT_CR_ID", length = 36)
    private String adoptCrId;

    @Column(name = "CREATED_AT", nullable = false)
    private Long createdAt;

    public String getRealmId() { return realmId; }
    public void setRealmId(String realmId) { this.realmId = realmId; }

    public String getEntityType() { return entityType; }
    public void setEntityType(String entityType) { this.entityType = entityType; }

    public String getEntityId() { return entityId; }
    public void setEntityId(String entityId) { this.entityId = entityId; }

    public String getAdoptCrId() { return adoptCrId; }
    public void setAdoptCrId(String adoptCrId) { this.adoptCrId = adoptCrId; }

    public Long getCreatedAt() { return createdAt; }
    public void setCreatedAt(Long createdAt) { this.createdAt = createdAt; }

    /**
     * Composite primary key class for {@link IgaUnsignedEntityEntity}.
     * Required by {@code @IdClass}; field names must match the entity's
     * {@code @Id}-annotated fields.
     */
    public static class Pk implements Serializable {
        private static final long serialVersionUID = 1L;

        private String realmId;
        private String entityType;
        private String entityId;

        public Pk() {
        }

        public Pk(String realmId, String entityType, String entityId) {
            this.realmId = realmId;
            this.entityType = entityType;
            this.entityId = entityId;
        }

        public String getRealmId() { return realmId; }
        public void setRealmId(String realmId) { this.realmId = realmId; }

        public String getEntityType() { return entityType; }
        public void setEntityType(String entityType) { this.entityType = entityType; }

        public String getEntityId() { return entityId; }
        public void setEntityId(String entityId) { this.entityId = entityId; }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof Pk)) return false;
            Pk that = (Pk) o;
            return Objects.equals(realmId, that.realmId)
                    && Objects.equals(entityType, that.entityType)
                    && Objects.equals(entityId, that.entityId);
        }

        @Override
        public int hashCode() {
            return Objects.hash(realmId, entityType, entityId);
        }
    }
}
