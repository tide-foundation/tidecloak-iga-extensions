package org.tidecloak.jpa.entities;

import jakarta.persistence.*;

/**
 * Long role attributes (compressed + base64url payloads) to avoid VARCHAR(255) limits in ROLE_ATTRIBUTE.
 *
 * Liquibase table: ROLE_ATTRIBUTE_LONG
 * Unique constraint: (ROLE_ID, NAME)
 */
@Entity
@Table(
        name = "ROLE_ATTRIBUTE_LONG",
        uniqueConstraints = {
                @UniqueConstraint(name = "UK_ROLE_ATTR_LONG_ROLE_NAME", columnNames = {"ROLE_ID", "NAME"})
        },
        indexes = {
                @Index(name = "IX_ROLE_ATTR_LONG_ROLE", columnList = "ROLE_ID")
        }
)
@NamedQueries({
        @NamedQuery(
                name = "RoleAttributeLongEntity.getByRoleAndName",
                query = "SELECT e FROM RoleAttributeLongEntity e WHERE e.roleId = :roleId AND e.name = :name"
        ),
        @NamedQuery(
                name = "RoleAttributeLongEntity.deleteByRoleAndName",
                query = "DELETE FROM RoleAttributeLongEntity e WHERE e.roleId = :roleId AND e.name = :name"
        )
})
public class RoleAttributeLongEntity {

    @Id
    @Column(name = "ID", length = 36, nullable = false)
    private String id;

    @Column(name = "ROLE_ID", length = 36, nullable = false)
    private String roleId;

    @Column(name = "NAME", length = 255, nullable = false)
    private String name;

    /** GZIP-compressed, then base64url-encoded string (no padding). */
    @Lob
    @Column(name = "VALUE", nullable = false)
    private String value;

    /** Hex SHA-256 of the *raw* (uncompressed) value for quick integrity checks/diffing. */
    @Column(name = "HASH_SHA256", length = 64, nullable = false)
    private String hashSha256;

    @Column(name = "CREATED_AT", nullable = false)
    private long createdAt;

    @Column(name = "UPDATED_AT", nullable = false)
    private long updatedAt;

    public RoleAttributeLongEntity() {}

    @PrePersist
    public void onCreate() {
        long now = System.currentTimeMillis();
        if (createdAt == 0L) createdAt = now;
        updatedAt = now;
    }

    @PreUpdate
    public void onUpdate() {
        updatedAt = System.currentTimeMillis();
    }

    // Getters / setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getRoleId() { return roleId; }
    public void setRoleId(String roleId) { this.roleId = roleId; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getValue() { return value; }
    public void setValue(String value) { this.value = value; }

    public String getHashSha256() { return hashSha256; }
    public void setHashSha256(String hashSha256) { this.hashSha256 = hashSha256; }

    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }

    public long getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(long updatedAt) { this.updatedAt = updatedAt; }
}
