package org.tidecloak.iga.entities;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.Table;

@Entity
@Table(name = "TIDEPOLICY")
@NamedQueries({
    @NamedQuery(
        name = "TidePolicy.findById",
        query = "SELECT d FROM TidePolicyEntity d WHERE d.id = :id"
    ),
    @NamedQuery(
        name = "TidePolicy.findByRealm",
        query = "SELECT d FROM TidePolicyEntity d WHERE d.realmId = :realmId ORDER BY d.createdAt DESC"
    )
})

public class TidePolicyEntity {
    @Id
    @Column(name = "ID", length = 255)
    private String id;

    @Column(name = "REALM_ID", length = 36, nullable = false)
    private String realmId;

    @Column(name = "CREATED_AT", nullable = false)
    private Long createdAt;

    @Column(name = "DATA", length = 2000, nullable = false)
    private String data;

    // Large / free-form column — mirrors IgaChangeRequestEntity.ROWS_JSON /
    // DEPENDS_ON, which use columnDefinition = "TEXT" for unbounded text.
    @Column(name = "NOTES", columnDefinition = "TEXT")
    private String notes;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getRealmId() { return realmId; }
    public void setRealmId(String realmId) { this.realmId = realmId; }

    public Long getCreatedAt() { return createdAt; }
    public void setCreatedAt(Long createdAt) { this.createdAt = createdAt; }

    public String getData() { return data; }
    public void setData(String data) { this.data = data; }

    public String getNotes() { return notes; }
    public void setNotes(String notes) { this.notes = notes; }
}
