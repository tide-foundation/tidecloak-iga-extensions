package org.tidecloak.jpa.entities.drafting;

import jakarta.persistence.*;
import org.keycloak.models.jpa.entities.RoleEntity;
@NamedQueries({
        @NamedQuery(name="getPolicyByChangeSetId", query="select m from PolicyDraftEntity m where m.changesetRequestId = :changesetId"),
})

@Entity
@Table(name = "POLICY")
public class PolicyDraftEntity {

    @Id
    @Column(name="ID", length = 36)
    @Access(AccessType.PROPERTY) // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    protected String id;

    @Column(name = "CHANGESET_REQUEST_ID")
    private String changesetRequestId;

    @Column(name = "POLICY")
    private String policy;

    @Column(name = "TIMESTAMP")
    protected Long timestamp = System.currentTimeMillis();

    // Getters and setters for new fields
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getChangesetRequestId() {
        return changesetRequestId;
    }

    public void setChangesetRequestId(String changesetRequestId) {
        this.changesetRequestId = changesetRequestId;
    }

    public Long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Long timestamp) {
        this.timestamp = timestamp;
    }

    public String getPolicy() {
        return policy;
    }

    public void setPolicy(String policy) {
        this.policy = policy;
    }
}
