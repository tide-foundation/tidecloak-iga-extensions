package org.tidecloak.jpa.entities.drafting;

import jakarta.persistence.*;
import org.keycloak.models.jpa.entities.RoleEntity;
@NamedQueries({
        @NamedQuery(name="getPolicyByChangeSetId", query="select m from PolicyDraftEntity m where m.changesetRequestId = :changesetId"),
        @NamedQuery(name="getActiveRealmPolicy", query="select m from PolicyDraftEntity m where m.realmId = :realmId and m.scope = 'REALM'"),
        @NamedQuery(name="getPendingRealmPolicy", query="select m from PolicyDraftEntity m where m.realmId = :realmId and m.scope = 'REALM_PENDING'"),
        @NamedQuery(name="getDeletePendingRealmPolicy", query="select m from PolicyDraftEntity m where m.realmId = :realmId and m.scope = 'REALM_DELETE_PENDING'"),
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

    @Column(name = "REALM_ID")
    private String realmId;

    @Column(name = "SCOPE")
    private String scope;

    @Column(name = "TEMPLATE_ID")
    private String templateId;

    @Column(name = "TIMESTAMP")
    protected Long timestamp = System.currentTimeMillis();

    // Getters and setters
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

    public String getRealmId() {
        return realmId;
    }

    public void setRealmId(String realmId) {
        this.realmId = realmId;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getTemplateId() {
        return templateId;
    }

    public void setTemplateId(String templateId) {
        this.templateId = templateId;
    }
}
