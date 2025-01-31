package org.tidecloak.jpa.entities;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import org.keycloak.models.jpa.entities.UserEntity;

@Entity
@Table(name = "ADMIN_AUTHORIZATIONS")
public class AdminAuthorizationEntity {

    @Id
    @Column(name = "ID")
    private String id;

    // Many-to-One relationship with ChangesetRequestEntity
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "CHANGESET_REQUEST_ID", referencedColumnName = "CHANGESET_REQUEST_ID")
    private ChangesetRequestEntity changesetRequest;

    @Column(name="USER_ID")
    protected String userId;

    @Column(name = "ADMIN_AUTHORIZATION")
    private String adminAuthorization;

    @Column(name="IS_APPROVAL")
    private  boolean isApproval;


    public void setId(String id){this.id = id; }
    public  String getId() { return this.id; }
    public void setUserId(String userId) { this.userId = userId;}
    public String getUserId() { return this.userId;}
    public void setAdminAuthorization(String adminAuthorization) { this.adminAuthorization = adminAuthorization;}
    public String getAdminAuthorization() { return this.adminAuthorization; }
    public void setIsApproval(boolean isApproval) { this.isApproval = isApproval;}
    public boolean getIsApproval() { return this.isApproval;}
    public ChangesetRequestEntity getChangesetRequest() {
        return changesetRequest;
    }

    public void setChangesetRequest(ChangesetRequestEntity changesetRequest) {
        this.changesetRequest = changesetRequest;
    }

}
