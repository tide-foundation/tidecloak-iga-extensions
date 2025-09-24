package org.tidecloak.jpa.entities;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import org.keycloak.models.jpa.entities.UserEntity;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;

@NamedQueries({
        @NamedQuery(
                name  = "getProofDetailsForRealm",
                query = "SELECT a FROM AccessProofDetailEntity a WHERE a.realmId = :realmId ORDER BY a.createdTimestamp DESC"
        ),
        @NamedQuery(
                name  = "getProofDetailsForUser",
                query = "SELECT a FROM AccessProofDetailEntity a WHERE a.user = :user ORDER BY a.createdTimestamp DESC"
        ),
        @NamedQuery(
                name  = "getProofDetailsForDraft",
                query = "SELECT a FROM AccessProofDetailEntity a WHERE a.changeRequestKey.changeRequestId = :recordId ORDER BY a.createdTimestamp DESC"
        ),
        @NamedQuery(
                name  = "getProofDetailsForDraftByChangeSetTypeAndRealm",
                query = "SELECT a FROM AccessProofDetailEntity a WHERE a.changesetType = :changesetType AND a.realmId = :realmId"
        ),
        @NamedQuery(
                name  = "getProofDetailsForDraftByChangeSetTypeAndIdAndRealm",
                query = "SELECT a FROM AccessProofDetailEntity a WHERE a.changesetType = :changesetType AND a.changeRequestKey.changeRequestId = :recordId AND a.realmId = :realmId"
        ),
        @NamedQuery(
                name  = "getProofDetailsForDraftByChangeSetTypeAndId",
                query = "SELECT a FROM AccessProofDetailEntity a WHERE a.changesetType = :changesetType AND a.changeRequestKey.changeRequestId = :recordId"
        ),
        @NamedQuery(
                name  = "getProofDetailsForDraftByChangeSetTypeAndIdAndUser",
                query = "SELECT a FROM AccessProofDetailEntity a WHERE a.changesetType = :changesetType AND a.changeRequestKey.changeRequestId = :recordId AND a.user.id = :userId"
        ),
        @NamedQuery(
                name  = "getProofDetailsForDraftByChangeSetTypesAndId",
                query = "SELECT a FROM AccessProofDetailEntity a WHERE a.changesetType IN :changesetTypes AND a.changeRequestKey.changeRequestId = :recordId ORDER BY a.createdTimestamp DESC"
        ),
        @NamedQuery(
                name  = "getProofDetailsForDraftByChangeSetType",
                query = "SELECT a FROM AccessProofDetailEntity a WHERE a.changesetType = :changesetType"
        ),
        @NamedQuery(
                name  = "getProofDetailsForUserByClient",
                query = "SELECT a FROM AccessProofDetailEntity a WHERE a.user = :user AND a.clientId = :clientId ORDER BY a.createdTimestamp DESC"
        ),
        @NamedQuery(
                name  = "getProofDetailsForUserByClientAndRecordId",
                query = "SELECT a FROM AccessProofDetailEntity a WHERE a.user = :user AND a.clientId = :clientId AND a.changeRequestKey.changeRequestId = :recordId ORDER BY a.createdTimestamp DESC"
        ),
        @NamedQuery(
                name  = "getProofDetailsByClient",
                query = "SELECT a FROM AccessProofDetailEntity a WHERE a.clientId = :clientId ORDER BY a.createdTimestamp DESC"
        ),
        @NamedQuery(
                name  = "getProofDetailsForCompositeByClient",
                query = "SELECT a FROM AccessProofDetailEntity a WHERE a.changesetType = :changesetType AND a.clientId = :clientId ORDER BY a.createdTimestamp DESC"
        ),
        @NamedQuery(
                name  = "FindUserWithCompositeRoleRecord",
                query = "SELECT a FROM AccessProofDetailEntity a WHERE a.user = :user AND a.changeRequestKey.changeRequestId IN (SELECT d.id FROM TideCompositeRoleMappingDraftEntity d WHERE d.composite = :composite) ORDER BY a.createdTimestamp DESC"
        ),
        @NamedQuery(
                name  = "deleteProofRecordForUserAndClient",
                query = "DELETE FROM AccessProofDetailEntity a WHERE a.changeRequestKey.changeRequestId = :recordId AND a.user = :user AND a.clientId = :clientId"
        ),
        @NamedQuery(
                name  = "deleteProofRecordForUser",
                query = "DELETE FROM AccessProofDetailEntity a WHERE a.changeRequestKey.changeRequestId = :recordId AND a.user = :user"
        ),
        @NamedQuery(
                name  = "deleteProofRecords",
                query = "DELETE FROM AccessProofDetailEntity a WHERE a.changeRequestKey.mappingId = :recordId"
        ),
        @NamedQuery(
                name  = "deleteAllDraftProofRecordsForUser",
                query = "DELETE FROM AccessProofDetailEntity a WHERE a.user = :user"
        ),
        @NamedQuery(
                name  = "DeleteAllAccessProofsByRealm",
                query = "DELETE FROM AccessProofDetailEntity r WHERE r.user IN (SELECT u FROM UserEntity u WHERE u.realmId = :realmId)"
        ),
        @NamedQuery(
                name  = "DeleteAllAccessProofsByClient",
                query = "DELETE FROM AccessProofDetailEntity r WHERE r.clientId = :clientId"
        )
})
@Entity
@Table(name = "ACCESS_PROOF_DETAIL")
public class AccessProofDetailEntity {

    @Id
    @Column(name="ID", length = 36)
    @Access(AccessType.PROPERTY)
    protected String id;

    @Embedded
    private ChangeRequestKey changeRequestKey;

    @Enumerated(EnumType.STRING)
    @Column(name = "CHANGE_SET_TYPE")
    protected ChangeSetType changesetType;

    @ManyToOne(fetch= FetchType.LAZY)
    @JoinColumn(name="USER_ID")
    @JsonIgnoreProperties({"credentials", "federatedIdentities", "attributes"})
    protected UserEntity user;

    @Column(name = "CLIENT_ID")
    protected String clientId;

    @Column(name = "REALM_ID")
    protected String realmId;

    /** Baseline (current/active) user-context snapshot */
    @Lob
    @Column(name = "DEFAULT_USER_CONTEXT")
    protected String defaultUserContext;

    /** Draft preview (baseline + delta without dynamic fields) */
    @Lob
    @Column(name = "PROOF_DRAFT")
    protected String proofDraft;

    /** Optional AP hash (base64-url) when a role introduces an authorizer policy */
    @Column(name = "AUTHORIZER_POLICY_HASH")
    protected String authorizerPolicyHash;

    @Enumerated(EnumType.STRING)
    @Column(name = "DRAFT_STATUS")
    protected DraftStatus draftStatus;

    @Column(name = "CREATED_TIMESTAMP")
    protected Long createdTimestamp = System.currentTimeMillis();

    /** Final signature (Tide) or admin id (Base IGA) once committed */
    @Column(name = "FINAL_SIGNATURE")
    protected String signature;

    // --- getters/setters ---

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public ChangeRequestKey getChangeRequestKey() { return changeRequestKey; }
    public void setChangeRequestKey(ChangeRequestKey changeRequestKey) { this.changeRequestKey = changeRequestKey; }

    public ChangeSetType getChangesetType() { return changesetType; }
    public void setChangesetType(ChangeSetType changesetType) { this.changesetType = changesetType; }

    public UserEntity getUser() { return user; }
    public void setUser(UserEntity user) { this.user = user; }

    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }

    public String getRealmId() { return realmId; }
    public void setRealmId(String realmId) { this.realmId = realmId; }

    public String getDefaultUserContext() { return defaultUserContext; }
    public void setDefaultUserContext(String defaultUserContext) { this.defaultUserContext = defaultUserContext; }

    public String getProofDraft() { return proofDraft; }
    public void setProofDraft(String proofDraft) { this.proofDraft = proofDraft; }

    public String getAuthorizerPolicyHash() { return authorizerPolicyHash; }
    public void setAuthorizerPolicyHash(String authorizerPolicyHash) { this.authorizerPolicyHash = authorizerPolicyHash; }

    public DraftStatus getDraftStatus() { return draftStatus; }
    public void setDraftStatus(DraftStatus draftStatus) { this.draftStatus = draftStatus; }

    public Long getCreatedTimestamp() { return createdTimestamp; }
    public void setCreatedTimestamp(Long timestamp) { this.createdTimestamp = timestamp; }

    public String getSignature() { return signature; }
    public void setSignature(String signature) { this.signature = signature; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AccessProofDetailEntity)) return false;
        AccessProofDetailEntity that = (AccessProofDetailEntity) o;
        return id != null && id.equals(that.id);
    }

    @Override
    public int hashCode() { return id == null ? 0 : id.hashCode(); }
}
