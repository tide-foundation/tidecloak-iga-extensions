package org.tidecloak.jpa.entities;

import jakarta.persistence.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "SIGNATURE_ENTRY")
public class SignatureEntry implements Serializable {

    @Id
    @Column(name = "ID", length = 36)
    @Access(AccessType.PROPERTY)
    protected String id = KeycloakModelUtils.generateId();

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "AUTHORIZER_ID", referencedColumnName = "ID")
    private AuthorizerEntity authorizerEntity;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "CHANGESET_REQUEST_ID", referencedColumnName = "CHANGESET_REQUEST_ID")
    private ChangesetRequestEntity changesetRequest;

    @ElementCollection
    @CollectionTable(
            name = "SIGNATURE_ENTRY_SIGNATURES",
            joinColumns = @JoinColumn(name = "SIGNATURE_ENTRY_ID")
    )
    @Column(name = "AUTHORIZE_SIGNATURE", nullable = false)
    private List<String> authorizerSignatures = new ArrayList<>();

    // Default constructor
    public SignatureEntry() {}

    // Constructor with fields
    public SignatureEntry(AuthorizerEntity authorizerEntity, List<String> authorizerSignatures) {
        this.authorizerEntity = authorizerEntity;
        this.authorizerSignatures = authorizerSignatures;
    }

    // Getters and Setters
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public AuthorizerEntity getAuthorizerEntity() {
        return authorizerEntity;
    }

    public void setAuthorizerEntity(AuthorizerEntity authorizerEntity) {
        this.authorizerEntity = authorizerEntity;
    }

    public ChangesetRequestEntity getChangesetRequest() {
        return changesetRequest;
    }

    public void setChangesetRequest(ChangesetRequestEntity changesetRequest) {
        this.changesetRequest = changesetRequest;
    }

    public List<String> getAuthorizerSignatures() {
        return authorizerSignatures;
    }

    public void setAuthorizerSignatures(List<String> authorizerSignatures) {
        this.authorizerSignatures = authorizerSignatures;
    }

    public void addAuthorizerSignature(String authorizerSignature) {
        this.authorizerSignatures.add(authorizerSignature);
    }
}
