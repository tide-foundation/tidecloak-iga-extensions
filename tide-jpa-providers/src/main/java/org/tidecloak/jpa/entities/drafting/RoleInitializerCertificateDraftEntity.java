package org.tidecloak.jpa.entities.drafting;

import jakarta.persistence.*;
import org.keycloak.models.jpa.entities.RoleEntity;
@NamedQueries({
        @NamedQuery(name="getInitCertByChangeSetId", query="select m from RoleInitializerCertificateDraftEntity m where m.changesetRequestId = :changesetId"),
})

@Entity
@Table(name = "ROLE_INITIALIZER_CERTIFICATE")
public class RoleInitializerCertificateDraftEntity {

    @Id
    @Column(name="ID", length = 36)
    @Access(AccessType.PROPERTY) // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    protected String id;

    @Column(name = "CHANGESET_REQUEST_ID")
    private String changesetRequestId;

    @Column(name = "INIT_CERT")
    private String initCert;

    @Column(name = "INIT_CERT_SIG")
    private String initCertSig;

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

    public String getInitCert() {
        return initCert;
    }

    public void setInitCert(String initCert) {
        this.initCert = initCert;
    }

    public String getInitCertSig() {
        return initCertSig;
    }

    public void setInitCertSig(String initCertSig) {
        this.initCertSig = initCertSig;
    }
}
