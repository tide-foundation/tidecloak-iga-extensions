package org.tidecloak.jpa.entities;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import org.keycloak.models.jpa.entities.UserEntity;

import java.io.Serializable;

@NamedQueries({
        @NamedQuery(name="getAccessProofByUserId", query="select u from UserClientAccessProofEntity u where u.user = :user"),
        @NamedQuery(name="getAccessProofByClientId", query="select u from UserClientAccessProofEntity u where u.clientId = :clientId"),
        @NamedQuery(name="getAccessProofByUserAndClientId", query="select u from UserClientAccessProofEntity u where u.user = :user and u.clientId = :clientId "),
        @NamedQuery(name="getAccessProofByUserIdAndClientId", query="select u from UserClientAccessProofEntity u where u.user.Id = :userId and u.clientId = :clientId "),
        @NamedQuery(name="deleteProofByUser", query="delete from UserClientAccessProofEntity m where m.user = :user"),
        @NamedQuery(name="DeleteAllUserProofsByRealm",
                query = "DELETE FROM UserClientAccessProofEntity r " +
                        "WHERE r.user IN (SELECT u FROM UserEntity u WHERE u.realmId = :realmId)"
        ),
        @NamedQuery(name="DeleteAllUserProofsByClient",
                query = "DELETE FROM UserClientAccessProofEntity u " +
                        "where u.clientId = :clientId"
        ),
})
@Entity
@Table(name = "USER_CLIENT_ACCESS_PROOF")
@IdClass(UserClientAccessProofEntity.Key.class)
public class UserClientAccessProofEntity {

    @Id
    @ManyToOne(fetch= FetchType.LAZY)
    @JoinColumn(name="USER_ID")
    @JsonIgnoreProperties({"credentials", "federatedIdentities", "attributes"})
    protected UserEntity user;

    @Id
    @Column(name = "CLIENT_ID")
    protected String clientId;

    @Column(name = "ACCESS_PROOF")
    protected String accessProof;

    @Column(name = "ACCESS_PROOF_SIG")
    protected String accessProofSig;

    @Column(name = "ID_PROOF_SIG")
    protected String idProofSig;

    @Column(name = "ACCESS_PROOF_META")
    protected String accessProofMeta;

    public UserEntity getUser() {
        return user;
    }

    public void setUser(UserEntity user) {
        this.user = user;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }
    public String getAccessProof() {
        return accessProof;
    }

    public void setAccessProof(String proof) {
        this.accessProof = proof;
    }

    public String getAccessProofSig() {
        return accessProofSig;
    }

    public void setAccessProofSig(String sig) {
        this.accessProofSig = sig;
    }

    public String getIdProofSig() {
        return idProofSig;
    }

    public void setIdProofSig(String sig) {
        this.idProofSig = sig;
    }

    public String getAccessProofMeta() {
        return accessProofMeta;
    }

    public void setAccessProofMeta(String proofMeta) {
        this.accessProofMeta = proofMeta;
    }


    public static class Key implements Serializable {

        protected UserEntity user;

        protected String clientId;

        public Key() {
        }

        public Key(UserEntity user, String clientId) {
            this.user = user;
            this.clientId = clientId;
        }

        public UserEntity getUser() {
            return user;
        }

        public String getClientId() {
            return clientId;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Key key = (Key) o;

            if (!clientId.equals(key.clientId)) return false;
            if (!user.equals(key.user)) return false;

            return true;
        }

        @Override
        public int hashCode() {
            int result = user.hashCode();
            result = 31 * result + clientId.hashCode();

            return result;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof UserClientAccessProofEntity)) return false;

        UserClientAccessProofEntity key = (UserClientAccessProofEntity) o;

        if (!clientId.equals(key.clientId)) return false;
        if (!user.equals(key.user)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = user.hashCode();
        result = 31 * result + clientId.hashCode();
        return result;
    }
}