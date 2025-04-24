package org.tidecloak.jpa.entities;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import org.keycloak.models.jpa.entities.ComponentEntity;
import org.keycloak.models.jpa.entities.UserEntity;

@NamedQueries({
        @NamedQuery(name="getAuthorizerByProviderId", query="SELECT a FROM AuthorizerEntity a WHERE a.keyProvider.ID = :ID"),
        @NamedQuery(
                name = "getAuthorizerByProviderIdAndTypes",
                query = "SELECT a FROM AuthorizerEntity a WHERE a.keyProvider.ID = :ID AND a.type IN (:types)"
        )

})

@Entity
@Table(name = "AUTHORIZER")
public class AuthorizerEntity {

    @Id
    @Column(name="ID", length = 36)
    @Access(AccessType.PROPERTY) // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    protected String id;

    @ManyToOne // Many AuthorizerEntity records can be associated with one ComponentEntity
    @JoinColumn(name = "PROVIDER_ID", referencedColumnName = "ID")
    protected ComponentEntity keyProvider;

    @Column(name = "TYPE")
    private String type;

    @Column(name = "AUTHORIZER")
    private String authorizer; //

    @Column(name = "AUTHORIZER_CERTIFICATE")
    private String authorizerCertificate; //


    public String getId(){
        return this.id;
    }

    public void setId(String ID){
        this.id = ID;
    }

    public ComponentEntity getKeyProvider() {
        return keyProvider;
    }

    public void setKeyProvider(ComponentEntity keyProvider) {
        this.keyProvider = keyProvider;
    }

    public String getType(){
        return this.type;
    }

    public String getAuthorizer(){
        return this.authorizer;
    }

    public String getAuthorizerCertificate(){
        return this.authorizerCertificate;
    }


    public void setType(String type){
        this.type = type;
    }

    public void setAuthorizer(String authorizer){
        this.authorizer = authorizer;
    }
    public void setAuthorizerCertificate(String authorizerCertificate){
        this.authorizerCertificate = authorizerCertificate;
    }


}
