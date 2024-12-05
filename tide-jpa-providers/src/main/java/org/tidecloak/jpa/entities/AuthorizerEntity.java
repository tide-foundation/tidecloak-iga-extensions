package org.tidecloak.jpa.entities;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import org.keycloak.models.jpa.entities.ComponentEntity;
import org.keycloak.models.jpa.entities.UserEntity;

public class AuthorizerEntity {

    @Id
    @JoinColumn(name = "PROVIDER_ID", referencedColumnName = "ID")
    protected ComponentEntity keyProvider;

    @Column(name = "TYPE")
    private String type;

    @Column(name = "AUTHORIZER")
    private String authorizer; //

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

    public void setType(String type){
        this.type = type;
    }

    public void setAuthorizer(String authorizer){
        this.authorizer = authorizer;
    }


}
