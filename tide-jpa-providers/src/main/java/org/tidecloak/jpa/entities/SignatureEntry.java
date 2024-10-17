package org.tidecloak.jpa.entities;
import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import java.io.Serializable;

@Embeddable
public class SignatureEntry implements Serializable {

    @Column(name = "SIGNATURE")
    private String signature;

    @Column(name = "ADMIN_PUBLIC_KEY")
    private String ADMIN_PUBLIC_KEY; //

    // Constructors
    public SignatureEntry() {
    }

    public SignatureEntry(String signature, String adminPublicKey ) {
        this.signature = signature;
        this.ADMIN_PUBLIC_KEY = adminPublicKey;
    }

    // Getters and setters
    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getADMIN_PUBLIC_KEY() {
        return ADMIN_PUBLIC_KEY;
    }

    public void setADMIN_PUBLIC_KEY(String adminPublicKey) {
        this.ADMIN_PUBLIC_KEY = adminPublicKey;
    }
}