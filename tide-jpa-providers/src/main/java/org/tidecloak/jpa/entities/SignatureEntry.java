package org.tidecloak.jpa.entities;
import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import java.io.Serializable;

@Embeddable
public class SignatureEntry implements Serializable {

    @Column(name = "ACCESS_PROOF_SIGNATURE")
    private String ACCESS_PROOF_SIGNATURE;

    @Column(name = "ADMIN_PUBLIC_KEY")
    private String ADMIN_PUBLIC_KEY; //

    @Column(name = "ID_TOKEN_SIGNATURE")
    private  String ID_TOKEN_SIGNATURE;

    // Constructors
    public SignatureEntry() {
    }

    public SignatureEntry(String accessProofsignature, String idTokenSignature, String adminPublicKey ) {
        this.ACCESS_PROOF_SIGNATURE = accessProofsignature;
        this.ID_TOKEN_SIGNATURE = idTokenSignature;
        this.ADMIN_PUBLIC_KEY = adminPublicKey;

    }

    // Getters and setters
    public String getACCESS_PROOF_SIGNATURE() {
        return ACCESS_PROOF_SIGNATURE;
    }

    public void setACCESS_PROOF_SIGNATURE(String signature) {
        this.ACCESS_PROOF_SIGNATURE = signature;
    }

    public String getID_TOKEN_SIGNATURE() {
        return ID_TOKEN_SIGNATURE;
    }

    public void setID_TOKEN_SIGNATURE(String signature) {
        this.ID_TOKEN_SIGNATURE = signature;
    }

    public String getADMIN_PUBLIC_KEY() {
        return ADMIN_PUBLIC_KEY;
    }

    public void setADMIN_PUBLIC_KEY(String adminPublicKey) {
        this.ADMIN_PUBLIC_KEY = adminPublicKey;
    }
}