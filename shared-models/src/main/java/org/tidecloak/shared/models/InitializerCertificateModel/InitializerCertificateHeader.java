//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.tidecloak.shared.models.InitializerCertificateModel;

import com.fasterxml.jackson.annotation.JsonProperty;

public class InitializerCertificateHeader {
    @JsonProperty("kid")
    protected String kid;
    @JsonProperty("alg")
    protected String alg;
    @JsonProperty("vn")
    protected String version;

    public InitializerCertificateHeader() {
    }

    public InitializerCertificateHeader(String kid, String alg, String version) {
        this.kid = kid;
        this.alg = alg;
        this.version = version;
    }

    public String getKid() {
        return this.kid;
    }

    public void setKid(String kid) {
        this.kid = kid;
    }

    public String getAlg() {
        return this.alg;
    }

    public void setAlg(String alg) {
        this.alg = alg;
    }

    public String getVersion() {
        return this.version;
    }

    public void setVersion(String version) {
        this.version = version;
    }
}
