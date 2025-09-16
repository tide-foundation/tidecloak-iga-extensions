package org.tidecloak.shared.models.AuthorizerPolicyModel;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Who/what signed this server receipt. */
public final class AuthorizerPolicyHeader {
    @JsonProperty("kid") public String kid;   // server signing key id
    @JsonProperty("alg") public String alg;   // "EdDSA" / "RS256" / ...
    @JsonProperty("vn")  public String vn;    // envelope version, e.g., "v1"
    @JsonProperty("typ") public String typ;   // fixed: "policy-receipt"

    public AuthorizerPolicyHeader() {}
    public AuthorizerPolicyHeader(String kid, String alg, String vn) {
        this.kid = kid; this.alg = alg; this.vn = vn; this.typ = "policy-receipt";
    }
}
