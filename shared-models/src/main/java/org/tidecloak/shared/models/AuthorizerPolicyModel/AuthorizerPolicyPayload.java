package org.tidecloak.shared.models.AuthorizerPolicyModel;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public final class AuthorizerPolicyPayload {
    // ---------- Artifact / Attestation ----------
    @JsonProperty("vvkid")         public String vvkid;
    @JsonProperty("policyId")      public String policyId;        // <-- add
    @JsonProperty("policyVersion") public String policyVersion;   // <-- add
    @JsonProperty("bh")            public String bh;
    @JsonProperty("entryType")     public String entryType;
    @JsonProperty("sdkVersion")    public String sdkVersion;
    @JsonProperty("manifestHash")  public String manifestHash;
    @JsonProperty("abiDigest")     public String abiDigest;
    @JsonProperty("publisherSig")  public String publisherSig;
    @JsonProperty("storeKey")      public String storeKey;
    @JsonProperty("manifestKey")   public String manifestKey;
    @JsonProperty("iat")           public Long   iat;

    // Embed the compiled DLL directly (base64)
    @JsonProperty("assemblyBase64") public String assemblyBase64; // <-- add
    @JsonProperty("dllSize")        public Long   dllSize;
    @JsonProperty("peInfo")         public String peInfo;

    // ---------- Business Policy Config (InitCert parity) ----------
    @JsonProperty("vendor")      public String vendor;
    @JsonProperty("resource")    public String resource;
    @JsonProperty("threshold")   public Integer threshold;
    @JsonProperty("id")          public String id;
    @JsonProperty("authFlows")   public List<String> authFlows;
    @JsonProperty("signmodels")  public List<String> signmodels;
    @JsonProperty("mode")        public String mode;
    @JsonProperty("action")      public String action;
    @JsonProperty("policy")      public String policy;

    // ---------- OPTIONAL: routing/ops (keep if you already use them) ----------
    @JsonProperty("scope")       public String scope;
    @JsonProperty("subjectId")   public String subjectId;
    @JsonProperty("stage")       public String stage;
    @JsonProperty("signModelId") public String signModelId;
    @JsonProperty("priority")    public Integer priority;
    @JsonProperty("enabled")     public Boolean enabled;
    @JsonProperty("validFrom")   public Long    validFrom;
    @JsonProperty("validUntil")  public Long    validUntil;
    @JsonProperty("cfgHash")     public String  cfgHash;
    @JsonProperty("cfgJson")     public String  cfgJson;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class Vetting {
        @JsonProperty("refAllowlistOk") public Boolean refAllowlistOk;
        @JsonProperty("forbiddenCalls") public Integer forbiddenCalls;
        @JsonProperty("blockedApis")    public List<String> blockedApis;
        public Vetting() {}
        public Vetting(Boolean ok, Integer cnt, List<String> apis) {
            this.refAllowlistOk = ok; this.forbiddenCalls = cnt; this.blockedApis = apis;
        }
    }

    @JsonProperty("vetting") public Vetting vetting;
}
