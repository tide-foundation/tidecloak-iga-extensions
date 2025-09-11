package org.midgard.models.AuthorizerPolicyModel;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public final class AuthorizerPolicyPayload {
    // ---------- Artifact / Attestation ----------
    @JsonProperty("vvkid")        public String vvkid;        // server/vendor key id (also useful in config)
    @JsonProperty("policyId")     public String policyId;     // stable policy id (e.g., GUID)
    @JsonProperty("policyVersion")public String policyVersion;// semver or monotonically increasing
    @JsonProperty("bh")           public String bh;           // sha256:<HEX> of compiled DLL
    @JsonProperty("entryType")    public String entryType;    // fully-qualified .NET type
    @JsonProperty("sdkVersion")   public String sdkVersion;   // Policy SDK version fence
    @JsonProperty("manifestHash") public String manifestHash; // sha256:<HEX> of manifest json (optional)
    @JsonProperty("abiDigest")    public String abiDigest;    // optional
    @JsonProperty("publisherSig") public String publisherSig; // optional (server-side signing of manifest)
    @JsonProperty("storeKey")     public String storeKey;     // where DLL lives (optional)
    @JsonProperty("manifestKey")  public String manifestKey;  // where manifest lives (optional)
    @JsonProperty("iat")          public Long   iat;          // issued-at (epoch seconds)
    @JsonProperty("dllSize")      public Long   dllSize;      // optional
    @JsonProperty("peInfo")       public String peInfo;       // optional PE metadata

    // ---------- Business Policy Config (InitCert parity) ----------
    @JsonProperty("vendor")       public String vendor;
    @JsonProperty("resource")     public String resource;
    @JsonProperty("threshold")    public Integer threshold;
    @JsonProperty("id")           public String id;           // config instance id (can mirror policyId)
    @JsonProperty("authFlows")    public List<String> authFlows;
    @JsonProperty("signmodels")   public List<String> signmodels;
    @JsonProperty("mode")         public String mode;         // "enforce" (default) / "report"
    @JsonProperty("action")       public String action;       // "*" or verbs
    @JsonProperty("policy")       public String policy;       // human-friendly name (e.g., role name)

    // ---------- OPTIONAL: Gate routing / selection metadata ----------
    // Scope selection ladder: user > role > global (vvkid)
    @JsonProperty("scope")        public String scope;        // "user" | "role" | "global"
    @JsonProperty("subjectId")    public String subjectId;    // userId for scope=user, roleId for scope=role, null for global

    // Stage + sign request model routing
    @JsonProperty("stage")        public String stage;        // e.g. "Admin:2"
    @JsonProperty("signModelId")  public String signModelId;  // e.g. "UserContext:1"

    // Operational controls
    @JsonProperty("priority")     public Integer priority;    // higher wins among equals
    @JsonProperty("enabled")      public Boolean enabled;     // default true
    @JsonProperty("validFrom")    public Long    validFrom;   // epoch seconds
    @JsonProperty("validUntil")   public Long    validUntil;  // epoch seconds (optional)

    // Optional config binding (lets admins “point” to a concrete config instance)
    @JsonProperty("cfgHash")      public String cfgHash;      // e.g., sha256:<HEX> of cfg.json
    @JsonProperty("cfgJson")      public String cfgJson;      // small JSON blob used by policy (if desired)

    // Optional nested vetting (unchanged)
    @JsonProperty("vetting")      public Vetting vetting;

    public static final class Vetting {
        @JsonProperty("refAllowlistOk") public Boolean refAllowlistOk;
        @JsonProperty("forbiddenCalls") public Integer forbiddenCalls;
        @JsonProperty("blockedApis")    public List<String> blockedApis;

        public Vetting() {}
        public Vetting(Boolean ok, Integer cnt, List<String> apis) {
            this.refAllowlistOk = ok; this.forbiddenCalls = cnt; this.blockedApis = apis;
        }
    }
}
