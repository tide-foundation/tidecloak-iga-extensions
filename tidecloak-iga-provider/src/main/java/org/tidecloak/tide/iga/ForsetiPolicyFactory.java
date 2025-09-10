package org.tidecloak.tide.iga;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.*;
import org.midgard.Midgard;
import org.midgard.models.AuthorizerPolicyModel.AuthorizerPolicy;
import org.midgard.models.AuthorizerPolicyModel.AuthorizerPolicyHeader;
import org.midgard.models.AuthorizerPolicyModel.AuthorizerPolicyPayload;

import java.util.*;
import java.util.function.BiConsumer;

public final class ForsetiPolicyFactory {

    private static int resolveThreshold(RoleModel role) {
        String tideThreshold = role.getFirstAttribute("tideThreshold");
        if (tideThreshold == null) throw new IllegalStateException("Role missing 'tideThreshold'");
        return Integer.parseInt(tideThreshold);
    }

    private static ComponentModel tideKeyOrThrow(KeycloakSession session) {
        return session.getContext().getRealm().getComponentsStream()
                .filter(x -> x.getProviderId().equalsIgnoreCase(org.tidecloak.shared.Constants.TIDE_VENDOR_KEY))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Tide vendor key component not found"));
    }

    /**
     * Create a DRAFT (UNSIGNED) AuthorizerPolicy bound to:
     *  - scope=role, subjectId=role.getId()
     *  - stage (e.g. "Admin:2")
     *  - signModelId (e.g. "UserContext:1")
     *  - bh (compiled code identity)
     *
     * Returns AuthorizerPolicy with compact "h.p" (no VRK at draft time).
     */
    public static AuthorizerPolicy createRoleAuthorizerPolicy(
            KeycloakSession session,
            String resource,
            RoleModel role,
            String envelopeVn,              // e.g. "1"
            String algorithm,               // e.g. "EdDSA"
            List<String> authFlows,         // e.g. List.of("Admin:2")
            List<String> signModels,        // e.g. List.of("UserContext:1","Rules:1")
            String policySource,            // C# source (implements your policy)
            String entryType,               // FQN, e.g. "Ork.Forseti.Builtins.AuthorizerTemplatePolicy"
            String sdkVersion,              // e.g. "1.0.0"
            BiConsumer<String,String> codeStore, // (bh, assemblyB64) -> persist
            String stage,                   // e.g. "Admin:2"
            String signModelId,             // e.g. "UserContext:1"
            Integer priority                // null => default
    ) throws JsonProcessingException {

        // 1) resolve vendor config
        ComponentModel tideKey = tideKeyOrThrow(session);
        String vvkId  = tideKey.getConfig().getFirst("vvkId");
        String vendor = session.getContext().getRealm().getName();
        int threshold = resolveThreshold(role);

        // 2) compile to get BH (+ assembly)
        var compile = Midgard.CompilePolicy(policySource, entryType, sdkVersion);
        String bh = compile.bh; // "sha256:..."

        // 3) persist DLL by BH (draft artifact store)
        if (codeStore != null) {
            codeStore.accept(bh, compile.assemblyBase64);
        }

        // 4) build UNSIGNED AP (header+payload). No VRK signature at draft time.
        var header = new AuthorizerPolicyHeader(vvkId, algorithm, envelopeVn);

        var payload = new AuthorizerPolicyPayload();
        payload.vvkid      = vvkId;
        payload.vendor     = vendor;
        payload.resource   = resource;
        payload.threshold  = threshold;
        payload.id         = UUID.randomUUID().toString();
        payload.authFlows  = new ArrayList<>(authFlows);
        payload.signmodels = new ArrayList<>(signModels);
        payload.policy     = role.getName();
        payload.bh         = bh;          // code binding (also used in admin allow-list)
        payload.entryType  = entryType;
        payload.sdkVersion = sdkVersion;
        payload.mode       = "enforce";
        payload.action     = "*";
        payload.iat        = System.currentTimeMillis() / 1000;

        // ----- routing / selection metadata -----
        payload.scope      = "role";
        payload.subjectId  = role.getId();
        payload.stage      = stage;          // e.g., "Admin:2"
        payload.signModelId= signModelId;    // e.g., "UserContext:1"
        payload.priority   = (priority == null ? 0 : priority);
        payload.enabled    = Boolean.TRUE;
        payload.validFrom  = payload.iat;    // live now

        return AuthorizerPolicy.of(header, payload); // caller can store ap.toCompactString() == "h.p"
    }

    // Convenience: default admin template (Admin:2 + UserContext:1), still draft/unsigned.
    public static AuthorizerPolicy createRoleAuthorizerPolicy_DefaultAdminTemplate(
            KeycloakSession session,
            String resource,
            RoleModel role,
            List<String> signModels,
            BiConsumer<String,String> codeStore
    ) throws JsonProcessingException {
        List<String> authFlows = List.of("Admin:2");
        String envelopeVn = "1";
        String algorithm  = "EdDSA";
        String entryType  = "Ork.Forseti.Builtins.AuthorizerTemplatePolicy";
        String sdkVersion = "1.0.0";
        String stage      = "Admin:2";
        String signModelId= "UserContext:1";
        Integer priority  = 0;

        return createRoleAuthorizerPolicy(
                session, resource, role,
                envelopeVn, algorithm, authFlows, signModels,
                DEFAULT_ADMIN_TEMPLATE_CS, entryType, sdkVersion, codeStore,
                stage, signModelId, priority
        );
    }

    /** Minimal default template policy (server-side Forseti). */
    public static final String DEFAULT_ADMIN_TEMPLATE_CS =
            // keep this short; expand to your full template if needed
            "using System;using System.Linq;using System.Text.Json;using Ork.Forseti.Sdk;"+
                    "namespace Ork.Forseti.Builtins{public sealed class AuthorizerTemplatePolicy:IAccessPolicy{"+
                    "public PolicyDecision Authorize(AccessContext ctx){ForsetiSdk.SetCultureInvariant();"+
                    "string reqId=ForsetiSdk.Claim(\"request.id\")??\"\";string oldIdsJson=ForsetiSdk.Claim(\"request.oldIds\");"+
                    "string authors=ForsetiSdk.Claim(\"authorizers.json\");string smJson=ForsetiSdk.Claim(\"cfg.signmodels\");"+
                    "int threshold=int.TryParse(ForsetiSdk.Claim(\"cfg.threshold\"),out var t)?t:0;"+
                    "if(string.IsNullOrEmpty(authors))return PolicyDecision.Deny(\"missing authorizers\");"+
                    "string[] allowed=ParseArray(smJson);bool ok=allowed.Contains(reqId)||ParseArray(oldIdsJson).Any(x=>allowed.Contains(x));"+
                    "if(!ok)return PolicyDecision.Deny(\"request not allowed by signmodels\");"+
                    "int approved=CountUniqueApproved(authors);if(approved<threshold)return PolicyDecision.Deny($\"not enough authorizers {approved}/{threshold}\");"+
                    "return PolicyDecision.Allow();}"+
                    "static string[] ParseArray(string j){try{if(string.IsNullOrEmpty(j))return Array.Empty<string>();using var d=JsonDocument.Parse(j);"+
                    "if(d.RootElement.ValueKind!=JsonValueKind.Array)return Array.Empty<string>();return d.RootElement.EnumerateArray().Select(e=>e.GetString()??\"\").Where(s=>s.Length>0).ToArray();}catch{return Array.Empty<string>();}}"+
                    "static int CountUniqueApproved(string j){try{using var d=JsonDocument.Parse(j);if(d.RootElement.ValueKind!=JsonValueKind.Array)return 0;var set=new System.Collections.Generic.HashSet<string>(StringComparer.Ordinal);int n=0;foreach(var e in d.RootElement.EnumerateArray()){if(e.ValueKind!=JsonValueKind.Object)continue;"+
                    "if(!e.TryGetProperty(\"tideuserkey\",out var k)||k.ValueKind!=JsonValueKind.String)continue;var ks=k.GetString();if(string.IsNullOrEmpty(ks))continue;if(!set.Add(ks))return 0;"+
                    "bool approved=e.TryGetProperty(\"approved\",out var a)&&a.ValueKind==JsonValueKind.True;if(approved)n++;}return n;}catch{return 0;}}}}";
}
