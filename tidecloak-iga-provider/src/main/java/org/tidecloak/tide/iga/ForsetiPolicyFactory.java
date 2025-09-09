package org.tidecloak.tide.iga;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RoleModel;
import org.keycloak.component.ComponentModel;
import org.keycloak.common.util.MultivaluedHashMap;
import org.midgard.models.AuthorizerPolicyModel.AuthorizerPolicy;
import org.midgard.models.AuthorizerPolicyModel.AuthorizerPolicyHeader;
import org.midgard.models.AuthorizerPolicyModel.AuthorizerPolicyPayload;

import java.util.ArrayList;
import java.util.UUID;


public final class ForsetiPolicyFactory {

    /**
     * Builds an AuthorizerPolicy (header+payload).
     */
    public static AuthorizerPolicy createRoleAuthorizerPolicy(
            KeycloakSession session,
            String resource,
            RoleModel role,
            String envelopeVersion,   // like your old certVersion (e.g. "v1")
            String algorithm,         // e.g. "RS256", "EdDSA"
            ArrayList<String> authFlows,
            ArrayList<String> signModels
    ) throws JsonProcessingException {

        // Pull the VVKiD from your Tide provider config
        ComponentModel componentModel = session.getContext().getRealm().getComponentsStream()
                .filter(x -> x.getProviderId().equalsIgnoreCase(org.tidecloak.shared.Constants.TIDE_VENDOR_KEY))
                .findFirst()
                .orElse(null);

        if (componentModel == null) {
            throw new IllegalStateException("Tide vendor key component not found");
        }

        MultivaluedHashMap<String, String> config = componentModel.getConfig();
        String vvkId  = config.getFirst("vvkId");
        String vendor = session.getContext().getRealm().getName();

        String tideThreshold = role.getFirstAttribute("tideThreshold");
        if (tideThreshold == null) {
            return null;
        }
        int threshold = Integer.parseInt(tideThreshold);

        // Defaults for compile metadata (replace with real values if you have them here)
        String entryType  = "Forseti.Policies.CustomPolicy";
        String sdkVersion = "1.0.0";

        // Build header
        var header = new AuthorizerPolicyHeader(
                vvkId,            // kid
                algorithm,        // alg
                envelopeVersion,  // vn
                entryType,        // et
                sdkVersion        // sdk
        );

        // Build payload
        var payload = new AuthorizerPolicyPayload();
        payload.vendor     = vendor;
        payload.resource   = resource;
        payload.signmodels = signModels;
        payload.threshold  = threshold;
        payload.id         = UUID.randomUUID().toString();

        payload.vvkid      = vvkId;
        payload.policy     = role.getName();
        payload.hash       = "";
        payload.json       = "";
        payload.bh         = "";
        payload.entryType  = entryType;
        payload.sdkVersion = sdkVersion;
        payload.abiJson    = null;            // optional
        payload.mode       = "enforce";
        payload.action     = "*";

        return AuthorizerPolicy.of(header, payload);
    }

    /**
     * Overload similar to your old constructInitCert: minimal AuthorizerPolicy without compile metadata.
     */
    public static AuthorizerPolicy constructAuthorizerPolicy(
            String vvkId, String alg, String vn,
            String vendor, String resource,
            int threshold, ArrayList<String> authFlows,
            ArrayList<String> signModels
    ) {
        String entryType  = "Forseti.Policies.CustomPolicy";
        String sdkVersion = "1.0.0";

        var header = new AuthorizerPolicyHeader(vvkId, alg, vn, entryType, sdkVersion);

        var payload = new AuthorizerPolicyPayload();
        payload.vendor     = vendor;
        payload.resource   = resource;
        payload.signmodels = signModels;
        payload.threshold  = threshold;
        payload.id         = UUID.randomUUID().toString();

        payload.vvkid      = vvkId;
        payload.policy     = "Unnamed Policy";
        payload.hash       = "";
        payload.json       = "";
        payload.bh         = "";
        payload.entryType  = entryType;
        payload.sdkVersion = sdkVersion;

        return AuthorizerPolicy.of(header, payload);
    }
}
