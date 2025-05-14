package org.tidecloak.iga.changesetsigner.authorizer;

import java.util.HashMap;
import java.util.Map;

public class AuthorizerFactory {
    private static final Map<String, Authorizer> signers = new HashMap<>();

    static {
        signers.put("firstAdmin", new FirstAdmin());
        signers.put("multiAdmin", new MultiAdmin());
    }

    public static Authorizer getSigner(String authorizerType) {
        return signers.getOrDefault(authorizerType, null);
    }
}
