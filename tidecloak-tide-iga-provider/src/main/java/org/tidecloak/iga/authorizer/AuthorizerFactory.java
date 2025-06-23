package org.tidecloak.iga.authorizer;

import java.util.HashMap;
import java.util.Map;

public class AuthorizerFactory {
    private static final Map<String, Authorizer> authorizers = new HashMap<>();

    static {
        authorizers.put("firstAdmin", new FirstAdmin());
        authorizers.put("multiAdmin", new MultiAdmin());
    }

    public static Authorizer getSigner(String authorizerType) {
        return authorizers.getOrDefault(authorizerType, null);
    }
    public static Authorizer getCommitter(String authorizerType) {
        return authorizers.getOrDefault(authorizerType, null);
    }

}
