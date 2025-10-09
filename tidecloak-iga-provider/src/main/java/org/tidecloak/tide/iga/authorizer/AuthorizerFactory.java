package org.tidecloak.tide.iga.authorizer;

import java.util.HashMap;
import java.util.Map;

public class AuthorizerFactory {
    private static final Map<String, Authorizer> authorizers = new HashMap<>();

    static {
        authorizers.put("firstAdmin", new FirstAdmin());
        // you can still register the plain one as a fallback
        authorizers.put("multiAdmin", new MultiAdmin());
    }

    public static Authorizer getCommitter(String authorizerType) {
        if ("multiAdmin".equals(authorizerType)) {
            // try to load your override class, if it exists
            try {
                Class<?> override = Class.forName(
                        "org.ragnarok.authorizer.MultiAdminWithRagnarokOverride"
                );
                return (Authorizer) override.getDeclaredConstructor().newInstance();
            } catch (ClassNotFoundException cnfe) {
                // override not on classpath—just fall back
                return authorizers.get("multiAdmin");
            } catch (Exception e) {
                // something went wrong instantiating it
                throw new RuntimeException(
                        "Could not instantiate MultiAdminWithRagnarokOverride", e
                );
            }
        }

        // all other types just come from the map
        return authorizers.get(authorizerType);
    }

    public static Authorizer getSigner(String authorizerType) {
        // same logic if you need it for signWithAuthorizer
        return getCommitter(authorizerType);
    }
}
