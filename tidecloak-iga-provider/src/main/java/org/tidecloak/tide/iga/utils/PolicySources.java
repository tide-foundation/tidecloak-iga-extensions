package org.tidecloak.tide.iga.utils;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public final class PolicySources {
    public static String load(String resourcePath) {
        try (InputStream in = PolicySources.class.getResourceAsStream(resourcePath)) {
            if (in == null) throw new IllegalStateException("Missing resource: " + resourcePath);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Failed to read " + resourcePath, e);
        }
    }
}
