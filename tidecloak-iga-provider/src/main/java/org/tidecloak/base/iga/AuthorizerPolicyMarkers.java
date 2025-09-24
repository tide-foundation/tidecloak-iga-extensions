package org.tidecloak.base.iga;

import java.security.MessageDigest;

final class AuthorizerPolicyMarkers {
    private AuthorizerPolicyMarkers() {}

    static String primarySha256(String compactWithSigOrData) {
        try {
            byte[] b = compactWithSigOrData.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] h = MessageDigest.getInstance("SHA-256").digest(b);
            return "sha256:" + toHexUpper(h);
        } catch (Exception e) {
            return "";
        }
    }
    private static String toHexUpper(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02X", x));
        return sb.toString();
    }
}
