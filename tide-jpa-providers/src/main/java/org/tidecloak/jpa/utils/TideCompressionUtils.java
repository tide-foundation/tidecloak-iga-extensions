package org.tidecloak.jpa.util;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

public final class TideCompressionUtils {
    private TideCompressionUtils() {}

    /** Deflate (raw, no zlib header) then base64url encode. */
    public static String deflateToBase64Url(String input) {
        if (input == null || input.isEmpty()) return "";
        byte[] data = input.getBytes(StandardCharsets.UTF_8);

        Deflater def = new Deflater(Deflater.BEST_COMPRESSION, true /*nowrap*/);
        def.setInput(data);
        def.finish();

        byte[] buf = new byte[1024];
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while (!def.finished()) {
            int n = def.deflate(buf);
            out.write(buf, 0, n);
        }
        def.end();

        return Base64.getUrlEncoder().withoutPadding().encodeToString(out.toByteArray());
    }

    /** Base64url decode then inflate (raw). */
    public static String inflateFromBase64Url(String b64url) {
        if (b64url == null || b64url.isEmpty()) return "";
        byte[] compressed = Base64.getUrlDecoder().decode(b64url);

        Inflater inf = new Inflater(true /*nowrap*/);
        inf.setInput(compressed);

        byte[] buf = new byte[1024];
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            while (!inf.finished()) {
                int n = inf.inflate(buf);
                if (n == 0 && inf.needsInput()) break;
                out.write(buf, 0, n);
            }
        } catch (Exception e) {
            throw new RuntimeException("inflate failed", e);
        } finally {
            inf.end();
        }
        return out.toString(StandardCharsets.UTF_8);
    }
}
