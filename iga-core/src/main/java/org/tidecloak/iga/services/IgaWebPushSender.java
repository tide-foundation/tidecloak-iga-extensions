package org.tidecloak.iga.services;

import org.jboss.logging.Logger;
import org.tidecloak.iga.entities.IgaPushSubscriptionEntity;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Duration;
import java.util.Base64;

/**
 * Sends one Web Push message to one subscription (RFC 8030), authenticated with
 * VAPID (RFC 8292).
 *
 * <h3>The messages carry no payload, on purpose</h3>
 *
 * <p>A push message may carry an encrypted body (RFC 8291). These do not, for
 * two reasons that point the same way.</p>
 *
 * <p>The first is disclosure. A push message travels through a push service
 * chosen by the browser - Google's for Chrome, Mozilla's for Firefox, Apple's
 * for Safari - none of which is ours and none of which the vendor selected.
 * Even encrypted, the existence, timing and frequency of messages is visible to
 * that service. Putting realm names or change-request ids in the body would
 * hand a third party a running commentary on a vendor's governance activity.
 * An empty message tells it only that something happened.</p>
 *
 * <p>The second is blast radius. RFC 8291 payload encryption is ECDH plus HKDF
 * plus AES-GCM, and getting any of it subtly wrong produces messages that fail
 * silently at the browser. Omitting it removes that failure mode entirely and
 * leaves this class with one job: sign a JWT and POST.</p>
 *
 * <p>The cost is that the notification the browser shows is generic - "approvals
 * pending" rather than "realm a1 needs you". The service worker handles that by
 * treating an empty push as a prompt to open the app, which then loads the real
 * list over an authenticated connection. The detail arrives over the channel
 * that is already trusted, rather than the one that is not.</p>
 *
 * <h3>Failure handling</h3>
 *
 * <p>404 and 410 mean the browser subscription is gone for good; the caller is
 * told to forget it. Everything else - a 5xx, a timeout, a push service having
 * a bad day - is transient and the subscription is kept.</p>
 */
public final class IgaWebPushSender {

    private static final Logger log = Logger.getLogger(IgaWebPushSender.class);

    /** How long the push service should hold the message for an offline device. */
    private static final int TTL_SECONDS = 12 * 60 * 60;

    /** VAPID tokens must be short-lived; 12h is within the 24h ceiling RFC 8292 sets. */
    private static final long TOKEN_LIFETIME_SECONDS = 12 * 60 * 60;

    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    private static final HttpClient CLIENT = HttpClient.newBuilder()
            .connectTimeout(TIMEOUT)
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    /** What the caller should do with the subscription afterwards. */
    public enum Result {
        /** Accepted by the push service. */
        DELIVERED,
        /** The subscription is dead - delete it. */
        GONE,
        /** Transient; keep the subscription and try again next time. */
        FAILED
    }

    private final IgaVapidKeys keys;
    private final String subject;

    /**
     * @param keys the realm's VAPID key pair
     * @param subject the {@code sub} claim - a mailto: or https: URI identifying
     *                who to contact about this sender, as RFC 8292 requires
     */
    public IgaWebPushSender(IgaVapidKeys keys, String subject) {
        this.keys = keys;
        this.subject = subject;
    }

    public Result send(IgaPushSubscriptionEntity subscription) {
        String endpoint = subscription.getEndpoint();
        try {
            URI uri = URI.create(endpoint);
            String token = vapidToken(audienceOf(uri));

            HttpRequest request = HttpRequest.newBuilder(uri)
                    .timeout(TIMEOUT)
                    .header("TTL", String.valueOf(TTL_SECONDS))
                    // No Content-Length here, even though RFC 8030 wants one on a
                    // bodyless push: HttpClient treats it as a restricted header
                    // and throws IllegalArgumentException from .header() rather
                    // than at send time. BodyPublishers.noBody() sets it to 0
                    // itself. Nor any Content-Encoding: an empty push is a valid
                    // RFC 8030 message and needs no encryption headers.
                    .header("Urgency", "normal")
                    .header("Authorization", "vapid t=" + token + ", k=" + keys.getPublicKey())
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .build();

            HttpResponse<Void> response = CLIENT.send(request, HttpResponse.BodyHandlers.discarding());
            int status = response.statusCode();

            if (status == 404 || status == 410) {
                return Result.GONE;
            }
            if (status >= 200 && status < 300) {
                return Result.DELIVERED;
            }
            log.debugf("Web push to %s returned %d", hostOf(endpoint), status);
            return Result.FAILED;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Result.FAILED;
        } catch (IOException e) {
            // The push service was unreachable or hung up. Environmental and
            // transient, so debug: it will be retried on the next change request.
            log.debugf(e, "Web push to %s failed", hostOf(endpoint));
            return Result.FAILED;
        } catch (Exception e) {
            // Anything else reaching here is a defect in how the request was
            // built, not a network condition - it will fail identically forever.
            // WARN because the alternative is what happened with the restricted
            // Content-Length header: every notification silently dropped, with
            // the only evidence below the default log level.
            log.warnf(e, "Web push to %s could not be sent - this will not recover on its own",
                    hostOf(endpoint));
            return Result.FAILED;
        }
    }

    /** The push service origin, which is what the token is audience-bound to. */
    private static String audienceOf(URI endpoint) {
        return endpoint.getScheme() + "://" + endpoint.getHost()
                + (endpoint.getPort() == -1 ? "" : ":" + endpoint.getPort());
    }

    private static String hostOf(String endpoint) {
        try {
            return URI.create(endpoint).getHost();
        } catch (RuntimeException e) {
            return "<unparseable endpoint>";
        }
    }

    /** A signed ES256 JWT: {@code {"aud":…,"exp":…,"sub":…}}. */
    private String vapidToken(String audience) throws Exception {
        long exp = (System.currentTimeMillis() / 1000L) + TOKEN_LIFETIME_SECONDS;

        String header = base64Url("{\"typ\":\"JWT\",\"alg\":\"ES256\"}".getBytes(StandardCharsets.UTF_8));
        String claims = base64Url(("{\"aud\":\"" + audience + "\",\"exp\":" + exp
                + ",\"sub\":\"" + subject + "\"}").getBytes(StandardCharsets.UTF_8));

        String signingInput = header + "." + claims;

        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(keys.getPrivateKey());
        signer.update(signingInput.getBytes(StandardCharsets.US_ASCII));

        return signingInput + "." + base64Url(derToJose(signer.sign()));
    }

    private static String base64Url(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    /**
     * Convert the JVM's DER-encoded ECDSA signature to the fixed 64-byte
     * {@code r || s} form JOSE requires.
     *
     * <p>This conversion is mandatory and easy to miss: {@code SHA256withECDSA}
     * emits {@code SEQUENCE { INTEGER r, INTEGER s }}, and a push service handed
     * those bytes rejects the token as malformed. Both integers are re-padded to
     * exactly 32 bytes, since DER strips leading zeros and adds a sign byte when
     * the high bit is set.</p>
     */
    static byte[] derToJose(byte[] der) {
        int offset = 0;
        if (der[offset++] != 0x30) {
            throw new IllegalArgumentException("Not a DER SEQUENCE");
        }
        // Length may be short-form (one byte) or long-form (0x81 + one byte).
        int lengthByte = der[offset++] & 0xFF;
        if (lengthByte == 0x81) {
            offset++;
        }

        if (der[offset++] != 0x02) {
            throw new IllegalArgumentException("Expected DER INTEGER for r");
        }
        int rLength = der[offset++] & 0xFF;
        byte[] r = new byte[rLength];
        System.arraycopy(der, offset, r, 0, rLength);
        offset += rLength;

        if (der[offset++] != 0x02) {
            throw new IllegalArgumentException("Expected DER INTEGER for s");
        }
        int sLength = der[offset++] & 0xFF;
        byte[] s = new byte[sLength];
        System.arraycopy(der, offset, s, 0, sLength);

        byte[] out = new byte[64];
        System.arraycopy(IgaVapidKeys.toFixedLength(new BigInteger(1, r).toByteArray(), 32), 0, out, 0, 32);
        System.arraycopy(IgaVapidKeys.toFixedLength(new BigInteger(1, s).toByteArray(), 32), 0, out, 32, 32);
        return out;
    }
}
