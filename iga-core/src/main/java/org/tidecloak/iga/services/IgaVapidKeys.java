package org.tidecloak.iga.services;

import org.keycloak.models.RealmModel;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * The realm's VAPID key pair (RFC 8292), used to identify this server to a push
 * service.
 *
 * <p><b>What these keys are, and are not.</b> VAPID keys authenticate the
 * <em>sender</em>. They are not user secrets and they protect no governance
 * decision: holding the private key lets you push to endpoints you already
 * know, and the endpoints are the part that is actually sensitive. Nothing
 * signed with these keys is ever trusted by the approval path - an approval is
 * still a session-key signature produced in the enclave, exactly as before.</p>
 *
 * <p><b>Why realm attributes.</b> Storing them as realm attributes makes them
 * readable by anyone who can view the realm, which is a deliberate trade
 * against introducing a component SPI for a sender credential of this value.
 * If that trade stops being acceptable - for instance if VAPID keys later
 * authenticate something that matters - the fix is a {@code ComponentModel}
 * with a secret config field, the way {@code tide-vendor-key} stores its
 * material, and only this class needs to change.</p>
 *
 * <p>Keys are generated on first use and then reused, because the public half
 * is baked into every subscription a browser has already created: rotating it
 * silently invalidates every existing subscription.</p>
 */
public final class IgaVapidKeys {

    /** Base64url (unpadded) of the uncompressed P-256 point, 65 bytes. */
    public static final String PUBLIC_KEY_ATTR = "iga.push.vapid.publicKey";
    /** Base64 of the PKCS#8 encoding. */
    private static final String PRIVATE_KEY_ATTR = "iga.push.vapid.privateKey";

    private final String publicKey;
    private final PrivateKey privateKey;

    private IgaVapidKeys(String publicKey, PrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    /** Base64url public key, as the browser expects for {@code applicationServerKey}. */
    public String getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * The realm's existing key pair, or {@code null} if it has none yet.
     *
     * <p>Read-only, so it is safe on a request that must not write - the
     * subscribe endpoint uses {@link #getOrCreate} instead.</p>
     */
    public static IgaVapidKeys find(RealmModel realm) {
        String pub = realm.getAttribute(PUBLIC_KEY_ATTR);
        String priv = realm.getAttribute(PRIVATE_KEY_ATTR);
        if (pub == null || pub.isBlank() || priv == null || priv.isBlank()) {
            return null;
        }
        return new IgaVapidKeys(pub, decodePrivate(priv));
    }

    /** The realm's key pair, generating and storing one the first time. */
    public static IgaVapidKeys getOrCreate(RealmModel realm) {
        IgaVapidKeys existing = find(realm);
        if (existing != null) {
            return existing;
        }

        KeyPair pair = generate();
        String pub = encodePublic((ECPublicKey) pair.getPublic());
        String priv = Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());

        realm.setAttribute(PUBLIC_KEY_ATTR, pub);
        realm.setAttribute(PRIVATE_KEY_ATTR, priv);

        return new IgaVapidKeys(pub, pair.getPrivate());
    }

    private static KeyPair generate() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
            gen.initialize(new ECGenParameterSpec("secp256r1"));
            return gen.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Could not generate a VAPID key pair", e);
        }
    }

    private static PrivateKey decodePrivate(String base64Pkcs8) {
        try {
            byte[] der = Base64.getDecoder().decode(base64Pkcs8);
            return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (Exception e) {
            throw new IllegalStateException("Stored VAPID private key is unreadable", e);
        }
    }

    /**
     * Uncompressed point encoding: {@code 0x04 || X || Y}, each coordinate
     * left-padded to exactly 32 bytes.
     *
     * <p>The padding is the part that is easy to get wrong. {@code BigInteger}
     * drops leading zero bytes and adds a leading zero of its own when the high
     * bit is set, so a coordinate can arrive as 31 or 33 bytes. Either produces
     * a key the push service rejects.</p>
     */
    private static String encodePublic(ECPublicKey key) {
        byte[] x = toFixedLength(key.getW().getAffineX().toByteArray(), 32);
        byte[] y = toFixedLength(key.getW().getAffineY().toByteArray(), 32);

        byte[] out = new byte[65];
        out[0] = 0x04;
        System.arraycopy(x, 0, out, 1, 32);
        System.arraycopy(y, 0, out, 33, 32);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(out);
    }

    static byte[] toFixedLength(byte[] value, int length) {
        if (value.length == length) {
            return value;
        }
        byte[] out = new byte[length];
        if (value.length > length) {
            // Drop BigInteger's sign byte (leading 0x00) from the front.
            System.arraycopy(value, value.length - length, out, 0, length);
        } else {
            System.arraycopy(value, 0, out, length - value.length, value.length);
        }
        return out;
    }
}
