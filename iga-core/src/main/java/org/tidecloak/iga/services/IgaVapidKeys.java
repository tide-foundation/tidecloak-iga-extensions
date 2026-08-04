package org.tidecloak.iga.services;

import jakarta.persistence.EntityManager;
import org.tidecloak.iga.entities.IgaVapidKeyEntity;

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
 * <p><b>Why they are not realm attributes.</b> That was the first design and it
 * does not work: realm attributes are governed state, so under IGA the write is
 * captured as a {@code SET_REALM_ATTRIBUTE} change request rather than applied.
 * The generated pair is handed out and then forgotten, the realm accumulates a
 * change request nobody asked for, and the next call fails against that pending
 * CR. Operational data that no approval depends on must not enter the approval
 * pipeline - hence {@link IgaVapidKeyEntity}, its own table, where writes simply
 * apply. It also keeps the private key out of the realm representation, which
 * anyone who can view the realm can read.</p>
 *
 * <p>Keys are generated on first use and then reused, because the public half
 * is baked into every subscription a browser has already created: rotating it
 * silently invalidates every existing subscription.</p>
 */
public final class IgaVapidKeys {

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
     * <p>Read-only, so it is safe on the send path - a realm nobody has ever
     * subscribed in has nobody to notify, and generating a key there would be
     * work done for no one.</p>
     */
    public static IgaVapidKeys find(EntityManager em, String realmId) {
        IgaVapidKeyEntity row = em.find(IgaVapidKeyEntity.class, realmId);
        if (row == null) {
            return null;
        }
        return new IgaVapidKeys(row.getPublicKey(), decodePrivate(row.getPrivateKey()));
    }

    /** The realm's key pair, generating and storing one the first time. */
    public static IgaVapidKeys getOrCreate(EntityManager em, String realmId) {
        IgaVapidKeys existing = find(em, realmId);
        if (existing != null) {
            return existing;
        }

        KeyPair pair = generate();
        String pub = encodePublic((ECPublicKey) pair.getPublic());

        IgaVapidKeyEntity row = new IgaVapidKeyEntity();
        row.setRealmId(realmId);
        row.setPublicKey(pub);
        row.setPrivateKey(Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));
        row.setCreatedAt(System.currentTimeMillis());
        em.persist(row);
        em.flush();

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
