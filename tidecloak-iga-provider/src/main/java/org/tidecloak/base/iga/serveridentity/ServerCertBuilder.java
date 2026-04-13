package org.tidecloak.base.iga.serveridentity;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

/**
 * Builds X.509 TBS (to-be-signed) certificate bytes for server identity SVIDs.
 *
 * Uses raw ASN.1 DER encoding to avoid Bouncy Castle dependency in the provider module.
 * The TBS certificate is signed externally by VVK via ORK threshold signing.
 */
public class ServerCertBuilder {

    /**
     * Build X.509 TBS certificate bytes.
     *
     * @param publicKeyBase64url Ed25519 public key in base64url encoding
     * @param cn Common Name (client ID)
     * @param org Organization (realm name)
     * @param spiffeId SPIFFE URI for SAN
     * @param lifetimeSeconds Certificate lifetime
     * @return DER-encoded TBS certificate bytes
     */
    public static byte[] buildTbs(
            String publicKeyBase64url,
            String cn,
            String org,
            String issuerCn,
            String spiffeId,
            long lifetimeSeconds
    ) {
        byte[] pubKeyRaw = Base64.getUrlDecoder().decode(publicKeyBase64url);

        Instant now = Instant.now();
        Date notBefore = Date.from(now);
        Date notAfter = Date.from(now.plusSeconds(lifetimeSeconds));

        // Build TBS certificate structure manually in DER
        byte[] version = derExplicit(0, derInteger(BigInteger.valueOf(2))); // v3
        byte[] serialNumber = derInteger(new BigInteger(64, new SecureRandom()));
        byte[] signatureAlgorithm = ed25519AlgorithmIdentifier();
        byte[] issuer = derSequence(derSet(derSequence(
                derOid(new int[]{2, 5, 4, 3}), // CN
                derUtf8String(issuerCn)
        )));
        byte[] validity = derSequence(derUtcTime(notBefore), derUtcTime(notAfter));
        byte[] subject = derSequence(
                derSet(derSequence(derOid(new int[]{2, 5, 4, 10}), derUtf8String(org))), // O
                derSet(derSequence(derOid(new int[]{2, 5, 4, 3}), derUtf8String(cn)))    // CN
        );
        byte[] subjectPublicKeyInfo = derSequence(
                ed25519AlgorithmIdentifier(),
                derBitString(pubKeyRaw)
        );

        // Extensions
        byte[] sanExtension = buildSanExtension(spiffeId);
        byte[] keyUsageExtension = buildKeyUsageExtension();
        byte[] extKeyUsageExtension = buildExtKeyUsageExtension();
        byte[] basicConstraintsExtension = buildBasicConstraintsExtension();

        byte[] extensions = derExplicit(3, derSequence(
                sanExtension, keyUsageExtension, extKeyUsageExtension, basicConstraintsExtension
        ));

        return derSequence(
                version, serialNumber, signatureAlgorithm, issuer, validity,
                subject, subjectPublicKeyInfo, extensions
        );
    }

    /**
     * Assemble a complete X.509 certificate from TBS + signature.
     *
     * @param tbsCertificate DER-encoded TBS certificate
     * @param signatureBytes Ed25519 signature bytes
     * @return DER-encoded X.509 certificate
     */
    public static byte[] assembleCertificate(byte[] tbsCertificate, byte[] signatureBytes) {
        return derSequence(
                tbsCertificate,
                ed25519AlgorithmIdentifier(),
                derBitString(signatureBytes)
        );
    }

    /**
     * Convert DER certificate to PEM format.
     */
    public static String toPem(byte[] derCert) {
        String b64 = Base64.getEncoder().encodeToString(derCert);
        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN CERTIFICATE-----\n");
        for (int i = 0; i < b64.length(); i += 64) {
            pem.append(b64, i, Math.min(i + 64, b64.length()));
            pem.append('\n');
        }
        pem.append("-----END CERTIFICATE-----");
        return pem.toString();
    }

    // --- ASN.1 DER Encoding Helpers ---

    private static byte[] ed25519AlgorithmIdentifier() {
        // OID 1.3.101.112 (Ed25519), no parameters
        return derSequence(derOid(new int[]{1, 3, 101, 112}));
    }

    private static byte[] buildSanExtension(String spiffeUri) {
        // SAN extension OID: 2.5.29.17
        // URI is context tag [6]
        byte[] uriBytes = spiffeUri.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] uriValue = new byte[2 + uriBytes.length];
        uriValue[0] = (byte) 0x86; // context [6] implicit
        uriValue[1] = (byte) uriBytes.length;
        System.arraycopy(uriBytes, 0, uriValue, 2, uriBytes.length);

        return derSequence(
                derOid(new int[]{2, 5, 29, 17}),
                derOctetString(derSequence(uriValue))
        );
    }

    private static byte[] buildKeyUsageExtension() {
        // Key Usage OID: 2.5.29.15, critical, Digital Signature only (bit 0)
        byte[] keyUsageBits = new byte[]{0x03, 0x02, 0x07, (byte) 0x80}; // bit string, 7 unused bits, bit 0 set
        return derSequence(
                derOid(new int[]{2, 5, 29, 15}),
                new byte[]{0x01, 0x01, (byte) 0xFF}, // critical: true
                derOctetString(keyUsageBits)
        );
    }

    private static byte[] buildExtKeyUsageExtension() {
        // Extended Key Usage OID: 2.5.29.37
        // TLS Web Client Authentication: 1.3.6.1.5.5.7.3.2
        return derSequence(
                derOid(new int[]{2, 5, 29, 37}),
                derOctetString(derSequence(derOid(new int[]{1, 3, 6, 1, 5, 5, 7, 3, 2})))
        );
    }

    private static byte[] buildBasicConstraintsExtension() {
        // Basic Constraints OID: 2.5.29.19, critical, CA:FALSE
        return derSequence(
                derOid(new int[]{2, 5, 29, 19}),
                new byte[]{0x01, 0x01, (byte) 0xFF}, // critical: true
                derOctetString(derSequence()) // empty sequence = CA:FALSE
        );
    }

    // --- Low-level DER primitives ---

    private static byte[] derSequence(byte[]... contents) {
        return derTagged(0x30, contents);
    }

    private static byte[] derSet(byte[]... contents) {
        return derTagged(0x31, contents);
    }

    private static byte[] derTagged(int tag, byte[]... contents) {
        int totalLen = 0;
        for (byte[] c : contents) totalLen += c.length;
        byte[] lenBytes = derLength(totalLen);
        byte[] result = new byte[1 + lenBytes.length + totalLen];
        result[0] = (byte) tag;
        System.arraycopy(lenBytes, 0, result, 1, lenBytes.length);
        int offset = 1 + lenBytes.length;
        for (byte[] c : contents) {
            System.arraycopy(c, 0, result, offset, c.length);
            offset += c.length;
        }
        return result;
    }

    private static byte[] derExplicit(int tagNumber, byte[] content) {
        int tag = 0xA0 | tagNumber;
        byte[] lenBytes = derLength(content.length);
        byte[] result = new byte[1 + lenBytes.length + content.length];
        result[0] = (byte) tag;
        System.arraycopy(lenBytes, 0, result, 1, lenBytes.length);
        System.arraycopy(content, 0, result, 1 + lenBytes.length, content.length);
        return result;
    }

    private static byte[] derInteger(BigInteger value) {
        byte[] encoded = value.toByteArray();
        byte[] lenBytes = derLength(encoded.length);
        byte[] result = new byte[1 + lenBytes.length + encoded.length];
        result[0] = 0x02;
        System.arraycopy(lenBytes, 0, result, 1, lenBytes.length);
        System.arraycopy(encoded, 0, result, 1 + lenBytes.length, encoded.length);
        return result;
    }

    private static byte[] derOid(int[] components) {
        // First two components encoded as 40*c[0] + c[1]
        java.io.ByteArrayOutputStream oidBytes = new java.io.ByteArrayOutputStream();
        oidBytes.write(40 * components[0] + components[1]);
        for (int i = 2; i < components.length; i++) {
            int val = components[i];
            if (val < 128) {
                oidBytes.write(val);
            } else {
                // Multi-byte encoding
                byte[] stack = new byte[5];
                int pos = 4;
                stack[pos--] = (byte) (val & 0x7F);
                val >>= 7;
                while (val > 0) {
                    stack[pos--] = (byte) ((val & 0x7F) | 0x80);
                    val >>= 7;
                }
                oidBytes.write(stack, pos + 1, 4 - pos);
            }
        }
        byte[] oid = oidBytes.toByteArray();
        byte[] lenBytes = derLength(oid.length);
        byte[] result = new byte[1 + lenBytes.length + oid.length];
        result[0] = 0x06;
        System.arraycopy(lenBytes, 0, result, 1, lenBytes.length);
        System.arraycopy(oid, 0, result, 1 + lenBytes.length, oid.length);
        return result;
    }

    private static byte[] derUtf8String(String s) {
        byte[] bytes = s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] lenBytes = derLength(bytes.length);
        byte[] result = new byte[1 + lenBytes.length + bytes.length];
        result[0] = 0x0C; // UTF8String
        System.arraycopy(lenBytes, 0, result, 1, lenBytes.length);
        System.arraycopy(bytes, 0, result, 1 + lenBytes.length, bytes.length);
        return result;
    }

    private static byte[] derBitString(byte[] content) {
        // Bit string: tag 0x03, length, 0x00 (no unused bits), content
        int len = 1 + content.length;
        byte[] lenBytes = derLength(len);
        byte[] result = new byte[1 + lenBytes.length + len];
        result[0] = 0x03;
        System.arraycopy(lenBytes, 0, result, 1, lenBytes.length);
        result[1 + lenBytes.length] = 0x00; // no unused bits
        System.arraycopy(content, 0, result, 2 + lenBytes.length, content.length);
        return result;
    }

    private static byte[] derOctetString(byte[] content) {
        byte[] lenBytes = derLength(content.length);
        byte[] result = new byte[1 + lenBytes.length + content.length];
        result[0] = 0x04;
        System.arraycopy(lenBytes, 0, result, 1, lenBytes.length);
        System.arraycopy(content, 0, result, 1 + lenBytes.length, content.length);
        return result;
    }

    @SuppressWarnings("deprecation")
    private static byte[] derUtcTime(Date date) {
        // UTCTime format: YYMMDDHHMMSSZ
        String utc = String.format("%02d%02d%02d%02d%02d%02dZ",
                date.getYear() % 100, date.getMonth() + 1, date.getDate(),
                date.getHours(), date.getMinutes(), date.getSeconds());
        byte[] bytes = utc.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] result = new byte[2 + bytes.length];
        result[0] = 0x17; // UTCTime
        result[1] = (byte) bytes.length;
        System.arraycopy(bytes, 0, result, 2, bytes.length);
        return result;
    }

    private static byte[] derLength(int length) {
        if (length < 128) {
            return new byte[]{(byte) length};
        } else if (length < 256) {
            return new byte[]{(byte) 0x81, (byte) length};
        } else {
            return new byte[]{(byte) 0x82, (byte) (length >> 8), (byte) (length & 0xFF)};
        }
    }
}
