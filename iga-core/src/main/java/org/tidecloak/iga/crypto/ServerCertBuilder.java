package org.tidecloak.iga.crypto;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.TBSCertificate;

import java.io.IOException;
import java.util.Base64;

/**
 * Certificate ASSEMBLY only — Tidecloak no longer builds TBSCertificates.
 *
 * <p>Under {@code ResourceIdentity:1} the ORK constructs every TBSCertificate (subject, validity,
 * serial, extensions, SANs) from the CSRs it is sent, and returns those TBS bytes alongside the
 * threshold signatures. All this class does is staple the two together into a DER certificate.
 *
 * <p>Everything that used to live here — {@code buildTbs}, {@code buildVvkCaTbs}, the DN/extension
 * construction — is gone, because building a TBS locally and having it signed remotely is exactly
 * the model that was replaced. Do not reintroduce it: the ORK stamps its own validity window and
 * serial, so a locally rebuilt TBS will not match the signature.
 */
public final class ServerCertBuilder {

    /**
     * The issuing key's algorithm. The realm root CA is the gVVK, always Ed25519 (RFC 8410 §3:
     * id-Ed25519, absent parameters). This TLV must be byte-identical to the one the ORK embedded
     * in {@code TBSCertificate.signature}, since it is copied into the outer
     * {@code Certificate.signatureAlgorithm} field and the two must agree.
     */
    private static final AlgorithmIdentifier ED25519_SIG_ALG =
            new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519);

    /** RFC 7468 line length for PEM base64 bodies. */
    private static final int PEM_LINE_LENGTH = 64;

    private ServerCertBuilder() {
    }

    /**
     * Assemble a complete X.509 certificate from an ORK-built TBS and its cohort signature.
     *
     * @param tbsCertificate DER TBSCertificate exactly as returned by the ORK — never a local rebuild
     * @param signatureBytes the 64-byte Ed25519 signature the cohort produced over those bytes
     * @return DER-encoded X.509 certificate
     */
    public static byte[] assembleCertificate(byte[] tbsCertificate, byte[] signatureBytes) {
        ASN1EncodableVector certificate = new ASN1EncodableVector();
        certificate.add(TBSCertificate.getInstance(tbsCertificate));
        certificate.add(ED25519_SIG_ALG);
        certificate.add(new DERBitString(signatureBytes));
        try {
            return new DERSequence(certificate).getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to assemble certificate", e);
        }
    }

    /** Convert a DER certificate to PEM. */
    public static String toPem(byte[] derCert) {
        String base64 = Base64.getEncoder().encodeToString(derCert);
        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN CERTIFICATE-----\n");
        for (int offset = 0; offset < base64.length(); offset += PEM_LINE_LENGTH) {
            pem.append(base64, offset, Math.min(offset + PEM_LINE_LENGTH, base64.length()));
            pem.append('\n');
        }
        pem.append("-----END CERTIFICATE-----");
        return pem.toString();
    }
}
