package org.tidecloak.iga.crypto;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.StringReader;
import java.util.Base64;

/**
 * Reads the workload's PKCS#10 ({@code CertificationRequest}, RFC 2986) enrolment request and
 * verifies its proof of possession.
 *
 * <h2>Proof of possession</h2>
 * A PKCS#10 request is self-signed: the {@code signature} field is the requester's signature over
 * the DER of {@code certificationRequestInfo}, made with the private key matching the
 * {@code subjectPKInfo} carried inside it. {@link #parseAndVerify} checks that signature, so a
 * request that parses has proven the caller holds the private key for the public key it asks to
 * have certified. A caller cannot enrol a key it does not control — in particular it cannot
 * replay another workload's public key, because it could not produce the self-signature.
 *
 * <h2>P-256 only</h2>
 * The ORK accepts only a P-256 subject key, for both the resource and the realm CSR, so
 * {@link #parseAndVerify} rejects anything else up front. Enforcing it here rather than at each
 * call site is deliberate: all three callers — the public enrolment endpoint, the admin-filed
 * request, and the realm CSR this module generates for itself — are subject to the same rule, and
 * a check duplicated per caller is one that eventually gets missed on a new one.
 *
 * <p>The alternative, letting a wrong-curve CSR through to be refused by the cohort, wastes an
 * entire approval round: the request would file, sit in the queue, be approved by admins, and only
 * fail at commit. Rejecting at submission is a 400 to the caller that can still fix it.
 *
 * <p>Only the NAMED curve is accepted. A CSR carrying explicit curve parameters is refused even if
 * the parameters happen to describe P-256 — the ORK matches the named curve, and explicit
 * parameters are a well-known source of both interop failures and validation bugs.
 *
 * <p>The proof-of-possession check itself stays algorithm-driven: it verifies the self-signature
 * under whatever the CSR declares. The ORK carries this {@code SubjectPublicKeyInfo} verbatim into
 * the certificate it builds, so the issued certificate's subject-key algorithm is true by
 * construction. Independently of the subject key, an issued certificate's own
 * {@code signatureAlgorithm} is always Ed25519, because the gVVK that signs it is an Ed25519 key —
 * X.509 keeps the two fields independent — an Ed25519 CA can certify a P-256 subject key.
 *
 * <h2>Why Bouncy Castle</h2>
 * This class parses unauthenticated, caller-supplied bytes as the first step of a security gate,
 * so all ASN.1 handling is delegated to {@code bcpkix} rather than hand-rolled. Bouncy Castle
 * (bcpkix / bcprov / bcutil) is already on the Keycloak server runtime classpath under
 * {@code /opt/keycloak/lib/lib/main/}, so the dependency is declared {@code provided} like every
 * other runtime-supplied artifact in this module's pom.
 */
public final class CertificationRequestParser {

    /**
     * Passed explicitly to the verifier builder rather than looked up by name, so this does not
     * depend on BC being registered as a JVM security provider.
     */
    private static final BouncyCastleProvider BC = new BouncyCastleProvider();

    private CertificationRequestParser() {
    }

    /** Thrown for any malformed, unsupported, or unverifiable CSR. Message is caller-safe. */
    public static class InvalidCsrException extends IllegalArgumentException {
        public InvalidCsrException(String message) {
            super(message);
        }

        public InvalidCsrException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** What the enrolment flow needs out of a verified CSR. */
    public static final class ParsedCsr {
        /** The subject Common Name — the requesting client's clientId. */
        public final String commonName;
        /**
         * The DER {@code SubjectPublicKeyInfo} from the CSR. The whole SPKI is kept — not just the
         * key bits — because it is self-describing: it names the key's algorithm alongside the key
         * material, so {@link ServerCertBuilder} can copy it into the issued certificate without
         * having to be told what algorithm it is.
         *
         * <p>Returned as bytes, not text. Callers that persist it into the TEXT column
         * {@code IGA_SERVER_CERT_DRAFT.PUBLIC_KEY} encode it there; callers that hash or sign it
         * use it directly.
         */
        public final byte[] subjectPublicKeyInfo;
        /**
         * The CSR itself, normalised to DER regardless of whether it arrived as PEM. This is the
         * form the ORK consumes ({@code CertificateRequest.LoadSigningRequest(bytes)}), so it is
         * what gets persisted and replayed into the signing request — never the original text.
         */
        public final byte[] derEncoded;

        ParsedCsr(String commonName, byte[] subjectPublicKeyInfo, byte[] derEncoded) {
            this.commonName = commonName;
            this.subjectPublicKeyInfo = subjectPublicKeyInfo;
            this.derEncoded = derEncoded;
        }
    }

    /**
     * Parse a PKCS#10 CSR and verify its self-signature (proof of possession).
     *
     * @param csrBlob the CSR as PEM ({@code -----BEGIN CERTIFICATE REQUEST-----}) or as bare
     *                base64/base64url DER
     * @return the subject CN and the subject SubjectPublicKeyInfo
     * @throws InvalidCsrException if the blob is not a well-formed PKCS#10 request, if it carries
     *                             no Common Name, or if the self-signature does not verify
     */
    public static ParsedCsr parseAndVerify(String csrBlob) {
        PKCS10CertificationRequest csr = read(csrBlob);

        SubjectPublicKeyInfo subjectPublicKeyInfo = csr.getSubjectPublicKeyInfo();
        String commonName = commonNameOf(csr.getSubject());

        requireP256(subjectPublicKeyInfo);
        verifyProofOfPossession(csr, subjectPublicKeyInfo);

        try {
            return new ParsedCsr(commonName,
                    subjectPublicKeyInfo.getEncoded(ASN1Encoding.DER),
                    csr.getEncoded());
        } catch (Exception e) {
            throw new InvalidCsrException("CSR cannot be re-encoded", e);
        }
    }

    /**
     * The subject key must be an EC key on the NAMED P-256 curve — the only key the ORK certifies.
     *
     * <p>Runs before the proof-of-possession check so a wrong-curve CSR is refused on the cheaper
     * test, and so the error names the actual problem rather than surfacing as a signature failure.
     */
    private static void requireP256(SubjectPublicKeyInfo subjectPublicKeyInfo) {
        AlgorithmIdentifier algorithm = subjectPublicKeyInfo.getAlgorithm();
        if (!X9ObjectIdentifiers.id_ecPublicKey.equals(algorithm.getAlgorithm())) {
            throw new InvalidCsrException("CSR subject public key must be P-256; got algorithm OID "
                    + algorithm.getAlgorithm());
        }
        // A named curve encodes its parameters as the curve OID. Explicit parameters decode to a
        // sequence instead and are refused even when they describe P-256 — see the class javadoc.
        ASN1Encodable parameters = algorithm.getParameters();
        if (!(parameters instanceof ASN1ObjectIdentifier)
                || !X9ObjectIdentifiers.prime256v1.equals(parameters)) {
            throw new InvalidCsrException("CSR subject public key must be on the named P-256 "
                    + "(prime256v1) curve");
        }
    }

    /**
     * The proof-of-possession check: the CSR's own signature over certificationRequestInfo must
     * verify under the public key the CSR asks to have certified.
     */
    private static void verifyProofOfPossession(PKCS10CertificationRequest csr,
                                                SubjectPublicKeyInfo subjectPublicKeyInfo) {
        ContentVerifierProvider verifier;
        try {
            verifier = new JcaContentVerifierProviderBuilder()
                    .setProvider(BC)
                    .build(subjectPublicKeyInfo);
        } catch (Exception e) {
            throw new InvalidCsrException("CSR subject public key is not a usable public key", e);
        }
        boolean verified;
        try {
            verified = csr.isSignatureValid(verifier);
        } catch (Exception e) {
            throw new InvalidCsrException("CSR proof of possession failed: signature is malformed", e);
        }
        if (!verified) {
            throw new InvalidCsrException("CSR proof of possession failed: self-signature does not "
                    + "verify against the subject public key");
        }
    }

    /** First Common Name in the subject DN. */
    private static String commonNameOf(X500Name subject) {
        RDN[] cns = subject.getRDNs(BCStyle.CN);
        if (cns.length == 0) {
            throw new InvalidCsrException("CSR subject has no Common Name (CN)");
        }
        String commonName = IETFUtils.valueToString(cns[0].getFirst().getValue());
        if (commonName == null || commonName.isBlank()) {
            throw new InvalidCsrException("CSR subject has no Common Name (CN)");
        }
        return commonName;
    }

    /** Accept PEM or bare base64 / base64url DER. */
    private static PKCS10CertificationRequest read(String csrBlob) {
        if (csrBlob == null || csrBlob.isBlank()) {
            throw new InvalidCsrException("Missing CSR");
        }
        String blob = csrBlob.trim();
        try {
            if (blob.contains("-----BEGIN")) {
                try (PEMParser pemParser = new PEMParser(new StringReader(blob))) {
                    Object parsed = pemParser.readObject();
                    if (!(parsed instanceof PKCS10CertificationRequest)) {
                        throw new InvalidCsrException("PEM body is not a certificate request");
                    }
                    return (PKCS10CertificationRequest) parsed;
                }
            }
            // Bare base64: strip line wrapping and normalise base64url to standard base64.
            byte[] derBytes = Base64.getDecoder().decode(
                    blob.replaceAll("\\s", "").replace('-', '+').replace('_', '/'));
            return new PKCS10CertificationRequest(derBytes);
        } catch (InvalidCsrException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidCsrException("CSR is not a well-formed PKCS#10 request", e);
        }
    }
}
