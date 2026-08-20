package org.tidecloak.iga.crypto;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import java.util.Arrays;
import java.util.Date;

/**
 * Validates the certificates the ORK cohort returns before they are committed to the database.
 *
 * <h2>Why this exists</h2>
 * Tidecloak sends CSRs and gets back certificates it did not construct. The ORK builds every
 * TBSCertificate itself — subject, validity, serial, extensions — so nothing about the issued
 * certificate is guaranteed by construction on this side. Persisting whatever comes back would
 * mean trusting the response shape blindly and only discovering a mismatch when a workload's TLS
 * handshake fails in production, long after the change request was approved and closed.
 *
 * <p>Every check here answers "is this the certificate we asked for?" rather than "is this
 * well-formed?". The expensive-to-debug failure is a certificate that parses perfectly but
 * certifies the wrong key, outlives its mandate, or carries permissions nobody approved.
 */
public final class IssuedCertificateValidator {

    /**
     * Refuse a workload leaf whose validity window is longer than this. The ORK issues 10 years.
     */
    private static final long MAX_LEAF_LIFETIME_MILLIS = 11L * 365 * 24 * 3600 * 1000;
    /**
     * Refuse a realm server certificate whose validity window is longer than this. The ORK issues
     * 20 years — the same window as the root CA, twice what a workload leaf gets, because
     * Tidecloak's own TLS identity is not re-enrolled on the workload cadence.
     *
     * <p>Kept separate from {@link #MAX_CA_LIFETIME_MILLIS} even though the values match: this
     * certificate is an END ENTITY (basicConstraints CA=false, serverAuth) and only happens to
     * share the CA's lifetime. Collapsing the two would silently widen whichever one changed next.
     *
     * <p>21 years rather than 20 for the same reason the CA bound is: 20 calendar years spans 5
     * leap days, so an exactly-20-year ceiling would reject the very certificate the ORK issues.
     */
    private static final long MAX_REALM_CERT_LIFETIME_MILLIS = 21L * 365 * 24 * 3600 * 1000;
    /** Refuse a CA whose validity window is longer than this. The ORK issues 20 years. */
    private static final long MAX_CA_LIFETIME_MILLIS = 21L * 365 * 24 * 3600 * 1000;
    /** Tolerance for clock skew between this host and the cohort when checking notBefore. */
    private static final long CLOCK_SKEW_MILLIS = 5L * 60 * 1000;

    private static final BouncyCastleProvider BC = new BouncyCastleProvider();

    private IssuedCertificateValidator() {
    }

    /** Thrown when an issued certificate is not the one that was requested. */
    public static class InvalidIssuedCertificateException extends RuntimeException {
        public InvalidIssuedCertificateException(String message) {
            super(message);
        }

        public InvalidIssuedCertificateException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** What a validated leaf yielded, so the caller can persist it without re-parsing. */
    public static final class ValidatedCertificate {
        public final long notBefore;
        public final long notAfter;

        ValidatedCertificate(long notBefore, long notAfter) {
            this.notBefore = notBefore;
            this.notAfter = notAfter;
        }
    }

    /**
     * Validate the resource-identity (workload mTLS client) certificate.
     *
     * @param certificateDer  the assembled certificate
     * @param expectedSpkiDer the SubjectPublicKeyInfo from the CSR that was submitted
     * @param expectedIssuer  {@code CN=realm_<name>_ca}
     */
    public static ValidatedCertificate validateResourceCertificate(byte[] certificateDer,
                                                                   byte[] expectedSpkiDer,
                                                                   String expectedIssuer,
                                                                   byte[] issuerRawPublicKey) {
        X509CertificateHolder cert = parse(certificateDer, "resource certificate");
        requireSubjectPublicKey(cert, expectedSpkiDer, "resource certificate");
        requireIssuer(cert, expectedIssuer, "resource certificate");
        ValidatedCertificate validity = requireValidity(cert, MAX_LEAF_LIFETIME_MILLIS, "resource certificate");
        requireEndEntity(cert, "resource certificate");
        requireKeyUsage(cert, KeyUsage.digitalSignature, "resource certificate");
        requireExtendedKeyUsage(cert, KeyPurposeId.id_kp_clientAuth, "resource certificate");
        requireSignedBy(cert, issuerRawPublicKey, "resource certificate");
        return validity;
    }

    /**
     * Validate the Tidecloak realm server certificate. Same shape as the resource certificate but
     * serverAuth rather than clientAuth, and its key is Tidecloak's own rather than the workload's.
     *
     * <p>Its permitted lifetime is the one real difference: {@link #MAX_REALM_CERT_LIFETIME_MILLIS}
     * rather than the workload leaf's 11 years, because the ORK issues this one for 20 years.
     */
    public static ValidatedCertificate validateRealmCertificate(byte[] certificateDer,
                                                                byte[] expectedSpkiDer,
                                                                String expectedIssuer,
                                                                byte[] issuerRawPublicKey) {
        X509CertificateHolder cert = parse(certificateDer, "realm certificate");
        requireSubjectPublicKey(cert, expectedSpkiDer, "realm certificate");
        requireIssuer(cert, expectedIssuer, "realm certificate");
        ValidatedCertificate validity = requireValidity(cert, MAX_REALM_CERT_LIFETIME_MILLIS, "realm certificate");
        requireEndEntity(cert, "realm certificate");
        requireKeyUsage(cert, KeyUsage.digitalSignature, "realm certificate");
        requireExtendedKeyUsage(cert, KeyPurposeId.id_kp_serverAuth, "realm certificate");
        requireSignedBy(cert, issuerRawPublicKey, "realm certificate");
        return validity;
    }

    /**
     * Validate the realm root CA. This one is self-issued and self-signed by the gVVK, and it is
     * the trust anchor handed to workloads — so the checks that matter are that it certifies the
     * gVVK we expect and that it cannot mint subordinate CAs.
     */
    public static ValidatedCertificate validateRootCa(byte[] certificateDer,
                                                      String expectedSubject,
                                                      byte[] gvvkRawPublicKey) {
        X509CertificateHolder cert = parse(certificateDer, "root CA");

        // The anchor must certify the gVVK itself — otherwise it anchors trust in a key the
        // cohort does not hold, and every leaf under it is meaningless.
        SubjectPublicKeyInfo subjectPublicKeyInfo = cert.getSubjectPublicKeyInfo();
        if (!EdECObjectIdentifiers.id_Ed25519.equals(subjectPublicKeyInfo.getAlgorithm().getAlgorithm())) {
            throw new InvalidIssuedCertificateException("root CA subject key is not Ed25519");
        }
        if (!Arrays.equals(subjectPublicKeyInfo.getPublicKeyData().getOctets(), gvvkRawPublicKey)) {
            throw new InvalidIssuedCertificateException(
                    "root CA does not certify this realm's gVVK");
        }

        requireIssuer(cert, expectedSubject, "root CA");
        if (!new X500Name(expectedSubject).equals(cert.getSubject())) {
            throw new InvalidIssuedCertificateException(
                    "root CA subject is '" + cert.getSubject() + "', expected '" + expectedSubject + "'");
        }

        ValidatedCertificate validity = requireValidity(cert, MAX_CA_LIFETIME_MILLIS, "root CA");

        BasicConstraints constraints = BasicConstraints.fromExtensions(requireExtensions(cert, "root CA"));
        if (constraints == null || !constraints.isCA()) {
            throw new InvalidIssuedCertificateException("root CA is not marked CA:TRUE");
        }
        // pathlen 0: it may issue end entities and nothing else. A missing or larger pathlen would
        // let it certify further CAs.
        if (constraints.getPathLenConstraint() == null
                || constraints.getPathLenConstraint().intValue() != 0) {
            throw new InvalidIssuedCertificateException(
                    "root CA must carry pathLenConstraint 0 so it cannot issue subordinate CAs");
        }
        requireKeyUsage(cert, KeyUsage.keyCertSign | KeyUsage.cRLSign, "root CA");
        requireSignedBy(cert, gvvkRawPublicKey, "root CA");
        return validity;
    }

    // --- individual checks ---

    /**
     * The certificate must certify EXACTLY the key that was requested. This is the check that
     * catches a swapped or substituted subject key, and it is a byte comparison of the whole
     * SubjectPublicKeyInfo so a re-encoded or differently-parameterised key also fails.
     */
    private static void requireSubjectPublicKey(X509CertificateHolder cert, byte[] expectedSpkiDer,
                                                String certificateLabel) {
        byte[] actual;
        try {
            actual = cert.getSubjectPublicKeyInfo().getEncoded(ASN1Encoding.DER);
        } catch (Exception e) {
            throw new InvalidIssuedCertificateException(certificateLabel + ": subject key cannot be re-encoded", e);
        }
        if (!Arrays.equals(actual, expectedSpkiDer)) {
            throw new InvalidIssuedCertificateException(
                    certificateLabel + " certifies a different public key than the CSR requested");
        }
    }

    private static void requireIssuer(X509CertificateHolder cert, String expectedIssuer, String certificateLabel) {
        if (!new X500Name(expectedIssuer).equals(cert.getIssuer())) {
            throw new InvalidIssuedCertificateException(certificateLabel + " issuer is '" + cert.getIssuer()
                    + "', expected '" + expectedIssuer + "'");
        }
    }

    /**
     * Reject an already-expired certificate, one that is not yet valid beyond clock skew, and one
     * whose window is implausibly long. The last check is the one that matters: a certificate with
     * a 100-year life is a standing credential nobody approved.
     */
    private static ValidatedCertificate requireValidity(X509CertificateHolder cert, long maxLifetime,
                                                        String certificateLabel) {
        Date notBefore = cert.getNotBefore();
        Date notAfter = cert.getNotAfter();
        if (notBefore == null || notAfter == null) {
            throw new InvalidIssuedCertificateException(certificateLabel + " has no validity window");
        }
        long now = System.currentTimeMillis();
        if (!notAfter.after(notBefore)) {
            throw new InvalidIssuedCertificateException(certificateLabel + " notAfter is not after notBefore");
        }
        if (notAfter.getTime() <= now) {
            throw new InvalidIssuedCertificateException(certificateLabel + " is already expired (notAfter "
                    + notAfter + ")");
        }
        if (notBefore.getTime() > now + CLOCK_SKEW_MILLIS) {
            throw new InvalidIssuedCertificateException(certificateLabel + " is not valid until " + notBefore
                    + ", beyond acceptable clock skew");
        }
        long lifetime = notAfter.getTime() - notBefore.getTime();
        if (lifetime > maxLifetime) {
            throw new InvalidIssuedCertificateException(certificateLabel + " validity window of " + (lifetime / 86400000L)
                    + " days exceeds the permitted maximum of " + (maxLifetime / 86400000L) + " days");
        }
        return new ValidatedCertificate(notBefore.getTime(), notAfter.getTime());
    }

    /** A leaf must not be able to sign other certificates. */
    private static void requireEndEntity(X509CertificateHolder cert, String certificateLabel) {
        BasicConstraints constraints = BasicConstraints.fromExtensions(requireExtensions(cert, certificateLabel));
        if (constraints == null) {
            throw new InvalidIssuedCertificateException(certificateLabel + " has no basicConstraints extension");
        }
        if (constraints.isCA()) {
            throw new InvalidIssuedCertificateException(
                    certificateLabel + " is marked CA:TRUE — a leaf must not be able to issue certificates");
        }
    }

    /** The certificate's keyUsage must be exactly the permitted set — no extra bits. */
    private static void requireKeyUsage(X509CertificateHolder cert, int expectedBits, String certificateLabel) {
        KeyUsage keyUsage = KeyUsage.fromExtensions(requireExtensions(cert, certificateLabel));
        if (keyUsage == null) {
            throw new InvalidIssuedCertificateException(certificateLabel + " has no keyUsage extension");
        }
        if (!keyUsage.hasUsages(expectedBits)) {
            throw new InvalidIssuedCertificateException(certificateLabel + " is missing a required keyUsage bit");
        }
        // Extra bits are a privilege nobody approved, so treat them as a failure rather than
        // a curiosity: keyCertSign appearing on a leaf is exactly the case worth catching.
        KeyUsage permitted = new KeyUsage(expectedBits);
        if (!Arrays.equals(keyUsage.getBytes(), permitted.getBytes())) {
            throw new InvalidIssuedCertificateException(
                    certificateLabel + " carries keyUsage bits beyond those permitted");
        }
    }

    /** The certificate must carry the expected EKU, and must not carry any other. */
    private static void requireExtendedKeyUsage(X509CertificateHolder cert, KeyPurposeId expected,
                                                String certificateLabel) {
        ExtendedKeyUsage extendedKeyUsage = ExtendedKeyUsage.fromExtensions(requireExtensions(cert, certificateLabel));
        if (extendedKeyUsage == null) {
            throw new InvalidIssuedCertificateException(certificateLabel + " has no extendedKeyUsage extension");
        }
        if (!extendedKeyUsage.hasKeyPurposeId(expected)) {
            throw new InvalidIssuedCertificateException(certificateLabel + " is missing extendedKeyUsage "
                    + expected.getId());
        }
        if (extendedKeyUsage.size() != 1) {
            throw new InvalidIssuedCertificateException(certificateLabel
                    + " carries extendedKeyUsage purposes beyond " + expected.getId());
        }
    }

    /**
     * The certificate's signature must verify under the issuing key. Without this, every other
     * check is checking the contents of an unauthenticated blob — a caller who could influence the
     * response could hand back any certificate at all.
     */
    private static void requireSignedBy(X509CertificateHolder cert, byte[] issuerRawPublicKey,
                                        String certificateLabel) {
        SubjectPublicKeyInfo issuerSpki = new SubjectPublicKeyInfo(
                new org.bouncycastle.asn1.x509.AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                issuerRawPublicKey);
        try {
            ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder()
                    .setProvider(BC)
                    .build(issuerSpki);
            if (!cert.isSignatureValid(verifier)) {
                throw new InvalidIssuedCertificateException(
                        certificateLabel + " signature does not verify under the realm's gVVK");
            }
        } catch (InvalidIssuedCertificateException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidIssuedCertificateException(
                    certificateLabel + " signature could not be verified", e);
        }
    }

    private static Extensions requireExtensions(X509CertificateHolder cert, String certificateLabel) {
        Extensions extensions = cert.getExtensions();
        if (extensions == null) {
            throw new InvalidIssuedCertificateException(certificateLabel + " has no extensions");
        }
        return extensions;
    }

    private static X509CertificateHolder parse(byte[] certificateDer, String certificateLabel) {
        try {
            return new X509CertificateHolder(Certificate.getInstance(certificateDer));
        } catch (Exception e) {
            throw new InvalidIssuedCertificateException(
                    certificateLabel + " returned by the ORK is not a well-formed X.509 certificate", e);
        }
    }
}
