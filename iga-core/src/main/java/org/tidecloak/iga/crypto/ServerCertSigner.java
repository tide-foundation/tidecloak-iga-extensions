package org.tidecloak.iga.crypto;

import org.bouncycastle.cert.X509CertificateHolder;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.urls.UrlType;
import org.keycloak.common.util.MultivaluedHashMap;

import org.midgard.Midgard;
import org.midgard.Serialization.Tools;
import org.midgard.models.ModelRequest;
import org.midgard.models.RequestExtensions.ResourceIdentitySignRequest;
import org.midgard.models.SignRequestSettingsMidgard;
import org.midgard.models.SignatureResponse;
import org.tidecloak.iga.attestors.TideAttestor;
import org.tidecloak.iga.entities.IgaRealmCertEntity;
import org.tidecloak.iga.entities.IgaServerCertDraftEntity;

import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Server-identity signing seam against the ORK's {@code ResourceIdentity:1} request.
 *
 * <p>Tidecloak does not build certificates. It submits CSRs; the cohort constructs every
 * TBSCertificate and threshold-signs it with the gVVK, returning the TBS bytes it built alongside
 * the signatures. This class frames that request, then pairs the two halves back together.
 *
 * <h2>ORK contract</h2>
 * The draft layout is owned by {@link ResourceIdentitySignRequest} in MidgardJava, which mirrors
 * {@code Ork/Models/TideRequests/Authorization/TidecloakToken/ResourceIdentitySignRequest.cs}.
 * Building it by hand here would duplicate a wire format that already has one authority, so this
 * class only supplies the inputs and lets that request serialize them.
 *
 * <h2>Two modes</h2>
 * The request carries two INDEPENDENT optional sub-requests, and at least one must be set:
 * {@code SetResourceIdentityRequest} (the per-client leaf) and {@code SetTidecloakRealmRequest}
 * (the realm server certificate, which also yields the realm root CA). This class drives them
 * separately, because their lifecycles are: a client leaf is per (client, keypair) and reissued on
 * every enrolment, whereas the realm pair is realm-scoped. Asking for both on every enrolment would
 * re-issue Tidecloak's own TLS certificate each time a workload enrolled.
 * <ul>
 *   <li><b>Client mode</b> — {@link #buildApprovalModel} / {@link #issue}: resource request only.</li>
 *   <li><b>Realm mode</b> — {@link #buildRealmApprovalModel} / {@link #issueRealm}: realm request
 *       only. The root CA rides along with it and cannot be requested on its own.</li>
 * </ul>
 * The realm attestation is required in BOTH modes: the ORK verifies it and takes the realm name
 * from it (for the {@code CN=realm_<name>_ca} issuer) before it looks at which certificates were
 * asked for.
 *
 * <h2>Request draft vs response — two different slot spaces</h2>
 * <b>Draft slots are FIXED:</b> realm attestation, resource request, realm request. Slots 2 and 3
 * are always written — an unrequested certificate is a present but zero-length slot, not a missing
 * one. The certificate timestamp is NOT in the draft: it rides in dynamic data, outside the bytes
 * the admins authorize, and is stamped at send time ({@link #stampCertificateTimestamp}).
 *
 * <p><b>Response slots are COMPACTED.</b> {@code AdditionalData} is a {@code TideMemory} of the TBS
 * bytes the cohort built and {@code Signatures} are in the same order, but the ORK only appends a
 * slot for what was actually requested. So the index of a given certificate depends on the mode:
 * <pre>
 *   client mode  -> [0] resource
 *   realm mode   -> [0] realm server certificate, [1] root CA
 *   (both)       -> [0] resource, [1] realm server certificate, [2] root CA
 * </pre>
 * Reading a fixed index across modes therefore mismatches; each mode has its own constants below.
 */
public final class ServerCertSigner {

    private static final Logger logger = Logger.getLogger(ServerCertSigner.class);

    /** Matches {@link ResourceIdentitySignRequest}'s own Name/Version; used for the VRK creation-auth. */
    private static final String MODEL_ID = "ResourceIdentity:1";

    private static final String TIDE_VENDOR_KEY_PROVIDER_ID = "tide-vendor-key";
    private static final String CFG_GVRK = "gVRK";
    private static final String CFG_GVRK_CERTIFICATE = "gVRKCertificate";
    /** The "clientId" config key stores the gVVK public key (source convention, kept as-is). */
    private static final String CFG_GVVK = "clientId";

    /** Approval window for the carrier — NOT the certificate lifetime, which the ORK sets. */
    private static final long CARRIER_EXPIRY_SECONDS = 86400L;

    /**
     * Response slot indices, per mode. {@code PrepareDatasToSign} appends a slot only for a
     * sub-request that was actually set, so these are NOT interchangeable across modes — see the
     * class javadoc.
     */
    /** Client mode: the resource leaf is the only slot returned. */
    private static final int CLIENT_MODE_SLOT_RESOURCE = 0;
    /** Realm mode: server certificate first, then the root CA the ORK appends with it. */
    private static final int REALM_MODE_SLOT_SERVER = 0;
    private static final int REALM_MODE_SLOT_ROOT_CA = 1;

    private ServerCertSigner() {
    }

    // -------------------------------------------------------------------------
    // PHASE 1 — build the approval carrier
    // -------------------------------------------------------------------------
    public static String buildApprovalModel(KeycloakSession session, RealmModel realm,
                                            IgaServerCertDraftEntity draft,
                                            byte[] adminPolicyBytes) {
        MultivaluedHashMap<String, String> config = requireVendorKeyConfig(realm);
        try {
            boolean capable = TideAttestor.isRealSigningCapableRealm(realm);
            // Which authorization the cohort must demand of the finished carrier — see
            // #authorizedByDokenQuorum.
            boolean usePolicy = authorizedByDokenQuorum(session, realm);

            ResourceIdentitySignRequest request = new ResourceIdentitySignRequest(usePolicy);
            request.SetRealmAttestation(ResourceIdentityAttestations.realmConfig(session, realm));
            request.SetResourceIdentityRequest(
                    Base64.getUrlDecoder().decode(draft.getCsr()),
                    ResourceIdentityAttestations.clientConfig(session, realm, draft),
                    HexFormat.of().parseHex(draft.getSerialNumber()));
            // SetTidecloakRealmRequest is deliberately NOT called: the realm server certificate and
            // the root CA are realm-scoped, not per-enrolment, so requesting them on every workload
            // enrolment would re-issue Tidecloak's own TLS certificate each time. Leaving it unset
            // emits DRAFT slot 3 zero-length, which is how the ORK reads "resource identity only".
            // The realm pair is requested separately by buildRealmApprovalModel.

            // Override the 30-second default expiry from the constructor — this carrier has to
            // survive the admin approval window, not a single round-trip.
            request.SetCustomExpiry(System.currentTimeMillis() / 1000L + CARRIER_EXPIRY_SECONDS);

            // Authorize LAST: both paths sign over GetDataToAuthorize() = SHA512(draft) + expiry,
            // so every Set* that shapes the draft or the expiry has already run above.
            if (capable) {
                if (usePolicy) {
                    initializeCreationAuth(realm, request, config);   // multiAdmin: creation-auth, dokens follow
                } else {
                    authorizeWithVrk(realm, request, config);         // firstAdmin: VRK IS the approval
                }
            }
            // Only a Policy:1 carrier carries a Policy — it is what the ORK validates the collected
            // dokens against. A GVRK:1 carrier has no doken quorum to validate, so attaching one
            // there would be meaningless.
            if (usePolicy && adminPolicyBytes != null) {
                request.SetPolicy(adminPolicyBytes);
            }

            logger.infof("IGA server-cert: built %s carrier for client %s (realm %s, creation-auth=%s, "
                            + "authFlow=%s)",
                    MODEL_ID, draft.getClientId(), realm.getName(), capable ? "VRK" : "none(dev)",
                    usePolicy ? "Policy:1" : "VRK:1");
            return Base64.getEncoder().encodeToString(request.Encode());
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("IGA server-cert: failed to build " + MODEL_ID
                    + " carrier for realm " + realm.getName() + ": " + e.getMessage(), e);
        }
    }

    /**
     * Build the REALM-mode {@code ResourceIdentity:1} carrier the admin quorum dokens — the realm
     * server certificate request, which the ORK answers with that certificate AND the realm root CA.
     *
     * <p>The mirror of {@link #buildApprovalModel}: {@code SetResourceIdentityRequest} is NOT called
     * here, so draft slot 2 goes out zero-length and the cohort issues no per-client leaf. The realm
     * attestation is still required — the ORK reads the realm name out of it to build the
     * {@code CN=realm_<name>_ca} issuer before it looks at what was requested.
     *
     * <p>Two things are deliberately not sent. There is no root-CA CSR or serial: the cohort builds
     * that certificate over the gVVK it already holds and derives its serial from the gVVK SPKI, so
     * every ORK produces identical bytes. And {@code frontEndUrl} is passed null, letting the ORK
     * fall back to the realm attestation's own {@code frontendUrl} — that value is auth-chained
     * (gVVK-signed) whereas anything read locally here would not be, and it is the DNS host that
     * lands in the certificate's SAN, which is what a TLS client actually checks (RFC 6125).
     *
     * <p>No timestamp is set here. It is stamped into dynamic data at send time — see
     * {@link #stampCertificateTimestamp}.
     *
     * @param adminPolicyBytes M0 tide-realm-admin Policy bytes, or null (firstAdmin / dev)
     */
    public static String buildRealmApprovalModel(KeycloakSession session, RealmModel realm,
                                                 IgaRealmCertEntity realmCert,
                                                 byte[] adminPolicyBytes) {
        MultivaluedHashMap<String, String> config = requireVendorKeyConfig(realm);
        if (realmCert.getServerCsr() == null || realmCert.getServerSerialNumber() == null) {
            throw new RuntimeException("IGA realm-cert: CR " + realmCertCrId(realmCert)
                    + " has no server CSR/serial to request a realm certificate with");
        }
        try {
            boolean capable = TideAttestor.isRealSigningCapableRealm(realm);
            boolean usePolicy = authorizedByDokenQuorum(session, realm);

            ResourceIdentitySignRequest request = new ResourceIdentitySignRequest(usePolicy);
            request.SetRealmAttestation(ResourceIdentityAttestations.realmConfig(session, realm));
            request.SetTidecloakRealmRequest(
                    Base64.getUrlDecoder().decode(realmCert.getServerCsr()),
                    HexFormat.of().parseHex(realmCert.getServerSerialNumber()),
                    resolveRealmFrontendUrl(session, realm));

            // Override the 30-second default expiry from the constructor — this carrier has to
            // survive the admin approval window, not a single round-trip.
            request.SetCustomExpiry(System.currentTimeMillis() / 1000L + CARRIER_EXPIRY_SECONDS);

            // Authorize LAST: both paths sign over GetDataToAuthorize() = SHA512(draft) + expiry,
            // so every Set* that shapes the draft or the expiry has already run above.
            if (capable) {
                if (usePolicy) {
                    initializeCreationAuth(realm, request, config);   // multiAdmin: creation-auth, dokens follow
                } else {
                    authorizeWithVrk(realm, request, config);         // firstAdmin: VRK IS the approval
                }
            }
            if (usePolicy && adminPolicyBytes != null) {
                request.SetPolicy(adminPolicyBytes);
            }

            logger.infof("IGA realm-cert: built %s realm-mode carrier for realm %s (creation-auth=%s, "
                            + "authFlow=%s)",
                    MODEL_ID, realm.getName(), capable ? "VRK" : "none(dev)",
                    usePolicy ? "Policy:1" : "GVRK:1");
            return Base64.getEncoder().encodeToString(request.Encode());
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("IGA realm-cert: failed to build " + MODEL_ID
                    + " realm-mode carrier for realm " + realm.getName() + ": " + e.getMessage(), e);
        }
    }

    /**
     * Whether this realm's carrier will be authorized by an admin DOKEN QUORUM ({@code Policy:1})
     * rather than by the VRK alone ({@code GVRK:1}).
     *
     * <p>This picks the request's {@code AuthFlow}, so it has to describe how the carrier will
     * ACTUALLY be authorized, not merely which is preferable. A {@code Policy:1} carrier makes the
     * ORK's PolicyAuthorizationFlow demand a Policy plus dokens validated against it — which a
     * firstAdmin realm cannot supply: it has no admin quorum, and its M0 admin Policy does not
     * exist until the firstAdmin→multiAdmin flip creates it. Marking such a carrier
     * {@code Policy:1} is what produces "Model does not have a policy passed with it".
     *
     * <p>So it tracks authorizer mode exactly: multiAdmin realms collect dokens through the
     * two-phase enclave ceremony and are {@code Policy:1}; firstAdmin realms are authorized by the
     * VRK and are {@code GVRK:1}. Same discriminator {@code TideAttestor.sign} branches on when it
     * chooses between the firstAdmin VVK ceremony and the doken-carrier Policy:1 sign.
     *
     * <p>Note this is independent of the creation auth below, which is the MAIN gVRK pack either
     * way — that authorizes BUILDING the carrier, not approving the change it carries.
     */
    private static boolean authorizedByDokenQuorum(KeycloakSession session, RealmModel realm) {
        return TideAttestor.isMultiAdminMode(session, realm);
    }

    /**
     * The realm attribute the {@code realm_config} attestation carries as its {@code FrontendUrl},
     * and the one Keycloak resolves its frontend base URI from.
     */
    private static final String REALM_ATTR_FRONTEND_URL = "frontendUrl";

    /**
     * The {@code frontEndUrl} to send on a realm certificate request, or null to let the ORK fall
     * back to the realm attestation's own value.
     *
     * <p>The ORK certifies a DNS host as the server certificate's SAN — the only thing a TLS client
     * actually checks (RFC 6125) — and takes it from the request's {@code frontEndUrl} if set,
     * otherwise from {@code realm_config.FrontendUrl}. When NEITHER carries one it refuses the
     * request outright ("Neither the request nor the realm attestation carries a frontendUrl to
     * certify a Tidecloak realm server certificate"), because there would be no host to certify.
     *
     * <p>So: prefer the attested value and send null, because that one is gVVK-signed and therefore
     * auth-chained. Only when the realm has no {@code frontendUrl} attribute — the attestation emits
     * it as an empty string, which the ORK reads as absent — fall back to this instance's live
     * frontend base URI. That value is NOT auth-chained: it comes from the hostname configuration of
     * the node handling the request, so it is trusted only as far as the deployment is.
     *
     * <p>Realm-mode only. A client certificate carries no SAN dNSName, so its request has no
     * frontendUrl input at all.
     */
    private static String resolveRealmFrontendUrl(KeycloakSession session, RealmModel realm) {
        String attested = realm.getAttribute(REALM_ATTR_FRONTEND_URL);
        if (attested != null && !attested.isBlank()) {
            return null;   // attested and signed — let the ORK use it
        }

        URI baseUri = session.getContext().getUri(UrlType.FRONTEND).getBaseUri();
        if (baseUri == null) {
            throw new RuntimeException("IGA realm-cert: realm " + realm.getName() + " has no "
                    + REALM_ATTR_FRONTEND_URL + " attribute and this node could not resolve its own "
                    + "frontend base URI — there is no host to certify in the realm server "
                    + "certificate's SAN. Set the realm's " + REALM_ATTR_FRONTEND_URL + ".");
        }
        String frontendUrl = baseUri.toString();
        requireCertifiableHost(frontendUrl, baseUri, realm);

        logger.infof("IGA realm-cert: realm %s has no %s attribute — falling back to this node's "
                        + "frontend base URI '%s' for the server certificate SAN (not auth-chained; "
                        + "set the realm attribute to attest it).",
                realm.getName(), REALM_ATTR_FRONTEND_URL, frontendUrl);
        return frontendUrl;
    }

    /**
     * Reject a fallback URL the ORK would reject anyway, while the message can still name the cause.
     * It requires an absolute http(s) URL whose host is a DNS NAME — an IP literal is refused, which
     * is easy to hit on a local deployment bound to an address rather than a hostname.
     */
    private static void requireCertifiableHost(String frontendUrl, URI baseUri, RealmModel realm) {
        String scheme = baseUri.getScheme();
        String host = baseUri.getHost();
        boolean httpScheme = "http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme);
        // URI.getHost() returns null for a malformed authority, and brackets IPv6 literals.
        boolean ipLiteral = host != null
                && (host.matches("^\\d{1,3}(\\.\\d{1,3}){3}$") || host.startsWith("["));

        if (!baseUri.isAbsolute() || !httpScheme || host == null || host.isBlank() || ipLiteral) {
            throw new RuntimeException("IGA realm-cert: realm " + realm.getName() + " has no "
                    + REALM_ATTR_FRONTEND_URL + " attribute and this node's frontend base URI '"
                    + frontendUrl + "' cannot be certified — the ORK requires an absolute http(s) URL "
                    + "with a DNS host name (an IP address is refused). Set the realm's "
                    + REALM_ATTR_FRONTEND_URL + " to a hostname.");
        }
    }

    /**
     * Authorize a {@code GVRK:1} request directly with the VRK — the firstAdmin lane.
     *
     * <p>No {@code InitializeTideRequestWithVrk} here, and that is the point:
     * that helper exists to mint a SEPARATE {@code TideRequestInitialization:1} request whose
     * signature becomes a {@code Policy:1} carrier's CREATION authorization, so admins can then
     * doken it. It refuses anything that is not {@code Policy:1} ("Cannot initialize a request
     * which is not for a policy auth flow"), because a VRK-authorized request has no such
     * two-step: the VRK is the approver, so the request is authorized and signed in one go.
     *
     * <p>Authorized by the <b>firstAdmin AuthorizerPack</b>, NOT the MAIN gVRK pack. That pack is
     * the standing admin authority while a realm is in firstAdmin mode, and the ORK burns it at the
     * firstAdmin→multiAdmin flip — which is exactly the right lifetime, because after the flip
     * approvals come from the doken quorum and these carriers become {@code Policy:1}. Same pack
     * {@code TideAttestor.signUnitsWithFirstAdminVvk} uses for its {@code AttestationUnit:1}
     * ceremony; the MAIN gVRK pack's role is the creation-auth wrapper in
     * {@link #initializeCreationAuth}, which is a different authorization entirely.
     *
     * <p>Shape copied from {@code signUnitsWithFirstAdminVvk}: authorization computed LAST over
     * {@code GetDataToAuthorize()}, then the authorizer pack and its certificate.
     * {@code GetDataToAuthorize} hashes the draft and the expiry, so every {@code Set*} that shapes
     * either MUST already have run — call this at the very end of building the request.
     */
    private static void authorizeWithVrk(RealmModel realm, ResourceIdentitySignRequest request,
                                         MultivaluedHashMap<String, String> config)
            throws Exception {
        String firstAdminAuthorizer = config.getFirst(TideAttestor.CFG_FIRST_ADMIN_AUTHORIZER);
        String firstAdminAuthorizerCert =
                config.getFirst(TideAttestor.CFG_FIRST_ADMIN_AUTHORIZER_CERTIFICATE);
        if (firstAdminAuthorizer == null || firstAdminAuthorizer.isBlank()
                || firstAdminAuthorizerCert == null || firstAdminAuthorizerCert.isBlank()) {
            throw new RuntimeException("IGA cert: tide-vendor-key component is missing firstAdmin "
                    + "authorizer material (authorizer/authorizerCertificate) for realm "
                    + realm.getName() + " — cannot VRK-authorize a " + MODEL_ID + " request");
        }
        SignRequestSettingsMidgard settings = TideAttestor.constructSignSettings(config);

        request.SetAuthorization(
                Midgard.SignWithVrk(request.GetDataToAuthorize(), settings.VendorRotatingPrivateKey));
        request.SetAuthorizer(HexFormat.of().parseHex(firstAdminAuthorizer));
        request.SetAuthorizerCertificate(Base64.getDecoder().decode(firstAdminAuthorizerCert));
    }

    /**
     * Attach the seg-6/seg-8 creation authorization for a {@code Policy:1} carrier — the multiAdmin
     * lane. ALWAYS the MAIN gVRK pack.
     *
     * <p>This is not the admin approval — it is the vendor's authorization to CREATE the carrier,
     * and the two use different packs. {@code InitializeTideRequestWithVrk} builds an OUTER
     * {@code TideRequestInitialization:1} request that the ORK's VRKAuthorizationFlow authorizes;
     * the inner {@code ResourceIdentity:1} id is only folded in as the seg-2 draft label. The MAIN
     * gVRK pack lists {@code TideRequestInitialization:1} in its ModelIds — <b>the firstAdmin pack
     * does not</b>, so authorizing this wrapper with the firstAdmin pack fails with "This authorizer
     * has not allowed the model TideRequestInitialization:1 to be authorized".
     *
     * <p>The firstAdmin pack's role is the opposite one: it signs a real {@code AttestationUnit:1}
     * OUTER request in {@code signUnitsWithFirstAdminVvk}, which is the model that pack DOES allow.
     * Mode never changes which pack creation-auth uses — see
     * {@code TideAttestor.initializeApprovalRequestWithVrk}, which makes the same call.
     */
    private static void initializeCreationAuth(RealmModel realm,
                                               ResourceIdentitySignRequest request,
                                               MultivaluedHashMap<String, String> config)
            throws Exception {
        String gVrk = config.getFirst(CFG_GVRK);
        String gVrkCertificate = config.getFirst(CFG_GVRK_CERTIFICATE);
        if (gVrk == null || gVrk.isBlank()
                || gVrkCertificate == null || gVrkCertificate.isBlank()) {
            throw new RuntimeException("IGA server-cert: tide-vendor-key component is missing MAIN "
                    + "gVRK authorizer material (gVRK/gVRKCertificate) for realm " + realm.getName()
                    + " — cannot authorize a " + MODEL_ID + " request");
        }

        ModelRequest.InitializeTideRequestWithVrk(request, TideAttestor.constructSignSettings(config),
                MODEL_ID,
                HexFormat.of().parseHex(gVrk),
                Base64.getDecoder().decode(gVrkCertificate));
    }

    // -------------------------------------------------------------------------
    // COMMIT — sign, validate, return
    // -------------------------------------------------------------------------

    /**
     * Resolve the carrier to sign at commit, branching on authorizer mode exactly as
     * {@code TideAttestor.sign} does for producer units.
     *
     * <ul>
     *   <li><b>multiAdmin</b> — the carrier the two-phase enclave ceremony accumulated dokens onto,
     *       read from the CR. A blank one means the quorum ceremony never ran, so this fails closed
     *       rather than building a fresh zero-doken carrier that would bypass the approval.</li>
     *   <li><b>firstAdmin</b> — there is no doken ceremony and nothing is persisted at approval
     *       time, so the carrier is built HERE, at commit, and signed immediately under the
     *       firstAdmin pack's authority. Same shape as {@code signFirstAdminUnitWithVvk}.</li>
     * </ul>
     *
     * @param stored     {@code cr.getRequestModel()} — the accumulated carrier, if any
     * @param buildFresh builds the mode-appropriate carrier for the firstAdmin lane
     */
    private static String resolveCarrier(KeycloakSession session, RealmModel realm, String crId,
                                         String stored, java.util.function.Supplier<String> buildFresh) {
        if (TideAttestor.isMultiAdminMode(session, realm)) {
            if (stored == null || stored.isBlank()) {
                throw new RuntimeException("IGA cert: CR " + crId + " has no dokened " + MODEL_ID
                        + " carrier to sign — a multiAdmin change request must be approved through "
                        + "the approval enclave, which collects the admin doken quorum. Fail-closed.");
            }
            return stored;
        }
        // firstAdmin: single authority, no dokens to accumulate. An already-built carrier is
        // still preferred if one happens to exist, so a realm that flipped mid-flight reuses
        // whatever was collected rather than discarding it.
        if (stored != null && !stored.isBlank()) {
            return stored;
        }
        logger.infof("IGA cert: CR %s (realm %s) is firstAdmin — building the %s carrier at commit "
                + "(no doken ceremony to accumulate).", crId, realm.getName(), MODEL_ID);
        return buildFresh.get();
    }

    /** Validated certificates from one signing round. */
    public static final class IssuedCerts {
        public final String resourceCertificatePem;
        public final long notBefore;
        public final long notAfter;

        IssuedCerts(String resourceCertificatePem, long notBefore, long notAfter) {
            this.resourceCertificatePem = resourceCertificatePem;
            this.notBefore = notBefore;
            this.notAfter = notAfter;
        }
    }

    public static IssuedCerts issue(KeycloakSession session, RealmModel realm,
                                    IgaServerCertDraftEntity draft) {
        MultivaluedHashMap<String, String> config = requireVendorKeyConfig(realm);
        String carrier = resolveCarrier(session, realm, draftCrId(draft),
                draft.getChangeRequest() != null ? draft.getChangeRequest().getRequestModel() : null,
                () -> buildApprovalModel(session, realm, draft, null));
        try {
            SignRequestSettingsMidgard settings = TideAttestor.constructSignSettings(config);
            ModelRequest request = ModelRequest.FromBytes(Base64.getDecoder().decode(carrier));
            stampCertificateTimestamp(request);

            SignatureResponse response = Midgard.SignModel(settings, request);
            if (response == null || response.Signatures == null || response.Signatures.length == 0) {
                throw new RuntimeException("ORK returned no signatures for " + MODEL_ID);
            }
            if (response.AdditionalData == null || response.AdditionalData.length == 0) {
                throw new RuntimeException("ORK returned no certificate data for " + MODEL_ID
                        + " — expected the built TBSCertificates in AdditionalData");
            }

            byte[] gvvk = HexFormat.of().parseHex(requireGvvk(config, realm));
            String caName = "CN=realm_" + realm.getName() + "_ca";
            byte[] expectedSpki = Base64.getUrlDecoder().decode(draft.getPublicKey());

            // Client mode requested one certificate, so the response carries exactly one slot.
            byte[] resourceDer = assemble(response, CLIENT_MODE_SLOT_RESOURCE, "resource certificate");
            IssuedCertificateValidator.ValidatedCertificate validity =
                    IssuedCertificateValidator.validateResourceCertificate(
                            resourceDer, expectedSpki, caName, gvvk);

            logger.infof("IGA server-cert: %s issued and validated for client %s (realm %s), notAfter=%d",
                    MODEL_ID, draft.getClientId(), realm.getName(), validity.notAfter);

            return new IssuedCerts(ServerCertBuilder.toPem(resourceDer),
                    validity.notBefore, validity.notAfter);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("IGA server-cert: " + MODEL_ID + " signing failed for client "
                    + draft.getClientId() + " (realm " + realm.getName() + "): " + e.getMessage(), e);
        }
    }

    // -------------------------------------------------------------------------
    // COMMIT — the realm-scoped pair
    // -------------------------------------------------------------------------

    /** Validated realm-scoped certificates from one signing round. */
    public static final class IssuedRealmCerts {
        public final String serverCertificatePem;
        public final long serverNotBefore;
        public final long serverNotAfter;
        public final String rootCaPem;
        public final String rootCaSerialNumberHex;
        public final long rootCaNotBefore;
        public final long rootCaNotAfter;

        IssuedRealmCerts(String serverCertificatePem, long serverNotBefore, long serverNotAfter,
                         String rootCaPem, String rootCaSerialNumberHex,
                         long rootCaNotBefore, long rootCaNotAfter) {
            this.serverCertificatePem = serverCertificatePem;
            this.serverNotBefore = serverNotBefore;
            this.serverNotAfter = serverNotAfter;
            this.rootCaPem = rootCaPem;
            this.rootCaSerialNumberHex = rootCaSerialNumberHex;
            this.rootCaNotBefore = rootCaNotBefore;
            this.rootCaNotAfter = rootCaNotAfter;
        }
    }

    public static IssuedRealmCerts issueRealm(KeycloakSession session, RealmModel realm,
                                              IgaRealmCertEntity realmCert) {
        MultivaluedHashMap<String, String> config = requireVendorKeyConfig(realm);
        String carrier = resolveCarrier(session, realm, realmCertCrId(realmCert),
                realmCert.getChangeRequest() != null ? realmCert.getChangeRequest().getRequestModel() : null,
                () -> buildRealmApprovalModel(session, realm, realmCert, null));
        if (realmCert.getServerPublicKey() == null) {
            throw new RuntimeException("IGA realm-cert: CR " + realmCertCrId(realmCert)
                    + " has no server public key to validate the issued certificate against");
        }
        try {
            SignRequestSettingsMidgard settings = TideAttestor.constructSignSettings(config);
            ModelRequest request = ModelRequest.FromBytes(Base64.getDecoder().decode(carrier));
            stampCertificateTimestamp(request);

            SignatureResponse response = Midgard.SignModel(settings, request);
            if (response == null || response.Signatures == null || response.Signatures.length == 0) {
                throw new RuntimeException("ORK returned no signatures for " + MODEL_ID);
            }
            if (response.AdditionalData == null || response.AdditionalData.length == 0) {
                throw new RuntimeException("ORK returned no certificate data for " + MODEL_ID
                        + " — expected the built TBSCertificates in AdditionalData");
            }

            byte[] gvvk = HexFormat.of().parseHex(requireGvvk(config, realm));
            String caName = "CN=realm_" + realm.getName() + "_ca";
            byte[] expectedSpki = Base64.getUrlDecoder().decode(realmCert.getServerPublicKey());

            byte[] serverDer = assemble(response, REALM_MODE_SLOT_SERVER, "realm server certificate");
            IssuedCertificateValidator.ValidatedCertificate serverValidity =
                    IssuedCertificateValidator.validateRealmCertificate(
                            serverDer, expectedSpki, caName, gvvk);

            byte[] rootCaDer = assemble(response, REALM_MODE_SLOT_ROOT_CA, "root CA");
            IssuedCertificateValidator.ValidatedCertificate rootCaValidity =
                    IssuedCertificateValidator.validateRootCa(rootCaDer, caName, gvvk);

            logger.infof("IGA realm-cert: %s issued and validated for realm %s, "
                            + "server notAfter=%d, root CA notAfter=%d",
                    MODEL_ID, realm.getName(), serverValidity.notAfter, rootCaValidity.notAfter);

            return new IssuedRealmCerts(
                    ServerCertBuilder.toPem(serverDer),
                    serverValidity.notBefore, serverValidity.notAfter,
                    ServerCertBuilder.toPem(rootCaDer), serialNumberHexOf(rootCaDer),
                    rootCaValidity.notBefore, rootCaValidity.notAfter);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("IGA realm-cert: " + MODEL_ID + " signing failed for realm "
                    + realm.getName() + ": " + e.getMessage(), e);
        }
    }

    /**
     * The certificate's serial as hex. Read back off the issued bytes rather than carried forward
     * from the request, because the cohort derives the root CA's serial from the gVVK SPKI itself.
     */
    private static String serialNumberHexOf(byte[] certificateDer) {
        try {
            return new X509CertificateHolder(certificateDer).getSerialNumber().toString(16);
        } catch (Exception e) {
            throw new RuntimeException("IGA realm-cert: issued certificate serial is unreadable", e);
        }
    }

    /**
     * Stamp the certificate timestamp into the request's DYNAMIC DATA, immediately before the
     * request leaves for the cohort.
     *
     * <h2>Why this is here and not in the carrier</h2>
     * The value is the {@code NotBefore} the ORK stamps on every certificate it issues, and the ORK
     * rejects one more than five minutes from its own clock. The carrier, though, is built when the
     * first admin opens the change request and only signed once the quorum has approved — so a
     * timestamp fixed at build time is stale by construction on any approval that takes longer than
     * five minutes.
     *
     * <p>It cannot simply be re-stamped in the draft either: the draft is what the admins authorize,
     * and every doken already collected is bound to the draft as it stood. Rewriting it would
     * invalidate all of them. Dynamic data is the segment that sits OUTSIDE the authorized bytes —
     * {@code GetDataToAuthorize} hashes only the draft and the expiry — so stamping here changes
     * nothing an admin signed over, and the approval window stops mattering.
     *
     * <p>That is also why it belongs at the send site rather than anywhere earlier: the only
     * timestamp guaranteed within the ORK's tolerance is the one taken as the request is dispatched.
     *
     * <p><b>Encoding.</b> 8 bytes, little-endian, UNIX seconds — matching how the draft encoded this
     * same value and how {@code ModelRequest} encodes {@code Expiry} in its own segment. This has to
     * agree byte-for-byte with what the ORK reads out of dynamic data; it is the one thing to
     * re-check against the ORK/Midgard side, and the single place to change if it differs.
     */
    private static void stampCertificateTimestamp(ModelRequest request) {
        long unixSeconds = System.currentTimeMillis() / 1000L;
        request.SetDynamicData(ByteBuffer.allocate(Long.BYTES)
                .order(ByteOrder.LITTLE_ENDIAN)
                .putLong(unixSeconds)
                .array());
    }

    /** Pair the TBS at {@code slot} with the signature at the same index. */
    private static byte[] assemble(SignatureResponse response, int slot, String certificateLabel) {
        byte[] certificateDer = tryAssemble(response, slot);
        if (certificateDer == null) {
            throw new RuntimeException("ORK response is missing the " + certificateLabel + " at slot " + slot);
        }
        return certificateDer;
    }

    private static byte[] tryAssemble(SignatureResponse response, int slot) {
        byte[] tbs = Tools.TryGetValue(response.AdditionalData, slot);
        if (tbs == null || tbs.length == 0 || response.Signatures.length <= slot) {
            return null;
        }
        return ServerCertBuilder.assembleCertificate(tbs, decodeSig(response.Signatures[slot]));
    }

    // -------------------------------------------------------------------------
    // helpers
    // -------------------------------------------------------------------------

    /**
     * A serial the ORK's {@code ValidateSerialNumber} accepts: 16 random octets with the leading
     * octet forced below {@code 0x80} and non-zero, so it DER-encodes as a positive INTEGER
     * without a pad byte and denotes the same number as its raw bytes (RFC 5280 §4.1.2.2).
     *
     * <p>Not used for the root CA — the cohort derives that serial from the gVVK SPKI so every
     * ORK produces identical bytes.
     */
    public static byte[] newSerialNumber() {
        byte[] serial = new byte[16];
        new SecureRandom().nextBytes(serial);
        serial[0] &= 0x7F;
        if (serial[0] == 0x00) {
            serial[0] = 0x01;
        }
        return serial;
    }

    /** ORK signatures come back base64url; normalise before decoding. */
    private static byte[] decodeSig(String sig) {
        return Base64.getDecoder().decode(sig.replace('-', '+').replace('_', '/'));
    }

    private static String draftCrId(IgaServerCertDraftEntity draft) {
        return draft.getChangeRequest() != null ? draft.getChangeRequest().getId() : "<none>";
    }

    private static String realmCertCrId(IgaRealmCertEntity realmCert) {
        return realmCert.getChangeRequest() != null ? realmCert.getChangeRequest().getId() : "<none>";
    }

    /** Resolve the realm's tide-vendor-key component (throws if absent). */
    public static ComponentModel requireVendorKey(RealmModel realm) {
        return realm.getComponentsStream()
                .filter(c -> TIDE_VENDOR_KEY_PROVIDER_ID.equals(c.getProviderId()))
                .findFirst()
                .orElseThrow(() -> new RuntimeException(
                        "IGA server-cert: realm " + realm.getName()
                                + " has no tide-vendor-key component (VVK not provisioned)"));
    }

    public static MultivaluedHashMap<String, String> requireVendorKeyConfig(RealmModel realm) {
        MultivaluedHashMap<String, String> config = requireVendorKey(realm).getConfig();
        if (config == null) {
            throw new RuntimeException("IGA server-cert: tide-vendor-key component has no config (realm "
                    + realm.getName() + ")");
        }
        return config;
    }

    private static String requireGvvk(MultivaluedHashMap<String, String> config, RealmModel realm) {
        String gVVK = config.getFirst(CFG_GVVK);
        if (gVVK == null || gVVK.isBlank()) {
            throw new RuntimeException("IGA server-cert: tide-vendor-key component missing gVVK "
                    + "(clientId config key) for realm " + realm.getName());
        }
        return gVVK;
    }
}
