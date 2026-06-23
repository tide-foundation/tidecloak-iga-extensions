package org.tidecloak.iga.attestors;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.midgard.Serialization.Tools;
import org.midgard.models.ModelRequest;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.tidecloak.iga.entities.IgaRolePolicyEntity;
import org.tidecloak.iga.providers.RagnarokOffboardService;

/**
 * OFFBOARD_REALM carrier must carry the M0 tide-realm-admin admin Policy.
 *
 * <p>The bug: {@code buildMultiAdminApprovalModel}'s OFFBOARD branch seeded the
 * ragnarok-built {@code Offboard:1} carrier (collected admin dokens) but never attached
 * the M0 admin threshold Policy via {@code SetPolicy(...)}. At commit the ORK's
 * {@code PolicyAuthorizationFlow} threw {@code "Model does not have a policy passed with
 * it"} because it had no carried Policy to validate the collected dokens against.
 *
 * <p>The fix attaches the M0 Policy iga-core-side via the segment-faithful
 * {@code ModelRequest.FromBytes → SetPolicy → Encode} round-trip. These tests pin the
 * contract directly against the REAL Midgard {@code ModelRequest} encode/decode (no ORK):
 * <ul>
 *   <li>the returned carrier's segment 9 (Policy) equals the M0 bytes;</li>
 *   <li>{@code SetPolicy} does NOT disturb the Draft / Expiry / vendor creation-auth
 *       (seg 7) — because {@code GetDataToAuthorize} hashes only Id+Draft+Expiry, never
 *       the Policy — so prior dokens stay valid;</li>
 *   <li>a realm with no established M0 admin Policy fails closed.</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TideAttestorOffboardCarrierPolicyTest {

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock JpaConnectionProvider jpa;
    @Mock EntityManager em;
    @Mock KeycloakContext ctx;
    @Mock RagnarokOffboardService ragnarok;
    @Mock ClientModel realmMgmt;
    @Mock RoleModel tideAdminRole;

    private TideAttestor attestor;

    /** The vendor-initialized Draft ragnarok puts in the Offboard:1 carrier (covered by seg-7). */
    private static final byte[] OFFBOARD_DRAFT = "offboard-draft-payload".getBytes(StandardCharsets.UTF_8);
    /** A fake non-empty seg-7 vendor creation-auth, to prove SetPolicy leaves it untouched. */
    private static final byte[] VENDOR_CREATION_AUTH = "vendor-creation-auth-seg7".getBytes(StandardCharsets.UTF_8);
    /** The raw M0 Policy bytes (what the ORK PolicyAuthorizationFlow validates dokens against). */
    private static final byte[] M0_POLICY_BYTES = "the-genuine-m0-admin-threshold-policy".getBytes(StandardCharsets.UTF_8);

    @BeforeEach
    void setUp() {
        lenient().when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa);
        lenient().when(jpa.getEntityManager()).thenReturn(em);
        lenient().when(session.getContext()).thenReturn(ctx);
        lenient().when(session.getProvider(RagnarokOffboardService.class)).thenReturn(ragnarok);
        lenient().when(realm.getId()).thenReturn("realm-offboard");
        lenient().when(realm.getName()).thenReturn("offboard-realm");
        // Resolve tide-realm-admin role id (keys the M0 IgaRolePolicy lookup).
        lenient().when(realm.getClientByClientId("realm-management")).thenReturn(realmMgmt);
        lenient().when(realmMgmt.getRole("tide-realm-admin")).thenReturn(tideAdminRole);
        lenient().when(tideAdminRole.getId()).thenReturn("tide-realm-admin-role-id");
        attestor = new TideAttestor(session);
    }

    /**
     * A vendor-style {@code Offboard:1} ModelRequest carrier with NO Policy (segment 9 empty),
     * a non-empty Draft, a long expiry, and a non-empty seg-7 creation-auth — exactly the shape
     * ragnarok returns (and the buggy carrier that reached the ORK without a Policy).
     */
    private static String ragnarokCarrierNoPolicy() {
        long expiry = (System.currentTimeMillis() / 1000) + 7L * 24 * 60 * 60;
        byte[] expiryBytes = leLong(expiry);
        byte[] encoded = Tools.CreateTideMemory(
                "Offboard".getBytes(StandardCharsets.UTF_8),  // 0 Name
                "1".getBytes(StandardCharsets.UTF_8),          // 1 Version
                expiryBytes,                                    // 2 Expiry
                OFFBOARD_DRAFT,                                 // 3 Draft
                "Policy:1".getBytes(StandardCharsets.UTF_8),    // 4 AuthFlow
                new byte[0],                                    // 5 DynamicData
                new byte[0],                                    // 6 Authorizer (no dokens yet)
                VENDOR_CREATION_AUTH,                           // 7 creation-auth (vendor-initialized)
                new byte[0],                                    // 8 AuthorizerCertificate
                new byte[0]                                     // 9 Policy — EMPTY (the bug)
        );
        return Base64.getEncoder().encodeToString(encoded);
    }

    /** Seed the M0 tide-realm-admin admin Policy row (Base64(Policy.ToBytes())). */
    private void seedM0AdminPolicy(String policyBody) {
        IgaRolePolicyEntity m0 = new IgaRolePolicyEntity();
        m0.setPolicy(policyBody);
        @SuppressWarnings("unchecked")
        TypedQuery<IgaRolePolicyEntity> q = mock(TypedQuery.class);
        when(em.createNamedQuery("IgaRolePolicy.findByRealmAndName", IgaRolePolicyEntity.class)).thenReturn(q);
        lenient().when(q.setParameter(org.mockito.ArgumentMatchers.eq("realmId"),
                org.mockito.ArgumentMatchers.any())).thenReturn(q);
        lenient().when(q.setParameter(org.mockito.ArgumentMatchers.eq("name"),
                org.mockito.ArgumentMatchers.any())).thenReturn(q);
        when(q.getResultStream()).thenAnswer(inv -> Stream.of(m0));
    }

    /** No M0 admin policy row at all (empty stream). */
    private void seedNoM0AdminPolicy() {
        @SuppressWarnings("unchecked")
        TypedQuery<IgaRolePolicyEntity> q = mock(TypedQuery.class);
        when(em.createNamedQuery("IgaRolePolicy.findByRealmAndName", IgaRolePolicyEntity.class)).thenReturn(q);
        lenient().when(q.setParameter(org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.any())).thenReturn(q);
        when(q.getResultStream()).thenAnswer(inv -> Stream.empty());
    }

    private org.tidecloak.iga.entities.IgaChangeRequestEntity freshOffboardCr() {
        org.tidecloak.iga.entities.IgaChangeRequestEntity cr =
                mock(org.tidecloak.iga.entities.IgaChangeRequestEntity.class);
        lenient().when(cr.getActionType()).thenReturn(TideAttestor.ACTION_OFFBOARD_REALM);
        lenient().when(cr.getId()).thenReturn("offboard-cr-1");
        // Fresh CR: no persisted carrier yet → the accumulation short-circuit is skipped.
        lenient().when(cr.getRequestModel()).thenReturn(null);
        return cr;
    }

    @Test
    void offboardCarrier_hasM0PolicyAttached_atSegment9() throws Exception {
        when(ragnarok.buildOffboardApprovalCarrier(session, realm)).thenReturn(ragnarokCarrierNoPolicy());
        // M0 stored as Base64(Policy.ToBytes()) — readM0AdminPolicyBytes Base64-decodes it.
        String m0Body = Base64.getEncoder().encodeToString(M0_POLICY_BYTES);
        seedM0AdminPolicy(m0Body);

        String carrierB64 = attestor.buildMultiAdminApprovalModel(session, realm, freshOffboardCr());

        byte[] carrier = Base64.getDecoder().decode(carrierB64);
        byte[] seg9Policy = Tools.GetValue(carrier, 9);
        assertArrayEquals(M0_POLICY_BYTES, seg9Policy,
                "the seeded OFFBOARD_REALM carrier must carry the M0 admin Policy at TideMemory "
                        + "segment 9 so the ORK PolicyAuthorizationFlow can validate the offboard dokens");
        assertTrue(seg9Policy.length > 0, "segment 9 (Policy) must be non-empty (was empty = the bug)");
    }

    @Test
    void setPolicy_doesNotDisturbDraftExpiryOrCreationAuth() throws Exception {
        String rawCarrier = ragnarokCarrierNoPolicy();
        when(ragnarok.buildOffboardApprovalCarrier(session, realm)).thenReturn(rawCarrier);
        seedM0AdminPolicy(Base64.getEncoder().encodeToString(M0_POLICY_BYTES));

        // The data-to-authorize (which seg-7 + every doken sign over) BEFORE attach.
        ModelRequest before = ModelRequest.FromBytes(Base64.getDecoder().decode(rawCarrier));
        String dataToAuthBefore = before.GetDataToAuthorize();

        String carrierB64 = attestor.buildMultiAdminApprovalModel(session, realm, freshOffboardCr());
        byte[] carrier = Base64.getDecoder().decode(carrierB64);
        ModelRequest after = ModelRequest.FromBytes(carrier);

        assertEquals(dataToAuthBefore, after.GetDataToAuthorize(),
                "GetDataToAuthorize (Id + SHA-512(Draft) + Expiry) must be UNCHANGED by SetPolicy — "
                        + "otherwise the vendor creation-auth and every appended doken would be invalidated");
        assertArrayEquals(OFFBOARD_DRAFT, Tools.GetValue(carrier, 3),
                "the vendor Draft (seg 3) must be preserved verbatim");
        assertArrayEquals(VENDOR_CREATION_AUTH, Tools.GetValue(carrier, 7),
                "the vendor creation-auth (seg 7) must be preserved verbatim — SetPolicy must not touch it");
    }

    @Test
    void offboardCarrier_persistsAttachedCarrierOnCr() throws Exception {
        when(ragnarok.buildOffboardApprovalCarrier(session, realm)).thenReturn(ragnarokCarrierNoPolicy());
        seedM0AdminPolicy(Base64.getEncoder().encodeToString(M0_POLICY_BYTES));
        org.tidecloak.iga.entities.IgaChangeRequestEntity cr = freshOffboardCr();

        String carrierB64 = attestor.buildMultiAdminApprovalModel(session, realm, cr);

        // The CR's REQUEST_MODEL must be the policy-attached carrier (what the enclave accumulates
        // dokens onto and what reaches the ORK at commit), not the policy-less ragnarok output.
        org.mockito.Mockito.verify(cr).setRequestModel(carrierB64);
        byte[] seg9 = Tools.GetValue(Base64.getDecoder().decode(carrierB64), 9);
        assertArrayEquals(M0_POLICY_BYTES, seg9, "persisted carrier must carry the M0 policy");
    }

    @Test
    void offboardCarrier_failsClosed_whenNoM0AdminPolicy() throws Exception {
        when(ragnarok.buildOffboardApprovalCarrier(session, realm)).thenReturn(ragnarokCarrierNoPolicy());
        seedNoM0AdminPolicy();

        RuntimeException ex = assertThrows(RuntimeException.class,
                () -> attestor.buildMultiAdminApprovalModel(session, realm, freshOffboardCr()),
                "an offboard carrier must fail closed when the realm has no established M0 admin Policy");
        assertTrue(String.valueOf(ex.getMessage()).contains("established admin policy"),
                "the fail-closed message must explain the missing admin policy — was: " + ex.getMessage());
    }

    @Test
    void ragnarokCarrier_startsWithoutPolicy_sanityOfTheFixture() throws Exception {
        // Guard the test fixture itself: the ragnarok carrier MUST start policy-less, else the
        // "attach" assertions above would pass vacuously.
        byte[] raw = Base64.getDecoder().decode(ragnarokCarrierNoPolicy());
        assertEquals(0, Tools.GetValue(raw, 9).length,
                "fixture sanity: the raw ragnarok carrier must have an EMPTY policy segment (the bug)");
        assertFalse(TideAttestor.isProducerEnvelopeSignedAction(TideAttestor.ACTION_OFFBOARD_REALM),
                "OFFBOARD_REALM stays a non-producer action (CR attestation stub-signs)");
    }

    private static byte[] leLong(long v) {
        byte[] b = new byte[8];
        for (int i = 0; i < 8; i++) b[i] = (byte) (v >>> (8 * i));
        return b;
    }
}
