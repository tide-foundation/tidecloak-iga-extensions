package org.tidecloak.iga.attestors;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.tidecloak.iga.entities.IgaAuthorizerEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.entities.IgaRolePolicyEntity;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import jakarta.persistence.TypedQuery;

import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Flip-gating coverage — the firstAdmin -> multiAdmin flip MUST happen on the first
 * M0 policy COMMIT, not unconditionally on the tide-realm-admin user grant.
 *
 * <p>The ordering invariant (the whole point of this change): sign the M0 admin Policy
 * with the firstAdmin AuthorizerPack (ALIVE pre-flip) -> commit/persist it -> ONLY THEN
 * flip (which burns that pack on the ORK side, the sole Policy:1 signer). So
 * {@link TideAttestor#writeBackPolicySig} must report whether a signed M0 policy was
 * actually committed, and {@link TideAttestor#combineFinal} flips only on a {@code true}.
 *
 * <p>These tests drive the NON-capable (dev/test) realm path deterministically: a mock
 * realm with no {@code tide-vendor-key} component is not real-signing-capable, so the
 * stub branch runs without needing live Midgard/ORK material.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TideAttestorFlipGateTest {

    private static final String REALM_ID = "realm-uuid-flip";
    private static final String TIDE_ROLE_ID = "tide-realm-admin-role-id";

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock JpaConnectionProvider jpa;
    @Mock EntityManager em;
    @Mock ClientModel realmManagement;
    @Mock RoleModel tideRealmAdmin;
    @Mock IgaChangeRequestEntity cr;
    @Mock TypedQuery<IgaRolePolicyEntity> policyQuery;
    @Mock TypedQuery<IgaAuthorizerEntity> authorizerQuery;

    private TideAttestor attestor;

    @BeforeEach
    void setUp() {
        when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa);
        when(jpa.getEntityManager()).thenReturn(em);
        when(realm.getId()).thenReturn(REALM_ID);
        when(realm.getName()).thenReturn("flip-realm");
        when(realm.getClientByClientId("realm-management")).thenReturn(realmManagement);
        when(realmManagement.getRole("tide-realm-admin")).thenReturn(tideRealmAdmin);
        when(tideRealmAdmin.getId()).thenReturn(TIDE_ROLE_ID);
        // NON-capable: no tide-vendor-key component -> isRealSigningCapable == false.
        // Fresh stream per call (isRealSigningCapable + realmVvkId both consume it).
        when(realm.getComponentsStream()).thenAnswer(inv -> Stream.<ComponentModel>empty());
        attestor = new TideAttestor(session);
    }

    /** Stub the IgaRolePolicy.findByRealmAndName named query to return {@code result}. */
    private void stubPolicyLookup(IgaRolePolicyEntity result) {
        when(em.createNamedQuery(eq("IgaRolePolicy.findByRealmAndName"), eq(IgaRolePolicyEntity.class)))
                .thenReturn(policyQuery);
        when(policyQuery.setParameter(anyString(), any())).thenReturn(policyQuery);
        // Fresh stream per call — findTideRealmAdminPolicy may be invoked more than once
        // in a single combineFinal (readTideRealmAdminPolicyBytes + writeBackPolicySig).
        when(policyQuery.getResultStream())
                .thenAnswer(inv -> result == null ? Stream.empty() : Stream.of(result));
    }

    /** Stub the IgaAuthorizer.findByRealm named query to return {@code row}. */
    private void stubAuthorizerLookup(IgaAuthorizerEntity row) {
        when(em.createNamedQuery(eq("IgaAuthorizer.findByRealm"), eq(IgaAuthorizerEntity.class)))
                .thenReturn(authorizerQuery);
        when(authorizerQuery.setParameter(anyString(), any())).thenReturn(authorizerQuery);
        // Fresh stream per call — resolveMode + flipModeToMultiAdmin both consume it.
        when(authorizerQuery.getResultStream())
                .thenAnswer(inv -> row == null ? Stream.empty() : Stream.of(row));
    }

    @Test
    void writeBackCommitsPolicyAndReturnsTrue_thenFlipFires_existingRow() {
        // GIVEN a tide-realm-admin M0 policy row already exists (e.g. pre-seeded via
        // POST /iga/role-policies). The non-capable write-back re-stamps it and commits.
        IgaRolePolicyEntity existing = new IgaRolePolicyEntity();
        existing.setId("pre-seeded-id");
        existing.setRealmId(REALM_ID);
        existing.setName(org.tidecloak.iga.attestors.TideAttestor.TIDE_REALM_ADMIN_POLICY_KEY);
        existing.setPolicy("stub-body");
        existing.setPolicySig("OLD");
        stubPolicyLookup(existing);

        // WHEN write-back runs
        boolean committed = attestor.writeBackPolicySig(session, realm, cr, "TIDE-FIRSTADMIN-v1:abc");

        // THEN it reports a committed M0 policy -> caller may flip; the row carries the sig.
        assertTrue(committed, "an existing M0 policy row that was re-stamped+flushed must report committed");
        assertEquals("TIDE-FIRSTADMIN-v1:abc", existing.getPolicySig(), "policySig must be written back");
        verify(em).flush();

        // AND the flip, when invoked on that committed signal, transitions firstAdmin -> multiAdmin.
        IgaAuthorizerEntity authRow = new IgaAuthorizerEntity();
        authRow.setMode("firstAdmin");
        stubAuthorizerLookup(authRow);
        attestor.flipModeToMultiAdmin(session, realm);
        assertEquals("multiAdmin", authRow.getMode(), "flip must transition the authorizer row to multiAdmin");
    }

    @Test
    void writeBackReturnsFalse_whenTideRealmAdminRoleUnresolvable_soNoFlip() {
        // GIVEN the realm-management tide-realm-admin role cannot be resolved: the M0 policy
        // row cannot be keyed, so NO signed policy can be committed.
        when(realmManagement.getRole("tide-realm-admin")).thenReturn(null);
        stubPolicyLookup(null);

        // WHEN write-back runs on a non-capable realm
        boolean committed = attestor.writeBackPolicySig(session, realm, cr, "TIDE-FIRSTADMIN-v1:abc");

        // THEN no policy is committed -> the caller MUST NOT flip (realm stays firstAdmin,
        // firstAdmin pack preserved). No row is persisted.
        assertFalse(committed, "no keyable role -> no committed policy -> must report NOT committed (no flip)");
        verify(em, never()).persist(any());
    }

    @Test
    void flipIsIdempotent_alreadyMultiAdmin_noChange() {
        // A redundant flip on an already-multiAdmin authorizer row is a harmless no-op.
        IgaAuthorizerEntity authRow = new IgaAuthorizerEntity();
        authRow.setMode("multiAdmin");
        stubAuthorizerLookup(authRow);

        attestor.flipModeToMultiAdmin(session, realm);

        assertEquals("multiAdmin", authRow.getMode());
        verify(em, never()).flush();
    }

    @Test
    void flipIsNoOp_whenNoAuthorizerRow() {
        // Defensive: no authorizer row -> flip cannot fabricate a mode.
        stubAuthorizerLookup(null);

        attestor.flipModeToMultiAdmin(session, realm);

        verify(em, never()).flush();
    }

    // -------------------------------------------------------------------------
    // ★ Flip-boundary fix — the flip-triggering grant's user_role_mapping_set is
    //   stamped REAL with the still-alive firstAdmin pack BEFORE the M0 policy sign
    //   burns it. Without the fix combineFinal returned the POLICY-bytes stub as the
    //   role-mapping attestation and the pack was burned before the unit could ever
    //   be re-signed → the new admin's login fail-closed forever.
    // -------------------------------------------------------------------------

    /** Stub the pre-change USER_ROLE_MAPPING role-id query used by the unit builder. */
    private void stubPreChangeRoleIds(List<String> ids) {
        Query q = mock(Query.class);
        when(em.createQuery(anyString())).thenReturn(q);
        when(q.setParameter(anyString(), any())).thenReturn(q);
        when(q.getResultList()).thenReturn((List) ids);
    }

    /** A bootstrap GRANT_ROLES CR: grants the realm-management tide-realm-admin role to a user. */
    private void stubBootstrapGrantCr() {
        // Tide realm (no authorizer row) -> resolveMode == firstAdmin via the attestor attribute.
        when(realm.getAttribute("iga.attestor")).thenReturn("tide");
        when(cr.getActionType()).thenReturn("GRANT_ROLES");
        when(cr.getEntityId()).thenReturn("granted-user-1");
        when(cr.getRowsJson()).thenReturn(
                "[{\"USER_ID\":\"granted-user-1\",\"ROLE_ID\":\"" + TIDE_ROLE_ID + "\"}]");
        when(cr.getRealmId()).thenReturn(REALM_ID);
        when(session.realms()).thenReturn(mock(org.keycloak.models.RealmProvider.class));
        when(session.realms().getRealm(REALM_ID)).thenReturn(realm);
        // No authorizer row -> resolveMode derives firstAdmin from iga.attestor=tide.
        stubAuthorizerLookup(null);
    }

    @Test
    void bootstrapGrant_signsProducerUnit_BEFORE_policySignAndFlip() {
        // GIVEN the flip-triggering grant. We spy the two pack-burn steps
        // (writeBackPolicySig = M0 sign, flipModeToMultiAdmin = the pack-burn signal) —
        // both package-private, so spyable — and drive the deterministic non-capable path.
        // The producer-unit sign (private sign(...)) runs INLINE before either, so by the
        // time writeBackPolicySig is invoked the role-mapping-set attestation is already the
        // returned value; we assert the strict ORDER of the two burn steps AND that the
        // policy arg handed to writeBackPolicySig is the M0 policy-bytes stub (NOT the
        // role-mapping sig) — proving the producer unit and the M0 policy are signed
        // SEPARATELY, the producer unit first.
        TideAttestor spy = spy(new TideAttestor(session));
        stubBootstrapGrantCr();
        stubPreChangeRoleIds(Collections.emptyList());
        // Policy row exists so writeBackPolicySig (non-capable) re-stamps it with the arg.
        IgaRolePolicyEntity policyRow = new IgaRolePolicyEntity();
        policyRow.setId("p1");
        policyRow.setRealmId(REALM_ID);
        policyRow.setName(org.tidecloak.iga.attestors.TideAttestor.TIDE_REALM_ADMIN_POLICY_KEY);
        policyRow.setPolicy("THE-M0-POLICY-BYTES");
        policyRow.setPolicySig("OLD");
        stubPolicyLookup(policyRow);

        String sig = spy.combineFinal(session, cr, Collections.emptyList());

        // The returned attestation (what the dispatcher fans onto the granted user's
        // role-mapping rows) is the producer user_role_mapping_set sig, distinct from the
        // M0 policy-bytes stub.
        String policyBytesStub = invokeStubSignOverPolicyBytes("THE-M0-POLICY-BYTES");
        assertNotEquals(policyBytesStub, sig,
                "the grant's attestation must be the producer unit sig, not the M0 policy stub");

        // Strict ordering: M0 policy sign -> flip (pack burned). The producer-unit sign
        // already ran (its result IS `sig`) before either.
        InOrder order = inOrder(spy);
        order.verify(spy).writeBackPolicySig(eq(session), eq(realm), eq(cr), eq(policyBytesStub));
        order.verify(spy).flipModeToMultiAdmin(session, realm);
    }

    @Test
    void bootstrapGrant_nonCapable_returnsRoleMappingStub_notPolicyBytesStub() {
        // GIVEN the flip-triggering grant on a NON-capable dev realm (no tide-vendor-key).
        // The fix routes the producer unit through the firstAdmin stub over the
        // user_role_mapping_set canonical — which must DIFFER from the M0 policy-bytes stub
        // the bug produced. (Both share the TIDE-FIRSTADMIN-v1 prefix; the SIGNED BYTES differ.)
        stubBootstrapGrantCr();
        stubPreChangeRoleIds(Collections.emptyList());
        // A tide-realm-admin policy row EXISTS, so readTideRealmAdminPolicyBytes returns its
        // policy bytes — the value the buggy path would have stamped on the role-mapping set.
        IgaRolePolicyEntity policyRow = new IgaRolePolicyEntity();
        policyRow.setId("p1");
        policyRow.setRealmId(REALM_ID);
        policyRow.setName(org.tidecloak.iga.attestors.TideAttestor.TIDE_REALM_ADMIN_POLICY_KEY);
        policyRow.setPolicy("THE-M0-POLICY-BYTES");
        policyRow.setPolicySig("OLD");
        stubPolicyLookup(policyRow);

        String sig = attestor.combineFinal(session, cr, Collections.emptyList());

        // The returned attestation is the firstAdmin stub over the role-mapping-set canonical
        // (real-shaped prefix), and is NOT the stub the buggy path produced over the policy bytes.
        assertTrue(sig.startsWith("TIDE-FIRSTADMIN-v1:"), "role-mapping attestation keeps the firstAdmin shape");
        String policyBytesStub = invokeStubSignOverPolicyBytes("THE-M0-POLICY-BYTES");
        assertNotEquals(policyBytesStub, sig,
                "the role-mapping attestation must NOT be the M0 policy-bytes stub (that was the bug)");
    }

    /** Compute the FIRSTADMIN stub the buggy path produced over the M0 policy bytes. */
    private static String invokeStubSignOverPolicyBytes(String policy) {
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(policy.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return "TIDE-FIRSTADMIN-v1:" + java.util.Base64.getEncoder().encodeToString(digest);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
