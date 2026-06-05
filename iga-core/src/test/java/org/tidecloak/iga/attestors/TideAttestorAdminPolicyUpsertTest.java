package org.tidecloak.iga.attestors;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.tidecloak.iga.entities.IgaRolePolicyEntity;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * M0 FIX coverage — the admin Policy (M0) row must be INSERTED, not merely
 * updated-if-present, on the firstAdmin->multiAdmin flip and on a threshold-change
 * regen. Previously the policy-write path was update-only: a realm that flipped
 * without a pre-seeded {@code iga_role_policy} row ended up multiAdmin with NO
 * signed M0 Policy, so every subsequent multiAdmin approval-model build threw
 * {@code APPROVAL_MODEL_BUILD_FAILED}.
 *
 * <p>These tests target {@code upsertAdminPolicyRow} — the shared insert-or-update
 * helper both write sites route through — directly, without standing up real
 * Midgard/ORK signing (which the real-signing-capable path would require).
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TideAttestorAdminPolicyUpsertTest {

    private static final String REALM_ID = "realm-uuid-xyz";
    private static final String TIDE_ROLE_ID = "tide-realm-admin-role-id";

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock JpaConnectionProvider jpa;
    @Mock EntityManager em;
    @Mock ClientModel realmManagement;
    @Mock RoleModel tideRealmAdmin;

    private TideAttestor attestor;

    @BeforeEach
    void setUp() {
        when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa);
        when(jpa.getEntityManager()).thenReturn(em);
        when(realm.getId()).thenReturn(REALM_ID);
        when(realm.getClientByClientId("realm-management")).thenReturn(realmManagement);
        when(realmManagement.getRole("tide-realm-admin")).thenReturn(tideRealmAdmin);
        when(tideRealmAdmin.getId()).thenReturn(TIDE_ROLE_ID);
        attestor = new TideAttestor(session);
    }

    @Test
    void insertsNewRowWhenNoneExists() {
        // The flip/regen with NO pre-seeded policy row must INSERT a fully-formed,
        // keyed-and-signed M0 Policy row — this is the bug fix (previously a no-op).
        IgaRolePolicyEntity result = attestor.upsertAdminPolicyRow(
                session, realm, null, "policy-body-bytes", "VVK-SIG", 3);

        assertNotNull(result, "a new M0 Policy row must be created on the flip");
        ArgumentCaptor<IgaRolePolicyEntity> captor = ArgumentCaptor.forClass(IgaRolePolicyEntity.class);
        verify(em, times(1)).persist(captor.capture());
        IgaRolePolicyEntity persisted = captor.getValue();
        assertNotNull(persisted.getId(), "inserted row needs a generated id");
        assertEquals(REALM_ID, persisted.getRealmId());
        assertEquals(TIDE_ROLE_ID, persisted.getRoleId(), "row must be keyed to tide-realm-admin");
        assertEquals("policy-body-bytes", persisted.getPolicy());
        assertEquals("VVK-SIG", persisted.getPolicySig());
        assertEquals(Integer.valueOf(3), persisted.getThreshold());
        assertEquals("EXPLICIT", persisted.getApprovalType());
        assertEquals("PUBLIC", persisted.getExecutionType());
        assertNotNull(persisted.getCreatedAt());
    }

    @Test
    void updatesExistingRowWithoutInserting() {
        // When a row already exists (e.g. a threshold-change regen), it is overwritten
        // in place — no new INSERT, so the unique (realm, role) constraint is respected.
        IgaRolePolicyEntity existing = new IgaRolePolicyEntity();
        existing.setId("pre-existing-id");
        existing.setRealmId(REALM_ID);
        existing.setRoleId(TIDE_ROLE_ID);
        existing.setPolicy("old-body");
        existing.setPolicySig("OLD-SIG");
        existing.setThreshold(2);

        IgaRolePolicyEntity result = attestor.upsertAdminPolicyRow(
                session, realm, existing, "new-body", "NEW-SIG", 5);

        assertSame(existing, result, "update path returns the same managed entity");
        verify(em, never()).persist(org.mockito.ArgumentMatchers.any());
        assertEquals("new-body", existing.getPolicy());
        assertEquals("NEW-SIG", existing.getPolicySig());
        assertEquals(Integer.valueOf(5), existing.getThreshold());
        assertNotNull(existing.getUpdatedAt());
        assertEquals("pre-existing-id", existing.getId(), "id is preserved on update");
    }

    @Test
    void returnsNullWhenTideRealmAdminRoleUnresolvable() {
        // No realm-management tide-realm-admin role → cannot key the row. The caller
        // (capable flip) fails closed; the non-capable path logs + skips.
        when(realmManagement.getRole("tide-realm-admin")).thenReturn(null);

        IgaRolePolicyEntity result = attestor.upsertAdminPolicyRow(
                session, realm, null, "body", "SIG", 1);

        assertNull(result);
        verify(em, never()).persist(org.mockito.ArgumentMatchers.any());
    }

    // -------------------------------------------------------------------------
    // M0 BACKFILL AUTO-HEAL — readM0AdminPolicyBytes creates + signs the admin
    // Policy on an already-flipped multiAdmin realm that never installed one.
    // -------------------------------------------------------------------------

    /** Stub the {@code IgaRolePolicy.findByRealmAndRole} query findTideRealmAdminPolicy runs. */
    @SuppressWarnings("unchecked")
    private void stubFindPolicy(IgaRolePolicyEntity... rows) {
        TypedQuery<IgaRolePolicyEntity> q = mock(TypedQuery.class);
        when(em.createNamedQuery(eq("IgaRolePolicy.findByRealmAndRole"), eq(IgaRolePolicyEntity.class)))
                .thenReturn(q);
        when(q.setParameter(anyString(), org.mockito.ArgumentMatchers.any())).thenReturn(q);
        // A fresh stream per invocation (findTideRealmAdminPolicy runs the query each call).
        when(q.getResultStream()).thenAnswer(inv -> Stream.of(rows));
    }

    @Test
    void backfillCreatesSignsAndPersistsM0OnCapableRealmWithNoPolicy() {
        // The myrealm symptom: a multiAdmin realm that flipped with NO iga_role_policy row.
        // readM0AdminPolicyBytes must CREATE + REAL-VVK-sign the M0 Policy at the live
        // threshold, persist it, and return the freshly-signed bytes (non-null) — no throw.
        stubFindPolicy(); // no existing row

        TideAttestor a = spy(new TideAttestor(session));
        // Capable realm (avoids needing real ORK material / THRESHOLD_* env in-unit).
        doReturn(true).when(a).isBackfillSigningCapable(realm);
        // Live committed admin count = 4 -> threshold = max(1, floor(0.7*4)) = 2.
        doReturn(4).when(a).liveTideRealmAdminCount(realm, session);
        // Stand in for the real Midgard->ORK ceremony: a real-flavored signed artifact whose
        // body is Base64(Policy.ToBytes()) so readM0AdminPolicyBytes Base64-decodes it.
        byte[] rawPolicyBytes = "signed-policy-tobytes".getBytes(StandardCharsets.UTF_8);
        String b64Body = Base64.getEncoder().encodeToString(rawPolicyBytes);
        TideAttestor.AdminPolicyArtifact artifact =
                new TideAttestor.AdminPolicyArtifact(b64Body, "REAL-VVK-SIG", true);
        // Capture the threshold the heal computes from the live admin count.
        ArgumentCaptor<Integer> thresholdCap = ArgumentCaptor.forClass(Integer.class);
        doReturn(artifact).when(a)
                .buildSignedAdminPolicyArtifact(eq(session), eq(realm), thresholdCap.capture(), any());

        byte[] result = a.readM0AdminPolicyBytes(session, realm);

        // Returned the freshly-signed raw Policy bytes (Base64-decoded body) — build proceeds.
        assertArrayEquals(rawPolicyBytes, result, "heal returns the just-signed Policy bytes");
        // Threshold matched the LIVE admin count: floor(0.7*4)=2.
        assertEquals(Integer.valueOf(2), thresholdCap.getValue(),
                "backfill threshold must equal max(1, floor(0.7 x live admin count))");
        // Persisted a NEW keyed+signed M0 row via the insert path.
        ArgumentCaptor<IgaRolePolicyEntity> persisted = ArgumentCaptor.forClass(IgaRolePolicyEntity.class);
        verify(em, times(1)).persist(persisted.capture());
        IgaRolePolicyEntity row = persisted.getValue();
        assertEquals(TIDE_ROLE_ID, row.getRoleId(), "M0 row keyed to tide-realm-admin");
        assertEquals(b64Body, row.getPolicy());
        assertEquals("REAL-VVK-SIG", row.getPolicySig());
        assertEquals(Integer.valueOf(2), row.getThreshold());
    }

    @Test
    void backfillIsIdempotentReusesExistingSignedRowWithoutResigning() {
        // A valid signed M0 row already exists -> readM0AdminPolicyBytes returns its bytes
        // unchanged and NEVER re-signs (no buildSignedAdminPolicyArtifact, no persist).
        byte[] rawPolicyBytes = "already-signed".getBytes(StandardCharsets.UTF_8);
        IgaRolePolicyEntity existing = new IgaRolePolicyEntity();
        existing.setId("existing-id");
        existing.setRoleId(TIDE_ROLE_ID);
        existing.setPolicy(Base64.getEncoder().encodeToString(rawPolicyBytes));
        existing.setPolicySig("EXISTING-SIG");
        stubFindPolicy(existing);

        TideAttestor a = spy(new TideAttestor(session));

        byte[] result = a.readM0AdminPolicyBytes(session, realm);

        assertArrayEquals(rawPolicyBytes, result, "existing signed row reused verbatim");
        // No re-sign, no capability probe, no insert — pure read.
        verify(a, never()).buildSignedAdminPolicyArtifact(any(), any(), anyInt(), any());
        verify(a, never()).isBackfillSigningCapable(any());
        verify(em, never()).persist(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void backfillSkippedOnNonCapableRealmReturnsNull() {
        // NON-capable realm with no policy row: we do NOT fabricate a "real" policy.
        // readM0AdminPolicyBytes returns null (the existing stub/throw behaviour).
        stubFindPolicy(); // no existing row

        TideAttestor a = spy(new TideAttestor(session));
        doReturn(false).when(a).isBackfillSigningCapable(realm);

        byte[] result = a.readM0AdminPolicyBytes(session, realm);

        assertNull(result, "non-capable realm is not auto-healed");
        verify(a, never()).buildSignedAdminPolicyArtifact(any(), any(), anyInt(), any());
        verify(em, never()).persist(org.mockito.ArgumentMatchers.any());
    }
}
