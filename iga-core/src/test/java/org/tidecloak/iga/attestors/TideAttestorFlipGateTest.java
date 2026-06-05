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
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.tidecloak.iga.entities.IgaAuthorizerEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.entities.IgaRolePolicyEntity;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
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

    /** Stub the IgaRolePolicy.findByRealmAndRole named query to return {@code result}. */
    private void stubPolicyLookup(IgaRolePolicyEntity result) {
        when(em.createNamedQuery(eq("IgaRolePolicy.findByRealmAndRole"), eq(IgaRolePolicyEntity.class)))
                .thenReturn(policyQuery);
        when(policyQuery.setParameter(anyString(), any())).thenReturn(policyQuery);
        when(policyQuery.getResultStream())
                .thenReturn(result == null ? Stream.empty() : Stream.of(result));
    }

    /** Stub the IgaAuthorizer.findByRealm named query to return {@code row}. */
    private void stubAuthorizerLookup(IgaAuthorizerEntity row) {
        when(em.createNamedQuery(eq("IgaAuthorizer.findByRealm"), eq(IgaAuthorizerEntity.class)))
                .thenReturn(authorizerQuery);
        when(authorizerQuery.setParameter(anyString(), any())).thenReturn(authorizerQuery);
        when(authorizerQuery.getResultStream())
                .thenReturn(row == null ? Stream.empty() : Stream.of(row));
    }

    @Test
    void writeBackCommitsPolicyAndReturnsTrue_thenFlipFires_existingRow() {
        // GIVEN a tide-realm-admin M0 policy row already exists (e.g. pre-seeded via
        // POST /iga/role-policies). The non-capable write-back re-stamps it and commits.
        IgaRolePolicyEntity existing = new IgaRolePolicyEntity();
        existing.setId("pre-seeded-id");
        existing.setRealmId(REALM_ID);
        existing.setRoleId(TIDE_ROLE_ID);
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
}
