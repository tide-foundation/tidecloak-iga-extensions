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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.never;
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
}
