package org.tidecloak.iga.attestors;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.midgard.models.Policy.Policy;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.entities.IgaRolePolicyEntity;
import org.tidecloak.iga.providers.IgaConflictException;
import org.tidecloak.iga.providers.IgaJitPolicyService;

import java.util.Base64;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Raising the governed request to sign one JIT policy.
 *
 * <p>The property that matters is what does NOT happen: nothing reaches IGA_ROLE_POLICY until the
 * quorum has signed. An unsigned JIT policy cannot mint a credential, so a row stored at request
 * time would look like a grant that is not one.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TideAttestorJitPolicyCrTest {

    private static final String REALM_ID = "realm-uuid-xyz";
    private static final String POLICY_NAME = "jit:myclient:case:read:vuid-abc";

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock JpaConnectionProvider jpa;
    @Mock EntityManager em;

    private TideAttestor attestor;

    @BeforeEach
    void setUp() {
        when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa);
        when(jpa.getEntityManager()).thenReturn(em);
        when(realm.getId()).thenReturn(REALM_ID);
        when(realm.getName()).thenReturn("mediquill");
        when(realm.getAccessTokenLifespan()).thenReturn(600);
        stubNoPending();
        attestor = new TideAttestor(session);
    }

    /** No pending CR for this policy name. */
    @SuppressWarnings("unchecked")
    private void stubNoPending() {
        TypedQuery<IgaChangeRequestEntity> q = org.mockito.Mockito.mock(TypedQuery.class);
        when(em.createNamedQuery(anyString(), eq(IgaChangeRequestEntity.class))).thenReturn(q);
        when(q.setParameter(anyString(), any())).thenReturn(q);
        when(q.getResultList()).thenReturn(Collections.emptyList());
    }

    private byte[] jitPolicyBytes() {
        Policy p = IgaJitPolicyService.buildPolicy(realm, "contract-1", "vuid-abc", "myclient",
                "case:read", "assessment-1", "content",
                (System.currentTimeMillis() / 1000L) + 3600);
        return p.ToBytes();
    }

    @Test
    void raisingTheRequestStoresNothingInRolePolicy() {
        attestor.requestJitPolicySignature(session, realm, POLICY_NAME, jitPolicyBytes(), "sasha");

        // The signed policy is installed at COMMIT. Storing it now would put a row there that
        // reads as a grant before any admin has approved it.
        verify(em, never()).persist(any(IgaRolePolicyEntity.class));
        verify(em, never()).merge(any(IgaRolePolicyEntity.class));
    }

    @Test
    void theRequestCarriesTheExactBytesToBeSigned() {
        byte[] policy = jitPolicyBytes();

        attestor.requestJitPolicySignature(session, realm, POLICY_NAME, policy, "sasha");

        ArgumentCaptor<Object> cap = ArgumentCaptor.forClass(Object.class);
        verify(em).persist(cap.capture());
        IgaChangeRequestEntity cr = (IgaChangeRequestEntity) cap.getValue();

        assertEquals(TideAttestor.ACTION_SIGN_JIT_POLICY, cr.getActionType());
        assertEquals(TideAttestor.ENTITY_TYPE_JIT_POLICY, cr.getEntityType());
        assertEquals(POLICY_NAME, cr.getEntityId());

        // Carried verbatim, so the bytes an admin approves are the bytes the commit signs.
        String expected = Base64.getEncoder().encodeToString(policy);
        assertTrue(cr.getRowsJson().contains(expected),
                "the unsigned policy must be carried verbatim in ROWS_JSON");
    }

    @Test
    void theReservedAdminPolicyNameIsRefused() {
        // Sharing the carrier with the admin-policy re-sign must not mean a JIT grant can rewrite
        // the quorum it is approved by.
        assertThrows(IllegalArgumentException.class, () ->
                attestor.requestJitPolicySignature(session, realm,
                        TideAttestor.TIDE_REALM_ADMIN_POLICY_KEY, jitPolicyBytes(), "sasha"));

        verify(em, never()).persist(any());
    }

    @Test
    void anEmptyPolicyOrNameIsRefused() {
        assertThrows(IllegalArgumentException.class, () ->
                attestor.requestJitPolicySignature(session, realm, "  ", jitPolicyBytes(), "sasha"));
        assertThrows(IllegalArgumentException.class, () ->
                attestor.requestJitPolicySignature(session, realm, POLICY_NAME, new byte[0], "sasha"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void asecondPendingSignatureForTheSamePolicyIsRefused() {
        // Two pending signatures for one policy name would race for the same row, and whichever
        // committed last would silently win.
        IgaChangeRequestEntity existing = new IgaChangeRequestEntity();
        existing.setId("cr-already-pending");
        TypedQuery<IgaChangeRequestEntity> q = org.mockito.Mockito.mock(TypedQuery.class);
        when(em.createNamedQuery(anyString(), eq(IgaChangeRequestEntity.class))).thenReturn(q);
        when(q.setParameter(anyString(), any())).thenReturn(q);
        when(q.getResultList()).thenReturn(List.of(existing));

        IgaConflictException e = assertThrows(IgaConflictException.class, () ->
                attestor.requestJitPolicySignature(session, realm, POLICY_NAME, jitPolicyBytes(), "sasha"));

        assertTrue(e.getMessage().contains("cr-already-pending"), e.getMessage());
        verify(em, never()).persist(any());
    }
}
