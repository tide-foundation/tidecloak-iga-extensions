package org.tidecloak.iga.providers;

import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.persistence.TypedQuery;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.tidecloak.iga.entities.IgaRolePolicyEntity;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The realm-level policy service keys reads/writes by (realmId, NAME). The
 * by-name lookup must return the row carrying the EXACT bytes/sig/threshold that
 * were stored (the M0 byte-identity invariant: only the lookup key changed, not
 * the signed contents).
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class IgaRealmPolicyServiceByNameTest {

    private static final String REALM_ID = "realm-uuid-svc";
    private static final String NAME = "tide-realm-admin";

    @Mock EntityManager em;

    private IgaRolePolicyService service;

    @BeforeEach
    void setUp() {
        service = new IgaRolePolicyService(em);
    }

    @SuppressWarnings("unchecked")
    private TypedQuery<IgaRolePolicyEntity> stubByName(IgaRolePolicyEntity result) {
        TypedQuery<IgaRolePolicyEntity> q = mock(TypedQuery.class);
        when(em.createNamedQuery(eq("IgaRolePolicy.findByRealmAndName"), eq(IgaRolePolicyEntity.class)))
                .thenReturn(q);
        when(q.setParameter(anyString(), any())).thenReturn(q);
        if (result == null) {
            when(q.getSingleResult()).thenThrow(new NoResultException());
        } else {
            when(q.getSingleResult()).thenReturn(result);
        }
        return q;
    }

    @Test
    void findByName_returnsRowWithIdenticalBytes() {
        IgaRolePolicyEntity stored = new IgaRolePolicyEntity();
        stored.setId("id-1");
        stored.setRealmId(REALM_ID);
        stored.setName(NAME);
        stored.setPolicy("Base64-Policy-ToBytes-VERBATIM");
        stored.setPolicySig("REAL-VVK-SIG-64B");
        stored.setThreshold(3);
        stubByName(stored);

        IgaRolePolicyEntity found = service.findByRealmAndName(REALM_ID, NAME);

        assertSame(stored, found);
        // Byte-identity: the policy body and sig come back unchanged.
        assertArrayEquals("Base64-Policy-ToBytes-VERBATIM".getBytes(),
                found.getPolicy().getBytes());
        assertEquals("REAL-VVK-SIG-64B", found.getPolicySig());
        assertEquals(Integer.valueOf(3), found.getThreshold());
    }

    @Test
    void findByName_returnsNullWhenAbsent() {
        stubByName(null);
        assertNull(service.findByRealmAndName(REALM_ID, "no-such-policy"));
    }

    @Test
    void upsert_insertsKeyedByName() {
        stubByName(null); // no existing -> INSERT
        service.upsert(REALM_ID, "custom-x", "body", "SIG", null, "EXPLICIT", "PUBLIC", 2, null);

        ArgumentCaptor<IgaRolePolicyEntity> cap = ArgumentCaptor.forClass(IgaRolePolicyEntity.class);
        verify(em).persist(cap.capture());
        IgaRolePolicyEntity persisted = cap.getValue();
        assertEquals(REALM_ID, persisted.getRealmId());
        assertEquals("custom-x", persisted.getName());
        assertEquals("body", persisted.getPolicy());
        assertEquals("SIG", persisted.getPolicySig());
    }
}
