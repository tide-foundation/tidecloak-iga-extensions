package org.tidecloak.iga.services;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Pins the purge order (children before parents), that every delete is scoped to
 * the deleted realm, and that the in-flight CR can be kept.
 */
class IgaRealmCleanupTest {

    private static final String REALM_ID = "deleted-realm-id";

    /** One entry per executed delete: the JPQL or named query, plus its bound parameters. */
    private record Executed(String query, Map<String, Object> params) {
    }

    private EntityManager em;
    private final List<Executed> executed = new ArrayList<>();

    @BeforeEach
    void setUp() {
        em = mock(EntityManager.class);
        when(em.createQuery(anyString())).thenAnswer(inv -> recordingQuery(inv.getArgument(0)));
        when(em.createNamedQuery(anyString())).thenAnswer(inv -> recordingQuery(inv.getArgument(0)));
    }

    private Query recordingQuery(String text) {
        Query q = mock(Query.class);
        Map<String, Object> params = new HashMap<>();
        when(q.setParameter(anyString(), any())).thenAnswer(inv -> {
            params.put(inv.getArgument(0), inv.getArgument(1));
            return q;
        });
        when(q.executeUpdate()).thenAnswer(inv -> {
            executed.add(new Executed(text, params));
            return 1;
        });
        return q;
    }

    private int indexOf(String fragment) {
        for (int i = 0; i < executed.size(); i++) {
            if (executed.get(i).query().contains(fragment)) return i;
        }
        throw new AssertionError("no delete ran for " + fragment);
    }

    @Test
    void deletesEveryTable_childrenBeforeParents() {
        int n = IgaRealmCleanup.purge(em, REALM_ID, null);

        assertEquals(11, executed.size());
        assertEquals(11, n);
        int changeRequests = indexOf("DELETE FROM IgaChangeRequestEntity");
        assertTrue(indexOf("IgaAuthorizationEntity") < changeRequests);
        assertTrue(indexOf("IgaCommentEntity") < changeRequests);
        assertTrue(indexOf("IgaServerCertDraft.deleteByRealm") < changeRequests);
        assertTrue(indexOf("IgaLicensingDraft.deleteByRealm") < changeRequests);
        assertTrue(indexOf("IgaUnsignedEntityEntity") < changeRequests);
        assertTrue(indexOf("IgaRolePolicy.deleteByRealm") < indexOf("IgaForsetiContract.deleteByRealm"));
        indexOf("IgaAuthorizerEntity");
        indexOf("IgaLicenseHistory.deleteByRealm");
        indexOf("IgaToggleJobEntity");
    }

    @Test
    void everyDeleteIsScopedToTheDeletedRealm() {
        // This is what keeps the master-keyed bypass audit row (and every other realm) safe.
        IgaRealmCleanup.purge(em, REALM_ID, null);
        for (Executed e : executed) {
            assertEquals(REALM_ID, e.params().get("realmId"), e.query());
        }
    }

    @Test
    void keepsTheExcludedChangeRequestAndItsChildren() {
        IgaRealmCleanup.purge(em, REALM_ID, "in-flight-cr");
        for (String fragment : List.of("IgaAuthorizationEntity", "IgaCommentEntity",
                "DELETE FROM IgaChangeRequestEntity")) {
            Executed e = executed.get(indexOf(fragment));
            assertTrue(e.query().contains("cr.id <> :keep"), e.query());
            assertEquals("in-flight-cr", e.params().get("keep"));
        }
    }

    @Test
    void noExclusion_keepsNothing() {
        IgaRealmCleanup.purge(em, REALM_ID, null);
        Executed e = executed.get(indexOf("DELETE FROM IgaChangeRequestEntity"));
        assertEquals("", e.params().get("keep"));
    }

    @Test
    void nullRealmId_doesNothing() {
        assertEquals(0, IgaRealmCleanup.purge(em, null, null));
        verifyNoInteractions(em);
        assertFalse(executed.size() > 0);
    }
}
