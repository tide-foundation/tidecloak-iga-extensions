package org.tidecloak.iga.providers;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link IgaChangeRequestService#findDuplicatePending} — the
 * exact-duplicate detector that distinguishes an idempotent re-request of an
 * already-pending action (same actionType + same target row) from a DIFFERENT
 * pending change on the same entity.
 *
 * <p>This is the discriminator the relationship seams use so that re-doing a
 * pending grant yields a handled 202 "already pending", while only a genuinely
 * different pending CR raises the (409-mapped) conflict — never an uncaught 500.</p>
 */
class IgaFindDuplicatePendingTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String REALM = "realm-uuid";
    private static final String USER = "user-uuid";
    private static final String ROLE_X = "role-x";
    private static final String ROLE_Y = "role-y";

    private EntityManager em;
    private TypedQuery<IgaChangeRequestEntity> query;
    private IgaChangeRequestService service;

    @SuppressWarnings("unchecked")
    @BeforeEach
    void setUp() {
        em = mock(EntityManager.class);
        query = mock(TypedQuery.class);
        KeycloakSession session = mock(KeycloakSession.class);
        when(em.createNamedQuery(eq("IgaChangeRequest.findPendingByEntity"),
                eq(IgaChangeRequestEntity.class))).thenReturn(query);
        when(query.setParameter(anyString(), any())).thenReturn(query);
        service = new IgaChangeRequestService(em, session);
    }

    private static IgaChangeRequestEntity cr(String id, String actionType,
                                             List<Map<String, Object>> rows) {
        IgaChangeRequestEntity e = new IgaChangeRequestEntity();
        e.setId(id);
        e.setRealmId(REALM);
        e.setEntityType("USER");
        e.setEntityId(USER);
        e.setActionType(actionType);
        try {
            e.setRowsJson(MAPPER.writeValueAsString(rows));
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
        e.setStatus("PENDING");
        return e;
    }

    private static List<Map<String, Object>> grantRows(String roleId) {
        return List.of(Map.of("USER_ID", USER, "ROLE_ID", roleId));
    }

    @Test
    void exactDuplicateGrant_isReturned() {
        IgaChangeRequestEntity existing = cr("cr-1", "GRANT_ROLES", grantRows(ROLE_X));
        when(query.getResultList()).thenReturn(List.of(existing));

        IgaChangeRequestEntity dup = service.findDuplicatePending(
                REALM, "USER", USER, "GRANT_ROLES", grantRows(ROLE_X));

        assertSame(existing, dup, "same action + same role row → duplicate");
    }

    @Test
    void differentRoleSameAction_isNotDuplicate() {
        IgaChangeRequestEntity existing = cr("cr-1", "GRANT_ROLES", grantRows(ROLE_X));
        when(query.getResultList()).thenReturn(List.of(existing));

        // Admin's actual scenario: a pending grant of role X must NOT be treated as a
        // duplicate of a grant of role Y → falls through to the conflict path.
        IgaChangeRequestEntity dup = service.findDuplicatePending(
                REALM, "USER", USER, "GRANT_ROLES", grantRows(ROLE_Y));

        assertNull(dup);
    }

    @Test
    void sameRowDifferentAction_isNotDuplicate() {
        // A pending REVOKE of role X is not a duplicate of a GRANT of role X.
        IgaChangeRequestEntity existing = cr("cr-1", "REVOKE_ROLES", grantRows(ROLE_X));
        when(query.getResultList()).thenReturn(List.of(existing));

        IgaChangeRequestEntity dup = service.findDuplicatePending(
                REALM, "USER", USER, "GRANT_ROLES", grantRows(ROLE_X));

        assertNull(dup);
    }

    @Test
    void noPendingCr_isNotDuplicate() {
        when(query.getResultList()).thenReturn(List.of());

        IgaChangeRequestEntity dup = service.findDuplicatePending(
                REALM, "USER", USER, "GRANT_ROLES", grantRows(ROLE_X));

        assertNull(dup);
    }

    @Test
    void duplicateFoundAmongMultiplePending() {
        IgaChangeRequestEntity other = cr("cr-1", "JOIN_GROUPS",
                List.of(Map.of("USER", USER, "GROUP", "group-1")));
        IgaChangeRequestEntity match = cr("cr-2", "GRANT_ROLES", grantRows(ROLE_X));
        when(query.getResultList()).thenReturn(List.of(other, match));

        IgaChangeRequestEntity dup = service.findDuplicatePending(
                REALM, "USER", USER, "GRANT_ROLES", grantRows(ROLE_X));

        assertSame(match, dup);
    }
}
