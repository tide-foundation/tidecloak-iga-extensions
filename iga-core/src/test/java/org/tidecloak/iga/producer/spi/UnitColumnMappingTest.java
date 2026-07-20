package org.tidecloak.iga.producer.spi;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.tidecloak.iga.producer.units.AttestationUnit;
import org.tidecloak.iga.producer.units.AttestationUnitType;
import org.tidecloak.iga.producer.units.ParentType;
import org.tidecloak.iga.producer.units.ScopeRoleAllowlistSetUnit;

import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The uniform Design B read/backfill contract: {@link UnitColumnMapping} must resolve
 * a column for EVERY one of the 18 {@link AttestationUnitType}s the login emits (the
 * read flip is all-or-nothing, so a single un-mapped type would fail-close every login
 * on a realm whose closure contains it).
 *
 * <p>These tests mock the {@link EntityManager} so the JPQL dispatch is exercised
 * without a DB: a {@code readStored} call must reach a SELECT query for its type, and a
 * {@code stamp} call must reach an UPDATE query carrying the exact sig — neither may hit
 * the resolver's {@code default} (which throws {@link IllegalStateException}).
 */
class UnitColumnMappingTest {

    private static final String REALM = "realm-uuid";

    /** A minimal concrete unit for a given type whose target_id is deterministic. */
    private static AttestationUnit unitOf(AttestationUnitType type) {
        return new AttestationUnit(REALM, "target-" + type.wireValue()) {
            @Override public AttestationUnitType type() { return type; }
            @Override public Map<String, Object> payload() { return Collections.emptyMap(); }
        };
    }

    @Test
    void everyUnitType_resolvesAReadColumn_noDefaultThrow() {
        EnumMap<AttestationUnitType, Boolean> covered = new EnumMap<>(AttestationUnitType.class);
        for (AttestationUnitType type : AttestationUnitType.values()) {
            EntityManager em = mock(EntityManager.class);
            Query q = mock(Query.class);
            when(em.createQuery(anyString())).thenReturn(q);
            when(q.setParameter(anyString(), org.mockito.ArgumentMatchers.any())).thenReturn(q);
            when(q.setMaxResults(org.mockito.ArgumentMatchers.anyInt())).thenReturn(q);
            when(q.getResultList()).thenReturn(List.of("TIDE-FIRSTADMIN-v1:abc"));

            AttestationUnit unit = (type == AttestationUnitType.SCOPE_ROLE_ALLOWLIST_SET)
                    ? new ScopeRoleAllowlistSetUnit(REALM, ParentType.client, "client-uuid", List.of())
                    : unitOf(type);

            // Must not throw the IllegalStateException default — every type is mapped.
            String stored = UnitColumnMapping.readStored(em, unit);
            assertEquals("TIDE-FIRSTADMIN-v1:abc", stored,
                    "read for " + type + " must return the column value");
            // It must have issued a SELECT against the right column.
            ArgumentCaptor<String> jpql = ArgumentCaptor.forClass(String.class);
            org.mockito.Mockito.verify(em).createQuery(jpql.capture());
            assertTrue(jpql.getValue().startsWith("SELECT"),
                    type + " read must be a SELECT, was: " + jpql.getValue());
            covered.put(type, true);
        }
        assertEquals(AttestationUnitType.values().length, covered.size(),
                "all 18 unit types must have a read column");
    }

    @Test
    void everyUnitType_stampsWithExactSig_noDefaultThrow() {
        String sig = "TIDE-FIRSTADMIN-v1:" + java.util.Base64.getEncoder()
                .encodeToString(new byte[64]);
        for (AttestationUnitType type : AttestationUnitType.values()) {
            EntityManager em = mock(EntityManager.class);
            Query q = mock(Query.class);
            when(em.createQuery(anyString())).thenReturn(q);
            when(q.setParameter(anyString(), org.mockito.ArgumentMatchers.any())).thenReturn(q);
            when(q.executeUpdate()).thenReturn(1);

            AttestationUnit unit = (type == AttestationUnitType.SCOPE_ROLE_ALLOWLIST_SET)
                    ? new ScopeRoleAllowlistSetUnit(REALM, ParentType.client_scope, "scope-uuid", List.of())
                    : unitOf(type);

            int rows = UnitColumnMapping.stamp(em, unit, sig);
            assertEquals(1, rows, "stamp for " + type + " must update one row in this fixture");

            ArgumentCaptor<String> jpql = ArgumentCaptor.forClass(String.class);
            org.mockito.Mockito.verify(em).createQuery(jpql.capture());
            assertTrue(jpql.getValue().startsWith("UPDATE"),
                    type + " stamp must be an UPDATE, was: " + jpql.getValue());
            // The exact sig must be bound (no transformation).
            org.mockito.Mockito.verify(q).setParameter(eq("sig"), eq(sig));
        }
    }

    @Test
    void scopeRoleAllowlist_picksClientVsClientScopeColumn_byParentType() {
        // parent_type=client -> ClientEntity column
        assertColumnEntity(new ScopeRoleAllowlistSetUnit(REALM, ParentType.client, "p", List.of()),
                "ClientEntity");
        // parent_type=client_scope -> ClientScopeEntity column
        assertColumnEntity(new ScopeRoleAllowlistSetUnit(REALM, ParentType.client_scope, "p", List.of()),
                "ClientScopeEntity");
    }

    private static void assertColumnEntity(ScopeRoleAllowlistSetUnit unit, String expectEntity) {
        EntityManager em = mock(EntityManager.class);
        Query q = mock(Query.class);
        when(em.createQuery(anyString())).thenReturn(q);
        when(q.setParameter(anyString(), org.mockito.ArgumentMatchers.any())).thenReturn(q);
        when(q.setMaxResults(org.mockito.ArgumentMatchers.anyInt())).thenReturn(q);
        when(q.getResultList()).thenReturn(Collections.emptyList());

        assertNull(UnitColumnMapping.readStored(em, unit));
        ArgumentCaptor<String> jpql = ArgumentCaptor.forClass(String.class);
        org.mockito.Mockito.verify(em).createQuery(jpql.capture());
        assertTrue(jpql.getValue().contains(expectEntity),
                "scope_role_allowlist_set (" + unit.parentType() + ") must read from "
                        + expectEntity + ", was: " + jpql.getValue());
        assertTrue(jpql.getValue().contains("scopeRoleAllowlistAttestation"));
    }

    @Test
    void setUnits_stampFansAcrossAllOwnerRows_noRowFilter() {
        // A user_role_mapping_set stamp must UPDATE every row sharing the owner key
        // (the WHERE keys on user.id only — no roleId), so the per-set sig is readable
        // from any row. Assert the UPDATE has no row-narrowing predicate.
        EntityManager em = mock(EntityManager.class);
        Query q = mock(Query.class);
        when(em.createQuery(anyString())).thenReturn(q);
        when(q.setParameter(anyString(), org.mockito.ArgumentMatchers.any())).thenReturn(q);
        when(q.executeUpdate()).thenReturn(3);

        AttestationUnit urm = unitOf(AttestationUnitType.USER_ROLE_MAPPING_SET);
        int rows = UnitColumnMapping.stamp(em, urm, "sig");
        assertEquals(3, rows);
        ArgumentCaptor<String> jpql = ArgumentCaptor.forClass(String.class);
        org.mockito.Mockito.verify(em).createQuery(jpql.capture());
        assertTrue(jpql.getValue().contains("WHERE e.user.id = :id")
                        && !jpql.getValue().contains("roleId"),
                "URM-set stamp must fan across the whole owner set, was: " + jpql.getValue());
    }

    @Test
    void readForSetUnit_filtersNonNull() {
        // The set-unit read must require attestation IS NOT NULL (so an un-stamped row
        // among stamped ones never returns a NULL ahead of the real sig).
        EntityManager em = mock(EntityManager.class);
        Query q = mock(Query.class);
        when(em.createQuery(anyString())).thenReturn(q);
        when(q.setParameter(anyString(), org.mockito.ArgumentMatchers.any())).thenReturn(q);
        when(q.setMaxResults(org.mockito.ArgumentMatchers.anyInt())).thenReturn(q);
        when(q.getResultList()).thenReturn(Collections.emptyList());

        UnitColumnMapping.readStored(em, unitOf(AttestationUnitType.GROUP_ROLE_MAPPING_SET));
        ArgumentCaptor<String> jpql = ArgumentCaptor.forClass(String.class);
        org.mockito.Mockito.verify(em).createQuery(jpql.capture());
        assertTrue(jpql.getValue().contains("attestation IS NOT NULL"),
                "set-unit read must filter NULL rows, was: " + jpql.getValue());
        assertNotNull(jpql.getValue());
    }
}
