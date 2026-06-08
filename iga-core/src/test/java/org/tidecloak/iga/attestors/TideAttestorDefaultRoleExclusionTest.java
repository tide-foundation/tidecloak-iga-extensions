package org.tidecloak.iga.attestors;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.producer.units.AttestationUnit;
import org.tidecloak.iga.producer.units.AttestationUnitType;
import org.tidecloak.iga.producer.units.UserRoleMappingSetUnit;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * ★ D1b divergence guard — {@code TideAttestor.buildUserRoleMappingSetUnit} (the firstAdmin
 * GRANT_ROLES commit signer) must EXCLUDE the realm default-role id IDENTICALLY to the producer
 * helper {@code RealmAttestationExporter.userRoleMappingSet}. The two MUST produce byte-identical
 * sets or the VVK verify breaks.
 *
 * <p>The DB-level {@code AND urm.roleId <> :defaultRoleId} clause is not observable through a
 * fixed-result em mock, so this exercises the POST-query union filter: a GRANT_ROLES CR that
 * grants the DEFAULT-role id (e.g. the default-roles composite arriving via an explicit grant
 * row) must NOT re-introduce it into the signed set. The signed unit must byte-match the
 * producer's {@link UserRoleMappingSetUnit} over the committed set WITHOUT the default-role id.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TideAttestorDefaultRoleExclusionTest {

    private static final String REALM_ID = "realm-uuid-excl";
    private static final String USER_ID = "user-excl";
    private static final String DEFAULT_ROLE_ID = "default-roles-realm-uuid-excl";

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock JpaConnectionProvider jpa;
    @Mock EntityManager em;
    @Mock IgaChangeRequestEntity cr;

    private TideAttestor attestor;

    @BeforeEach
    void setUp() {
        when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa);
        when(jpa.getEntityManager()).thenReturn(em);
        when(realm.getId()).thenReturn(REALM_ID);
        RoleModel defaultRole = mock(RoleModel.class);
        when(defaultRole.getId()).thenReturn(DEFAULT_ROLE_ID);
        when(realm.getDefaultRole()).thenReturn(defaultRole);
        attestor = new TideAttestor(session);
    }

    private void stubPreSetQuery(List<String> ids) {
        Query q = mock(Query.class);
        when(em.createQuery(anyString())).thenReturn(q);
        when(q.setParameter(anyString(), org.mockito.ArgumentMatchers.any())).thenReturn(q);
        when(q.getResultList()).thenReturn((List) ids);
    }

    @Test
    void grantOfTheDefaultRoleId_isExcludedFromTheSignedSet_byteIdenticalToProducer() {
        // PRE-set (after the mocked JPQL) = {r-aaa}. The CR grants the DEFAULT-role id.
        // The union filter must DROP the default-role id, leaving {r-aaa}.
        stubPreSetQuery(Arrays.asList("r-aaa"));
        when(cr.getActionType()).thenReturn("GRANT_ROLES");
        when(cr.getEntityId()).thenReturn(USER_ID);
        when(cr.getRowsJson()).thenReturn(
                "[{\"USER_ID\":\"" + USER_ID + "\",\"ROLE_ID\":\"" + DEFAULT_ROLE_ID + "\"}]");

        List<AttestationUnit> units = attestor.buildAllCrUnits(session, realm, cr, true);

        assertEquals(1, units.size());
        AttestationUnit u0 = units.get(0);
        assertEquals(AttestationUnitType.USER_ROLE_MAPPING_SET, u0.type());
        assertEquals(USER_ID, u0.targetId());

        // Byte-identity: the producer would emit ONLY {r-aaa} (the default-role id excluded by
        // its JPQL). The signer must match exactly.
        byte[] producerBytes = new UserRoleMappingSetUnit(
                REALM_ID, USER_ID, Arrays.asList("r-aaa")).serialize();
        assertArrayEquals(producerBytes, u0.serialize(),
                "the signer must exclude the default-role id (union filter) and byte-match the "
                        + "producer's user_role_mapping_set over the non-default set");
    }

    @Test
    void explicitGrant_alongsideDefault_keepsOnlyTheExplicitGrant() {
        // PRE-set = {r-aaa}; the CR grants BOTH an explicit role r-zzz AND the default-role id.
        // Result must be {r-aaa, r-zzz} (sorted) — the default-role id dropped.
        stubPreSetQuery(Arrays.asList("r-aaa"));
        when(cr.getActionType()).thenReturn("GRANT_ROLES");
        when(cr.getEntityId()).thenReturn(USER_ID);
        when(cr.getRowsJson()).thenReturn(
                "[{\"USER_ID\":\"" + USER_ID + "\",\"ROLE_ID\":\"r-zzz\"},"
                        + "{\"USER_ID\":\"" + USER_ID + "\",\"ROLE_ID\":\"" + DEFAULT_ROLE_ID + "\"}]");

        List<AttestationUnit> units = attestor.buildAllCrUnits(session, realm, cr, true);

        byte[] producerBytes = new UserRoleMappingSetUnit(
                REALM_ID, USER_ID, Arrays.asList("r-aaa", "r-zzz")).serialize();
        assertArrayEquals(producerBytes, units.get(0).serialize(),
                "only the explicit grant survives alongside the pre-set; the default-role id is dropped");
        assertFalse(units.get(0).serialize().length == 0);
    }
}
