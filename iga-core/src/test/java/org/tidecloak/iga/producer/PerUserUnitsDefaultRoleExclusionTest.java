package org.tidecloak.iga.producer;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.UserModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.tidecloak.iga.producer.units.AttestationUnit;
import org.tidecloak.iga.producer.units.AttestationUnitType;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import jakarta.persistence.TypedQuery;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * ★ accept-unattested self-reg aud-fix CLOSURE invariant guard.
 *
 * <p>The registration-boundary default-role grant ({@code IgaUserAdapter
 * .grantDefaultRolesForRegistration}) makes the self-reg user HOLD the realm
 * default-role so KC emits the {@code account} audience. The OTHER invariant that
 * MUST simultaneously hold is that this default-roles-only user contributes NO
 * {@code user_role_mapping_set} unit to the producer closure — otherwise the
 * default-roles-only gate (which admits the unsigned {@code user_identity}) would
 * see a role-mapping unit and the accept-unattested login would be rejected.</p>
 *
 * <p>The D1b exclusion lives in {@link RealmAttestationExporter#perUserUnits}: the
 * realm default-role id is filtered out of the role-mapping set (DB-level
 * {@code AND urm.roleId <> :defaultRoleId}), so a user holding ONLY the default-role
 * yields an EMPTY set → the existing empty-skip drops the {@code user_role_mapping_set}
 * unit. This pins that a roleless-after-exclusion user emits only {@code user_identity}
 * (no role-mapping unit), independent of how the user came to hold default-roles.</p>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PerUserUnitsDefaultRoleExclusionTest {

    private static final String REALM_ID = "realm-uuid-selfreg";
    private static final String USER_ID = "selfreg-user-1";

    @Mock EntityManager em;
    @Mock UserModel user;

    @Test
    void defaultRolesOnlyUser_emitsNoUserRoleMappingSetUnit() {
        // The self-reg user (id/username only; no custom attributes).
        when(user.getId()).thenReturn(USER_ID);
        when(user.getUsername()).thenReturn("selfreg");
        when(user.getAttributes()).thenReturn(Collections.emptyMap());

        // defaultRoleIdForRealm: typed RealmEntity query → the realm default-role id.
        @SuppressWarnings("unchecked")
        TypedQuery<String> typed = mock(TypedQuery.class);
        when(em.createQuery(anyString(), eq(String.class))).thenReturn(typed);
        when(typed.setParameter(anyString(), org.mockito.ArgumentMatchers.any())).thenReturn(typed);
        when(typed.getSingleResult()).thenReturn("default-roles-" + REALM_ID);

        // userRoleMappingSet + userGroupMembershipSet: untyped JPQL. The role query,
        // with the default-role id excluded at the DB level, returns EMPTY for a
        // default-roles-only user; the group query also returns EMPTY.
        Query q = mock(Query.class);
        lenient().when(em.createQuery(anyString())).thenReturn(q);
        lenient().when(q.setParameter(anyString(), org.mockito.ArgumentMatchers.any())).thenReturn(q);
        when(q.getResultList()).thenReturn(Collections.emptyList());

        RealmAttestationExporter exporter = new RealmAttestationExporter();
        List<AttestationUnit> units = exporter.perUserUnits(em, user, REALM_ID);

        // user_identity is always emitted; the role-mapping/group set units are NOT,
        // because the post-exclusion sets are empty.
        boolean hasRoleMappingUnit = units.stream()
                .anyMatch(u -> u.type() == AttestationUnitType.USER_ROLE_MAPPING_SET);
        assertTrue(units.stream()
                        .anyMatch(u -> u.type() == AttestationUnitType.USER_IDENTITY),
                "perUserUnits must always emit the user_identity unit");
        assertEquals(false, hasRoleMappingUnit,
                "a default-roles-only self-reg user must emit NO user_role_mapping_set unit "
                        + "(default-role excluded by D1b) so the default-roles-only gate still "
                        + "admits the unsigned user_identity");
        // Exactly one unit (user_identity) for a default-roles-only, group-less user.
        assertEquals(1, units.size(),
                "default-roles-only + group-less user → only the user_identity unit");
    }
}
