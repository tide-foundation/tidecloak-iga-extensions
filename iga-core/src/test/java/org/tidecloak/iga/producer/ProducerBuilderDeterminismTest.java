package org.tidecloak.iga.producer;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.OrganizationDomainModel;
import org.keycloak.models.OrganizationModel;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.tidecloak.iga.producer.units.ClientMapperSetUnit;
import org.tidecloak.iga.producer.units.ClientScopeMapperSetUnit;
import org.tidecloak.iga.producer.units.OrgDomain;
import org.tidecloak.iga.producer.units.OrganizationDomainSetUnit;
import org.tidecloak.iga.producer.units.ParentType;
import org.tidecloak.iga.producer.units.RealmDefaultGroupsSetUnit;
import org.tidecloak.iga.producer.units.ScopeRoleAllowlistSetUnit;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * PR-A.2 coverage — the shared {@link RealmAttestationExporter} producer builders the
 * POST-replay column stampers ({@code TideAttestor#stampProducerUnitColumns}) reuse MUST
 * emit a DETERMINISTIC (sorted) envelope, so the commit-time stamp byte-matches the
 * login/export emission over the same committed state regardless of the underlying KC
 * stream iteration order (the literal-bytes VVK verification makes member ORDER
 * load-bearing).
 *
 * <p>Each test feeds the builder a deliberately UNSORTED member stream and asserts the
 * serialized bytes equal a hand-constructed unit whose members are in ASCENDING order —
 * proving the builder normalizes the order and that the commit path (which calls the same
 * builder) is byte-identical to login.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ProducerBuilderDeterminismTest {

    private static final String REALM_ID = "realm-uuid-det";
    private static final String CLIENT_UUID = "client-uuid-det";
    private static final String SCOPE_ID = "scope-uuid-det";
    private static final String ORG_ID = "org-uuid-det";

    private ProtocolMapperModel mapper(String id, String factory) {
        ProtocolMapperModel m = mock(ProtocolMapperModel.class);
        when(m.getId()).thenReturn(id);
        when(m.getProtocolMapper()).thenReturn(factory);
        return m;
    }

    private RoleModel role(String id) {
        RoleModel r = mock(RoleModel.class);
        when(r.getId()).thenReturn(id);
        return r;
    }

    @Test
    void clientMapperSet_filtersIrrelevantFactories_andSortsIds() {
        // Build the mapper mocks FIRST (nested when() inside a when().thenReturn(...)
        // argument trips Mockito's UnfinishedStubbing guard).
        ProtocolMapperModel pmZ = mapper("pm-zzz", "oidc-usermodel-attribute-mapper");
        ProtocolMapperModel pmSub = mapper("pm-sub", "oidc-sub-mapper");
        ProtocolMapperModel pmA = mapper("pm-aaa", "oidc-usermodel-property-mapper");
        ClientModel client = mock(ClientModel.class);
        when(client.getId()).thenReturn(CLIENT_UUID);
        // Unsorted, with one JWT-body-irrelevant factory (oidc-sub-mapper) that must drop.
        when(client.getProtocolMappersStream()).thenReturn(Stream.of(pmZ, pmSub, pmA));

        byte[] built = RealmAttestationExporter.clientMapperSet(client, REALM_ID).serialize();

        byte[] expected = new ClientMapperSetUnit(REALM_ID, CLIENT_UUID,
                Arrays.asList("pm-aaa", "pm-zzz")).serialize();
        assertArrayEquals(expected, built,
                "client_mapper_set must drop irrelevant factories and sort the surviving ids");
    }

    @Test
    void clientScopeMapperSet_sortsIds() {
        ProtocolMapperModel pmC = mapper("pm-ccc", "oidc-usermodel-attribute-mapper");
        ProtocolMapperModel pmA = mapper("pm-aaa", "oidc-usermodel-property-mapper");
        ClientScopeModel scope = mock(ClientScopeModel.class);
        when(scope.getId()).thenReturn(SCOPE_ID);
        when(scope.getProtocolMappersStream()).thenReturn(Stream.of(pmC, pmA));

        byte[] built = RealmAttestationExporter.clientScopeMapperSet(scope, REALM_ID).serialize();

        byte[] expected = new ClientScopeMapperSetUnit(REALM_ID, SCOPE_ID,
                Arrays.asList("pm-aaa", "pm-ccc")).serialize();
        assertArrayEquals(expected, built,
                "client_scope_mapper_set must sort the member ids");
    }

    @Test
    void scopeRoleAllowlistSet_sortsRoleIds() {
        RoleModel rZ = role("r-zzz");
        RoleModel rA = role("r-aaa");
        ClientModel client = mock(ClientModel.class);
        when(client.getScopeMappingsStream()).thenReturn(Stream.of(rZ, rA));

        byte[] built = RealmAttestationExporter.scopeRoleAllowlistSet(
                ParentType.client, CLIENT_UUID, client, REALM_ID).serialize();

        byte[] expected = new ScopeRoleAllowlistSetUnit(REALM_ID, ParentType.client, CLIENT_UUID,
                Arrays.asList("r-aaa", "r-zzz")).serialize();
        assertArrayEquals(expected, built,
                "scope_role_allowlist_set must sort the allowlisted role ids");
    }

    @Test
    void realmDefaultGroupsSet_sortsGroupIds() {
        RealmModel realm = mock(RealmModel.class);
        org.keycloak.models.GroupModel gB = mock(org.keycloak.models.GroupModel.class);
        org.keycloak.models.GroupModel gA = mock(org.keycloak.models.GroupModel.class);
        when(gB.getId()).thenReturn("g-bbb");
        when(gA.getId()).thenReturn("g-aaa");
        when(realm.getDefaultGroupsStream()).thenReturn(Stream.of(gB, gA));

        byte[] built = RealmAttestationExporter.realmDefaultGroupsSetStatic(realm, REALM_ID).serialize();

        byte[] expected = new RealmDefaultGroupsSetUnit(REALM_ID,
                Arrays.asList("g-aaa", "g-bbb")).serialize();
        assertArrayEquals(expected, built,
                "realm_default_groups_set must sort the group ids");
    }

    @Test
    void organizationDomainSet_sortsByName() {
        OrganizationModel org = mock(OrganizationModel.class);
        when(org.getId()).thenReturn(ORG_ID);
        OrganizationDomainModel dZ = mock(OrganizationDomainModel.class);
        OrganizationDomainModel dA = mock(OrganizationDomainModel.class);
        when(dZ.getName()).thenReturn("zeta.example");
        when(dZ.isVerified()).thenReturn(true);
        when(dA.getName()).thenReturn("alpha.example");
        when(dA.isVerified()).thenReturn(false);
        // getDomains() returns a Stream (unsorted: zeta before alpha).
        when(org.getDomains()).thenReturn(Stream.of(dZ, dA));

        byte[] built = RealmAttestationExporter.organizationDomainSet(org, REALM_ID).serialize();

        byte[] expected = new OrganizationDomainSetUnit(REALM_ID, ORG_ID, Arrays.asList(
                new OrgDomain("alpha.example", false),
                new OrgDomain("zeta.example", true))).serialize();
        assertArrayEquals(expected, built,
                "organization_domain_set must sort the domains by name");
    }
}
