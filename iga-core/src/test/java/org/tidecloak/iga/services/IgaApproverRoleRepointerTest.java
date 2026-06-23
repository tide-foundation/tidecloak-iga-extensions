package org.tidecloak.iga.services;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import static org.mockito.ArgumentMatchers.any;
import org.keycloak.models.ClientModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.IdentityProviderStorageProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OrganizationModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.RoleProvider;
import org.keycloak.organization.OrganizationProvider;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

/**
 * Unit tests for {@link IgaApproverRoleRepointer}.
 *
 * <p>Drives the switch-to-Tide approver-role repoint against MOCKED KC models:
 * verifies every config surface (realm / realm-role / client / client-role /
 * group / idp / organization) is repointed to {@code tide-realm-admin}, that
 * surfaces without an approver role or already pointing at the canonical role
 * are left untouched (idempotency), and that a Tideless realm is not corrupted.</p>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class IgaApproverRoleRepointerTest {

    private static final String ATTR = IgaApproverRoleRepointer.ATTR_APPROVER_ROLE;
    private static final String TIDE = IgaApproverRoleRepointer.TIDE_REALM_ADMIN;

    private KeycloakSession session;
    private RealmModel realm;
    private RoleProvider roleProvider;
    private IdentityProviderStorageProvider idpProvider;
    private OrganizationProvider orgProvider;

    @BeforeEach
    void setup() {
        session = mock(KeycloakSession.class);
        realm = mock(RealmModel.class);
        roleProvider = mock(RoleProvider.class);
        idpProvider = mock(IdentityProviderStorageProvider.class);
        orgProvider = mock(OrganizationProvider.class);

        lenient().when(realm.getName()).thenReturn("myrealm");
        lenient().when(session.roles()).thenReturn(roleProvider);
        lenient().when(session.identityProviders()).thenReturn(idpProvider);
        lenient().when(session.getProvider(OrganizationProvider.class)).thenReturn(orgProvider);

        // default: empty everything
        lenient().when(realm.getAttribute(ATTR)).thenReturn(null);
        lenient().when(roleProvider.getRealmRolesStream(realm)).thenReturn(Stream.empty());
        lenient().when(realm.getClientsStream()).thenReturn(Stream.empty());
        lenient().when(realm.getGroupsStream()).thenReturn(Stream.empty());
        lenient().when(realm.getIdentityProvidersStream()).thenReturn(Stream.empty());
        lenient().when(orgProvider.getAllStream()).thenReturn(Stream.empty());
    }

    // ── needsRepoint pure predicate ──────────────────────────────────────────

    @Test
    void needsRepoint_predicate() {
        assertFalse(IgaApproverRoleRepointer.needsRepoint(null));
        assertFalse(IgaApproverRoleRepointer.needsRepoint(""));
        assertFalse(IgaApproverRoleRepointer.needsRepoint("   "));
        assertFalse(IgaApproverRoleRepointer.needsRepoint(TIDE));
        assertFalse(IgaApproverRoleRepointer.needsRepoint("  tide-realm-admin  "));
        assertTrue(IgaApproverRoleRepointer.needsRepoint("custom-approver"));
        assertTrue(IgaApproverRoleRepointer.needsRepoint("iga-approver-role"));
    }

    // ── realm-level surface ──────────────────────────────────────────────────

    @Test
    void realmAttribute_repointed() {
        when(realm.getAttribute(ATTR)).thenReturn("custom-approver");

        IgaApproverRoleRepointer.Result r =
                IgaApproverRoleRepointer.repointToTideRealmAdmin(session, realm);

        verify(realm).setAttribute(eq(ATTR), eq(TIDE));
        assertEquals(1, r.realm);
        assertEquals(1, r.total());
    }

    @Test
    void realmAttribute_alreadyTide_noop() {
        when(realm.getAttribute(ATTR)).thenReturn(TIDE);

        IgaApproverRoleRepointer.Result r =
                IgaApproverRoleRepointer.repointToTideRealmAdmin(session, realm);

        verify(realm, never()).setAttribute(eq(ATTR), eq(TIDE));
        assertEquals(0, r.total());
    }

    @Test
    void realmAttribute_unset_noop_tidelessNotCorrupted() {
        when(realm.getAttribute(ATTR)).thenReturn(null);

        IgaApproverRoleRepointer.Result r =
                IgaApproverRoleRepointer.repointToTideRealmAdmin(session, realm);

        verify(realm, never()).setAttribute(eq(ATTR), eq(TIDE));
        assertEquals(0, r.total());
    }

    // ── realm roles + client roles ───────────────────────────────────────────

    @Test
    void realmRole_repointed_onlyWhenSet() {
        RoleModel withRole = mock(RoleModel.class);
        when(withRole.getFirstAttribute(ATTR)).thenReturn("custom-approver");
        RoleModel noRole = mock(RoleModel.class);
        when(noRole.getFirstAttribute(ATTR)).thenReturn(null);
        RoleModel already = mock(RoleModel.class);
        when(already.getFirstAttribute(ATTR)).thenReturn(TIDE);

        when(roleProvider.getRealmRolesStream(realm)).thenReturn(Stream.of(withRole, noRole, already));

        IgaApproverRoleRepointer.Result r =
                IgaApproverRoleRepointer.repointToTideRealmAdmin(session, realm);

        verify(withRole).setSingleAttribute(eq(ATTR), eq(TIDE));
        verify(noRole, never()).setSingleAttribute(eq(ATTR), eq(TIDE));
        verify(already, never()).setSingleAttribute(eq(ATTR), eq(TIDE));
        assertEquals(1, r.realmRoles);
    }

    @Test
    void client_and_clientRole_repointed() {
        ClientModel client = mock(ClientModel.class);
        when(client.getClientId()).thenReturn("my-client");
        when(client.getAttribute(ATTR)).thenReturn("custom-approver");

        RoleModel clientRole = mock(RoleModel.class);
        when(clientRole.getFirstAttribute(ATTR)).thenReturn("another-custom");
        when(client.getRolesStream()).thenReturn(Stream.of(clientRole));

        when(realm.getClientsStream()).thenReturn(Stream.of(client));

        IgaApproverRoleRepointer.Result r =
                IgaApproverRoleRepointer.repointToTideRealmAdmin(session, realm);

        verify(client).setAttribute(eq(ATTR), eq(TIDE));
        verify(clientRole).setSingleAttribute(eq(ATTR), eq(TIDE));
        assertEquals(1, r.clients);
        assertEquals(1, r.clientRoles);
    }

    // ── groups ───────────────────────────────────────────────────────────────

    @Test
    void group_repointed() {
        GroupModel g = mock(GroupModel.class);
        when(g.getFirstAttribute(ATTR)).thenReturn("custom-approver");
        when(realm.getGroupsStream()).thenReturn(Stream.of(g));

        IgaApproverRoleRepointer.Result r =
                IgaApproverRoleRepointer.repointToTideRealmAdmin(session, realm);

        verify(g).setSingleAttribute(eq(ATTR), eq(TIDE));
        assertEquals(1, r.groups);
    }

    // ── identity providers (config map, persisted via update) ────────────────

    @Test
    void idp_repointed_andPersisted() {
        IdentityProviderModel idp = mock(IdentityProviderModel.class);
        when(idp.getAlias()).thenReturn("oidc-x");
        Map<String, String> config = new HashMap<>();
        config.put(ATTR, "custom-approver");
        config.put("other", "keep-me");
        when(idp.getConfig()).thenReturn(config);
        when(realm.getIdentityProvidersStream()).thenReturn(Stream.of(idp));

        IgaApproverRoleRepointer.Result r =
                IgaApproverRoleRepointer.repointToTideRealmAdmin(session, realm);

        assertEquals(TIDE, config.get(ATTR));
        assertEquals("keep-me", config.get("other"));
        verify(idpProvider).update(idp);
        assertEquals(1, r.idps);
    }

    @Test
    void idp_alreadyTide_notUpdated() {
        IdentityProviderModel idp = mock(IdentityProviderModel.class);
        when(idp.getAlias()).thenReturn("oidc-x");
        Map<String, String> config = new HashMap<>();
        config.put(ATTR, TIDE);
        when(idp.getConfig()).thenReturn(config);
        when(realm.getIdentityProvidersStream()).thenReturn(Stream.of(idp));

        IgaApproverRoleRepointer.Result r =
                IgaApproverRoleRepointer.repointToTideRealmAdmin(session, realm);

        verify(idpProvider, never()).update(idp);
        assertEquals(0, r.idps);
    }

    // ── organizations (full attribute-map read-modify-write) ─────────────────

    @Test
    void organization_repointed_preservesOtherAttrs() {
        OrganizationModel org = mock(OrganizationModel.class);
        when(org.getName()).thenReturn("acme");
        Map<String, List<String>> attrs = new LinkedHashMap<>();
        attrs.put(ATTR, List.of("custom-approver"));
        attrs.put("iga.threshold", List.of("3"));
        when(org.getAttributes()).thenReturn(attrs);
        when(orgProvider.getAllStream()).thenReturn(Stream.of(org));

        IgaApproverRoleRepointer.Result r =
                IgaApproverRoleRepointer.repointToTideRealmAdmin(session, realm);

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, List<String>>> cap =
                ArgumentCaptor.forClass(Map.class);
        verify(org).setAttributes(cap.capture());
        Map<String, List<String>> written = cap.getValue();
        assertEquals(List.of(TIDE), written.get(ATTR));
        assertEquals(List.of("3"), written.get("iga.threshold"));
        assertEquals(1, r.organizations);
    }

    @Test
    void organization_alreadyTide_noop() {
        OrganizationModel org = mock(OrganizationModel.class);
        when(org.getName()).thenReturn("acme");
        Map<String, List<String>> attrs = new LinkedHashMap<>();
        attrs.put(ATTR, List.of(TIDE));
        when(org.getAttributes()).thenReturn(attrs);
        when(orgProvider.getAllStream()).thenReturn(Stream.of(org));

        IgaApproverRoleRepointer.Result r =
                IgaApproverRoleRepointer.repointToTideRealmAdmin(session, realm);

        verify(org, never()).setAttributes(any());
        assertEquals(0, r.organizations);
    }

    // ── all surfaces at once + idempotent re-run ─────────────────────────────

    @Test
    void allSurfaces_repointed_thenSecondRunIsNoop() {
        when(realm.getAttribute(ATTR)).thenReturn("custom-approver");

        RoleModel realmRole = mock(RoleModel.class);
        when(realmRole.getFirstAttribute(ATTR)).thenReturn("custom-approver");
        when(roleProvider.getRealmRolesStream(realm)).thenReturn(Stream.of(realmRole));

        ClientModel client = mock(ClientModel.class);
        when(client.getClientId()).thenReturn("c");
        when(client.getAttribute(ATTR)).thenReturn("custom-approver");
        RoleModel clientRole = mock(RoleModel.class);
        when(clientRole.getFirstAttribute(ATTR)).thenReturn("custom-approver");
        when(client.getRolesStream()).thenReturn(Stream.of(clientRole));
        when(realm.getClientsStream()).thenReturn(Stream.of(client));

        GroupModel group = mock(GroupModel.class);
        when(group.getFirstAttribute(ATTR)).thenReturn("custom-approver");
        when(realm.getGroupsStream()).thenReturn(Stream.of(group));

        IdentityProviderModel idp = mock(IdentityProviderModel.class);
        Map<String, String> idpConfig = new HashMap<>();
        idpConfig.put(ATTR, "custom-approver");
        when(idp.getConfig()).thenReturn(idpConfig);
        when(realm.getIdentityProvidersStream()).thenReturn(Stream.of(idp));

        OrganizationModel org = mock(OrganizationModel.class);
        Map<String, List<String>> orgAttrs = new LinkedHashMap<>();
        orgAttrs.put(ATTR, List.of("custom-approver"));
        when(org.getAttributes()).thenReturn(orgAttrs);
        when(orgProvider.getAllStream()).thenReturn(Stream.of(org));

        IgaApproverRoleRepointer.Result r1 =
                IgaApproverRoleRepointer.repointToTideRealmAdmin(session, realm);

        assertEquals(1, r1.realm);
        assertEquals(1, r1.realmRoles);
        assertEquals(1, r1.clients);
        assertEquals(1, r1.clientRoles);
        assertEquals(1, r1.groups);
        assertEquals(1, r1.idps);
        assertEquals(1, r1.organizations);
        assertEquals(7, r1.total());

        // Second run: every surface now reports tide-realm-admin → no rewrites.
        when(realm.getAttribute(ATTR)).thenReturn(TIDE);
        when(realmRole.getFirstAttribute(ATTR)).thenReturn(TIDE);
        when(client.getAttribute(ATTR)).thenReturn(TIDE);
        when(clientRole.getFirstAttribute(ATTR)).thenReturn(TIDE);
        when(group.getFirstAttribute(ATTR)).thenReturn(TIDE);
        // idp config map was mutated in-place to TIDE by run 1; the org receives
        // a brand-new map via setAttributes, so reflect the post-run-1 state on
        // the getAttributes() stub explicitly.
        orgAttrs.put(ATTR, List.of(TIDE));
        when(roleProvider.getRealmRolesStream(realm)).thenReturn(Stream.of(realmRole));
        when(realm.getClientsStream()).thenReturn(Stream.of(client));
        when(client.getRolesStream()).thenReturn(Stream.of(clientRole));
        when(realm.getGroupsStream()).thenReturn(Stream.of(group));
        when(realm.getIdentityProvidersStream()).thenReturn(Stream.of(idp));
        when(orgProvider.getAllStream()).thenReturn(Stream.of(org));

        IgaApproverRoleRepointer.Result r2 =
                IgaApproverRoleRepointer.repointToTideRealmAdmin(session, realm);

        assertEquals(0, r2.total());
    }

    @Test
    void noOrgProvider_doesNotThrow() {
        when(session.getProvider(OrganizationProvider.class)).thenReturn(null);
        when(realm.getAttribute(ATTR)).thenReturn("custom-approver");

        IgaApproverRoleRepointer.Result r =
                IgaApproverRoleRepointer.repointToTideRealmAdmin(session, realm);

        assertEquals(1, r.realm);
        assertEquals(0, r.organizations);
    }
}
