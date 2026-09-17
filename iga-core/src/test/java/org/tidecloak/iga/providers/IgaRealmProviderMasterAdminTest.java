package org.tidecloak.iga.providers;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.AdminRoles;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.representations.AccessToken;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

/**
 * Who counts as a master super admin for the realm-delete bypass. The fixture is a
 * master realm user holding the admin role; each "false" test breaks one condition.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class IgaRealmProviderMasterAdminTest {

    @Mock KeycloakSession session;
    @Mock KeycloakContext ctx;
    @Mock UserSessionModel userSession;
    @Mock RealmModel master;
    @Mock UserModel user;
    @Mock RoleModel adminRole;

    @BeforeEach
    void masterSuperAdmin() {
        when(session.getContext()).thenReturn(ctx);
        when(ctx.getBearerToken()).thenReturn(new AccessToken());
        when(ctx.getUserSession()).thenReturn(userSession);
        when(userSession.getRealm()).thenReturn(master);
        when(userSession.getUser()).thenReturn(user);
        when(master.getName()).thenReturn("master");
        when(master.getRole(AdminRoles.ADMIN)).thenReturn(adminRole);
        when(user.isEnabled()).thenReturn(true);
        when(user.hasRole(adminRole)).thenReturn(true);
    }

    @Test
    void masterAdmin_true() {
        assertTrue(IgaRealmProvider.isMasterAdmin(session));
    }

    @Test
    void tenantRealmSession_false() {
        when(master.getName()).thenReturn("tenant");
        assertFalse(IgaRealmProvider.isMasterAdmin(session));
    }

    @Test
    void noUserSession_false() {
        when(ctx.getUserSession()).thenReturn(null);
        assertFalse(IgaRealmProvider.isMasterAdmin(session));
    }

    @Test
    void noBearerToken_false() {
        when(ctx.getBearerToken()).thenReturn(null);
        assertFalse(IgaRealmProvider.isMasterAdmin(session));
    }

    @Test
    void masterUserWithoutAdminRole_false() {
        when(user.hasRole(adminRole)).thenReturn(false);
        assertFalse(IgaRealmProvider.isMasterAdmin(session));
    }

    @Test
    void disabledUser_false() {
        when(user.isEnabled()).thenReturn(false);
        assertFalse(IgaRealmProvider.isMasterAdmin(session));
    }

    @Test
    void exception_false() {
        when(userSession.getUser()).thenThrow(new IllegalStateException("boom"));
        assertFalse(IgaRealmProvider.isMasterAdmin(session));
    }
}
