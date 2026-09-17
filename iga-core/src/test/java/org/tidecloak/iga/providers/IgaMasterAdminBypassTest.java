package org.tidecloak.iga.providers;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AdminRoles;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ImpersonationSessionNote;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Pins who may delete an IGA-on realm with no change request. The fixture is a
 * master super admin sending DELETE for the target realm; each "stays governed"
 * test breaks exactly one condition.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class IgaMasterAdminBypassTest {

    private static final String TARGET_ID = "11111111-1111-1111-1111-111111111111";

    @Mock KeycloakSession session;
    @Mock KeycloakContext ctx;
    @Mock UserSessionModel userSession;
    @Mock RealmModel master;
    @Mock RealmModel target;
    @Mock RealmModel contextRealm;
    @Mock UserModel user;
    @Mock RoleModel adminRole;
    @Mock ClientModel client;
    @Mock HttpRequest request;

    @BeforeEach
    void masterSuperAdminDeletingTarget() {
        IgaMasterAdminBypass.setEnabled(true);
        when(session.getContext()).thenReturn(ctx);
        when(ctx.getBearerToken()).thenReturn(new AccessToken());
        when(ctx.getUserSession()).thenReturn(userSession);
        when(ctx.getClient()).thenReturn(client);
        when(ctx.getHttpRequest()).thenReturn(request);
        when(ctx.getRealm()).thenReturn(contextRealm);
        when(request.getHttpMethod()).thenReturn("DELETE");
        when(contextRealm.getId()).thenReturn(TARGET_ID);
        when(target.getId()).thenReturn(TARGET_ID);
        when(userSession.getRealm()).thenReturn(master);
        when(userSession.getUser()).thenReturn(user);
        when(master.getName()).thenReturn("master");
        when(master.getRole(AdminRoles.ADMIN)).thenReturn(adminRole);
        when(user.isEnabled()).thenReturn(true);
        when(user.hasRole(adminRole)).thenReturn(true);
        when(user.getId()).thenReturn("admin-user-id");
        when(user.getUsername()).thenReturn("admin");
        when(client.isFullScopeAllowed()).thenReturn(true);
        when(client.getClientId()).thenReturn("admin-cli");
    }

    @AfterEach
    void resetFlag() {
        IgaMasterAdminBypass.setEnabled(true);
    }

    private boolean allowed() {
        return IgaMasterAdminBypass.allowsRealmDelete(session, target);
    }

    // ---- bypass applies ----

    @Test
    void masterSuperAdmin_allowed() {
        assertTrue(allowed());
        IgaMasterAdminBypass.Caller caller = IgaMasterAdminBypass.resolveCaller(session, target);
        assertNotNull(caller);
        assertEquals("admin-user-id", caller.userId());
        assertEquals("admin", caller.username());
        assertEquals("admin-cli", caller.clientId());
        assertFalse(caller.temporaryAdmin());
        assertFalse(caller.serviceAccount());
    }

    @Test
    void serviceAccountWithAdmin_allowed() {
        when(user.getServiceAccountClientLink()).thenReturn("some-client-uuid");
        IgaMasterAdminBypass.Caller caller = IgaMasterAdminBypass.resolveCaller(session, target);
        assertNotNull(caller);
        assertTrue(caller.serviceAccount());
    }

    @Test
    void temporaryBootstrapAdmin_allowedAndFlagged() {
        when(user.getFirstAttribute(UserModel.IS_TEMP_ADMIN_ATTR_NAME)).thenReturn("true");
        IgaMasterAdminBypass.Caller caller = IgaMasterAdminBypass.resolveCaller(session, target);
        assertNotNull(caller);
        assertTrue(caller.temporaryAdmin());
    }

    @Test
    void clientWithAdminRoleInScope_allowed() {
        when(client.isFullScopeAllowed()).thenReturn(false);
        when(client.hasScope(adminRole)).thenReturn(true);
        assertTrue(allowed());
    }

    // ---- stays governed ----

    @Test
    void noBearerToken_governed() {
        when(ctx.getBearerToken()).thenReturn(null);
        assertFalse(allowed());
    }

    @Test
    void noUserSession_governed() {
        when(ctx.getUserSession()).thenReturn(null);
        assertFalse(allowed());
    }

    @Test
    void tenantRealmSession_governed() {
        when(master.getName()).thenReturn("tenant");
        assertFalse(allowed());
    }

    @Test
    void masterUserWithoutAdminRole_governed() {
        when(user.hasRole(adminRole)).thenReturn(false);
        assertFalse(allowed());
    }

    @Test
    void onlyTenantManageRealmClientRole_governed() {
        RoleModel manageRealm = mock(RoleModel.class);
        when(user.hasRole(manageRealm)).thenReturn(true);
        when(user.hasRole(adminRole)).thenReturn(false);
        assertFalse(allowed());
    }

    @Test
    void adminRoleMissingFromMaster_governed() {
        when(master.getRole(AdminRoles.ADMIN)).thenReturn(null);
        assertFalse(allowed());
    }

    @Test
    void disabledUser_governed() {
        when(user.isEnabled()).thenReturn(false);
        assertFalse(allowed());
    }

    @Test
    void impersonatedSession_governed() {
        when(userSession.getNote(ImpersonationSessionNote.IMPERSONATOR_ID.toString()))
                .thenReturn("impersonator-id");
        assertFalse(allowed());
    }

    @Test
    void clientWithoutAdminScope_governed() {
        when(client.isFullScopeAllowed()).thenReturn(false);
        when(client.hasScope(adminRole)).thenReturn(false);
        assertFalse(allowed());
    }

    @Test
    void noClient_governed() {
        when(ctx.getClient()).thenReturn(null);
        assertFalse(allowed());
    }

    @Test
    void nonDeleteMethod_governed() {
        when(request.getHttpMethod()).thenReturn("PUT");
        assertFalse(allowed());
    }

    @Test
    void contextRealmMismatch_governed() {
        when(contextRealm.getId()).thenReturn("some-other-realm-id");
        assertFalse(allowed());
    }

    @Test
    void flagOff_governed() {
        IgaMasterAdminBypass.setEnabled(false);
        assertFalse(allowed());
    }

    @Test
    void exception_governed() {
        when(userSession.getUser()).thenThrow(new IllegalStateException("boom"));
        assertFalse(allowed());
        assertNull(IgaMasterAdminBypass.resolveCaller(session, target));
    }

    // ---- replay flag handling ----

    @Test
    void replayFlag_removedAfterSuccess_whenAbsentBefore() {
        when(session.getAttribute("IGA_REPLAY_ACTIVE")).thenReturn(null);
        assertTrue(IgaMasterAdminBypass.runUnderReplayFlag(session, () -> true));
        verify(session).setAttribute("IGA_REPLAY_ACTIVE", "true");
        verify(session).removeAttribute("IGA_REPLAY_ACTIVE");
    }

    @Test
    void replayFlag_removedAfterException_whenAbsentBefore() {
        when(session.getAttribute("IGA_REPLAY_ACTIVE")).thenReturn(null);
        assertThrows(IllegalStateException.class, () ->
                IgaMasterAdminBypass.runUnderReplayFlag(session, () -> {
                    throw new IllegalStateException("delete failed");
                }));
        verify(session).removeAttribute("IGA_REPLAY_ACTIVE");
    }

    @Test
    void replayFlag_priorValueKept() {
        when(session.getAttribute("IGA_REPLAY_ACTIVE")).thenReturn("true");
        assertFalse(IgaMasterAdminBypass.runUnderReplayFlag(session, () -> false));
        verify(session, never()).removeAttribute("IGA_REPLAY_ACTIVE");
    }
}
