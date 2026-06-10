package org.tidecloak.iga.attestors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.RoleProvider;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.tidecloak.iga.attestors.IgaScopeResolver.ResolvedScope;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.services.IgaFirstAdminAutoCommit;

/**
 * Governance classification + scope-resolution coverage for the five whole-entity
 * DELETE_* action types ({@code DELETE_USER / DELETE_ROLE / DELETE_GROUP /
 * DELETE_CLIENT / DELETE_CLIENT_SCOPE}) introduced by the "govern whole-entity
 * deletes" feature.
 *
 * <p>These actions are NON-PRODUCER (no attestation unit → {@code combineFinal}
 * stub-signs) and are NOT firstAdmin baseline-config auto-commit (they stay MANUAL,
 * incl. under firstAdmin). The scope resolver resolves the TARGET entity's own
 * scope for DELETE_ROLE / DELETE_CLIENT (per-target approver/threshold), and the
 * realm default (empty scope) for DELETE_USER / DELETE_GROUP / DELETE_CLIENT_SCOPE.
 *
 * <p>The capture overrides ({@code IgaUserProvider.removeUser},
 * {@code IgaRealmProvider.removeRole/removeGroup/removeClient/removeClientScope})
 * and the replay handlers ({@code IgaReplayDispatcher.replayDelete*}) are exercised
 * end-to-end by the live stack (a JpaUserProvider/JpaRealmProvider subclass cannot
 * be instantiated without a real EntityManagerFactory); their contract is asserted
 * here at the classification + resolution layer the rest of the pipeline depends on.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class DeleteEntityGovernanceTest {

    private static final String REALM_ID = "realm-uuid";

    @Mock private KeycloakSession session;
    @Mock private RealmModel realm;

    private static IgaChangeRequestEntity cr(String actionType, String rowsJson) {
        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setId("cr-" + actionType);
        cr.setRealmId(REALM_ID);
        cr.setEntityType("X");
        cr.setActionType(actionType);
        cr.setRowsJson(rowsJson);
        cr.setStatus("PENDING");
        return cr;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Non-producer classification — DELETE_* have NO producer attestation unit,
    // so they stub-sign via combineFinal (never reach the edge-set unit builder).
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    void deleteActions_areNotProducerEnvelopeSigned() {
        assertFalse(TideAttestor.isProducerEnvelopeSignedAction("DELETE_USER"));
        assertFalse(TideAttestor.isProducerEnvelopeSignedAction("DELETE_ROLE"));
        assertFalse(TideAttestor.isProducerEnvelopeSignedAction("DELETE_GROUP"));
        assertFalse(TideAttestor.isProducerEnvelopeSignedAction("DELETE_CLIENT"));
        assertFalse(TideAttestor.isProducerEnvelopeSignedAction("DELETE_CLIENT_SCOPE"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NOT firstAdmin baseline-config auto-commit — deletes stay MANUAL even for
    // the firstAdmin (defaults-only auto-commit is for realm config, not deletes).
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    void deleteActions_areNotBaselineAutoCommit() {
        assertFalse(IgaFirstAdminAutoCommit.isBaselineConfigActionType("DELETE_USER"));
        assertFalse(IgaFirstAdminAutoCommit.isBaselineConfigActionType("DELETE_ROLE"));
        assertFalse(IgaFirstAdminAutoCommit.isBaselineConfigActionType("DELETE_GROUP"));
        assertFalse(IgaFirstAdminAutoCommit.isBaselineConfigActionType("DELETE_CLIENT"));
        assertFalse(IgaFirstAdminAutoCommit.isBaselineConfigActionType("DELETE_CLIENT_SCOPE"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Scope resolution — per-target for DELETE_ROLE / DELETE_CLIENT.
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    void deleteRole_resolvesTargetRoleScope() {
        RoleProvider roleProvider = mock(RoleProvider.class);
        when(session.roles()).thenReturn(roleProvider);
        RoleModel role = mock(RoleModel.class);
        when(roleProvider.getRoleById(realm, "role-1")).thenReturn(role);
        // The target role carries its OWN iga.approverRole + iga.threshold.
        when(role.getFirstAttribute(IgaScopeResolver.ATTR_APPROVER_ROLE)).thenReturn("role-approver");
        when(role.getFirstAttribute(IgaScopeResolver.ATTR_THRESHOLD)).thenReturn("3");

        ResolvedScope scope = IgaScopeResolver.resolve(session, realm,
                cr("DELETE_ROLE", "[{\"ROLE_ID\":\"role-1\",\"ROLE_NAME\":\"r\"}]"));

        assertTrue(scope.requiredApproverRoles.contains("role-approver"),
                "deleting a role that carries iga.approverRole must require THAT approver");
        // realm default not consulted because the target supplies the threshold.
        assertEquals(3, IgaScopeResolver.resolveThreshold(realm, scope));
    }

    @Test
    void deleteClient_resolvesTargetClientScope() {
        ClientProvider clientProvider = mock(ClientProvider.class);
        when(session.clients()).thenReturn(clientProvider);
        ClientModel client = mock(ClientModel.class);
        // The capture row keys the client by its UUID (CLIENT_UUID); the resolver
        // walks CLIENT_UUID via getClientById(realm, uuid).
        when(clientProvider.getClientById(realm, "client-uuid")).thenReturn(client);
        when(client.getAttribute(IgaScopeResolver.ATTR_APPROVER_ROLE)).thenReturn("client-approver");
        when(client.getAttribute(IgaScopeResolver.ATTR_THRESHOLD)).thenReturn("2");

        ResolvedScope scope = IgaScopeResolver.resolve(session, realm,
                cr("DELETE_CLIENT", "[{\"CLIENT_UUID\":\"client-uuid\",\"CLIENT_ID\":\"acme\"}]"));

        assertTrue(scope.requiredApproverRoles.contains("client-approver"),
                "deleting a client that carries iga.approverRole must require THAT approver");
        assertEquals(2, IgaScopeResolver.resolveThreshold(realm, scope));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Scope resolution — realm default (empty scope) for DELETE_USER /
    // DELETE_GROUP / DELETE_CLIENT_SCOPE.
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    void deleteUser_groupAndClientScope_yieldRealmDefaultScope() {
        // No per-target collectors are walked → empty scope → realm-default
        // threshold/approver. The realm declares iga.threshold=4.
        lenient().when(realm.getAttribute(IgaScopeResolver.ATTR_THRESHOLD)).thenReturn("4");

        for (String action : List.of("DELETE_USER", "DELETE_GROUP", "DELETE_CLIENT_SCOPE")) {
            String row = switch (action) {
                case "DELETE_USER" -> "[{\"USER_ID\":\"u1\"}]";
                case "DELETE_GROUP" -> "[{\"GROUP_ID\":\"g1\"}]";
                default -> "[{\"CLIENT_SCOPE_ID\":\"cs1\",\"ID\":\"cs1\"}]";
            };
            ResolvedScope scope = IgaScopeResolver.resolve(session, realm, cr(action, row));
            assertTrue(scope.requiredApproverRoles.isEmpty(),
                    action + " must yield an empty approver-role set (realm default)");
            assertTrue(scope.thresholds.isEmpty(),
                    action + " must contribute no per-scope threshold");
            // Falls back to the realm default iga.threshold.
            assertEquals(4, IgaScopeResolver.resolveThreshold(realm, scope),
                    action + " must use the realm-default threshold");
        }
    }
}
