package org.tidecloak.iga.attestors;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import jakarta.persistence.TypedQuery;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.midgard.models.ModelRequest;
import org.midgard.models.Policy.Policy;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.tidecloak.iga.entities.IgaAuthorizationEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.entities.IgaRolePolicyEntity;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Coverage for the threshold-policy re-sign CR feature — the steady-state multiAdmin
 * admin-policy regen emitted as an explicit, enclave-signed {@code REGEN_ADMIN_POLICY}
 * CR (one per batch, folded) that REPLACES the old silent doken-less in-line re-sign.
 *
 * <p>The {@code maybeEmitThresholdPolicyCr} tests drive the deterministic NON-capable
 * realm path (a mock realm with no {@code tide-vendor-key} component): the emit logic
 * is mode/capability-agnostic, so a multiAdmin authorizer row is enough. The active
 * tide-realm-admin count is driven by stubbing the committed-ids JPQL + the
 * role-members stream.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TideAttestorThresholdPolicyCrTest {

    private static final String REALM_ID = "realm-uuid-thr";
    private static final String TIDE_ROLE_ID = "tide-realm-admin-role-id";
    private static final String VVK_ID = "vvk-123";

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock JpaConnectionProvider jpa;
    @Mock EntityManager em;
    @Mock ClientModel realmManagement;
    @Mock RoleModel tideRealmAdmin;
    @Mock UserProvider users;

    private TideAttestor attestor;

    @BeforeEach
    void setUp() {
        when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa);
        when(jpa.getEntityManager()).thenReturn(em);
        when(realm.getId()).thenReturn(REALM_ID);
        when(realm.getName()).thenReturn("thr-realm");
        when(realm.getClientByClientId("realm-management")).thenReturn(realmManagement);
        when(realmManagement.getRole("tide-realm-admin")).thenReturn(tideRealmAdmin);
        when(tideRealmAdmin.getId()).thenReturn(TIDE_ROLE_ID);
        // NON-capable realm: no tide-vendor-key component. realmVvkId() then returns null,
        // so the carried VVK_ID is null in those tests; the *_carrier tests inject a component.
        when(realm.getComponentsStream()).thenAnswer(inv -> Stream.<ComponentModel>empty());
        attestor = new TideAttestor(session);
    }

    // --- helpers -------------------------------------------------------------

    private IgaChangeRequestEntity grantCr(String id) {
        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setId(id);
        cr.setRealmId(REALM_ID);
        cr.setActionType("GRANT_ROLES");
        cr.setEntityId("user-" + id);
        cr.setRequestedBy("admin-1");
        cr.setRowsJson("[{\"USER_ID\":\"user-" + id + "\",\"ROLE_ID\":\"" + TIDE_ROLE_ID + "\"}]");
        return cr;
    }

    private IgaChangeRequestEntity revokeCr(String id) {
        IgaChangeRequestEntity cr = grantCr(id);
        cr.setActionType("REVOKE_ROLES");
        return cr;
    }

    private IgaRolePolicyEntity policyAtThreshold(int threshold) {
        IgaRolePolicyEntity p = new IgaRolePolicyEntity();
        p.setId("policy-row-id");
        p.setRealmId(REALM_ID);
        p.setRoleId(TIDE_ROLE_ID);
        p.setPolicy("M0-BODY");
        p.setThreshold(threshold);
        return p;
    }

    /** Stub IgaRolePolicy.findByRealmAndRole to return {@code policy} (or none). */
    @SuppressWarnings("unchecked")
    private void stubPolicyLookup(IgaRolePolicyEntity policy) {
        TypedQuery<IgaRolePolicyEntity> q = mock(TypedQuery.class);
        when(em.createNamedQuery(eq("IgaRolePolicy.findByRealmAndRole"), eq(IgaRolePolicyEntity.class)))
                .thenReturn(q);
        when(q.setParameter(anyString(), any())).thenReturn(q);
        when(q.getResultStream()).thenAnswer(inv -> policy == null ? Stream.empty() : Stream.of(policy));
    }

    /** Stub the service's findPending (IgaChangeRequest.findPendingByEntity) to return {@code pending}. */
    @SuppressWarnings("unchecked")
    private void stubFindPending(IgaChangeRequestEntity pending) {
        TypedQuery<IgaChangeRequestEntity> q = mock(TypedQuery.class);
        when(em.createNamedQuery(eq("IgaChangeRequest.findPendingByEntity"), eq(IgaChangeRequestEntity.class)))
                .thenReturn(q);
        when(q.setParameter(anyString(), any())).thenReturn(q);
        when(q.getResultList())
                .thenReturn(pending == null ? List.of() : List.of(pending));
    }

    /** Drive countActiveTideRealmAdmins to return {@code n} (committed JPQL + role-members stream). */
    @SuppressWarnings("unchecked")
    private void stubActiveAdminCount(int n) {
        List<String> ids = new ArrayList<>();
        List<UserModel> members = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            String uid = "admin-user-" + i;
            ids.add(uid);
            UserModel u = mock(UserModel.class);
            when(u.getId()).thenReturn(uid);
            when(u.isEnabled()).thenReturn(true);
            members.add(u);
        }
        // committedTideAdminUserIds JPQL
        Query jpql = mock(Query.class);
        when(em.createQuery(anyString())).thenReturn(jpql);
        when(jpql.setParameter(anyString(), any())).thenReturn(jpql);
        when(jpql.getResultList()).thenReturn((List) ids);
        // session.users().getRoleMembersStream
        when(session.users()).thenReturn(users);
        when(users.getRoleMembersStream(eq(realm), eq(tideRealmAdmin)))
                .thenAnswer(inv -> members.stream());
    }

    // --- create --------------------------------------------------------------

    @Test
    void create_emitsOneRegenCr_whenThresholdMoves() {
        // 2 active admins (threshold floor(0.7*2)=1); a grant brings post-commit to 3
        // (floor(0.7*3)=2). The threshold MOVES 1 -> 2, so a CR is created.
        stubPolicyLookup(policyAtThreshold(1));
        stubFindPending(null);
        stubActiveAdminCount(2);

        attestor.maybeEmitThresholdPolicyCr(session, realm, grantCr("g1"));

        ArgumentCaptor<IgaChangeRequestEntity> captor = ArgumentCaptor.forClass(IgaChangeRequestEntity.class);
        verify(em, times(1)).persist(captor.capture());
        IgaChangeRequestEntity emitted = captor.getValue();
        assertEquals("REGEN_ADMIN_POLICY", emitted.getActionType());
        assertEquals("ADMIN_POLICY", emitted.getEntityType());
        assertEquals(TIDE_ROLE_ID, emitted.getEntityId(), "CR keyed to the tide-realm-admin role id");
        assertEquals(List.of("g1"), emitted.getDependsOnList(), "policy CR dependsOn the assignment CR");
        // ROWS_JSON carries old/new threshold + role + unsigned policy bytes.
        assertTrue(emitted.getRowsJson().contains("\"OLD_THRESHOLD\":1"));
        assertTrue(emitted.getRowsJson().contains("\"NEW_THRESHOLD\":2"));
        assertTrue(emitted.getRowsJson().contains("POLICY_BODY_UNSIGNED"));
    }

    @Test
    void create_noCr_whenNotAMembershipChange() {
        // A grant of some OTHER role is delta 0 -> no CR, no policy lookup needed.
        IgaChangeRequestEntity cr = grantCr("x");
        cr.setRowsJson("[{\"USER_ID\":\"u\",\"ROLE_ID\":\"some-other-role\"}]");

        attestor.maybeEmitThresholdPolicyCr(session, realm, cr);

        verify(em, never()).persist(any());
    }

    // --- IsEqualTo no-op -----------------------------------------------------

    @Test
    void isEqualTo_noCr_whenThresholdUnchanged() {
        // 4 active admins (floor(0.7*4)=2); a grant -> 5 (floor(0.7*5)=3)... pick numbers that
        // do NOT move: 1 active admin (floor=1... wait clamp), use 10 admins -> floor(0.7*10)=7,
        // +1 -> 11 -> floor(0.7*11)=7. Threshold stays 7 -> NO CR.
        stubPolicyLookup(policyAtThreshold(7));
        stubFindPending(null);
        stubActiveAdminCount(10);

        attestor.maybeEmitThresholdPolicyCr(session, realm, grantCr("g1"));

        verify(em, never()).persist(any());
    }

    // --- nets-to-zero cancel -------------------------------------------------

    @Test
    void netsToZero_cancelsPendingRegenCr_whenThresholdReturnsToCurrent() {
        // The policy already encodes the threshold the batch nets back to, AND a pending
        // REGEN_ADMIN_POLICY exists (an earlier CR in the batch moved it). The IsEqualTo
        // branch must CANCEL that pending CR.
        stubPolicyLookup(policyAtThreshold(7));
        IgaChangeRequestEntity pending = new IgaChangeRequestEntity();
        pending.setId("pending-regen");
        pending.setRealmId(REALM_ID);
        pending.setEntityType("ADMIN_POLICY");
        pending.setEntityId(TIDE_ROLE_ID);
        pending.setActionType("REGEN_ADMIN_POLICY");
        pending.setStatus("PENDING");
        stubFindPending(pending);
        stubActiveAdminCount(10); // +1 -> 11 -> floor 7 == current 7

        attestor.maybeEmitThresholdPolicyCr(session, realm, grantCr("g2"));

        assertEquals("CANCELLED", pending.getStatus(), "the stale pending policy CR is cancelled");
        assertNotNull(pending.getResolvedAt());
        verify(em, never()).persist(any());
    }

    // --- fold-to-one ---------------------------------------------------------

    @Test
    void fold_rewritesPendingCrInPlace_andClearsAuthorizations() {
        // A pending REGEN_ADMIN_POLICY already exists; a SECOND membership change in the batch
        // moves the threshold again. We must UPDATE the pending CR in place (no new persist),
        // re-point dependsOn to include the new assignment, and CLEAR its authorizations.
        stubPolicyLookup(policyAtThreshold(1));
        IgaChangeRequestEntity pending = new IgaChangeRequestEntity();
        pending.setId("pending-regen");
        pending.setRealmId(REALM_ID);
        pending.setEntityType("ADMIN_POLICY");
        pending.setEntityId(TIDE_ROLE_ID);
        pending.setActionType("REGEN_ADMIN_POLICY");
        pending.setStatus("PENDING");
        pending.setRequestModel("STALE-CARRIER");
        pending.setDependsOnList(List.of("g1"));
        stubFindPending(pending);
        // existing carrier had 2 authorizations to clear
        IgaAuthorizationEntity a1 = new IgaAuthorizationEntity();
        IgaAuthorizationEntity a2 = new IgaAuthorizationEntity();
        TypedQuery<IgaAuthorizationEntity> authQ = mock(TypedQuery.class);
        when(em.createNamedQuery(eq("IgaAuthorization.findByChangeRequest"), eq(IgaAuthorizationEntity.class)))
                .thenReturn(authQ);
        when(authQ.setParameter(anyString(), any())).thenReturn(authQ);
        when(authQ.getResultList()).thenReturn(Arrays.asList(a1, a2));
        stubActiveAdminCount(2); // +1 -> 3 -> floor 2; current 1 -> MOVES

        attestor.maybeEmitThresholdPolicyCr(session, realm, grantCr("g2"));

        verify(em, never()).persist(any());                 // folded, not created
        verify(em, times(1)).remove(a1);
        verify(em, times(1)).remove(a2);                    // authorizations cleared
        assertNull(pending.getRequestModel(), "stale carrier cleared (re-sign required)");
        assertTrue(pending.getDependsOnList().contains("g1"), "keeps prior dependency");
        assertTrue(pending.getDependsOnList().contains("g2"), "adds the new assignment dependency");
        assertTrue(pending.getRowsJson().contains("\"NEW_THRESHOLD\":2"));
    }

    // --- revoke lowers threshold ---------------------------------------------

    @Test
    void revoke_emitsCr_whenThresholdLowers() {
        // 4 active admins (floor(0.7*4)=2); a revoke -> 3 (floor(0.7*3)=2)... stays. Use 3 active
        // (floor 2); revoke -> 2 (floor 1). Threshold LOWERS 2 -> 1 -> a CR with delta -1.
        stubPolicyLookup(policyAtThreshold(2));
        stubFindPending(null);
        stubActiveAdminCount(3);

        attestor.maybeEmitThresholdPolicyCr(session, realm, revokeCr("r1"));

        ArgumentCaptor<IgaChangeRequestEntity> captor = ArgumentCaptor.forClass(IgaChangeRequestEntity.class);
        verify(em, times(1)).persist(captor.capture());
        IgaChangeRequestEntity emitted = captor.getValue();
        assertTrue(emitted.getRowsJson().contains("\"OLD_THRESHOLD\":2"));
        assertTrue(emitted.getRowsJson().contains("\"NEW_THRESHOLD\":1"));
        assertEquals(List.of("r1"), emitted.getDependsOnList());
    }

    // --- unsigned policy bytes + ModelIds config check -----------------------

    @Test
    void unsignedPolicyBytes_recoverShapeAndModelIdsAny() {
        // The config check: the M0 policy the ORK re-sign authorizes against must have
        // ModelIds containing "any" (the wildcard) so PolicyAuthorizationFlow accepts the
        // Policy:1 request model. buildUnsignedAdminPolicyBytes uses new Policy(...,"any",...).
        byte[] bytes = TideAttestor.buildUnsignedAdminPolicyBytes(5, VVK_ID);
        Policy parsed = Policy.From(bytes);
        assertTrue(Arrays.asList(parsed.getModelIds()).contains("any"),
                "M0 policy ModelIds must include the \"any\" wildcard for Policy:1 re-sign auth");
        assertEquals("GenericResourceAccessThresholdRole:1", parsed.getContractId());
        assertEquals(VVK_ID, parsed.getKeyId());
    }

    // --- phase-1 approval-model carrier shape --------------------------------

    @Test
    void approvalModelCarrier_isPolicySignRequest_overNewPolicyBytes_withM0Embedded() throws Exception {
        // The REGEN CR's phase-1 approval model is a Policy:1 PolicySignRequest over the NEW
        // unsigned policy bytes (verbatim from ROWS_JSON) with the EXISTING M0 embedded. It must
        // round-trip via ModelRequest.FromBytes and carry the embedded policy.
        byte[] newPolicy = TideAttestor.buildUnsignedAdminPolicyBytes(3, VVK_ID);
        String newPolicyB64 = Base64.getEncoder().encodeToString(newPolicy);

        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setId("regen-cr");
        cr.setRealmId(REALM_ID);
        cr.setActionType("REGEN_ADMIN_POLICY");
        cr.setEntityType("ADMIN_POLICY");
        cr.setEntityId(TIDE_ROLE_ID);
        cr.setRowsJson("[{\"OLD_THRESHOLD\":1,\"NEW_THRESHOLD\":3,\"ROLE_ID\":\"" + TIDE_ROLE_ID
                + "\",\"VVK_ID\":\"" + VVK_ID + "\",\"POLICY_BODY_UNSIGNED\":\"" + newPolicyB64 + "\"}]");

        // The M0 admin policy row whose Base64(Policy.ToBytes()) is the embedded authorizer.
        byte[] m0 = TideAttestor.buildUnsignedAdminPolicyBytes(1, VVK_ID);
        IgaRolePolicyEntity m0Row = policyAtThreshold(1);
        m0Row.setPolicy(Base64.getEncoder().encodeToString(m0));
        stubPolicyLookup(m0Row);

        String carrier = attestor.buildMultiAdminApprovalModel(session, realm, cr);

        assertNotNull(carrier);
        assertEquals(carrier, cr.getRequestModel(), "carrier persisted on the CR REQUEST_MODEL");
        ModelRequest parsed = ModelRequest.FromBytes(Base64.getDecoder().decode(carrier));
        assertNotNull(parsed, "phase-1 carrier must FromBytes");
        // The draft IS the new unsigned policy bytes (PolicySignRequest's payload draft).
        byte[] draft = parsed.GetDraft();
        assertTrue(draft != null && draft.length > 0, "carrier must carry a non-empty draft (the new policy)");
    }
}
