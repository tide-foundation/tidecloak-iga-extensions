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
import org.midgard.Serialization.Tools;
import org.midgard.models.ModelRequest;
import org.midgard.models.Policy.Policy;
import org.midgard.models.RequestExtensions.PolicySignRequest;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.tidecloak.iga.entities.IgaAuthorizationEntity;
import org.tidecloak.iga.entities.IgaAuthorizerEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.entities.IgaRolePolicyEntity;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
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
 * <p>The {@code maybeEmitThresholdPolicyCrAtCapture} tests drive the deterministic
 * NON-capable realm path (a mock realm with no {@code tide-vendor-key} component): the
 * emit logic is capability-agnostic but multiAdmin-mode-GATED, so the tests stub a
 * multiAdmin authorizer row ({@code stubMultiAdminMode}). The projected post-commit count
 * is driven by the committed-ids JPQL + role-members stream ({@code stubActiveAdminCount})
 * plus the pending tide-realm-admin assignment delta ({@code stubPendingAssignments}).
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
        // committedTideAdminUserIds JPQL (FROM UserRoleMappingEntity) — string-matched so it
        // does NOT collide with findPendingByAction's IgaChangeRequestEntity JPQL.
        Query jpql = mock(Query.class);
        when(em.createQuery(contains("UserRoleMappingEntity"))).thenReturn(jpql);
        when(jpql.setParameter(anyString(), any())).thenReturn(jpql);
        when(jpql.getResultList()).thenReturn((List) ids);
        // session.users().getRoleMembersStream
        when(session.users()).thenReturn(users);
        when(users.getRoleMembersStream(eq(realm), eq(tideRealmAdmin)))
                .thenAnswer(inv -> members.stream());
    }

    /**
     * Drive resolveMode to return {@code multiAdmin} (an IgaAuthorizer row with that mode).
     * The capture-time policy hook is a STEADY-STATE multiAdmin-only path; without this the
     * firstAdmin-bootstrap guard short-circuits.
     */
    private void stubMultiAdminMode() {
        IgaAuthorizerEntity row = new IgaAuthorizerEntity();
        row.setRealmId(REALM_ID);
        row.setMode(TideAttestor.MODE_MULTI_ADMIN);
        @SuppressWarnings("unchecked")
        TypedQuery<IgaAuthorizerEntity> q = mock(TypedQuery.class);
        when(em.createNamedQuery(eq("IgaAuthorizer.findByRealm"), eq(IgaAuthorizerEntity.class)))
                .thenReturn(q);
        when(q.setParameter(anyString(), any())).thenReturn(q);
        when(q.getResultStream()).thenAnswer(inv -> Stream.of(row));
    }

    /**
     * Drive pendingTideRealmAdminDelta: stub findPendingByAction (GRANT_ROLES / REVOKE_ROLES,
     * FROM IgaChangeRequestEntity) to return {@code grants} pending grant CRs and {@code revokes}
     * pending revoke CRs, ALL targeting the tide-realm-admin role. At capture the triggering
     * assignment CR is already persisted, so the test models it as part of this pending set.
     */
    @SuppressWarnings("unchecked")
    private void stubPendingAssignments(int grants, int revokes) {
        // findPendingByAction (createQuery(String, IgaChangeRequestEntity.class) ... :actionType)
        // — a fresh TypedQuery per call that returns grants/revokes keyed on the bound actionType.
        // All returned CRs carry the tide-realm-admin ROLE_ID (crTargetsRole → true).
        when(em.createQuery(contains("IgaChangeRequestEntity"), eq(IgaChangeRequestEntity.class)))
                .thenAnswer(inv -> {
                    TypedQuery<IgaChangeRequestEntity> qq = mock(TypedQuery.class);
                    List<IgaChangeRequestEntity> result = new ArrayList<>();
                    when(qq.setParameter(anyString(), any())).thenAnswer(p -> {
                        if ("actionType".equals(p.getArgument(0))) {
                            String action = p.getArgument(1);
                            result.clear();
                            int n = "GRANT_ROLES".equals(action) ? grants
                                    : "REVOKE_ROLES".equals(action) ? revokes : 0;
                            for (int i = 0; i < n; i++) result.add(grantCr("pend-" + action + "-" + i));
                        }
                        return qq;
                    });
                    when(qq.getResultList()).thenAnswer(r -> new ArrayList<>(result));
                    return qq;
                });
    }

    // --- create --------------------------------------------------------------

    @Test
    void create_emitsOneRegenCr_whenThresholdMoves() {
        // 2 committed admins; the (already-pending) tide-realm-admin grant nets +1 → projected
        // 3 (floor(0.7*3)=2). Encoded threshold 1 MOVES to 2, so a CR is created.
        stubMultiAdminMode();
        stubPolicyLookup(policyAtThreshold(1));
        stubFindPending(null);
        stubActiveAdminCount(2);
        stubPendingAssignments(1, 0);

        attestor.maybeEmitThresholdPolicyCrAtCapture(session, realm, grantCr("g1"));

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
        stubMultiAdminMode();
        IgaChangeRequestEntity cr = grantCr("x");
        cr.setRowsJson("[{\"USER_ID\":\"u\",\"ROLE_ID\":\"some-other-role\"}]");

        attestor.maybeEmitThresholdPolicyCrAtCapture(session, realm, cr);

        verify(em, never()).persist(any());
    }

    @Test
    void create_noCr_whenFirstAdminBootstrap() {
        // firstAdmin mode (no IgaAuthorizer row, tide attestor) — the FIRST tide-realm-admin
        // grant bootstraps the M0 inline and must NOT spawn a REGEN CR. The capture hook
        // short-circuits before any projection.
        when(realm.getAttribute("iga.attestor")).thenReturn("tide");
        @SuppressWarnings("unchecked")
        TypedQuery<IgaAuthorizerEntity> q = mock(TypedQuery.class);
        when(em.createNamedQuery(eq("IgaAuthorizer.findByRealm"), eq(IgaAuthorizerEntity.class)))
                .thenReturn(q);
        when(q.setParameter(anyString(), any())).thenReturn(q);
        when(q.getResultStream()).thenAnswer(inv -> Stream.empty()); // no row → firstAdmin

        attestor.maybeEmitThresholdPolicyCrAtCapture(session, realm, grantCr("bootstrap"));

        verify(em, never()).persist(any());
    }

    // --- IsEqualTo no-op -----------------------------------------------------

    @Test
    void isEqualTo_noCr_whenThresholdUnchanged() {
        // 4 active admins (floor(0.7*4)=2); a grant -> 5 (floor(0.7*5)=3)... pick numbers that
        // do NOT move: 1 active admin (floor=1... wait clamp), use 10 admins -> floor(0.7*10)=7,
        // +1 -> 11 -> floor(0.7*11)=7. Threshold stays 7 -> NO CR.
        stubMultiAdminMode();
        stubPolicyLookup(policyAtThreshold(7));
        stubFindPending(null);
        stubActiveAdminCount(10);
        stubPendingAssignments(1, 0);

        attestor.maybeEmitThresholdPolicyCrAtCapture(session, realm, grantCr("g1"));

        verify(em, never()).persist(any());
    }

    // --- nets-to-zero cancel -------------------------------------------------

    @Test
    void netsToZero_cancelsPendingRegenCr_whenThresholdReturnsToCurrent() {
        // The policy already encodes the threshold the batch nets back to, AND a pending
        // REGEN_ADMIN_POLICY exists (an earlier CR in the batch moved it). A grant+revoke pair
        // nets the projected delta to 0 → projected count == committed → threshold unchanged →
        // the IsEqualTo branch must CANCEL that pending CR.
        stubMultiAdminMode();
        stubPolicyLookup(policyAtThreshold(7));
        IgaChangeRequestEntity pending = new IgaChangeRequestEntity();
        pending.setId("pending-regen");
        pending.setRealmId(REALM_ID);
        pending.setEntityType("ADMIN_POLICY");
        pending.setEntityId(TIDE_ROLE_ID);
        pending.setActionType("REGEN_ADMIN_POLICY");
        pending.setStatus("PENDING");
        stubFindPending(pending);
        stubActiveAdminCount(10);
        stubPendingAssignments(1, 1); // net 0 -> projected 10 -> floor 7 == current 7

        attestor.maybeEmitThresholdPolicyCrAtCapture(session, realm, grantCr("g2"));

        assertEquals("CANCELLED", pending.getStatus(), "the stale pending policy CR is cancelled");
        assertNotNull(pending.getResolvedAt());
        verify(em, never()).persist(any());
    }

    // --- fold-to-one ---------------------------------------------------------

    @Test
    void fold_rewritesPendingCrInPlace_andClearsAuthorizations() {
        // A pending REGEN_ADMIN_POLICY already exists; a SECOND tide-realm-admin grant in the
        // batch is captured. Both pending grants net +2 over 2 committed -> projected 4 ->
        // floor(0.7*4)=2 (the FINAL batch threshold). We must UPDATE the pending CR in place (no
        // new persist), re-point dependsOn to include the new assignment, and CLEAR its
        // authorizations.
        stubMultiAdminMode();
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
        stubActiveAdminCount(2);
        stubPendingAssignments(2, 0); // net +2 -> projected 4 -> floor 2; encoded 1 -> MOVES

        attestor.maybeEmitThresholdPolicyCrAtCapture(session, realm, grantCr("g2"));

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
        // 3 committed admins (floor(0.7*3)=2); a pending tide-realm-admin revoke nets -1 ->
        // projected 2 -> floor(0.7*2)=1. Threshold LOWERS 2 -> 1 -> a CR.
        stubMultiAdminMode();
        stubPolicyLookup(policyAtThreshold(2));
        stubFindPending(null);
        stubActiveAdminCount(3);
        stubPendingAssignments(0, 1);

        attestor.maybeEmitThresholdPolicyCrAtCapture(session, realm, revokeCr("r1"));

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

    // --- old-policy revocation flag in the authorized Draft (phase-1) --------

    @Test
    void approvalModelCarrier_setsRevocationFlag_atDraftIndex2() throws Exception {
        // The REGEN phase-1 carrier must set the OLD-policy rotation flag INSIDE the
        // cryptographically authorized Draft: PolicySignRequest.SetRevokeAuthorizingPolicyOnSign
        // appends a trailing {0x01} segment at Draft index 2 (segment 0 = new policy payload,
        // segment 1 = contract-to-upload, segment 2 = the revoke flag). Decoding the persisted
        // carrier via ModelRequest.FromBytes and reading Draft segment 2 must yield {0x01}, so
        // the collected admin dokens cover the burn intent and the ORK burns the old M0 at commit.
        byte[] newPolicy = TideAttestor.buildUnsignedAdminPolicyBytes(3, VVK_ID);
        String newPolicyB64 = Base64.getEncoder().encodeToString(newPolicy);

        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setId("regen-cr-flag");
        cr.setRealmId(REALM_ID);
        cr.setActionType("REGEN_ADMIN_POLICY");
        cr.setEntityType("ADMIN_POLICY");
        cr.setEntityId(TIDE_ROLE_ID);
        cr.setRowsJson("[{\"OLD_THRESHOLD\":1,\"NEW_THRESHOLD\":3,\"ROLE_ID\":\"" + TIDE_ROLE_ID
                + "\",\"VVK_ID\":\"" + VVK_ID + "\",\"POLICY_BODY_UNSIGNED\":\"" + newPolicyB64 + "\"}]");

        byte[] m0 = TideAttestor.buildUnsignedAdminPolicyBytes(1, VVK_ID);
        IgaRolePolicyEntity m0Row = policyAtThreshold(1);
        m0Row.setPolicy(Base64.getEncoder().encodeToString(m0));
        stubPolicyLookup(m0Row);

        String carrier = attestor.buildMultiAdminApprovalModel(session, realm, cr);

        ModelRequest parsed = ModelRequest.FromBytes(Base64.getDecoder().decode(carrier));
        byte[] draft = parsed.GetDraft();
        byte[] revokeSeg = Tools.TryGetValue(draft, 2);
        assertNotNull(revokeSeg, "REGEN carrier Draft must carry a segment at index 2 (the revoke flag)");
        assertArrayEquals(new byte[]{0x01}, revokeSeg,
                "REGEN carrier Draft index 2 must be the {0x01} old-policy-revocation flag");

        // Segment 0 is the verbatim new unsigned policy payload (flag is on the request Draft,
        // NOT the policy bytes) — POLICY_BODY_UNSIGNED is unchanged by the flag.
        assertArrayEquals(newPolicy, Tools.GetValue(draft, 0),
                "REGEN carrier Draft index 0 must be the verbatim unsigned new policy bytes");
    }

    @Test
    void nonRegenPolicyRequest_hasNoRevocationFlag_atDraftIndex2() throws Exception {
        // Negative control: a Policy:1 request built WITHOUT SetRevokeAuthorizingPolicyOnSign
        // (the shape of a normal, non-REGEN approval carrier) carries ONLY the policy payload
        // segment — Draft index 2 is absent. Proves the {0x01} at index 2 is the rotation flag,
        // not an unconditional artifact of the carrier encoding.
        byte[] policyBytes = TideAttestor.buildUnsignedAdminPolicyBytes(3, VVK_ID);
        PolicySignRequest req = new PolicySignRequest(policyBytes, "Policy:1");
        byte[] draft = req.GetDraft();

        assertArrayEquals(policyBytes, Tools.GetValue(draft, 0),
                "non-revoke carrier Draft index 0 is the policy payload");
        byte[] seg2 = Tools.TryGetValue(draft, 2);
        assertTrue(seg2 == null || !Arrays.equals(new byte[]{0x01}, seg2),
                "non-REGEN carrier Draft must NOT carry the {0x01} revoke flag at index 2");
    }

    // --- vendor creation-auth wiring (enclave-validation regression) ----------

    @Test
    void policyApprovalCarrier_vendorInitialized_whenCapable() throws Exception {
        // REGRESSION for the enclave bug ("buffer length is 0 ... Must initialize request to get
        // creation time"): the REGEN policy carrier MUST take the SAME seg-7 VRK creation-auth the
        // producer-unit path takes. We spy the capability gate to the capable branch and assert
        // buildPolicyResignApprovalModel routes through initializeApprovalRequestWithVrk over the
        // SAME PolicySignRequest whose Draft was already materialized (policy@0 + revoke-flag@2),
        // so the seg-7 signature covers the full, non-empty Draft the enclave validates.
        byte[] newPolicy = TideAttestor.buildUnsignedAdminPolicyBytes(3, VVK_ID);
        String newPolicyB64 = Base64.getEncoder().encodeToString(newPolicy);

        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setId("regen-cr-init");
        cr.setRealmId(REALM_ID);
        cr.setActionType("REGEN_ADMIN_POLICY");
        cr.setEntityType("ADMIN_POLICY");
        cr.setEntityId(TIDE_ROLE_ID);
        cr.setRowsJson("[{\"OLD_THRESHOLD\":1,\"NEW_THRESHOLD\":3,\"ROLE_ID\":\"" + TIDE_ROLE_ID
                + "\",\"VVK_ID\":\"" + VVK_ID + "\",\"POLICY_BODY_UNSIGNED\":\"" + newPolicyB64 + "\"}]");

        byte[] m0 = TideAttestor.buildUnsignedAdminPolicyBytes(1, VVK_ID);
        IgaRolePolicyEntity m0Row = policyAtThreshold(1);
        m0Row.setPolicy(Base64.getEncoder().encodeToString(m0));
        stubPolicyLookup(m0Row);

        TideAttestor spy = org.mockito.Mockito.spy(new TideAttestor(session));
        // Force the capable branch (the static gate also reads THRESHOLD_* env we can't control).
        org.mockito.Mockito.doReturn(true).when(spy).approvalRequestNeedsVrkInit(realm);
        // The real init does a live ORK round-trip; stub it to assert it was reached with a
        // Policy:1 (AuthFlow) request carrying a non-empty Draft (revoke flag @2 already set).
        final boolean[] reached = {false};
        org.mockito.Mockito.doAnswer(inv -> {
            ModelRequest req = inv.getArgument(1);
            assertEquals("Policy:1", req.Id(),
                    "the carrier handed to vendor-init must be the Policy:1 re-sign request");
            byte[] d = req.GetDraft();
            assertArrayEquals(new byte[]{0x01}, Tools.TryGetValue(d, 2),
                    "Draft must already carry the revoke flag @2 BEFORE creation-auth (the seg-7 "
                            + "signature must cover it)");
            reached[0] = true;
            return null;
        }).when(spy).initializeApprovalRequestWithVrk(eq(realm), any(ModelRequest.class));

        String carrier = spy.buildMultiAdminApprovalModel(session, realm, cr);

        assertTrue(reached[0], "policy approval-model build MUST call initializeApprovalRequestWithVrk "
                + "on a capable realm (the missing step that caused the enclave self-close)");
        assertNotNull(carrier, "carrier still built + persisted");
        verify(spy, times(1)).initializeApprovalRequestWithVrk(eq(realm), any(ModelRequest.class));
    }

    @Test
    void policyApprovalCarrier_noVendorInit_whenNotCapable() {
        // Parity gate: a NON-capable realm (the deterministic unit-test environment) must NOT
        // attempt the VRK creation-auth — same gate as the producer-unit path — but still build
        // a round-trippable carrier (the dev/test wiring path).
        byte[] newPolicy = TideAttestor.buildUnsignedAdminPolicyBytes(3, VVK_ID);
        String newPolicyB64 = Base64.getEncoder().encodeToString(newPolicy);

        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setId("regen-cr-noinit");
        cr.setRealmId(REALM_ID);
        cr.setActionType("REGEN_ADMIN_POLICY");
        cr.setEntityType("ADMIN_POLICY");
        cr.setEntityId(TIDE_ROLE_ID);
        cr.setRowsJson("[{\"OLD_THRESHOLD\":1,\"NEW_THRESHOLD\":3,\"ROLE_ID\":\"" + TIDE_ROLE_ID
                + "\",\"VVK_ID\":\"" + VVK_ID + "\",\"POLICY_BODY_UNSIGNED\":\"" + newPolicyB64 + "\"}]");

        byte[] m0 = TideAttestor.buildUnsignedAdminPolicyBytes(1, VVK_ID);
        IgaRolePolicyEntity m0Row = policyAtThreshold(1);
        m0Row.setPolicy(Base64.getEncoder().encodeToString(m0));
        stubPolicyLookup(m0Row);

        TideAttestor spy = org.mockito.Mockito.spy(new TideAttestor(session));
        org.mockito.Mockito.doReturn(false).when(spy).approvalRequestNeedsVrkInit(realm);

        String carrier = spy.buildMultiAdminApprovalModel(session, realm, cr);

        assertNotNull(carrier, "non-capable realm still builds the carrier (dev/test wiring)");
        verify(spy, never()).initializeApprovalRequestWithVrk(any(), any());
    }
}
