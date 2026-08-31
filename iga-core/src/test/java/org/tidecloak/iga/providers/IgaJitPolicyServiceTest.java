package org.tidecloak.iga.providers;

import org.junit.jupiter.api.Test;
import org.keycloak.models.RealmModel;
import org.midgard.Serialization.Tools;
import org.midgard.models.Policy.ApprovalType;
import org.midgard.models.Policy.ExecutionType;
import org.midgard.models.Policy.Policy;
import org.midgard.models.Policy.PolicyParameters;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The JIT policy is what binds a credential's lifetime to the grant behind it, so these pin the
 * two properties that binding depends on: the fallback lifetime comes from the realm rather than a
 * constant, and the Draft says the same expiry the policy does.
 */
public class IgaJitPolicyServiceTest {

    private static final String CONTRACT = "contract-1";
    private static final String VUID     = "vuid-abc";
    private static final String RESOURCE = "myclient";
    private static final String ROLE     = "case:read";
    private static final String CASE     = "assessment-1";

    private static RealmModel realmWithLifespan(int seconds) {
        RealmModel realm = mock(RealmModel.class);
        when(realm.getAccessTokenLifespan()).thenReturn(seconds);
        return realm;
    }

    private static Policy jitPolicy(RealmModel realm, Long expiry) {
        return jitPolicy(realm, expiry, ROLE);
    }

    private static Policy jitPolicy(RealmModel realm, Long expiry, String role) {
        return IgaJitPolicyService.buildPolicy(realm, CONTRACT, VUID, RESOURCE, role, CASE,
                "content", expiry);
    }

    @Test
    public void theFallbackLifetimeComesFromTheRealmsOwnAccessTokenLifespan() {
        assertEquals(900, IgaJitPolicyService.jitLifetimeSeconds(realmWithLifespan(900)));
        assertEquals(60, IgaJitPolicyService.jitLifetimeSeconds(realmWithLifespan(60)));
    }

    @Test
    public void anUnsetLifespanFallsBackToKeycloaksDefaultRatherThanUnbounded() {
        // A realm that has not set one reports 0. Reading that as "no limit" would let a standing
        // grant mint a credential that never expires, which is the opposite of the intent.
        assertEquals(IgaJitPolicyService.DEFAULT_ACCESS_TOKEN_LIFESPAN_SECONDS,
                IgaJitPolicyService.jitLifetimeSeconds(realmWithLifespan(0)));
        assertEquals(IgaJitPolicyService.DEFAULT_ACCESS_TOKEN_LIFESPAN_SECONDS,
                IgaJitPolicyService.jitLifetimeSeconds(realmWithLifespan(-1)));
        assertEquals(IgaJitPolicyService.DEFAULT_ACCESS_TOKEN_LIFESPAN_SECONDS,
                IgaJitPolicyService.jitLifetimeSeconds(null));
    }

    @Test
    public void aLifespanBeyondTheContractsCeilingIsClamped() {
        assertEquals(IgaJitPolicyService.MAX_JIT_LIFETIME_SECONDS,
                IgaJitPolicyService.jitLifetimeSeconds(realmWithLifespan(999999)));
    }

    @Test
    public void thePolicyPinsTheGrant() {
        Policy p = jitPolicy(realmWithLifespan(900), 1800000000L);

        assertEquals(ROLE, p.GetParameter("GrantedRole", String.class));
        assertEquals(CASE, p.GetParameter("AssessmentId", String.class));
        assertEquals("assessment", p.GetParameter("Scope", String.class));
        assertEquals(VUID, p.getKeyId());
        assertEquals(Long.valueOf(1800000000L), p.getExpiry());
        assertEquals(IgaJitPolicyService.JIT_MODEL_ID, p.getModelIds()[0]);
    }

    @Test
    public void aGrantIsApprovedOnceAndUsedByItsHolderAlone() {
        // IMPLICIT + PRIVATE is the shape of a just-in-time grant, and either half alone breaks it.
        //
        // EXPLICIT would make PolicyAuthorizationFlow demand a fresh quorum of approver dokens at
        // every mint, so a grant already approved could never actually be used. PRIVATE is what
        // stops IMPLICIT being a hole: the minter must present their own unexpired doken, bound by
        // audience to this key, before the contract is even reached.
        Policy p = jitPolicy(realmWithLifespan(900), 1800000000L);

        assertEquals(ApprovalType.IMPLICIT, p.getApprovalType());
        assertEquals(ExecutionType.PRIVATE, p.getExecutionType());
    }

    @Test
    public void aGrantWithNoAssessmentIsOrgScoped() {
        Policy p = IgaJitPolicyService.buildPolicy(realmWithLifespan(300), CONTRACT, VUID, RESOURCE,
                ROLE, null, "content", null);

        assertEquals("org", p.GetParameter("Scope", String.class));
        assertEquals("", p.GetParameter("AssessmentId", String.class));
    }

    @Test
    public void aGrantWithNoExpiryTakesTheRealmsLifespanFromNow() {
        // The fallback lands on the POLICY, at build time. Doing it here rather than in the
        // contract is what keeps the contract free of a clock read, which every ork must agree on.
        long before = System.currentTimeMillis() / 1000L;
        Policy p = jitPolicy(realmWithLifespan(900), null);
        long after = System.currentTimeMillis() / 1000L;

        assertNotNull(p.getExpiry());
        assertTrue(p.getExpiry() >= before + 900 && p.getExpiry() <= after + 900,
                "expected roughly now+900, got " + p.getExpiry());
    }

    @Test
    public void anExplicitExpiryIsKeptEvenBeyondTheRealmsLifespan() {
        // The realm's lifespan is a fallback, not a ceiling: a grant may legitimately outlive an
        // access token.
        long weekOut = (System.currentTimeMillis() / 1000L) + 604800;

        assertEquals(Long.valueOf(weekOut), jitPolicy(realmWithLifespan(300), weekOut).getExpiry());
        assertNull(IgaJitPolicyService.rejectionReason(realmWithLifespan(300),
                jitPolicy(realmWithLifespan(300), weekOut)));
    }

    @Test
    public void theDraftCarriesTheSameExpiryThePolicyDoes() {
        // The one place the two must agree. The contract refuses a token whose expiry is not
        // exactly the policy's, so a Draft built from anything else would never be signed.
        long expiry = 1800000000L;
        Policy p = jitPolicy(realmWithLifespan(900), expiry);

        byte[] draft = IgaJitPolicyService.buildDraft(p, VUID, CASE, ROLE, "{}");

        assertEquals(VUID, new String(Tools.GetValue(draft, IgaJitPolicyService.DRAFT_SUBJECT),
                StandardCharsets.UTF_8));
        assertEquals(CASE, new String(Tools.GetValue(draft, IgaJitPolicyService.DRAFT_ASSESSMENT),
                StandardCharsets.UTF_8));
        assertEquals(ROLE, new String(Tools.GetValue(draft, IgaJitPolicyService.DRAFT_ROLE),
                StandardCharsets.UTF_8));

        byte[] expiryBytes = Tools.GetValue(draft, IgaJitPolicyService.DRAFT_EXPIRY);
        assertEquals(8, expiryBytes.length);
        assertEquals(expiry, ByteBuffer.wrap(expiryBytes).order(ByteOrder.LITTLE_ENDIAN).getLong());
    }

    @Test
    public void aPolicyWithNoExpiryCannotMintAJitToken() {
        // buildPolicy always sets one, so this is the hand-assembled case: without an expiry there
        // is nothing to pin the credential's lifetime to, and the token would be a standing one
        // wearing a just-in-time name.
        Policy p = handBuilt(ROLE, null);

        assertNull(p.getExpiry());
        assertThrows(IllegalArgumentException.class,
                () -> IgaJitPolicyService.buildDraft(p, VUID, CASE, ROLE, "{}"));
        assertNotNull(IgaJitPolicyService.rejectionReason(realmWithLifespan(900), p));
    }

    @Test
    public void aJitPolicyThatPinsNoRoleIsRefused() {
        String reason = IgaJitPolicyService.rejectionReason(realmWithLifespan(900),
                handBuilt("", 1800000000L));

        assertNotNull(reason);
        assertTrue(reason.contains("pin the role"), reason);
    }

    @Test
    public void aNonJitPolicyIsNotSubjectToTheseRules() {
        // The extra rules key off the model id, so an ordinary policy is untouched by them.
        PolicyParameters params = new PolicyParameters();
        params.put("resource", RESOURCE);
        Policy ordinary = new Policy(CONTRACT, new String[]{"SomethingElse:1"}, VUID,
                ApprovalType.EXPLICIT, ExecutionType.PUBLIC, params);

        assertNull(IgaJitPolicyService.rejectionReason(realmWithLifespan(60), ordinary));
        assertTrue(!IgaJitPolicyService.isJitPolicy(ordinary));
    }

    /** A JIT policy assembled by hand, so a shape the builder would never produce can be tested. */
    private static Policy handBuilt(String grantedRole, Long expiry) {
        PolicyParameters params = new PolicyParameters();
        params.put("GrantedRole", grantedRole);
        params.put("Resource", RESOURCE);
        return new Policy(CONTRACT, new String[]{IgaJitPolicyService.JIT_MODEL_ID}, VUID,
                ApprovalType.EXPLICIT, ExecutionType.PUBLIC, params, expiry);
    }
}
