package org.tidecloak.iga.providers;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ★ accept-unattested default-role grant — the PATH-INDEPENDENT 1-arg
 * {@code addUser} default-role grant gate.
 *
 * <p><b>Staging bug (keylessh).</b> Users who enrolled via the Tide IdP-broker /
 * link-tide-account path were created with ZERO realm roles (verified: {@code 6d1a3bbf},
 * {@code uvuv}, both {@code federated:['tide']}), even though {@code registrationAllowed=true}.
 * The former gate keyed the {@code addDefaultRoles=true} grant on a live
 * {@link StackWalker} self-enrollment signal — a {@code RegistrationUserCreation} frame OR
 * a positive Tide-broker check that required the auth-session {@code BROKERED_CONTEXT} note's
 * IdP <em>alias</em> to equal the literal {@code "tide"}. On the deployed Tide-broker /
 * link-tide path that signal did not resolve (no live Tide-broker note at the {@code addUser}
 * instant, and {@code SerializedBrokeredIdentityContext.getIdentityProviderId()} returns the
 * configured IdP <em>alias</em>, which need not be {@code "tide"}), so the grant was skipped →
 * roleless user → empty {@code resource_access} → no {@code account} aud → ORK TVE rejects
 * "attested claim 'aud' is suppressed in token".</p>
 *
 * <p><b>Fix.</b> Drop the fragile stack-frame / broker-alias sniffing. The grant now fires for
 * EVERY create path, gated ONLY on the two load-bearing guards:
 * <ol>
 *   <li><b>RegOn</b> ({@code realm.isRegistrationAllowed()}) — the open-registration posture.</li>
 *   <li><b>MF2 benign-composite guard</b> — never confer a TAINTED (privileged) default-role
 *       composite to an unsigned self-registrant.</li>
 * </ol>
 *
 * <p>These tests pin the pure, path-independent decision
 * {@link IgaUserProvider#shouldGrantDefaultRolesOnSelfCreate(boolean, boolean)} (the live
 * {@link StackWalker} and {@code DefaultRoleCompositeGuard} cannot be mocked here; the live
 * instance overload delegates to this pure method). Because the decision takes NO call-path
 * input, the Tide IdP-broker / link-tide enrollment path — which carries no registration
 * frame and whose IdP alias may not be {@code "tide"} — now grants exactly like the
 * registration form.</p>
 */
class IgaUserProviderRegistrationDefaultRolesTest {

    // ── RegOn OFF: never grant at creation (open-registration posture is the gate) ──

    @Test
    void regOnOff_benignComposite_doesNotGrant() {
        assertFalse(IgaUserProvider.shouldGrantDefaultRolesOnSelfCreate(
                        /*registrationAllowed=*/ false, /*benign=*/ true),
                "RegOn off → no creation-time default-role grant (stock-suppressed); "
                        + "closed-realm creates still get default-roles via the D3 commit replay");
    }

    @Test
    void regOnOff_nonBenignComposite_doesNotGrant() {
        assertFalse(IgaUserProvider.shouldGrantDefaultRolesOnSelfCreate(false, false),
                "RegOn off → no grant regardless of composite");
    }

    // ── RegOn ON + benign composite: PATH-INDEPENDENT grant (the fix) ───────────────

    @Test
    void regOnOn_benignComposite_grants_registrationForm() {
        // The plain browser registration form keeps granting.
        assertTrue(IgaUserProvider.shouldGrantDefaultRolesOnSelfCreate(true, true),
                "RegOn on + benign composite → grant the realm default-role at creation");
    }

    @Test
    void regOnOn_benignComposite_grants_tideBrokerLinkTideEnrollment() {
        // ★ THE FIX: the Tide IdP-broker / link-tide-account enrollment path carries NO
        // RegistrationUserCreation frame and its brokered IdP alias need not be "tide", so the
        // old frame/broker-alias gate returned false and the user was created ROLELESS. The
        // new gate is path-independent: with RegOn on and a benign composite it grants — the
        // SAME inputs the registration form produces — so the Tide-enrolled user ends up
        // holding default-roles-<realm> (carrying the account aud). This is the exact scenario
        // that regressed on staging keylessh (6d1a3bbf, uvuv) and MUST now grant.
        assertTrue(IgaUserProvider.shouldGrantDefaultRolesOnSelfCreate(true, true),
                "RegOn on + benign composite → grant for the Tide IdP-broker / link-tide "
                        + "enrollment path (no registration frame, no 'tide' alias required) — "
                        + "the roleless-enrollee staging bug fix");
    }

    @Test
    void regOnOn_benignComposite_grants_regardlessOfCreatePath() {
        // Any other create path (external-IdP first-login, token-exchange, admin-create) reaches
        // the same gate. Under RegOn + benign it also grants; for the captured-then-vetoed
        // admin / governed creates the grant is a harmless idempotent no-op (discarded with the
        // request-tx rollback, then re-granted at the D3 commit replay). The decision does not
        // branch on the path — that is what makes the fix robust.
        assertTrue(IgaUserProvider.shouldGrantDefaultRolesOnSelfCreate(true, true),
                "RegOn on + benign composite → grant is path-independent");
    }

    // ── RegOn ON + NON-benign composite: MF2 guard refuses (privilege escalation gate) ──

    @Test
    void regOnOn_nonBenignComposite_mf2Refuses() {
        // MF2: a tainted default-role composite (a privileged child role) must NOT be conferred
        // to an unsigned self-registrant. Dropping the frame narrowing does NOT reopen the MF2
        // vector because a privileged default-role is still refused here.
        assertFalse(IgaUserProvider.shouldGrantDefaultRolesOnSelfCreate(true, false),
                "RegOn on + NON-benign default-role composite → MF2 guard refuses the grant "
                        + "(no privilege to an unsigned self-registrant)");
    }
}
