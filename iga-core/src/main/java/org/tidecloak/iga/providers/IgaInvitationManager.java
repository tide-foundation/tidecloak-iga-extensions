package org.tidecloak.iga.providers;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OrganizationInvitationModel;
import org.keycloak.models.OrganizationInvitationModel.Filter;
import org.keycloak.models.OrganizationModel;
import org.keycloak.organization.InvitationManager;

import java.util.Map;
import java.util.stream.Stream;

/**
 * Decorating {@link InvitationManager} that intercepts organization-member
 * <b>invitations</b> through the IGA approval workflow, mirroring exactly how
 * {@link IgaOrganizationProvider} intercepts create/update/delete/member/idp
 * organization mutations.
 *
 * <h2>Why this is the seam (KC 26.5.5)</h2>
 * The admin REST endpoints
 * {@code POST {realm}/organizations/{id}/members/invite-user} and
 * {@code .../members/invite-existing-user}
 * ({@code OrganizationMemberResource.inviteUser/inviteExistingUser}) delegate to
 * {@code OrganizationInvitationResource.inviteUser/inviteExistingUser}, which
 * funnel into the private {@code sendInvitation(UserModel)}. There, in strict
 * order:
 * <ol>
 *   <li>{@code invitationManager.create(organization, email, firstName,
 *       lastName)} — the FIRST and ONLY persisting side-effect
 *       ({@code JpaInvitationManager.create} does {@code em.persist(entity)}
 *       and stamps {@code expiresAt = Time.currentTime() +
 *       realm.getActionTokenGeneratedByAdminLifespan()});</li>
 *   <li>{@code createInvitationLink/createRegistrationLink → createToken(...)}
 *       — builds + serializes the {@code InviteOrgActionToken} (NOT separately
 *       persisted; embedded in the link, validity derived from the
 *       invitation's {@code expiresAt});</li>
 *   <li>{@code session.getProvider(EmailTemplateProvider.class)
 *       .sendOrgInviteEmail(...)} — sends the e-mail.</li>
 * </ol>
 * {@code InvitationManager} is a first-class Keycloak SPI returned by
 * {@code OrganizationProvider.getInvitationManager()}, so there IS a clean SPI
 * seam — no JAX-RS interceptor hack is needed. By throwing
 * {@code IgaPendingApprovalException} from a wrapping {@code create(...)} we
 * stop the flow at step (1), <b>before</b> the entity is persisted and
 * therefore strictly before token serialization (step 2) and the e-mail send
 * (step 3). Nothing is created and no e-mail goes out at request time.
 *
 * <h2>Resend (POST {realm}/organizations/{id}/members/invitations/{id}/resend)</h2>
 * KC's {@code OrganizationInvitationResource.resendInvitation} calls
 * {@code invitationManager.remove(id)} on the existing invitation and then
 * delegates to {@code inviteUser(email, firstName, lastName)}, which funnels
 * into the SAME {@code sendInvitation} and therefore the SAME
 * {@code invitationManager.create(...)}. Our {@code create(...)} below
 * intercepts there and would normally emit {@code ORG_INVITE_MEMBER}. To make
 * resend its own governance action ({@code ORG_RESEND_INVITE}) — useful for
 * audit + future scope rules — we inspect the in-flight request URI in
 * {@code create(...)} and switch the recorded action type when the path ends
 * with {@code /resend}. {@link IgaReplayDispatcher} maps both action types to
 * the same {@code replayOrgInviteMember} body (transcription of KC's
 * {@code sendInvitation}); a resend's replay therefore mints a fresh token +
 * sends a fresh e-mail, exactly like the original invite. Limitation: the
 * pre-existing invitation row is deleted by KC's {@code resendInvitation}
 * BEFORE our seam fires (request-time {@code invitationManager.remove(id)},
 * not intercepted), so a denied resend leaves no invitation behind. Properly
 * governing the {@code remove(id)} on the resend path requires a JAX-RS
 * pre-matching filter or a Tide-side patch to {@code OrganizationInvitationResource}
 * (out of scope for Phase 7a — see report).
 *
 * <h2>Governance model</h2>
 * <ul>
 *   <li><b>Request time</b>: no invitation row, no token, no e-mail →
 *       {@code IgaPendingApprovalException} (HTTP 202). The invitation payload
 *       (org id, email, first/last name) is captured into the change request.
 *       </li>
 *   <li><b>Commit / replay</b> ({@code IGA_REPLAY_ACTIVE=true}): this wrapper
 *       passes straight through to the real {@code JpaInvitationManager}, so
 *       the dispatcher re-runs KC's own
 *       {@code OrganizationInvitationResource} logic — the invitation is
 *       created, a fresh token is minted, and the e-mail is sent NOW (the real
 *       invitation happens at approval time). Token/invitation validity starts
 *       from commit time because {@code expiresAt} is computed inside
 *       {@code create()}.</li>
 *   <li><b>Deny</b>: replay never runs, so by construction no invitation, no
 *       token, no e-mail — nothing to undo.</li>
 *   <li><b>Double-commit</b>: {@code IgaAdminResource.commit} rejects any CR
 *       not in {@code PENDING} state (HTTP 409) and
 *       {@code IgaReplayDispatcher.replay} flips status to {@code APPROVED};
 *       replay can therefore never run twice, so no duplicate
 *       invitation/token/e-mail.</li>
 * </ul>
 *
 * <p>Every read / lookup / remove method delegates straight to the wrapped
 * manager so listing, get-by-id/email, expiry checks and explicit invitation
 * deletes behave exactly like stock Keycloak. Only {@code create(...)} — the
 * single persisting + side-effecting entry point — is intercepted, and only
 * when IGA is active and not replaying.</p>
 */
public class IgaInvitationManager implements InvitationManager {

    /** Recorded action type when the in-flight request URI ends with /resend. */
    private static final String ACTION_INVITE = "ORG_INVITE_MEMBER";
    private static final String ACTION_RESEND = "ORG_RESEND_INVITE";

    private final InvitationManager delegate;
    private final IgaOrganizationProvider provider;
    private final KeycloakSession session;

    public IgaInvitationManager(InvitationManager delegate, IgaOrganizationProvider provider) {
        this(delegate, provider, null);
    }

    public IgaInvitationManager(InvitationManager delegate, IgaOrganizationProvider provider,
                                KeycloakSession session) {
        this.delegate = delegate;
        this.provider = provider;
        this.session = session;
    }

    @Override
    public OrganizationInvitationModel create(OrganizationModel organization, String email,
                                              String firstName, String lastName) {
        if (provider.igaActive() && organization != null) {
            // Defer the real invitation to commit time. This throw happens
            // BEFORE the wrapped JpaInvitationManager.create persists the
            // OrganizationInvitationEntity, hence strictly before the action
            // token is serialized and before sendOrgInviteEmail is called in
            // OrganizationInvitationResource.sendInvitation. The payload is
            // captured so replay can reconstruct the exact KC invite call.
            //
            // URI sniff: distinguish a normal invite from a resend so the CR
            // gets the right action type for audit + (future) scope rules.
            // KC's OrganizationInvitationResource.resendInvitation funnels
            // through the same sendInvitation → invitationManager.create path,
            // and the request URI is still .../invitations/{id}/resend at this
            // point (we run inside the resend handler's call stack).
            String action = resendInFlight() ? ACTION_RESEND : ACTION_INVITE;
            provider.recordOrgInvite(organization.getId(), email, firstName, lastName, action);
            return null; // unreachable — recordOrgInvite always throws
        }
        return delegate.create(organization, email, firstName, lastName);
    }

    /**
     * Detect whether the in-flight admin request is a resend
     * ({@code .../invitations/{id}/resend}) by inspecting the request URI on
     * the current {@link KeycloakSession}. We accept either the session passed
     * to the constructor (preferred) OR fall back to
     * {@link IgaOrganizationProvider}'s session via its public accessor —
     * either yields the same {@code KeycloakContext}. If no session/URI is
     * available (programmatic non-REST callers) we conservatively treat the
     * call as a fresh invite.
     */
    private boolean resendInFlight() {
        KeycloakSession s = session != null ? session : provider.session();
        if (s == null) return false;
        try {
            org.keycloak.models.KeycloakContext ctx = s.getContext();
            if (ctx == null) return false;
            org.keycloak.models.KeycloakUriInfo uri = ctx.getUri();
            if (uri == null) return false;
            String path = uri.getPath();
            return path != null && path.endsWith("/resend");
        } catch (Exception ignored) {
            return false;
        }
    }

    @Override
    public OrganizationInvitationModel getById(String id) {
        return delegate.getById(id);
    }

    @Override
    public OrganizationInvitationModel getByEmail(OrganizationModel organization, String email) {
        return delegate.getByEmail(organization, email);
    }

    @Override
    public Stream<OrganizationInvitationModel> getAllStream(OrganizationModel organization,
                                                            Map<Filter, String> attributes,
                                                            Integer first, Integer max) {
        return delegate.getAllStream(organization, attributes, first, max);
    }

    @Override
    public boolean remove(String id) {
        return delegate.remove(id);
    }
}
