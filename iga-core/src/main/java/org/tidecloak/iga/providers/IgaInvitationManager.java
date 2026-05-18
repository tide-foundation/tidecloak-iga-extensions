package org.tidecloak.iga.providers;

import org.keycloak.models.OrganizationInvitationModel;
import org.keycloak.models.OrganizationInvitationModel.Filter;
import org.keycloak.models.OrganizationModel;
import org.keycloak.organization.InvitationManager;

import java.util.List;
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

    private final InvitationManager delegate;
    private final IgaOrganizationProvider provider;

    public IgaInvitationManager(InvitationManager delegate, IgaOrganizationProvider provider) {
        this.delegate = delegate;
        this.provider = provider;
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
            provider.recordOrgInvite(organization.getId(), email, firstName, lastName);
            return null; // unreachable — recordOrgInvite always throws
        }
        return delegate.create(organization, email, firstName, lastName);
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
