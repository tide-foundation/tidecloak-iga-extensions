package org.tidecloak.iga.services;

import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.ErrorResponse;

import jakarta.ws.rs.core.Response;

import org.tidecloak.iga.providers.IgaSystemProvisionerProvider;

/**
 * SINGLE source of truth for the {@code tide-realm-admin} lockout safeguard.
 *
 * <h2>What it protects</h2>
 * The {@code tide-realm-admin} client role on {@code realm-management} is the IGA
 * <em>approver</em> role: its holders sign (commit) every IGA change request. If that
 * role is ever conferred on a user who is NOT both (a) Tide-identity-committed
 * ({@code UserEntity.attestation} present — see
 * {@link IgaSystemProvisionerProvider#isUserIdentityCommitted}) AND (b) linked to the
 * Tide identity provider ({@code "tide"} federated identity), then after a VRK rotation
 * no eligible approver can ever sign again — a permanent, unrecoverable admin lockout.
 *
 * <h2>Two enforcement points, ONE rule (no drift)</h2>
 * The eligibility predicate must be applied at BOTH points where a direct
 * {@code tide-realm-admin} grant can take effect:
 * <ul>
 *   <li><b>Capture time</b> — {@code IgaUserAdapter.grantRole} (the inline
 *       {@code GRANT_ROLES} interception), so an ineligible grant never even enters the
 *       approval pipeline as a pending change request.</li>
 *   <li><b>Commit / replay time</b> — {@code IgaReplayDispatcher.grantRoleDirect}, which
 *       runs under {@code IGA_REPLAY_ACTIVE} and therefore bypasses the capture-time
 *       interception entirely. Without a re-check here a {@code GRANT_ROLES} change
 *       request that was filed BEFORE the capture-time guard shipped (or otherwise reaches
 *       commit) would replay the grant onto an ineligible user with no validation,
 *       re-opening the lockout at commit time.</li>
 * </ul>
 * Both call this class so the rule cannot drift between the two paths.
 *
 * <h2>Failure mode</h2>
 * {@link #assertEligible} throws {@code ErrorResponse.error(..., 400 BAD_REQUEST)} — a
 * JAX-RS {@link jakarta.ws.rs.WebApplicationException} carrying a clean error Response.
 * At capture time this maps to the same 400 the inline guard already returned. On the
 * commit/replay path the exception propagates out of {@code IgaReplayDispatcher.replay} →
 * {@code IgaAdminResource.commitResolved}, rolling back the commit JPA transaction (so the
 * grant is NOT applied and the change request stays PENDING) and is mapped to a 400 by the
 * JAX-RS layer — exactly as {@code IgaScopeResolver.requireApprover}'s {@code ForbiddenException}
 * propagates to a 403. No partial state survives a refusal: the guard runs BEFORE the
 * {@code user.grantRole(role)} model write.
 */
public final class TideRealmAdminGuard {

    /** Provider id of the Tide identity provider (mirrors IgaUserAdapter's local constant). */
    public static final String TIDE_IDP_PROVIDER_ID = "tide";

    private TideRealmAdminGuard() {
    }

    /**
     * True iff {@code role} is the DIRECT {@code tide-realm-admin} client role on the
     * {@code realm-management} client. Direct grant only — we deliberately do NOT walk
     * composites or group-derived roles here; the lockout safeguard targets the explicit
     * assignment of the approver role.
     */
    public static boolean isTideRealmAdminRole(RealmModel realm, RoleModel role) {
        if (role == null || !role.isClientRole()) return false;
        if (!IgaApproverRoleRepointer.TIDE_REALM_ADMIN.equals(role.getName())) return false; // "tide-realm-admin"
        ClientModel owner = realm.getClientById(role.getContainerId());
        return owner != null && "realm-management".equals(owner.getClientId());
    }

    /**
     * Re-validate (or throw) that {@code user} is eligible to hold the
     * {@code tide-realm-admin} approver role: it must be BOTH Tide-identity-committed AND
     * linked to the Tide identity provider. Throws {@code ErrorResponse.error(..., 400)}
     * otherwise. Callers MUST invoke this BEFORE applying the grant so no partial state is
     * left on a refusal.
     *
     * @param session the active session (used for the provisioner provider + federated-identity read)
     * @param realm   the realm the user belongs to
     * @param user    the grant target (already resolved); MUST be non-null
     */
    public static void assertEligible(KeycloakSession session, RealmModel realm, UserModel user) {
        boolean committed = session.getProvider(IgaSystemProvisionerProvider.class)
                .isUserIdentityCommitted(realm, user.getId());
        if (!committed) {
            throw ErrorResponse.error(
                    "Cannot assign tide-realm-admin: the target user's Tide identity is not yet committed.",
                    Response.Status.BAD_REQUEST);
        }
        boolean tideLinked = session.users().getFederatedIdentitiesStream(realm, user)
                .anyMatch(fi -> TIDE_IDP_PROVIDER_ID.equals(fi.getIdentityProvider()));
        if (!tideLinked) {
            throw ErrorResponse.error(
                    "Cannot assign tide-realm-admin: the target user is not linked to the Tide identity provider.",
                    Response.Status.BAD_REQUEST);
        }
    }
}
