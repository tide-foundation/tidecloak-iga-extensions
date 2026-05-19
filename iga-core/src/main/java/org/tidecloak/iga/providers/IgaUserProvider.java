package org.tidecloak.iga.providers;

import org.jboss.logging.Logger;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.jpa.JpaUserProvider;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;

import jakarta.persistence.EntityManager;

/**
 * Extends {@link JpaUserProvider} to intercept user mutations through IGA when
 * enabled. {@code JpaUserProvider.session} is private, so we maintain our own
 * reference as {@code igaSession}.
 *
 * <h2>CREATE_USER — model-layer accumulate-then-veto (Phase 3)</h2>
 * This replaces the dead JAX-RS {@code IgaRepresentationCaptureFilter}
 * transport (provider-jar {@code @Provider} request filters are never
 * discovered by Keycloak's RESTEasy runtime — same finding as CLIENT /
 * CLIENT_SCOPE). The SAME proven mechanism as
 * {@code IgaRealmProvider.addClient/addClientScope}:
 * <ol>
 *   <li>When IGA is active (not replay, not master), {@link #addUser(RealmModel,
 *       String)} creates a REAL <em>scratch</em> {@link UserEntity} via the
 *       5-arg local-storage {@code super.addUser(realm,id,username,false,false)}
 *       — {@code addDefaultRoles=false}, {@code addDefaultRequiredActions=false}
 *       so the accumulated rep carries ONLY what the admin sent — and returns a
 *       capture-mode {@link IgaUserAdapter}.</li>
 *   <li>KC's {@code UsersResource.createUser} flow then applies the COMPLETE
 *       incoming representation to that genuine adapter (attributes, enabled,
 *       email/names, requiredActions, federated identities, groups, role
 *       mappings, credentials). Every call passes through to the real
 *       {@link UserEntity} (lifecycle proof identical to client-scope) AND is
 *       accumulated into an in-memory {@code UserRepresentation}.</li>
 *   <li>At the post-build terminal seam {@code IgaUserAdapter#getId}
 *       (UsersResource.createUser:175, gated on username-observed) the
 *       accumulated rep is written as a {@code CREATE_USER} change request in a
 *       SEPARATE transaction, the request tx is marked rollback-only and
 *       {@link IgaPendingApprovalException} is thrown (→ HTTP 202 + Location).
 *       The scratch user + credentials + memberships + role mappings + fed
 *       identities die with the request-tx rollback (zero rows at draft).</li>
 * </ol>
 * Federated identities are added by the provider (not the adapter):
 * {@code RepresentationToModel.createFederatedIdentities} calls
 * {@code session.users().addFederatedIdentity}, intercepted in
 * {@link #addFederatedIdentity(RealmModel, UserModel, FederatedIdentityModel)}
 * — in capture mode it records into the capture-mode adapter and does NOT
 * persist (discarded by the rollback anyway).
 *
 * <h2>Replay / master / IGA-off</h2>
 * Under {@code IGA_REPLAY_ACTIVE} (set by {@code IgaReplayDispatcher.replay})
 * {@code addUser} takes the plain {@code super} path returning a non-capture
 * {@link IgaUserAdapter}, so {@code RepresentationToModel.createUser} →
 * {@code DefaultExportImportManager.createUser} rebuilds the full user
 * (it uses the 5-arg local-storage {@code addUser}, NOT this 1-arg seam, and
 * its nested setter/credential/group/role calls pass straight through the
 * inert wrappers). Master realm is excluded because
 * {@code IgaChangeRequestService.isIgaEnabled} returns false for it. Replay is
 * UNCHANGED.
 */
public class IgaUserProvider extends JpaUserProvider {

    private static final Logger log = Logger.getLogger(IgaUserProvider.class);

    // JpaUserProvider.session is private; store our own copy
    private final KeycloakSession igaSession;

    public IgaUserProvider(KeycloakSession session, EntityManager em) {
        super(session, em);
        this.igaSession = session;
    }

    private IgaChangeRequestService getService() {
        return new IgaChangeRequestService(em, igaSession);
    }

    private boolean isIgaActive(RealmModel realm) {
        IgaChangeRequestService service = getService();
        if (!service.isIgaEnabled(realm)) return false;
        Object replay = igaSession.getAttribute("IGA_REPLAY_ACTIVE");
        return !"true".equals(replay);
    }

    @Override
    public UserModel addUser(RealmModel realm, String username) {
        if (isIgaActive(realm)) {
            // Model-layer accumulate-then-veto (see class javadoc). Create the
            // REAL (scratch) UserEntity via the 5-arg local-storage addUser so
            // we own the id and DON'T add default roles / required actions
            // (the accumulated rep must carry only what the admin sent). Return
            // a capture-mode IgaUserAdapter; KC's createUser flow builds the
            // full model on it and the terminal IgaUserAdapter#getId seam emits
            // the CREATE_USER CR + rollback-only + throws (→ 202 + Location).
            String userId = KeycloakModelUtils.generateId();
            UserModel base = super.addUser(realm, userId,
                    username == null ? null : username.toLowerCase(), false, false);
            if (base == null) return null;
            if (base instanceof org.keycloak.models.jpa.UserAdapter ua) {
                UserEntity entity = ua.getEntity();
                log.debugf("IGA capture CREATE_USER: scratch user entity created for "
                        + "username=%s (uuid=%s) — accumulating full representation until the "
                        + "model-layer terminal seam (UsersResource.createUser#getId)",
                        username, userId);
                return new IgaUserAdapter(igaSession, realm, em, entity, /*captureMode=*/ true);
            }
            return base;
        }
        UserModel base = super.addUser(realm, username);
        if (base == null) return null;
        if (base instanceof org.keycloak.models.jpa.UserAdapter ua) {
            UserEntity entity = ua.getEntity();
            return new IgaUserAdapter(igaSession, realm, em, entity);
        }
        return base;
    }

    @Override
    public void addFederatedIdentity(RealmModel realm, UserModel user, FederatedIdentityModel identity) {
        // KC's UsersResource.createUser:171 →
        // RepresentationToModel.createFederatedIdentities calls this with the
        // capture-mode adapter as `user`. Record into the accumulator and DON'T
        // persist (discarded by the request-tx rollback anyway). Outside
        // capture (inline / replay / IGA-off) behave exactly as super.
        if (user instanceof IgaUserAdapter iua && iua.isCaptureMode()) {
            iua.captureFederatedIdentity(identity);
            return;
        }
        super.addFederatedIdentity(realm, user, identity);
    }

    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        UserModel base = super.getUserById(realm, id);
        if (base == null) return null;
        if (base instanceof org.keycloak.models.jpa.UserAdapter ua) {
            UserEntity entity = ua.getEntity();
            return new IgaUserAdapter(igaSession, realm, em, entity);
        }
        return base;
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        UserModel base = super.getUserByUsername(realm, username);
        if (base == null) return null;
        if (base instanceof org.keycloak.models.jpa.UserAdapter ua) {
            UserEntity entity = ua.getEntity();
            return new IgaUserAdapter(igaSession, realm, em, entity);
        }
        return base;
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        UserModel base = super.getUserByEmail(realm, email);
        if (base == null) return null;
        if (base instanceof org.keycloak.models.jpa.UserAdapter ua) {
            UserEntity entity = ua.getEntity();
            return new IgaUserAdapter(igaSession, realm, em, entity);
        }
        return base;
    }
}
