package org.tidecloak.iga.providers;

import org.jboss.logging.Logger;
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
 * <h2>CREATE_USER — model-layer accumulate-then-veto</h2>
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
 *       incoming representation to that genuine adapter. Every call passes
 *       through to the real {@link UserEntity} (lifecycle proof identical to
 *       client-scope) but only the TOKEN-AFFECTING subset (username, enabled,
 *       email, emailVerified, firstName, lastName, attributes, realmRoles,
 *       clientRoles, groups) is accumulated into an in-memory
 *       {@code UserRepresentation}. credentials, requiredActions,
 *       federatedIdentities, createdTimestamp and federationLink are NOT
 *       governed (see {@code IgaUserAdapter} javadoc) — they pass straight
 *       through to the scratch user and die with the rollback.</li>
 *   <li>At the post-build terminal seam {@code IgaUserAdapter#getId}
 *       (UsersResource.createUser:175, gated on username-observed) the
 *       accumulated rep is written as a {@code CREATE_USER} change request in a
 *       SEPARATE transaction, the request tx is marked rollback-only and
 *       {@link IgaPendingApprovalException} is thrown (→ HTTP 202 + Location).
 *       The scratch user + credentials + memberships + role mappings + fed
 *       identities die with the request-tx rollback (zero rows at draft).</li>
 * </ol>
 * Federated identities are NOT governed: {@code addFederatedIdentity} is no
 * longer overridden, so {@code RepresentationToModel.createFederatedIdentities}'
 * {@code session.users().addFederatedIdentity} call on the scratch user passes
 * straight through to {@code JpaUserProvider} and is discarded by the
 * request-tx rollback (never accumulated, never replayed).
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
            //
            // ★ accept-unattested SELF-REGISTRATION default-role grant.
            // For the self-registration flow ONLY (a RegistrationUserCreation
            // frame in the live stack — see inSelfRegistrationFlow), pass
            // addDefaultRoles=true to the 5-arg local-storage super.addUser. KC's
            // JpaUserProvider.addUser then grants realm.getDefaultRole() + joins
            // the default groups on the REAL JpaUser (a plain UserAdapter — line
            // 124-131 of JpaUserProvider), BEFORE we wrap it in the capture
            // adapter. That grant is therefore NOT routed through the IGA capture
            // path → no nested GRANT_ROLES CR — and it PERSISTS on the live user.
            //
            // WHY: an accept-unattested self-reg user is admitted UNSIGNED at
            // login and its CREATE_USER CR never commits, so the D3 commit-replay
            // default-role grant (IgaReplayDispatcher.replayCreateUser :559-566)
            // never runs. Without granting here the self-reg user is ROLELESS →
            // KC builds the token with empty resource_access → no `account`
            // audience → the ORK TVE rejects "attested claim 'aud' is suppressed
            // in token" (the producer closure attests aud=[account] from the
            // universal-inherited realm default-role's account children).
            //
            // CLOSURE INVARIANT (gate still admits): the realm default-role id is
            // the D1b exclusion in RealmAttestationExporter.perUserUnits — a user
            // holding ONLY default-roles → empty role_ids → NO user_role_mapping_set
            // unit. So the user HOLDS default-roles (token carries the account aud)
            // AND the producer closure has no role-mapping unit (the
            // default-roles-only gate still admits the unsigned user_identity).
            //
            // SCOPE: the 1-arg overload is NOT registration-only — admin-create
            // (UsersResource#createUser, via profile.create()), service-account
            // (ClientManager), token-exchange and IdP-broker all reach this branch.
            // Only the self-registration flow gets default-roles here; admin-create
            // keeps the CR + D3 commit-replay grant (granting at creation too would
            // double-grant), and the internal callers keep stock-suppressed creation.
            boolean grantDefaultRoles = inSelfRegistrationFlow();
            String userId = KeycloakModelUtils.generateId();
            UserModel base = super.addUser(realm, userId,
                    username == null ? null : username.toLowerCase(),
                    grantDefaultRoles, false);
            if (grantDefaultRoles) {
                log.infof("IGA capture CREATE_USER: self-registration flow detected "
                        + "(RegistrationUserCreation frame) — granted realm default-role + "
                        + "default groups on the live user (uuid=%s) at creation so the "
                        + "accept-unattested self-reg token carries the account aud; the "
                        + "default-role is D1b-excluded so no user_role_mapping_set unit is "
                        + "produced (gate still admits the unsigned user_identity).",
                        userId);
            }
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

    /**
     * Close the partialImport user bypass.
     *
     * <p>{@code PartialImportManager}'s {@code UsersPartialImport} routes users
     * through {@code DefaultExportImportManager.createUser}
     * which calls THIS 5-arg
     * local-storage {@code addUser(realm,id,username,false,false)} — NOT the
     * 1-arg seam above. Without this seam it fell straight through to
     * {@code JpaUserProvider}, so partialImport users were created
     * UNGOVERNED (the bypass).
     *
     * <p>Gating (provably does NOT regress single-entity user replay, which
     * uses this exact 5-arg path):
     * <ul>
     *   <li><b>partialImport + IGA on + NOT replay</b> → return a
     *       capture-mode {@link IgaUserAdapter} and register it with
     *       {@link IgaImportMode}. KC's
     *       {@code DefaultExportImportManager.createUser} then applies every
     *       setter/{@code joinGroup} to that capture adapter (accumulated, the
     *       scratch user is built then discarded by the batch rollback). The
     *       row is harvested at batch-emit time.</li>
     *   <li><b>{@code IGA_REPLAY_ACTIVE=true}</b> (commit-time replay —
     *       {@code IgaReplayDispatcher.replayCreateUser} sets this then calls
     *       {@code DefaultExportImportManager.createUser} → this 5-arg path):
     *       {@link IgaImportMode#isImportMode} returns false (replay
     *       short-circuit), so we take the SAME plain {@code super} path the
     *       1-arg seam's replay branch takes — a non-capture
     *       {@link IgaUserAdapter}. Single-entity replay is byte-unchanged.</li>
     *   <li><b>IGA off / master / no partialImport frame</b> →
     *       {@code isImportMode} false → plain {@code super} (inert wrapper,
     *       exactly the pre-Phase-4 behaviour).</li>
     * </ul>
     */
    @Override
    public UserModel addUser(RealmModel realm, String id, String username,
                             boolean addDefaultRoles, boolean addDefaultRequiredActions) {
        if (IgaImportMode.isImportMode(igaSession, realm)) {
            UserModel base = super.addUser(realm, id, username,
                    addDefaultRoles, addDefaultRequiredActions);
            if (base == null) return null;
            if (base instanceof org.keycloak.models.jpa.UserAdapter ua) {
                UserEntity entity = ua.getEntity();
                log.infof("IGA multi-entity: capture CREATE_USER via 5-arg "
                        + "local-storage addUser (partialImport path) for "
                        + "username=%s (uuid=%s) — capture-mode adapter "
                        + "registered with the batch (bypass closed)",
                        username, id);
                IgaUserAdapter adapter = new IgaUserAdapter(
                        igaSession, realm, em, entity, /*captureMode=*/ true);
                IgaImportMode.registerImportUser(igaSession, realm, adapter);
                return adapter;
            }
            return base;
        }
        // Replay / IGA-off / master / non-import: unchanged pass-through
        // (single-entity replay uses this exact path — must NOT regress).
        UserModel base = super.addUser(realm, id, username,
                addDefaultRoles, addDefaultRequiredActions);
        if (base == null) return null;
        if (base instanceof org.keycloak.models.jpa.UserAdapter ua) {
            UserEntity entity = ua.getEntity();
            return new IgaUserAdapter(igaSession, realm, em, entity);
        }
        return base;
    }

    /**
     * The KC 26.5.5 self-registration form-action class. {@code success(FormContext)}
     * (services {@code RegistrationUserCreation.success:155}) calls
     * {@code profile.create()} → {@code DefaultUserProfile.create} →
     * {@code DeclarativeUserProfileProvider}'s {@code createUserFactory().apply} →
     * {@code session.users().addUser(realm, username)} (the 1-arg seam above). So when
     * the 1-arg {@code addUser} runs inside the self-registration flow, this class is
     * present in the live stack (above the user-profile factory). It is NOT present for
     * admin-create ({@code UsersResource#createUser} is the {@code profile.create()}
     * entry instead), service-account ({@code ClientManager}), token-exchange
     * ({@code AbstractTokenExchangeProvider}), IdP-broker
     * ({@code IdpCreateUserIfUniqueAuthenticator}) or master bootstrap
     * ({@code ApplianceBootstrap}) — the other 1-arg callers.
     */
    private static final String KC_REGISTRATION_USER_CREATION =
            "org.keycloak.authentication.forms.RegistrationUserCreation";

    /**
     * Live-stack predicate: is the current {@code addUser} call running inside the
     * self-registration flow (a {@link #KC_REGISTRATION_USER_CREATION} frame anywhere
     * in the stack)? Drives the {@code addDefaultRoles=true} scoping in the 1-arg
     * {@link #addUser(RealmModel, String)} capture branch. Walks the live stack once
     * and delegates the decision to the pure, unit-testable
     * {@link #isSelfRegistrationFrame(java.util.List)}.
     */
    private boolean inSelfRegistrationFlow() {
        java.util.List<String> frames = StackWalker.getInstance()
                .walk(s -> s.map(f -> f.getClassName() + "#" + f.getMethodName())
                        .collect(java.util.stream.Collectors.toList()));
        return isSelfRegistrationFrame(frames);
    }

    /**
     * Pure, unit-testable self-registration classifier. Given the live stack-frame
     * signatures as {@code "<FQN>#<method>"} (any order), return true iff a
     * {@link #KC_REGISTRATION_USER_CREATION} frame is present — the
     * registration-SPECIFIC marker that scopes the default-role grant ON for
     * self-registration while leaving admin-create and the other internal 1-arg
     * {@code addUser} callers stock-suppressed. Frame-list-driven so the
     * registration-vs-admin/other partition is pinnable without a live
     * {@link StackWalker}.
     */
    static boolean isSelfRegistrationFrame(java.util.List<String> frameSignatures) {
        if (frameSignatures == null) {
            return false;
        }
        for (String sig : frameSignatures) {
            if (sig == null) {
                continue;
            }
            int hash = sig.lastIndexOf('#');
            String cn = hash >= 0 ? sig.substring(0, hash) : sig;
            if (KC_REGISTRATION_USER_CREATION.equals(cn)) {
                return true;
            }
        }
        return false;
    }

    // addFederatedIdentity is NOT overridden — federated identities are IdP
    // brokering, not token claims, and are NOT governed. KC's
    // UsersResource.createUser:171 → RepresentationToModel.createFederatedIdentities
    // may call session.users().addFederatedIdentity on the capture-mode scratch
    // user; it passes straight through to the inherited JpaUserProvider and
    // dies with the request-tx rollback (never accumulated, never replayed;
    // IgaUserAdapter#getId also explicitly nulls rep.federatedIdentities).

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
