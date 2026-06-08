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
            // ★ accept-unattested SELF-ENROLLMENT default-role grant (PATH-ROBUST).
            // For genuine self-enrollment under RegOn — BOTH the registration form
            // (a RegistrationUserCreation frame) AND the Tide-enrolled IdP-broker /
            // link-tide-account import (which arrives here as UserCacheSession#addUser,
            // with NO RegistrationUserCreation frame) — pass addDefaultRoles=true to
            // the 5-arg local-storage super.addUser. KC's JpaUserProvider.addUser then
            // grants realm.getDefaultRole() + joins the default groups on the REAL
            // JpaUser (a plain UserAdapter — line 124-131 of JpaUserProvider), BEFORE
            // we wrap it in the capture adapter. That grant is therefore NOT routed
            // through the IGA capture path → no nested GRANT_ROLES CR — and it
            // PERSISTS on the live user.
            //
            // WHY PATH-ROBUST (the Round-1 gap): the earlier gate keyed SOLELY on a
            // RegistrationUserCreation StackWalker frame (isSelfRegistrationFrame),
            // which fires for the plain registration form but NOT for the
            // Tide-enrolled broker/link-tide import — the ACTUAL user flow. That left
            // Tide-enrolled self-registrants ROLELESS → no account aud → ORK TVE
            // "attested claim 'aud' is suppressed". The gate is now keyed on RegOn
            // (realm.isRegistrationAllowed()) with admin-create / service-account
            // EXCLUDED (see shouldGrantDefaultRolesOnSelfCreate), so BOTH self-enroll
            // paths land the local default-role while admin/internal paths are
            // unchanged.
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
            // (ClientManager), token-exchange and IdP-broker/link-tide all reach this
            // branch. Under RegOn we grant default-roles for genuine self-enrollment
            // (registration form AND Tide-enrolled broker/link-tide import) but EXCLUDE
            // admin-create (its CR commits and the D3 commit-replay grant assigns
            // default-roles; granting at creation too would double-grant) and
            // service-account creates (ClientManager — internal, no account aud needed,
            // keeps stock-suppressed creation). When RegOn is OFF nothing is granted
            // here (stock-suppressed), so the open-registration posture is the gate.
            boolean grantDefaultRoles = shouldGrantDefaultRolesOnSelfCreate(realm);
            String userId = KeycloakModelUtils.generateId();
            UserModel base = super.addUser(realm, userId,
                    username == null ? null : username.toLowerCase(),
                    grantDefaultRoles, false);
            if (grantDefaultRoles) {
                log.infof("IGA capture CREATE_USER: self-enrollment under RegOn detected "
                        + "(registration form OR Tide-enrolled broker/link-tide import; "
                        + "registrationAllowed=true, not admin-create/service-account) — "
                        + "granted realm default-role + default groups on the live user "
                        + "(uuid=%s) at creation so the accept-unattested self-enroll token "
                        + "carries the account aud; the default-role is D1b-excluded so no "
                        + "user_role_mapping_set unit is produced (gate still admits the "
                        + "unsigned user_identity).",
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
     * The KC admin user-create resource. Its presence anywhere in the live 1-arg
     * {@code addUser} stack marks the call as ADMIN-create
     * ({@code UsersResource.createUser} → {@code profile.create()} → the 1-arg seam).
     * Admin-create is EXCLUDED from the creation-time default-role grant: its
     * CREATE_USER CR commits and {@code IgaReplayDispatcher.replayCreateUser} D3-grants
     * default-roles at replay; granting at creation too would double-grant.
     */
    private static final String KC_USERS_RESOURCE =
            "org.keycloak.services.resources.admin.UsersResource";

    /**
     * The KC service-account manager. Its presence marks an internal
     * service-account user-create ({@code ClientManager.enableServiceAccount} →
     * {@code addUser}). Service-account users are EXCLUDED — they are internal, need
     * no {@code account} audience, and granting the realm default-role to them would
     * be a regression.
     */
    private static final String KC_CLIENT_MANAGER =
            "org.keycloak.services.managers.ClientManager";

    /**
     * Live-stack + RegOn predicate driving the {@code addDefaultRoles=true} scoping in
     * the 1-arg {@link #addUser(RealmModel, String)} capture branch. Walks the live
     * stack once and delegates to the pure, unit-testable
     * {@link #shouldGrantDefaultRolesOnSelfCreate(java.util.List, boolean)}.
     */
    private boolean shouldGrantDefaultRolesOnSelfCreate(RealmModel realm) {
        java.util.List<String> frames = StackWalker.getInstance()
                .walk(s -> s.map(f -> f.getClassName() + "#" + f.getMethodName())
                        .collect(java.util.stream.Collectors.toList()));
        return shouldGrantDefaultRolesOnSelfCreate(frames, realm.isRegistrationAllowed());
    }

    /**
     * Pure, unit-testable PATH-ROBUST self-enrollment classifier. Given the live
     * stack-frame signatures as {@code "<FQN>#<method>"} (any order) and the realm's
     * RegOn flag, return true iff the just-created user should receive the LOCAL realm
     * default-role at creation.
     *
     * <p>Decision (RegOn-gated, admin/service-account excluded):
     * <ol>
     *   <li>If {@code registrationAllowed} is false → {@code false}
     *       (no open-registration posture; nothing is granted at creation, the
     *       stock-suppressed behaviour).</li>
     *   <li>Else if an admin-create frame ({@link #KC_USERS_RESOURCE}{@code #createUser})
     *       is present → {@code false} (its CR commits and the D3 replay grant assigns
     *       default-roles; granting here would double-grant).</li>
     *   <li>Else if a service-account frame ({@link #KC_CLIENT_MANAGER}) is present →
     *       {@code false} (internal create, no account aud needed).</li>
     *   <li>Else → {@code true} — genuine self-enrollment. This covers BOTH the
     *       registration form (a {@link #KC_REGISTRATION_USER_CREATION} frame, the
     *       former {@link #isSelfRegistrationFrame} subset) AND the Tide-enrolled
     *       IdP-broker / link-tide-account import (which arrives as
     *       {@code UserCacheSession#addUser} with NO RegistrationUserCreation frame —
     *       the path the Round-1 StackWalker gate missed).</li>
     * </ol>
     *
     * <p>Why RegOn rather than a positive broker frame: the user has explicitly
     * accepted the open-registration posture (RegOn on ⇒ any unsigned default-roles
     * user is admitted at login), and keying on RegOn makes the grant path-robust
     * across the registration form AND every Tide self-enrollment entry (broker,
     * link-tide, cache-wrapped {@code addUser}) without enumerating fragile broker
     * frame signatures. Admin-create and service-account are the only paths that must
     * NOT grant, and both have a stable, distinctive frame to exclude.</p>
     */
    static boolean shouldGrantDefaultRolesOnSelfCreate(
            java.util.List<String> frameSignatures, boolean registrationAllowed) {
        if (!registrationAllowed) {
            return false;
        }
        if (frameSignatures == null) {
            // RegOn but no stack to inspect: default to granting (genuine
            // self-enrollment is the dominant RegOn create path). Admin/service-account
            // always have a live stack with their excluding frame, so this branch is
            // only reached in tests / degenerate cases.
            return true;
        }
        for (String sig : frameSignatures) {
            if (sig == null) {
                continue;
            }
            int hash = sig.lastIndexOf('#');
            String cn = hash >= 0 ? sig.substring(0, hash) : sig;
            String mn = hash >= 0 ? sig.substring(hash + 1) : "";
            if (KC_USERS_RESOURCE.equals(cn) && "createUser".equals(mn)) {
                return false;
            }
            if (KC_CLIENT_MANAGER.equals(cn)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Pure, unit-testable registration-FORM classifier. Given the live stack-frame
     * signatures as {@code "<FQN>#<method>"} (any order), return true iff a
     * {@link #KC_REGISTRATION_USER_CREATION} frame is present.
     *
     * <p>NOTE: this is the NARROW (registration-form-only) signal. The live
     * default-role grant gate is now the broader, path-robust
     * {@link #shouldGrantDefaultRolesOnSelfCreate(java.util.List, boolean)} (RegOn-gated,
     * admin/service-account excluded), which ALSO covers the Tide-enrolled
     * broker/link-tide import that has no RegistrationUserCreation frame. This
     * predicate is retained as the documented registration-form subset (a true here
     * implies the broader gate grants too, given RegOn) and is exercised by the
     * registration-form unit tests. Frame-list-driven so the partition is pinnable
     * without a live {@link StackWalker}.</p>
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
