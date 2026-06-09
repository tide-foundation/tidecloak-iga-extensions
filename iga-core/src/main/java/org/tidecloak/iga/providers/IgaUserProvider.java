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
        // Scoped vendor/system provisioning bypass (see
        // IgaChangeRequestService.IGA_VENDOR_PROVISIONING): apply directly, no capture.
        if (service.isVendorProvisioning()) return false;
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
     * The stock KC broker first-login authenticator. Its presence in the live 1-arg
     * {@code addUser} stack marks the create as an IdP-broker first-login
     * ({@code IdpCreateUserIfUniqueAuthenticator.authenticateImpl:90} →
     * {@code session.users().addUser(realm, username)}). This fires for EVERY brokered
     * IdP — Tide AND external (non-Tide) — so the frame ALONE does NOT distinguish a
     * genuine Tide self-enrollment from an external-IdP first-login. The allow-list gate
     * pairs this frame with a positive Tide-broker check ({@link #isTideBrokerEnrollment})
     * that reads the brokered IdP id from the auth session and admits ONLY the Tide IdP.
     */
    private static final String KC_IDP_CREATE_USER =
            "org.keycloak.authentication.authenticators.broker.IdpCreateUserIfUniqueAuthenticator";

    /** The Tide social/broker IdP provider id (TideIdentityProviderFactory.PROVIDER_ID). */
    private static final String TIDE_IDP_PROVIDER_ID = "tide";

    /** The auth-session note key the broker context is serialized under (AbstractIdpAuthenticator). */
    private static final String BROKERED_CONTEXT_NOTE = "BROKERED_CONTEXT";

    /**
     * Live-stack + RegOn predicate driving the {@code addDefaultRoles=true} scoping in
     * the 1-arg {@link #addUser(RealmModel, String)} capture branch (★ F2 ALLOW-LIST).
     * Walks the live stack once, resolves the genuine-self-enrollment signal (registration
     * form OR Tide-broker first-login), and ANDs it with the ★ MF2 benign-composite guard
     * so a tainted {@code default-roles-<realm>} (a privileged composite child) refuses
     * self-reg eligibility (the user falls back to the normal fail-closed / CR path) rather
     * than conferring privilege to an unsigned self-registrant.
     */
    private boolean shouldGrantDefaultRolesOnSelfCreate(RealmModel realm) {
        java.util.List<String> frames = StackWalker.getInstance()
                .walk(s -> s.map(f -> f.getClassName() + "#" + f.getMethodName())
                        .collect(java.util.stream.Collectors.toList()));
        boolean selfEnroll = isSelfEnrollmentFrame(frames, realm.isRegistrationAllowed(),
                isTideBrokerEnrollment());
        if (!selfEnroll) {
            return false;
        }
        // ★ MF2: never grant (and never mark eligible) a tainted default-role composite.
        if (!org.tidecloak.iga.services.DefaultRoleCompositeGuard
                .isBenignDefaultRoleComposite(realm)) {
            log.warnf("IGA self-enroll REFUSED (MF2 guard): realm '%s' default-role "
                    + "composite is NON-BENIGN (privileged child present). NOT granting "
                    + "default-roles at creation and NOT admitting unsigned — the self-reg "
                    + "falls back to the normal fail-closed / CR path.", realm.getName());
            return false;
        }
        return true;
    }

    /**
     * Live-stack Tide-broker enrollment check: true iff the current auth session carries a
     * brokered-identity context whose IdP id is the Tide provider ({@value #TIDE_IDP_PROVIDER_ID}).
     * This is the POSITIVE Tide self-enrollment signal that the generic
     * {@link #KC_IDP_CREATE_USER} frame cannot provide (the frame fires for external IdPs too).
     * The genuine Tide-enrolled browser registration creates its user via the stock broker
     * first-login authenticator (Tide IdP-extensions do NOT override it), so the brokered IdP
     * id is {@value #TIDE_IDP_PROVIDER_ID} for exactly that flow and some external alias for a
     * non-Tide IdP. Defensive: any failure to resolve the context → false (no grant).
     */
    private boolean isTideBrokerEnrollment() {
        try {
            org.keycloak.sessions.AuthenticationSessionModel authSession =
                    igaSession.getContext() == null ? null
                            : igaSession.getContext().getAuthenticationSession();
            if (authSession == null) {
                return false;
            }
            org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext ctx =
                    org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext
                            .readFromAuthenticationSession(authSession, BROKERED_CONTEXT_NOTE);
            return ctx != null && TIDE_IDP_PROVIDER_ID.equals(ctx.getIdentityProviderId());
        } catch (RuntimeException e) {
            // Out of an auth-session context, or a malformed note — treat as not-Tide-broker.
            return false;
        }
    }

    /**
     * Pure, unit-testable ★ F2 ALLOW-LIST self-enrollment classifier. Given the live
     * stack-frame signatures as {@code "<FQN>#<method>"} (any order), the realm's RegOn
     * flag, and whether the current auth session is a Tide-broker enrollment, return true
     * iff the just-created user should receive the LOCAL realm default-role at creation.
     *
     * <p><b>Why an allow-list (the F2 fix).</b> The former gate was a DENY-list — it
     * granted under RegOn for EVERYTHING except {@link #KC_USERS_RESOURCE}{@code #createUser}
     * and {@link #KC_CLIENT_MANAGER}. That silently granted default-roles (→ admitted
     * unsigned) to TWO non-self-reg paths that ALSO reach the 1-arg {@code addUser} under
     * RegOn: token-exchange user creation ({@code AbstractTokenExchangeProvider}) and
     * external (non-Tide) IdP first-login ({@link #KC_IDP_CREATE_USER}). Those are the
     * delivery vehicle for MF2. The allow-list grants ONLY for a recognised genuine
     * self-registration frame.</p>
     *
     * <p>Decision (RegOn-gated; grant requires a POSITIVE self-enrollment signal):
     * <ol>
     *   <li>If {@code registrationAllowed} is false → {@code false} (no open-registration
     *       posture; stock-suppressed).</li>
     *   <li>Else grant iff EITHER:
     *     <ul>
     *       <li>the registration FORM is present
     *           ({@link #KC_REGISTRATION_USER_CREATION} — the browser self-sign-up); OR</li>
     *       <li>this is a genuine Tide-broker first-login enrollment:
     *           {@code tideBrokerEnrollment} is true (the brokered IdP id is the Tide
     *           provider, resolved from the auth-session broker context by the live caller).
     *           The frame for this is the stock {@link #KC_IDP_CREATE_USER}; the Tide IdP
     *           uses the stock broker authenticator (no override), so the IdP-id check is
     *           what separates a Tide enrollment from an external-IdP first-login.</li>
     *     </ul>
     *   </li>
     *   <li>Otherwise → {@code false}. This now EXCLUDES, by omission from the allow-list:
     *       admin-create ({@link #KC_USERS_RESOURCE}), service-account
     *       ({@link #KC_CLIENT_MANAGER}), token-exchange ({@code AbstractTokenExchangeProvider}),
     *       AND external (non-Tide) IdP first-login (the generic {@link #KC_IDP_CREATE_USER}
     *       frame WITHOUT a Tide broker context).</li>
     * </ol>
     *
     * <p>The genuine Tide-enrolled browser registration the user confirmed working creates
     * its user via the stock broker first-login authenticator (Tide IdP-extensions do NOT
     * override it) brokered from the Tide IdP, so {@code tideBrokerEnrollment} is true for
     * exactly that flow and it keeps granting. The plain registration form keeps granting
     * via the form frame.</p>
     */
    static boolean isSelfEnrollmentFrame(
            java.util.List<String> frameSignatures, boolean registrationAllowed,
            boolean tideBrokerEnrollment) {
        if (!registrationAllowed) {
            return false;
        }
        // Positive Tide-broker enrollment signal (IdP id = "tide"), resolved by the live
        // caller from the auth-session broker context. Independent of the frame list.
        if (tideBrokerEnrollment) {
            return true;
        }
        if (frameSignatures == null) {
            return false;
        }
        // Registration FORM frame → genuine browser self-sign-up.
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
