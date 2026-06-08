package org.tidecloak.iga.providers;

import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.jpa.UserAdapter;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.idm.UserRepresentation;
import org.tidecloak.iga.attestors.TideAttestor;
import org.tidecloak.iga.replay.IgaReplayExtension;
import org.tidecloak.iga.services.IgaQuarantineCache;
import org.tidecloak.iga.services.IgaUnsignedEntityService;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.persistence.EntityManager;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Wraps {@link UserAdapter} and intercepts user mutations for IGA.
 *
 * <h2>Two modes (same proven shape as {@link IgaClientScopeAdapter} /
 * {@link IgaRoleAdapter})</h2>
 * <ul>
 *   <li><b>Inline mode</b> ({@code captureMode == false}, default): wraps an
 *       already-approved, already-persisted user returned by
 *       {@code IgaUserProvider.getUserById/...}. Mutating calls
 *       (grantRole/joinGroup/setAttribute/…) record targeted delta change
 *       requests — the original inline interception behaviour, unchanged.</li>
 *   <li><b>Capture mode</b> ({@code captureMode == true}): wraps a
 *       <em>scratch</em> {@link UserEntity} that
 *       {@code IgaUserProvider.addUser} just persisted via the 5-arg
 *       local-storage {@code super.addUser(realm,id,username,false,false)} (NO
 *       default roles / required actions, so the captured rep carries ONLY what
 *       the admin sent). Every setter / relationship call still passes through
 *       to the real {@link UserAdapter} so KC's
 *       {@code UsersResource.createUser} flow builds the complete real model
 *       (lifecycle proof identical to client-scope), but each is ALSO
 *       <b>accumulated</b> into an in-memory {@link UserRepresentation}. The
 *       accumulated rep is emitted as the {@code CREATE_USER} change request at
 *       the terminal seam.</li>
 * </ul>
 *
 * <h2>CREATE_USER governs ONLY the 8 KC-routed token fields (product
 * decision)</h2>
 * User-create governance captures/replays EXACTLY the 8 fields KC's
 * {@code UsersResource.createUser} actually routes into the model:
 * {@code username}, {@code enabled}, {@code email}, {@code emailVerified},
 * {@code firstName}, {@code lastName}, {@code attributes}, {@code groups}.
 * Everything else is deliberately NOT captured, deferred or replayed:
 * <ul>
 *   <li><b>realmRoles / clientRoles</b> — roles are NOT capturable at
 *       user-create by any model-layer mechanism. Stock KC's
 *       {@code UsersResource.createUser} NEVER applies {@code realmRoles}/
 *       {@code clientRoles} — only {@code updateUserFromRep} +
 *       {@code createFederatedIdentities} + {@code createGroups} +
 *       {@code createCredentials}; {@code createRoleMappings} runs only on the
 *       import/replay path. So roles are discarded by stock KC too at
 *       user-create; {@code grantRole} does not fire during the admin create.
 *       Roles are assigned via the SEPARATE
 *       {@code POST /users/{id}/role-mappings/*} →
 *       {@code RoleMapperResource.addRealmRoleMappings} → {@code grantRole},
 *       which IGA already governs as a standalone {@code GRANT_ROLES} change
 *       request (the inline relationship-action path, UNCHANGED). The former
 *       capture-mode {@code rep.realmRoles}/{@code rep.clientRoles}
 *       accumulation was removed as a dead path.</li>
 *   <li><b>credentials</b> — a user's password is not governed; the user sets
 *       their own password post-approval (set-password email / self-service).
 *       The {@code credentialManager()} override + {@code CaptureCredentialManager}
 *       wrapper that earlier captured/replayed it were removed; KC's create
 *       flow may still invoke the real (super) credential manager but it is
 *       never accumulated.</li>
 *   <li><b>requiredActions</b> — login-flow gating, not token content.
 *       {@code addRequiredAction}/{@code removeRequiredAction} are no longer
 *       capture-intercepted (they pass straight through to {@code super}; the
 *       scratch user is rolled back at draft anyway).</li>
 *   <li><b>federatedIdentities</b> — IdP brokering, not token claims. The
 *       {@code IgaUserProvider.addFederatedIdentity} capture hook was reverted
 *       to plain delegation.</li>
 *   <li><b>createdTimestamp</b> — metadata, not token content.</li>
 *   <li><b>federationLink</b> — user-storage link, not token claims.</li>
 * </ul>
 * All seven non-governed fields are explicitly null'd on the
 * {@link UserRepresentation} before serialization at the terminal emit
 * ({@code rep.setRealmRoles(null)}, {@code setClientRoles(null)},
 * {@code setCredentials(null)}, {@code setRequiredActions(null)},
 * {@code setFederatedIdentities(null)}, {@code setCreatedTimestamp(null)},
 * {@code setFederationLink(null)}) so an inbound value can never ride along by
 * any path into a CR row. The scratch user is rolled back at draft regardless.
 *
 * <h2>User-create model-call trace</h2>
 * {@code UsersResource.createUser}:
 * <pre>
 *   profileProvider.create(USER_API, rep.getRawAttributes())
 *   UserModel user = profile.create();
 *        DefaultUserProfile.create:
 *          user = userSupplier.apply(attributes)        // == session.users()
 *                                                       //    .addUser(realm,username)
 *                                                       //    → IgaUserProvider.addUser
 *                                                       //      (2-arg)  → scratch
 *                                                       //      IgaUserAdapter (capture)
 *          updateInternal(user,false)                   // per writable attribute
 *               (sorted by key)
 *               user.setAttribute(name,values) — for ROOT attrs
 *               (USERNAME/FIRST_NAME/LAST_NAME/EMAIL) UserAdapter.setAttribute
 *               redirects to setUsername/setFirstName/setLastName/setEmail;
 *               custom attrs persist as attributes.
 *   UserResource.updateUserFromRep(profile,user,rep,session,false):
 *          if rep.isEnabled()!=null      user.setEnabled(..)
 *          if rep.isEmailVerified()!=null user.setEmailVerified(..)
 *          if createdTimestamp!=null     user.setCreatedTimestamp(..)
 *                  — NOT governed; passes through to super, never accumulated.
 *          if federationLink!=null       user.setFederationLink(..)
 *                  — NOT governed; passes through to super, never accumulated.
 *          reqActions!=null: per provider id user.addRequiredAction /
 *                  removeRequiredAction — NOT governed; passes straight through
 *                  to super (no capture interception), never accumulated.
 *          if a password credential isTemporary →
 *                  user.addRequiredAction(UPDATE_PASSWORD) — same: pass-through.
 *   RepresentationToModel.createFederatedIdentities(rep,session,realm,user):
 *        per identity
 *        session.users().addFederatedIdentity(realm,user,model)
 *        → IgaUserProvider.addFederatedIdentity — NOT governed; reverted to
 *        plain super delegation, never accumulated.
 *   RepresentationToModel.createGroups(session,rep,realm,user)
 *        per path user.joinGroup(group)
 *   RepresentationToModel.createCredentials(rep,session,realm,user,true)
 *        NOT intercepted — the
 *        credentialManager() override was removed; any inbound password is
 *        applied (if at all) to the throw-away scratch user via the real
 *        (super) credential manager and dies with the request-tx rollback. It
 *        is NEVER accumulated into the captured rep (see "Govern ONLY
 *        token-affecting user fields").
 *   adminEvent...resourcePath(uri, user.getId())...   // user.getId() #1
 *   Response.created(...user.getId()...)              // user.getId() #2
 * </pre>
 *
 * <h3>Snapshot-lossy fields</h3>
 * {@code ModelToRepresentation} for a user does NOT serialize group
 * memberships, and there is NO single unconditional terminal mutating model
 * call (enabled is conditional, the attribute loop is by-key, groups are
 * conditional). So — exactly like client-scope — we accumulate every
 * intercepted token-routed call into a {@link UserRepresentation} and emit
 * from the accumulator (never a live snapshot) at the post-build terminal
 * {@code getId()}. realmRoles, clientRoles, credentials, requiredActions,
 * federatedIdentities, createdTimestamp and federationLink are deliberately
 * excluded from the accumulator entirely (see "CREATE_USER governs ONLY the 8
 * KC-routed token fields").
 *
 * <h3>Deterministic terminal seam: {@code getId()} invoked DIRECTLY from
 * {@code UsersResource.createUser} (StackWalker resource boundary)</h3>
 * {@code user.getId()} is invoked early and unpredictably on the scratch
 * adapter via {@code UserAdapter.equals()} and
 * {@code hashCode()} during the JPA persistence context / user
 * events, and again from {@code DefaultUserProfile} /
 * {@code RepresentationToModel.*} mid-build. The fragile "first {@code getId()}
 * after a username was observed" trigger is replaced by a deterministic
 * StackWalker predicate ({@link #calledDirectlyFromCreateUserResource()})
 * proven by the trace: the ONLY {@code getId()} calls whose IMMEDIATE caller
 * (the nearest stack frame that is not this adapter's own {@code getId()} nor
 * the inherited {@code UserAdapter.equals/hashCode} that delegate straight
 * back into {@code getId()}) is {@code UsersResource.createUser} (or its
 * Quarkus {@code *quarkusrestinvoker*createUser*} wrapper) are the two
 * resource-terminal calls — ({@code adminEvent
 * ...resourcePath(uri, user.getId())}) and
 * ({@code Response.created(...user.getId()...)}), both AFTER the full model is
 * built. Every mid-build {@code getId()} has an intermediate non-resource
 * frame (UserAdapter.equals/hashCode, JPA proxy/persistence,
 * DefaultUserProfile, RepresentationToModel.createGroups/createCredentials/
 * createFederatedIdentities, group-event listeners) as its immediate caller →
 * NOT a terminal → falls straight through to {@code super.getId()} WITHOUT
 * emitting. {@link #usernameObserved} is retained as a defensive SECONDARY
 * gate. The fire-once guard latches the first (resourcePath) emit; the second
 * {@code getId()} (Response.created) falls through.
 *
 * <h3>REP_JSON faithfulness vs. replay (byte-faithful, replay UNCHANGED)</h3>
 * {@code IgaReplayDispatcher.replayCreateUser} deserializes {@code REP_JSON} to
 * a {@link UserRepresentation}, pins {@code id}/{@code username}, then calls
 * {@code RepresentationToModel.createUser} →
 * {@code DefaultExportImportManager.createUser},
 * which consumes EXACTLY: id+username (via 5-arg local addUser, NOT the
 * IGA 1-arg), enabled, createdTimestamp, email,
 * emailVerified, firstName, lastName, federationLink,
 * attributes, requiredActions,
 * credentials→createCredentials, federatedIdentities,
 * realmRoles/clientRoles→createRoleMappings, clientConsents,
 * notBefore, serviceAccountClientId, groups. The
 * accumulator below populates ONLY the 8 KC-routed token fields (username,
 * enabled, email, emailVerified, firstName, lastName, attributes, groups);
 * {@code groups} are group PATHS — the exact shape {@code createGroups}
 * consumes via {@code findGroupByPath}.
 * The other 7 fields are absent from REP_JSON and KC's import path is
 * null-safe for each absent one:
 * <ul>
 *   <li>{@code createRoleMappings} guards
 *       {@code if (userRep.getRealmRoles() != null)} AND
 *       {@code if (userRep.getClientRoles() != null)} → both loops skipped,
 *       user gets NO role mappings from the CREATE_USER replay (roles are
 *       governed separately via the GRANT_ROLES role-mapping CR).</li>
 *   <li>{@code createCredentials} guards
 *       {@code if (userRep.getCredentials() != null)} → loop skipped, user has
 *       NO password (no NPE).</li>
 *   <li>{@code requiredActions} guarded
 *       {@code if (userRep.getRequiredActions() != null)} → loop skipped.</li>
 *   <li>{@code createFederatedIdentities} guards
 *       {@code if (userRep.getFederatedIdentities() != null)} → loop skipped,
 *       no IdP link.</li>
 *   <li>{@code createdTimestamp} guarded
 *       {@code if (userRep.getCreatedTimestamp() != null)} → KC assigns its
 *       own create timestamp.</li>
 *   <li>{@code federationLink}: {@code user.setFederationLink(
 *       userRep.getFederationLink())} is
 *       unconditional but null-safe — passing null leaves the column at its
 *       default (no federation link), no NPE.</li>
 * </ul>
 */
public class IgaUserAdapter extends UserAdapter {

    private static final Logger log = Logger.getLogger(IgaUserAdapter.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    // UserAdapter.session is private, so we keep our own reference
    private final KeycloakSession igaSession;

    /**
     * When true this adapter wraps a scratch user mid-{@code createUser}; every
     * setter/relationship/credential call passes through to the real adapter
     * AND is accumulated; {@link #getId()} is the terminal emit seam (gated on
     * {@link #usernameObserved}).
     */
    private final boolean captureMode;

    /**
     * The KC 26.5.5 admin user-create resource method whose <em>direct</em>
     * presence as the immediate caller of {@code getId()} is the deterministic
     * terminal-emit signal. {@code UsersResource.createUser} is the ONLY method
     * that invokes {@code user.getId()} with NO intermediate non-adapter frame
     * (lines :175 adminEvent resourcePath, :177 Response.created — both AFTER
     * the full model is built by profile.create/updateUserFromRep/
     * createFederatedIdentities/createGroups/createCredentials). Every
     * mid-build {@code getId()} (UserAdapter.equals/hashCode, JPA persistence,
     * DefaultUserProfile, RepresentationToModel.*, group-event listeners) has
     * an intermediate non-resource frame and is therefore NOT a terminal.
     */
    private static final String KC_USERS_RESOURCE =
            "org.keycloak.services.resources.admin.UsersResource";
    private static final String KC_CREATE_USER = "createUser";

    /**
     * The KC 26.5.5 self-registration form-action whose {@code success(FormContext)}
     * method is the REGISTRATION terminal boundary. {@code RegistrationUserCreation.success}
     * calls {@code profile.create()} (services source line :155) — which routes through
     * {@code DefaultUserProfile.create} → {@code DeclarativeUserProfileProvider}'s
     * {@code createUserFactory().apply} → {@code session.users().addUser(realm, username)}
     * (the SAME 1-arg seam admin-create uses, yielding a capture-mode adapter) — and THEN,
     * with the full model already built, calls {@code user.setEnabled(true)} DIRECTLY at
     * services source line :159. That {@code setEnabled} call whose IMMEDIATE caller is
     * exactly {@code RegistrationUserCreation#success} is the deterministic registration
     * terminal-emit signal: it is post-build (profile.create has returned) and is NEVER
     * present on the admin-create path (admin enabled is applied by
     * {@code RepresentationToModel.updateUserFromRep}, not by RegistrationUserCreation),
     * the replay path (capture mode is false under IGA_REPLAY_ACTIVE so no setter emits),
     * or the partialImport path (no RegistrationUserCreation frame; the import-mode guard
     * also accumulates rather than emits). Match is EXACT: declaring class FQN ==
     * org.keycloak.authentication.forms.RegistrationUserCreation AND method == success.
     */
    private static final String KC_REGISTRATION_USER_CREATION =
            "org.keycloak.authentication.forms.RegistrationUserCreation";
    private static final String KC_REGISTRATION_SUCCESS = "success";

    // ---- accumulator (capture mode only) ----------------------------------
    private final UserRepresentation capturedRep = new UserRepresentation();
    private final Map<String, List<String>> capturedAttributes = new LinkedHashMap<>();
    private final Set<String> capturedGroupPaths = new LinkedHashSet<>();
    // NOTE: only the 8 KC-routed token fields are accumulated
    // (username, enabled, email, emailVerified, firstName, lastName,
    // attributes, groups). realmRoles/clientRoles are NOT part of CREATE_USER
    // (governed separately via the existing GRANT_ROLES role-mapping change
    // request — see the "Govern ONLY token-affecting user fields" section in
    // the class javadoc); credentials/requiredActions/federatedIdentities/
    // createdTimestamp/federationLink are likewise NOT governed.
    private final StringBuilder observedTrace = new StringBuilder();

    /**
     * True once a username has been observed via the capture path — KC's
     * {@code DefaultUserProfile.create} applies the username writable attribute
     * first, strictly after the scratch user is persisted and before the
     * terminal {@code getId()}. Partitions the early racy
     * equals/hashCode-driven {@code getId()} calls from the resource terminal
     * one (see class javadoc).
     */
    private boolean usernameObserved = false;

    /** Fire-once guard: only the first post-build getId() emits. */
    private boolean captureEmitted = false;

    /**
     * Skipped-getId breadcrumb counter: number of capture-mode {@code getId()}
     * calls that did NOT match the terminal predicate (the mid-build
     * runtime-proven getId#1–#6 plus the post-emit getId#8). Surfaced once in
     * the one INFO skip breadcrumb and in the EMIT line so an early/lossy emit
     * (e.g. a non-zero count of 0, or an emit before any skip) is immediately
     * diagnosable from the log without the old verbose per-getId stack dump.
     */
    private int skippedGetIdCount = 0;

    /**
     * One-shot breadcrumb latch: surface (exactly once) that a capture-mode
     * {@code getId()} was correctly skipped because its immediate caller was
     * NOT {@code UsersResource#createUser} (a mid-build getId, e.g. immediate
     * caller {@code UserCacheSession#addUser}). Proves the StackWalker
     * predicate suppressed the early/racy equals/hashCode/cache-driven
     * {@code getId()} rather than emitting a lossy rep. Recorded once (getId()
     * is invoked very frequently) so the observed-order trace shows
     * {@code …,getId(skip:not-UsersResource#createUser),…} interleaved with
     * setters.
     */
    private boolean skipTraced = false;

    /**
     * The last computed immediate caller logged on a SKIP. Used to de-dupe
     * consecutive identical-caller SKIP lines (getId() is invoked very
     * frequently mid-build) while ALWAYS logging the REAL computed
     * {@code <FQN>#<method>} at least once and again on any caller change — so
     * the log is self-evidencing for the next run.
     */
    private String lastSkipCaller = null;

    public IgaUserAdapter(KeycloakSession session, RealmModel realm, EntityManager em, UserEntity user) {
        this(session, realm, em, user, false);
    }

    public IgaUserAdapter(KeycloakSession session, RealmModel realm, EntityManager em,
                          UserEntity user, boolean captureMode) {
        super(session, realm, em, user);
        this.igaSession = session;
        this.captureMode = captureMode;
        if (captureMode) {
            // Identity is known up-front (the scratch user was persisted with
            // this id+username by the 5-arg super.addUser). Pre-seed so the
            // accumulator is self-consistent even if no setUsername fires.
            capturedRep.setId(super.getId());
            capturedRep.setUsername(super.getUsername());
            if (super.getUsername() != null) usernameObserved = true;
        }
    }

    private IgaChangeRequestService getService() {
        EntityManager em = igaSession.getProvider(JpaConnectionProvider.class).getEntityManager();
        return new IgaChangeRequestService(em, igaSession);
    }

    private boolean isIgaActive() {
        // In capture mode every per-setter override falls through to the real
        // UserAdapter (so createUser builds the complete model) AND accumulates;
        // interception/emit is concentrated at the terminal seam getId().
        if (captureMode) return false;
        IgaChangeRequestService service = getService();
        if (!service.isIgaEnabled(realm)) return false;
        Object replay = igaSession.getAttribute("IGA_REPLAY_ACTIVE");
        return !"true".equals(replay);
    }

    private void trace(String ev) {
        if (observedTrace.length() > 0) observedTrace.append(',');
        observedTrace.append(ev);
    }

    private static String yn(boolean b) {
        return b ? "Y" : "N";
    }

    // -------------------------------------------------------------------------
    // Deterministic terminal seam for CREATE_USER (capture mode only):
    // user.getId() invoked DIRECTLY by UsersResource.createUser.
    //
    // RUNTIME EVIDENCE (live POST /admin/realms/{realm}/users, IGA on — a real
    // capture-mode stack harvest, NOT a source guess):
    //   getId#1,#2,#3  immediate caller = UserCacheSession#fullyInvalidateUser /
    //                  #addUser (inside DefaultUserProfile#create)
    //   getId#4        immediate caller = UserCacheSession#addFederatedIdentity
    //   getId#5        immediate caller = UserStorageManager#addFederatedIdentity
    //   getId#6        immediate caller = JpaUserProvider#addFederatedIdentity
    //   getId#7        immediate caller = UsersResource#createUser  (:175
    //                  adminEvent.resourcePath — full model built)   ← TERMINAL
    //   getId#8        immediate caller = UsersResource#createUser  (:177
    //                  Response.created)                             ← fire-once
    // i.e. the ONLY getId() calls whose IMMEDIATE non-self caller is class
    // org.keycloak.services.resources.admin.UsersResource, method createUser are
    // the two resource-terminal calls (#7/#8). Every mid-build getId() (#1–#6)
    // has UserCacheSession / UserStorageManager / JpaUserProvider (driven by
    // DefaultUserProfile#create / RepresentationToModel#createFederatedIdentities)
    // as its immediate caller → NOT a terminal → falls straight through to
    // super.getId() WITHOUT emitting.
    //
    // The immediate caller is computed by walking the live stack and SKIPPING
    // only this adapter's own getId() and the inherited UserAdapter.{equals,
    // hashCode,getId} self-delegations; the FIRST remaining frame is the
    // "immediate caller". The match condition is EXACT: declaring class FQN ==
    // org.keycloak.services.resources.admin.UsersResource AND method == createUser
    // (mn.equals, not contains). The Quarkus generated
    // *quarkusrestinvoker*$createUser_* wrapper sits BELOW UsersResource#createUser
    // on the stack — it is NEVER the immediate caller — so it is deliberately
    // NOT matched here (matching it would be wrong; the runtime harvest proves
    // the resource-terminal calls' immediate frame is UsersResource#createUser
    // itself). usernameObserved is kept as a defensive SECONDARY gate. The
    // StackWalker runs only on getId() in capture mode for an IGA-governed user
    // create — a rare path — and short-circuits on the first surviving frame.
    // -------------------------------------------------------------------------

    /**
     * True iff {@code getId()}'s IMMEDIATE caller is
     * {@code org.keycloak.services.resources.admin.UsersResource#createUser}
     * (the resource terminal) — runtime-proven by the live capture-mode stack
     * harvest: getId#7 (caller {@code UsersResource#createUser} at :175
     * adminEvent.resourcePath) and getId#8 (:177 {@code Response.created}) are
     * the ONLY two whose immediate non-self caller is that exact class+method;
     * getId#1–#6 have {@code UserCacheSession#addUser/fullyInvalidateUser/
     * addFederatedIdentity}, {@code UserStorageManager#addFederatedIdentity} or
     * {@code JpaUserProvider#addFederatedIdentity} as their immediate caller
     * (driven by {@code DefaultUserProfile#create} /
     * {@code RepresentationToModel#createFederatedIdentities}) → NOT terminal.
     * The immediate caller is the FIRST stack frame after skipping only this
     * adapter's own {@code getId()} and the inherited
     * {@code UserAdapter.{equals,hashCode,getId}} self-delegations. The Quarkus
     * {@code *quarkusrestinvoker*$createUser_*} wrapper is BELOW
     * {@code UsersResource#createUser} on the stack (never the immediate
     * caller), so it is intentionally NOT matched.
     */
    private boolean calledDirectlyFromCreateUserResource() {
        return computeImmediateCaller() == TERMINAL;
    }

    /**
     * True iff the live {@code setEnabled()} call's IMMEDIATE caller is
     * {@code org.keycloak.authentication.forms.RegistrationUserCreation#success}
     * — the self-registration terminal boundary (see {@link #KC_REGISTRATION_USER_CREATION}).
     * Same {@link StackWalker} mechanism + skip rules as the admin predicate; the only
     * difference is the matched frame. Specific to registration: admin-create's
     * {@code setEnabled} comes from {@code RepresentationToModel.updateUserFromRep},
     * replay runs with capture mode off, and import has no such frame.
     */
    private boolean calledDirectlyFromRegistrationSuccess() {
        return computeImmediateCaller() == REGISTRATION_TERMINAL;
    }

    /** Sentinel: the computed immediate caller IS UsersResource#createUser. */
    private static final String TERMINAL = "<UsersResource#createUser>";

    /** Sentinel: the computed immediate caller IS RegistrationUserCreation#success. */
    private static final String REGISTRATION_TERMINAL =
            "<RegistrationUserCreation#success>";

    /**
     * Pure, unit-testable immediate-caller classifier. Given the ordered list of live
     * stack-frame signatures as {@code "<FQN>#<method>"} (innermost first, EXCLUDING
     * the current frame), apply the SAME skip rules as {@link #computeImmediateCaller}
     * (skip all {@code IgaUserAdapter} frames, the {@code java.lang.StackWalker}
     * machinery, and the inherited {@code UserAdapter.{equals,hashCode,getId}}
     * self-delegations) and return:
     * <ul>
     *   <li>{@link #TERMINAL} if the first surviving frame is
     *       {@code UsersResource#createUser} (admin-create terminal),</li>
     *   <li>{@link #REGISTRATION_TERMINAL} if it is
     *       {@code RegistrationUserCreation#success} (self-registration terminal),</li>
     *   <li>else the raw {@code "<FQN>#<method>"} of that first surviving frame
     *       (or {@code "<none>"} if every frame was skipped).</li>
     * </ul>
     * Driving this with synthetic frames lets the registration/admin/other partitions be
     * pinned in a plain unit test (the live {@link StackWalker} cannot be mocked).
     */
    static String classifyImmediateCaller(java.util.List<String> frameSignatures) {
        for (String sig : frameSignatures) {
            int hash = sig.lastIndexOf('#');
            String cn = hash >= 0 ? sig.substring(0, hash) : sig;
            String mn = hash >= 0 ? sig.substring(hash + 1) : "";

            if (IgaUserAdapter.class.getName().equals(cn)) {
                continue;
            }
            if (cn.startsWith("java.lang.StackWalker")) {
                continue;
            }
            if (UserAdapter.class.getName().equals(cn)
                    && ("equals".equals(mn) || "hashCode".equals(mn)
                        || "getId".equals(mn))) {
                continue;
            }
            if (KC_USERS_RESOURCE.equals(cn) && KC_CREATE_USER.equals(mn)) {
                return TERMINAL;
            }
            if (KC_REGISTRATION_USER_CREATION.equals(cn)
                    && KC_REGISTRATION_SUCCESS.equals(mn)) {
                return REGISTRATION_TERMINAL;
            }
            return cn + "#" + mn;
        }
        return "<none>";
    }

    /**
     * Walk the live stack and return the genuine external "immediate caller" of
     * {@code getId()} as {@code "<FQN>#<method>"}, or the {@link #TERMINAL}
     * sentinel iff that caller is exactly
     * {@code org.keycloak.services.resources.admin.UsersResource#createUser}.
     *
     * <p>Skip ALL {@code org.tidecloak.iga.providers.IgaUserAdapter} frames
     * (regardless of method) because this predicate runs INSIDE an
     * IgaUserAdapter helper ({@code calledDirectlyFromCreateUserResource} /
     * this method) — its OWN frames (plus {@code getId} and any lambda/
     * synthetic) would otherwise be computed as the "first surviving frame" and
     * mask the real caller, so the predicate never matched and the user
     * persisted ungoverned (201). Also skip the {@code java.lang.StackWalker}
     * machinery (JDK, normally absent but skipped defensively) and keep
     * skipping the inherited {@code UserAdapter.{equals,hashCode,getId}}
     * self-delegations. The FIRST surviving frame after these skips is the
     * genuine external immediate caller (runtime-proven: getId#7/#8 →
     * {@code UsersResource#createUser}; getId#1–#6 →
     * {@code UserCacheSession/UserStorageManager/JpaUserProvider}).</p>
     */
    private String computeImmediateCaller() {
        // Harvest the live frame signatures (innermost first) and delegate the
        // skip/match decision to the pure, unit-testable classifier so the
        // admin / registration / other partitions can be pinned without a live
        // stack. The skip rules + match conditions live in ONE place
        // (classifyImmediateCaller) — this method only adapts StackWalker to it.
        java.util.List<String> sigs = StackWalker
                .getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames
                        .map(f -> f.getDeclaringClass().getName() + "#"
                                + f.getMethodName())
                        .collect(java.util.stream.Collectors.toList()));
        return classifyImmediateCaller(sigs);
    }

    @Override
    public String getId() {
        // Hard guard: in a partialImport this capture adapter's row is
        // harvested by the batch-emit tx (buildImportUserPendingCr), NOT the
        // single-entity terminal seam. The StackWalker gate below already
        // never matches in import (the caller is
        // DefaultExportImportManager.createUser, not
        // UsersResource#createUser), so this is belt-and-braces: it can NEVER
        // single-entity-emit/throw inside an import. Phases 1–3 (no
        // partialImport frame) skip this and are byte-unchanged.
        if (captureMode && !captureEmitted
                && IgaImportMode.inPartialImport()) {
            return super.getId();
        }
        // Primary deterministic gate: the resource-boundary StackWalker
        // (immediate caller == UsersResource#createUser). Secondary defensive
        // gate: usernameObserved (KC's DefaultUserProfile.create always applies
        // the username writable attribute strictly before createUser:175).
        // Either gate failing → fall straight through to super.getId() WITHOUT
        // emitting. RUNTIME EVIDENCE: getId#3's immediate caller is
        // UserCacheSession#addUser (mid-build, inside DefaultUserProfile#create)
        // → predicate false → no emit; getId#7's immediate caller is
        // UsersResource#createUser (:175, full model built) → predicate true →
        // emit; getId#8 (:177) is latched out by the fire-once guard.
        // Compute the genuine external immediate caller ONCE per getId() (only
        // in capture mode, pre-emit) so the SKIP/EMIT logs print the ACTUAL
        // frame, never a templated example — the run is self-evidencing.
        String immediateCaller = (captureMode && !captureEmitted)
                ? computeImmediateCaller() : null;
        if (!captureMode || captureEmitted || !usernameObserved
                || immediateCaller != TERMINAL) {
            // Skipped-getId breadcrumb: a capture-mode getId() did NOT match
            // the terminal predicate (mid-build #1–#6 / the post-emit #8).
            // Counted; every skip-after-username logs the REAL computed
            // immediate caller (de-duped on consecutive identical callers so
            // the frequent racy getId()s don't flood the log, but ALWAYS at
            // least once and on any caller change) so a future SKIP shows the
            // exact frame for a definitive next step with zero ambiguity.
            if (captureMode && !captureEmitted) {
                skippedGetIdCount++;
                if (usernameObserved
                        && !immediateCaller.equals(lastSkipCaller)) {
                    lastSkipCaller = immediateCaller;
                    if (!skipTraced) {
                        skipTraced = true;
                        trace("getId(skip:not-UsersResource#createUser)");
                    }
                    log.infof("IGA user-capture SKIP: immediate caller=%s "
                            + "(not UsersResource#createUser) — suppressed, no "
                            + "emit (skippedGetIdCount=%d)",
                            immediateCaller, skippedGetIdCount);
                }
            }
            return super.getId();
        }
        // Arm the fire-once guard BEFORE any further model/service call so the
        // emit path cannot re-enter this seam and the second getId() at
        // UsersResource.createUser:177 (runtime getId#8) falls through.
        captureEmitted = true;
        trace("getId#EMIT(UsersResource#createUser)");
        emitPersistPendingCreateUserCr(ADMIN_TERMINAL_LABEL);
        // unreachable — emit always throws IgaPendingApprovalException
        return super.getId();
    }

    /**
     * Shared CREATE_USER persist-pending emit, fired by EITHER terminal seam:
     * the admin-create {@code getId()} seam (immediate caller
     * {@code UsersResource#createUser}) or the self-registration {@code setEnabled}
     * seam (immediate caller {@code RegistrationUserCreation#success}). Both seams
     * reach here ONLY after KC has fully built the user model on this capture
     * adapter, so the in-memory accumulator is complete and identical to what the
     * pre-existing admin path produced. Always throws
     * {@link IgaPendingApprovalException} (→ HTTP 202 + Location); never returns.
     *
     * @param terminalLabel the human-readable terminal frame, for the EMIT/PERSIST
     *                       log lines (admin vs registration) — diagnostics only.
     */
    private void emitPersistPendingCreateUserCr(String terminalLabel) {
        String userId = super.getId();
        String username = capturedRep.getUsername() != null
                ? capturedRep.getUsername() : super.getUsername();

        Map<String, Object> row = buildCapturedUserRow();

        String requestedBy = getCurrentUserId();

        // ─────────────────────────────────────────────────────────────────────
        // ★ PERSIST-PENDING (enroll-before-commit).
        //
        // HISTORY: this seam used to setRollbackOnly() so the fully-built scratch
        // user died with the request tx and ONLY the CR survived. That made a
        // post-flip Tide user UN-ENROLLABLE while PENDING (no live row for
        // LinkTideAccount to write vuid/tideUserKey onto), so user_identity was
        // signed pre-enrollment and the login batch-verify failed.
        //
        // NEW: we PERSIST the pending user. DefaultKeycloakSession#close() COMMITS
        // the request tx unless getRollbackOnly() is set (it inspects ONLY the
        // rollback flag — a propagating exception does NOT auto-rollback), so by
        // NOT setting rollback-only the live user (already fully built by KC —
        // admin: UsersResource.createUser:175 (profile.create + updateUserFromRep
        // + createGroups); registration: RegistrationUserCreation.success:155
        // profile.create — then we fire here AFTER the build) survives. Its
        // UserEntity.attestation column is NULL (KC never stamps it) — that NULL is
        // the "pending/quarantined" marker.
        //
        // QUARANTINE / FAIL-CLOSED until commit (two modes, mode-aware):
        //   • Tide realm (iga.attestor=="tide"): the login signed-token path
        //     (DefaultTokenManager.encodeTideSignedTokens →
        //     IgaAttestationExporterProvider.exportSignedAccessTokenUnits →
        //     replayOrFailClosed) FAIL-CLOSES on the NULL user_identity column, so
        //     the pending user CANNOT mint a real login token. We must NOT write the
        //     IGA_UNSIGNED_ENTITY sidecar here: it would flip IgaUserAdapter.isEnabled()
        //     to false, and the enrollment browser flow (AuthenticationProcessor.
        //     validateUser → USER_DISABLED) would reject the user BEFORE LinkTideAccount
        //     can run. Enabled-but-attestation-NULL is the required state.
        //   • Tideless realm (iga.attestor!="tide"): tokens are NOT signed, so there
        //     is no replayOrFailClosed guard. We quarantine via the IGA_UNSIGNED_ENTITY
        //     sidecar (isEnabled()→false hard-refuses every login/token checkpoint)
        //     until the CREATE_USER CR commits. Tideless realms have no Tide enrollment,
        //     so the sidecar does NOT block any enroll flow.
        //
        // The non-governed live state KC applied to the scratch user before the
        // terminal (credentials/password + federated identities — the OLD rollback
        // discarded these; CREATE_USER governs ONLY the 8 token fields, REP_JSON
        // nulls them) is STRIPPED so the persisted live user matches the governed
        // representation. The user sets their own password / links Tide post-approval.
        // ─────────────────────────────────────────────────────────────────────
        stripNonGovernedLiveState();

        boolean tideRealm = TideAttestor.ID.equals(realm.getAttribute("iga.attestor"));

        String[] crIdHolder = new String[1];
        KeycloakModelUtils.runJobInTransaction(igaSession.getKeycloakSessionFactory(), newSession -> {
            RealmModel newRealm = newSession.realms().getRealm(realm.getId());
            EntityManager newEm = newSession.getProvider(JpaConnectionProvider.class).getEntityManager();
            IgaChangeRequestService newService = new IgaChangeRequestService(newEm, newSession);
            crIdHolder[0] = newService.create(newRealm, "USER", userId,
                    "CREATE_USER", List.of(row), requestedBy).getId();
            // Tideless quarantine: register the persisted-but-pending user in the
            // unsigned-entity sidecar, keyed to its CREATE_USER CR id so the commit
            // can clear it (IgaReplayDispatcher.replayCreateUser → clearByAdoptCr).
            // Tide realms intentionally skip this (replayOrFailClosed is the guard,
            // and the sidecar would block enrollment — see the block comment above).
            if (!tideRealm) {
                IgaUnsignedEntityService.markUnsigned(newEm, newRealm.getId(),
                        IgaReplayExtension.ENTITY_TYPE_USER, userId, crIdHolder[0]);
                newEm.flush();
            }
        });

        // ─────────────────────────────────────────────────────────────────────
        // ★ REGISTRATION default-role grant (accept-unattested self-reg aud fix).
        //
        // For the SELF-REGISTRATION terminal ONLY, grant the realm default-role +
        // join the realm default groups onto the just-persisted pending user, so a
        // self-reg user who is admitted UNSIGNED at login (RegOn / accept-unattested:
        // the CREATE_USER CR is filed PENDING and NEVER commits) still HOLDS the
        // default-roles. Without this the self-reg user is ROLELESS → KC builds the
        // token with empty resource_access → no `account` audience → the TVE
        // bidirectional check (TokenValidationEngine:965) rejects with
        // "attested claim 'aud' is suppressed in token" (the producer's metadata
        // closure attests aud=[account] from the default-role composite, and the ORK
        // universal-inherits the realm default-role, so the token MUST carry it).
        //
        // SUPPRESSION (no nested CR): we are still in captureMode here, so
        // grantRole/joinGroup short-circuit to super.* (plain pass-through, NO
        // GRANT_ROLES/JOIN_GROUPS CR is emitted). This mirrors exactly how
        // IgaReplayDispatcher.replayCreateUser :559-566 grants default-roles at
        // commit under IGA_REPLAY_ACTIVE.
        //
        // CLOSURE INVARIANT (gate still admits): the realm default-role id is the
        // D1b exclusion in RealmAttestationExporter.perUserUnits :418 — a user
        // holding ONLY default-roles → empty role_ids → NO user_role_mapping_set
        // unit. So the user HOLDS default-roles (KC token carries the account aud)
        // AND the producer closure has no role-mapping unit (the default-roles-only
        // gate still admits the unsigned user_identity). Both invariants hold.
        //
        // SCOPE: admin-create (terminal=UsersResource#createUser) is UNCHANGED — its
        // CREATE_USER CR commits and the D3 replay grant handles default-roles there;
        // double-granting would be wrong. Strictly gated on the registration terminal.
        if (isRegistrationTerminal(terminalLabel)) {
            grantDefaultRolesForRegistration();
        }

        // NOTE: NO setRollbackOnly() — the request tx COMMITS so the pending user
        // persists. The CR was written on a separate session above (so it is durable
        // independently), and the 202 below is still returned via the exception mapper.
        log.infof("IGA user-capture PERSIST-PENDING: terminal=%s user=%s uuid=%s realm=%s "
                + "mode=%s — live user persisted, UserEntity.attestation NULL "
                + "(pending), %s; CREATE_USER CR=%s. Enrollable while PENDING; "
                + "real login fail-closed until commit finalizes (stamps user_identity).",
                terminalLabel, username, userId, realm.getName(),
                tideRealm ? "tide" : "tideless",
                tideRealm ? "no quarantine sidecar (replayOrFailClosed guards login)"
                          : "IGA_UNSIGNED_ENTITY sidecar set (isEnabled()=false guards login)",
                crIdHolder[0]);

        throw new IgaPendingApprovalException(crIdHolder[0], "USER", "CREATE_USER");
    }

    /**
     * Pure decision: is this persist-pending emit firing from the SELF-REGISTRATION
     * terminal (so the just-persisted user must be granted the realm default-role,
     * because the accept-unattested self-reg login admits the user UNSIGNED and its
     * CREATE_USER CR never commits → the D3 replay grant never runs)?
     *
     * <p>True iff {@code terminalLabel} is exactly the registration terminal frame
     * {@code "RegistrationUserCreation#success"} (the value passed by the
     * registration {@link #setEnabled} seam). The admin terminal
     * ({@code "UsersResource#createUser"}) returns false — its CR commits and the
     * {@code IgaReplayDispatcher.replayCreateUser} D3 grant assigns default-roles
     * there, so granting here would double-grant. Factored out as a pure,
     * frame-list-free predicate so the registration-vs-admin scoping is unit-pinnable
     * without a live stack/session.</p>
     */
    /** The exact terminalLabel the registration {@link #setEnabled} seam passes. */
    static final String REGISTRATION_TERMINAL_LABEL = "RegistrationUserCreation#success";

    /** The exact terminalLabel the admin {@link #getId} seam passes. */
    static final String ADMIN_TERMINAL_LABEL = "UsersResource#createUser";

    static boolean isRegistrationTerminal(String terminalLabel) {
        return REGISTRATION_TERMINAL_LABEL.equals(terminalLabel);
    }

    /**
     * Grant the realm default-role + join the realm default groups onto {@code this}
     * just-persisted pending user, mirroring stock KC
     * {@code JpaUserProvider.addUser} and the commit-time D3 grant
     * ({@code IgaReplayDispatcher.replayCreateUser:559-566}).
     *
     * <p>★ Suppression (no nested CR): we are in {@code captureMode} here, so the
     * overridden {@link #grantRole}/{@link #joinGroup} short-circuit to {@code super.*}
     * (plain pass-through) and do NOT spawn a GRANT_ROLES/JOIN_GROUPS change request —
     * exactly as the replay grant runs under {@code IGA_REPLAY_ACTIVE}. The granted
     * default-role edge is NOT per-user signed: the producer's D1b exclusion
     * ({@code RealmAttestationExporter.perUserUnits} / {@code userRoleMappingSet}
     * filters the realm default-role id) keeps the closure free of a
     * {@code user_role_mapping_set} unit, so the default-roles-only gate still admits.</p>
     */
    private void grantDefaultRolesForRegistration() {
        if (!captureMode) {
            // Defensive: only ever invoked from the capture-mode persist-pending emit.
            return;
        }
        org.keycloak.models.RoleModel defaultRole = realm.getDefaultRole();
        if (defaultRole != null) {
            grantRole(defaultRole);
        }
        realm.getDefaultGroupsStream().forEach(this::joinGroup);
        log.infof("IGA self-reg PERSIST-PENDING: granted realm default-role%s + default groups "
                + "to self-registered user uuid=%s (no nested CR — captureMode pass-through; "
                + "default-role excluded from the producer user_role_mapping_set unit, "
                + "so the token carries the account aud and the gate still admits).",
                defaultRole != null ? " " + defaultRole.getName() : " (none)", super.getId());
    }

    /**
     * Strip the live state KC applied to the scratch user that CREATE_USER does
     * NOT govern (credentials + federated identities), so the PERSISTED pending
     * user matches the governed {@link #buildCapturedUserRow()} REP_JSON exactly
     * (which explicitly nulls credentials/federatedIdentities). Before this change
     * the request-tx rollback discarded them; now that the user persists we must
     * remove them here or an un-governed create-time password / IdP link would
     * silently survive onto the live (committed) user.
     *
     * <p>Governed token fields (username/enabled/email/emailVerified/first/last/
     * attributes/groups) are LEFT intact — they are the CREATE_USER closure. Roles
     * are not applied by KC's createUser at all (governed separately), so there is
     * nothing to strip there.</p>
     */
    private void stripNonGovernedLiveState() {
        try {
            // Credentials (any create-time password). credentialManager() is the
            // real super manager (the capture override was removed).
            credentialManager().getStoredCredentialsStream()
                    .map(org.keycloak.credential.CredentialModel::getId)
                    .filter(java.util.Objects::nonNull)
                    .collect(java.util.stream.Collectors.toList())
                    .forEach(id -> {
                        try {
                            credentialManager().removeStoredCredentialById(id);
                        } catch (RuntimeException re) {
                            log.debugf(re, "PERSIST-PENDING: failed removing credential %s for user %s",
                                    id, super.getId());
                        }
                    });
        } catch (RuntimeException re) {
            log.debugf(re, "PERSIST-PENDING: credential strip skipped for user %s", super.getId());
        }
        try {
            // Federated identities applied by createFederatedIdentities (:171).
            igaSession.users().getFederatedIdentitiesStream(realm, this)
                    .map(org.keycloak.models.FederatedIdentityModel::getIdentityProvider)
                    .filter(java.util.Objects::nonNull)
                    .collect(java.util.stream.Collectors.toList())
                    .forEach(idp -> {
                        try {
                            igaSession.users().removeFederatedIdentity(realm, this, idp);
                        } catch (RuntimeException re) {
                            log.debugf(re, "PERSIST-PENDING: failed removing fed-identity %s for user %s",
                                    idp, super.getId());
                        }
                    });
        } catch (RuntimeException re) {
            log.debugf(re, "PERSIST-PENDING: fed-identity strip skipped for user %s", super.getId());
        }
    }

    /**
     * Build the {@code CREATE_USER} CR row from the accumulator — the SINGLE
     * source of truth shared by the single-entity terminal seam
     * ({@link #getId()}) and the partialImport batch path
     * ({@link #buildImportUserPendingCr()}). Identical rep/row contract in
     * both cases (so {@code IgaReplayDispatcher.replayCreateUser} is
     * byte-unchanged). NO side effects (no CR write, no throw, no
     * rollback-only).
     */
    private Map<String, Object> buildCapturedUserRow() {
        String userId = super.getId();
        String username = capturedRep.getUsername() != null
                ? capturedRep.getUsername() : super.getUsername();

        // Build the CR rep entirely from the accumulator (authoritative — the
        // live model never serializes groups/roles, and getId() can fire early
        // via equals/hashCode; see class javadoc). ONLY token-affecting fields
        // are populated.
        UserRepresentation rep = new UserRepresentation();
        rep.setId(userId);
        rep.setUsername(username);
        if (capturedRep.isEnabled() != null) rep.setEnabled(capturedRep.isEnabled());
        if (capturedRep.getEmail() != null) rep.setEmail(capturedRep.getEmail());
        if (capturedRep.isEmailVerified() != null) rep.setEmailVerified(capturedRep.isEmailVerified());
        if (capturedRep.getFirstName() != null) rep.setFirstName(capturedRep.getFirstName());
        if (capturedRep.getLastName() != null) rep.setLastName(capturedRep.getLastName());
        if (!capturedAttributes.isEmpty()) {
            Map<String, List<String>> attrs = new LinkedHashMap<>();
            for (Map.Entry<String, List<String>> e : capturedAttributes.entrySet()) {
                attrs.put(e.getKey(), new ArrayList<>(e.getValue()));
            }
            rep.setAttributes(attrs);
        }
        if (!capturedGroupPaths.isEmpty()) {
            rep.setGroups(new ArrayList<>(capturedGroupPaths));
        }
        // Belt-and-braces: CREATE_USER governs ONLY the 8 KC-routed token
        // fields (username, enabled, email, emailVerified, firstName, lastName,
        // attributes, groups). Explicitly null every non-governed field so an
        // inbound value in the create request can NEVER ride along into the CR
        // through any path (none are accumulated; this proves the serialized
        // rep carries no `realmRoles`, `clientRoles`, `credentials`,
        // `requiredActions`, `federatedIdentities`, `createdTimestamp` or
        // `federationLink`).
        //
        // realmRoles/clientRoles in particular: roles are NOT capturable at
        // user-create — stock KC's UsersResource.createUser NEVER applies
        // realmRoles/clientRoles (only updateUserFromRep +
        // createFederatedIdentities + createGroups + createCredentials;
        // createRoleMappings runs only on the import/replay path). Roles are
        // assigned via the separate POST /users/{id}/role-mappings/* →
        // grantRole, which IGA already governs as a standalone GRANT_ROLES
        // change request (untouched). The user sets their own password after
        // approval; required actions / IdP links / metadata are not part of
        // the issued token and are intentionally out of scope.
        rep.setRealmRoles(null);
        rep.setClientRoles(null);
        rep.setCredentials(null);
        rep.setRequiredActions(null);
        rep.setFederatedIdentities(null);
        rep.setCreatedTimestamp(null);
        rep.setFederationLink(null);

        String repJson;
        try {
            repJson = MAPPER.writeValueAsString(rep);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new RuntimeException(
                    "IGA capture CREATE_USER: failed to serialize captured "
                    + "UserRepresentation for user=" + username, e);
        }

        int attrs = rep.getAttributes() == null ? 0 : rep.getAttributes().size();
        int groups = rep.getGroups() == null ? 0 : rep.getGroups().size();
        // ONE concise INFO emit line. The immediate caller is printed from the
        // ACTUAL computed value (the TERMINAL sentinel resolves to the real
        // UsersResource#createUser frame) — self-evidencing, not a template.
        log.infof("IGA user-capture EMIT: immediate caller=UsersResource#createUser "
                + "acc=[username=%s,enabled=%s,email=%s,first=%s,last=%s,"
                + "emailVerified=%s,attrs=%d,groups=%d] chars=%d "
                + "(skippedGetIdCount=%d user=%s uuid=%s; CR written in a "
                + "separate tx, request tx rollback-only so the scratch user + "
                + "memberships are discarded; the 8 token fields, no password, "
                + "replay on commit)",
                yn(username != null),
                rep.isEnabled() == null ? "-" : (rep.isEnabled() ? "Y" : "N"),
                yn(rep.getEmail() != null),
                yn(rep.getFirstName() != null),
                yn(rep.getLastName() != null),
                rep.isEmailVerified() == null ? "-"
                        : (rep.isEmailVerified() ? "Y" : "N"),
                attrs, groups, repJson.length(),
                skippedGetIdCount, username, userId);

        // rowsJson contract (must match IgaReplayDispatcher.replayCreateUser):
        // ID = user UUID, USERNAME = lowercased username, REALM_ID = realm UUID,
        // REP_JSON = the full UserRepresentation JSON.
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("ID", userId);
        row.put("USERNAME", username == null ? null : username.toLowerCase());
        row.put("REALM_ID", realm.getId());
        row.put("REP_JSON", repJson);
        return row;
    }

    /**
     * partialImport batch path. Build this user's
     * {@code CREATE_USER} {@link IgaImportMode.PendingCr} from the
     * accumulator. Called by {@link IgaImportMode.BatchEmitTransaction#commit}
     * AFTER {@code DefaultExportImportManager.createUser} has applied every
     * setter / {@code joinGroup} to the scratch user (so the accumulator is
     * complete) and BEFORE the scratch JPA tx commits. Uses the SAME
     * {@link #buildCapturedUserRow()} contract as the single-entity seam, so
     * replay is identical and {@code IgaReplayDispatcher} is byte-unchanged.
     * NO throw, NO rollback-only here — the batch-emit tx owns that.
     */
    IgaImportMode.PendingCr buildImportUserPendingCr() {
        if (!captureMode) {
            return null;
        }
        String userId = super.getId();
        Map<String, Object> row = buildCapturedUserRow();
        String requestedBy = getCurrentUserId();
        log.infof("IGA multi-entity ACCUM: CREATE_USER %s (uuid=%s) — row "
                + "harvested at batch emit from the 5-arg local-storage "
                + "addUser import path (the bypass is closed)",
                row.get("USERNAME"), userId);
        return new IgaImportMode.PendingCr("USER", userId, "CREATE_USER",
                List.of(row), requestedBy);
    }

    // -------------------------------------------------------------------------
    // Non-token fields are NOT governed.
    //
    // credentials: the credentialManager() override and CaptureCredentialManager
    // delegate were REMOVED. credentialManager() is no longer overridden, so the
    // real (super) UserAdapter credential manager is used unchanged — KC's
    // createUser flow (UsersResource.createUser:174 →
    // RepresentationToModel.createCredentials) is simply NOT intercepted; any
    // inbound password is applied (if at all) to the throw-away scratch user
    // and dies with the request-tx rollback. It is NEVER accumulated, and
    // getId() explicitly nulls rep.credentials before serialization.
    //
    // requiredActions / federatedIdentities / createdTimestamp /
    // federationLink: also NOT governed (not part of the issued token).
    // addRequiredAction/removeRequiredAction are no longer capture-intercepted
    // (plain super pass-through, see below); the
    // IgaUserProvider.addFederatedIdentity capture hook was reverted to plain
    // super delegation; createdTimestamp/federationLink are not accumulated.
    // All four are explicitly null'd on the rep before serialization in
    // getId(). The approved user sets their own password (set-password email /
    // self-service) post-approval.
    // -------------------------------------------------------------------------

    boolean isCaptureMode() {
        return captureMode;
    }

    // -------------------------------------------------------------------------
    // Identity / scalar setters — capture mode accumulates; inline mode
    // unchanged (root scalars were never intercepted inline, so super-only).
    // -------------------------------------------------------------------------

    @Override
    public void setUsername(String username) {
        super.setUsername(username);
        if (captureMode) {
            capturedRep.setUsername(super.getUsername());
            usernameObserved = true;
            trace("setUsername");
        }
    }

    @Override
    public void setEnabled(boolean enabled) {
        super.setEnabled(enabled);
        if (captureMode) {
            capturedRep.setEnabled(enabled);
            trace("setEnabled:" + enabled);

            // ★ REGISTRATION TERMINAL SEAM.
            // Self-registration never reaches the admin getId() terminal
            // (UsersResource#createUser): RegistrationUserCreation.success
            // (:155 profile.create → the 1-arg addUser capture seam → full model
            // build) then calls user.setEnabled(true) DIRECTLY at services :159,
            // AFTER the model is fully built. So when THIS setEnabled's immediate
            // caller is exactly RegistrationUserCreation#success we are at the
            // registration terminal: fire the SAME persist-pending CREATE_USER CR
            // as admin-create. Gated identically to the admin seam:
            //   • capture mode (already inside this branch),
            //   • not already emitted (fire-once),
            //   • NOT a partialImport (the import path accumulates via the batch,
            //     and has no RegistrationUserCreation frame anyway — belt+braces),
            //   • immediate caller == RegistrationUserCreation#success.
            // Specificity: admin enabled is applied by
            // RepresentationToModel.updateUserFromRep (NOT RegistrationUserCreation),
            // replay runs with captureMode==false (this branch is skipped), and
            // import is excluded by the guard below. usernameObserved is true here
            // because profile.create applied the username before returning to
            // success() — kept as a defensive secondary gate, mirroring getId().
            if (!captureEmitted
                    && !IgaImportMode.inPartialImport()
                    && usernameObserved
                    && calledDirectlyFromRegistrationSuccess()) {
                captureEmitted = true;
                trace("setEnabled#EMIT(RegistrationUserCreation#success)");
                log.infof("IGA user-capture: registration terminal reached "
                        + "(setEnabled immediate caller=RegistrationUserCreation#success) "
                        + "— firing persist-pending CREATE_USER CR for self-registered "
                        + "user uuid=%s", super.getId());
                emitPersistPendingCreateUserCr(REGISTRATION_TERMINAL_LABEL);
            }
        }
    }

    @Override
    public void setEmail(String email) {
        super.setEmail(email);
        if (captureMode) {
            capturedRep.setEmail(super.getEmail());
            trace("setEmail");
        }
    }

    @Override
    public void setEmailVerified(boolean verified) {
        super.setEmailVerified(verified);
        if (captureMode) {
            capturedRep.setEmailVerified(verified);
            trace("setEmailVerified:" + verified);
        }
    }

    @Override
    public void setFirstName(String firstName) {
        super.setFirstName(firstName);
        if (captureMode) {
            capturedRep.setFirstName(firstName);
            trace("setFirstName");
        }
    }

    @Override
    public void setLastName(String lastName) {
        super.setLastName(lastName);
        if (captureMode) {
            capturedRep.setLastName(lastName);
            trace("setLastName");
        }
    }

    // setFederationLink / setCreatedTimestamp are NOT overridden — these fields
    // are not governed (not part of the issued token). KC's createUser may call
    // them on the scratch user; they pass straight through to the inherited
    // UserAdapter and die with the request-tx rollback. Never accumulated.

    // addRequiredAction / removeRequiredAction are NOT overridden at all —
    // required actions are login-flow gating, not token content, and are not
    // governed. KC's createUser flow (UserResource.updateUserFromRep:307-330)
    // may call them on the scratch user; they pass straight through to the
    // inherited UserAdapter (no capture interception, no inline CR — required
    // actions were never inline-governed) and die with the request-tx
    // rollback. An inbound UPDATE_PASSWORD on the create request therefore
    // never reaches the CR (getId() also explicitly nulls
    // rep.requiredActions, belt-and-braces).

    // -------------------------------------------------------------------------
    // Role mappings.
    //
    // CREATE_USER does NOT govern roles. Roles are NOT capturable at
    // user-create by any model-layer mechanism: stock KC's
    // UsersResource.createUser NEVER applies realmRoles/clientRoles — it
    // runs only updateUserFromRep + createFederatedIdentities + createGroups +
    // createCredentials; createRoleMappings runs only on the import/replay
    // path. So grantRole/deleteRoleMapping do NOT fire during an admin user
    // create at all, and there is intentionally NO capture-mode accumulation
    // here (the former rep.realmRoles/rep.clientRoles capture path was removed
    // as dead — getId() also explicitly nulls rep.realmRoles/rep.clientRoles,
    // belt-and-braces). In capture mode these simply pass straight through to
    // the inherited UserAdapter (the scratch user is rolled back at draft
    // anyway).
    //
    // Roles are assigned via the SEPARATE POST /users/{id}/role-mappings/* →
    // RoleMapperResource.addRealmRoleMappings → grantRole, which IGA already
    // governs as a standalone GRANT_ROLES / REVOKE_ROLES change request on the
    // INLINE path below. That inline relationship-action governance is
    // UNCHANGED.
    // -------------------------------------------------------------------------

    @Override
    public void grantRole(RoleModel role) {
        if (captureMode) {
            // Roles are not part of CREATE_USER and (per the KC trace) do not
            // fire during admin user-create anyway — plain pass-through, no
            // accumulation. The standalone GRANT_ROLES governance is the
            // inline path below (untouched).
            super.grantRole(role);
            return;
        }
        if (!isIgaActive()) {
            super.grantRole(role);
            return;
        }
        IgaChangeRequestService service = getService();
        String userId = getId();
        checkNoPendingCr(service, userId);
        String requestedBy = getCurrentUserId();
        service.create(realm, "USER", userId, "GRANT_ROLES",
                List.of(Map.of("USER_ID", userId, "ROLE_ID", role.getId())),
                requestedBy);
    }

    @Override
    public void deleteRoleMapping(RoleModel role) {
        if (captureMode) {
            super.deleteRoleMapping(role);
            return;
        }
        if (!isIgaActive()) {
            super.deleteRoleMapping(role);
            return;
        }
        IgaChangeRequestService service = getService();
        String userId = getId();
        checkNoPendingCr(service, userId);
        String requestedBy = getCurrentUserId();
        service.create(realm, "USER", userId, "REVOKE_ROLES",
                List.of(Map.of("USER_ID", userId, "ROLE_ID", role.getId())),
                requestedBy);
    }

    // -------------------------------------------------------------------------
    // Group memberships.
    //
    // capture: pass through + accumulate the group PATH (the exact shape
    // RepresentationToModel.createGroups
    // consumes — userRep.getGroups() are paths resolved via findGroupByPath).
    // inline: targeted JOIN_GROUPS / LEAVE_GROUPS CR (unchanged).
    // -------------------------------------------------------------------------

    @Override
    public void joinGroup(GroupModel group) {
        if (captureMode) {
            super.joinGroup(group);
            if (group != null) {
                capturedGroupPaths.add(KeycloakModelUtils.buildGroupPath(group));
                trace("joinGroup:" + group.getName());
            }
            return;
        }
        if (!isIgaActive()) {
            super.joinGroup(group);
            return;
        }
        IgaChangeRequestService service = getService();
        String userId = getId();
        checkNoPendingCr(service, userId);
        String requestedBy = getCurrentUserId();
        service.create(realm, "USER", userId, "JOIN_GROUPS",
                List.of(Map.of("USER", userId, "GROUP", group.getId())),
                requestedBy);
    }

    @Override
    public void joinGroup(GroupModel group, org.keycloak.models.MembershipMetadata metadata) {
        if (captureMode) {
            super.joinGroup(group, metadata);
            if (group != null) {
                capturedGroupPaths.add(KeycloakModelUtils.buildGroupPath(group));
                trace("joinGroup:" + group.getName());
            }
            return;
        }
        if (!isIgaActive()) {
            super.joinGroup(group, metadata);
            return;
        }
        IgaChangeRequestService service = getService();
        String userId = getId();
        checkNoPendingCr(service, userId);
        String requestedBy = getCurrentUserId();
        service.create(realm, "USER", userId, "JOIN_GROUPS",
                List.of(Map.of("USER", userId, "GROUP", group.getId())),
                requestedBy);
    }

    @Override
    public void leaveGroup(GroupModel group) {
        if (captureMode) {
            super.leaveGroup(group);
            if (group != null) {
                capturedGroupPaths.remove(KeycloakModelUtils.buildGroupPath(group));
                trace("leaveGroup:" + group.getName());
            }
            return;
        }
        if (!isIgaActive()) {
            super.leaveGroup(group);
            return;
        }
        IgaChangeRequestService service = getService();
        String userId = getId();
        checkNoPendingCr(service, userId);
        String requestedBy = getCurrentUserId();
        service.create(realm, "USER", userId, "LEAVE_GROUPS",
                List.of(Map.of("USER", userId, "GROUP", group.getId())),
                requestedBy);
    }

    // -------------------------------------------------------------------------
    // Attribute interception (USER_ATTRIBUTE).
    //
    // capture: pass through to the real adapter (so the model is built) AND
    // accumulate. UserAdapter.setAttribute/setSingleAttribute redirect ROOT
    // attrs (USERNAME/FIRST_NAME/LAST_NAME/EMAIL) to the scalar setters, but
    // DefaultUserProfile calls setAttribute(name, values) for EVERY writable
    // attribute (including the root ones) — so to keep the rep faithful we
    // mirror that redirect here BEFORE delegating: root attrs go to the
    // capturedRep scalar fields (where DefaultExportImportManager.createUser
    // reads firstName/lastName/email/username), custom attrs go to
    // rep.attributes (where createUser:989-996 reads them). super still applies
    // them so the scratch model is complete (discarded by rollback).
    //
    // inline mode: the existing one-pending-CR-per-entity rule (unchanged;
    // KNOWN LIMITATION below).
    // -------------------------------------------------------------------------

    @Override
    public void setSingleAttribute(String name, String value) {
        if (captureMode) {
            super.setSingleAttribute(name, value);
            accumulateAttribute(name, value == null ? null : List.of(value));
            trace("setSingleAttribute:" + name);
            return;
        }
        if (!isIgaActive()) {
            super.setSingleAttribute(name, value);
            return;
        }
        IgaChangeRequestService service = getService();
        String userId = getId();
        Map<String, Object> row = new HashMap<>();
        row.put("USER_ID", userId);
        row.put("NAME", name);
        row.put("VALUE", value);
        // Coalesce a same-request follow-up write into the CR this request
        // already created for this user; a foreign pending CR still 409s.
        service.coalesceOrCreate(realm, "USER", userId, "SET_USER_ATTRIBUTE",
                List.of(row), getCurrentUserId(), java.util.Set.of(name));
    }

    @Override
    public void setAttribute(String name, List<String> values) {
        if (captureMode) {
            super.setAttribute(name, values);
            accumulateAttribute(name, values);
            trace("setAttribute:" + name);
            return;
        }
        if (!isIgaActive()) {
            super.setAttribute(name, values);
            return;
        }
        IgaChangeRequestService service = getService();
        String userId = getId();
        // Multi-value: emit one row per value so replay can persist each one.
        List<Map<String, Object>> rows = new ArrayList<>();
        if (values != null) {
            for (String v : values) {
                Map<String, Object> row = new HashMap<>();
                row.put("USER_ID", userId);
                row.put("NAME", name);
                row.put("VALUE", v);
                rows.add(row);
            }
        }
        if (rows.isEmpty()) {
            // Empty values means "remove all" — represent as a single null-value
            // row so replay can detect it as a clear.
            Map<String, Object> row = new HashMap<>();
            row.put("USER_ID", userId);
            row.put("NAME", name);
            row.put("VALUE", null);
            rows.add(row);
        }
        // Multi-value write: on coalesce, drop every prior row for this NAME
        // wholesale before appending the full new set (preserves the
        // one-row-per-value contract).
        service.coalesceOrCreate(realm, "USER", userId, "SET_USER_ATTRIBUTE",
                rows, getCurrentUserId(), java.util.Set.of(name));
    }

    @Override
    public void removeAttribute(String name) {
        if (captureMode) {
            super.removeAttribute(name);
            if (org.keycloak.models.UserModel.FIRST_NAME.equals(name)) {
                capturedRep.setFirstName(null);
            } else if (org.keycloak.models.UserModel.LAST_NAME.equals(name)) {
                capturedRep.setLastName(null);
            } else if (org.keycloak.models.UserModel.EMAIL.equals(name)) {
                capturedRep.setEmail(null);
            } else {
                capturedAttributes.remove(name);
            }
            trace("removeAttribute:" + name);
            return;
        }
        if (!isIgaActive()) {
            super.removeAttribute(name);
            return;
        }
        IgaChangeRequestService service = getService();
        String userId = getId();
        Map<String, Object> row = new HashMap<>();
        row.put("USER_ID", userId);
        row.put("NAME", name);
        service.coalesceOrCreate(realm, "USER", userId, "REMOVE_USER_ATTRIBUTE",
                List.of(row), getCurrentUserId(), java.util.Set.of(name));
    }

    /**
     * Mirror {@code UserAdapter.setAttribute}'s root-attribute redirect into the
     * accumulator so the captured {@link UserRepresentation} matches what
     * {@code DefaultExportImportManager.createUser} reads: ROOT attrs
     * (USERNAME/FIRST_NAME/LAST_NAME/EMAIL) populate the rep's scalar fields
     * (createUser:984-987 + username at 979); everything else is a custom
     * attribute (createUser:989-996).
     */
    private void accumulateAttribute(String name, List<String> values) {
        String first = (values != null && !values.isEmpty()) ? values.get(0) : null;
        if (org.keycloak.models.UserModel.USERNAME.equals(name)) {
            if (first != null) {
                capturedRep.setUsername(KeycloakModelUtils.toLowerCaseSafe(first));
                usernameObserved = true;
            }
        } else if (org.keycloak.models.UserModel.FIRST_NAME.equals(name)) {
            capturedRep.setFirstName(first);
        } else if (org.keycloak.models.UserModel.LAST_NAME.equals(name)) {
            capturedRep.setLastName(first);
        } else if (org.keycloak.models.UserModel.EMAIL.equals(name)) {
            capturedRep.setEmail(first == null ? null
                    : KeycloakModelUtils.toLowerCaseSafe(first));
        } else {
            if (values == null) {
                capturedAttributes.remove(name);
            } else {
                List<String> nonNull = new ArrayList<>();
                for (String v : values) {
                    if (v != null) nonNull.add(v);
                }
                if (nonNull.isEmpty()) {
                    capturedAttributes.remove(name);
                } else {
                    capturedAttributes.put(name, nonNull);
                }
            }
        }
    }

    private void checkNoPendingCr(IgaChangeRequestService service, String userId) {
        var existing = service.findPending(realm.getId(), "USER", userId);
        if (existing != null) {
            throw new IgaConflictException(existing.getId());
        }
    }

    private String getCurrentUserId() {
        try {
            var auth = igaSession.getContext().getAuthenticationSession();
            if (auth != null) {
                return auth.getAuthenticatedUser() != null
                        ? auth.getAuthenticatedUser().getId()
                        : null;
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // Quarantine hooks.
    //
    // The IGA capture-then-veto workflow leaves an entity that pre-dates IGA
    // (or that pre-dates an OFF→ON toggle) "unsigned" until its ADOPT_X CR
    // commits. An unsigned user — or a user who
    // holds ANY unsigned role — is treated as not-enabled (HARD refuse, NOT
    // silent strip). The group quarantine is silent-strip
    // (membership simply vanishes from token mapping) so the user can still
    // log in while their unsigned-group claims are absent.
    //
    // KC checkpoints surfaced by user.isEnabled():
    //   TokenManager                          (token issuance / refresh)
    //   AuthorizationCodeGrantType            (auth-code → token)
    //   JWTAuthorizationGrantType             (JWT bearer grant)
    //   DeviceGrantType                       (device code → token)
    //   CibaGrantType                         (CIBA → token)
    //   AbstractTokenExchangeProvider         (token exchange)
    //   ResourceOwnerPasswordCredentialsGrantType: via authenticator-flow
    //   browser flow: via AbstractUsernameFormAuthenticator etc.
    //
    // KC checkpoints surfaced by client.isEnabled():
    //   ClientIdAndSecretAuthenticator   (client_secret_basic/post)
    //   AbstractJWTClientValidator       (client JWT auth)
    //   AccessTokenIntrospectionProvider (introspection)
    // -------------------------------------------------------------------------

    /**
     * User quarantine hook (HARD refuse).
     *
     * <p>Defers to {@code super.isEnabled()} first to preserve vanilla KC
     * behaviour: if the user was explicitly disabled by an admin, that
     * remains the answer (no need to even hit the quarantine cache). If the
     * user is otherwise enabled, consult the quarantine cache: when the user
     * OR any role they effectively hold has an unattested
     * {@code IGA_UNSIGNED_ENTITY} sidecar row, return {@code false} so every
     * KC isEnabled checkpoint (TokenManager etc.) hard-refuses the
     * operation. The cache is request-scoped (memoised on the session) so a
     * single token issuance pays the batched query at most once.</p>
     */
    @Override
    public boolean isEnabled() {
        boolean superEnabled = super.isEnabled();
        if (!superEnabled) {
            return false;
        }
        if (IgaQuarantineCache.isUserUnsignedWithRoles(igaSession, realm, this)) {
            // One INFO line per request per user — the dedupe key partitions
            // log noise from token issuance hot-path while still surfacing
            // EVERY first quarantine refusal (per user, per request) for
            // operator triage.
            if (IgaQuarantineCache.firstObservation(igaSession, "user:" + super.getId())) {
                log.infof("IGA quarantine REFUSE: user=%s realm=%s — user or "
                        + "one of their roles is unsigned (ADOPT pending); "
                        + "treating as not-enabled.",
                        super.getId(), realm.getName());
            }
            return false;
        }
        return true;
    }

    /**
     * Group quarantine hook (SILENT strip).
     *
     * <p>Filter the user's group stream so unsigned groups never reach the
     * token-mapping path. Group membership claims that derive from an
     * unsigned group are simply absent from the issued token; the user can
     * still log in. Roles inherited via an unsigned group are also stripped
     * at the same point (groups gone → role-through-group gone).</p>
     *
     * <p><b>Admin-REST context bypass.</b>
     * For admin reads: WARN but don't block — operators
     * must see the queue. The no-arg {@code getGroupsStream()} is invoked from
     * BOTH the token-mapping path (oidc/saml GroupMembershipMapper,
     * TokenManager → must strip) AND from the admin-REST path
     * ({@code UserResource.groupMembership} and the
     * {@code UserPermissions.evaluateHierarchy} permission check before it,
     * {@code RoleUtils.hasRoleFromGroup} during admin reads, etc. — must NOT
     * strip; operators must observe the unsigned group so they can ADOPT it).
     * The discriminator is the live call stack: if any frame is one of KC's
     * admin REST resource classes (under {@code
     * org.keycloak.services.resources.admin}) we are servicing an admin
     * operation and the strip must NOT fire. The StackWalker can't be spoofed
     * by a malicious caller (the discriminator IS the call site itself), so
     * this is safe even if a token-issuing request ever attempted to set a
     * session attribute. Token-mapping call sites
     * ({@code GroupMembershipMapper}, {@code TokenManager}) are NEVER in the
     * admin resource package — the strip fires there as designed.</p>
     */
    @Override
    public Stream<GroupModel> getGroupsStream() {
        final boolean adminContext = isCalledFromAdminRestResource();
        return super.getGroupsStream().filter(g -> {
            if (!IgaQuarantineCache.isGroupUnsigned(igaSession, realm, g)) {
                return true;
            }
            if (adminContext) {
                // Operator-observable read: keep the unsigned group visible
                // so the admin can ADOPT it. WARN (one-shot per session per
                // group) so the unsigned-membership is still surfaced in the
                // log for triage, but do NOT strip.
                if (IgaQuarantineCache.firstObservation(igaSession,
                        "group-admin:" + g.getId())) {
                    log.warnf("IGA quarantine VISIBLE-IN-ADMIN: group=%s "
                            + "realm=%s — ADOPT pending; group surfaced to "
                            + "admin REST caller (token-mapping reads will "
                            + "still strip until ADOPT commits).",
                            g.getId(), realm.getName());
                }
                return true;
            }
            if (IgaQuarantineCache.firstObservation(igaSession,
                    "group:" + g.getId())) {
                log.infof("IGA quarantine STRIP group: group=%s realm=%s — "
                        + "ADOPT pending; group membership omitted from "
                        + "token mapping.", g.getId(), realm.getName());
            }
            return false;
        });
    }

    /**
     * True iff any frame on the live
     * call stack is one of KC's admin REST resource classes (declaring class
     * FQN starts with {@code org.keycloak.services.resources.admin.}). When
     * true, the no-arg {@link #getGroupsStream()} MUST NOT strip — admins
     * must see unsigned groups so they can authorize ADOPT.
     *
     * <p>Why a stack-walk rather than a session attribute: the discriminator
     * must not be spoofable. A
     * malicious caller could set an arbitrary session attribute before
     * issuing a token-issuance request and trick the gate into NOT stripping;
     * the StackWalker is immune because the discriminator IS the call site.
     * Token-mapping callers ({@code oidc/saml GroupMembershipMapper},
     * {@code TokenManager}, {@code AccountRestService},
     * {@code ClientUpdaterSourceGroupsCondition}) have NO frame under
     * {@code services.resources.admin} on the stack — the predicate returns
     * false and the strip fires as designed.
     *
     * <p>The walk short-circuits on the first matching frame (typically
     * very near the top of the stack for an admin REST request — the
     * resource method is on the call path). RETAIN_CLASS_REFERENCE is used
     * for parity with the existing {@code computeImmediateCaller} (no
     * lookupClass overhead for a missed match).
     */
    private static boolean isCalledFromAdminRestResource() {
        return StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames.anyMatch(f -> {
                    String cn = f.getDeclaringClass().getName();
                    // The admin resource package covers every admin REST
                    // class (UserResource, UsersResource, GroupResource,
                    // RoleMapperResource, …) including its fgap subpackage
                    // (UserPermissions.evaluateHierarchy →
                    // user.getGroupsStream()).
                    return cn.startsWith("org.keycloak.services.resources.admin.");
                }));
    }
}
