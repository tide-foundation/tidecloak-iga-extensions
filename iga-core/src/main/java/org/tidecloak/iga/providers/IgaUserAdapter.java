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

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.persistence.EntityManager;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
 *       {@code UsersResource.createUser} (keycloak-services 26.5.5
 *       UsersResource.java:143-192) NEVER applies {@code realmRoles}/
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
 * <h2>KC 26.5.5 user-create model-call trace (verified, source on classpath)</h2>
 * {@code UsersResource.createUser} (keycloak-services
 * UsersResource.java:143-192):
 * <pre>
 * 160  profileProvider.create(USER_API, rep.getRawAttributes())
 * 168  UserModel user = profile.create();
 *        DefaultUserProfile.create (DefaultUserProfile.java:94-106):
 *          103  user = userSupplier.apply(attributes)   // == session.users()
 *                                                       //    .addUser(realm,username)
 *                                                       //    → IgaUserProvider.addUser
 *                                                       //      (2-arg)  → scratch
 *                                                       //      IgaUserAdapter (capture)
 *          105  updateInternal(user,false)              // DefaultUserProfile.java:
 *               117-194: per writable attribute (sorted by key)
 *               user.setAttribute(name,values) — for ROOT attrs
 *               (USERNAME/FIRST_NAME/LAST_NAME/EMAIL) UserAdapter.setAttribute
 *               redirects to setUsername/setFirstName/setLastName/setEmail
 *               (UserAdapter.java:182-216); custom attrs persist as attributes.
 * 170  UserResource.updateUserFromRep(profile,user,rep,session,false)
 *        UserResource.java:296-331:
 *          299  if rep.isEnabled()!=null      user.setEnabled(..)
 *          300  if rep.isEmailVerified()!=null user.setEmailVerified(..)
 *          301  if createdTimestamp!=null     user.setCreatedTimestamp(..)
 *                  — NOT governed; passes through to super, never accumulated.
 *          303  if federationLink!=null       user.setFederationLink(..)
 *                  — NOT governed; passes through to super, never accumulated.
 *          307-320 reqActions!=null: per provider id user.addRequiredAction /
 *                  removeRequiredAction — NOT governed; passes straight through
 *                  to super (no capture interception), never accumulated.
 *          322-330 if a password credential isTemporary →
 *                  user.addRequiredAction(UPDATE_PASSWORD) — same: pass-through.
 * 171  RepresentationToModel.createFederatedIdentities(rep,session,realm,user)
 *        RepresentationToModel.java:775-782: per identity
 *        session.users().addFederatedIdentity(realm,user,model)
 *        → IgaUserProvider.addFederatedIdentity — NOT governed; reverted to
 *        plain super delegation, never accumulated.
 * 172  RepresentationToModel.createGroups(session,rep,realm,user)
 *        RepresentationToModel.java:762-773: per path user.joinGroup(group)
 * 174  RepresentationToModel.createCredentials(rep,session,realm,user,true)
 *        RepresentationToModel.java:784-808: NOT intercepted — the
 *        credentialManager() override was removed; any inbound password is
 *        applied (if at all) to the throw-away scratch user via the real
 *        (super) credential manager and dies with the request-tx rollback. It
 *        is NEVER accumulated into the captured rep (see "Govern ONLY
 *        token-affecting user fields").
 * 175  adminEvent...resourcePath(uri, user.getId())...   // user.getId() #1
 * 177  Response.created(...user.getId()...)              // user.getId() #2
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
 * adapter via {@code UserAdapter.equals()} (UserAdapter.java:587-594) and
 * {@code hashCode()} (596-599) during the JPA persistence context / user
 * events, and again from {@code DefaultUserProfile} /
 * {@code RepresentationToModel.*} mid-build. The fragile "first {@code getId()}
 * after a username was observed" trigger is replaced by a deterministic
 * StackWalker predicate ({@link #calledDirectlyFromCreateUserResource()})
 * proven by the trace: the ONLY {@code getId()} calls whose IMMEDIATE caller
 * (the nearest stack frame that is not this adapter's own {@code getId()} nor
 * the inherited {@code UserAdapter.equals/hashCode} that delegate straight
 * back into {@code getId()}) is {@code UsersResource.createUser} (or its
 * Quarkus {@code *quarkusrestinvoker*createUser*} wrapper) are the two
 * resource-terminal calls — UsersResource.java:175 ({@code adminEvent
 * ...resourcePath(uri, user.getId())}) and :177
 * ({@code Response.created(...user.getId()...)}), both AFTER the full model is
 * built. Every mid-build {@code getId()} has an intermediate non-resource
 * frame (UserAdapter.equals/hashCode, JPA proxy/persistence,
 * DefaultUserProfile, RepresentationToModel.createGroups/createCredentials/
 * createFederatedIdentities, group-event listeners) as its immediate caller →
 * NOT a terminal → falls straight through to {@code super.getId()} WITHOUT
 * emitting. {@link #usernameObserved} is retained as a defensive SECONDARY
 * gate. The fire-once guard latches the :175 emit; the second {@code getId()}
 * at :177 falls through.
 *
 * <h3>REP_JSON faithfulness vs. replay (byte-faithful, replay UNCHANGED)</h3>
 * {@code IgaReplayDispatcher.replayCreateUser} deserializes {@code REP_JSON} to
 * a {@link UserRepresentation}, pins {@code id}/{@code username}, then calls
 * {@code RepresentationToModel.createUser} →
 * {@code DefaultExportImportManager.createUser}
 * (keycloak-model-storage-private DefaultExportImportManager.java:975-1026),
 * which consumes EXACTLY: id+username (979, via 5-arg local addUser, NOT the
 * IGA 1-arg), enabled (980), createdTimestamp (981-983), email (984),
 * emailVerified (985), firstName (986), lastName (987), federationLink (988),
 * attributes (989-996), requiredActions (997-1001),
 * credentials→createCredentials (1002), federatedIdentities (1003),
 * realmRoles/clientRoles→createRoleMappings (1004), clientConsents (1005),
 * notBefore (1012), serviceAccountClientId (1016), groups (1024). The
 * accumulator below populates ONLY the 8 KC-routed token fields (username,
 * enabled, email, emailVerified, firstName, lastName, attributes, groups);
 * {@code groups} are group PATHS — the exact shape {@code createGroups}
 * (RepresentationToModel.java:762-773) consumes via {@code findGroupByPath}.
 * The other 7 fields are absent from REP_JSON and KC's import path is
 * null-safe for each absent one (verified, KC 26.5.5 sources on classpath):
 * <ul>
 *   <li>{@code createRoleMappings} guards
 *       {@code if (userRep.getRealmRoles() != null)}
 *       (RepresentationToModel.java:824) AND
 *       {@code if (userRep.getClientRoles() != null)}
 *       (RepresentationToModel.java:833) → both loops skipped, user gets NO
 *       role mappings from the CREATE_USER replay (roles are governed
 *       separately via the GRANT_ROLES role-mapping CR).</li>
 *   <li>{@code createCredentials} guards
 *       {@code if (userRep.getCredentials() != null)}
 *       (RepresentationToModel.java:786) → loop skipped, user has NO password
 *       (no NPE).</li>
 *   <li>{@code requiredActions} guarded
 *       {@code if (userRep.getRequiredActions() != null)}
 *       (DefaultExportImportManager.java:997) → loop skipped.</li>
 *   <li>{@code createFederatedIdentities} guards
 *       {@code if (userRep.getFederatedIdentities() != null)}
 *       (RepresentationToModel.java:776) → loop skipped, no IdP link.</li>
 *   <li>{@code createdTimestamp} guarded
 *       {@code if (userRep.getCreatedTimestamp() != null)}
 *       (DefaultExportImportManager.java:981) → KC assigns its own create
 *       timestamp.</li>
 *   <li>{@code federationLink}: {@code user.setFederationLink(
 *       userRep.getFederationLink())} (DefaultExportImportManager.java:988) is
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
     * terminal-emit signal. {@code UsersResource.createUser}
     * (keycloak-services 26.5.5 UsersResource.java:143-192) is the ONLY method
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
     * TEMPORARY DIAGNOSTIC build counter: sequential index of every
     * capture-mode {@code getId()} call (#1, #2, …) so the IGA-USERDIAG log
     * lines can be correlated in execution order. NOT used by any production
     * decision; this whole capture-mode getId() diagnostic path neither emits,
     * throws nor rolls back.
     */
    private int diagGetIdSeq = 0;

    /**
     * TEMPORARY DIAGNOSTIC max stack frames captured per getId() log line
     * (after JDK/reflection filtering). Capping keeps each line readable; the
     * KC/Quarkus/RESTEasy/Tidecloak frames we need are at the top so 30 is
     * comfortably enough to reach the resource boundary.
     */
    private static final int DIAG_MAX_FRAMES = 30;

    /**
     * One-shot diagnostic breadcrumb: record (once) that a mid-build
     * {@code getId()} was correctly skipped because the resource frame was
     * absent. Proves the StackWalker predicate suppressed the early/racy
     * equals/hashCode/JPA-driven {@code getId()} rather than emitting a lossy
     * rep. Not recorded on every skip (getId() is invoked very frequently) —
     * just the first, so the observed-order trace shows
     * {@code …,getId(skip:no-resource-frame),…} interleaved with setters.
     */
    private boolean skipTraced = false;

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
            // TEMPORARY DIAGNOSTIC: one-time addUser capture-entry marker. No
            // end marker is possible (this build never emits/throws — the
            // resource returns 201); the deliverable is the IGA-USERDIAG log
            // from this START to the end of the createUser flow.
            log.infof("IGA-USERDIAG === capture-mode addUser START "
                    + "username=%s realm=%s ===",
                    super.getUsername(),
                    realm == null ? null : realm.getName());
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
    // The fragile "first getId() after usernameObserved" trigger is replaced by
    // a StackWalker resource-boundary predicate proven by the KC 26.5.5 trace:
    // the ONLY user.getId() calls whose IMMEDIATE caller (the nearest stack
    // frame that is neither this adapter's getId() override nor the inherited
    // UserAdapter.equals/hashCode that delegate straight back into getId()) is
    // UsersResource.createUser are the two resource-terminal calls
    // (UsersResource.java:175 adminEvent resourcePath, :177 Response.created).
    // Every mid-build getId() (UserAdapter.equals/hashCode, JPA proxy /
    // persistence, DefaultUserProfile, RepresentationToModel.createGroups/
    // createCredentials/createFederatedIdentities, group-event listeners) has
    // an intermediate non-resource frame as its immediate caller, so it is NOT
    // a terminal and falls straight through to super.getId() WITHOUT emitting.
    //
    // Quarkus invoker robustness: KC runs the resource method behind a
    // generated *quarkusrestinvoker*$createUser_* wrapper. The predicate
    // accepts EITHER the real UsersResource#createUser frame OR a Quarkus
    // invoker frame for it (class name containing "quarkusrestinvoker" AND a
    // method/class reference to createUser). usernameObserved is kept as a
    // defensive SECONDARY gate (the resource frame is the primary deterministic
    // gate). The StackWalker runs only on getId() in capture mode for an
    // IGA-governed user create — a rare path — and short-circuits on the first
    // matching frame.
    // -------------------------------------------------------------------------

    /**
     * True iff {@code getId()} is being invoked DIRECTLY from
     * {@code UsersResource.createUser} (or its Quarkus invoker wrapper) — i.e.
     * the nearest stack frame that is not this adapter's own {@code getId()} or
     * the inherited {@code UserAdapter.equals/hashCode} (which delegate
     * straight back into {@code getId()}) is the resource terminal. Returns
     * {@code false} for every mid-build {@code getId()} whose immediate caller
     * is {@code DefaultUserProfile}, JPA persistence, a JPA/Hibernate proxy,
     * {@code RepresentationToModel.*}, a group-event listener, etc.
     */
    private boolean calledDirectlyFromCreateUserResource() {
        return StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> {
                    var it = frames.iterator();
                    while (it.hasNext()) {
                        StackWalker.StackFrame f = it.next();
                        Class<?> c = f.getDeclaringClass();
                        String cn = c.getName();
                        String mn = f.getMethodName();

                        // Skip this adapter's own getId() override and the
                        // inherited UserAdapter.equals()/hashCode() that call
                        // getId() — they are NOT the logical "caller" of the
                        // terminal; we want the frame that drove the lookup.
                        if (IgaUserAdapter.class.getName().equals(cn)
                                && "getId".equals(mn)) {
                            continue;
                        }
                        if (UserAdapter.class.getName().equals(cn)
                                && ("equals".equals(mn) || "hashCode".equals(mn)
                                    || "getId".equals(mn))) {
                            continue;
                        }

                        // First "real" caller frame. Terminal IFF it is the
                        // KC admin createUser resource (or its Quarkus invoker
                        // for that exact method).
                        boolean realResource =
                                KC_USERS_RESOURCE.equals(cn)
                                        && mn != null
                                        && mn.contains(KC_CREATE_USER);
                        boolean quarkusInvoker =
                                cn != null
                                        && cn.contains("quarkusrestinvoker")
                                        && ((mn != null && mn.contains(KC_CREATE_USER))
                                            || cn.contains(KC_CREATE_USER));
                        return realResource || quarkusInvoker;
                    }
                    return false;
                });
    }

    /**
     * TEMPORARY DIAGNOSTIC build of {@code getId()}.
     *
     * <p><b>Non-capture / inline path is byte-equivalent in behaviour</b>: it
     * still just returns {@code super.getId()} (inline mode never emitted from
     * getId()). <b>Capture path: NO emit / NO throw / NO setRollbackOnly.</b>
     * On EVERY capture-mode getId() call we log a single INFO line with the
     * sequential index, the would-be accumulator state, and the real filtered
     * runtime stack, then fall straight through to {@code super.getId()} so the
     * ENTIRE {@code UsersResource.createUser} flow runs to completion (the e2e
     * probe uses a throwaway scratch realm — an ungoverned create there is
     * harmless and is the intended diagnostic). The whole point is to OBSERVE
     * every getId() call's actual stack so the true terminal frame can be
     * identified from data; emitting/throwing would abort the flow and hide
     * later frames. The accumulation logic in the setters is intact, so
     * {@code acc=[...]} faithfully reflects what WOULD have been captured.
     * {@link #calledDirectlyFromCreateUserResource()},
     * {@link #captureEmitted}, {@link #skipTraced} are unused in this build but
     * retained byte-unchanged for an easy revert.</p>
     */
    @Override
    public String getId() {
        if (captureMode) {
            int n = ++diagGetIdSeq;
            int attrCount = capturedAttributes.size();
            int groupCount = capturedGroupPaths.size();
            log.infof("IGA-USERDIAG getId#%d acc=[username=%s,enabled=%s,"
                    + "email=%s,first=%s,last=%s,emailVerified=%s,attrs=%d,"
                    + "groups=%d] stack=%s",
                    n,
                    yn(capturedRep.getUsername() != null),
                    yn(capturedRep.isEnabled() != null),
                    yn(capturedRep.getEmail() != null),
                    yn(capturedRep.getFirstName() != null),
                    yn(capturedRep.getLastName() != null),
                    yn(capturedRep.isEmailVerified() != null),
                    attrCount, groupCount,
                    diagFilteredStack());
            return super.getId();
        }
        return super.getId();
    }

    /**
     * TEMPORARY DIAGNOSTIC stack formatter. Walks the live stack with
     * {@code RETAIN_CLASS_REFERENCE}, drops pure JDK ({@code java.*}/
     * {@code javax.*}/{@code jdk.*}/{@code sun.*}) and reflection frames AND
     * this method's own + {@code IgaUserAdapter.getId} frames, KEEPS every
     * {@code org.keycloak.*}, {@code io.quarkus.*},
     * {@code org.jboss.resteasy.*}/{@code org.jboss.resteasy.reactive.*} and
     * {@code org.tidecloak.*} frame (exactly the frames that pinpoint the
     * terminal), and renders each surviving frame as
     * {@code <declaring-class-FQN>#<method>}. Capped at
     * {@link #DIAG_MAX_FRAMES} surviving frames so each log line stays
     * readable; the resource boundary is well within that cap.
     */
    private String diagFilteredStack() {
        return StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> {
                    StringBuilder sb = new StringBuilder();
                    int kept = 0;
                    var it = frames.iterator();
                    while (it.hasNext()) {
                        StackWalker.StackFrame f = it.next();
                        Class<?> c = f.getDeclaringClass();
                        String cn = c.getName();
                        String mn = f.getMethodName();

                        // Drop this diagnostic's own frames + getId override.
                        if (IgaUserAdapter.class.getName().equals(cn)
                                && ("diagFilteredStack".equals(mn)
                                    || "getId".equals(mn))) {
                            continue;
                        }
                        // Drop pure JDK / reflection noise but KEEP every
                        // keycloak / quarkus / resteasy / tidecloak frame.
                        boolean keepAlways =
                                cn.startsWith("org.keycloak.")
                                || cn.startsWith("io.quarkus.")
                                || cn.startsWith("org.jboss.resteasy.")
                                || cn.startsWith("org.tidecloak.");
                        if (!keepAlways) {
                            if (cn.startsWith("java.")
                                    || cn.startsWith("javax.")
                                    || cn.startsWith("jakarta.")
                                    || cn.startsWith("jdk.")
                                    || cn.startsWith("sun.")
                                    || cn.contains(".reflect.")) {
                                continue;
                            }
                        }
                        if (kept >= DIAG_MAX_FRAMES) {
                            sb.append(" >|cap@").append(DIAG_MAX_FRAMES);
                            break;
                        }
                        if (kept > 0) sb.append(" > ");
                        sb.append(cn).append('#').append(mn);
                        kept++;
                    }
                    if (kept == 0) sb.append("<none>");
                    return sb.toString();
                });
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
            log.infof("IGA-USERDIAG set:username=%s", super.getUsername());
        }
    }

    @Override
    public void setEnabled(boolean enabled) {
        super.setEnabled(enabled);
        if (captureMode) {
            capturedRep.setEnabled(enabled);
            trace("setEnabled:" + enabled);
            log.infof("IGA-USERDIAG set:enabled=%s", enabled);
        }
    }

    @Override
    public void setEmail(String email) {
        super.setEmail(email);
        if (captureMode) {
            capturedRep.setEmail(super.getEmail());
            trace("setEmail");
            log.infof("IGA-USERDIAG set:email=%s", super.getEmail());
        }
    }

    @Override
    public void setEmailVerified(boolean verified) {
        super.setEmailVerified(verified);
        if (captureMode) {
            capturedRep.setEmailVerified(verified);
            trace("setEmailVerified:" + verified);
            log.infof("IGA-USERDIAG set:emailVerified=%s", verified);
        }
    }

    @Override
    public void setFirstName(String firstName) {
        super.setFirstName(firstName);
        if (captureMode) {
            capturedRep.setFirstName(firstName);
            trace("setFirstName");
            log.infof("IGA-USERDIAG set:firstName=%s", firstName);
        }
    }

    @Override
    public void setLastName(String lastName) {
        super.setLastName(lastName);
        if (captureMode) {
            capturedRep.setLastName(lastName);
            trace("setLastName");
            log.infof("IGA-USERDIAG set:lastName=%s", lastName);
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
    // UsersResource.createUser (keycloak-services 26.5.5
    // UsersResource.java:143-192) NEVER applies realmRoles/clientRoles — it
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
    // RepresentationToModel.createGroups, RepresentationToModel.java:762-773,
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
                log.infof("IGA-USERDIAG set:joinGroup=%s",
                        KeycloakModelUtils.buildGroupPath(group));
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
                log.infof("IGA-USERDIAG set:joinGroup=%s",
                        KeycloakModelUtils.buildGroupPath(group));
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
                log.infof("IGA-USERDIAG set:leaveGroup=%s",
                        KeycloakModelUtils.buildGroupPath(group));
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
            log.infof("IGA-USERDIAG set:singleAttribute=%s=%s", name, value);
            return;
        }
        if (!isIgaActive()) {
            super.setSingleAttribute(name, value);
            return;
        }
        IgaChangeRequestService service = getService();
        String userId = getId();
        checkNoPendingCr(service, userId);
        Map<String, Object> row = new HashMap<>();
        row.put("USER_ID", userId);
        row.put("NAME", name);
        row.put("VALUE", value);
        service.create(realm, "USER", userId, "SET_USER_ATTRIBUTE",
                List.of(row), getCurrentUserId());
    }

    @Override
    public void setAttribute(String name, List<String> values) {
        if (captureMode) {
            super.setAttribute(name, values);
            accumulateAttribute(name, values);
            trace("setAttribute:" + name);
            log.infof("IGA-USERDIAG set:attribute=%s=%s", name, values);
            return;
        }
        if (!isIgaActive()) {
            super.setAttribute(name, values);
            return;
        }
        IgaChangeRequestService service = getService();
        String userId = getId();
        checkNoPendingCr(service, userId);
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
        service.create(realm, "USER", userId, "SET_USER_ATTRIBUTE", rows, getCurrentUserId());
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
            log.infof("IGA-USERDIAG set:removeAttribute=%s", name);
            return;
        }
        if (!isIgaActive()) {
            super.removeAttribute(name);
            return;
        }
        IgaChangeRequestService service = getService();
        String userId = getId();
        checkNoPendingCr(service, userId);
        Map<String, Object> row = new HashMap<>();
        row.put("USER_ID", userId);
        row.put("NAME", name);
        service.create(realm, "USER", userId, "REMOVE_USER_ATTRIBUTE",
                List.of(row), getCurrentUserId());
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
}
