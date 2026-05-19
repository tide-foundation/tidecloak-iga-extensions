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
    // NOT matched here (requiring/looking for it was 4d217fb's mistake; the
    // runtime harvest proves #7/#8's immediate frame is UsersResource#createUser
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

    /** Sentinel: the computed immediate caller IS UsersResource#createUser. */
    private static final String TERMINAL = "<UsersResource#createUser>";

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
        return StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> {
                    var it = frames.iterator();
                    while (it.hasNext()) {
                        StackWalker.StackFrame f = it.next();
                        Class<?> c = f.getDeclaringClass();
                        String cn = c.getName();
                        String mn = f.getMethodName();

                        // Skip ALL IgaUserAdapter frames (any method: getId,
                        // calledDirectlyFromCreateUserResource,
                        // computeImmediateCaller, lambdas/synthetics) because
                        // the predicate runs inside an IgaUserAdapter helper;
                        // the immediate caller must be the first NON-
                        // IgaUserAdapter, NON-UserAdapter-self frame
                        // (runtime-proven: getId#7/#8 → UsersResource#createUser).
                        if (IgaUserAdapter.class.getName().equals(cn)) {
                            continue;
                        }
                        // Skip the StackWalker machinery itself (JDK frames —
                        // typically already absent, skipped defensively).
                        if (cn.startsWith("java.lang.StackWalker")) {
                            continue;
                        }
                        // Skip the inherited UserAdapter.{equals,hashCode,getId}
                        // that delegate straight back into getId() — they are
                        // NOT the logical caller.
                        if (UserAdapter.class.getName().equals(cn)
                                && ("equals".equals(mn) || "hashCode".equals(mn)
                                    || "getId".equals(mn))) {
                            continue;
                        }

                        // First surviving frame == the genuine external
                        // immediate caller. RUNTIME-PROVEN match: terminal IFF
                        // its declaring class FQN is exactly UsersResource AND
                        // its method is exactly createUser. This uniquely
                        // matches getId#7 (UsersResource#createUser, :175) and
                        // getId#8 (:177) and NEVER getId#1–#6 (those resolve to
                        // UserCacheSession#addUser/fullyInvalidateUser/
                        // addFederatedIdentity / UserStorageManager#
                        // addFederatedIdentity / JpaUserProvider#
                        // addFederatedIdentity). The Quarkus invoker is BELOW
                        // this frame, never the immediate caller, so it is not
                        // (and must not be) matched.
                        if (KC_USERS_RESOURCE.equals(cn)
                                && KC_CREATE_USER.equals(mn)) {
                            return TERMINAL;
                        }
                        return cn + "#" + mn;
                    }
                    return "<none>";
                });
    }

    @Override
    public String getId() {
        // Phase 4 hard guard: in a partialImport this capture adapter's row is
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

        String userId = super.getId();
        String username = capturedRep.getUsername() != null
                ? capturedRep.getUsername() : super.getUsername();

        Map<String, Object> row = buildCapturedUserRow();

        String requestedBy = getCurrentUserId();
        String[] crIdHolder = new String[1];
        KeycloakModelUtils.runJobInTransaction(igaSession.getKeycloakSessionFactory(), newSession -> {
            RealmModel newRealm = newSession.realms().getRealm(realm.getId());
            EntityManager newEm = newSession.getProvider(JpaConnectionProvider.class).getEntityManager();
            IgaChangeRequestService newService = new IgaChangeRequestService(newEm, newSession);
            crIdHolder[0] = newService.create(newRealm, "USER", userId,
                    "CREATE_USER", List.of(row), requestedBy).getId();
        });

        // Mark the REQUEST tx rollback-only so DefaultKeycloakSession#close()
        // rolls back and the scratch user + everything attached dies. The CR
        // survives because runJobInTransaction wrote it on a separate session.
        // Same idiom + lifecycle proof as IgaClientScopeAdapter#getId /
        // IgaRoleAdapter#getName.
        igaSession.getTransactionManager().setRollbackOnly();

        throw new IgaPendingApprovalException(crIdHolder[0], "USER", "CREATE_USER");
    }

    /**
     * Build the {@code CREATE_USER} CR row from the accumulator — the SINGLE
     * source of truth shared by the single-entity terminal seam
     * ({@link #getId()}) and the Phase 4 partialImport batch path
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
        // user-create — stock KC's UsersResource.createUser
        // (keycloak-services 26.5.5 UsersResource.java:143-192) NEVER applies
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
     * Phase 4 — partialImport batch path. Build this user's
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
