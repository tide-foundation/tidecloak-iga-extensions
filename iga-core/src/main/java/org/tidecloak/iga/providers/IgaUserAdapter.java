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
 * <h2>Credentials are NOT governed (product decision)</h2>
 * A user's password is deliberately NOT captured, deferred or replayed. The
 * {@code credentialManager()} override and {@code CaptureCredentialManager}
 * wrapper that earlier captured/replayed the password were removed: the user
 * sets their own password themselves (an {@code UPDATE_PASSWORD} required
 * action / set-password email / self-service) AFTER the governed create is
 * approved. This keeps plaintext passwords out of CR rows and removes the
 * riskiest novel seam. The captured {@link UserRepresentation} is therefore
 * <b>guaranteed never to carry a {@code credentials} field</b> (it is
 * explicitly null'd before serialization at the terminal emit). KC's create
 * flow may still invoke the real (super) credential manager — credentials
 * simply aren't intercepted, captured or persisted (the scratch user is rolled
 * back at draft regardless). {@code UPDATE_PASSWORD} is a <em>required
 * action</em>, NOT a credential, and IS captured (so the approved user can be
 * told to set a password).
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
 *          303  if federationLink!=null       user.setFederationLink(..)
 *          307-320 reqActions!=null: per provider id user.addRequiredAction /
 *                  removeRequiredAction
 *          322-330 if a password credential isTemporary →
 *                  user.addRequiredAction(UPDATE_PASSWORD)
 * 171  RepresentationToModel.createFederatedIdentities(rep,session,realm,user)
 *        RepresentationToModel.java:775-782: per identity
 *        session.users().addFederatedIdentity(realm,user,model)
 *        → IgaUserProvider.addFederatedIdentity (intercepted there)
 * 172  RepresentationToModel.createGroups(session,rep,realm,user)
 *        RepresentationToModel.java:762-773: per path user.joinGroup(group)
 * 174  RepresentationToModel.createCredentials(rep,session,realm,user,true)
 *        RepresentationToModel.java:784-808: NOT intercepted — the
 *        credentialManager() override was removed; any inbound password is
 *        applied (if at all) to the throw-away scratch user via the real
 *        (super) credential manager and dies with the request-tx rollback. It
 *        is NEVER accumulated into the captured rep (see "Credentials are NOT
 *        governed").
 * 175  adminEvent...resourcePath(uri, user.getId())...   // user.getId() #1
 * 177  Response.created(...user.getId()...)              // user.getId() #2
 * </pre>
 *
 * <h3>Snapshot-lossy fields</h3>
 * {@code ModelToRepresentation} for a user does NOT serialize group
 * memberships, role mappings, required actions or federated identities, and
 * there is NO single unconditional terminal mutating model call (enabled is
 * conditional, the attribute loop is by-key, groups/roles/fed are all
 * conditional). So — exactly like client-scope — we accumulate every
 * intercepted call into a {@link UserRepresentation} and emit from the
 * accumulator (never a live snapshot) at the post-build terminal {@code getId()}.
 * Credentials are deliberately excluded from the accumulator entirely (see
 * "Credentials are NOT governed").
 *
 * <h3>Terminal seam: {@code getId()} at UsersResource.createUser:175 (then 177),
 * gated on {@link #usernameObserved}</h3>
 * {@code user.getId()} is invoked early and unpredictably on the scratch
 * adapter via {@code UserAdapter.equals()} (UserAdapter.java:588-594) and
 * {@code hashCode()} (596-599) during the JPA persistence context / user events
 * — BEFORE any field is applied (the user analogue of client-scope's
 * equals/hashCode/toString→getId() hazard). {@code DefaultUserProfile.create}
 * always applies the {@code username} writable attribute first
 * (UserAdapter.setAttribute → {@link #setUsername(String)}), strictly AFTER the
 * scratch user is persisted and BEFORE KC's terminal {@code getId()} at
 * createUser:175. So {@link #usernameObserved} cleanly partitions the early
 * racy {@code getId()} calls (no setter seen → fall through to
 * {@code super.getId()}) from the resource-level terminal {@code getId()} (every
 * field the rep carries already accumulated → emit). Because the rep is rebuilt
 * from the ACCUMULATOR, even a {@code getId()} that lands mid-build still
 * carries every field observed so far; the fire-once guard latches the final
 * emit and the second {@code getId()} at :177 falls through.
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
 * accumulator below populates precisely those fields (EXCEPT credentials —
 * never accumulated; see "Credentials are NOT governed") with the precise
 * shapes {@code createRoleMappings}/{@code createGroups} consume (realmRoles =
 * role NAMES; clientRoles = {humanClientId → [role name]}; groups = group
 * PATHS). On replay {@code RepresentationToModel.createCredentials}
 * (RepresentationToModel.java:786) is guarded by
 * {@code if (userRep.getCredentials() != null)} — with no {@code credentials}
 * in REP_JSON the loop is skipped and the user is created with NO password
 * (no NPE), exactly the intended behaviour.
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

    // ---- accumulator (capture mode only) ----------------------------------
    private final UserRepresentation capturedRep = new UserRepresentation();
    private final Map<String, List<String>> capturedAttributes = new LinkedHashMap<>();
    private final Set<String> capturedRequiredActions = new LinkedHashSet<>();
    private final Set<String> capturedGroupPaths = new LinkedHashSet<>();
    private final Set<String> capturedRealmRoles = new LinkedHashSet<>();
    private final Map<String, List<String>> capturedClientRoles = new LinkedHashMap<>();
    // NOTE: credentials are deliberately NOT accumulated — a user's password is
    // not governed (the user sets it themselves post-approval). See the
    // "Credentials are NOT governed" section in the class javadoc.
    private final List<org.keycloak.representations.idm.FederatedIdentityRepresentation>
            capturedFederatedIdentities = new ArrayList<>();
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

    // -------------------------------------------------------------------------
    // Terminal seam for CREATE_USER (capture mode only): user.getId(), GATED
    // on usernameObserved. See class javadoc for the early-getId() hazard and
    // why username cleanly partitions the early racy calls from the terminal.
    // -------------------------------------------------------------------------
    @Override
    public String getId() {
        if (!captureMode || captureEmitted || !usernameObserved) {
            return super.getId();
        }
        // Arm the fire-once guard BEFORE any further model/service call so the
        // emit path cannot re-enter this seam and the second getId() at
        // UsersResource.createUser:177 falls through.
        captureEmitted = true;
        trace("getId#emit");

        String userId = super.getId();
        String username = capturedRep.getUsername() != null
                ? capturedRep.getUsername() : super.getUsername();

        // Build the CR rep entirely from the accumulator (authoritative — the
        // live model never serializes creds/groups/roles/reqActions/fed, and
        // getId() can fire early via equals/hashCode; see class javadoc).
        UserRepresentation rep = new UserRepresentation();
        rep.setId(userId);
        rep.setUsername(username);
        if (capturedRep.isEnabled() != null) rep.setEnabled(capturedRep.isEnabled());
        if (capturedRep.getEmail() != null) rep.setEmail(capturedRep.getEmail());
        if (capturedRep.isEmailVerified() != null) rep.setEmailVerified(capturedRep.isEmailVerified());
        if (capturedRep.getFirstName() != null) rep.setFirstName(capturedRep.getFirstName());
        if (capturedRep.getLastName() != null) rep.setLastName(capturedRep.getLastName());
        if (capturedRep.getFederationLink() != null) rep.setFederationLink(capturedRep.getFederationLink());
        if (capturedRep.getCreatedTimestamp() != null) rep.setCreatedTimestamp(capturedRep.getCreatedTimestamp());
        if (!capturedAttributes.isEmpty()) {
            Map<String, List<String>> attrs = new LinkedHashMap<>();
            for (Map.Entry<String, List<String>> e : capturedAttributes.entrySet()) {
                attrs.put(e.getKey(), new ArrayList<>(e.getValue()));
            }
            rep.setAttributes(attrs);
        }
        if (!capturedRequiredActions.isEmpty()) {
            rep.setRequiredActions(new ArrayList<>(capturedRequiredActions));
        }
        if (!capturedGroupPaths.isEmpty()) {
            rep.setGroups(new ArrayList<>(capturedGroupPaths));
        }
        if (!capturedRealmRoles.isEmpty()) {
            rep.setRealmRoles(new ArrayList<>(capturedRealmRoles));
        }
        if (!capturedClientRoles.isEmpty()) {
            Map<String, List<String>> cr = new LinkedHashMap<>();
            for (Map.Entry<String, List<String>> e : capturedClientRoles.entrySet()) {
                cr.put(e.getKey(), new ArrayList<>(e.getValue()));
            }
            rep.setClientRoles(cr);
        }
        // Credentials are NOT governed: explicitly null the credentials field
        // so an inbound password in the create request can NEVER ride along
        // into the CR through any path (the accumulator never records one;
        // this is belt-and-braces — the serialized rep provably carries no
        // `credentials`). The user sets their own password after approval.
        rep.setCredentials(null);
        if (!capturedFederatedIdentities.isEmpty()) {
            List<org.keycloak.representations.idm.FederatedIdentityRepresentation> fis =
                    new ArrayList<>();
            for (org.keycloak.representations.idm.FederatedIdentityRepresentation f
                    : capturedFederatedIdentities) {
                org.keycloak.representations.idm.FederatedIdentityRepresentation ff =
                        new org.keycloak.representations.idm.FederatedIdentityRepresentation();
                ff.setIdentityProvider(f.getIdentityProvider());
                ff.setUserId(f.getUserId());
                ff.setUserName(f.getUserName());
                fis.add(ff);
            }
            rep.setFederatedIdentities(fis);
        }

        String repJson;
        try {
            repJson = MAPPER.writeValueAsString(rep);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new RuntimeException(
                    "IGA capture CREATE_USER: failed to serialize captured "
                    + "UserRepresentation for user=" + username, e);
        }

        int attrs = rep.getAttributes() == null ? 0 : rep.getAttributes().size();
        int reqActions = rep.getRequiredActions() == null ? 0 : rep.getRequiredActions().size();
        int groups = rep.getGroups() == null ? 0 : rep.getGroups().size();
        int realmRoles = rep.getRealmRoles() == null ? 0 : rep.getRealmRoles().size();
        int clientRoles = rep.getClientRoles() == null ? 0
                : rep.getClientRoles().values().stream().mapToInt(List::size).sum();
        int fed = rep.getFederatedIdentities() == null ? 0 : rep.getFederatedIdentities().size();
        log.infof("IGA capture CREATE_USER: accumulated-rep path for user=%s (uuid=%s, "
                + "enabled=%s, attributes=%d, requiredActions=%d, groups=%d, realmRoles=%d, "
                + "clientRoles=%d, fedIdentities=%d, %d chars; credentials NOT governed) captured "
                + "at the post-build terminal seam (UsersResource.createUser#getId, gated on "
                + "username-observed); observed order=[%s]; CR written in a separate tx, request "
                + "tx marked rollback-only so the scratch user + memberships + role mappings + "
                + "fed identities are discarded (zero rows persisted at draft); full config "
                + "(no password) will replay on commit",
                username, userId, rep.isEnabled(), attrs, reqActions, groups, realmRoles,
                clientRoles, fed, repJson.length(), observedTrace);

        // rowsJson contract (must match IgaReplayDispatcher.replayCreateUser):
        // ID = user UUID, USERNAME = lowercased username, REALM_ID = realm UUID,
        // REP_JSON = the full UserRepresentation JSON.
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("ID", userId);
        row.put("USERNAME", username == null ? null : username.toLowerCase());
        row.put("REALM_ID", realm.getId());
        row.put("REP_JSON", repJson);

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

    // -------------------------------------------------------------------------
    // Credentials are NOT governed.
    //
    // The credentialManager() override and the CaptureCredentialManager
    // delegate that earlier captured/replayed the user's password were REMOVED
    // (product decision). credentialManager() is no longer overridden, so the
    // real (super) UserAdapter credential manager is used unchanged — KC's
    // createUser flow (UsersResource.createUser:174 →
    // RepresentationToModel.createCredentials) is simply NOT intercepted; any
    // inbound password is applied (if at all) to the throw-away scratch user
    // and dies with the request-tx rollback. It is NEVER accumulated into the
    // captured rep, and getId() explicitly nulls rep.credentials before
    // serialization, so the CR provably carries no plaintext password. The
    // approved user sets their own password (UPDATE_PASSWORD required action /
    // set-password email / self-service). UPDATE_PASSWORD is a required action,
    // NOT a credential, and is still captured (see addRequiredAction below).
    // -------------------------------------------------------------------------

    /** Capture a federated identity (invoked from IgaUserProvider). */
    void captureFederatedIdentity(org.keycloak.models.FederatedIdentityModel identity) {
        if (!captureMode || identity == null) return;
        org.keycloak.representations.idm.FederatedIdentityRepresentation fi =
                new org.keycloak.representations.idm.FederatedIdentityRepresentation();
        fi.setIdentityProvider(identity.getIdentityProvider());
        fi.setUserId(identity.getUserId());
        fi.setUserName(identity.getUserName());
        capturedFederatedIdentities.add(fi);
        trace("federatedIdentity:" + identity.getIdentityProvider());
    }

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

    @Override
    public void setFederationLink(String link) {
        super.setFederationLink(link);
        if (captureMode) {
            capturedRep.setFederationLink(link);
            trace("setFederationLink");
        }
    }

    @Override
    public void setCreatedTimestamp(Long timestamp) {
        super.setCreatedTimestamp(timestamp);
        if (captureMode) {
            capturedRep.setCreatedTimestamp(timestamp);
            trace("setCreatedTimestamp");
        }
    }

    @Override
    public void addRequiredAction(String actionName) {
        super.addRequiredAction(actionName);
        if (captureMode) {
            capturedRequiredActions.add(actionName);
            trace("addRequiredAction:" + actionName);
        }
    }

    // NOTE: the RequiredAction-enum overloads are intentionally NOT overridden.
    // UserModel.addRequiredAction(RequiredAction)/removeRequiredAction
    // (RequiredAction) are interface DEFAULT methods that delegate to the
    // String overload (UserModel.java:130-140). UserAdapter does not override
    // them, so KC's UserResource.updateUserFromRep:327
    // user.addRequiredAction(RequiredAction.UPDATE_PASSWORD) routes through the
    // inherited default into THIS String override exactly once — overriding the
    // enum overload too would double-capture.

    @Override
    public void removeRequiredAction(String actionName) {
        super.removeRequiredAction(actionName);
        if (captureMode) {
            capturedRequiredActions.remove(actionName);
            trace("removeRequiredAction:" + actionName);
        }
    }

    // -------------------------------------------------------------------------
    // Role mappings.
    //
    // capture: pass through + accumulate into rep.realmRoles (realm role
    // NAMES) / rep.clientRoles ({human clientId → [role name]}) — EXACTLY the
    // shape RepresentationToModel.createRoleMappings (RepresentationToModel.java
    // :823-857, invoked from DefaultExportImportManager.createUser:1004)
    // consumes on replay. inline: targeted GRANT_ROLES / REVOKE_ROLES CR
    // (unchanged).
    // -------------------------------------------------------------------------

    @Override
    public void grantRole(RoleModel role) {
        if (captureMode) {
            super.grantRole(role);
            if (role != null) {
                if (role.isClientRole()) {
                    String clientId = null;
                    try {
                        org.keycloak.models.ClientModel owning =
                                realm.getClientById(role.getContainerId());
                        if (owning != null) clientId = owning.getClientId();
                    } catch (RuntimeException ignored) {
                        // cannot resolve owning client → skip from rep (the
                        // real link is still on the scratch model via super,
                        // discarded with the rollback; no worse than bare).
                    }
                    if (clientId != null) {
                        capturedClientRoles
                                .computeIfAbsent(clientId, k -> new ArrayList<>())
                                .add(role.getName());
                        trace("grantRole:client:" + clientId + "/" + role.getName());
                    }
                } else {
                    capturedRealmRoles.add(role.getName());
                    trace("grantRole:realm:" + role.getName());
                }
            }
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
            if (role != null) {
                if (role.isClientRole()) {
                    try {
                        org.keycloak.models.ClientModel owning =
                                realm.getClientById(role.getContainerId());
                        if (owning != null) {
                            List<String> names = capturedClientRoles.get(owning.getClientId());
                            if (names != null) {
                                names.remove(role.getName());
                                if (names.isEmpty()) {
                                    capturedClientRoles.remove(owning.getClientId());
                                }
                            }
                        }
                    } catch (RuntimeException ignored) {
                    }
                } else {
                    capturedRealmRoles.remove(role.getName());
                }
                trace("deleteRoleMapping:" + role.getName());
            }
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
