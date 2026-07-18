package org.tidecloak.iga.providers;

import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.tidecloak.iga.services.IgaMigrationContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.jpa.JpaUserProvider;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;

import jakarta.persistence.EntityManager;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
 *       (UsersResource.createUser, gated on username-observed) the
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
        // TIDECLOAK: Keycloak's own model migration must apply directly — never
        // captured as a governance CR (would 409 on a realm with a pending CR
        // and abort boot). See IgaMigrationContext.
        if (IgaMigrationContext.isOnKeycloakMigrationPath()) return false;
        Object replay = igaSession.getAttribute("IGA_REPLAY_ACTIVE");
        return !"true".equals(replay);
    }

    /**
     * Persist the change request in a SEPARATE Keycloak session/transaction so it
     * survives the rollback caused by the pending-approval exception, mark the
     * REQUEST transaction rollback-only (so the in-flight delete is discarded —
     * the entity survives while PENDING), then throw the pending-approval signal
     * (mapped to HTTP 202 + Location). Identical mechanism to
     * {@code IgaRealmProvider.recordAndThrow} / {@code IgaOrganizationProvider
     * .recordAndThrow}; replicated here because {@link JpaUserProvider} has no
     * shared base with those providers.
     */
    private void recordAndThrow(RealmModel realm, String entityType, String entityId,
                                String actionType, List<Map<String, Object>> rows) {
        String[] crIdHolder = new String[1];
        KeycloakModelUtils.runJobInTransaction(igaSession.getKeycloakSessionFactory(), newSession -> {
            RealmModel newRealm = newSession.realms().getRealm(realm.getId());
            EntityManager newEm = newSession.getProvider(JpaConnectionProvider.class).getEntityManager();
            IgaChangeRequestService newService = new IgaChangeRequestService(newEm, newSession);
            crIdHolder[0] = newService.create(newRealm, entityType, entityId, actionType, rows, null).getId();
        });
        igaSession.getTransactionManager().setRollbackOnly();
        throw new IgaPendingApprovalException(crIdHolder[0], entityType, actionType);
    }

    // -------------------------------------------------------------------------
    // DELETE USER — govern whole-entity user deletes (capture → approve →
    // replay-delete-on-commit). Mirrors IgaOrganizationProvider.remove /
    // IgaRealmProvider.removeRole. UsersResource#deleteUser (DELETE
    // {realm}/users/{id}) calls session.users().removeUser(realm, user) — THIS
    // seam — so an IGA-on realm captures a DELETE_USER CR (202) instead of
    // deleting. The real delete happens at commit via
    // IgaReplayDispatcher.replayDeleteUser (under IGA_REPLAY_ACTIVE → isIgaActive
    // is false → this override passes straight through). System/default users are
    // GOVERNED too (no hard block); the only pass-through is the
    // vendor-provisioning bypass + IGA-off, both folded into isIgaActive.
    // -------------------------------------------------------------------------

    @Override
    public boolean removeUser(RealmModel realm, UserModel user) {
        if (isIgaActive(realm) && user != null) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("USER_ID", user.getId());
            row.put("REALM_ID", realm.getId());
            row.put("USERNAME", user.getUsername());
            recordAndThrow(realm, "USER", user.getId(), "DELETE_USER", List.of(row));
            return false; // unreachable — recordAndThrow always throws
        }
        return super.removeUser(realm, user);
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
            // accept-unattested default-role grant (PATH-INDEPENDENT).
            // Pass addDefaultRoles=true to the 5-arg local-storage super.addUser for
            // EVERY create path under an open-registration (RegOn) realm — registration
            // form, Tide IdP-broker first-login, link-tide-account enrollment,
            // external-IdP first-login, token-exchange, admin-create — subject only to
            // the MF2 benign-composite guard. KC's JpaUserProvider.addUser then grants
            // realm.getDefaultRole() + joins the default groups on the REAL JpaUser (a
            // plain UserAdapter — in JpaUserProvider), BEFORE we wrap it in the capture
            // adapter. That grant is therefore NOT routed through the IGA capture path →
            // no nested GRANT_ROLES CR — and it PERSISTS on the live user (for the
            // persist-pending self-enrollment terminals).
            //
            // WHY PATH-INDEPENDENT (the staging bug fix): the earlier gate keyed the
            // grant on a live StackWalker signal — a RegistrationUserCreation frame OR a
            // positive Tide-broker check that required the auth-session BROKERED_CONTEXT
            // note's IdP *alias* to equal the literal "tide". On the deployed
            // Tide-broker / link-tide enrollment path that signal did not resolve (no
            // live Tide-broker note at the addUser instant, and the brokered IdP alias
            // need not be "tide"), so grantDefaultRoles came back false and Tide-enrolled
            // users (e.g. staging keylessh 6d1a3bbf, uvuv) were created ROLELESS → no
            // account aud → ORK TVE "attested claim 'aud' is suppressed". The gate is now
            // keyed ONLY on RegOn + the MF2 benign-composite guard (see
            // shouldGrantDefaultRolesOnSelfCreate) — no stack-frame / broker-alias
            // sniffing — so EVERY enrollment path lands the local default-role.
            //
            // WHY GRANT AT CREATION: an accept-unattested self-enroll user is admitted
            // UNSIGNED at login and its CREATE_USER CR never commits, so the D3
            // commit-replay default-role grant (IgaReplayDispatcher.replayCreateUser)
            // never runs. Without granting here the user is ROLELESS → KC builds the
            // token with empty resource_access → no `account` audience → the ORK TVE
            // rejects "attested claim 'aud' is suppressed in token" (the producer closure
            // attests aud=[account] from the universal-inherited realm default-role's
            // account children).
            //
            // CLOSURE INVARIANT (gate still admits): the realm default-role id is
            // the D1b exclusion in RealmAttestationExporter.perUserUnits — a user
            // holding ONLY default-roles → empty role_ids → NO user_role_mapping_set
            // unit. So the user HOLDS default-roles (token carries the account aud)
            // AND the producer closure has no role-mapping unit (the
            // default-roles-only gate still admits the unsigned user_identity). This
            // holds because the ORK universal-inherits the realm default-role set
            // (U19 RealmDefaultRolesSetAttestationUnit) for everyone.
            //
            // BLAST RADIUS: admin-create / service-account / governed creates are
            // captured-then-vetoed — the creation-time grant is on the scratch user and
            // is discarded with the request-tx rollback, then re-granted for real at
            // commit via the D3 replay path — so granting here is a harmless idempotent
            // no-op for them; only the persist-pending self-enrollment terminals retain
            // it. When RegOn is OFF nothing is granted here (stock-suppressed), so the
            // open-registration posture is the gate.
            boolean grantDefaultRoles = shouldGrantDefaultRolesOnSelfCreate(realm);
            String userId = KeycloakModelUtils.generateId();
            UserModel base = super.addUser(realm, userId,
                    username == null ? null : username.toLowerCase(),
                    grantDefaultRoles, false);
            if (grantDefaultRoles) {
                log.infof("IGA capture CREATE_USER: default-role grant under RegOn "
                        + "(path-independent: registration form / Tide IdP-broker / "
                        + "link-tide / any create; registrationAllowed=true, benign "
                        + "default-role composite) — granted realm default-role + default "
                        + "groups on the live user (uuid=%s) at creation so the "
                        + "accept-unattested enroll token carries the account aud; the "
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

    /** The Tide social/broker IdP provider id (TideIdentityProviderFactory.PROVIDER_ID). */
    private static final String TIDE_IDP_PROVIDER_ID = "tide";

    /** The auth-session note key the broker context is serialized under (AbstractIdpAuthenticator). */
    private static final String BROKERED_CONTEXT_NOTE = "BROKERED_CONTEXT";

    /**
     * PATH-INDEPENDENT default-role grant gate for the 1-arg
     * {@link #addUser(RealmModel, String)} capture branch.
     *
     * <p><b>Why path-independent (the staging bug fix).</b> The former gate keyed the
     * grant on a live {@link StackWalker} self-enrollment signal — a
     * {@code RegistrationUserCreation} frame OR a positive Tide-broker check that
     * required the auth-session {@code BROKERED_CONTEXT} note's IdP <em>alias</em> to
     * equal the literal {@code "tide"}. On the deployed Tide-broker / link-tide
     * enrollment path that signal did NOT resolve (the stock broker create carries no
     * live Tide-broker note at the {@code addUser} instant, and
     * {@code SerializedBrokeredIdentityContext.getIdentityProviderId()} returns the
     * configured IdP <em>alias</em>, which need not be {@code "tide"}), so
     * {@code grantDefaultRoles} came back {@code false} and Tide-enrolled users were
     * created ROLELESS → empty {@code resource_access} → no {@code account} audience →
     * the ORK TVE rejects the login ("attested claim 'aud' is suppressed in token").
     * Fragile stack-frame / broker-alias sniffing is removed; the grant now fires for
     * EVERY create path (registration form, Tide IdP-broker first-login,
     * link-tide-account enrollment, external-IdP first-login, token-exchange,
     * admin-create) — that is what a realm <em>default</em> role means.
     *
     * <p><b>The two guards that remain (both genuinely load-bearing):</b>
     * <ol>
     *   <li><b>RegOn</b> ({@code realm.isRegistrationAllowed()}) — the open-registration
     *       posture. When RegOn is OFF nothing is granted here (stock-suppressed); the
     *       accept-unattested admit-unsigned behaviour is scoped to open-registration
     *       realms, and closed-realm admin creates still receive default-roles via the
     *       commit-time D3 replay grant ({@code IgaReplayDispatcher.replayCreateUser}).</li>
     *   <li><b>MF2 benign-composite guard</b>
     *       ({@link org.tidecloak.iga.services.DefaultRoleCompositeGuard#isBenignDefaultRoleComposite})
     *       — never confer a TAINTED {@code default-roles-<realm>} (a privileged composite
     *       child) to an unsigned self-registrant. If the composite is non-benign the grant
     *       refuses and the user falls back to the normal fail-closed / CR path. This is
     *       the sole privilege-escalation gate; dropping the frame narrowing does NOT
     *       reopen the MF2 vector because a privileged default-role is still refused here.</li>
     * </ol>
     *
     * <p><b>TVE-safety (unchanged).</b> The realm default-role id is the D1b exclusion in
     * {@code RealmAttestationExporter.perUserUnits}: a user holding ONLY default-roles →
     * empty {@code role_ids} → NO {@code user_role_mapping_set} unit, and the ORK
     * universal-inherits the realm default-role set (U19
     * {@code RealmDefaultRolesSetAttestationUnit}). So granting default-roles directly at
     * creation carries the {@code account} audience in the token while the producer
     * closure still emits no per-user role-mapping unit — the default-roles-only
     * user_identity is admitted unsigned exactly as before.
     *
     * <p><b>Blast radius on non-self-enroll paths.</b> Admin-create and governed creates
     * are captured-then-vetoed: the creation-time grant is on the real (scratch) user and
     * is discarded with the request-tx rollback, then re-granted for real at commit via
     * the D3 replay path — so granting here is a harmless no-op for them. Service-account
     * creates are likewise vetoed/replayed. Only the persist-pending self-enrollment paths
     * (registration form, Tide-broker, link-tide) actually retain the creation-time grant,
     * which is precisely the intent. The underlying
     * {@code JpaUserProvider.addUser(..., addDefaultRoles=true)} grant is idempotent
     * ({@code grantRole} no-ops when the role is already present), so no double-grant occurs.
     */
    private boolean shouldGrantDefaultRolesOnSelfCreate(RealmModel realm) {
        boolean registrationAllowed = realm.isRegistrationAllowed();
        boolean benignComposite = org.tidecloak.iga.services.DefaultRoleCompositeGuard
                .isBenignDefaultRoleComposite(realm);
        if (registrationAllowed && !benignComposite) {
            // MF2: never grant (and never mark eligible) a tainted default-role composite.
            log.warnf("IGA self-enroll REFUSED (MF2 guard): realm '%s' default-role "
                    + "composite is NON-BENIGN (privileged child present). NOT granting "
                    + "default-roles at creation and NOT admitting unsigned — the create "
                    + "falls back to the normal fail-closed / CR path.", realm.getName());
        }
        return shouldGrantDefaultRolesOnSelfCreate(registrationAllowed, benignComposite);
    }

    /**
     * Pure, path-independent, unit-testable form of the default-role grant gate. Grant iff
     * RegOn is on AND the realm default-role composite is benign (MF2). There is NO
     * stack-frame or broker-alias input — the decision does not depend on the call path,
     * which is what fixes the Tide IdP-broker / link-tide enrollment miss.
     *
     * @param registrationAllowed        the realm RegOn flag ({@code realm.isRegistrationAllowed()})
     * @param benignDefaultRoleComposite MF2 guard result
     *        ({@code DefaultRoleCompositeGuard.isBenignDefaultRoleComposite(realm)})
     */
    static boolean shouldGrantDefaultRolesOnSelfCreate(boolean registrationAllowed,
                                                       boolean benignDefaultRoleComposite) {
        return registrationAllowed && benignDefaultRoleComposite;
    }

    /**
     * Live-stack Tide-broker enrollment check, session-parameterised so the capture
     * adapter ({@link IgaUserAdapter}) can reuse the exact same Tide-broker enrollment
     * seam when deciding whether the admin-terminal capture-then-veto rollback applies
     * (see {@code IgaUserAdapter#getId}). NOTE: this is NOT used by the default-role grant
     * gate — that gate is now path-independent (see
     * {@link #shouldGrantDefaultRolesOnSelfCreate(RealmModel)}). Contract: true iff the
     * current auth session carries a brokered-identity
     * context whose IdP id is the Tide provider ({@value #TIDE_IDP_PROVIDER_ID}); any failure
     * to resolve the context → false.
     */
    static boolean isTideBrokerEnrollment(KeycloakSession igaSession) {
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

    // addFederatedIdentity is NOT overridden — federated identities are IdP
    // brokering, not token claims, and are NOT governed. KC's
    // UsersResource.createUser → RepresentationToModel.createFederatedIdentities
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
