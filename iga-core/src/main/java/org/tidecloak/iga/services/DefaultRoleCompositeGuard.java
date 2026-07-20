package org.tidecloak.iga.services;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.Set;

import org.jboss.logging.Logger;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;

/**
 * MF2 (HIGH) guard — validates that the realm composite default-role
 * ({@code default-roles-<realm>}) does NOT expand to any <em>privileged /
 * realm-escalation</em> role before the accept-unattested self-registration
 * model trusts it.
 *
 * <h2>The hole this closes</h2>
 * The whole accept-unattested self-enrollment model trusts that
 * {@code default-roles-<realm>} confers only a non-privileged baseline — but
 * NOTHING validated that. If an admin (or a committed CR) adds a privileged
 * role ({@code tide-realm-admin}, any {@code realm-management} client role such
 * as {@code manage-users} / {@code manage-realm} / {@code realm-admin}) as a
 * COMPOSITE CHILD of the default role:
 * <ul>
 *   <li>the creation-time / persist-pending grant
 *       ({@code IgaUserProvider.addUser} /
 *       {@code IgaUserAdapter.grantDefaultRolesForRegistration}) confers the
 *       WHOLE composite (children universal-inherited) to every self-registered
 *       user; and</li>
 *   <li>the producer D1b exclusion ({@code RealmAttestationExporter.userRoleMappingSet})
 *       filters only the DIRECT {@code default-roles-<realm>} row — it does NOT
 *       walk the composite, so the privileged children are conferred via
 *       composite expansion at token time, NOT a direct {@code USER_ROLE_MAPPING}
 *       row. {@code userRoleMappingSet} returns empty → no
 *       {@code user_role_mapping_set} unit → {@code selfRegEligible} stays true →
 *       the fully-unsigned user gets a PRIVILEGED token with nothing anomalous in
 *       the closure.</li>
 * </ul>
 *
 * <h2>The guard: a privileged-role DENYLIST walked transitively</h2>
 * <p>An earlier revision used a strict <em>allowlist</em> (only
 * {@code offline_access} / {@code uma_authorization} + the stock {@code account}
 * baseline were "benign", everything else tainted). That was too strict: a
 * normal realm default-role composite legitimately also contains the operator's
 * application baseline role (e.g. {@code appUser}) and Tide's self-scoped E2EE
 * roles ({@code _tide_dob.selfencrypt} / {@code _tide_dob.selfdecrypt}). The
 * allowlist classified those NON-privileged application roles as tainted, so the
 * grant was refused and Tide self-registrants were created ROLELESS (empty
 * {@code resource_access} → no {@code account} audience → ORK TVE rejects the
 * login: "attested claim 'aud' is suppressed in token").</p>
 *
 * <p>The guard is now a <b>denylist of the realm-escalation surface</b>. Walk
 * {@code default-roles-<realm>} TRANSITIVELY (cycle-safe) and fail-closed if ANY
 * transitively-reachable leaf is a <em>privileged</em> role. A role is
 * privileged iff it is on the Keycloak/Tide realm-administration surface:</p>
 * <ul>
 *   <li>ANY client role under the {@code realm-management} client — the entire
 *       KC admin authorization surface ({@code manage-users}, {@code manage-realm},
 *       {@code manage-clients}, {@code realm-admin}, {@code view-users},
 *       {@code impersonation}, {@code tide-realm-admin}, …). Realm authorization
 *       in Keycloak flows through these roles, so the whole client is privileged
 *       by definition;</li>
 *   <li>the Tide approver role {@code tide-realm-admin} by NAME wherever it
 *       appears (defense-in-depth — it lives on {@code realm-management}, but we
 *       also reject it if ever re-homed);</li>
 *   <li>a REALM role whose bare name denotes realm administration
 *       ({@link #PRIVILEGED_REALM_ROLE_NAMES}: {@code admin}, {@code realm-admin},
 *       {@code create-realm}) — belt-and-suspenders for names that strongly imply
 *       realm control.</li>
 * </ul>
 *
 * <p>EVERYTHING ELSE is benign: the composite root {@code default-roles-<realm>}
 * itself, the stock default realm roles, the stock {@code account} self-service
 * roles, the operator's application roles ({@code appUser} and any other
 * non-privileged realm/client role), and the self-scoped {@code _tide_*} E2EE
 * encrypt/decrypt roles. None of those confer control of the realm — they are
 * exactly the "default" baseline an operator intends every user to hold, which
 * is what a realm <em>default</em> role means.</p>
 *
 * <h2>Why a denylist + transitive walk is still fail-safe</h2>
 * The transitive walk descends into EVERY composite, so even if an operator
 * hides {@code realm-management:realm-admin} beneath a benignly-named grouping
 * role, the walk reaches the privileged LEAF and refuses. The denylist only
 * changes the treatment of <em>unknown NON-privileged</em> roles (they are now
 * accepted, which is the whole point — {@code appUser}/{@code _tide_*} are
 * unknown-but-benign application roles that legitimately belong on the default
 * composite). The escalation vector (a privileged child conferred to unsigned
 * self-registrants) stays closed because every privileged leaf is still refused.
 *
 * <p>Stateless utility. The pure leaf classifier {@link #isBenignChild(boolean,
 * String, String, String)} is unit-testable without a realm; the realm walk
 * {@link #isBenignDefaultRoleComposite(RealmModel)} is exercised end-to-end.</p>
 */
public final class DefaultRoleCompositeGuard {

    private static final Logger log = Logger.getLogger(DefaultRoleCompositeGuard.class);

    /**
     * The Keycloak admin-authorization client. EVERY role under this client is
     * privileged (it is the realm-management surface: manage-users, manage-realm,
     * realm-admin, view-users, impersonation, tide-realm-admin, …). Mirrors the
     * canonical clientId used by {@link TideRealmAdminGuard} /
     * {@link IgaSystemEntityFilter#BUILTIN_CLIENT_IDS}.
     */
    public static final String REALM_MANAGEMENT_CLIENT_ID = "realm-management";

    /**
     * Bare REALM-role names that denote realm administration / escalation and are
     * refused wherever they appear on the default-role composite. Keycloak
     * authorization actually flows through {@code realm-management} client roles
     * (covered above), so this is defense-in-depth for names that unambiguously
     * imply realm control. No legitimate default-role composite contains a realm
     * role with one of these names.
     */
    public static final Set<String> PRIVILEGED_REALM_ROLE_NAMES = Set.of(
            "admin",
            "realm-admin",
            "create-realm"
    );

    private DefaultRoleCompositeGuard() {
    }

    /**
     * Pure, unit-testable single-leaf classifier. Given a role's
     * (isClientRole, name, owning-clientId-or-null) and the realm's
     * {@code default-roles-<realm>} composite-root name, return {@code true} iff
     * the role is NON-privileged (benign).
     *
     * <p>DENYLIST semantics — a role is benign unless it is on the realm-escalation
     * surface (see {@link #isPrivilegedChild}):</p>
     * <ol>
     *   <li>a {@code null} name is fail-closed (we cannot classify it) → NOT benign;</li>
     *   <li>a CLIENT role under {@code realm-management} is privileged → NOT benign;</li>
     *   <li>the {@code tide-realm-admin} role (by name, any container) is
     *       privileged → NOT benign;</li>
     *   <li>a REALM role in {@link #PRIVILEGED_REALM_ROLE_NAMES} is privileged →
     *       NOT benign;</li>
     *   <li>everything else (the composite root {@code default-roles-<realm>}, the
     *       stock default realm roles, the {@code account} baseline, the operator's
     *       {@code appUser} and any other application role, the self-scoped
     *       {@code _tide_*} E2EE roles) is benign.</li>
     * </ol>
     *
     * @param isClientRole       whether the role is a client role.
     * @param roleName           the role's name ({@code null} → fail-closed, NOT benign).
     * @param ownerClientId      the owning client's {@code clientId} for a client
     *                           role ({@code null} for a realm role).
     * @param defaultRolesName   the realm composite root name
     *                           ({@code default-roles-<realm>}). Retained for API
     *                           stability; the root is benign because it is not a
     *                           privileged role, so no special-casing is needed.
     */
    public static boolean isBenignChild(boolean isClientRole, String roleName,
                                        String ownerClientId, String defaultRolesName) {
        if (roleName == null) {
            return false; // unresolvable name — fail closed
        }
        return !isPrivilegedChild(isClientRole, roleName, ownerClientId);
    }

    /**
     * True iff the role is on the realm-escalation surface (see class javadoc).
     * The sole privilege boundary of the guard.
     */
    static boolean isPrivilegedChild(boolean isClientRole, String roleName, String ownerClientId) {
        if (roleName == null) {
            return true; // cannot classify → treat as privileged (fail-closed)
        }
        // tide-realm-admin is privileged wherever it lives (defense-in-depth).
        if (IgaApproverRoleRepointer.TIDE_REALM_ADMIN.equals(roleName)) {
            return true;
        }
        if (isClientRole) {
            // The ENTIRE realm-management client is the admin surface. Every other
            // client's roles are application-scoped, not realm escalation.
            return REALM_MANAGEMENT_CLIENT_ID.equals(ownerClientId);
        }
        // Realm role: privileged only if its bare name denotes realm administration.
        return PRIVILEGED_REALM_ROLE_NAMES.contains(roleName);
    }

    /**
     * Walk the realm's {@code default-roles-<realm>} composite TRANSITIVELY
     * (cycle-safe) and return true iff NO transitively-reachable role is privileged
     * per {@link #isBenignChild}. Fails closed (returns {@code false} + loud
     * {@code ERROR}) on the first privileged child, naming it + the realm.
     *
     * <p>A {@code null} realm or a realm with no default role is treated as
     * benign-vacuous (true): there is nothing privileged to confer. (The
     * downstream grant path is independently gated on {@code registrationAllowed}
     * and only ever grants a non-null default role.)</p>
     */
    public static boolean isBenignDefaultRoleComposite(RealmModel realm) {
        if (realm == null) {
            return true;
        }
        RoleModel defaultRole = realm.getDefaultRole();
        if (defaultRole == null) {
            return true;
        }
        String defaultRolesName = "default-roles-" + realm.getName();

        Set<String> seen = new HashSet<>();
        Deque<RoleModel> stack = new ArrayDeque<>();
        stack.push(defaultRole);
        while (!stack.isEmpty()) {
            RoleModel role = stack.pop();
            if (role == null) {
                continue;
            }
            String id = role.getId();
            if (id != null && !seen.add(id)) {
                continue; // cycle / diamond — already classified this node
            }
            String ownerClientId = clientIdOf(realm, role);
            if (!isBenignChild(role.isClientRole(), role.getName(), ownerClientId, defaultRolesName)) {
                log.errorf("IGA MF2 GUARD: realm '%s' default-role composite "
                        + "'%s' contains a PRIVILEGED child role '%s' (%s) — refusing to "
                        + "treat self-registered users as accept-unattested eligible. A "
                        + "privileged child on the default-role would confer realm-escalation "
                        + "privilege to every unsigned self-registered user via composite "
                        + "expansion (NOT a direct USER_ROLE_MAPPING row, so it is invisible to "
                        + "the D1b user_role_mapping_set unit). Self-reg falls back to the "
                        + "fail-closed / CR path. Remove the privileged child from the "
                        + "default-role to restore self-registration.",
                        realm.getName(), defaultRolesName, role.getName(),
                        role.isClientRole()
                                ? "client role under client '" + ownerClientId + "'"
                                : "realm role");
                return false;
            }
            // Descend into composites.
            if (role.isComposite()) {
                role.getCompositesStream().forEach(stack::push);
            }
        }
        return true;
    }

    /**
     * Resolve the {@code clientId} of a client role's owning client, or
     * {@code null} for a realm role / unresolvable owner.
     */
    private static String clientIdOf(RealmModel realm, RoleModel role) {
        if (!role.isClientRole()) {
            return null;
        }
        try {
            ClientModel owner = realm.getClientById(role.getContainerId());
            return owner == null ? null : owner.getClientId();
        } catch (RuntimeException e) {
            return null;
        }
    }
}
