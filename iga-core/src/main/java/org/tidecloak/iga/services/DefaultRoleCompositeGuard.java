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
 * ({@code default-roles-<realm>}) expands ONLY to a benign, non-privileged
 * baseline before the accept-unattested self-registration model trusts it.
 *
 * <h2>The hole this closes</h2>
 * The whole accept-unattested self-enrollment model trusts that
 * {@code default-roles-<realm>} confers only benign {@code account} baseline —
 * but NOTHING validated that. If an admin (or a committed CR) adds a privileged
 * role ({@code tide-realm-admin}, {@code manage-users}, any
 * {@code realm-management} client role) as a COMPOSITE CHILD of the default
 * role:
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
 * <h2>The guard</h2>
 * Walk the {@code default-roles-<realm>} composite TRANSITIVELY (cycle-safe) and
 * fail-closed if ANY leaf is not on the benign allowlist. "Benign" is an
 * ALLOWLIST (not a deny-list — an unknown role is tainted, never benign):
 * <ul>
 *   <li>the realm composite root {@code default-roles-<realm>} itself (the node
 *       we are expanding) and any nested composite that is itself only a
 *       grouping of benign leaves;</li>
 *   <li>the two stock default realm roles {@code offline_access},
 *       {@code uma_authorization} (see {@link IgaSystemEntityFilter#DEFAULT_REALM_ROLE_NAMES});</li>
 *   <li>the stock {@code account} / {@code account-console} client baseline
 *       roles ({@link #BENIGN_ACCOUNT_CLIENT_IDS} ×
 *       {@link #BENIGN_ACCOUNT_ROLE_NAMES}: view-profile, manage-account,
 *       manage-account-links, view-applications, view-consent, manage-consent,
 *       delete-account, view-groups).</li>
 * </ul>
 * EVERYTHING ELSE is tainted: any {@code realm-management} client role,
 * {@code tide-realm-admin}, any client role under a non-account client, and any
 * realm role not in the benign set (this catches {@code admin},
 * {@code manage-*}, {@code realm-admin}, and any operator-authored role we
 * cannot positively classify). On taint we emit a LOUD {@code ERROR} naming the
 * offending child + realm and return {@code false}.
 *
 * <p>Stateless utility. The pure leaf classifier {@link #isBenignChild(boolean,
 * String, String, String)} is unit-testable without a realm; the realm walk
 * {@link #isBenignDefaultRoleComposite(RealmModel)} is exercised end-to-end.</p>
 */
public final class DefaultRoleCompositeGuard {

    private static final Logger log = Logger.getLogger(DefaultRoleCompositeGuard.class);

    /** The {@code account} surface clients whose baseline roles are benign. */
    public static final Set<String> BENIGN_ACCOUNT_CLIENT_IDS = Set.of(
            "account",
            "account-console"
    );

    /**
     * The stock {@code account} client baseline roles (Keycloak 26.5.5
     * {@code AccountRoles}). These are the only client roles a benign
     * default-role composite may confer. NOTE: {@code realm-management} roles are
     * NEVER benign — they are privileged by definition.
     */
    public static final Set<String> BENIGN_ACCOUNT_ROLE_NAMES = Set.of(
            "view-profile",
            "manage-account",
            "manage-account-links",
            "view-applications",
            "view-consent",
            "manage-consent",
            "delete-account",
            "view-groups"
    );

    private DefaultRoleCompositeGuard() {
    }

    /**
     * Pure, unit-testable single-leaf classifier. Given a role's
     * (isClientRole, name, owning-clientId-or-null) and the realm's
     * {@code default-roles-<realm>} composite-root name, return true iff the role
     * is on the benign allowlist.
     *
     * <p>ALLOWLIST semantics — an unrecognised role is NOT benign:</p>
     * <ol>
     *   <li>The composite root {@code default-roles-<realm>} itself (a realm role)
     *       is benign (it is the node being expanded / a benign grouping).</li>
     *   <li>A REALM role is benign iff it is {@code offline_access} or
     *       {@code uma_authorization} (the stock default realm roles) OR the
     *       composite root. Every other realm role (incl. {@code admin},
     *       {@code manage-*}, {@code tide-realm-admin} if ever modelled as a realm
     *       role, operator-authored roles) is TAINTED.</li>
     *   <li>A CLIENT role is benign iff its owning client is
     *       {@code account}/{@code account-console} AND its name is one of the
     *       stock account baseline roles. Every {@code realm-management} role
     *       (manage-users, manage-realm, realm-admin, tide-realm-admin, …) and
     *       every role under any other client is TAINTED.</li>
     * </ol>
     *
     * @param isClientRole       whether the role is a client role.
     * @param roleName           the role's name (may be {@code null} → tainted).
     * @param ownerClientId      the owning client's {@code clientId} for a client
     *                           role ({@code null} for a realm role).
     * @param defaultRolesName   the realm composite root name
     *                           ({@code default-roles-<realm>}).
     */
    public static boolean isBenignChild(boolean isClientRole, String roleName,
                                        String ownerClientId, String defaultRolesName) {
        if (roleName == null) {
            return false;
        }
        if (!isClientRole) {
            if (roleName.equals(defaultRolesName)) {
                return true; // the composite root / a benign nested grouping
            }
            return IgaSystemEntityFilter.DEFAULT_REALM_ROLE_NAMES.contains(roleName);
        }
        // Client role: benign ONLY under the account surface, and only the
        // stock baseline names. realm-management is never benign.
        return ownerClientId != null
                && BENIGN_ACCOUNT_CLIENT_IDS.contains(ownerClientId)
                && BENIGN_ACCOUNT_ROLE_NAMES.contains(roleName);
    }

    /**
     * Walk the realm's {@code default-roles-<realm>} composite TRANSITIVELY
     * (cycle-safe) and return true iff EVERY transitively-reachable role is
     * benign per {@link #isBenignChild}. Fails closed (returns {@code false} +
     * loud {@code ERROR}) on the first tainted child, naming it + the realm.
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
                        + "'%s' contains a NON-BENIGN child role '%s' (%s) — refusing to "
                        + "treat self-registered users as accept-unattested eligible. A "
                        + "privileged child on the default-role would confer privilege to "
                        + "every unsigned self-registered user via composite expansion "
                        + "(NOT a direct USER_ROLE_MAPPING row, so it is invisible to the "
                        + "D1b user_role_mapping_set unit). Self-reg falls back to the "
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
