package org.tidecloak.iga.services;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.models.ClientModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OrganizationModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.organization.OrganizationProvider;
import org.tidecloak.iga.attestors.IgaScopeResolver;

/**
 * Repoints every declared IGA approver-role config surface to the canonical
 * Tide approver role <b>{@code tide-realm-admin}</b> when a realm switches to
 * Tide IGA (the toggle-on / {@code iga.attestor=tide} path in
 * {@link org.tidecloak.iga.rest.TideAdminCompatResource#toggleIga}).
 *
 * <p><b>Why.</b> In Tideless IGA an operator may pin approvals to a custom or
 * attribute-derived role via {@code iga.approverRole}. In Tide mode the
 * canonical approver role is {@code tide-realm-admin} — the role the toggle-on
 * flow creates as its first stage and the one the multiAdmin quorum consults at
 * commit time ({@link IgaScopeResolver#requireApprover}). On the switch to
 * Tide, every place that declares a required approver role must therefore be
 * repointed to {@code tide-realm-admin} so a stale Tideless approver role can
 * never gate (or silently bypass) a post-flip commit.</p>
 *
 * <h2>The full set of approver-role config surfaces</h2>
 * The only approver-role config primitive {@link IgaScopeResolver} consumes is
 * the {@code iga.approverRole} attribute, harvested from these entity kinds:
 * <ul>
 *   <li><b>realm</b> attribute {@code iga.approverRole} (the realm default /
 *       admin-coverage surface; {@code TideAdminCompatResource}),</li>
 *   <li><b>each realm role</b> ({@link IgaScopeResolver#collectRoleScope}),</li>
 *   <li><b>each client role</b> (same collector — client roles are scope-marked
 *       exactly like realm roles),</li>
 *   <li><b>each client</b> ({@link IgaScopeResolver#collectClientScope}),</li>
 *   <li><b>each group</b>, walked with ancestors
 *       ({@link IgaScopeResolver#walkGroupAncestors}),</li>
 *   <li><b>each identity provider</b> config map
 *       ({@link IgaScopeResolver#collectIdpScope}),</li>
 *   <li><b>each organization</b> attributes
 *       ({@link IgaScopeResolver#collectOrganizationScope}).</li>
 * </ul>
 * There is no other approver-role source: {@code IGA_ROLE_POLICY} is the
 * un-enforced Tide-mode scaffold (not a gate input), and the
 * {@code IgaForsetiContractService} carries no approver-role field.
 *
 * <h2>Idempotency &amp; scope</h2>
 * For every surface we only rewrite a <b>non-blank</b> {@code iga.approverRole}
 * that is <b>not already</b> {@code tide-realm-admin}. A surface that never
 * declared an approver role is left untouched (it correctly falls through to the
 * realm default), and a re-run on an already-Tide realm is a no-op. This makes
 * the sweep safe to run on every toggle-on, including a re-toggle.
 *
 * <p><b>Suppression.</b> This sweep runs inside the toggle handler BEFORE the
 * {@code isIGAEnabled} flip — IGA is still OFF — so the attribute writes are
 * plain model writes and are not captured as {@code SET_*_ATTRIBUTE} CRs. It
 * does not depend on the {@code IGA_REPLAY_ACTIVE} guard, but running pre-flip
 * keeps it consistent with the sibling tide-realm-admin role creation and the
 * {@code iga.attestor=tide} write.</p>
 *
 * <p><b>firstAdmin safety.</b> Repointing to {@code tide-realm-admin} does not
 * affect the firstAdmin flow: {@code IgaScopeResolver} bypasses
 * {@code requireApprover} entirely in firstAdmin mode
 * ({@code isFirstAdminMode}), and ADOPT_* CRs are a no-op for the approver
 * gate. The repointed value only becomes load-bearing once the realm flips to
 * multiAdmin, which is exactly the role the quorum is expected to hold.</p>
 *
 * <p><b>Best-effort.</b> Each surface is wrapped independently; a failure on one
 * entity logs and continues so a single bad row can never abort the toggle.</p>
 */
public final class IgaApproverRoleRepointer {

    private static final Logger log = Logger.getLogger(IgaApproverRoleRepointer.class);

    /** The canonical Tide approver role created by the toggle-on flow. */
    public static final String TIDE_REALM_ADMIN = "tide-realm-admin";

    /** {@code iga.approverRole} — the single approver-role config attribute. */
    public static final String ATTR_APPROVER_ROLE = IgaScopeResolver.ATTR_APPROVER_ROLE;

    private IgaApproverRoleRepointer() {
    }

    /** Per-surface count of approver-role values actually rewritten. */
    public static final class Result {
        public int realm;
        public int realmRoles;
        public int clientRoles;
        public int clients;
        public int groups;
        public int idps;
        public int organizations;

        public int total() {
            return realm + realmRoles + clientRoles + clients + groups + idps + organizations;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("realm", realm);
            m.put("realmRoles", realmRoles);
            m.put("clientRoles", clientRoles);
            m.put("clients", clients);
            m.put("groups", groups);
            m.put("idps", idps);
            m.put("organizations", organizations);
            m.put("total", total());
            return m;
        }
    }

    /**
     * Whether {@code current} needs repointing: it must be a non-blank value
     * that is not already {@code tide-realm-admin}. (Trim-insensitive compare so
     * a whitespace-padded {@code "tide-realm-admin"} is treated as already
     * canonical.)
     */
    static boolean needsRepoint(String current) {
        if (current == null) return false;
        String trimmed = current.trim();
        return !trimmed.isEmpty() && !TIDE_REALM_ADMIN.equals(trimmed);
    }

    /**
     * Repoint every declared {@code iga.approverRole} on the realm to
     * {@code tide-realm-admin}. Idempotent; best-effort per surface.
     *
     * @return per-surface counts of values actually rewritten.
     */
    public static Result repointToTideRealmAdmin(KeycloakSession session, RealmModel realm) {
        Result r = new Result();
        if (realm == null) return r;

        // 1) Realm-level default approver role.
        try {
            if (needsRepoint(realm.getAttribute(ATTR_APPROVER_ROLE))) {
                realm.setAttribute(ATTR_APPROVER_ROLE, TIDE_REALM_ADMIN);
                r.realm++;
            }
        } catch (RuntimeException ex) {
            log.warnf(ex, "IGA repoint: realm-level iga.approverRole rewrite failed for realm %s (continuing).",
                    realm.getName());
        }

        // 2) Realm roles.
        try {
            for (RoleModel role : session.roles().getRealmRolesStream(realm).toList()) {
                try {
                    if (needsRepoint(role.getFirstAttribute(ATTR_APPROVER_ROLE))) {
                        role.setSingleAttribute(ATTR_APPROVER_ROLE, TIDE_REALM_ADMIN);
                        r.realmRoles++;
                    }
                } catch (RuntimeException ex) {
                    log.debugf(ex, "IGA repoint: realm-role %s iga.approverRole rewrite failed (continuing).",
                            role.getName());
                }
            }
        } catch (RuntimeException ex) {
            log.warnf(ex, "IGA repoint: realm-role iteration failed for realm %s (continuing).", realm.getName());
        }

        // 3) Clients + their client roles.
        try {
            for (ClientModel client : realm.getClientsStream().toList()) {
                try {
                    if (needsRepoint(client.getAttribute(ATTR_APPROVER_ROLE))) {
                        client.setAttribute(ATTR_APPROVER_ROLE, TIDE_REALM_ADMIN);
                        r.clients++;
                    }
                } catch (RuntimeException ex) {
                    log.debugf(ex, "IGA repoint: client %s iga.approverRole rewrite failed (continuing).",
                            client.getClientId());
                }
                try {
                    for (RoleModel role : client.getRolesStream().toList()) {
                        try {
                            if (needsRepoint(role.getFirstAttribute(ATTR_APPROVER_ROLE))) {
                                role.setSingleAttribute(ATTR_APPROVER_ROLE, TIDE_REALM_ADMIN);
                                r.clientRoles++;
                            }
                        } catch (RuntimeException ex) {
                            log.debugf(ex, "IGA repoint: client-role %s iga.approverRole rewrite failed (continuing).",
                                    role.getName());
                        }
                    }
                } catch (RuntimeException ex) {
                    log.debugf(ex, "IGA repoint: client %s role iteration failed (continuing).",
                            client.getClientId());
                }
            }
        } catch (RuntimeException ex) {
            log.warnf(ex, "IGA repoint: client iteration failed for realm %s (continuing).", realm.getName());
        }

        // 4) Groups (flat stream already includes every subgroup).
        try {
            for (GroupModel group : realm.getGroupsStream().toList()) {
                try {
                    if (needsRepoint(group.getFirstAttribute(ATTR_APPROVER_ROLE))) {
                        group.setSingleAttribute(ATTR_APPROVER_ROLE, TIDE_REALM_ADMIN);
                        r.groups++;
                    }
                } catch (RuntimeException ex) {
                    log.debugf(ex, "IGA repoint: group %s iga.approverRole rewrite failed (continuing).",
                            group.getName());
                }
            }
        } catch (RuntimeException ex) {
            log.warnf(ex, "IGA repoint: group iteration failed for realm %s (continuing).", realm.getName());
        }

        // 5) Identity providers. IdP carries approverRole in its config map; the
        //    edit must be persisted via identityProviders().update(idp).
        try {
            for (IdentityProviderModel idp : realm.getIdentityProvidersStream().toList()) {
                try {
                    Map<String, String> config = idp.getConfig();
                    if (config != null && needsRepoint(config.get(ATTR_APPROVER_ROLE))) {
                        config.put(ATTR_APPROVER_ROLE, TIDE_REALM_ADMIN);
                        session.identityProviders().update(idp);
                        r.idps++;
                    }
                } catch (RuntimeException ex) {
                    log.debugf(ex, "IGA repoint: idp %s iga.approverRole rewrite failed (continuing).",
                            idp.getAlias());
                }
            }
        } catch (RuntimeException ex) {
            log.warnf(ex, "IGA repoint: idp iteration failed for realm %s (continuing).", realm.getName());
        }

        // 6) Organizations. OrganizationModel exposes only the full attribute
        //    map (no single-attr setter), so read-modify-write the map and
        //    re-set it, preserving every other attribute and any extra values.
        try {
            OrganizationProvider orgProvider = session.getProvider(OrganizationProvider.class);
            if (orgProvider != null) {
                for (OrganizationModel org : orgProvider.getAllStream().toList()) {
                    try {
                        Map<String, List<String>> attrs = org.getAttributes();
                        List<String> cur = (attrs == null) ? null : attrs.get(ATTR_APPROVER_ROLE);
                        String first = (cur == null || cur.isEmpty()) ? null : cur.get(0);
                        if (needsRepoint(first)) {
                            Map<String, List<String>> updated = new LinkedHashMap<>(attrs);
                            updated.put(ATTR_APPROVER_ROLE, List.of(TIDE_REALM_ADMIN));
                            org.setAttributes(updated);
                            r.organizations++;
                        }
                    } catch (RuntimeException ex) {
                        log.debugf(ex, "IGA repoint: organization %s iga.approverRole rewrite failed (continuing).",
                                org.getName());
                    }
                }
            }
        } catch (RuntimeException ex) {
            log.warnf(ex, "IGA repoint: organization iteration failed for realm %s (continuing).", realm.getName());
        }

        if (r.total() > 0) {
            log.infof("IGA toggle-on: repointed iga.approverRole -> %s for realm %s "
                            + "(realm=%d realmRoles=%d clientRoles=%d clients=%d groups=%d idps=%d orgs=%d)",
                    TIDE_REALM_ADMIN, realm.getName(),
                    r.realm, r.realmRoles, r.clientRoles, r.clients, r.groups, r.idps, r.organizations);
        }
        return r;
    }
}
