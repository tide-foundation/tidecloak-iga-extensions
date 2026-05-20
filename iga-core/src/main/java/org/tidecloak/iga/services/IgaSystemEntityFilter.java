package org.tidecloak.iga.services;

import org.keycloak.models.RealmModel;
import org.tidecloak.iga.replay.IgaReplayExtension;

import java.util.Set;

/**
 * Phase 6b — system-entity skip rules for the toggle-on ADOPT scan.
 *
 * <p>The toggle-on scan ({@link IgaAdoptScan}) walks every unattested row in
 * the realm and (by default) emits a per-entity ADOPT_X change request. Two
 * categories of entities must NOT be quarantined under default settings,
 * because doing so locks the realm out of its own bootstrap:</p>
 * <ol>
 *   <li><b>Hard-pinned skips</b> — entities the scan MUST NEVER quarantine
 *       even with {@code iga.adopt.includeSystem=true}: the realm composite
 *       role {@code default-roles-&lt;realm&gt;} and the bookkeeping client
 *       {@code default-roles-&lt;realm&gt;} that backs it. Any user created in
 *       the realm receives the composite automatically — pending-quarantining
 *       it would freeze every subsequent login/create.</li>
 *   <li><b>Soft skips</b> (default on, can be opted out of with
 *       {@code iga.adopt.includeSystem=true}) — three sets:
 *     <ul>
 *       <li>KC's built-in per-realm admin clients
 *           ({@code realm-management}, {@code account},
 *           {@code account-console}, {@code security-admin-console},
 *           {@code broker}, {@code admin-cli}) AND every client-role under
 *           them. Avoids quarantining the very surface used to commit change
 *           requests.</li>
 *       <li>KC's default client-scopes
 *           ({@link #DEFAULT_CLIENT_SCOPE_NAMES} — profile, email, roles,
 *           role_list, …). Avoids quarantining the token-issuance plumbing
 *           every fresh realm starts with.</li>
 *       <li>KC's default realm roles
 *           ({@link #DEFAULT_REALM_ROLE_NAMES} — offline_access,
 *           uma_authorization). NOT the composite
 *           default-roles-&lt;realm&gt; (that is hard-pinned above).</li>
 *     </ul>
 *     All three can be brought under governance by an operator that
 *     explicitly wants to (set {@code iga.adopt.includeSystem=true}), but the
 *     default keeps the realm's bootstrap surface ungoverned.</li>
 * </ol>
 *
 * <p>The {@code master} realm is filtered earlier — at the toggle handler —
 * because Tide's master-realm escape hatch must remain unconditionally usable
 * for recovery. This class does NOT need to re-filter master: the toggle
 * handler refuses to enable IGA on master at all.</p>
 *
 * <p>Stateless utility. Lookups are cheap (string compare against a small
 * constant set); the scan invokes one call per row.</p>
 */
public final class IgaSystemEntityFilter {

    /**
     * KC's per-realm built-in clients. Mirrors
     * {@code RepresentationToModel#getBuiltinClients} / the master-realm setup
     * in stock KC 26.5.x — these clients are auto-created at realm creation
     * and back the admin/account/CLI surfaces.
     */
    public static final Set<String> BUILTIN_CLIENT_IDS = Set.of(
            "realm-management",
            "account",
            "account-console",
            "security-admin-console",
            "broker",
            "admin-cli"
    );

    /**
     * KC's per-realm default client-scopes, created automatically on realm
     * creation by the OIDC + SAML + (when enabled) ORGANIZATION protocol
     * factories and {@code RealmManager.setupOfflineTokens}. None of these are
     * admin-authored — bringing them under governance by default would
     * quarantine the entire token-issuance surface of a fresh realm. They are
     * soft-skipped (lifted by {@code iga.adopt.includeSystem=true}) so an
     * operator can still opt them in if needed.
     *
     * <p>Sources (Keycloak 26.5.5):
     * <ul>
     *   <li>{@code org.keycloak.protocol.oidc.OIDCLoginProtocolFactory
     *       #createDefaultClientScopesImpl}: profile, email, address, phone,
     *       roles, web-origins, microprofile-jwt, basic, service_account
     *       (always); acr (Profile.Feature.STEP_UP_AUTHENTICATION); organization
     *       (Profile.Feature.ORGANIZATION).</li>
     *   <li>{@code org.keycloak.services.managers.RealmManager
     *       #setupOfflineTokens} → {@code DefaultClientScopes
     *       .createOfflineAccessClientScope}: offline_access.</li>
     *   <li>{@code org.keycloak.protocol.saml.SamlProtocolFactory
     *       #createDefaultClientScopesImpl}: role_list (always);
     *       saml_organization (Profile.Feature.ORGANIZATION).</li>
     *   <li>{@code org.keycloak.protocol.oid4vc.OID4VCLoginProtocolFactory
     *       #createDefaultClientScopesImpl}: oid4vc_natural_person
     *       (when the OID4VC provider is enabled).</li>
     * </ul>
     * </p>
     *
     * <p>We list every name unconditionally (feature flags vary per
     * deployment); a missing scope just means the realm never had it and the
     * filter never sees a row to skip — no harm.</p>
     */
    public static final Set<String> DEFAULT_CLIENT_SCOPE_NAMES = Set.of(
            "profile",
            "email",
            "address",
            "phone",
            "offline_access",
            "roles",
            "web-origins",
            "microprofile-jwt",
            "acr",
            "basic",
            "service_account",
            "organization",
            "role_list",
            "saml_organization",
            "oid4vc_natural_person"
    );

    /**
     * KC's per-realm default realm roles, created automatically on realm
     * creation. Constants from {@code org.keycloak.models.Constants}:
     * <ul>
     *   <li>{@code OFFLINE_ACCESS_ROLE} ({@code "offline_access"}) — added by
     *       {@code KeycloakModelUtils.setupOfflineRole} from
     *       {@code RealmManager.setupOfflineTokens}.</li>
     *   <li>{@code AUTHZ_UMA_AUTHORIZATION} ({@code "uma_authorization"}) —
     *       added by {@code KeycloakModelUtils.setupAuthorizationServices} as
     *       part of {@code AUTHZ_DEFAULT_AUTHORIZATION_ROLES}.</li>
     * </ul>
     *
     * <p>Neither is the realm-composite-default-role
     * ({@code default-roles-&lt;realm&gt;}, hard-pinned above) — these two are
     * regular realm roles that the composite references, and they are
     * soft-skipped (lifted by {@code iga.adopt.includeSystem=true}).</p>
     */
    public static final Set<String> DEFAULT_REALM_ROLE_NAMES = Set.of(
            "offline_access",
            "uma_authorization"
    );

    private IgaSystemEntityFilter() {
    }

    /**
     * @param realm        the realm being scanned (its name supplies the
     *                     {@code default-roles-&lt;realm&gt;} hard-pin string).
     * @param entityType   USER | ROLE | GROUP | CLIENT | CLIENT_SCOPE (the
     *                     five Phase 6b scan targets).
     * @param entityId     the entity's own UUID (unused today but kept on the
     *                     surface so future rules can pivot on it without
     *                     re-threading callers).
     * @param entityName   the entity's human-readable name (USERNAME for
     *                     USER, ROLE name, GROUP name, CLIENT_SCOPE name); for
     *                     CLIENT this is the {@code clientId} string. May be
     *                     {@code null} when the scanner cannot resolve it.
     * @param parentClientId for client-roles, the {@code clientId} string of
     *                     the role's owning client (used to soft-skip every
     *                     role under a built-in client when {@code
     *                     includeSystem=false}). {@code null} for realm roles
     *                     and non-ROLE entity types.
     * @param includeSystem if {@code true}, soft-skip rules are LIFTED.
     *                     Hard-pinned skips remain.
     * @return {@code true} when this entity must be skipped by the scan.
     */
    public static boolean shouldSkip(RealmModel realm,
                                      String entityType,
                                      String entityId,
                                      String entityName,
                                      String parentClientId,
                                      boolean includeSystem) {
        if (realm == null || entityType == null) {
            return false;
        }
        String defaultRolesName = "default-roles-" + realm.getName();

        // -------------------------------------------------------------------
        // HARD-PINNED skips — regardless of includeSystem.
        // -------------------------------------------------------------------
        if (IgaReplayExtension.ENTITY_TYPE_ROLE.equals(entityType)) {
            // The realm composite role default-roles-<realm>. KC binds every
            // new user to this composite at create-time, so quarantining it
            // would brick the realm. Pin even when the operator asks to
            // include system entities.
            if (defaultRolesName.equals(entityName)) {
                return true;
            }
        }
        if (IgaReplayExtension.ENTITY_TYPE_CLIENT.equals(entityType)) {
            // The bookkeeping client default-roles-<realm> exists alongside
            // the role and is similarly pinned.
            if (defaultRolesName.equals(entityName)) {
                return true;
            }
        }

        // -------------------------------------------------------------------
        // SOFT skips — lifted when includeSystem=true.
        // -------------------------------------------------------------------
        if (includeSystem) {
            return false;
        }
        if (IgaReplayExtension.ENTITY_TYPE_CLIENT.equals(entityType)) {
            return entityName != null && BUILTIN_CLIENT_IDS.contains(entityName);
        }
        if (IgaReplayExtension.ENTITY_TYPE_ROLE.equals(entityType)) {
            // Client-roles whose parent client is built-in: skip them as a
            // unit with their parent.
            if (parentClientId != null) {
                return BUILTIN_CLIENT_IDS.contains(parentClientId);
            }
            // Realm roles auto-created by the realm bootstrap
            // (offline_access, uma_authorization). The realm composite
            // default-roles-<realm> is hard-pinned above and is not part of
            // this soft set.
            return entityName != null && DEFAULT_REALM_ROLE_NAMES.contains(entityName);
        }
        if (IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE.equals(entityType)) {
            // Default client-scopes auto-created by OIDC/SAML/OID4VC protocol
            // factories + RealmManager.setupOfflineTokens. Operator-authored
            // scopes (e.g. the e2e p6b-scope) fall through and ARE quarantined.
            return entityName != null && DEFAULT_CLIENT_SCOPE_NAMES.contains(entityName);
        }
        return false;
    }
}
