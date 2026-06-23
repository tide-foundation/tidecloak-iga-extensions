package org.tidecloak.iga.providers;

import org.keycloak.common.enums.SslRequired;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OTPPolicy;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.jpa.RealmAdapter;
import org.keycloak.models.jpa.entities.RealmEntity;

import jakarta.persistence.EntityManager;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Wraps RealmAdapter and intercepts realm-attribute writes (REALM_ATTRIBUTE
 * table) plus realm-column setters and realm-default-group operations for the
 * IGA approval workflow.
 *
 * <h3>Bootstrap: enabling IGA</h3>
 * When IGA is OFF and an admin sets the realm attribute {@code isIGAEnabled =
 * true}, {@code isIgaActive(this)} returns {@code false} at the moment of the
 * write so the call is passed straight through to {@code super.setAttribute}.
 * IGA only "engages" on the next write, after the attribute has been
 * persisted.
 *
 * <h3>Disable: turning IGA off</h3>
 * Once IGA is ON, an admin trying to set {@code isIGAEnabled = false} goes
 * through the normal change-request flow — disabling IGA requires admin
 * approval just like any other privileged realm-attribute write.
 *
 * <h3>Conflict rule</h3>
 * The existing one-pending-CR-per-entity rule applies: while a realm-attribute
 * or realm-config CR is pending, attempting to set or remove ANY realm
 * attribute / config on the same realm fails with 409. Admins must approve or
 * deny the existing CR first.
 *
 * <h3>Realm column setters (Tier 1 + Tier 2)</h3>
 * Security-critical and auth-behavior column setters on the REALM row are
 * intercepted into {@code SET_REALM_CONFIG} change requests. The CR carries a
 * single row {@code [{key: "<setterName>", value: "<stringified>"}]} so the
 * replay knows which setter to invoke. Themes, locale and token-lifetime
 * setters (Tier 3) are intentionally NOT intercepted — they remain writable
 * directly until a future expansion adds them.
 */
public class IgaRealmAdapter extends RealmAdapter {

    private final KeycloakSession igaSession;

    public IgaRealmAdapter(KeycloakSession session, EntityManager em, RealmEntity realm) {
        super(session, em, realm);
        this.igaSession = session;
    }

    private IgaChangeRequestService getService() {
        EntityManager em = igaSession.getProvider(JpaConnectionProvider.class).getEntityManager();
        return new IgaChangeRequestService(em, igaSession);
    }

    private boolean isIgaActive() {
        IgaChangeRequestService service = getService();
        // isIgaEnabled checks the very attribute being mutated; this means
        // an admin enabling IGA for the first time falls into the !active
        // branch and the write is applied directly.
        if (!service.isIgaEnabled(this)) return false;
        // Scoped vendor/system provisioning bypass: while VendorResource's
        // license/keygen provisioning block is active on this session, realm-
        // config + realm-attribute writes apply DIRECTLY (no CR, no pending-CR
        // conflict) — this single chokepoint covers every Tier-1/Tier-2 setter,
        // setAttribute/removeAttribute, default-group and default-scope override
        // (each of which gates on isIgaActive() before recording). Inert when the
        // flag is absent — ongoing admin edits stay governed.
        if (service.isVendorProvisioning()) return false;
        Object replay = igaSession.getAttribute("IGA_REPLAY_ACTIVE");
        return !"true".equals(replay);
    }

    @Override
    public void setAttribute(String name, String value) {
        if (!isIgaActive()) {
            super.setAttribute(name, value);
            return;
        }
        IgaChangeRequestService service = getService();
        String realmId = getId();
        Map<String, Object> row = new HashMap<>();
        row.put("REALM_ID", realmId);
        row.put("NAME", name);
        row.put("VALUE", value);
        // Coalesce same-request realm-attribute writes into one CR (a
        // multi-field realm-settings save); a foreign pending CR still 409s.
        service.coalesceOrCreate(this, "REALM", realmId, "SET_REALM_ATTRIBUTE",
                List.of(row), null, java.util.Set.of(name));
    }

    @Override
    public void removeAttribute(String name) {
        if (!isIgaActive()) {
            super.removeAttribute(name);
            return;
        }
        // Defect: realm-root PUT over-captured a destructive 14-row
        // REMOVE_REALM_ATTRIBUTE batch. Root cause is KC's
        // DefaultExportImportManager.updateRealm, which diffs the incoming rep's
        // attribute set against the live realm and fires removeAttribute for
        // EVERY existing attribute absent from the (often partial) PUT body:
        //   Set<String> attrsToRemove = strip(realm.getAttributes()).keySet();
        //   attrsToRemove.removeAll(rep.getAttributes().keySet());
        //   for (attr : attrsToRemove) realm.removeAttribute(attr);
        // A partial body therefore "removes" attributes the admin never touched.
        // The KC admin console always sends the FULL attribute set (attrsToRemove
        // empty → no removals), so suppressing the diff-loop removals only changes
        // the partial-body API path: we keep the omitted attributes (non-
        // destructive / fail-safe) and govern just the explicit SET changes. An
        // explicit, intentional realm-attribute removal still flows through any
        // other caller (e.g. a dedicated remove endpoint) and is captured.
        if (isOnRealmUpdateDiffRemoval()) {
            return;
        }
        IgaChangeRequestService service = getService();
        String realmId = getId();
        Map<String, Object> row = new HashMap<>();
        row.put("REALM_ID", realmId);
        row.put("NAME", name);
        service.coalesceOrCreate(this, "REALM", realmId, "REMOVE_REALM_ATTRIBUTE",
                List.of(row), null, java.util.Set.of(name));
    }

    /**
     * Is this {@code removeAttribute} call the destructive attribute-diff removal
     * inside {@code DefaultExportImportManager.updateRealm} (the realm-root
     * {@code PUT /admin/realms/{realm}} handler)? Matched by the presence of that
     * exact frame on the call stack. Same StackWalker idiom as
     * {@link #isOnRealmBootstrapPath()}.
     */
    private boolean isOnRealmUpdateDiffRemoval() {
        return StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames.anyMatch(f ->
                        "org.keycloak.storage.datastore.DefaultExportImportManager".equals(
                                f.getDeclaringClass().getName())
                                && "updateRealm".equals(f.getMethodName())));
    }

    private void checkNoPendingCr(IgaChangeRequestService service, String realmId) {
        var existing = service.findPending(realmId, "REALM", realmId);
        if (existing != null) {
            throw new IgaConflictException(existing.getId());
        }
    }

    // -------------------------------------------------------------------------
    // Realm column setters — recorded as SET_REALM_CONFIG change requests.
    //
    // Each interceptor calls {@link #recordRealmConfig(String, String)} which
    // checks the per-realm pending-CR rule then persists a CR with rows_json
    // {@code [{key: "<setterName>", value: "<stringified>"}]}. The replay
    // dispatches on key and calls the matching {@code super.setX(value)} with
    // {@code IGA_REPLAY_ACTIVE = "true"} so this wrapper passes through.
    // -------------------------------------------------------------------------

    private void recordRealmConfig(String key, String value) {
        IgaChangeRequestService service = getService();
        String realmId = getId();
        Map<String, Object> row = new HashMap<>();
        row.put("key", key);
        row.put("value", value);
        // Coalesce same-request realm-config setters into one SET_REALM_CONFIG
        // CR (a realm save touching several Tier-1/Tier-2 columns); merge keys on
        // the config "key". A foreign pending CR still 409s.
        service.coalesceOrCreate(this, "REALM", realmId, "SET_REALM_CONFIG",
                List.of(row), null, java.util.Set.of(key));
    }

    private static String s(Object v) {
        return v == null ? null : v.toString();
    }

    // ----- Tier 1: security-critical -----

    @Override
    public void setEnabled(boolean enabled) {
        if (!isIgaActive()) { super.setEnabled(enabled); return; }
        recordRealmConfig("setEnabled", s(enabled));
    }

    @Override
    public void setSslRequired(SslRequired sslRequired) {
        if (!isIgaActive()) { super.setSslRequired(sslRequired); return; }
        recordRealmConfig("setSslRequired", sslRequired == null ? null : sslRequired.name());
    }

    @Override
    public void setPasswordPolicy(PasswordPolicy policy) {
        if (!isIgaActive()) { super.setPasswordPolicy(policy); return; }
        recordRealmConfig("setPasswordPolicy", policy == null ? null : policy.toString());
    }

    @Override
    public void setOTPPolicy(OTPPolicy policy) {
        if (!isIgaActive()) { super.setOTPPolicy(policy); return; }
        // OTPPolicy is structured; we serialize the salient fields as a single
        // string `algorithm:digits:period:initialCounter:lookAheadWindow:type:reusable`.
        // Replay parses it back and rebuilds the OTPPolicy.
        String value = policy == null ? null : (
                policy.getAlgorithm() + ":" + policy.getDigits() + ":" + policy.getPeriod()
                        + ":" + policy.getInitialCounter() + ":" + policy.getLookAheadWindow()
                        + ":" + policy.getType() + ":" + policy.isCodeReusable());
        recordRealmConfig("setOTPPolicy", value);
    }

    @Override
    public void setBruteForceProtected(boolean value) {
        if (!isIgaActive()) { super.setBruteForceProtected(value); return; }
        recordRealmConfig("setBruteForceProtected", s(value));
    }

    @Override
    public void setPermanentLockout(final boolean val) {
        if (!isIgaActive()) { super.setPermanentLockout(val); return; }
        recordRealmConfig("setPermanentLockout", s(val));
    }

    @Override
    public void setRegistrationAllowed(boolean registrationAllowed) {
        if (!isIgaActive()) { super.setRegistrationAllowed(registrationAllowed); return; }
        recordRealmConfig("setRegistrationAllowed", s(registrationAllowed));
    }

    @Override
    public void setVerifyEmail(boolean verifyEmail) {
        if (!isIgaActive()) { super.setVerifyEmail(verifyEmail); return; }
        recordRealmConfig("setVerifyEmail", s(verifyEmail));
    }

    @Override
    public void setResetPasswordAllowed(boolean resetPasswordAllowed) {
        if (!isIgaActive()) { super.setResetPasswordAllowed(resetPasswordAllowed); return; }
        recordRealmConfig("setResetPasswordAllowed", s(resetPasswordAllowed));
    }

    @Override
    public void setBrowserFlow(AuthenticationFlowModel flow) {
        if (!isIgaActive()) { super.setBrowserFlow(flow); return; }
        recordRealmConfig("setBrowserFlow", flow == null ? null : flow.getId());
    }

    @Override
    public void setDirectGrantFlow(AuthenticationFlowModel flow) {
        if (!isIgaActive()) { super.setDirectGrantFlow(flow); return; }
        recordRealmConfig("setDirectGrantFlow", flow == null ? null : flow.getId());
    }

    @Override
    public void setResetCredentialsFlow(AuthenticationFlowModel flow) {
        if (!isIgaActive()) { super.setResetCredentialsFlow(flow); return; }
        recordRealmConfig("setResetCredentialsFlow", flow == null ? null : flow.getId());
    }

    @Override
    public void setClientAuthenticationFlow(AuthenticationFlowModel flow) {
        if (!isIgaActive()) { super.setClientAuthenticationFlow(flow); return; }
        recordRealmConfig("setClientAuthenticationFlow", flow == null ? null : flow.getId());
    }

    @Override
    public void setNotBefore(int notBefore) {
        if (!isIgaActive()) { super.setNotBefore(notBefore); return; }
        recordRealmConfig("setNotBefore", s(notBefore));
    }

    // ----- Tier 2: auth behavior -----

    @Override
    public void setName(String name) {
        if (!isIgaActive()) { super.setName(name); return; }
        recordRealmConfig("setName", name);
    }

    @Override
    public void setRegistrationFlow(AuthenticationFlowModel flow) {
        if (!isIgaActive()) { super.setRegistrationFlow(flow); return; }
        recordRealmConfig("setRegistrationFlow", flow == null ? null : flow.getId());
    }

    @Override
    public void setFirstBrokerLoginFlow(AuthenticationFlowModel flow) {
        if (!isIgaActive()) { super.setFirstBrokerLoginFlow(flow); return; }
        recordRealmConfig("setFirstBrokerLoginFlow", flow == null ? null : flow.getId());
    }

    @Override
    public void setRegistrationEmailAsUsername(boolean registrationEmailAsUsername) {
        if (!isIgaActive()) { super.setRegistrationEmailAsUsername(registrationEmailAsUsername); return; }
        recordRealmConfig("setRegistrationEmailAsUsername", s(registrationEmailAsUsername));
    }

    @Override
    public void setEditUsernameAllowed(boolean editUsernameAllowed) {
        if (!isIgaActive()) { super.setEditUsernameAllowed(editUsernameAllowed); return; }
        recordRealmConfig("setEditUsernameAllowed", s(editUsernameAllowed));
    }

    @Override
    public void setLoginWithEmailAllowed(boolean loginWithEmailAllowed) {
        if (!isIgaActive()) { super.setLoginWithEmailAllowed(loginWithEmailAllowed); return; }
        recordRealmConfig("setLoginWithEmailAllowed", s(loginWithEmailAllowed));
    }

    @Override
    public void setDuplicateEmailsAllowed(boolean duplicateEmailsAllowed) {
        if (!isIgaActive()) { super.setDuplicateEmailsAllowed(duplicateEmailsAllowed); return; }
        recordRealmConfig("setDuplicateEmailsAllowed", s(duplicateEmailsAllowed));
    }

    @Override
    public void setRememberMe(boolean rememberMe) {
        if (!isIgaActive()) { super.setRememberMe(rememberMe); return; }
        recordRealmConfig("setRememberMe", s(rememberMe));
    }

    @Override
    public void setFailureFactor(int failureFactor) {
        if (!isIgaActive()) { super.setFailureFactor(failureFactor); return; }
        recordRealmConfig("setFailureFactor", s(failureFactor));
    }

    @Override
    public void setMaxFailureWaitSeconds(int val) {
        if (!isIgaActive()) { super.setMaxFailureWaitSeconds(val); return; }
        recordRealmConfig("setMaxFailureWaitSeconds", s(val));
    }

    // -------------------------------------------------------------------------
    // Realm default groups
    //
    // The REALM_DEFAULT_GROUPS table is a list-collection table — it has no
    // entity class for per-row attestation. Coverage is provided by the change
    // request itself; the rows_json snapshot captures the (REALM_ID, GROUP_ID)
    // tuple for the audit trail.
    // -------------------------------------------------------------------------

    @Override
    public void addDefaultGroup(GroupModel group) {
        if (!isIgaActive()) { super.addDefaultGroup(group); return; }
        String realmId = getId();
        // coalesceOrCreate (not checkNoPendingCr+create): a realm-settings save
        // can touch several default-group/default-scope rows in one request and
        // each carries the SAME (REALM, realmId) entity key, so the second write
        // would otherwise self-409 against the first. Coalescing folds them into
        // one REALM-keyed CR. GROUP_NAME is a NAME_KEYS-resolvable label so the
        // inbox summary reads "Add realm default group <name>" instead of
        // "Realm (unnamed)" (the REALM entity has no useEntityName lookup).
        Map<String, Object> row = new HashMap<>();
        row.put("REALM_ID", realmId);
        row.put("GROUP_ID", group.getId());
        row.put("GROUP_NAME", group.getName());
        getService().coalesceOrCreate(this, "REALM", realmId, "ADD_REALM_DEFAULT_GROUP",
                List.of(row), null, java.util.Set.of(group.getId()));
    }

    @Override
    public void removeDefaultGroup(GroupModel group) {
        if (!isIgaActive()) { super.removeDefaultGroup(group); return; }
        String realmId = getId();
        Map<String, Object> row = new HashMap<>();
        row.put("REALM_ID", realmId);
        row.put("GROUP_ID", group.getId());
        row.put("GROUP_NAME", group.getName());
        getService().coalesceOrCreate(this, "REALM", realmId, "REMOVE_REALM_DEFAULT_GROUP",
                List.of(row), null, java.util.Set.of(group.getId()));
    }

    // -------------------------------------------------------------------------
    // Realm DEFAULT client scopes (DEFAULT_CLIENT_SCOPE table)
    //
    // The realm-level default-default / default-optional client-scope templates
    // every new client inherits — a token-shaping input. Captured here, at the
    // model adapter, NOT at the provider: with the infinispan cache ON the admin
    // route
    //   PUT /admin/realms/{realm}/default-default-client-scopes/{scopeId}
    //     → RealmAdminResource.addDefaultClientScope
    //     → realm.addDefaultClientScope(scope, defaultScope)   [CacheRealmAdapter]
    //     → cacheRealmAdapter.getDelegateForUpdate()           [== modelSupplier.get()
    //                                                              == IgaRealmProvider.getRealm
    //                                                              == THIS adapter]
    //     → updated.addDefaultClientScope(scope, defaultScope) [THIS override]
    // i.e. the cache adapter (model/infinispan RealmAdapter) DELEGATES
    // to the model adapter via getDelegateForUpdate(), so unlike the
    // CLIENT_SCOPE_CLIENT attach (which the cache ClientAdapter routes straight
    // to the provider, bypassing the model adapter — see IgaRealmProvider
    // .addClientScopes), the realm default-scope path DOES hit this override.
    // Same layer as the existing addDefaultGroup capture above.
    //
    // Each add/remove is captured as a REALM_DEFAULT_SCOPE_ADD / REMOVE CR
    // carrying {REALM_ID, SCOPE_ID, DEFAULT_SCOPE}; persistence of the
    // DEFAULT_CLIENT_SCOPE row is deferred to commit/replay (we never call
    // super on the governed path), where IgaReplayDispatcher applies
    // realm.addDefaultClientScope and stamps the ATTESTATION column.
    //
    // Bootstrap suppression: realm-creation drives realm.addDefaultClientScope
    // through the OIDC/SAML/OID4VC protocol factories + DefaultClientScopes
    // (offline_access). During genuine realm creation IGA is OFF (the toggle
    // attribute is not yet set) so isIgaActive() is already false and we pass
    // through; the StackWalker guard additionally suppresses the case where a
    // protocol factory re-runs createDefaultClientScopes on an already-IGA realm
    // (RealmManager feature re-init) — those bootstrap defaults are attested via
    // the toggle-on ADOPT scan, not live capture. Same idiom as
    // IgaRealmProvider.isOnClientCreationPath.
    // -------------------------------------------------------------------------

    @Override
    public void addDefaultClientScope(ClientScopeModel clientScope, boolean defaultScope) {
        if (!isIgaActive() || isOnRealmBootstrapPath()) {
            super.addDefaultClientScope(clientScope, defaultScope);
            return;
        }
        String realmId = getId();
        // coalesceOrCreate + CLIENT_SCOPE_NAME label — same rationale as
        // addDefaultGroup: back-to-back realm-default writes share the (REALM,
        // realmId) key and must coalesce instead of self-409, and the row needs a
        // NAME_KEYS-resolvable label so the summary reads the scope name not
        // "Realm (unnamed)".
        Map<String, Object> row = new HashMap<>();
        row.put("REALM_ID", realmId);
        row.put("SCOPE_ID", clientScope.getId());
        row.put("DEFAULT_SCOPE", defaultScope);
        row.put("CLIENT_SCOPE_NAME", clientScope.getName());
        getService().coalesceOrCreate(this, "REALM", realmId, "REALM_DEFAULT_SCOPE_ADD",
                List.of(row), null, java.util.Set.of(clientScope.getId()));
    }

    @Override
    public void removeDefaultClientScope(ClientScopeModel clientScope) {
        if (!isIgaActive() || isOnRealmBootstrapPath()) {
            super.removeDefaultClientScope(clientScope);
            return;
        }
        String realmId = getId();
        Map<String, Object> row = new HashMap<>();
        row.put("REALM_ID", realmId);
        row.put("SCOPE_ID", clientScope.getId());
        row.put("CLIENT_SCOPE_NAME", clientScope.getName());
        getService().coalesceOrCreate(this, "REALM", realmId, "REALM_DEFAULT_SCOPE_REMOVE",
                List.of(row), null, java.util.Set.of(clientScope.getId()));
    }

    /**
     * StackWalker discriminator: are we inside Keycloak's realm-bootstrap
     * default-scope setup, where the realm's default-default / default-optional
     * scope templates are auto-created and must NOT be live-governed (they are
     * attested via the toggle-on ADOPT scan instead)? Matches if ANY of the
     * bootstrap frames is present on the current stack (KC 26.5.5):
     * <ul>
     *   <li>{@code OIDCLoginProtocolFactory.createDefaultClientScopesImpl} —
     *       profile/email/address/phone/roles/web-origins/microprofile-jwt/acr/
     *       basic/organization.</li>
     *   <li>{@code SamlProtocolFactory.createDefaultClientScopesImpl} —
     *       role_list / saml_organization.</li>
     *   <li>{@code OID4VCLoginProtocolFactory.createDefaultClientScopesImpl} —
     *       oid4vc_natural_person.</li>
     *   <li>{@code DefaultClientScopes.createOfflineAccessClientScope} /
     *       {@code createDefaultClientScopes} — offline_access (server-spi-private
     *       {@code models.utils.DefaultClientScopes}).</li>
     *   <li>{@code RealmManager.createDefaultClientScopes} — the services-layer
     *       entry point (covers any future factory).</li>
     * </ul>
     * The governed admin route ({@code RealmAdminResource.addDefaultClientScope}
     * on an already-existing realm) carries NONE of these frames, so it is
     * correctly NOT suppressed. Class-name prefix match on the protocol factories
     * so any subclass / synthetic lambda frame counts too.
     */
    private boolean isOnRealmBootstrapPath() {
        return StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames.anyMatch(f -> {
                    String cn = f.getDeclaringClass().getName();
                    String mn = f.getMethodName();
                    if (cn.startsWith("org.keycloak.protocol.oidc.OIDCLoginProtocolFactory")
                            || cn.startsWith("org.keycloak.protocol.saml.SamlProtocolFactory")
                            || cn.startsWith("org.keycloak.protocol.oid4vc.OID4VCLoginProtocolFactory")) {
                        return "createDefaultClientScopesImpl".equals(mn);
                    }
                    if ("org.keycloak.models.utils.DefaultClientScopes".equals(cn)) {
                        return true;
                    }
                    return "org.keycloak.services.managers.RealmManager".equals(cn)
                            && "createDefaultClientScopes".equals(mn);
                }));
    }
}
