package org.tidecloak.iga.attestors;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.tidecloak.iga.entities.IgaAuthorizationEntity;
import org.tidecloak.iga.entities.IgaAuthorizerEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.entities.IgaRolePolicyEntity;
import org.tidecloak.iga.providers.IgaAuthorizerService;
import org.tidecloak.iga.replay.IgaReplayExtension;

import jakarta.persistence.EntityManager;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

/**
 * DUMMY set-signing attestor (id {@code tide}). It implements the FULL
 * per-(table, owner) SET-SIGNING mechanism — owner resolution, post-change-set
 * gathering, deterministic canonicalization, and a single signing swap-point —
 * with only the cryptography stubbed. The real Midgard {@code signClaims()} call
 * swaps in at exactly one method: {@link #sign(byte[])}.
 *
 * <h2>The set-signing model</h2>
 * The signing unit for a LINKAGE table is a per-(table, owner) SET: all rows in
 * that table sharing the same owner key are signed as ONE aggregate. When a row
 * is added or removed, the owner's WHOLE set is re-signed (including/excluding
 * the changed row) and that one signature is written to EVERY row in the owner's
 * set (the fan-out is done by {@code IgaReplayDispatcher} gated on
 * {@link #isSetSigned()}). NODE tables stay PER-ENTITY: the "set" is the single
 * entity, so its signature is over its own canonical state.
 *
 * <h2>combineFinal runs BEFORE replay applies the change</h2>
 * {@code IgaAdminResource.commit} calls {@code combineFinal} and then passes the
 * returned string to the dispatcher, which applies the model change and stamps.
 * So at combineFinal time the DB still holds the PRE-change set; we therefore
 * read the current set and adjust it by the CR's pending delta (ADD → union the
 * new member(s); REMOVE → minus the removed member(s)) to obtain the POST-change
 * set that the signature commits to.
 *
 * <p>The per-admin authorization recording is identical to
 * {@link SimpleNameAttestor} (the dummy needs no real per-admin crypto), so the
 * approver-role / threshold gates behave exactly as on a Tideless realm.
 */
public class TideAttestor implements IgaAttestor {

    private static final Logger log = Logger.getLogger(TideAttestor.class);

    public static final String ID = "tide";

    /** Prefix marking the stubbed signature so it is unmistakably a dummy. */
    public static final String DUMMY_SIG_PREFIX = "TIDE-DUMMY-v1:";

    /**
     * Prefix marking a firstAdmin (single-signer, 1-of-1 admin quorum) bootstrap
     * signature, distinct from the multiAdmin {@link #DUMMY_SIG_PREFIX}. In wave 1a
     * {@link #sign(KeycloakSession, RealmModel, String, byte[])}'s firstAdmin branch
     * still produces the SHA-256 stub under this prefix; wave 2 swaps in the real
     * VRK → Midgard → ORK signature here (port plan §3.4, §6.4).
     */
    public static final String FIRSTADMIN_SIG_PREFIX = "TIDE-FIRSTADMIN-v1:";

    /** Mode column values on {@link IgaAuthorizerEntity} (port plan §3.1, §4). */
    public static final String MODE_FIRST_ADMIN = "firstAdmin";
    public static final String MODE_MULTI_ADMIN = "multiAdmin";

    /** Realm attribute discriminating Tide vs Tideless (IgaAttestors.java:21-35). */
    private static final String ATTR_IGA_ATTESTOR = "iga.attestor";

    /** Stock KC realm-management client + the legacy {@code Constants.TIDE_REALM_ADMIN} role name. */
    private static final String REALM_MANAGEMENT_CLIENT_ID = "realm-management";
    private static final String TIDE_REALM_ADMIN_ROLE = "tide-realm-admin";

    /** Multiplier for the dynamic multiAdmin threshold floor (port plan §3.6). */
    private static final double THRESHOLD_PERCENTAGE = 0.7;

    /**
     * The realm's VRK key-provider component (port plan §5/§9.3). Its presence is
     * the VRK-availability precondition for the firstAdmin lazy seed: absent → no
     * VRK to sign with, so the seed is skipped and resolveMode's no-row branch
     * keeps reporting firstAdmin (Decision 1).
     */
    private static final String TIDE_VENDOR_KEY_PROVIDER_ID = "tide-vendor-key";
    /** Component config keys carrying the VRK authorizer material (legacy MultiAdmin.java:95-96). */
    private static final String CFG_GVRK = "gVRK";
    private static final String CFG_GVRK_CERTIFICATE = "gVRKCertificate";
    /** Vendor verifying-key id the admin policy artifact is keyed to (legacy TideRoleRequests.java:137). */
    private static final String CFG_VVK_ID = "vvkId";

    // -------------------------------------------------------------------------
    // Admin-policy artifact shape (port plan §7a.2 / legacy TideRoleRequests.java:144-148)
    // -------------------------------------------------------------------------
    /** Stock realm-management client id the admin policy scopes (legacy Constants.REALM_MANAGEMENT_CLIENT_ID). */
    private static final String POLICY_RESOURCE = REALM_MANAGEMENT_CLIENT_ID;
    /** Policy type tag legacy stamped on the {@code tide-realm-admin} policy (TideRoleRequests.java:148). */
    private static final String POLICY_TYPE = "GenericResourceAccessThresholdRole:1";
    /** ApprovalType.EXPLICIT / ExecutionType.PUBLIC (legacy TideRoleRequests.java:148). */
    private static final String POLICY_APPROVAL_TYPE = "EXPLICIT";
    private static final String POLICY_EXECUTION_TYPE = "PUBLIC";

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<List<Map<String, Object>>> LIST_MAP_REF =
            new TypeReference<List<Map<String, Object>>>() {};

    public TideAttestor(KeycloakSession session) {
        // session is supplied per-call; matches the factory create(session) wiring.
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public boolean isSetSigned() {
        return true;
    }

    /**
     * Record one admin's authorization toward threshold — identical mechanism
     * to {@link SimpleNameAttestor}: enforce the approver-role gate via
     * {@link IgaScopeResolver}, then persist the admin's username as the partial
     * signature. The dummy attestor performs no real per-admin cryptography.
     */
    @Override
    public IgaAuthorizationEntity record(KeycloakSession session,
                                         IgaChangeRequestEntity cr,
                                         UserModel admin,
                                         String attestationPayload) {
        RealmModel realm = session.realms().getRealm(cr.getRealmId());

        // Lazy firstAdmin seed (port plan §9.3 / Decision 2): the FIRST authorizer
        // row is born here, on the first Tide-mode record(), seeded firstAdmin.
        // Idempotent — only creates when absent. No mode-specific dedup difference:
        // both firstAdmin and multiAdmin persist the same IgaAuthorizationEntity
        // shape (partialSig = admin username), and the existing approver-role gate
        // + the one-layer-up dedup (IgaAdminResource.authorize) are unchanged
        // (port plan §3.2).
        maybeSeedFirstAdminAuthorizer(session, realm);

        IgaScopeResolver.ResolvedScope scope = IgaScopeResolver.resolve(session, realm, cr);
        IgaScopeResolver.requireApprover(session, realm, admin, scope, cr);

        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        IgaAuthorizationEntity auth = new IgaAuthorizationEntity();
        auth.setId(UUID.randomUUID().toString());
        auth.setChangeRequest(cr);
        auth.setAuthorizedBy(admin.getId());
        auth.setPartialSig(admin.getUsername());
        auth.setCreatedAt(System.currentTimeMillis());
        em.persist(auth);
        em.flush();
        return auth;
    }

    @Override
    public int getThreshold(KeycloakSession session, RealmModel realm, IgaChangeRequestEntity cr) {
        // firstAdmin is single-signer onboarding: ALWAYS 1, unconditionally — it
        // does not consult per-scope overrides, the realm attribute, or the admin
        // count (port plan §3.5; legacy FirstAdmin reads no threshold at all). The
        // constant-first equals() is null-safe for resolveMode's null return.
        if (MODE_FIRST_ADMIN.equals(resolveMode(session, realm))) {
            return 1;
        }
        // multiAdmin: a per-scope iga.threshold (set WITH iga.approverRole on the
        // same entity) or an ADOPT_* short-circuit still wins via the shared
        // resolver; only the realm-level default flips from the static
        // iga.threshold to the dynamic 0.7 floor. The shared IgaScopeResolver
        // stays the Tideless-static path (port plan §3.5, §8, D9).
        IgaScopeResolver.ResolvedScope scope = IgaScopeResolver.resolve(session, realm, cr);
        if (scope != null && !scope.thresholds.isEmpty()) {
            return IgaScopeResolver.resolveThreshold(session, realm, scope, cr);   // per-scope override wins
        }
        if (cr != null && IgaReplayExtension.isAdoptAction(cr.getActionType())) {
            return 1;                                                              // ADOPT bypass wins
        }
        return Math.max(1, (int) (THRESHOLD_PERCENTAGE * countActiveTideRealmAdmins(realm, session))); // §3.6 / §3.7
    }

    // -------------------------------------------------------------------------
    // Mode resolution + dynamic threshold count (port plan §3.1, §3.5–3.7)
    // -------------------------------------------------------------------------

    /**
     * Resolve the firstAdmin/multiAdmin mode for the realm (port plan §3.1).
     *
     * <p>If an {@link IgaAuthorizerEntity} row exists and its {@code mode} column
     * is set, that column is authoritative. Otherwise (the dormant-entity default
     * — {@code iga_authorizer} holds 0 rows for every realm today, §9.1) the mode
     * is decided by the realm's Tide-vs-Tideless discriminator
     * {@code iga.attestor} (IgaAttestors.java:21-35):
     * <ul>
     *   <li>{@code iga.attestor=="tide"} → {@code "firstAdmin"} — a Tide realm
     *       that has not yet bootstrapped its admin policy. The first Tide-mode
     *       {@link #record} lazily materialises this row seeded {@code firstAdmin}
     *       (§9.3); until then this no-row branch reports {@code firstAdmin} so the
     *       bootstrap branch runs.</li>
     *   <li>otherwise → {@code null} (no-op). The authorizer entity is irrelevant
     *       to Tideless; {@code SimpleNameAttestor} never consults it and never
     *       calls this method, so this branch is reached only by a defensive stray
     *       call and deliberately does not fabricate a mode for a non-Tide realm.</li>
     * </ul>
     *
     * <p>Package-static so the single chokepoint {@link IgaScopeResolver#requireApprover}
     * can consult the SAME mode signal that drives {@link #getThreshold} — the
     * firstAdmin gate-bypass and the firstAdmin threshold=1 must agree on the mode
     * or they could diverge (bypass without 1-of-1, or vice versa).
     */
    static String resolveMode(KeycloakSession session, RealmModel realm) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        IgaAuthorizerEntity row = em.createNamedQuery("IgaAuthorizer.findByRealm", IgaAuthorizerEntity.class)
                .setParameter("realmId", realm.getId())
                .getResultStream().findFirst().orElse(null);

        // A row exists with a set mode column: it is authoritative.
        if (row != null && row.getMode() != null) {
            return row.getMode();
        }

        // No row (or a legacy row predating the MODE column): derive from the
        // realm's Tide-vs-Tideless discriminator.
        String attestor = realm.getAttribute(ATTR_IGA_ATTESTOR);              // IgaAttestors.java:22
        if (ID.equals(attestor)) {
            return MODE_FIRST_ADMIN;
        }
        return null;
    }

    /**
     * Count the realm's ACTIVE tide-realm-admins for the dynamic multiAdmin
     * threshold (port plan §3.6 / §3.7). A user counts iff it simultaneously
     * (a) holds the {@code tide-realm-admin} realm-management role,
     * (b) is enabled, and (c) has a COMMITTED Tide identity — operationalised as a
     * {@code USER_ROLE_MAPPING} row for {@code (user, tide-realm-admin)} with
     * {@code attestation IS NOT NULL} (the inverse of the unsigned-row scan
     * {@code IgaUnsignedRowScanner.userRoleMappings}, IgaUnsignedRowScanner.java:541-547).
     * A PENDING grant stamps nothing, so a committed grant is exactly a non-pending
     * one and this single signal subsumes both the "committed" and "not pending"
     * sub-predicates.
     */
    private static int countActiveTideRealmAdmins(RealmModel realm, KeycloakSession session) {
        ClientModel rm = realm.getClientByClientId(REALM_MANAGEMENT_CLIENT_ID);
        if (rm == null) return 0;
        RoleModel tideAdmin = rm.getRole(TIDE_REALM_ADMIN_ROLE);
        if (tideAdmin == null) return 0;

        // (user id) set whose USER_ROLE_MAPPING.attestation IS NOT NULL for the
        // tide-realm-admin role — the committed/stamped grants.
        Set<String> committedAdminUserIds = committedTideAdminUserIds(session, realm, tideAdmin.getId());
        if (committedAdminUserIds.isEmpty()) return 0;

        return (int) session.users().getRoleMembersStream(realm, tideAdmin)
                .filter(UserModel::isEnabled)
                .filter(u -> committedAdminUserIds.contains(u.getId()))  // committed grant only (not PENDING)
                .count();
    }

    /**
     * Inverse of {@code IgaUnsignedRowScanner.userRoleMappings} (IgaUnsignedRowScanner.java:541-547):
     * the user ids whose {@code (user, roleId)} USER_ROLE_MAPPING row is stamped
     * ({@code attestation IS NOT NULL}) — i.e. the committed grants of {@code roleId}
     * in the realm.
     */
    private static Set<String> committedTideAdminUserIds(KeycloakSession session, RealmModel realm, String roleId) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        @SuppressWarnings("unchecked")
        List<String> ids = em.createQuery(
                        "SELECT urm.user.id FROM UserRoleMappingEntity urm "
                                + "WHERE urm.user.realmId = :realmId AND urm.roleId = :roleId "
                                + "AND urm.attestation IS NOT NULL")
                .setParameter("realmId", realm.getId())
                .setParameter("roleId", roleId)
                .getResultList();
        return new HashSet<>(ids);
    }

    /**
     * Lazy firstAdmin authorizer seed (port plan §9.3 / Decision 2). On the first
     * Tide-mode {@link #record}, if the realm has NO {@link IgaAuthorizerEntity}
     * row AND {@code iga.attestor=="tide"}, create exactly one seeded
     * {@code mode="firstAdmin"} via the existing {@link IgaAuthorizerService#create}
     * persist path. This is the ONLY place the first row is born (no eager
     * toggle-on / realm-init seed); it is idempotent (the {@code !hasRow} guard
     * skips re-seeding).
     *
     * <p>VRK-availability precondition (§9.3 / §Q4): the seed needs the realm's
     * {@code tide-vendor-key} component for its NOT-NULL {@code providerId} /
     * {@code authorizer} / {@code authorizerCertificate} fields (the VRK material).
     * If that component is absent — or present but not yet VRK-provisioned — the
     * seed is SKIPPED and {@link #resolveMode}'s no-row branch keeps reporting
     * {@code firstAdmin} (Decision 1). A missing component means "VRK not
     * provisioned", NOT "Tideless": the Tide discriminator is {@code iga.attestor},
     * and this whole method runs only on the tide attestor's path.
     *
     * <p>Wave 1a note: this reads the component with plain KC model access only
     * (no MidgardJava / no {@code SecretKeys} deserialization / no crypto). The
     * gVRK / gVRKCertificate config values are carried verbatim into the row; the
     * VRK signing that interprets them is wave 2 (§5).
     */
    private void maybeSeedFirstAdminAuthorizer(KeycloakSession session, RealmModel realm) {
        if (!ID.equals(realm.getAttribute(ATTR_IGA_ATTESTOR))) {
            return; // not a Tide realm — never seed (defensive; tide attestor only).
        }
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        IgaAuthorizerService authorizerService = new IgaAuthorizerService(em);
        if (!authorizerService.listByRealm(realm.getId()).isEmpty()) {
            return; // row already exists — idempotent, do not re-seed.
        }

        // VRK material from the realm's tide-vendor-key component (legacy
        // MultiAdmin.java:95-96, 474-484). Absent component or unprovisioned
        // material → defer the seed (the no-row branch reports firstAdmin).
        ComponentModel vendorKey = realm.getComponentsStream()
                .filter(c -> TIDE_VENDOR_KEY_PROVIDER_ID.equals(c.getProviderId()))
                .findFirst()
                .orElse(null);
        if (vendorKey == null) {
            log.infof("IGA firstAdmin seed deferred: realm %s has no tide-vendor-key component "
                    + "(VRK not provisioned); resolveMode reports firstAdmin via the no-row branch.",
                    realm.getName());
            return;
        }
        String gVrk = vendorKey.getConfig() != null ? vendorKey.getConfig().getFirst(CFG_GVRK) : null;
        String gVrkCert = vendorKey.getConfig() != null ? vendorKey.getConfig().getFirst(CFG_GVRK_CERTIFICATE) : null;
        if (gVrk == null || gVrk.isBlank() || gVrkCert == null || gVrkCert.isBlank()) {
            log.infof("IGA firstAdmin seed deferred: realm %s tide-vendor-key component is missing "
                    + "VRK authorizer material (gVRK/gVRKCertificate); resolveMode reports firstAdmin "
                    + "via the no-row branch.", realm.getName());
            return;
        }

        authorizerService.create(realm.getId(), vendorKey.getId(), MODE_FIRST_ADMIN,
                gVrk, gVrkCert, MODE_FIRST_ADMIN);
        log.infof("IGA firstAdmin authorizer lazily seeded for realm %s (mode=firstAdmin).",
                realm.getName());
    }

    /**
     * SET-SIGNING core. Resolve (table, owner) from the CR, gather the owner's
     * POST-change set, canonicalize it deterministically, and sign it once via
     * the single {@link #sign(byte[])} swap-point. For NODE creates the "set" is
     * the single entity's own canonical state.
     */
    @Override
    public String combineFinal(KeycloakSession session,
                               IgaChangeRequestEntity cr,
                               List<IgaAuthorizationEntity> authorizations) {
        RealmModel realm = session.realms().getRealm(cr.getRealmId());
        String mode = resolveMode(session, realm);   // "firstAdmin" (row or no-row tide) | "multiAdmin" | null

        // The tide-realm-admin POLICY bootstrap is the only case whose payload
        // differs: in firstAdmin mode a GRANT_ROLES of tide-realm-admin signs the
        // realm's stored policy bytes verbatim (port plan §6.2); every other CR —
        // in both modes — signs the regular set/node canonical (§6.3, unchanged).
        boolean isPolicyBootstrap = MODE_FIRST_ADMIN.equals(mode)
                && isTideRealmAdminAssignment(realm, cr);
        byte[] canonical = isPolicyBootstrap
                ? readTideRealmAdminPolicyBytes(session, realm, cr)
                : canonicalForRegularCr(session, cr);

        String sig = sign(session, realm, mode, canonical);

        // Transition trigger (port plan §7): on a successful firstAdmin-mode sign
        // of the tide-realm-admin policy CR, write back policySig AND flip the
        // realm's authorizer mode to multiAdmin — in the SAME JPA transaction as
        // the dispatcher's ATTESTATION write (§7.2/§7.3). Null-safe + idempotent:
        // already-multiAdmin never reaches here (gated on firstAdmin), and a
        // redundant flip is a harmless no-op (§7.4 / §12 Q6).
        if (isPolicyBootstrap) {
            writeBackPolicySig(session, realm, cr, sig);
            flipModeToMultiAdmin(session, realm);
        } else if (MODE_MULTI_ADMIN.equals(mode)) {
            // Wave 1b (port plan §7a): multiAdmin steady-state. If this committing CR
            // changes the active tide-realm-admin set (grant/revoke of the role), the
            // dynamic threshold floor(0.7 x N) may move, so the SIGNED admin policy
            // artifact must be regenerated + re-signed to encode the new threshold.
            // Sequenced LAST — after the CR's own attestation `sig` is already built
            // above — so the regen never disturbs the CR sign (legacy defer-to-end-of
            // -batch rule, MultiAdmin.java:429-431). No-op (and IsEqualTo-skipped) when
            // the CR is not a membership change or the threshold did not actually move.
            maybeRegenerateAdminPolicyOnMembershipChange(session, realm, cr);
        }
        return sig;
    }

    /**
     * The regular set/node canonical today's attestor produces — unchanged by the
     * port (port plan §6.3, §3.3 multiAdmin row). LINKAGE actions sign the owner's
     * POST-change member set; NODE / non-linkage actions sign the entity's own
     * canonical state.
     */
    private byte[] canonicalForRegularCr(KeycloakSession session, IgaChangeRequestEntity cr) {
        String actionType = cr.getActionType();
        List<Map<String, Object>> rows = parseRows(cr.getRowsJson());
        TideSetResolver.Linkage linkage = TideSetResolver.linkageFor(actionType);
        if (linkage != null) {
            // LINKAGE: sign the owner's POST-change member set. (rows may span
            // more than one owner for a multi-row CR — we sign the union keyed
            // by owner so every affected owner's set commits to the same final
            // string; the dispatcher fans out per owner.)
            return canonicalizeLinkageSet(session, cr, linkage, rows, actionType);
        }
        // NODE / non-linkage: per-entity — sign the entity's own canonical state,
        // exactly the single-row scope the per-row attestor stamps.
        return canonicalizeNode(cr, rows);
    }

    // -------------------------------------------------------------------------
    // firstAdmin policy-bootstrap detection + transition flip (port plan §6.2, §7)
    // -------------------------------------------------------------------------

    /**
     * Detect "this CR is the tide-realm-admin policy CR" (port plan §7.1) — the
     * signal legacy used: a {@code GRANT_ROLES} CR whose row carries the
     * realm-management {@code tide-realm-admin} role id
     * ({@code FirstAdmin.isAssigningTideRealmAdminRole}, FirstAdmin.java:160-167).
     * GRANT_ROLES rows carry USER_ID + ROLE_ID (IgaReplayDispatcher.java:181-184).
     */
    private boolean isTideRealmAdminAssignment(RealmModel realm, IgaChangeRequestEntity cr) {
        if (cr == null || !"GRANT_ROLES".equals(cr.getActionType())) return false;
        String tideRoleId = tideRealmAdminRoleId(realm);
        if (tideRoleId == null) return false;
        for (Map<String, Object> row : parseRows(cr.getRowsJson())) {
            if (tideRoleId.equals(str(row, "ROLE_ID"))) return true;
        }
        return false;
    }

    /** Resolve the realm-management {@code tide-realm-admin} role id, or null if absent. */
    private static String tideRealmAdminRoleId(RealmModel realm) {
        ClientModel rm = realm.getClientByClientId(REALM_MANAGEMENT_CLIENT_ID);
        if (rm == null) return null;
        RoleModel tideRole = rm.getRole(TIDE_REALM_ADMIN_ROLE);
        return tideRole != null ? tideRole.getId() : null;
    }

    /**
     * The bootstrap payload (port plan §6.2): the realm's tide-realm-admin
     * {@code IgaRolePolicyEntity.policy} value, signed as UTF-8 bytes VERBATIM
     * (no base64-decode — iga-core does not base64-encode the policy on the way
     * in; §6.2 byte-shape resolution). If no policy row exists yet for the
     * tide-realm-admin role (the policy may be upserted via the separate
     * {@code POST /iga/role-policies} path, §7.1), fall back to the regular CR
     * canonical so the role grant still receives a valid attestation and the
     * transition still fires on the role-assignment signal. The policy write-back
     * (§7.2) is then a no-op (there is no row to stamp).
     */
    private byte[] readTideRealmAdminPolicyBytes(KeycloakSession session, RealmModel realm,
                                                 IgaChangeRequestEntity cr) {
        IgaRolePolicyEntity policy = findTideRealmAdminPolicy(session, realm);
        if (policy != null && policy.getPolicy() != null) {
            return policy.getPolicy().getBytes(StandardCharsets.UTF_8);
        }
        log.infof("IGA firstAdmin policy bootstrap: realm %s has no tide-realm-admin role-policy row "
                + "to sign; signing the grant's regular canonical and flipping to multiAdmin on the "
                + "role-assignment signal (policySig write-back skipped).", realm.getName());
        return canonicalForRegularCr(session, cr);
    }

    /** Look up the tide-realm-admin {@link IgaRolePolicyEntity} (realm + role id), or null. */
    private static IgaRolePolicyEntity findTideRealmAdminPolicy(KeycloakSession session, RealmModel realm) {
        String tideRoleId = tideRealmAdminRoleId(realm);
        if (tideRoleId == null) return null;
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        return em.createNamedQuery("IgaRolePolicy.findByRealmAndRole", IgaRolePolicyEntity.class)
                .setParameter("realmId", realm.getId())
                .setParameter("roleId", tideRoleId)
                .getResultStream().findFirst().orElse(null);
    }

    /**
     * Write the firstAdmin bootstrap signature back to the tide-realm-admin
     * {@code IgaRolePolicyEntity.policySig} (port plan §6.4, §7.2), in the same
     * JPA transaction as the dispatcher's ATTESTATION write (§7.3 — the entity is
     * managed, so the column update commits atomically with the replay). No-op
     * when no policy row exists (see {@link #readTideRealmAdminPolicyBytes}).
     */
    private void writeBackPolicySig(KeycloakSession session, RealmModel realm, IgaChangeRequestEntity cr,
                                    String sig) {
        IgaRolePolicyEntity policy = findTideRealmAdminPolicy(session, realm);
        if (policy == null) return;
        policy.setPolicySig(sig);
        policy.setUpdatedAt(System.currentTimeMillis());
        // managed entity — no explicit persist needed; flush keeps it in-tx.
        session.getProvider(JpaConnectionProvider.class).getEntityManager().flush();
    }

    /**
     * Transition flip (port plan §7.2): set the realm's authorizer
     * {@code mode = "multiAdmin"} in the same JPA transaction as the ATTESTATION
     * write. Null-safe + idempotent — a redundant flip is a harmless no-op
     * (§7.4 / §12 Q6). The lazy seed (§9.3) guarantees the row exists by the time
     * this runs (record() fires before combineFinal), but we guard defensively.
     */
    private void flipModeToMultiAdmin(KeycloakSession session, RealmModel realm) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        IgaAuthorizerEntity row = em.createNamedQuery("IgaAuthorizer.findByRealm", IgaAuthorizerEntity.class)
                .setParameter("realmId", realm.getId())
                .getResultStream().findFirst().orElse(null);
        if (row == null) return; // defensive: lazy seed should have created it.
        if (MODE_FIRST_ADMIN.equals(row.getMode())) {
            row.setMode(MODE_MULTI_ADMIN);
            em.flush();
            log.infof("IGA mode transition: realm %s flipped firstAdmin -> multiAdmin on tide-realm-admin "
                    + "policy sign.", realm.getName());
        }
    }

    // -------------------------------------------------------------------------
    // Wave 1b — threshold-change admin-policy regeneration (port plan §7a)
    // -------------------------------------------------------------------------

    /**
     * Steady-state (multiAdmin) admin-policy regeneration on an active-admin-set
     * change (port plan §7a). Fired from {@link #combineFinal} ONLY in multiAdmin
     * mode, AFTER the committing CR's own attestation signature is built (so the
     * regen is sequenced last — legacy {@code MultiAdmin.java:429-431} defer rule).
     *
     * <h3>What it does</h3>
     * <ol>
     *   <li>Detect a membership-changing CR: a committed GRANT/REVOKE of the
     *       realm-management {@code tide-realm-admin} role. Anything else → no-op.</li>
     *   <li>Compute the POST-commit active-admin count. {@code combineFinal} runs
     *       BEFORE the dispatcher replays this CR, so {@link #countActiveTideRealmAdmins}
     *       still returns the PRE-commit count; we add the CR's pending net delta
     *       (+1 grant / -1 revoke) — the exact legacy {@code additionalAdmins}
     *       (ChangeSetProcessor.java:304, TideRoleRequests.java:128).</li>
     *   <li>{@code newThreshold = max(1, floor(0.7 x postCommitCount))} — the SAME
     *       formula + the SAME counting function {@link #getThreshold} uses, so the
     *       policy the artifact encodes and the gate {@code getThreshold} enforces
     *       cannot drift (§7a.7).</li>
     *   <li>IsEqualTo short-circuit (legacy TideRoleRequests.java:163-168): if the
     *       current policy already encodes {@code newThreshold}, skip — no rewrite,
     *       no re-sign. The floor formula means most single adds DON'T move the
     *       threshold, so this is the primary churn control (§7a.4). Exactly one
     *       regen per committed membership-changing CR.</li>
     *   <li>Rebuild the policy artifact (§7a.2 shape) at {@code newThreshold},
     *       re-sign it via the VRK path (§7a.3 — the SAME signing primitive the
     *       bootstrap policy sign uses, so {@code policySig} carries the
     *       {@link #FIRSTADMIN_SIG_PREFIX} VRK prefix across bootstrap AND every
     *       regen — §7a.5), and write {@code policy}/{@code policySig} in the same
     *       JPA transaction as the CR commit (§7a.6 fail-closed + atomic).</li>
     * </ol>
     *
     * <h3>Who signs (port plan §7a.3, legacy step 5)</h3>
     * The membership CR is authorized by the OLD quorum at the OLD threshold
     * ({@code getThreshold} was evaluated at the commit gate BEFORE this CR was
     * counted); the regenerated policy — VRK-signed here — installs the NEW
     * threshold for SUBSEQUENT CRs. OLD quorum installs NEW threshold; no
     * circular "need the new quorum to authorize its own creation".
     */
    private void maybeRegenerateAdminPolicyOnMembershipChange(KeycloakSession session, RealmModel realm,
                                                              IgaChangeRequestEntity cr) {
        int delta = tideRealmAdminMembershipDelta(realm, cr);
        if (delta == 0) {
            return; // not a tide-realm-admin grant/revoke — the set is unchanged.
        }

        IgaRolePolicyEntity policy = findTideRealmAdminPolicy(session, realm);
        if (policy == null) {
            // No admin policy artifact to keep in sync (it is upserted via the
            // separate POST /iga/role-policies path, §7.1). Nothing to regenerate;
            // the live getThreshold gate is unaffected (it never reads this row).
            log.infof("IGA policy regen skipped: realm %s has no tide-realm-admin role-policy row "
                    + "to regenerate (membership delta %+d); live threshold gate is unaffected.",
                    realm.getName(), delta);
            return;
        }

        // combineFinal runs PRE-replay, so the live count excludes this CR's effect;
        // add the pending net delta to obtain the post-commit count (legacy
        // additionalAdmins). Clamp at 0 — a revoke can never make the count negative.
        int postCommitCount = Math.max(0, countActiveTideRealmAdmins(realm, session) + delta);
        int newThreshold = Math.max(1, (int) (THRESHOLD_PERCENTAGE * postCommitCount));

        // IsEqualTo short-circuit (legacy TideRoleRequests.java:163-168): regenerate
        // only when the encoded threshold actually moves.
        Integer currentThreshold = currentEncodedThreshold(policy);
        if (currentThreshold != null && currentThreshold == newThreshold) {
            log.infof("IGA policy regen skipped (threshold unchanged): realm %s tide-realm-admin policy "
                    + "already encodes threshold %d (membership delta %+d, post-commit admins %d).",
                    realm.getName(), newThreshold, delta, postCommitCount);
            return;
        }

        String vvkId = realmVvkId(realm);
        String newPolicyBody = buildAdminPolicyArtifact(newThreshold, vvkId);
        // VRK sign (firstAdmin signing primitive) — the admin policy is ALWAYS
        // VRK-signed (bootstrap + every regen), even though the realm is multiAdmin:
        // the artifact is a governance parameter, not the CR's enclave-signed rows
        // (§7a.3, §7a.5). Forcing MODE_FIRST_ADMIN here selects the VRK prefix.
        String newPolicySig = sign(session, realm, MODE_FIRST_ADMIN,
                newPolicyBody.getBytes(StandardCharsets.UTF_8));

        policy.setPolicy(newPolicyBody);
        policy.setPolicySig(newPolicySig);
        policy.setThreshold(newThreshold);
        policy.setApprovalType(POLICY_APPROVAL_TYPE);
        policy.setExecutionType(POLICY_EXECUTION_TYPE);
        policy.setUpdatedAt(System.currentTimeMillis());
        // Managed entity — flush keeps the rewrite in the CR's commit transaction
        // (§7a.6 atomic: if the commit rolls back, so does the regen).
        session.getProvider(JpaConnectionProvider.class).getEntityManager().flush();

        log.infof("IGA admin policy regenerated: realm %s tide-realm-admin threshold %s -> %d "
                + "(membership delta %+d, post-commit admins %d); policy re-signed (VRK prefix).",
                realm.getName(), String.valueOf(currentThreshold), newThreshold, delta, postCommitCount);
    }

    /**
     * The pending net delta this CR applies to the active tide-realm-admin count
     * (port plan §7a.1 / legacy ChangeSetProcessor.java:304): {@code +1} for a
     * committed GRANT of the realm-management {@code tide-realm-admin} role,
     * {@code -1} for a committed REVOKE, {@code 0} for any other CR. Detection
     * mirrors {@link #isTideRealmAdminAssignment} (the role's IDENTITY on a CR row),
     * extended to the REVOKE action.
     */
    private int tideRealmAdminMembershipDelta(RealmModel realm, IgaChangeRequestEntity cr) {
        if (cr == null) return 0;
        String action = cr.getActionType();
        if (!"GRANT_ROLES".equals(action) && !"REVOKE_ROLES".equals(action)) return 0;
        String tideRoleId = tideRealmAdminRoleId(realm);
        if (tideRoleId == null) return 0;
        boolean touchesTideAdmin = false;
        for (Map<String, Object> row : parseRows(cr.getRowsJson())) {
            if (tideRoleId.equals(str(row, "ROLE_ID"))) { touchesTideAdmin = true; break; }
        }
        if (!touchesTideAdmin) return 0;
        return "GRANT_ROLES".equals(action) ? 1 : -1;
    }

    /**
     * Build the admin-policy artifact body (port plan §7a.2 / legacy
     * TideRoleRequests.java:144-148): a deterministic JSON object carrying the
     * recomputed {@code threshold} + the {@code role}/{@code resource} scope +
     * the policy-type metadata, keyed to the realm's {@code vvkId}. Legacy built a
     * Midgard {@code Policy("GenericResourceAccessThresholdRole:1","any",vvkId,
     * EXPLICIT,PUBLIC,{threshold,role,resource})}; iga-core has no Midgard Policy
     * type, so the same field set is emitted as canonical JSON. Keys are written in
     * a FIXED order so the bytes are stable (same threshold → same body → the
     * IsEqualTo skip and the deterministic stub signature both hold).
     */
    private static String buildAdminPolicyArtifact(int threshold, String vvkId) {
        StringBuilder b = new StringBuilder(160);
        b.append('{');
        b.append("\"type\":\"").append(POLICY_TYPE).append("\",");
        b.append("\"vvkId\":").append(vvkId == null ? "null" : "\"" + jsonEscape(vvkId) + "\"").append(',');
        b.append("\"approvalType\":\"").append(POLICY_APPROVAL_TYPE).append("\",");
        b.append("\"executionType\":\"").append(POLICY_EXECUTION_TYPE).append("\",");
        b.append("\"threshold\":").append(threshold).append(',');
        b.append("\"role\":\"").append(TIDE_REALM_ADMIN_ROLE).append("\",");
        b.append("\"resource\":\"").append(POLICY_RESOURCE).append('"');
        b.append('}');
        return b.toString();
    }

    /**
     * Read the threshold the current policy artifact encodes, for the IsEqualTo
     * short-circuit. Prefers the stored {@code IgaRolePolicyEntity.threshold}
     * column (authoritative + cheap); falls back to parsing {@code "threshold":N}
     * out of the {@code policy} body for rows whose column was never populated
     * (e.g. a bootstrap-only or externally-upserted policy). Returns {@code null}
     * if neither yields an int (then the regen does NOT skip — it rewrites).
     */
    private static Integer currentEncodedThreshold(IgaRolePolicyEntity policy) {
        if (policy.getThreshold() != null) {
            return policy.getThreshold();
        }
        String body = policy.getPolicy();
        if (body == null) return null;
        java.util.regex.Matcher m = THRESHOLD_IN_BODY.matcher(body);
        if (m.find()) {
            try {
                return Integer.valueOf(m.group(1));
            } catch (NumberFormatException ignore) {
                return null;
            }
        }
        return null;
    }

    /** Matches {@code "threshold": 7} (any surrounding whitespace) in a policy body. */
    private static final java.util.regex.Pattern THRESHOLD_IN_BODY =
            java.util.regex.Pattern.compile("\"threshold\"\\s*:\\s*(\\d+)");

    /** The realm's {@code vvkId} from its {@code tide-vendor-key} component, or null. */
    private static String realmVvkId(RealmModel realm) {
        ComponentModel vendorKey = realm.getComponentsStream()
                .filter(c -> TIDE_VENDOR_KEY_PROVIDER_ID.equals(c.getProviderId()))
                .findFirst()
                .orElse(null);
        if (vendorKey == null || vendorKey.getConfig() == null) return null;
        return vendorKey.getConfig().getFirst(CFG_VVK_ID);
    }

    /** Minimal JSON string escaping for the policy body's {@code vvkId} value. */
    private static String jsonEscape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    // -------------------------------------------------------------------------
    // Canonicalization
    // -------------------------------------------------------------------------

    /**
     * Build the deterministic canonical form of an owner's POST-change set.
     *
     * <p>combineFinal runs BEFORE replay applies the change, so the DB still
     * holds the PRE-change set. We read the current member set per owner and
     * adjust by the CR's pending delta: an ADD action unions the new member(s);
     * a REMOVE action subtracts them. The canonical form is a sorted, stable
     * serialization of: table name, owner id, and the sorted member-key list —
     * so the same set always yields the same bytes regardless of insertion
     * order, and a changed set yields different bytes.
     */
    private byte[] canonicalizeLinkageSet(KeycloakSession session,
                                          IgaChangeRequestEntity cr,
                                          TideSetResolver.Linkage linkage,
                                          List<Map<String, Object>> rows,
                                          String actionType) {
        boolean isRemove = isRemoveAction(actionType);
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        // Group the CR's pending members by owner (a CR may touch >1 owner).
        // Owner value comes from the descriptor's ownerRowKey EXCEPT protocol_mapper,
        // whose owner can be a client OR a client_scope (resolved per row below).
        java.util.LinkedHashMap<String, LinkedHashSet<String>> deltaByOwner = new java.util.LinkedHashMap<>();
        java.util.LinkedHashMap<String, String> ownerFieldByOwner = new java.util.LinkedHashMap<>();
        for (Map<String, Object> row : rows) {
            String owner = resolveOwner(linkage, row);
            String ownerField = resolveOwnerField(linkage, row);
            String member = resolveMember(linkage, row);
            if (owner == null || member == null) continue;
            deltaByOwner.computeIfAbsent(owner, k -> new LinkedHashSet<>()).add(member);
            ownerFieldByOwner.putIfAbsent(owner, ownerField);
        }

        StringBuilder canon = new StringBuilder();
        canon.append("table=").append(linkage.table()).append('\n');
        // Owners sorted for determinism across multi-owner CRs.
        for (String owner : new TreeSet<>(deltaByOwner.keySet())) {
            String ownerField = ownerFieldByOwner.get(owner);
            // Current (PRE-change) member set for this owner.
            @SuppressWarnings("unchecked")
            List<Object> current = em.createQuery(
                            "SELECT e." + linkage.memberField() + " FROM " + linkage.entityName()
                                    + " e WHERE e." + ownerField + " = :owner")
                    .setParameter("owner", owner)
                    .getResultList();
            TreeSet<String> set = new TreeSet<>();
            for (Object o : current) {
                if (o != null) set.add(o.toString());
            }
            // Apply the pending delta to obtain the POST-change set.
            if (isRemove) {
                set.removeAll(deltaByOwner.get(owner));
            } else {
                set.addAll(deltaByOwner.get(owner));
            }
            canon.append("owner=").append(owner).append('\n');
            canon.append("members=");
            boolean first = true;
            for (String m : set) {
                if (!first) canon.append(',');
                canon.append(m);
                first = false;
            }
            canon.append('\n');
        }
        return canon.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Per-entity canonical form for NODE / non-linkage actions: the entity's own
     * identity + the CR's row payload, deterministically serialized. This is the
     * single-row scope the per-row attestor stamps — there is no "set" to gather.
     */
    private byte[] canonicalizeNode(IgaChangeRequestEntity cr, List<Map<String, Object>> rows) {
        StringBuilder canon = new StringBuilder();
        canon.append("node=").append(cr.getActionType()).append('\n');
        canon.append("entityType=").append(String.valueOf(cr.getEntityType())).append('\n');
        canon.append("entityId=").append(String.valueOf(cr.getEntityId())).append('\n');
        // Sorted, stable rendering of each row's keys for determinism.
        List<String> rendered = new ArrayList<>();
        for (Map<String, Object> row : rows) {
            rendered.add(new TreeSet<>(row.keySet()).stream()
                    .map(k -> k + "=" + String.valueOf(row.get(k)))
                    .reduce((a, b) -> a + ";" + b).orElse(""));
        }
        java.util.Collections.sort(rendered);
        for (String r : rendered) {
            canon.append("row=").append(r).append('\n');
        }
        return canon.toString().getBytes(StandardCharsets.UTF_8);
    }

    // -------------------------------------------------------------------------
    // Owner / member resolution
    // -------------------------------------------------------------------------

    /** Resolve the owner VALUE for a CR row, handling protocol_mapper's dual parent. */
    private String resolveOwner(TideSetResolver.Linkage linkage, Map<String, Object> row) {
        if ("protocol_mapper".equals(linkage.table())) {
            String clientUuid = str(row, "CLIENT_UUID");
            if (clientUuid != null) return clientUuid;
            String clientId = str(row, "CLIENT_ID"); // human id; owner field switches below
            if (clientId != null) return clientId;
            return str(row, "CLIENT_SCOPE_ID");
        }
        return TideSetResolver.ownerValue(linkage, row);
    }

    /** Resolve the owner JPA FIELD for a CR row (protocol_mapper switches client vs scope). */
    private String resolveOwnerField(TideSetResolver.Linkage linkage, Map<String, Object> row) {
        if ("protocol_mapper".equals(linkage.table())) {
            String clientUuid = str(row, "CLIENT_UUID");
            String clientId = str(row, "CLIENT_ID");
            if (clientUuid != null || clientId != null) return linkage.ownerField(); // client.id
            return TideSetResolver.PROTOCOL_MAPPER_SCOPE_OWNER_FIELD; // clientScope.id
        }
        return linkage.ownerField();
    }

    /** Resolve the member VALUE for a CR row. */
    private String resolveMember(TideSetResolver.Linkage linkage, Map<String, Object> row) {
        return str(row, linkage.memberRowKey());
    }

    private static boolean isRemoveAction(String actionType) {
        if (actionType == null) return false;
        return actionType.endsWith("_REMOVE")
                || actionType.startsWith("REVOKE")
                || actionType.startsWith("LEAVE")
                || actionType.equals("GROUP_REVOKE_ROLES")
                || actionType.equals("REMOVE_COMPOSITE")
                || actionType.equals("REMOVE_SCOPE")
                || actionType.equals("SCOPE_REMOVE_ROLE")
                || actionType.equals("REALM_DEFAULT_SCOPE_REMOVE");
    }

    // -------------------------------------------------------------------------
    // Reusable set-sign compute (shared with the dispatcher's nested-child path)
    // -------------------------------------------------------------------------

    /**
     * Build the EXACT single-owner canonical form a linkage set commits to and
     * sign it via the single {@link #sign(byte[])} swap-point. This is the
     * reusable counterpart to {@link #canonicalizeLinkageSet} for the case where
     * the POST-change member set is already known (no PRE-change-plus-delta
     * reconstruction needed) — used by {@code IgaReplayDispatcher} to sign the
     * nested-child set of a node-create (e.g. a {@code CREATE_ROLE} that carried
     * {@code composites} inline) so those child rows become independently
     * re-derivable as a {@code (table, owner)} set, identical in form to the
     * dedicated linkage actions ({@code ADD_COMPOSITE}, ...).
     *
     * <p>The canonical is byte-for-byte the same form
     * {@link #canonicalizeLinkageSet} produces for a single owner:
     * <pre>table=&lt;table&gt;\nowner=&lt;owner&gt;\nmembers=&lt;sorted,comma-joined&gt;\n</pre>
     *
     * @param tableEntityName the linkage's physical table name (the value written
     *                        after {@code table=} — i.e. {@link TideSetResolver.Linkage#table()}).
     * @param ownerId         the owner (group-by) value.
     * @param memberIds       the POST-change member ids of the owner's set; sorted
     *                        deterministically here (TreeSet), so call order is
     *                        irrelevant.
     * @return the {@code TIDE-DUMMY-v1:...} signature over the set's canonical.
     */
    public String signSet(KeycloakSession session, String tableEntityName,
                          String ownerId, java.util.Collection<String> memberIds) {
        return sign(canonicalSet(tableEntityName, ownerId, memberIds));
    }

    /**
     * Deterministic single-owner canonical bytes for a linkage set — the EXACT
     * form {@link #canonicalizeLinkageSet} emits per owner. Members are sorted
     * (TreeSet) so call/insertion order never affects the signature.
     */
    private static byte[] canonicalSet(String table, String ownerId,
                                       java.util.Collection<String> memberIds) {
        TreeSet<String> set = new TreeSet<>();
        if (memberIds != null) {
            for (String m : memberIds) {
                if (m != null) set.add(m);
            }
        }
        StringBuilder canon = new StringBuilder();
        canon.append("table=").append(table).append('\n');
        canon.append("owner=").append(ownerId).append('\n');
        canon.append("members=");
        boolean first = true;
        for (String m : set) {
            if (!first) canon.append(',');
            canon.append(m);
            first = false;
        }
        canon.append('\n');
        return canon.toString().getBytes(StandardCharsets.UTF_8);
    }

    // -------------------------------------------------------------------------
    // The SINGLE crypto swap-point
    // -------------------------------------------------------------------------

    /**
     * Mode-aware signing swap-point (port plan §3.4). WAVE 1a: both branches still
     * produce the SHA-256 stub — sign() stays stubbed here. They differ ONLY in
     * the prefix that marks the quorum + ceremony:
     * <ul>
     *   <li>{@code firstAdmin} → {@link #FIRSTADMIN_SIG_PREFIX}. Wave 2 swaps in the
     *       real VRK → Midgard → ORK signature here (NOT a local key op; §5.1).</li>
     *   <li>{@code multiAdmin} (and any non-firstAdmin mode) → {@link #DUMMY_SIG_PREFIX},
     *       the existing enclave-threshold stub; wave 2 lands {@code Midgard.signClaims()}.</li>
     * </ul>
     * The distinction between modes is NOT local-vs-network — both ceremonies go
     * Midgard → ORK in production (§3.4, §8); it is (a) admin quorum and (b) key /
     * signing ceremony.
     */
    private String sign(KeycloakSession session, RealmModel realm, String mode, byte[] canonical) {
        String prefix = MODE_FIRST_ADMIN.equals(mode) ? FIRSTADMIN_SIG_PREFIX : DUMMY_SIG_PREFIX;
        return stubSign(prefix, canonical);
    }

    /**
     * Sign the canonical bytes of a set (or node state) for the multiAdmin
     * set-signing path used by {@code IgaReplayDispatcher}'s nested-child fan-out
     * (see {@link #signSet}). Always the multiAdmin stub — the dispatcher's
     * set-signing model predates modes and is mode-agnostic.
     *
     * <p>TODO: replace with Midgard signClaims() — single crypto swap-point.
     */
    private String sign(byte[] canonical) {
        return stubSign(DUMMY_SIG_PREFIX, canonical);
    }

    /**
     * The deterministic SHA-256 stub: {@code <prefix> + base64(sha256(canonical))}.
     * Determinism (same set → same sig) is exactly what the set-signing model
     * relies on. Shared by both {@link #sign} overloads so the byte-shape is
     * identical across the mode branch and the dispatcher fan-out.
     */
    private static String stubSign(String prefix, byte[] canonical) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(canonical);
            return prefix + java.util.Base64.getEncoder().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 unavailable for TideAttestor dummy signing", e);
        }
    }

    // -------------------------------------------------------------------------
    // Utilities
    // -------------------------------------------------------------------------

    private static List<Map<String, Object>> parseRows(String rowsJson) {
        try {
            return MAPPER.readValue(rowsJson, LIST_MAP_REF);
        } catch (Exception e) {
            throw new RuntimeException("TideAttestor: failed to parse rowsJson", e);
        }
    }

    private static String str(Map<String, Object> row, String key) {
        Object v = row.get(key);
        return v != null ? v.toString() : null;
    }

    @Override
    public void close() {
    }
}
