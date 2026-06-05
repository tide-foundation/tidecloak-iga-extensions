package org.tidecloak.iga.attestors;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OrganizationModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.midgard.Midgard;
import org.midgard.models.ModelRequest;
import org.midgard.models.Policy.ApprovalType;
import org.midgard.models.Policy.ExecutionType;
import org.midgard.models.Policy.Policy;
import org.midgard.models.Policy.PolicyParameters;
import org.midgard.models.RequestExtensions.AttestationUnitSignRequest;
import org.midgard.models.RequestExtensions.PolicySignRequest;
import org.midgard.models.SignRequestSettingsMidgard;
import org.midgard.models.SignatureResponse;
import org.tidecloak.iga.crypto.SecretKeys;
import org.tidecloak.iga.producer.RealmAttestationExporter;
import org.tidecloak.iga.producer.units.GroupRoleMappingSetUnit;
import org.tidecloak.iga.producer.units.RoleCompositeChildrenSetUnit;
import org.tidecloak.iga.producer.units.UserGroupMembershipSetUnit;
import org.tidecloak.iga.producer.units.UserRoleMappingSetUnit;
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
import java.util.Comparator;
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
     * signature, distinct from the multiAdmin {@link #DUMMY_SIG_PREFIX}. Currently
     * {@link #sign(KeycloakSession, RealmModel, String, byte[])}'s firstAdmin branch
     * produces the SHA-256 stub under this prefix; the real VRK → Midgard → ORK
     * signature is the eventual replacement here.
     */
    public static final String FIRSTADMIN_SIG_PREFIX = "TIDE-FIRSTADMIN-v1:";

    /** Mode column values on {@link IgaAuthorizerEntity}. */
    public static final String MODE_FIRST_ADMIN = "firstAdmin";
    public static final String MODE_MULTI_ADMIN = "multiAdmin";

    /** Realm attribute discriminating Tide vs Tideless. */
    private static final String ATTR_IGA_ATTESTOR = "iga.attestor";

    /** Stock KC realm-management client + the legacy {@code Constants.TIDE_REALM_ADMIN} role name. */
    private static final String REALM_MANAGEMENT_CLIENT_ID = "realm-management";
    private static final String TIDE_REALM_ADMIN_ROLE = "tide-realm-admin";

    /** Multiplier for the dynamic multiAdmin threshold floor. */
    private static final double THRESHOLD_PERCENTAGE = 0.7;

    /**
     * The realm's VRK key-provider component. Its presence is
     * the VRK-availability precondition for the firstAdmin lazy seed: absent → no
     * VRK to sign with, so the seed is skipped and resolveMode's no-row branch
     * keeps reporting firstAdmin.
     */
    public static final String TIDE_VENDOR_KEY_PROVIDER_ID = "tide-vendor-key";
    /** Component config keys carrying the VRK authorizer material. */
    private static final String CFG_GVRK = "gVRK";
    private static final String CFG_GVRK_CERTIFICATE = "gVRKCertificate";
    /**
     * Component config keys carrying the <b>firstAdmin</b> AuthorizerPack + its
     * authenticating cert — the SignModel request's seg-6 authorizer / seg-8
     * authorizer-certificate for a firstAdmin ceremony. Written by
     * {@code VendorResource.SetUpTideRealm} ({@code authorizer}={@code FIRST_ADMIN},
     * {@code authorizerCertificate}={@code FIRST_ADMIN_SIGNATURE}) and consumed
     * exactly as {@code IGAUtils.signInitialTideAdmin}
     * ({@code parseHex(authorizer)} / {@code Base64.decode(authorizerCertificate)}).
     * <p>Unlike {@link #CFG_GVRK} (the 7-model MAIN VRK pack: RotateVRK, UpdateSettings,
     * UserToken, EnableOffboard, RequestInitialization, DelegationToken, ServerCert —
     * <b>NO {@code AttestationUnit:1}</b>), the firstAdmin pack's ModelIds are
     * {@code [UserContext:1, EnableOffboard:1, Policy:1, AttestationUnit:1]} — so the
     * ORK's VRKAuthorizationFlow finds {@code AttestationUnit:1} among the authorizer's
     * allowed models and accepts the sign. {@code authorizer} is hex; its cert base64.
     */
    public static final String CFG_FIRST_ADMIN_AUTHORIZER = "authorizer";
    public static final String CFG_FIRST_ADMIN_AUTHORIZER_CERTIFICATE = "authorizerCertificate";
    /** Vendor verifying-key id the admin policy artifact is keyed to. */
    private static final String CFG_VVK_ID = "vvkId";
    /**
     * Component config keys the firstAdmin VRK signing ceremony sources for its
     * {@link SignRequestSettingsMidgard} (via {@code VendorResource.ConstructSignSettings}).
     * {@code clientSecret} is the {@link SecretKeys} JSON blob carrying {@code activeVrk};
     * the rest are the ORK-network endpoint + vendor identity the native Midgard core dials.
     */
    private static final String CFG_CLIENT_SECRET = "clientSecret";
    private static final String CFG_HOME_ORK = "systemHomeOrk";
    private static final String CFG_PAYER_PUBLIC = "payerPublic";
    private static final String CFG_OBF_GVVK = "obfGVVK";

    /** Threshold env vars the Midgard signing settings require. */
    private static final String ENV_THRESHOLD_T = "THRESHOLD_T";
    private static final String ENV_THRESHOLD_N = "THRESHOLD_N";

    /**
     * Auth-flow id for a firstAdmin attestation-unit VRK sign — the single
     * {@code String} the {@link AttestationUnitSignRequest} constructor takes (the
     * positional successor to {@code ModelRequest.New}'s auth-flow arg). {@code "VRK:1"}
     * mirrors every VRK sign site.
     */
    private static final String VRK_AUTH_FLOW = "VRK:1";

    /** GRANT_ROLES CR row keys. */
    private static final String ROW_USER_ID = "USER_ID";
    private static final String ROW_ROLE_ID = "ROLE_ID";

    // SET-unit CR row keys (mirror IgaReplayDispatcher / TideSetResolver linkages).
    private static final String ROW_USER = "USER";            // JOIN/LEAVE_GROUPS owner
    private static final String ROW_GROUP = "GROUP";          // JOIN/LEAVE_GROUPS member, GROUP_*_ROLES owner
    private static final String ROW_ROLE = "ROLE";            // GROUP_*_ROLES member
    private static final String ROW_COMPOSITE = "COMPOSITE";  // ADD/REMOVE_COMPOSITE owner (parent role)
    private static final String ROW_CHILD_ROLE = "CHILD_ROLE";// ADD/REMOVE_COMPOSITE member (child role)

    // SET-unit actionTypes whose commit signs the producer set-envelope CBOR.
    private static final String ACTION_JOIN_GROUPS = "JOIN_GROUPS";
    private static final String ACTION_LEAVE_GROUPS = "LEAVE_GROUPS";
    private static final String ACTION_GROUP_GRANT_ROLES = "GROUP_GRANT_ROLES";
    private static final String ACTION_GROUP_REVOKE_ROLES = "GROUP_REVOKE_ROLES";
    private static final String ACTION_ADD_COMPOSITE = "ADD_COMPOSITE";
    private static final String ACTION_REMOVE_COMPOSITE = "REMOVE_COMPOSITE";

    // -------------------------------------------------------------------------
    // M1: multiAdmin two-phase approval ModelRequest (doken-collection seam)
    // -------------------------------------------------------------------------
    /**
     * Auth-flow id stamped on the phase-1 multiAdmin approval {@link org.midgard.models.ModelRequest}.
     * {@code "Policy:1"} is the admin-quorum (threshold-Policy) authorization flow —
     * the ORK evaluates the embedded admin {@link Policy} (the M0 artifact) against the
     * collected dokens. Mirrors the gold-reference {@code MultiAdmin.signWithAuthorizer}
     * ({@code ModelRequest.New(name, version, "Policy:1", draft)}) and the
     * {@code AddPolicyAuthorizationToSerializedRequest} contract Heimdall uses.
     */
    private static final String POLICY_AUTH_FLOW = "Policy:1";

    /**
     * The {@code modelId} arg to {@code InitializeTideRequestWithVrk} for the phase-1
     * approval request. The phase-1 request is a Midgard {@link AttestationUnitSignRequest}
     * whose constructor stamps Name={@code AttestationUnit}, Version={@code 1}; this
     * {@code AttestationUnit:1} id is one of the firstAdmin authorizer pack's allowed
     * ModelIds, so the ORK's creation-auth flow accepts the {@code InitializeTideRequestWithVrk}
     * seg-7 signature.
     */
    private static final String APPROVAL_MODEL_ID = "AttestationUnit:1";

    /**
     * Seconds added to the signing request's default expiry before
     * {@code GetDataToAuthorize} (the 30s Midgard default is too short for the ORK
     * ceremony round-trip). 3 minutes.
     */
    private static final long FIRSTADMIN_SIGN_EXPIRY_SECONDS = 180L;

    /** The action type whose firstAdmin sign is upgraded to the real VRK ceremony. */
    private static final String ACTION_GRANT_ROLES = "GRANT_ROLES";

    // -------------------------------------------------------------------------
    // Admin-policy artifact shape
    // -------------------------------------------------------------------------
    /** Stock realm-management client id the admin policy scopes. */
    private static final String POLICY_RESOURCE = REALM_MANAGEMENT_CLIENT_ID;
    /** Policy type tag stamped on the {@code tide-realm-admin} policy. */
    private static final String POLICY_TYPE = "GenericResourceAccessThresholdRole:1";
    /** ApprovalType.EXPLICIT / ExecutionType.PUBLIC. */
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

        // Lazy firstAdmin seed: the FIRST authorizer row is born here, on the first
        // Tide-mode record(), seeded firstAdmin. Idempotent — only creates when
        // absent. No mode-specific dedup difference: both firstAdmin and multiAdmin
        // persist the same IgaAuthorizationEntity shape (approval = admin username),
        // and the existing approver-role gate + the one-layer-up dedup
        // (IgaAdminResource.authorize) are unchanged.
        maybeSeedFirstAdminAuthorizer(session, realm);

        IgaScopeResolver.ResolvedScope scope = IgaScopeResolver.resolve(session, realm, cr);
        IgaScopeResolver.requireApprover(session, realm, admin, scope, cr);

        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        IgaAuthorizationEntity auth = new IgaAuthorizationEntity();
        auth.setId(UUID.randomUUID().toString());
        auth.setChangeRequest(cr);
        auth.setAuthorizedBy(admin.getId());
        auth.setApproval(admin.getUsername());
        auth.setCreatedAt(System.currentTimeMillis());
        em.persist(auth);
        em.flush();
        return auth;
    }

    @Override
    public int getThreshold(KeycloakSession session, RealmModel realm, IgaChangeRequestEntity cr) {
        // firstAdmin is single-signer onboarding: ALWAYS 1, unconditionally — it
        // does not consult per-scope overrides, the realm attribute, or the admin
        // count. The constant-first equals() is null-safe for resolveMode's null return.
        if (MODE_FIRST_ADMIN.equals(resolveMode(session, realm))) {
            return 1;
        }
        // multiAdmin: a per-scope iga.threshold (set WITH iga.approverRole on the
        // same entity) or an ADOPT_* short-circuit still wins via the shared
        // resolver; only the realm-level default flips from the static
        // iga.threshold to the dynamic 0.7 floor. The shared IgaScopeResolver
        // stays the Tideless-static path.
        IgaScopeResolver.ResolvedScope scope = IgaScopeResolver.resolve(session, realm, cr);
        if (scope != null && !scope.thresholds.isEmpty()) {
            return IgaScopeResolver.resolveThreshold(session, realm, scope, cr);   // per-scope override wins
        }
        if (cr != null && IgaReplayExtension.isAdoptAction(cr.getActionType())) {
            return 1;                                                              // ADOPT bypass wins
        }
        return Math.max(1, (int) (THRESHOLD_PERCENTAGE * countActiveTideRealmAdmins(realm, session)));
    }

    // -------------------------------------------------------------------------
    // Mode resolution + dynamic threshold count
    // -------------------------------------------------------------------------

    /**
     * Resolve the firstAdmin/multiAdmin mode for the realm.
     *
     * <p>If an {@link IgaAuthorizerEntity} row exists and its {@code mode} column
     * is set, that column is authoritative. Otherwise (the dormant-entity default
     * — {@code iga_authorizer} holds 0 rows for every realm today) the mode
     * is decided by the realm's Tide-vs-Tideless discriminator
     * {@code iga.attestor}:
     * <ul>
     *   <li>{@code iga.attestor=="tide"} → {@code "firstAdmin"} — a Tide realm
     *       that has not yet bootstrapped its admin policy. The first Tide-mode
     *       {@link #record} lazily materialises this row seeded {@code firstAdmin};
     *       until then this no-row branch reports {@code firstAdmin} so the
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
    /**
     * Public mode check for the REST layer (which lives in a different package and
     * cannot see the package-private {@link #resolveMode}). True iff the realm's
     * authorizer mode resolves to {@code multiAdmin} — the discriminator the two-phase
     * approval endpoints branch on (firstAdmin stays single-phase).
     */
    public static boolean isMultiAdminMode(KeycloakSession session, RealmModel realm) {
        return MODE_MULTI_ADMIN.equals(resolveMode(session, realm));
    }

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
        String attestor = realm.getAttribute(ATTR_IGA_ATTESTOR);
        if (ID.equals(attestor)) {
            return MODE_FIRST_ADMIN;
        }
        return null;
    }

    /**
     * Count the realm's ACTIVE tide-realm-admins for the dynamic multiAdmin
     * threshold. A user counts iff it simultaneously
     * (a) holds the {@code tide-realm-admin} realm-management role,
     * (b) is enabled, and (c) has a COMMITTED Tide identity — operationalised as a
     * {@code USER_ROLE_MAPPING} row for {@code (user, tide-realm-admin)} with
     * {@code attestation IS NOT NULL} (the inverse of the unsigned-row scan
     * {@code IgaUnsignedRowScanner.userRoleMappings}).
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
     * Inverse of {@code IgaUnsignedRowScanner.userRoleMappings}:
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
     * Lazy firstAdmin authorizer seed. On the first
     * Tide-mode {@link #record}, if the realm has NO {@link IgaAuthorizerEntity}
     * row AND {@code iga.attestor=="tide"}, create exactly one seeded
     * {@code mode="firstAdmin"} via the existing {@link IgaAuthorizerService#create}
     * persist path. This is the ONLY place the first row is born (no eager
     * toggle-on / realm-init seed); it is idempotent (the {@code !hasRow} guard
     * skips re-seeding).
     *
     * <p>VRK-availability precondition: the seed needs the realm's
     * {@code tide-vendor-key} component for its NOT-NULL {@code providerId} /
     * {@code authorizer} / {@code authorizerCertificate} fields (the VRK material).
     * If that component is absent — or present but not yet VRK-provisioned — the
     * seed is SKIPPED and {@link #resolveMode}'s no-row branch keeps reporting
     * {@code firstAdmin}. A missing component means "VRK not
     * provisioned", NOT "Tideless": the Tide discriminator is {@code iga.attestor},
     * and this whole method runs only on the tide attestor's path.
     *
     * <p>This reads the component with plain KC model access only
     * (no MidgardJava / no {@code SecretKeys} deserialization / no crypto). The
     * gVRK / gVRKCertificate config values are carried verbatim into the row; the
     * VRK signing that interprets them is a later step.
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

        // VRK material from the realm's tide-vendor-key component. Absent component
        // or unprovisioned material → defer the seed (the no-row branch reports firstAdmin).
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
        // realm's stored policy bytes verbatim; every other CR —
        // in both modes — signs the regular set/node canonical.
        boolean isPolicyBootstrap = MODE_FIRST_ADMIN.equals(mode)
                && isTideRealmAdminAssignment(realm, cr);
        byte[] canonical = isPolicyBootstrap
                ? readTideRealmAdminPolicyBytes(session, realm, cr)
                : canonicalForRegularCr(session, cr);

        // A firstAdmin NON-policy GRANT_ROLES CR is signed by the
        // REAL VVK → Midgard → ORK ceremony over the producer's `user_role_mapping_set`
        // unit-envelope CBOR (built fresh from the CR's POST-change role set, NOT the
        // entity-state canonical) — so the signed bytes are exactly what the ork
        // TVE re-derives. Everything else — incl. the firstAdmin tide-realm-admin
        // POLICY bootstrap (which signs policy bytes, not a role-mapping-set) and every
        // multiAdmin CR — keeps the stub. The policy-bootstrap exclusion is essential:
        // that path's `canonical` is the admin-policy bytes, NOT a user_role_mapping_set,
        // so it must not enter the GRANT_ROLES unit ceremony even though its actionType
        // is GRANT_ROLES. The ceremony rebuilds its OWN unit CBOR from `cr`; `canonical`
        // is only the stub fallback's input (and every non-eligible path's bytes).
        boolean realCeremonyEligible = !isPolicyBootstrap
                && isProducerEnvelopeSignedAction(cr.getActionType());
        String sig = sign(session, realm, mode, realCeremonyEligible, cr, canonical);

        // Transition trigger: on a successful firstAdmin-mode sign of the
        // tide-realm-admin policy CR, sign+commit the M0 admin Policy and ONLY
        // THEN flip the realm's authorizer mode to multiAdmin — in the SAME JPA
        // transaction as the dispatcher's ATTESTATION write.
        //
        // ★ FLIP IS NOW GATED ON A COMMITTED, SIGNED M0 POLICY. The flip burns
        // the firstAdmin AuthorizerPack on the ORK side (ork PolicySignRequest.cs:102
        // revokes it), and that pack is the ONLY pack carrying Policy:1 — i.e. the
        // ONLY pack that can sign the M0 admin Policy. So the ordering is strict:
        //   sign M0 policy (firstAdmin pack, ALIVE) -> commit/persist the policy row
        //   -> THEN flip (which burns the pack).
        // The pack must NEVER be burned before the policy is committed, and the realm
        // must NEVER flip without a signed+committed M0 policy (that exact mis-order
        // produced myrealm's broken state: flipped, no M0 policy, every subsequent
        // multiAdmin approval-model build threw APPROVAL_MODEL_BUILD_FAILED, and the
        // pack was gone so it could never be re-signed). writeBackPolicySig now
        // RETURNS whether a signed M0 policy was actually committed: if it was not
        // (the non-capable role-unresolvable skip path), the realm STAYS firstAdmin
        // — the pack is preserved so a later attempt can still sign+commit+flip. A
        // capable-realm sign FAILURE throws out of writeBackPolicySig (fail-closed)
        // and aborts combineFinal before the flip — the realm stays firstAdmin and
        // the error surfaces. Idempotent: already-multiAdmin never reaches here
        // (gated on firstAdmin).
        if (isPolicyBootstrap) {
            boolean policyCommitted = writeBackPolicySig(session, realm, cr, sig);
            if (policyCommitted) {
                flipModeToMultiAdmin(session, realm);
            } else {
                log.warnf("IGA firstAdmin policy bootstrap: realm %s did NOT commit a signed M0 admin "
                        + "Policy (no tide-realm-admin role to key the row); STAYING firstAdmin — the "
                        + "firstAdmin pack is preserved so the flip can be retried once the policy commits.",
                        realm.getName());
            }
        } else if (MODE_MULTI_ADMIN.equals(mode)) {
            // multiAdmin steady-state. If this committing CR
            // changes the active tide-realm-admin set (grant/revoke of the role), the
            // dynamic threshold floor(0.7 x N) may move, so the SIGNED admin policy
            // artifact must be regenerated + re-signed to encode the new threshold.
            // Sequenced LAST — after the CR's own attestation `sig` is already built
            // above — so the regen never disturbs the CR sign. No-op (and IsEqualTo-
            // skipped) when the CR is not a membership change or the threshold did not
            // actually move.
            maybeRegenerateAdminPolicyOnMembershipChange(session, realm, cr);
        }
        return sig;
    }

    /**
     * The regular set/node canonical today's attestor produces. LINKAGE actions sign the owner's
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
    // firstAdmin policy-bootstrap detection + transition flip
    // -------------------------------------------------------------------------

    /**
     * Detect "this CR is the tide-realm-admin policy CR" — a {@code GRANT_ROLES}
     * CR whose row carries the realm-management {@code tide-realm-admin} role id.
     * GRANT_ROLES rows carry USER_ID + ROLE_ID.
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
     * The bootstrap payload: the realm's tide-realm-admin
     * {@code IgaRolePolicyEntity.policy} value, signed as UTF-8 bytes VERBATIM
     * (no base64-decode — iga-core does not base64-encode the policy on the way
     * in). If no policy row exists yet for the
     * tide-realm-admin role (the policy may be upserted via the separate
     * {@code POST /iga/role-policies} path), fall back to the regular CR
     * canonical so the role grant still receives a valid attestation and the
     * transition still fires on the role-assignment signal. The policy write-back
     * is then a no-op (there is no row to stamp).
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
     * Write the firstAdmin bootstrap result back to the tide-realm-admin
     * {@code IgaRolePolicyEntity}, in the same JPA transaction as the dispatcher's
     * ATTESTATION write (the entity is managed, so the column updates commit
     * atomically with the replay). No-op when no policy row exists (see
     * {@link #readTideRealmAdminPolicyBytes}).
     *
     * <h3>M0 capability split</h3>
     * <ul>
     *   <li>REAL-SIGNING-CAPABLE realm: install a genuine VVK-signed admin
     *       threshold {@link Policy} — {@code POLICY = Base64(signed Policy.ToBytes())},
     *       {@code POLICY_SIG = real VVK sig}, plus {@code THRESHOLD}/types — at the
     *       POST-bootstrap admin threshold (the multiAdmin floor the realm transitions
     *       into). The real {@link #signAdminPolicyWithVvk} ceremony is fail-closed.</li>
     *   <li>NON-capable (dev/test) realm: keep the pre-M0 behaviour exactly — stamp
     *       only {@code POLICY_SIG} with the firstAdmin bootstrap signature {@code sig}
     *       (the VVK-unit / stub GRANT signature produced by {@link #combineFinal}),
     *       leaving {@code POLICY} as upserted.</li>
     * </ul>
     *
     * <h3>Flip gate (return contract)</h3>
     * Returns {@code true} iff a signed M0 admin Policy row was actually committed
     * (capable: real VVK-signed; non-capable: stub-bodied + bootstrap-sig). The caller
     * ({@link #combineFinal}) flips firstAdmin→multiAdmin ONLY on {@code true} — the flip
     * burns the firstAdmin pack (the only Policy:1 signer), so it must never fire without
     * a committed policy. Returns {@code false} ONLY on the one non-fatal skip: a
     * NON-capable realm whose tide-realm-admin role cannot be resolved to key the row — no
     * policy committed, so the realm STAYS firstAdmin (pack preserved for a retry). A
     * CAPABLE-realm sign/key failure THROWS (fail-closed) rather than returning, aborting
     * combineFinal before any flip.
     */
    boolean writeBackPolicySig(KeycloakSession session, RealmModel realm, IgaChangeRequestEntity cr,
                                    String sig) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        IgaRolePolicyEntity policy = findTideRealmAdminPolicy(session, realm);

        if (isRealSigningCapable(realm)) {
            // POST-bootstrap admin threshold: combineFinal runs PRE-replay, so the live
            // count excludes this bootstrap CR's tide-realm-admin grant; add its pending
            // delta (+1) and apply the SAME max(1, floor(0.7 x N)) floor getThreshold /
            // the regen use, so the installed admin policy and the live gate agree.
            int postCommitCount = Math.max(0,
                    countActiveTideRealmAdmins(realm, session) + tideRealmAdminMembershipDelta(realm, cr));
            int threshold = Math.max(1, (int) (THRESHOLD_PERCENTAGE * postCommitCount));
            String vvkId = realmVvkId(realm);
            AdminPolicyArtifact artifact = buildSignedAdminPolicyArtifact(session, realm, threshold, vvkId);
            // M0 FIX: the policy row MUST exist after the flip. On a real-signing-capable
            // realm the firstAdmin->multiAdmin transition is the moment the admin Policy is
            // generated + VVK-signed, so INSERT it if no row was pre-seeded via the separate
            // POST /iga/role-policies path. Previously this returned early when the row was
            // missing, flipping the realm to multiAdmin with NO signed M0 Policy — every
            // subsequent multiAdmin approval-model build then threw APPROVAL_MODEL_BUILD_FAILED.
            policy = upsertAdminPolicyRow(session, realm, policy,
                    artifact.policyBody, artifact.policySig, threshold);
            if (policy == null) {
                // tide-realm-admin role id unresolvable — cannot key a row. The flip should
                // not proceed without a signed policy on a capable realm: fail-closed.
                throw new RuntimeException("IGA firstAdmin policy bootstrap: realm " + realm.getName()
                        + " has no realm-management tide-realm-admin role to key the admin Policy (M0)");
            }
            em.flush();
            log.infof("IGA firstAdmin policy bootstrap: realm %s installed REAL VVK-signed admin "
                    + "threshold Policy (threshold %d).", realm.getName(), threshold);
            return true; // signed M0 policy committed → caller may flip
        }

        // NON-capable: pre-M0 behaviour — stamp the bootstrap GRANT signature only.
        // Still create the row if absent so the multiAdmin approval-model build has an
        // M0 Policy to embed (stub body + the bootstrap GRANT sig). Threshold mirrors the
        // capable path: max(1, floor(0.7 x post-commit admins)).
        if (policy == null) {
            int postCommitCount = Math.max(0,
                    countActiveTideRealmAdmins(realm, session) + tideRealmAdminMembershipDelta(realm, cr));
            int threshold = Math.max(1, (int) (THRESHOLD_PERCENTAGE * postCommitCount));
            String stubBody = buildAdminPolicyArtifact(threshold, realmVvkId(realm));
            policy = upsertAdminPolicyRow(session, realm, null, stubBody, sig, threshold);
            if (policy == null) {
                log.infof("IGA firstAdmin policy bootstrap (non-capable): realm %s has no "
                        + "tide-realm-admin role to key the admin Policy row; policySig write-back skipped.",
                        realm.getName());
                return false; // NO policy committed → caller must NOT flip; stay firstAdmin
            }
            em.flush();
            return true; // stub M0 policy row committed → caller may flip
        }
        policy.setPolicySig(sig);
        policy.setUpdatedAt(System.currentTimeMillis());
        // managed entity — no explicit persist needed; flush keeps it in-tx.
        em.flush();
        return true; // existing M0 policy row re-stamped + committed → caller may flip
    }

    /**
     * M0 FIX — insert-or-update the tide-realm-admin {@link IgaRolePolicyEntity}.
     * The firstAdmin bootstrap and the threshold-change regen both need the row to
     * EXIST after they run (the previous update-only behaviour silently no-op'd when
     * the row had never been pre-seeded, leaving a multiAdmin realm with no M0 Policy).
     *
     * @param existing the already-looked-up row (may be {@code null} → INSERT a new one)
     * @return the managed (inserted or updated) entity, or {@code null} when the
     *         realm-management tide-realm-admin role cannot be resolved to key the row.
     */
    IgaRolePolicyEntity upsertAdminPolicyRow(KeycloakSession session, RealmModel realm,
                                                     IgaRolePolicyEntity existing,
                                                     String policyBody, String policySig, int threshold) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        long now = System.currentTimeMillis();
        if (existing != null) {
            existing.setPolicy(policyBody);
            existing.setPolicySig(policySig);
            existing.setThreshold(threshold);
            existing.setApprovalType(POLICY_APPROVAL_TYPE);
            existing.setExecutionType(POLICY_EXECUTION_TYPE);
            existing.setUpdatedAt(now);
            return existing;
        }
        String tideRoleId = tideRealmAdminRoleId(realm);
        if (tideRoleId == null) {
            return null;
        }
        IgaRolePolicyEntity row = new IgaRolePolicyEntity();
        row.setId(java.util.UUID.randomUUID().toString());
        row.setRealmId(realm.getId());
        row.setRoleId(tideRoleId);
        row.setPolicy(policyBody);
        row.setPolicySig(policySig);
        row.setThreshold(threshold);
        row.setApprovalType(POLICY_APPROVAL_TYPE);
        row.setExecutionType(POLICY_EXECUTION_TYPE);
        row.setCreatedAt(now);
        em.persist(row);
        log.infof("IGA admin Policy (M0) row created for realm %s (tide-realm-admin, threshold %d).",
                realm.getName(), threshold);
        return row;
    }

    /**
     * Transition flip: set the realm's authorizer
     * {@code mode = "multiAdmin"} in the same JPA transaction as the ATTESTATION
     * write. Null-safe + idempotent — a redundant flip is a harmless no-op.
     * The lazy seed guarantees the row exists by the time
     * this runs (record() fires before combineFinal), but we guard defensively.
     */
    void flipModeToMultiAdmin(KeycloakSession session, RealmModel realm) {
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
    // Threshold-change admin-policy regeneration
    // -------------------------------------------------------------------------

    /**
     * Steady-state (multiAdmin) admin-policy regeneration on an active-admin-set
     * change. Fired from {@link #combineFinal} ONLY in multiAdmin
     * mode, AFTER the committing CR's own attestation signature is built (so the
     * regen is sequenced last).
     *
     * <h3>What it does</h3>
     * <ol>
     *   <li>Detect a membership-changing CR: a committed GRANT/REVOKE of the
     *       realm-management {@code tide-realm-admin} role. Anything else → no-op.</li>
     *   <li>Compute the POST-commit active-admin count. {@code combineFinal} runs
     *       BEFORE the dispatcher replays this CR, so {@link #countActiveTideRealmAdmins}
     *       still returns the PRE-commit count; we add the CR's pending net delta
     *       (+1 grant / -1 revoke).</li>
     *   <li>{@code newThreshold = max(1, floor(0.7 x postCommitCount))} — the SAME
     *       formula + the SAME counting function {@link #getThreshold} uses, so the
     *       policy the artifact encodes and the gate {@code getThreshold} enforces
     *       cannot drift.</li>
     *   <li>IsEqualTo short-circuit: if the
     *       current policy already encodes {@code newThreshold}, skip — no rewrite,
     *       no re-sign. The floor formula means most single adds DON'T move the
     *       threshold, so this is the primary churn control. Exactly one
     *       regen per committed membership-changing CR.</li>
     *   <li>Rebuild the policy artifact at {@code newThreshold},
     *       re-sign it with the realm's CURRENT authorizer mode (the invariant:
     *       admin policy signed with the mode the realm is in). This regen fires
     *       only while the realm is already multiAdmin, so {@code policySig} carries
     *       the multiAdmin {@link #DUMMY_SIG_PREFIX} (enclave path) — distinct from
     *       the firstAdmin/VRK {@link #FIRSTADMIN_SIG_PREFIX} the bootstrap
     *       transition stamps. Write {@code policy}/{@code policySig} in the same JPA
     *       transaction as the CR commit (fail-closed + atomic).</li>
     * </ol>
     *
     * <h3>Who signs</h3>
     * The membership CR is authorized by the OLD quorum at the OLD threshold
     * ({@code getThreshold} was evaluated at the commit gate BEFORE this CR was
     * counted); the regenerated policy — multiAdmin-signed here — installs the NEW
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

        // combineFinal runs PRE-replay, so the live count excludes this CR's effect;
        // add the pending net delta to obtain the post-commit count.
        // Clamp at 0 — a revoke can never make the count negative.
        int postCommitCount = Math.max(0, countActiveTideRealmAdmins(realm, session) + delta);
        int newThreshold = Math.max(1, (int) (THRESHOLD_PERCENTAGE * postCommitCount));

        // IsEqualTo short-circuit: regenerate only when the encoded threshold actually
        // moves AND a row already exists. If the row is MISSING (e.g. a realm that flipped
        // before the M0-FIX, or never had one seeded), we must INSERT it now regardless of
        // the threshold delta so the multiAdmin approval-model has an M0 Policy to embed.
        Integer priorThreshold = (policy == null) ? null : currentEncodedThreshold(policy);
        if (priorThreshold != null && priorThreshold == newThreshold) {
            log.infof("IGA policy regen skipped (threshold unchanged): realm %s tide-realm-admin policy "
                    + "already encodes threshold %d (membership delta %+d, post-commit admins %d).",
                    realm.getName(), newThreshold, delta, postCommitCount);
            return;
        }

        String vvkId = realmVvkId(realm);
        // M0: capability-aware artifact. On a REAL-SIGNING-CAPABLE realm this is a
        // genuine VVK-signed Midgard Policy (POLICY = Base64(signed Policy.ToBytes()),
        // POLICY_SIG = real VVK sig); on a non-capable dev/test realm it is the
        // pre-M0 stub (hand-rolled JSON body + DUMMY_SIG_PREFIX digest) — byte-for-byte
        // the previous behaviour. This regen fires ONLY from combineFinal's multiAdmin
        // branch, so when not capable the sig is the multiAdmin DUMMY_SIG_PREFIX as before.
        //
        // ★★ M3 GAP (KNOWN — do NOT fix here) ★★
        // On a REAL-SIGNING-CAPABLE realm, buildSignedAdminPolicyArtifact -> signAdminPolicyWithVvk
        // signs the Policy:1 admin Policy with the firstAdmin AuthorizerPack (CFG_FIRST_ADMIN_AUTHORIZER /
        // CFG_FIRST_ADMIN_AUTHORIZER_CERTIFICATE — the only pack carrying Policy:1). But this regen runs
        // ONLY in multiAdmin mode, AFTER the flip BURNED that pack (ork PolicySignRequest.cs:102 revokes
        // it). So on a provisioned realm the threshold-change re-sign would attempt Policy:1 with a
        // REVOKED pack → ORK rejects → fail-closed throw → the membership CR commit fails. The M3 fix
        // needs a quorum/Policy-flow signer (NOT the firstAdmin pack) for the steady-state re-sign.
        // Today this is latent because real-signing-capable multiAdmin realms with a moving threshold
        // are not yet exercised; flagged for the M3 work item.
        AdminPolicyArtifact artifact = buildSignedAdminPolicyArtifact(session, realm, newThreshold, vvkId);

        IgaRolePolicyEntity result = upsertAdminPolicyRow(session, realm, policy,
                artifact.policyBody, artifact.policySig, newThreshold);
        if (result == null) {
            log.infof("IGA policy regen skipped: realm %s has no tide-realm-admin role to key the "
                    + "admin Policy row (membership delta %+d).", realm.getName(), delta);
            return;
        }
        // Managed/persisted entity — flush keeps the rewrite in the CR's commit transaction
        // (atomic: if the commit rolls back, so does the regen).
        session.getProvider(JpaConnectionProvider.class).getEntityManager().flush();

        log.infof("IGA admin policy %s: realm %s tide-realm-admin threshold %s -> %d "
                + "(membership delta %+d, post-commit admins %d); policy re-signed (%s).",
                priorThreshold == null ? "created" : "regenerated",
                realm.getName(), String.valueOf(priorThreshold), newThreshold, delta, postCommitCount,
                artifact.real ? "real VVK ceremony" : (DUMMY_SIG_PREFIX + " stub"));
    }

    /**
     * The pending net delta this CR applies to the active tide-realm-admin count:
     * {@code +1} for a committed GRANT of the realm-management {@code tide-realm-admin} role,
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
     * Build the admin-policy artifact body: a deterministic JSON object carrying the
     * recomputed {@code threshold} + the {@code role}/{@code resource} scope +
     * the policy-type metadata, keyed to the realm's {@code vvkId}. The equivalent
     * Midgard {@code Policy("GenericResourceAccessThresholdRole:1","any",vvkId,
     * EXPLICIT,PUBLIC,{threshold,role,resource})} has no type in iga-core, so the
     * same field set is emitted as canonical JSON. Keys are written in
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

    // -------------------------------------------------------------------------
    // M0: real VVK-signed admin threshold Policy (multiAdmin ceremony)
    // -------------------------------------------------------------------------

    /**
     * The (policy-body, policy-signature) pair an admin-policy artifact resolves to.
     * <ul>
     *   <li>REAL-SIGNING-CAPABLE realm: {@code policyBody} is
     *       {@code Base64(Policy.ToBytes())} of a REAL VVK-signed Midgard
     *       {@link Policy} (signature attached via {@link Policy#AddSignature}), and
     *       {@code policySig} is the Base64 VVK signature string returned by the ORK
     *       network; {@code real == true}.</li>
     *   <li>NON-capable (dev/test) realm: {@code policyBody} is the legacy hand-rolled
     *       canonical JSON ({@link #buildAdminPolicyArtifact}) and {@code policySig} is
     *       the SHA-256 stub under {@link #DUMMY_SIG_PREFIX}; {@code real == false}.</li>
     * </ul>
     * Carrying both together lets every write site stamp {@code POLICY} and
     * {@code POLICY_SIG} consistently from ONE capability decision.
     */
    private static final class AdminPolicyArtifact {
        final String policyBody;
        final String policySig;
        final boolean real;
        AdminPolicyArtifact(String policyBody, String policySig, boolean real) {
            this.policyBody = policyBody;
            this.policySig = policySig;
            this.real = real;
        }
    }

    /**
     * Capability-aware admin-policy producer — the single seam M0 introduces so the
     * {@code IgaRolePolicyEntity.POLICY}/{@code POLICY_SIG} write sites no longer
     * hand-roll the body + SHA-256 stub directly.
     *
     * <p>When the realm is REAL-SIGNING-CAPABLE ({@link #isRealSigningCapable}) the
     * artifact is a genuine VVK-signed Midgard {@link Policy} produced by
     * {@link #signAdminPolicyWithVvk} (routed Midgard → native core → ORK network).
     * Otherwise it is the EXISTING stub: the legacy hand-rolled JSON body
     * ({@link #buildAdminPolicyArtifact}) plus a {@link #DUMMY_SIG_PREFIX} SHA-256
     * signature over those bytes — byte-for-byte what the pre-M0 code produced, so
     * current dev/test realms and their assertions are unaffected.
     *
     * <p>The real path is fail-closed (it throws if the ORK ceremony fails): once a
     * realm is provisioned, its admin policy must never be stamped with a fake digest.
     * The stub path never throws.
     */
    private AdminPolicyArtifact buildSignedAdminPolicyArtifact(KeycloakSession session, RealmModel realm,
                                                               int threshold, String vvkId) {
        if (isRealSigningCapable(realm)) {
            SignedPolicy signed = signAdminPolicyWithVvk(session, realm, threshold, vvkId);
            // Store the SIGNED Policy bytes Base64-encoded into the TEXT POLICY column,
            // exactly as the gold reference persists it
            // (TideRoleRequests: Base64.encode(policy.ToBytes())).
            String body = java.util.Base64.getEncoder().encodeToString(signed.signedPolicyBytes);
            return new AdminPolicyArtifact(body, signed.vvkSignature, true);
        }
        // NON-capable: keep the pre-M0 stub (hand-rolled body + DUMMY_SIG_PREFIX digest).
        String body = buildAdminPolicyArtifact(threshold, vvkId);
        String sig = stubSign(DUMMY_SIG_PREFIX, body.getBytes(StandardCharsets.UTF_8));
        return new AdminPolicyArtifact(body, sig, false);
    }

    /** The (signed-policy-bytes, VVK-signature) result of the real admin-policy ceremony. */
    private static final class SignedPolicy {
        final byte[] signedPolicyBytes;
        final String vvkSignature;
        SignedPolicy(byte[] signedPolicyBytes, String vvkSignature) {
            this.signedPolicyBytes = signedPolicyBytes;
            this.vvkSignature = vvkSignature;
        }
    }

    /**
     * The REAL admin-threshold Policy signing ceremony (M0) — a single-signer
     * (1-of-1 ADMIN quorum) VVK signature over a genuine Midgard {@link Policy},
     * routed Midgard → native core → ORK network. It mirrors
     * {@link #signFirstAdminUnitWithVvk} field-for-field: the SAME
     * {@link #constructSignSettings} settings build, the SAME firstAdmin authorizer
     * pack ({@code authorizer}/{@code authorizerCertificate} — whose ModelIds carry
     * {@code Policy:1} so the ORK's VRKAuthorizationFlow accepts the policy sign),
     * the SAME {@code Midgard.SignWithVrk(req.GetDataToAuthorize(), activeVrk)}
     * VRK:1 authorization, and the SAME {@code Midgard.SignModel} call. The ONLY
     * difference from the firstAdmin GRANT ceremony is the signed payload: a
     * {@link PolicySignRequest} carrying {@code policy.ToBytes()} instead of an
     * {@link AttestationUnitSignRequest} carrying a {@code user_role_mapping_set}
     * unit CBOR. This is the exact shape the gold reference
     * {@code IGAUtils.signInitialTideAdmin} / {@code TideRoleRequests} uses for the
     * admin-policy sign.
     *
     * <h3>Policy shape</h3>
     * {@code new Policy("GenericResourceAccessThresholdRole:1", "any", vvkId,
     * EXPLICIT, PUBLIC, {threshold, role=tide-realm-admin, resource=realm-management})}
     * — reusing the existing {@link #POLICY_TYPE}/{@link #TIDE_REALM_ADMIN_ROLE}/
     * {@link #POLICY_RESOURCE} constants and the {@code "any"} modelId the gold
     * reference uses. The ORK feeds the policy's v3 {@code DataToVerify} to the VVK
     * signer; the returned signature is attached back onto the {@link Policy} via
     * {@link Policy#AddSignature} so {@link Policy#ToBytes()} carries it.
     *
     * <p>Called only after {@link #isRealSigningCapable} already passed (via
     * {@link #buildSignedAdminPolicyArtifact}), so the settings/material are present.
     * A signing FAILURE is fail-closed (throws) — a real-provisioned admin policy
     * must not fall back to a fake stub.
     *
     * @return the real VVK-signed {@link Policy#ToBytes()} (signature attached) plus
     *         the Base64 VVK signature string.
     * @throws RuntimeException if material is missing or the Midgard sign fails.
     */
    private SignedPolicy signAdminPolicyWithVvk(KeycloakSession session, RealmModel realm,
                                                int threshold, String vvkId) {
        ComponentModel vendorKey = realm.getComponentsStream()
                .filter(c -> TIDE_VENDOR_KEY_PROVIDER_ID.equals(c.getProviderId()))
                .findFirst()
                .orElseThrow(() -> new RuntimeException(
                        "IGA admin-policy sign: realm " + realm.getName()
                                + " has no tide-vendor-key component (VRK not provisioned)"));
        MultivaluedHashMap<String, String> config = vendorKey.getConfig();
        if (config == null) {
            throw new RuntimeException("IGA admin-policy sign: tide-vendor-key component has no config (realm "
                    + realm.getName() + ")");
        }

        try {
            SignRequestSettingsMidgard settings = constructSignSettings(config);
            // seg-6 authorizer + seg-8 authorizer-certificate: the SAME firstAdmin
            // AuthorizerPack signFirstAdminUnitWithVvk uses (its ModelIds include
            // Policy:1, so the ORK's VRKAuthorizationFlow accepts a Policy sign) —
            // NOT the gVRK/gVRKCertificate MAIN pack. Sourced exactly as
            // IGAUtils.signInitialTideAdmin (parseHex(authorizer) /
            // Base64.decode(authorizerCertificate)).
            String firstAdminAuthorizer = config.getFirst(CFG_FIRST_ADMIN_AUTHORIZER);
            String firstAdminAuthorizerCert = config.getFirst(CFG_FIRST_ADMIN_AUTHORIZER_CERTIFICATE);
            if (firstAdminAuthorizer == null || firstAdminAuthorizer.isBlank()
                    || firstAdminAuthorizerCert == null || firstAdminAuthorizerCert.isBlank()) {
                throw new RuntimeException("IGA admin-policy sign: tide-vendor-key component is missing "
                        + "firstAdmin authorizer material (authorizer/authorizerCertificate) for realm "
                        + realm.getName());
            }

            // Build the REAL Midgard admin-threshold Policy. Params + shape are
            // byte-identical to the gold reference (TideRoleRequests / IGAUtils):
            // contractId=GenericResourceAccessThresholdRole:1, modelId="any",
            // keyId=vvkId, EXPLICIT/PUBLIC, params{threshold, role, resource}.
            PolicyParameters params = new PolicyParameters();
            params.put("threshold", threshold);
            params.put("role", TIDE_REALM_ADMIN_ROLE);
            params.put("resource", POLICY_RESOURCE);
            Policy policy = new Policy(POLICY_TYPE, "any", vvkId,
                    ApprovalType.EXPLICIT, ExecutionType.PUBLIC, params);

            // PolicySignRequest stamps Name=Policy,Version=1; its byte[] payload is the
            // unsigned policy bytes (policy.ToBytes()) and its String arg is the VRK:1
            // auth-flow — exactly the gold reference's
            // `new PolicySignRequest(policy.ToBytes(), "VRK:1")`.
            PolicySignRequest req = new PolicySignRequest(policy.ToBytes(), VRK_AUTH_FLOW);

            // Override expiry BEFORE GetDataToAuthorize — match the firstAdmin ceremony's
            // +180s ORK round-trip headroom (the PolicySignRequest default is 30s).
            req.SetCustomExpiry((System.currentTimeMillis() / 1000) + FIRSTADMIN_SIGN_EXPIRY_SECONDS);

            // Attach the firstAdmin authorization triplet — authorization computed LAST
            // over GetDataToAuthorize, then the firstAdmin authorizer pack + its cert,
            // exactly as signFirstAdminUnitWithVvk / IGAUtils.signInitialTideAdmin.
            req.SetAuthorization(
                    Midgard.SignWithVrk(req.GetDataToAuthorize(), settings.VendorRotatingPrivateKey));
            req.SetAuthorizer(java.util.HexFormat.of().parseHex(firstAdminAuthorizer));
            req.SetAuthorizerCertificate(java.util.Base64.getDecoder().decode(firstAdminAuthorizerCert));

            SignatureResponse resp = Midgard.SignModel(settings, req);
            if (resp == null || resp.Signatures == null || resp.Signatures.length == 0
                    || resp.Signatures[0] == null) {
                throw new RuntimeException("IGA admin-policy sign: Midgard.SignModel returned no signature "
                        + "for realm " + realm.getName());
            }
            String vvkSig = resp.Signatures[0];
            // Attach the VVK signature onto the Policy so ToBytes() carries it (the
            // real signed artifact). Mirrors TideRoleRequests.commitRolePolicy
            // (policy.AddSignature(Base64.decode(signature))).
            policy.AddSignature(java.util.Base64.getDecoder().decode(vvkSig));
            log.infof("IGA admin threshold Policy signed via Midgard VVK ceremony (realm %s, threshold %d).",
                    realm.getName(), threshold);
            return new SignedPolicy(policy.ToBytes(), vvkSig);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            // Fail-closed: a real-provisioned admin policy must not fall back to a
            // fake stub on a real signing failure.
            throw new RuntimeException("IGA admin-policy sign: Midgard VVK ceremony failed for realm "
                    + realm.getName() + ": " + e.getMessage(), e);
        }
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
    // M1: multiAdmin two-phase approval ModelRequest (doken-collection seam)
    // -------------------------------------------------------------------------

    /**
     * <b>Phase 1</b> of the multiAdmin doken-collection ceremony: build the per-CR
     * {@code Policy:1} {@link ModelRequest} the admin's browser enclave (Heimdall)
     * approves, and persist its Base64 on the CR's {@code REQUEST_MODEL} carrier.
     *
     * <h3>What it assembles</h3>
     * <ol>
     *   <li><b>Draft</b> — the action's signing payload. For a steady-state
     *       {@code GRANT_ROLES} CR this is the EXACT same {@code user_role_mapping_set}
     *       unit-envelope CBOR the firstAdmin path signs ({@link #buildUserRoleMappingSetUnitCbor}),
     *       so the ork {@code TokenValidationEngine} re-derives identical bytes. Any
     *       other action falls back to the regular set/node canonical
     *       ({@link #canonicalForRegularCr}) — a dev carry-through (only GRANT_ROLES is
     *       exercised by the live Policy:1 round-trip).</li>
     *   <li><b>Request</b> — a Midgard {@link AttestationUnitSignRequest} (auth flow
     *       {@code Policy:1}), the SAME class the firstAdmin path uses
     *       ({@link #signFirstAdminUnitWithVvk}). {@code SetUnits(byte[][])} stores the
     *       unit CBOR VERBATIM and {@code SerializeDraft} frames it as the canonical
     *       TideMemory ({@code [LE version=1][LE len][unit]...}) the ork's
     *       {@code AttestationUnitSignRequest.Deserialize} reads via {@code Draft.TryGetValue(i)}
     *       — NOT a raw {@code ModelRequest.New} with the unit bytes as the Draft. The
     *       constructor stamps Name={@code AttestationUnit}, Version={@code 1}; {@code Policy:1}
     *       is the admin-quorum auth flow the ork's {@code AttestationUnit:1} accepts
     *       (its {@code AllowedAuthorizationFlows} include {@code Policy}).</li>
     *   <li><b>Policy</b> — {@code SetPolicy(<the M0 admin Policy bytes>)}: the genuine
     *       VVK-signed threshold {@link Policy} M0 installed on the tide-realm-admin
     *       {@link IgaRolePolicyEntity} (stored Base64 of {@code Policy.ToBytes()}). The
     *       enclave authorizes the request AGAINST this policy.</li>
     *   <li><b>Creation-auth</b> — {@code InitializeTideRequestWithVrk(...)}: the seg-7
     *       VRK signature proving this realm's vendor created the request, sourced from
     *       the SAME firstAdmin authorizer pack + settings the M0 / firstAdmin ceremonies
     *       use. Capability-gated: only attempted on a {@link #isRealSigningCapable} realm
     *       (dev/test realms get the un-initialized request, sufficient for the round-trip
     *       wiring M1 validates).</li>
     * </ol>
     *
     * <p><b>multiAdmin only.</b> Callers branch on {@link #resolveMode}; the firstAdmin
     * single-phase path never invokes this. The persisted Base64 is what the admin-UI
     * fetches (GET .../approval-model) and hands to the enclave.
     *
     * @return the Base64 of {@code ModelRequest.Encode()} (also persisted on the CR).
     * @throws RuntimeException if the realm has no M0 admin Policy to embed, or (on a
     *         real-signing-capable realm) the VRK creation-auth fails — fail-closed, so a
     *         provisioned realm never ships an un-authorized approval request.
     */
    public String buildMultiAdminApprovalModel(KeycloakSession session, RealmModel realm,
                                               IgaChangeRequestEntity cr) {
        // The M0 admin Policy bytes to embed — the genuine VVK-signed threshold Policy.
        byte[] adminPolicyBytes = readM0AdminPolicyBytes(session, realm);
        if (adminPolicyBytes == null) {
            throw new RuntimeException("IGA multiAdmin approval: realm " + realm.getName()
                    + " has no signed tide-realm-admin admin Policy (M0) to embed in the "
                    + "Policy:1 approval request for CR " + cr.getId());
        }

        // The action's draft: reuse the producer unit-CBOR for any producer-envelope-
        // signed action (set units) so the ork TVE re-derives identical bytes; otherwise
        // the regular canonical (a dev/non-real-signing carry-through — only the
        // producer-envelope actions are exercised by the live Policy:1 round-trip).
        byte[] unitCbor = isProducerEnvelopeSignedAction(cr.getActionType())
                ? buildUnitCbor(session, realm, cr)
                : canonicalForRegularCr(session, cr);

        // M2: frame the draft via the proper Midgard AttestationUnitSignRequest (NOT a raw
        // ModelRequest.New). SetUnits(byte[][]) stores the unit CBOR VERBATIM; SerializeDraft
        // then builds the canonical TideMemory framing ([LE version=1][LE len][unit]...) the
        // ork's AttestationUnitSignRequest.Deserialize reads via Draft.TryGetValue(i). This
        // mirrors signFirstAdminUnitWithVvk's request construction field-for-field, with the
        // ONLY differences being (a) the Policy:1 auth flow (admin-quorum) instead of VRK:1,
        // and (b) SetPolicy + InitializeTideRequestWithVrk creation-auth (vs. the firstAdmin
        // SignWithVrk authorizer triplet). The constructor stamps Name=AttestationUnit,
        // Version=1 (model id AttestationUnit:1).
        AttestationUnitSignRequest req = new AttestationUnitSignRequest(POLICY_AUTH_FLOW);
        // VERBATIM CBOR via the byte[][] overload (NOT List<?>/Object — those re-CBOR-wrap
        // each element through Jackson, corrupting the envelope).
        req.SetUnits(new byte[][]{ unitCbor });
        // Longer expiry than the 30s default — admin approval is a human round-trip. Set
        // BEFORE materializing the draft / creation-auth (Expiry folds into both the
        // data-to-authorize hash and InitializeTideRequestWithVrk's expireAtTime).
        req.SetCustomExpiry((System.currentTimeMillis() / 1000) + FIRSTADMIN_SIGN_EXPIRY_SECONDS);
        // Embed the M0 admin Policy the enclave authorizes the request against.
        req.SetPolicy(adminPolicyBytes);

        // Materialize Draft (the TideMemory unit framing) BEFORE the VRK creation-auth and
        // Encode(): for an AttestationUnitSignRequest the units are lazily folded into Draft
        // by SerializeDraft, which only runs via GetDataToAuthorize/GetDraft. Without this,
        // InitializeTideRequestWithVrk would SHA512 an EMPTY Draft (seg-7 signed over nothing)
        // and Encode() would persist an empty seg-3 — both breaking the ork round-trip.
        try {
            // GetDraft() runs SerializeDraft and returns the framed bytes (we don't need the
            // return — the side effect of populating req.Draft is the point).
            req.GetDraft();
        } catch (Exception e) {
            throw new RuntimeException("IGA multiAdmin approval: failed to serialize the "
                    + "AttestationUnit draft framing for CR " + cr.getId() + ": " + e.getMessage(), e);
        }

        // seg-7 creation-authorization via the realm's VRK — only on a real-signing-capable
        // realm (dev/test realms carry no real VRK; the un-initialized request still
        // round-trips for the carrier/threshold wiring). Fail-closed once capable.
        if (isRealSigningCapable(realm)) {
            initializeApprovalRequestWithVrk(realm, req);
        }

        String encoded = java.util.Base64.getEncoder().encodeToString(req.Encode());
        cr.setRequestModel(encoded);
        session.getProvider(JpaConnectionProvider.class).getEntityManager().flush();
        log.infof("IGA multiAdmin approval (phase 1): built Policy:1 ModelRequest for CR %s "
                + "(action=%s, realm=%s, creation-auth=%s).", cr.getId(), cr.getActionType(),
                realm.getName(), isRealSigningCapable(realm) ? "VRK" : "none(dev)");
        return encoded;
    }

    /**
     * Attach the seg-7 VRK creation-authorization to the phase-1 approval request — the
     * iga-core port of the gold-reference {@code MultiAdmin.signWithAuthorizer}'s
     * {@code ModelRequest.InitializeTideRequestWithVrk(req, settings, modelId, authorizerBytes, certBytes)}.
     * Uses the SAME settings build ({@link #constructSignSettings}) and the SAME firstAdmin
     * authorizer pack ({@code authorizer}/{@code authorizerCertificate}) the M0 /
     * firstAdmin unit ceremonies use, so the ORK's VRKAuthorizationFlow accepts the
     * {@code AttestationUnit:1} creation. Called only after {@link #isRealSigningCapable}
     * passed; fail-closed (throws) on any signing failure.
     */
    private void initializeApprovalRequestWithVrk(RealmModel realm, ModelRequest req) {
        ComponentModel vendorKey = realm.getComponentsStream()
                .filter(c -> TIDE_VENDOR_KEY_PROVIDER_ID.equals(c.getProviderId()))
                .findFirst()
                .orElseThrow(() -> new RuntimeException(
                        "IGA multiAdmin approval: realm " + realm.getName()
                                + " has no tide-vendor-key component (VRK not provisioned)"));
        MultivaluedHashMap<String, String> config = vendorKey.getConfig();
        if (config == null) {
            throw new RuntimeException("IGA multiAdmin approval: tide-vendor-key component has no config "
                    + "(realm " + realm.getName() + ")");
        }
        try {
            SignRequestSettingsMidgard settings = constructSignSettings(config);
            // The ORK's VRKAuthorizationFlow.AuthorizeAsync authorizes the OUTER request id
            // that InitializeTideRequestWithVrk builds — "TideRequestInitialization:1" — NOT the
            // inner APPROVAL_MODEL_ID ("AttestationUnit:1", which is only embedded as the seg-2
            // draft modelId and merely existence-checked). The MAIN gVRK pack lists
            // TideRequestInitialization:1 in its ModelIds; the firstAdmin pack does not. So the
            // creation-auth wrapper must be authorized by the MAIN gVRK pack, not the firstAdmin
            // pack. (signUnitsWithFirstAdminVvk stays on the firstAdmin pack — it signs a real
            // AttestationUnit:1 OUTER request, which the firstAdmin pack does allow.)
            String gVrk = config.getFirst(CFG_GVRK);
            String gVrkCert = config.getFirst(CFG_GVRK_CERTIFICATE);
            if (gVrk == null || gVrk.isBlank()
                    || gVrkCert == null || gVrkCert.isBlank()) {
                throw new RuntimeException("IGA multiAdmin approval: tide-vendor-key component is missing "
                        + "MAIN gVRK authorizer material (gVRK/gVRKCertificate) for realm "
                        + realm.getName());
            }
            ModelRequest.InitializeTideRequestWithVrk(req, settings, APPROVAL_MODEL_ID,
                    java.util.HexFormat.of().parseHex(gVrk),
                    java.util.Base64.getDecoder().decode(gVrkCert));
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("IGA multiAdmin approval: VRK creation-auth failed for realm "
                    + realm.getName() + ": " + e.getMessage(), e);
        }
    }

    /**
     * <b>Phase 2</b> of the multiAdmin doken-collection ceremony: accept the
     * doken-embedded serialized {@link ModelRequest} back from the admin's enclave,
     * validate it, persist it onto the CR carrier, and record the approving admin
     * toward threshold.
     *
     * <h3>What it does (mirrors the gold-reference {@code MultiAdmin.commit})</h3>
     * <ol>
     *   <li><b>Validate</b> — the returned Base64 must parse via {@link ModelRequest#FromBytes}.
     *       A malformed request is rejected (the enclave round-trip produced garbage).</li>
     *   <li><b>Persist</b> — overwrite {@code REQUEST_MODEL} with the doken-embedded bytes.
     *       The policy is deliberately NOT re-set ({@code SetPolicy} would invalidate the
     *       embedded doken — gold reference {@code MultiAdmin.commit}, the "would invalidate
     *       the doken" skip).</li>
     *   <li><b>Record</b> — once-per-admin dedup (mirrors the gold reference's
     *       already-approved guard), then persist the admin's {@link IgaAuthorizationEntity}
     *       toward the {@link #getThreshold} gate, reusing {@link #record}'s approver-role +
     *       persistence path. The commit gate ({@code IgaAdminResource.commit}) still does
     *       the actual threshold check + combineFinal/dispatch.</li>
     * </ol>
     *
     * <p>This (phase 2) only collects + persists the doken-embedded carrier and counts
     * the approval toward threshold; the actual {@code Midgard.SignModel(Policy:1)} over
     * the collected carrier runs at COMMIT time ({@link #signMultiAdminUnitViaPolicy},
     * reached from {@link #combineFinal} via {@link #sign}), capability-gated + fail-closed.
     *
     * @param dokenEmbeddedModelB64 the Base64 of the doken-embedded {@code ModelRequest.Encode()}.
     * @param admin the approving admin (whose distinct approval counts toward threshold).
     * @return {@code true} if this call recorded a NEW approval; {@code false} if the admin
     *         had already approved (idempotent dedup — the model is still persisted).
     * @throws RuntimeException if the returned bytes do not parse as a {@link ModelRequest}.
     */
    public boolean acceptMultiAdminApprovalModel(KeycloakSession session, RealmModel realm,
                                                 IgaChangeRequestEntity cr,
                                                 String dokenEmbeddedModelB64, UserModel admin) {
        if (dokenEmbeddedModelB64 == null || dokenEmbeddedModelB64.isBlank()) {
            throw new RuntimeException("IGA multiAdmin approval (phase 2): empty doken-embedded model "
                    + "for CR " + cr.getId());
        }
        // (1) Validate it parses as a ModelRequest (round-trip integrity).
        byte[] decoded;
        try {
            decoded = java.util.Base64.getDecoder().decode(dokenEmbeddedModelB64);
            ModelRequest parsed = ModelRequest.FromBytes(decoded);
            if (parsed == null) {
                throw new RuntimeException("ModelRequest.FromBytes returned null");
            }
        } catch (RuntimeException re) {
            throw re;
        } catch (Exception e) {
            throw new RuntimeException("IGA multiAdmin approval (phase 2): returned model for CR "
                    + cr.getId() + " is not a valid ModelRequest: " + e.getMessage(), e);
        }

        // (2) Persist the doken-embedded model back on the carrier. NO re-SetPolicy —
        // that would invalidate the embedded doken (gold reference MultiAdmin.commit:441).
        cr.setRequestModel(dokenEmbeddedModelB64);

        // (3) Once-per-admin dedup, then record toward threshold.
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<IgaAuthorizationEntity> existing = em.createNamedQuery(
                        "IgaAuthorization.findByChangeRequest", IgaAuthorizationEntity.class)
                .setParameter("changeRequestId", cr.getId())
                .getResultList();
        for (IgaAuthorizationEntity a : existing) {
            if ((admin.getUsername() != null && admin.getUsername().equals(a.getApproval()))
                    || (admin.getId() != null && admin.getId().equals(a.getAuthorizedBy()))) {
                em.flush(); // keep the doken-embedded model write
                log.infof("IGA multiAdmin approval (phase 2): admin %s already approved CR %s — "
                        + "model persisted, no new approval recorded.", admin.getUsername(), cr.getId());
                return false;
            }
        }
        // record() enforces the approver-role gate and persists the IgaAuthorizationEntity.
        record(session, cr, admin, null);
        em.flush();
        log.infof("IGA multiAdmin approval (phase 2): recorded approval by %s for CR %s "
                + "(doken-embedded model persisted).", admin.getUsername(), cr.getId());
        return true;
    }

    /**
     * The M0 admin Policy bytes to embed in the phase-1 approval request: the
     * tide-realm-admin {@link IgaRolePolicyEntity#getPolicy()} value. On a
     * real-signing-capable realm M0 stores {@code Base64(Policy.ToBytes())} of a genuine
     * VVK-signed {@link Policy}, so we Base64-decode to recover the raw {@code Policy.ToBytes()}.
     * If the stored value is NOT Base64 (a dev/test stub realm where M0 wrote the legacy
     * hand-rolled JSON body), we fall back to the verbatim UTF-8 bytes so the round-trip
     * still carries SOMETHING as the policy — the enclave/ORK only consumes it for real on
     * a provisioned realm. Returns {@code null} only when there is no admin policy row at all.
     */
    private static byte[] readM0AdminPolicyBytes(KeycloakSession session, RealmModel realm) {
        IgaRolePolicyEntity policy = findTideRealmAdminPolicy(session, realm);
        if (policy == null || policy.getPolicy() == null || policy.getPolicy().isBlank()) {
            return null;
        }
        String body = policy.getPolicy();
        try {
            // M0 real path persists Base64(Policy.ToBytes()) — decode to the raw Policy bytes.
            return java.util.Base64.getDecoder().decode(body);
        } catch (IllegalArgumentException notBase64) {
            // Dev/test stub realm: M0 wrote hand-rolled JSON. Carry it verbatim.
            return body.getBytes(StandardCharsets.UTF_8);
        }
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
     * Mode-aware signing swap-point.
     *
     * <p>The {@code firstAdmin} branch produces the REAL VVK → Midgard → ORK
     * ceremony — but ONLY for a non-policy {@code GRANT_ROLES} CR
     * ({@code realCeremonyEligible}) AND ONLY once the realm is established as
     * REAL-SIGNING-CAPABLE ({@link #isRealSigningCapable}). The ceremony signs the
     * producer's {@code user_role_mapping_set} unit-envelope CBOR (built from the
     * CR's POST-change role set), NOT the entity-state canonical, so the signed
     * bytes are byte-identical to what the ork TVE re-derives. It re-wraps the
     * returned Midgard signature with the existing {@link #FIRSTADMIN_SIG_PREFIX} so
     * the {@code TIDE-FIRSTADMIN-v1:} stamp shape the dispatcher fan-out depends on
     * is preserved.
     *
     * <p><b>Capability gate (graceful) vs fail-closed.</b> The real ceremony is
     * attempted only when {@link #isRealSigningCapable} confirms the realm has a
     * provisioned VRK ({@code tide-vendor-key} + {@code activeVrk}), the ork
     * endpoint settings, and the {@code THRESHOLD_T/N} env. If NOT capable (any
     * dev/test realm without real orks — {@code clientSecret='{}'}, no
     * {@code systemHomeOrk}/{@code vvkId}, no threshold env) the path falls back to
     * the firstAdmin {@link #FIRSTADMIN_SIG_PREFIX} STUB — no hard-fail. Once
     * capable, a ceremony ERROR (e.g. ORKs unreachable) is fail-closed (throws): a
     * real-provisioned firstAdmin GRANT_ROLES must never be stamped with a fake digest.
     *
     * <p>Every other path keeps the stub:
     * <ul>
     *   <li>{@code firstAdmin} non-eligible (the tide-realm-admin POLICY bootstrap,
     *       and any non-{@code GRANT_ROLES} CR) → {@link #FIRSTADMIN_SIG_PREFIX} stub.</li>
     *   <li>{@code multiAdmin} — when the realm is REAL-SIGNING-CAPABLE the collected-doken
     *       carrier ({@code cr.requestModel}) is reloaded and signed via the real
     *       {@code Midgard.SignModel(Policy:1)} ceremony ({@link #signMultiAdminUnitViaPolicy}),
     *       fail-closed; the stamped value is the real ORK signature, NOT the
     *       {@link #DUMMY_SIG_PREFIX} digest. A NON-capable dev/test realm keeps the
     *       {@link #DUMMY_SIG_PREFIX} stub (no carrier / no orks). Any non-firstAdmin,
     *       non-multiAdmin mode also keeps the stub.</li>
     * </ul>
     * The distinction between modes is NOT local-vs-network — both ceremonies go
     * Midgard → ORK in production; it is (a) admin quorum and (b) key /
     * signing ceremony.
     *
     * @param realCeremonyEligible {@code true} iff this is a firstAdmin non-policy
     *        {@code GRANT_ROLES} CR (computed by {@link #combineFinal}, which knows
     *        the policy-bootstrap discriminator); gates the real ceremony so the
     *        policy-bootstrap path — whose {@code canonical} is policy bytes, not a
     *        role-mapping-set — never enters it.
     * @param cr       the committing CR — the eligible firstAdmin ceremony rebuilds
     *        its OWN {@code user_role_mapping_set} unit CBOR from this; every other
     *        path ignores it and signs {@code canonical}.
     * @param canonical the entity-state canonical (the stub input for every
     *        non-eligible path AND the eligible path's capability-gate fallback).
     */
    private String sign(KeycloakSession session, RealmModel realm, String mode,
                        boolean realCeremonyEligible, IgaChangeRequestEntity cr, byte[] canonical) {
        if (MODE_FIRST_ADMIN.equals(mode)) {
            if (realCeremonyEligible && isRealSigningCapable(realm)) {
                return signFirstAdminUnitWithVvk(session, realm, cr);      // REAL VVK unit-CBOR ceremony (fail-closed)
            }
            return stubSign(FIRSTADMIN_SIG_PREFIX, canonical);             // firstAdmin stub (not capable / policy bootstrap / other CRs)
        }
        if (MODE_MULTI_ADMIN.equals(mode) && isRealSigningCapable(realm)) {
            return signMultiAdminUnitViaPolicy(session, realm, cr);        // REAL Midgard.SignModel(Policy:1) over the collected-doken carrier (fail-closed)
        }
        return stubSign(DUMMY_SIG_PREFIX, canonical);                     // multiAdmin (not capable) / non-firstAdmin stub
    }

    /**
     * Capability check (graceful) — is this realm REAL-SIGNING-CAPABLE? True iff the
     * realm carries everything the firstAdmin VVK ceremony needs to reach the ORK
     * network, so a NEGATIVE answer can safely fall back to the stub without
     * hard-failing (dev/test realms), while a POSITIVE answer commits the realm
     * to fail-closed real signing.
     *
     * <p>Probes, all NON-throwing (a malformed {@code clientSecret} is treated as
     * "not capable", not an error):
     * <ol>
     *   <li>a {@code tide-vendor-key} component with config exists;</li>
     *   <li>its {@code clientSecret} {@link SecretKeys} blob carries a non-blank
     *       {@code activeVrk} (the VRK private key to sign with) — a
     *       {@code clientSecret='{}'} fails here;</li>
     *   <li>the VRK authorizer material {@code gVRK}/{@code gVRKCertificate} is
     *       present;</li>
     *   <li>the ork-endpoint settings {@code systemHomeOrk} + {@code vvkId} are
     *       present;</li>
     *   <li>{@code THRESHOLD_T} and {@code THRESHOLD_N} env vars are set to non-zero
     *       ints.</li>
     * </ol>
     * This is the SAME material {@link #constructSignSettings} requires — the gate is
     * its non-fatal pre-flight, so "capable" ⇒ {@code constructSignSettings} will not
     * throw on the settings it builds. (It does not pre-dial the ORKs; an actually
     * unreachable ORK surfaces inside the ceremony and is fail-closed there.)
     */
    private static boolean isRealSigningCapable(RealmModel realm) {
        ComponentModel vendorKey = realm.getComponentsStream()
                .filter(c -> TIDE_VENDOR_KEY_PROVIDER_ID.equals(c.getProviderId()))
                .findFirst().orElse(null);
        if (vendorKey == null || vendorKey.getConfig() == null) {
            return false;
        }
        MultivaluedHashMap<String, String> config = vendorKey.getConfig();

        // (2) activeVrk from the clientSecret blob — a malformed/empty blob → not capable.
        String clientSecret = config.getFirst(CFG_CLIENT_SECRET);
        if (clientSecret == null || clientSecret.isBlank()) {
            return false;
        }
        try {
            SecretKeys secretKeys = MAPPER.readValue(clientSecret, SecretKeys.class);
            if (secretKeys == null || secretKeys.activeVrk == null || secretKeys.activeVrk.isBlank()) {
                return false;
            }
        } catch (Exception parseFail) {
            return false; // unparseable clientSecret → treat as not-provisioned (stub).
        }

        // (3) VRK authorizer material + (4) ork-endpoint settings.
        if (isBlank(config.getFirst(CFG_GVRK)) || isBlank(config.getFirst(CFG_GVRK_CERTIFICATE))
                || isBlank(config.getFirst(CFG_HOME_ORK)) || isBlank(config.getFirst(CFG_VVK_ID))) {
            return false;
        }

        // (5) THRESHOLD_T / THRESHOLD_N env, non-zero ints.
        return thresholdEnv(ENV_THRESHOLD_T) > 0 && thresholdEnv(ENV_THRESHOLD_N) > 0;
    }

    /** Parse a THRESHOLD_* env var to an int; 0 when unset/blank/non-numeric. */
    private static int thresholdEnv(String name) {
        String v = System.getenv(name);
        if (v == null || v.isBlank()) {
            return 0;
        }
        try {
            return Integer.parseInt(v.trim());
        } catch (NumberFormatException nfe) {
            return 0;
        }
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    /**
     * Reusable BATCH unit-signer — the generalized firstAdmin {@code AttestationUnit:1}
     * ceremony. Signs N verbatim CBOR attestation-unit envelopes under the firstAdmin
     * authorizer pack (VRK:1 / AuthorizerPack) in a SINGLE {@code Midgard.SignModel}
     * round-trip and returns the bare (prefix-free, Base64-decoded) 64-byte VVK
     * signatures, one per unit, in order.
     *
     * <h3>Why one round-trip yields N sigs (batch)</h3>
     * The ork {@code AttestationUnitSignRequest.Deserialize()} walks every Draft
     * TideMemory segment, adds one unit per segment, and sets
     * {@code AmountOfSignaturesRequested = <unit count>}; {@code PrepareDatasToSign()}
     * emits one {@code PlainSignatureFormat} per unit. So a request whose Draft frames
     * {@code units[0..N-1]} (via {@link AttestationUnitSignRequest#SetUnits(byte[][])})
     * comes back as {@code Signatures[0..N-1]}, {@code Signatures[i]} being the VVK
     * signature over {@code units[i]}'s verbatim CBOR. No per-unit loop needed.
     *
     * <h3>Verbatim-bytes contract</h3>
     * The envelopes are passed through the {@code byte[][]} overload (stores bytes
     * as-is); the {@code List<?>}/{@code Object} overloads MUST NOT be used (they
     * re-CBOR-wrap each element through Jackson, corrupting the wire shape). The caller
     * MUST sign and ship the SAME byte[] it serialized — the ork verifies over the
     * literal envelope bytes.
     *
     * @param unitEnvelopes          one verbatim CBOR unit-envelope per requested sig (>=1)
     * @param settings               the realm signing settings ({@link #constructSignSettings})
     * @param firstAdminAuthorizer   hex of the firstAdmin AuthorizerPack ({@code authorizer})
     * @param firstAdminAuthorizerCert Base64 of its VVK-signature cert ({@code authorizerCertificate})
     * @param realmName              for log/error context only
     * @return {@code byte[][]} of bare 64-byte VVK sigs, {@code sigs[i]} over {@code unitEnvelopes[i]}
     * @throws Exception fail-closed on a missing/short signature response
     */
    public static byte[][] signUnitsWithFirstAdminVvk(byte[][] unitEnvelopes,
                                                      SignRequestSettingsMidgard settings,
                                                      String firstAdminAuthorizer,
                                                      String firstAdminAuthorizerCert,
                                                      String realmName) throws Exception {
        if (unitEnvelopes == null || unitEnvelopes.length == 0) {
            return new byte[0][];
        }

        AttestationUnitSignRequest req = new AttestationUnitSignRequest(VRK_AUTH_FLOW);
        // VERBATIM CBOR via the byte[][] overload (NOT List<?>/Object — those re-CBOR-wrap
        // each element through Jackson, corrupting the envelope). One Draft segment per unit.
        req.SetUnits(unitEnvelopes);

        // Override expiry BEFORE GetDataToAuthorize — the 30s Midgard default is too short
        // for the ORK ceremony round-trip (+180s).
        req.SetCustomExpiry((System.currentTimeMillis() / 1000) + FIRSTADMIN_SIGN_EXPIRY_SECONDS);

        // Attach the firstAdmin authorization triplet (authorization computed LAST over
        // GetDataToAuthorize, then the firstAdmin authorizer pack + its cert) — exactly the
        // gold-reference ordering. The firstAdmin pack (AttestationUnit:1 in its ModelIds),
        // NOT the gVRK/gVRKCertificate MAIN pack which the ORK's VRKAuthorizationFlow
        // rejects for AttestationUnit:1.
        req.SetAuthorization(
                Midgard.SignWithVrk(req.GetDataToAuthorize(), settings.VendorRotatingPrivateKey));
        req.SetAuthorizer(java.util.HexFormat.of().parseHex(firstAdminAuthorizer));
        req.SetAuthorizerCertificate(java.util.Base64.getDecoder().decode(firstAdminAuthorizerCert));

        SignatureResponse resp = Midgard.SignModel(settings, req);
        if (resp == null || resp.Signatures == null || resp.Signatures.length < unitEnvelopes.length) {
            throw new RuntimeException("IGA unit sign: Midgard.SignModel returned "
                    + (resp == null || resp.Signatures == null ? "no" : String.valueOf(resp.Signatures.length))
                    + " signatures for " + unitEnvelopes.length + " unit(s) (realm " + realmName + ")");
        }
        byte[][] out = new byte[unitEnvelopes.length][];
        for (int i = 0; i < unitEnvelopes.length; i++) {
            if (resp.Signatures[i] == null) {
                throw new RuntimeException("IGA unit sign: null signature at index " + i
                        + " (realm " + realmName + ")");
            }
            // Signatures[i] is Base64 (same form ModelRequest decodes for creation-auth) —
            // decode to the bare 64-byte VVK sig the consumer ships verbatim.
            out[i] = java.util.Base64.getDecoder().decode(resp.Signatures[i]);
        }
        return out;
    }

    /**
     * The REAL firstAdmin signing ceremony — single-signer (1-of-1 ADMIN quorum)
     * VVK signature over the producer's {@code user_role_mapping_set} unit-envelope
     * CBOR, routed Midgard → native core → ORK network. The settings build +
     * VRK-authorizer triplet are copied field-for-field from the gold reference
     * {@code IGAUtils.signInitialTideAdmin} and {@code VendorResource.ConstructSignSettings};
     * the request triplet mirrors {@code TideChainOfTrustExchangeProvider}.
     *
     * <h3>What is signed: the unit CBOR, not the entity-state canonical</h3>
     * The bytes handed to Midgard are the EXACT {@code user_role_mapping_set}
     * unit-envelope CBOR the producer ({@link RealmAttestationExporter}) emits and
     * the ork {@code TokenValidationEngine} re-derives — built here from the CR's
     * POST-change role set via {@link #buildUserRoleMappingSetUnitCbor}. They are
     * passed VERBATIM through {@link AttestationUnitSignRequest#SetUnits(byte[][])}
     * (the 2-D byte[] overload that stores the bytes as-is); the {@code List<?>} /
     * {@code Object} overloads must NOT be used — they re-run the bytes through a
     * Jackson {@code writeValueAsBytes}, double-CBOR-wrapping the already-encoded
     * envelope into a byte-string and corrupting the wire shape. {@code Signatures[0]}
     * is the VVK signature over {@code units[0]}'s CBOR.
     *
     * <p><b>Wire shape preserved:</b> the return is {@code FIRSTADMIN_SIG_PREFIX +
     * <midgard-sig>}, byte-compatible with the prior stub's prefix so the
     * dispatcher's opaque fan-out and the prefix assertions are unaffected. Only
     * reached when {@link #isRealSigningCapable} already passed, so the
     * settings/material are present; an actual signing FAILURE is fail-closed.
     *
     * @throws RuntimeException if the unit cannot be built, or the Midgard sign
     *         fails (fail-closed — a real-provisioned firstAdmin GRANT_ROLES cannot
     *         be stamped with a fake signature).
     */
    private String signFirstAdminUnitWithVvk(KeycloakSession session, RealmModel realm,
                                             IgaChangeRequestEntity cr) {
        ComponentModel vendorKey = realm.getComponentsStream()
                .filter(c -> TIDE_VENDOR_KEY_PROVIDER_ID.equals(c.getProviderId()))
                .findFirst()
                .orElseThrow(() -> new RuntimeException(
                        "IGA firstAdmin sign: realm " + realm.getName()
                                + " has no tide-vendor-key component (VRK not provisioned)"));
        MultivaluedHashMap<String, String> config = vendorKey.getConfig();
        if (config == null) {
            throw new RuntimeException("IGA firstAdmin sign: tide-vendor-key component has no config (realm "
                    + realm.getName() + ")");
        }

        try {
            SignRequestSettingsMidgard settings = constructSignSettings(config);
            // seg-6 authorizer + seg-8 authorizer-certificate: the firstAdmin
            // AuthorizerPack (ModelIds include AttestationUnit:1) and its VVK-signature
            // cert — NOT the gVRK/gVRKCertificate MAIN pack (7 models, no
            // AttestationUnit:1, which the ORK's VRKAuthorizationFlow rejects with
            // "This authorizer has not allowed the model AttestationUnit:1 to be
            // authorized"). Sourced exactly as IGAUtils.signInitialTideAdmin
            // (parseHex(authorizer) / Base64.decode(authorizerCertificate)).
            String firstAdminAuthorizer = config.getFirst(CFG_FIRST_ADMIN_AUTHORIZER);
            String firstAdminAuthorizerCert = config.getFirst(CFG_FIRST_ADMIN_AUTHORIZER_CERTIFICATE);
            if (firstAdminAuthorizer == null || firstAdminAuthorizer.isBlank()
                    || firstAdminAuthorizerCert == null || firstAdminAuthorizerCert.isBlank()) {
                throw new RuntimeException("IGA firstAdmin sign: tide-vendor-key component is missing "
                        + "firstAdmin authorizer material (authorizer/authorizerCertificate) for realm "
                        + realm.getName());
            }

            // The producer's unit-envelope CBOR for the CR's affected owner
            // (POST-change set) — the exact bytes the ork TVE re-derives. This IS the
            // draft this ceremony attests. Dispatched per actionType
            // (user_role_mapping_set, user_group_membership_set, group_role_mapping_set,
            // role_composite_children_set), each reusing the producer's own builder.
            byte[] unitCbor = buildUnitCbor(session, realm, cr);

            // Delegate to the reusable batch unit-signer (single-unit case). It runs the
            // identical firstAdmin VRK:1 / AttestationUnit:1 ceremony and returns one bare
            // 64-byte VVK signature per unit (prefix-free). Signatures[0] is the VVK sig
            // over unit[0]'s verbatim CBOR.
            byte[][] sigs = signUnitsWithFirstAdminVvk(
                    new byte[][]{ unitCbor }, settings, firstAdminAuthorizer, firstAdminAuthorizerCert,
                    realm.getName());

            log.infof("IGA firstAdmin GRANT_ROLES signed via Midgard VVK unit ceremony (realm %s).",
                    realm.getName());
            // Preserve the firstAdmin stamp shape: prefix + the real ORK signature
            // (the VVK signature over unit[0]'s CBOR), Base64 of the bare sig bytes.
            return FIRSTADMIN_SIG_PREFIX + java.util.Base64.getEncoder().encodeToString(sigs[0]);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            // Fail-closed: a real-provisioned firstAdmin GRANT_ROLES must not fall
            // back to a fake stub on a real signing failure.
            throw new RuntimeException("IGA firstAdmin sign: Midgard VVK unit ceremony failed for realm "
                    + realm.getName() + ": " + e.getMessage(), e);
        }
    }

    /**
     * <b>M2</b> — the REAL multiAdmin commit ceremony: sign the collected-doken
     * {@code Policy:1} carrier via {@code Midgard.SignModel}, yielding the genuine ORK
     * threshold signature over the attestation unit. This replaces the M1
     * {@link #DUMMY_SIG_PREFIX} stub for a REAL-SIGNING-CAPABLE realm.
     *
     * <h3>What it does</h3>
     * <ol>
     *   <li><b>Reload</b> the doken-embedded serialized {@link ModelRequest} from the CR
     *       carrier ({@link IgaChangeRequestEntity#getRequestModel()} — Base64 of
     *       {@code Encode()}). After phase-2 ({@link #acceptMultiAdminApprovalModel}) this
     *       carrier already holds the request the enclave authorized: seg-3 Draft = the
     *       {@link AttestationUnitSignRequest} TideMemory unit framing, seg-6/7 = the
     *       admin-quorum dokens + their Policy:1 approval signatures, seg-9 = the M0 admin
     *       Policy. {@code FromBytes} reconstructs all of it verbatim.</li>
     *   <li><b>Do NOT re-{@code SetPolicy}</b> (nor touch the authorizer/authorization) —
     *       the carrier IS the doken-bound request; re-setting any of those segments would
     *       invalidate the collected dokens (the same "would invalidate the doken" rule
     *       phase-2 follows on accept-back). We sign the request AS-RELOADED.</li>
     *   <li><b>{@code Midgard.SignModel}</b> with the realm's {@link #constructSignSettings}
     *       (same settings build the firstAdmin / M0 ceremonies use) → the ORK runs the
     *       {@code PolicyAuthorizationFlow} (verifying the embedded dokens against the M0
     *       Policy) and returns the VVK signature over the unit. The bare
     *       {@code Signatures[0]} is the stamped attestation — a REAL signature, distinct
     *       from {@link #DUMMY_SIG_PREFIX}, so {@code IgaReplayDispatcher} writes it onto
     *       the row's {@code attestation} column.</li>
     * </ol>
     *
     * <p><b>Capability + fail-closed.</b> Reached ONLY from {@link #sign} after
     * {@link #isRealSigningCapable} passed (a NON-capable dev/test realm keeps the
     * {@link #DUMMY_SIG_PREFIX} stub), so the settings/material are present. A missing
     * carrier (phase-1 never ran) or any signing FAILURE is fail-closed (throws) — a
     * real-provisioned multiAdmin commit must never be stamped with a fake digest.
     *
     * <p><b>Note (M3).</b> The LIVE Policy:1 round-trip (real ORKs + real enclave dokens)
     * is deferred to M3 — it needs the ork's {@code AttestationUnit:1} Policy-flow change,
     * a 2-admin realm, and the admin-UI. This method is the iga-half seam: capability-gated
     * and fail-closed, so on a provisioned realm it goes straight to the real ceremony.
     *
     * @throws RuntimeException if the carrier is absent/unparseable or the Midgard sign fails.
     */
    private String signMultiAdminUnitViaPolicy(KeycloakSession session, RealmModel realm,
                                               IgaChangeRequestEntity cr) {
        String carrier = cr.getRequestModel();
        if (carrier == null || carrier.isBlank()) {
            throw new RuntimeException("IGA multiAdmin sign: CR " + cr.getId() + " has no approval-model "
                    + "carrier (phase-1 buildMultiAdminApprovalModel never ran) — cannot Policy:1-sign");
        }
        ComponentModel vendorKey = realm.getComponentsStream()
                .filter(c -> TIDE_VENDOR_KEY_PROVIDER_ID.equals(c.getProviderId()))
                .findFirst()
                .orElseThrow(() -> new RuntimeException(
                        "IGA multiAdmin sign: realm " + realm.getName()
                                + " has no tide-vendor-key component (VRK not provisioned)"));
        MultivaluedHashMap<String, String> config = vendorKey.getConfig();
        if (config == null) {
            throw new RuntimeException("IGA multiAdmin sign: tide-vendor-key component has no config (realm "
                    + realm.getName() + ")");
        }
        try {
            // Reload the doken-embedded request verbatim. NO SetPolicy / SetAuthorizer /
            // SetAuthorization — the carrier already carries the doken-bound segments the
            // ORK's PolicyAuthorizationFlow consumes; re-setting any would invalidate them.
            ModelRequest req = ModelRequest.FromBytes(java.util.Base64.getDecoder().decode(carrier));
            if (req == null) {
                throw new RuntimeException("ModelRequest.FromBytes returned null for the CR carrier");
            }

            SignRequestSettingsMidgard settings = constructSignSettings(config);
            SignatureResponse resp = Midgard.SignModel(settings, req);
            if (resp == null || resp.Signatures == null || resp.Signatures.length == 0
                    || resp.Signatures[0] == null) {
                throw new RuntimeException("IGA multiAdmin sign: Midgard.SignModel returned no signature "
                        + "for realm " + realm.getName());
            }
            log.infof("IGA multiAdmin commit signed via Midgard Policy:1 ceremony (realm %s, CR %s).",
                    realm.getName(), cr.getId());
            // The bare ORK signature over the unit — the REAL attestation (NOT DUMMY_SIG_PREFIX).
            return resp.Signatures[0];
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            // Fail-closed: a real-provisioned multiAdmin commit must not fall back to a
            // fake stub on a real signing failure.
            throw new RuntimeException("IGA multiAdmin sign: Midgard Policy:1 ceremony failed for realm "
                    + realm.getName() + " (CR " + cr.getId() + "): " + e.getMessage(), e);
        }
    }

    /**
     * Build the producer's {@code user_role_mapping_set} unit-envelope CBOR for a
     * firstAdmin {@code GRANT_ROLES} CR. The bytes
     * are byte-identical to what {@link RealmAttestationExporter#userRoleMappingSet}
     * → {@link UserRoleMappingSetUnit#serialize()} emits for the affected user, so
     * the ork {@code TokenValidationEngine} re-derives the same envelope and the VVK
     * signature verifies.
     *
     * <h3>POST-change set, in PRODUCER RAW order (not sorted)</h3>
     * {@code combineFinal} runs BEFORE the dispatcher replays the grant, so the DB
     * still holds the PRE-change USER_ROLE_MAPPING set. We read it with the SAME
     * JPQL the producer uses ({@code SELECT urm.roleId FROM UserRoleMappingEntity urm
     * WHERE urm.user.id = :owner}) — preserving the RAW JPA result order into an
     * {@link ArrayList}, NOT a sorted {@link TreeSet} — then APPEND the CR's pending
     * grant role-id(s) iff not already present. The producer emits the raw stored
     * child set verbatim ({@code UserRoleMappingSetUnit} javadoc: "RAW stored
     * USER_ROLE_MAPPING child set"); a TreeSet here would reorder the ids and the
     * CBOR would NOT match the ork-side re-derivation. (Mirrors
     * {@link #canonicalizeLinkageSet}'s PRE-set + delta logic but for the ordered
     * producer set rather than the sorted canonical.)
     *
     * <p>A {@code GRANT_ROLES} CR is captured per single user+role
     * ({@code IgaUserAdapter.grantRole}: one row {@code {USER_ID, ROLE_ID}}); we
     * resolve that user from the rows (preferring {@code cr.getEntityId()}), apply
     * EVERY row's ROLE_ID to that user's set (defensive against a multi-row CR), and
     * serialize the one unit. The realm binding is the unit's {@code target_id ==
     * userId}; the realm id is {@code realm.getId()}.
     */
    private byte[] buildUserRoleMappingSetUnitCbor(KeycloakSession session, RealmModel realm,
                                                   IgaChangeRequestEntity cr) {
        List<Map<String, Object>> rows = parseRows(cr.getRowsJson());

        // Resolve the affected user: prefer the CR's entityId (the grant subject —
        // IgaUserAdapter.grantRole sets entityId = userId), fall back to the first
        // row's USER_ID. Collect every pending grant role-id for that user.
        String userId = cr.getEntityId();
        LinkedHashSet<String> grantedRoleIds = new LinkedHashSet<>();
        for (Map<String, Object> row : rows) {
            String rowUser = str(row, ROW_USER_ID);
            if (userId == null) {
                userId = rowUser; // no entityId — adopt the first row's user.
            }
            if (rowUser != null && rowUser.equals(userId)) {
                String roleId = str(row, ROW_ROLE_ID);
                if (roleId != null) {
                    grantedRoleIds.add(roleId);
                }
            }
        }
        if (userId == null) {
            throw new RuntimeException("IGA firstAdmin sign: GRANT_ROLES CR " + cr.getId()
                    + " carries no resolvable USER_ID for the user_role_mapping_set unit");
        }

        // PRE-change RAW stored role-id set for the user, in producer JPA order
        // (UNFILTERED — onlyAttested=false on the producer's default export, so the
        // pending-but-unsigned grant we are about to add is included; we mirror the
        // unfiltered query and append the grant ourselves).
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        @SuppressWarnings("unchecked")
        List<String> roleIds = new ArrayList<>(em.createQuery(
                        "SELECT urm.roleId FROM UserRoleMappingEntity urm WHERE urm.user.id = :owner"
                                + " ORDER BY urm.roleId")
                .setParameter("owner", userId)
                .getResultList());
        // Apply the pending grant delta: add each granted id not already present.
        for (String roleId : grantedRoleIds) {
            if (!roleIds.contains(roleId)) {
                roleIds.add(roleId);
            }
        }
        // Deterministic role-id ordering. The VVK sig is verified over the LITERAL
        // envelope bytes (no re-canonicalization), so role_ids ORDER is load-bearing.
        // Sort the assembled set ascending so it byte-matches the producer's emitted
        // unit (RealmAttestationExporter#userRoleMappingSet, ORDER BY urm.roleId):
        // signer = sorted(pre-set ∪ granted) == producer = sorted(committed set).
        roleIds.sort(Comparator.naturalOrder());

        return new UserRoleMappingSetUnit(realm.getId(), userId, roleIds).serialize();
    }

    // -------------------------------------------------------------------------
    // Generalized producer-envelope CBOR builder (PR-A: SET units)
    // -------------------------------------------------------------------------

    /**
     * Is this actionType signed at commit by re-building + signing the PRODUCER's own
     * unit-envelope CBOR (so the ork TVE re-derives byte-identical bytes), rather than
     * by the legacy SHA-256 stub over a hand-rolled canonical?
     *
     * <p>Covered today (PR-A): the {@code user_role_mapping_set} template plus the three
     * SET units whose OWNER entity already exists at commit time (the edge is what the CR
     * adds/removes) — so the post-change member set is {@code pre-set ± delta}, exactly
     * like the proven {@code GRANT_ROLES} path. NODE creates (whose entity does NOT exist
     * until replay) and the DERIVED/realm-scoped sets are deferred to PR-A.2.
     */
    static boolean isProducerEnvelopeSignedAction(String actionType) {
        if (actionType == null) {
            return false;
        }
        switch (actionType) {
            case ACTION_GRANT_ROLES:            // user_role_mapping_set (template)
            case ACTION_JOIN_GROUPS:            // user_group_membership_set (add)
            case ACTION_LEAVE_GROUPS:           // user_group_membership_set (remove)
            case ACTION_GROUP_GRANT_ROLES:      // group_role_mapping_set (add)
            case ACTION_GROUP_REVOKE_ROLES:     // group_role_mapping_set (remove)
            case ACTION_ADD_COMPOSITE:          // role_composite_children_set (add)
            case ACTION_REMOVE_COMPOSITE:       // role_composite_children_set (remove)
                return true;
            default:
                return false;
        }
    }

    /**
     * Build the producer unit-envelope CBOR for a producer-envelope-signed CR, reusing
     * the SAME {@link RealmAttestationExporter} builder the login/export path uses so the
     * bytes are byte-identical to the ork-side re-derivation. Dispatched per actionType.
     */
    byte[] buildUnitCbor(KeycloakSession session, RealmModel realm,
                                 IgaChangeRequestEntity cr) {
        String actionType = cr.getActionType();
        switch (actionType) {
            case ACTION_GRANT_ROLES:
                return buildUserRoleMappingSetUnitCbor(session, realm, cr);
            case ACTION_JOIN_GROUPS:
            case ACTION_LEAVE_GROUPS:
                return buildUserGroupMembershipSetUnitCbor(session, realm, cr);
            case ACTION_GROUP_GRANT_ROLES:
            case ACTION_GROUP_REVOKE_ROLES:
                return buildGroupRoleMappingSetUnitCbor(session, realm, cr);
            case ACTION_ADD_COMPOSITE:
            case ACTION_REMOVE_COMPOSITE:
                return buildRoleCompositeChildrenSetUnitCbor(session, realm, cr);
            default:
                throw new RuntimeException("IGA firstAdmin sign: actionType " + actionType
                        + " has no producer-envelope unit builder (CR " + cr.getId() + ")");
        }
    }

    /**
     * Apply the CR's per-row member delta to a pre-change owner set, in PRODUCER sort
     * order. {@code addAction=true} → JOIN/GRANT/ADD (member ids appended iff absent);
     * {@code addAction=false} → LEAVE/REVOKE/REMOVE (member ids dropped). The result is
     * sorted ascending to byte-match the producer's {@code ORDER BY} emission (the VVK
     * sig is verified over the LITERAL envelope bytes, so member ORDER is load-bearing).
     */
    private static List<String> applyMemberDelta(List<String> preSet,
                                                 LinkedHashSet<String> deltaMembers,
                                                 boolean addAction) {
        List<String> members = new ArrayList<>(preSet);
        if (addAction) {
            for (String m : deltaMembers) {
                if (!members.contains(m)) {
                    members.add(m);
                }
            }
        } else {
            members.removeAll(deltaMembers);
        }
        members.sort(Comparator.naturalOrder());
        return members;
    }

    /**
     * {@code user_group_membership_set} (unit 14) — owner = user; member = group id.
     * Pre-set read via {@link RealmAttestationExporter#userGroupMembershipSet} (unfiltered,
     * onlyAttested=false) ± the CR's JOIN/LEAVE delta, then re-serialized.
     */
    byte[] buildUserGroupMembershipSetUnitCbor(KeycloakSession session, RealmModel realm,
                                                       IgaChangeRequestEntity cr) {
        List<Map<String, Object>> rows = parseRows(cr.getRowsJson());
        boolean addAction = ACTION_JOIN_GROUPS.equals(cr.getActionType());

        String userId = cr.getEntityId();
        LinkedHashSet<String> deltaGroups = new LinkedHashSet<>();
        for (Map<String, Object> row : rows) {
            String rowUser = str(row, ROW_USER);
            if (userId == null) {
                userId = rowUser;
            }
            if (rowUser != null && rowUser.equals(userId)) {
                String groupId = str(row, ROW_GROUP);
                if (groupId != null) {
                    deltaGroups.add(groupId);
                }
            }
        }
        if (userId == null) {
            throw new RuntimeException("IGA firstAdmin sign: " + cr.getActionType() + " CR "
                    + cr.getId() + " carries no resolvable USER for user_group_membership_set");
        }
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<String> groupIds = applyMemberDelta(
                RealmAttestationExporter.userGroupMembershipSet(em, userId, false),
                deltaGroups, addAction);
        return new UserGroupMembershipSetUnit(realm.getId(), userId, groupIds).serialize();
    }

    /**
     * {@code group_role_mapping_set} (unit 10) — owner = group; member = role id.
     * Pre-set via {@link RealmAttestationExporter#groupRoleMappingSet} ± the CR's
     * GROUP_GRANT/REVOKE_ROLES delta, re-serialized.
     */
    byte[] buildGroupRoleMappingSetUnitCbor(KeycloakSession session, RealmModel realm,
                                                    IgaChangeRequestEntity cr) {
        List<Map<String, Object>> rows = parseRows(cr.getRowsJson());
        boolean addAction = ACTION_GROUP_GRANT_ROLES.equals(cr.getActionType());

        String groupId = cr.getEntityId();
        LinkedHashSet<String> deltaRoles = new LinkedHashSet<>();
        for (Map<String, Object> row : rows) {
            String rowGroup = str(row, ROW_GROUP);
            if (groupId == null) {
                groupId = rowGroup;
            }
            if (rowGroup != null && rowGroup.equals(groupId)) {
                String roleId = str(row, ROW_ROLE);
                if (roleId != null) {
                    deltaRoles.add(roleId);
                }
            }
        }
        if (groupId == null) {
            throw new RuntimeException("IGA firstAdmin sign: " + cr.getActionType() + " CR "
                    + cr.getId() + " carries no resolvable GROUP for group_role_mapping_set");
        }
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        GroupRoleMappingSetUnit preUnit = RealmAttestationExporter.groupRoleMappingSet(
                em, groupId, realm.getId());
        List<String> roleIds = applyMemberDelta(preUnit.roleIds(), deltaRoles, addAction);
        return new GroupRoleMappingSetUnit(realm.getId(), groupId, roleIds).serialize();
    }

    /**
     * {@code role_composite_children_set} (unit 9) — owner = parent (composite) role;
     * member = child role id. Pre-set read live from the model via
     * {@link RealmAttestationExporter#roleCompositeChildrenSet} ± the CR's
     * ADD/REMOVE_COMPOSITE delta, re-serialized. The parent role already exists at commit
     * time; only the composite edge is being added/removed, so the model read is valid.
     */
    byte[] buildRoleCompositeChildrenSetUnitCbor(KeycloakSession session, RealmModel realm,
                                                         IgaChangeRequestEntity cr) {
        List<Map<String, Object>> rows = parseRows(cr.getRowsJson());
        boolean addAction = ACTION_ADD_COMPOSITE.equals(cr.getActionType());

        String parentRoleId = cr.getEntityId();
        LinkedHashSet<String> deltaChildren = new LinkedHashSet<>();
        for (Map<String, Object> row : rows) {
            String rowParent = str(row, ROW_COMPOSITE);
            if (parentRoleId == null) {
                parentRoleId = rowParent;
            }
            if (rowParent != null && rowParent.equals(parentRoleId)) {
                String childRoleId = str(row, ROW_CHILD_ROLE);
                if (childRoleId != null) {
                    deltaChildren.add(childRoleId);
                }
            }
        }
        if (parentRoleId == null) {
            throw new RuntimeException("IGA firstAdmin sign: " + cr.getActionType() + " CR "
                    + cr.getId() + " carries no resolvable COMPOSITE parent role for "
                    + "role_composite_children_set");
        }
        RoleModel parent = realm.getRoleById(parentRoleId);
        if (parent == null) {
            throw new RuntimeException("IGA firstAdmin sign: " + cr.getActionType() + " CR "
                    + cr.getId() + " parent role " + parentRoleId + " not found");
        }
        RoleCompositeChildrenSetUnit preUnit =
                RealmAttestationExporter.roleCompositeChildrenSet(parent, realm.getId());
        List<String> childIds = applyMemberDelta(preUnit.childRoleIds(), deltaChildren, addAction);
        return new RoleCompositeChildrenSetUnit(realm.getId(), parentRoleId, childIds).serialize();
    }

    // -------------------------------------------------------------------------
    // PR-A.2: POST-replay per-unit-type column stamping (uniform Design B)
    // -------------------------------------------------------------------------

    /**
     * <b>POST-replay producer-envelope column stamping.</b> Called from
     * {@code IgaAdminResource.commit} AFTER the dispatcher/extension has applied the CR
     * (the live entity now exists), in the SAME JPA transaction as the replay. For the
     * remaining producer attestation-unit types (the NODE units, the DERIVED owner-sets,
     * and the realm-scoped units), this signs the SAME shared
     * {@link RealmAttestationExporter} producer envelope the login/export path emits and
     * stamps it onto that unit type's DEDICATED attestation column (added in PR-A) —
     * so commit bytes == login bytes by construction and the ork TVE re-derives identical
     * bytes.
     *
     * <p>Distinct from {@link #combineFinal}, which runs PRE-replay and returns the ONE
     * signature the dispatcher fans onto the edge/node {@code ATTESTATION} column. The
     * node/derived/realm units have NO clean PRE-replay seam (a {@code CREATE_*} entity
     * does not exist yet, and a derived set's owner-side column is separate from the
     * edge), so they are stamped here instead, from the committed live state.
     *
     * <p>No-op unless the resolved attestor is set-signing (tide). Best-effort per unit
     * type — a build/stamp failure for one unit type is logged and skipped rather than
     * aborting an already-applied commit (the row simply keeps a NULL per-unit column),
     * EXCEPT a real-signing-capable VVK ceremony failure, which is fail-closed inside
     * {@link #signProducerEnvelope}.
     */
    public void stampProducerUnitColumns(KeycloakSession session, RealmModel realm,
                                         IgaChangeRequestEntity cr) {
        String mode = resolveMode(session, realm);
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        String action = cr.getActionType();
        try {
            switch (action) {
                // ---- NODE units: re-stamp the owner's node column with the real envelope ----
                case "CREATE_CLIENT", "SET_CLIENT_ATTRIBUTE", "UPDATE_CLIENT_WEB_ORIGINS",
                     "UPDATE_CLIENT_REDIRECT_URIS" ->
                        stampClientConfig(session, realm, mode, em, cr);
                case "CREATE_CLIENT_SCOPE", "SET_CLIENT_SCOPE_ATTRIBUTE" ->
                        stampClientScopeConfig(session, realm, mode, em, cr);
                case "CREATE_ROLE", "SET_ROLE_ATTRIBUTE" ->
                        stampRoleDefinition(session, realm, mode, em, cr);
                case "CREATE_GROUP", "SET_GROUP_ATTRIBUTE" ->
                        stampGroupDefinition(session, realm, mode, em, cr);
                case "CREATE_USER", "SET_USER_ATTRIBUTE" ->
                        stampUserIdentity(session, realm, mode, em, cr);
                case "CREATE_ORGANIZATION", "UPDATE_ORGANIZATION" ->
                        stampOrganizationNode(session, realm, mode, em, cr);

                // ---- DERIVED sets: re-sign the owner's set into the owner's set column ----
                case "ASSIGN_SCOPE", "REMOVE_SCOPE" ->
                        stampClientScopeAssignmentSet(session, realm, mode, em, cr);
                case "ADD_PROTOCOL_MAPPER", "UPDATE_PROTOCOL_MAPPER", "REMOVE_PROTOCOL_MAPPER" ->
                        stampMapperSet(session, realm, mode, em, cr);
                case "SCOPE_MAPPING_ADD", "SCOPE_MAPPING_REMOVE" ->
                        stampScopeRoleAllowlistClient(session, realm, mode, em, cr);
                case "SCOPE_ADD_ROLE", "SCOPE_REMOVE_ROLE" ->
                        stampScopeRoleAllowlistScope(session, realm, mode, em, cr);

                // ---- REALM-scoped units ----
                case "SET_REALM_ATTRIBUTE", "SET_REALM_CONFIG" ->
                        stampRealmConfig(session, realm, mode, em, cr);
                case "ADD_REALM_DEFAULT_GROUP", "REMOVE_REALM_DEFAULT_GROUP" ->
                        stampRealmDefaultGroupsSet(session, realm, mode, em, cr);
                case "ORG_INVITE_MEMBER", "ORG_RESEND_INVITE" ->
                        stampOrgDomainSet(session, realm, mode, em, cr);
                default -> { /* edge sets already covered by combineFinal fan-out; no-op */ }
            }
        } catch (RuntimeException fatal) {
            // Fail-closed VVK ceremony failures (real-signing realm) propagate; everything
            // else was already swallowed inside the per-unit stampers.
            throw fatal;
        }
    }

    /**
     * Sign a producer unit-envelope for the POST-replay column stampers. firstAdmin +
     * real-signing-capable → the REAL single-unit VVK ceremony (fail-closed); every other
     * case → the deterministic stub under the mode-appropriate prefix (firstAdmin →
     * {@link #FIRSTADMIN_SIG_PREFIX}, else {@link #DUMMY_SIG_PREFIX}). Mirrors
     * {@link #sign}'s mode dispatch but is envelope-driven (no CR canonical), so the same
     * byte-shape is produced for the per-unit columns.
     */
    private String signProducerEnvelope(KeycloakSession session, RealmModel realm, String mode,
                                        byte[] envelope) {
        if (MODE_FIRST_ADMIN.equals(mode) && isRealSigningCapable(realm)) {
            return signEnvelopeWithFirstAdminVvk(realm, envelope);
        }
        String prefix = MODE_FIRST_ADMIN.equals(mode) ? FIRSTADMIN_SIG_PREFIX : DUMMY_SIG_PREFIX;
        return stubSign(prefix, envelope);
    }

    /**
     * Real single-unit firstAdmin VVK ceremony over an arbitrary producer envelope,
     * reusing {@link #signUnitsWithFirstAdminVvk} (the batch signer). Fail-closed.
     */
    private String signEnvelopeWithFirstAdminVvk(RealmModel realm, byte[] envelope) {
        ComponentModel vendorKey = realm.getComponentsStream()
                .filter(c -> TIDE_VENDOR_KEY_PROVIDER_ID.equals(c.getProviderId()))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("IGA unit-column stamp: realm "
                        + realm.getName() + " has no tide-vendor-key component (VRK not provisioned)"));
        MultivaluedHashMap<String, String> config = vendorKey.getConfig();
        try {
            SignRequestSettingsMidgard settings = constructSignSettings(config);
            String authorizer = config.getFirst(CFG_FIRST_ADMIN_AUTHORIZER);
            String authorizerCert = config.getFirst(CFG_FIRST_ADMIN_AUTHORIZER_CERTIFICATE);
            byte[][] sigs = signUnitsWithFirstAdminVvk(new byte[][]{ envelope }, settings,
                    authorizer, authorizerCert, realm.getName());
            return FIRSTADMIN_SIG_PREFIX + java.util.Base64.getEncoder().encodeToString(sigs[0]);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("IGA unit-column stamp: VVK ceremony failed for realm "
                    + realm.getName() + ": " + e.getMessage(), e);
        }
    }

    // ---- NODE stampers (owner exists post-replay; re-stamp the node ATTESTATION column) ----

    private void stampClientConfig(KeycloakSession session, RealmModel realm, String mode,
                                   EntityManager em, IgaChangeRequestEntity cr) {
        try {
            ClientModel client = resolveClientForStamp(realm, cr);
            if (client == null) return;
            byte[] env = RealmAttestationExporter.clientConfig(client, realm.getId()).serialize();
            String sig = signProducerEnvelope(session, realm, mode, env);
            em.createQuery("UPDATE ClientEntity e SET e.attestation = :sig WHERE e.id = :id")
                    .setParameter("sig", sig).setParameter("id", client.getId()).executeUpdate();
        } catch (RuntimeException fatal) { rethrowIfFailClosed(fatal); }
    }

    private void stampClientScopeConfig(KeycloakSession session, RealmModel realm, String mode,
                                        EntityManager em, IgaChangeRequestEntity cr) {
        try {
            // CREATE_CLIENT_SCOPE keys on ID; SET_CLIENT_SCOPE_ATTRIBUTE keys on SCOPE_ID.
            String scopeId = firstRowKeyOr(cr, "SCOPE_ID", "ID");
            if (scopeId == null) return;
            ClientScopeModel scope = realm.getClientScopeById(scopeId);
            if (scope == null) return;
            byte[] env = RealmAttestationExporter.clientScopeConfig(scope, realm.getId()).serialize();
            String sig = signProducerEnvelope(session, realm, mode, env);
            em.createQuery("UPDATE ClientScopeEntity e SET e.attestation = :sig WHERE e.id = :id")
                    .setParameter("sig", sig).setParameter("id", scopeId).executeUpdate();
        } catch (RuntimeException fatal) { rethrowIfFailClosed(fatal); }
    }

    private void stampRoleDefinition(KeycloakSession session, RealmModel realm, String mode,
                                     EntityManager em, IgaChangeRequestEntity cr) {
        try {
            // CREATE_ROLE keys the new row on ID; SET_ROLE_ATTRIBUTE keys on ROLE_ID.
            String roleId = firstRowKeyOr(cr, "ROLE_ID", "ID");
            if (roleId == null) return;
            RoleModel role = realm.getRoleById(roleId);
            if (role == null) return;
            byte[] env = RealmAttestationExporter.roleDefinition(role, realm.getId()).serialize();
            String sig = signProducerEnvelope(session, realm, mode, env);
            em.createQuery("UPDATE RoleEntity e SET e.attestation = :sig WHERE e.id = :id")
                    .setParameter("sig", sig).setParameter("id", roleId).executeUpdate();
        } catch (RuntimeException fatal) { rethrowIfFailClosed(fatal); }
    }

    private void stampGroupDefinition(KeycloakSession session, RealmModel realm, String mode,
                                      EntityManager em, IgaChangeRequestEntity cr) {
        try {
            // CREATE_GROUP keys on ID; SET_GROUP_ATTRIBUTE keys on GROUP_ID.
            String groupId = firstRowKeyOr(cr, "GROUP_ID", "ID");
            if (groupId == null) return;
            org.keycloak.models.GroupModel group = realm.getGroupById(groupId);
            if (group == null) return;
            byte[] env = RealmAttestationExporter.groupDefinition(group, realm.getId()).serialize();
            String sig = signProducerEnvelope(session, realm, mode, env);
            em.createQuery("UPDATE GroupEntity e SET e.attestation = :sig WHERE e.id = :id")
                    .setParameter("sig", sig).setParameter("id", groupId).executeUpdate();
        } catch (RuntimeException fatal) { rethrowIfFailClosed(fatal); }
    }

    private void stampUserIdentity(KeycloakSession session, RealmModel realm, String mode,
                                   EntityManager em, IgaChangeRequestEntity cr) {
        try {
            // CREATE_USER keys on ID; SET_USER_ATTRIBUTE keys on USER_ID.
            String userId = firstRowKeyOr(cr, "USER_ID", "ID");
            if (userId == null) return;
            UserModel user = session.users().getUserById(realm, userId);
            if (user == null) return;
            byte[] env = RealmAttestationExporter.userIdentity(user, realm.getId()).serialize();
            String sig = signProducerEnvelope(session, realm, mode, env);
            em.createQuery("UPDATE UserEntity e SET e.attestation = :sig WHERE e.id = :id")
                    .setParameter("sig", sig).setParameter("id", userId).executeUpdate();
        } catch (RuntimeException fatal) { rethrowIfFailClosed(fatal); }
    }

    private void stampOrganizationNode(KeycloakSession session, RealmModel realm, String mode,
                                       EntityManager em, IgaChangeRequestEntity cr) {
        try {
            String orgId = firstRowKey(cr, "ORG_ID");
            org.keycloak.organization.OrganizationProvider orgs =
                    session.getProvider(org.keycloak.organization.OrganizationProvider.class);
            if (orgs == null) return;
            // CREATE_ORGANIZATION rows carry ORG_NAME not ORG_ID; resolve by name then.
            OrganizationModel org = orgId != null ? orgs.getById(orgId) : null;
            if (org == null) {
                String name = firstRowKey(cr, "ORG_NAME");
                if (name != null) {
                    org = orgs.getAllStream().filter(o -> name.equals(o.getName())).findFirst().orElse(null);
                }
            }
            if (org == null) return;
            String groupId = RealmAttestationExporter.organizationBackingGroupId(em, org.getId());
            byte[] env = RealmAttestationExporter.organizationDefinition(org, groupId, realm.getId()).serialize();
            String sig = signProducerEnvelope(session, realm, mode, env);
            em.createQuery("UPDATE OrganizationEntity e SET e.attestation = :sig WHERE e.id = :id")
                    .setParameter("sig", sig).setParameter("id", org.getId()).executeUpdate();
        } catch (RuntimeException fatal) { rethrowIfFailClosed(fatal); }
    }

    // ---- DERIVED set stampers (owner exists; re-sign owner set into owner set column) ----

    private void stampClientScopeAssignmentSet(KeycloakSession session, RealmModel realm, String mode,
                                               EntityManager em, IgaChangeRequestEntity cr) {
        try {
            String clientUuid = firstRowKey(cr, "CLIENT_UUID");
            if (clientUuid == null) return;
            ClientModel client = realm.getClientById(clientUuid);
            if (client == null) return;
            byte[] env = RealmAttestationExporter.clientScopeAssignmentSet(client, realm.getId()).serialize();
            String sig = signProducerEnvelope(session, realm, mode, env);
            em.createQuery("UPDATE ClientEntity e SET e.clientScopeAssignmentAttestation = :sig WHERE e.id = :id")
                    .setParameter("sig", sig).setParameter("id", clientUuid).executeUpdate();
        } catch (RuntimeException fatal) { rethrowIfFailClosed(fatal); }
    }

    private void stampMapperSet(KeycloakSession session, RealmModel realm, String mode,
                                EntityManager em, IgaChangeRequestEntity cr) {
        try {
            // The mapper's parent is a client (CLIENT_UUID) OR a client_scope (CLIENT_SCOPE_ID).
            String clientUuid = firstRowKey(cr, "CLIENT_UUID");
            String scopeId = firstRowKey(cr, "CLIENT_SCOPE_ID");
            if (clientUuid != null) {
                ClientModel client = realm.getClientById(clientUuid);
                if (client == null) return;
                byte[] env = RealmAttestationExporter.clientMapperSet(client, realm.getId()).serialize();
                String sig = signProducerEnvelope(session, realm, mode, env);
                em.createQuery("UPDATE ClientEntity e SET e.clientMapperSetAttestation = :sig WHERE e.id = :id")
                        .setParameter("sig", sig).setParameter("id", clientUuid).executeUpdate();
            } else if (scopeId != null) {
                ClientScopeModel scope = realm.getClientScopeById(scopeId);
                if (scope == null) return;
                byte[] env = RealmAttestationExporter.clientScopeMapperSet(scope, realm.getId()).serialize();
                String sig = signProducerEnvelope(session, realm, mode, env);
                em.createQuery("UPDATE ClientScopeEntity e SET e.clientScopeMapperSetAttestation = :sig WHERE e.id = :id")
                        .setParameter("sig", sig).setParameter("id", scopeId).executeUpdate();
            }
        } catch (RuntimeException fatal) { rethrowIfFailClosed(fatal); }
    }

    private void stampScopeRoleAllowlistClient(KeycloakSession session, RealmModel realm, String mode,
                                               EntityManager em, IgaChangeRequestEntity cr) {
        try {
            String clientUuid = firstRowKey(cr, "CLIENT_UUID");
            if (clientUuid == null) return;
            ClientModel client = realm.getClientById(clientUuid);
            if (client == null) return;
            byte[] env = RealmAttestationExporter.scopeRoleAllowlistSet(
                    org.tidecloak.iga.producer.units.ParentType.client, client.getId(),
                    client, realm.getId()).serialize();
            String sig = signProducerEnvelope(session, realm, mode, env);
            em.createQuery("UPDATE ClientEntity e SET e.scopeRoleAllowlistAttestation = :sig WHERE e.id = :id")
                    .setParameter("sig", sig).setParameter("id", clientUuid).executeUpdate();
        } catch (RuntimeException fatal) { rethrowIfFailClosed(fatal); }
    }

    private void stampScopeRoleAllowlistScope(KeycloakSession session, RealmModel realm, String mode,
                                              EntityManager em, IgaChangeRequestEntity cr) {
        try {
            String scopeId = firstRowKey(cr, "SCOPE_ID");
            if (scopeId == null) return;
            ClientScopeModel scope = realm.getClientScopeById(scopeId);
            if (scope == null) return;
            byte[] env = RealmAttestationExporter.scopeRoleAllowlistSet(
                    org.tidecloak.iga.producer.units.ParentType.client_scope, scope.getId(),
                    scope, realm.getId()).serialize();
            String sig = signProducerEnvelope(session, realm, mode, env);
            em.createQuery("UPDATE ClientScopeEntity e SET e.scopeRoleAllowlistAttestation = :sig WHERE e.id = :id")
                    .setParameter("sig", sig).setParameter("id", scopeId).executeUpdate();
        } catch (RuntimeException fatal) { rethrowIfFailClosed(fatal); }
    }

    // ---- REALM-scoped stampers (forked RealmEntity fields in tidecloak-override) ----

    private void stampRealmConfig(KeycloakSession session, RealmModel realm, String mode,
                                  EntityManager em, IgaChangeRequestEntity cr) {
        try {
            byte[] env = RealmAttestationExporter.realmConfig(realm, realm.getId()).serialize();
            String sig = signProducerEnvelope(session, realm, mode, env);
            em.createQuery("UPDATE RealmEntity e SET e.realmConfigAttestation = :sig WHERE e.id = :id")
                    .setParameter("sig", sig).setParameter("id", realm.getId()).executeUpdate();
        } catch (RuntimeException fatal) { rethrowIfFailClosed(fatal); }
    }

    private void stampRealmDefaultGroupsSet(KeycloakSession session, RealmModel realm, String mode,
                                            EntityManager em, IgaChangeRequestEntity cr) {
        try {
            byte[] env = RealmAttestationExporter.realmDefaultGroupsSetStatic(realm, realm.getId()).serialize();
            String sig = signProducerEnvelope(session, realm, mode, env);
            em.createQuery("UPDATE RealmEntity e SET e.realmDefaultGroupsAttestation = :sig WHERE e.id = :id")
                    .setParameter("sig", sig).setParameter("id", realm.getId()).executeUpdate();
        } catch (RuntimeException fatal) { rethrowIfFailClosed(fatal); }
    }

    private void stampOrgDomainSet(KeycloakSession session, RealmModel realm, String mode,
                                   EntityManager em, IgaChangeRequestEntity cr) {
        try {
            String orgId = firstRowKey(cr, "ORG_ID");
            if (orgId == null) return;
            org.keycloak.organization.OrganizationProvider orgs =
                    session.getProvider(org.keycloak.organization.OrganizationProvider.class);
            if (orgs == null) return;
            OrganizationModel org = orgs.getById(orgId);
            if (org == null) return;
            byte[] env = RealmAttestationExporter.organizationDomainSet(org, realm.getId()).serialize();
            String sig = signProducerEnvelope(session, realm, mode, env);
            em.createQuery("UPDATE OrganizationEntity e SET e.orgDomainAttestation = :sig WHERE e.id = :id")
                    .setParameter("sig", sig).setParameter("id", orgId).executeUpdate();
        } catch (RuntimeException fatal) { rethrowIfFailClosed(fatal); }
    }

    // ---- small helpers for the stampers ----

    /** Re-throw only the fail-closed VVK ceremony failures; swallow build/lookup misses. */
    private static void rethrowIfFailClosed(RuntimeException e) {
        String m = e.getMessage();
        if (m != null && m.startsWith("IGA unit-column stamp: VVK ceremony failed")) {
            throw e;
        }
        log.warnf(e, "IGA unit-column stamp: skipped a per-unit-type column stamp (%s)", m);
    }

    /** The first row's value for {@code primary}, falling back to {@code secondary}, or null. */
    private static String firstRowKeyOr(IgaChangeRequestEntity cr, String primary, String secondary) {
        String v = firstRowKey(cr, primary);
        return v != null ? v : firstRowKey(cr, secondary);
    }

    /** The first row's value for {@code key}, or null. */
    private static String firstRowKey(IgaChangeRequestEntity cr, String key) {
        List<Map<String, Object>> rows = parseRows(cr.getRowsJson());
        for (Map<String, Object> row : rows) {
            String v = str(row, key);
            if (v != null) return v;
        }
        return null;
    }

    /** Resolve the client a CREATE_CLIENT / SET_CLIENT_ATTRIBUTE / web-origins CR targets. */
    private static ClientModel resolveClientForStamp(RealmModel realm, IgaChangeRequestEntity cr) {
        // CREATE_CLIENT carries ID (own UUID); attribute/web-origins CRs carry CLIENT_UUID.
        String uuid = firstRowKey(cr, "ID");
        if (uuid == null) uuid = firstRowKey(cr, "CLIENT_UUID");
        return uuid == null ? null : realm.getClientById(uuid);
    }

    /**
     * Build the {@link SignRequestSettingsMidgard} from the realm's
     * {@code tide-vendor-key} config — the iga-core port of
     * {@code VendorResource.ConstructSignSettings}, with the {@code activeVrk}
     * sourced from the {@code clientSecret} {@link SecretKeys} blob (as
     * {@code IGAUtils.signInitialTideAdmin} does). {@code THRESHOLD_T}/{@code THRESHOLD_N}
     * come from env vars; a missing/zero value is fatal (the ORK ceremony is
     * undefined without a real threshold).
     */
    public static SignRequestSettingsMidgard constructSignSettings(MultivaluedHashMap<String, String> config)
            throws Exception {
        String clientSecret = config.getFirst(CFG_CLIENT_SECRET);
        if (clientSecret == null || clientSecret.isBlank()) {
            throw new RuntimeException("IGA firstAdmin sign: tide-vendor-key component has no clientSecret "
                    + "(no activeVrk to sign with)");
        }
        SecretKeys secretKeys = MAPPER.readValue(clientSecret, SecretKeys.class);
        if (secretKeys.activeVrk == null || secretKeys.activeVrk.isBlank()) {
            throw new RuntimeException("IGA firstAdmin sign: clientSecret carries no activeVrk");
        }

        String tEnv = System.getenv(ENV_THRESHOLD_T);
        String nEnv = System.getenv(ENV_THRESHOLD_N);
        int threshold = (tEnv == null || tEnv.isBlank()) ? 0 : Integer.parseInt(tEnv);
        int max = (nEnv == null || nEnv.isBlank()) ? 0 : Integer.parseInt(nEnv);
        if (threshold == 0 || max == 0) {
            throw new RuntimeException("IGA firstAdmin sign: signing-threshold env vars not set "
                    + "(THRESHOLD_T=" + threshold + ", THRESHOLD_N=" + max + ")");
        }

        SignRequestSettingsMidgard settings = new SignRequestSettingsMidgard();
        settings.VVKId = config.getFirst(CFG_VVK_ID);
        settings.HomeOrkUrl = config.getFirst(CFG_HOME_ORK);
        settings.PayerPublicKey = config.getFirst(CFG_PAYER_PUBLIC);
        settings.ObfuscatedVendorPublicKey = config.getFirst(CFG_OBF_GVVK);
        settings.VendorRotatingPrivateKey = secretKeys.activeVrk;
        settings.Threshold_T = threshold;
        settings.Threshold_N = max;
        return settings;
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
