package org.tidecloak.iga.attestors;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.tidecloak.iga.entities.IgaAuthorizationEntity;
import org.tidecloak.iga.entities.IgaAuthorizerEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
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
     */
    private String resolveMode(KeycloakSession session, RealmModel realm) {
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
     * SET-SIGNING core. Resolve (table, owner) from the CR, gather the owner's
     * POST-change set, canonicalize it deterministically, and sign it once via
     * the single {@link #sign(byte[])} swap-point. For NODE creates the "set" is
     * the single entity's own canonical state.
     */
    @Override
    public String combineFinal(KeycloakSession session,
                               IgaChangeRequestEntity cr,
                               List<IgaAuthorizationEntity> authorizations) {
        String actionType = cr.getActionType();
        List<Map<String, Object>> rows = parseRows(cr.getRowsJson());

        TideSetResolver.Linkage linkage = TideSetResolver.linkageFor(actionType);
        byte[] canonical;
        if (linkage != null) {
            // LINKAGE: sign the owner's POST-change member set. (rows may span
            // more than one owner for a multi-row CR — we sign the union keyed
            // by owner so every affected owner's set commits to the same final
            // string; the dispatcher fans out per owner.)
            canonical = canonicalizeLinkageSet(session, cr, linkage, rows, actionType);
        } else {
            // NODE / non-linkage: per-entity — sign the entity's own canonical
            // state, exactly the single-row scope the per-row attestor stamps.
            canonical = canonicalizeNode(cr, rows);
        }
        return sign(canonical);
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
     * Sign the canonical bytes of a set (or node state).
     *
     * <p>DUMMY: returns {@code "TIDE-DUMMY-v1:" + base64(sha256(canonical))} — a
     * deterministic, clearly-marked stub so the full set-signing mechanism is
     * runnable and testable end to end. Determinism (same set → same sig) is
     * exactly what the set-signing model relies on.
     *
     * <p>TODO: replace with Midgard signClaims() — single crypto swap-point.
     */
    private String sign(byte[] canonical) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(canonical);
            return DUMMY_SIG_PREFIX + java.util.Base64.getEncoder().encodeToString(digest);
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
