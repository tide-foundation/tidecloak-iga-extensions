package org.tidecloak.iga.services;

import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.tidecloak.iga.attestors.TideAttestor;
import org.tidecloak.iga.producer.ExportRequest;
import org.tidecloak.iga.producer.RealmAttestationExporter;
import org.tidecloak.iga.producer.spi.UnitColumnMapping;
import org.tidecloak.iga.producer.units.AttestationUnit;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Uniform Design B (PR-B) — the toggle-on / ADOPT full-closure signing backfill.
 *
 * <p>Run after the OFF→ON {@link IgaAdoptScan} (firstAdmin mode, pack ALIVE,
 * pre-flip). It signs EVERY producer attestation unit for the realm with the
 * firstAdmin VVK pack and stamps the real {@code TIDE-FIRSTADMIN-v1:}+b64(64-byte
 * VVK sig) onto that unit's dedicated column (the PR-A / PR-A.2 per-unit-type
 * columns), via the shared {@link UnitColumnMapping}.
 *
 * <h2>Why a backfill exists</h2>
 * Before PR-B the login read was HYBRID: it replayed only {@code user_role_mapping_set}
 * from its column and RE-SIGNED every other unit at login. PR-B flips the read to
 * uniform replay-from-column (no re-sign), so post-flip login NEVER touches the
 * firstAdmin pack (which is burned at the multiAdmin flip). For the read to succeed,
 * every unit a login emits must already carry a real column sig — including the
 * provisioning / no-CR units that no admin action ever signed: realm_config, built-in
 * roles + their composites, the derived mapper / allowlist / assignment sets, default
 * scopes / groups, and every pre-existing enabled user's identity / role / group sets.
 * This backfill closes that gap once, while the firstAdmin pack is still alive.
 *
 * <h2>Enumeration — the EXACT login closure, reusing the producer</h2>
 * The login read is all-or-nothing, so the backfill must enumerate precisely the unit
 * set the login emits. It does so in TWO membership-orthogonal phases, both through the
 * SAME {@link RealmAttestationExporter} the login uses (so the bytes cannot drift):
 * <ul>
 *   <li><b>FULL REALM METADATA (membership-INDEPENDENT) —
 *       {@link RealmAttestationExporter#exportRealmMetadata}.</b> Enumerates EVERY
 *       metadata unit the realm owns regardless of current membership: all roles
 *       (realm + every client's, INCLUDING {@code tide-realm-admin}, {@code realm-admin}
 *       and the {@code realm-management} system composites) -> {@code role_definition}
 *       + {@code role_composite_children_set}; all client scopes -> config / mapper-set /
 *       allowlist / protocol_mappers; all clients -> config / mapper-set /
 *       scope-assignment / allowlist / protocol_mappers; the realm -> {@code realm_config}
 *       + {@code realm_default_groups_set}; all groups -> definition / role-mapping; all
 *       orgs -> definition / domain-set. This signs the units NO current user surfaces,
 *       which is why a fresh realm's {@code tide-realm-admin -> realm-admin} composite (and
 *       all {@code realm-management} composites) are now signed BEFORE any user holds the
 *       role — so the multiAdmin-flip login finds its full closure already real.</li>
 *   <li><b>PER-USER membership (membership-DEPENDENT) — {@link RealmAttestationExporter#export}
 *       over the MAXIMAL request surface.</b> Emits the per-user units
 *       ({@code user_identity}, {@code user_role_mapping_set},
 *       {@code user_group_membership_set}) that are derived from each enabled user's own
 *       state; the metadata it re-surfaces is dedup'd against the metadata phase:</li>
 *   <li><b>per enabled user × per client</b> — covers every (client, user) login the
 *       realm can issue. Realm-state / config / role / scope / group / derived-set
 *       units are user-independent and dedup across these exports (idempotent stamp);
 *       per-user units (user_identity, user_role_mapping_set, user_group_membership_set)
 *       and per-group units (group_role_mapping_set) appear in the relevant user's
 *       export and are stamped there.</li>
 *   <li><b>scope = the union of every optional scope's name</b> — the producer only
 *       emits an optional scope's mapper/config closure when the scope is active
 *       (its name appears in the requested scope param). Activating ALL optional
 *       scopes makes each export emit the MAXIMAL scope closure, so any scope
 *       combination a real login requests is a subset of what the backfill signs.
 *       (The columns are keyed by entity id, not by scope, so a unit's bytes are the
 *       same whether or not its scope is active in a given request.)</li>
 * </ul>
 * Because BOTH this backfill and the login go through {@link RealmAttestationExporter}
 * + {@link UnitColumnMapping}, the set the backfill stamps and the set the login reads
 * cannot drift.
 *
 * <h2>Idempotency + gating</h2>
 * A unit is (re)signed only when its column is NULL or a non-replayable STUB (a sig
 * whose decoded body is not 64 bytes — e.g. the firstAdmin/policy 32-byte
 * {@code base64(sha256)} stub). An existing real 64-byte sig (e.g. one a prior
 * commit stamped) is NEVER clobbered. The whole pass is a no-op unless the realm is
 * {@link TideAttestor#isFirstAdminMode firstAdmin} AND
 * {@link TideAttestor#isRealSigningCapableRealm real-signing-capable}.
 */
public final class IgaToggleOnBackfill {

    private static final Logger log = Logger.getLogger(IgaToggleOnBackfill.class);

    private IgaToggleOnBackfill() {}

    /** Outcome of a backfill pass (surfaced in the toggle response + logs). */
    public static final class Result {
        public final boolean ran;
        public final String skipReason;   // null when ran
        public final int unitsSigned;     // units freshly stamped
        public final int unitsSkipped;    // units already carrying a real sig
        public final int usersCovered;
        public final int clientsCovered;

        Result(boolean ran, String skipReason, int unitsSigned, int unitsSkipped,
               int usersCovered, int clientsCovered) {
            this.ran = ran;
            this.skipReason = skipReason;
            this.unitsSigned = unitsSigned;
            this.unitsSkipped = unitsSkipped;
            this.usersCovered = usersCovered;
            this.clientsCovered = clientsCovered;
        }

        static Result skipped(String reason) {
            return new Result(false, reason, 0, 0, 0, 0);
        }
    }

    /**
     * Sign + stamp the full producer closure for {@code realm}. Fail-closed: a real
     * VVK ceremony failure propagates (a capable firstAdmin realm must NOT half-sign
     * and then flip its login read to uniform). Caller runs this inside the toggle-on
     * transaction (or its own job tx).
     */
    public static Result backfill(KeycloakSession session, RealmModel realm) {
        if (!TideAttestor.isFirstAdminMode(session, realm)) {
            log.debugf("IGA toggle-on backfill: realm %s not in firstAdmin mode — skipping "
                    + "(the uniform read only replays firstAdmin-pack sigs).", realm.getName());
            return Result.skipped("not_first_admin");
        }
        // GATE on PROVISIONED (realm-state only), NOT can-sign-now: a Tide-provisioned realm
        // ALWAYS runs the real backfill. If its ORKs are down or THRESHOLD_T/N is unset the
        // PHASE-2 signEnvelopesWithFirstAdminVvk → constructSignSettings THROWS (fail-loud,
        // propagated to the sweep job tx → rollback → CRs PENDING), instead of silently
        // skipping and leaving the closure stub-signed. Only a genuinely tideless/dev realm
        // (no firstAdmin VVK material) is NOT provisioned → skip + keep stub behaviour.
        if (!TideAttestor.isTideSigningProvisionedRealm(realm)) {
            log.infof("IGA toggle-on backfill: realm %s is not Tide-signing-provisioned (no firstAdmin "
                    + "VVK material) — skipping; columns stay NULL and the dev/test login keeps "
                    + "its stub behaviour.", realm.getName());
            return Result.skipped("not_tide_signing_provisioned");
        }

        session.getContext().setRealm(realm);
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        // Maximal scope string: every optional scope's NAME (default scopes are always
        // active). Activating all optional scopes makes each export emit the maximal
        // scope mapper/config closure, so any login's requested scope is a subset.
        List<ClientModel> clients = realm.getClientsStream().collect(Collectors.toList());
        String maxScope = maximalOptionalScopeString(clients);

        // Every ENABLED user — the per-user unit families (identity / role-set /
        // group-set) are stamped from each user's own export. Disabled users cannot
        // log in, so the login never emits their units; we skip them (matches the
        // login surface exactly).
        List<UserModel> users = session.users()
                .searchForUserStream(realm, java.util.Collections.emptyMap())
                .filter(UserModel::isEnabled)
                .collect(Collectors.toList());

        int skipped = 0;
        List<AttestationUnit> toSign = new ArrayList<>();
        // PHASE 1 - ENUMERATE + DEDUP. Walk every (user, client) export, COLLECTING the unique
        // units that still need a real sig (instead of signing each inline = one ORK round-trip
        // per unit). toSign[] order is the order sigs come back in (sig[i] maps to toSign.get(i)).
        // Dedup envelopes already processed this pass (same unit can appear in many
        // exports — realm/role/client units repeat across every user). Key = unit
        // type + target id; a real sign happens at most once per logical unit.
        Set<String> processed = new LinkedHashSet<>();

        // PHASE 1a - FULL REALM METADATA (membership-INDEPENDENT). Enumerate EVERY metadata
        // unit the realm owns - all roles (incl tide-realm-admin, realm-admin, the
        // realm-management system composites), all client scopes, all clients, all groups,
        // all orgs - regardless of which (if any) current user holds them. This is the ROOT
        // fix: the per-(user x client) export below only emits the metadata a CURRENT user's
        // token surfaces, so any role NO enabled user holds (tide-realm-admin and its
        // realm-management composite children) never got its role_composite_children_set /
        // role_definition signed -> the moment a user is granted tide-realm-admin and logs in,
        // the uniform read fail-closed on that NULL composite. Signing the full metadata
        // closure here, membership-independent, closes that gap. Built with the SAME producer
        // builders the login uses (RealmAttestationExporter), so the bytes are identical.
        List<AttestationUnit> metadataUnits =
                new RealmAttestationExporter().exportRealmMetadata(session, realm);
        for (AttestationUnit unit : metadataUnits) {
            String key = unit.type().name() + ' ' + unit.targetId();
            if (!processed.add(key)) {
                continue; // already handled this logical unit in this pass
            }
            String stored = UnitColumnMapping.readStored(em, unit);
            if (isRealReplayableSig(stored)) {
                skipped++;
                continue; // a real 64-byte sig is already present - never clobber
            }
            toSign.add(unit); // dedup'd, NULL-or-stub metadata column - needs a real sig
        }

        // PHASE 1b - PER-USER membership units (membership-DEPENDENT): user_identity,
        // user_role_mapping_set, user_group_membership_set (+ any metadata a user surfaces,
        // already covered + deduped by PHASE 1a). The per-(user x client) export is retained
        // because the per-user membership units are user-state-derived and only emitted by an
        // export for that user; the metadata units it re-emits are dedup'd against PHASE 1a.
        for (UserModel user : users) {
            for (ClientModel client : clients) {
                List<AttestationUnit> units;
                try {
                    units = new RealmAttestationExporter().export(session, realm,
                            ExportRequest.accessToken(client.getClientId(), user.getId(), maxScope));
                } catch (RuntimeException e) {
                    // A (client, user) combination the producer cannot build (e.g. a
                    // client a user could never get a token for) is not a login surface;
                    // log and continue. The login for a real (client, user) goes through
                    // the SAME export, so anything it CAN emit, this loop reaches.
                    log.debugf("IGA toggle-on backfill: export skipped for client=%s user=%s (%s)",
                            client.getClientId(), user.getId(), e.getMessage());
                    continue;
                }
                for (AttestationUnit unit : units) {
                    String key = unit.type().name() + ' ' + unit.targetId();
                    if (!processed.add(key)) {
                        continue; // already handled this logical unit in this pass
                    }
                    String stored = UnitColumnMapping.readStored(em, unit);
                    if (isRealReplayableSig(stored)) {
                        skipped++;
                        continue; // a real 64-byte sig is already present — never clobber
                    }
                    toSign.add(unit); // dedup'd, NULL-or-stub column - needs a real sig
                }
            }
        }

        // PHASE 2 - BATCH SIGN. Sign ALL unique envelopes in ONE (or, for a pathologically
        // large closure, a few chunked) Midgard.SignModel ORK round-trip(s): the ork returns
        // one VVK sig per unit in a single multi-unit AttestationUnit:1 request, instead of N
        // round-trips. Envelopes are the EXACT bytes each unit serializes (same wire shape the
        // login read replays); sig[i] is the firstAdmin sig over envelopes[i]. Fail-closed: a
        // real ceremony failure propagates (a capable firstAdmin realm must not half-sign then
        // flip its uniform read).
        byte[][] envelopes = new byte[toSign.size()][];
        for (int i = 0; i < toSign.size(); i++) {
            envelopes[i] = toSign.get(i).serialize();
        }
        String[] sigs = TideAttestor.signEnvelopesWithFirstAdminVvk(realm, envelopes);

        // PHASE 3 - DISTRIBUTE. Stamp sig[i] onto unit toSign.get(i)'s dedicated column(s).
        // The unit->sig mapping is preserved by index, so each unit gets the sig over its OWN
        // envelope. A unit with no owner row to stamp (entity/edge vanished mid-pass) is a
        // benign no-op - the login won't emit it either (same live model) - not a coverage hole.
        int signed = 0;
        for (int i = 0; i < toSign.size(); i++) {
            AttestationUnit unit = toSign.get(i);
            int rows = UnitColumnMapping.stamp(em, unit, sigs[i]);
            if (rows > 0) {
                signed++;
            } else {
                log.debugf("IGA toggle-on backfill: unit %s target %s had no row to stamp "
                        + "(skipped)", unit.type(), unit.targetId());
            }
        }

        log.infof("IGA toggle-on backfill complete for realm %s: signed=%d, alreadyReal=%d, "
                        + "users=%d, clients=%d, orkRoundTrips=%d", realm.getName(), signed, skipped,
                users.size(), clients.size(), (toSign.isEmpty() ? 0 : ((toSign.size() + 99) / 100)));
        return new Result(true, null, signed, skipped, users.size(), clients.size());
    }

    /**
     * Post-commit full-closure convergence — the ROOT-cause fix for the incomplete
     * hand-coded ADOPT stampers.
     *
     * <p>The per-CR {@code stampProducerUnitColumns} ADOPT cases hand-list each
     * adopted node's OWN small unit family, but that hand-listing is incomplete: a
     * login emits the ENTIRE producer closure (all 18 unit types), and units owned by
     * SYSTEM entities (e.g. {@code role_composite_children_set} on
     * {@code default-roles-<realm>} and the built-in admin clients' composite roles,
     * plus the protocol_mappers on KC default scopes / built-in clients) arrive via
     * the EDGE / attestation-only ADOPT CRs whose hand-coded path deliberately does
     * NOT stamp the owner's derived-set column (it assumes "the owning node's ADOPT CR
     * covers it" — which only holds for the subset of nodes whose own ADOPT CR was
     * emitted and whose stamper enumerates that set). The net effect was
     * {@code role_composite_children_set} (ALL still 32B {@code TIDE-DUMMY} stub) and
     * 23/39 {@code protocol_mapper} columns staying NULL/stub after a bulk-approve, so
     * the uniform login read fail-closed on {@code role_composite_children_set}.
     *
     * <p>Rather than patch each hand-listed case, this re-uses the PROVEN-COMPLETE
     * {@link #backfill} enumeration — the SAME producer-driven
     * {@link RealmAttestationExporter#export} -> {@code signEnvelopesWithFirstAdminVvk}
     * -> {@link UnitColumnMapping#stamp} closure the login read consumes — and runs it
     * ONCE after the admin's approval (single or bulk commit) leaves the realm
     * fully-adopted. Because the backfill enumerates the EXACT login surface (every
     * enabled user x client x maximal scope) and emits every unit those exports
     * produce — INCLUDING system units, since {@link RealmAttestationExporter#export}
     * does NOT apply {@code IgaSystemEntityFilter} — every login-emitted unit (all 18
     * types) is stamped REAL by construction, not by a hand-listed subset.
     *
     * <p><b>Partial-closure sign (2026-06-24): no fully-adopted gate.</b> We NO LONGER
     * defer the stamp while ADOPT_* CRs remain pending. On every commit (toggle sweep,
     * bulk-approve, or single-CR approve) this runs the closure stamp over whatever is
     * LIVE + COMMITTED right now: the {@link #backfill} enumeration walks the committed
     * model and is idempotent (signs only NULL/stub columns, no-ops a unit whose owner
     * row is absent), so an intentionally-held still-PENDING ADOPT entity is simply left
     * UNSIGNED — its login fail-closes PER-LOGIN-SURFACE (the read in
     * {@code IgaAttestationExporterProvider.exportSignedAccessTokenUnits} builds + checks
     * ONLY one {@code (client,user,scope)} login's closure), never blocking the sign of
     * the committed subset. As each held ADOPT is later approved/committed, that commit
     * re-fires this idempotent converge and incrementally signs the newly-committed
     * entity's units. The pass is firstAdmin+capable gated and fail-closed: only a
     * GENUINE VVK ceremony failure (ORK down / threshold / pack) propagates — a pending
     * ADOPT no longer short-circuits the closure sign.
     *
     * <p>Runs in the caller's commit JPA transaction (same {@code em}), so the stamps
     * land atomically with that commit. A no-op (returns {@link Result#skipped}) only
     * when the realm is not firstAdmin / not Tide-signing-provisioned (dev/test realms
     * keep their stub behaviour).
     *
     * @param session the commit session (realm context will be set on it)
     * @param realm   the realm whose ADOPT set was just (partly) committed
     * @return the {@link Result} of the (possibly partial) closure pass
     */
    public static Result convergeAfterCommit(KeycloakSession session, RealmModel realm) {
        // Cheap gate FIRST: if the realm is not a firstAdmin Tide-provisioned realm the whole
        // pass is a no-op anyway — skip the pending-ADOPT count query entirely. Provisioning
        // (a pure in-memory tide-vendor-key + activeVrk check, NO threshold env / NO ORK dial)
        // is evaluated before the firstAdmin-mode check (which reads realm state) so a
        // non-provisioned dev/test realm short-circuits without touching the DB. GATE on
        // PROVISIONED, NOT can-sign-now: a provisioned realm whose ORKs are down or whose
        // THRESHOLD env is unset still ENTERS backfill and FAILS LOUD at PHASE-2 sign (the
        // throw propagates to the sweep job tx → rollback → CRs PENDING), never stub-stubs.
        if (!TideAttestor.isTideSigningProvisionedRealm(realm)
                || !TideAttestor.isFirstAdminMode(session, realm)) {
            return Result.skipped("not_first_admin_or_not_provisioned");
        }
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        long pendingAdopt = em.createQuery(
                        "SELECT COUNT(cr) FROM IgaChangeRequestEntity cr "
                                + "WHERE cr.realmId = :realmId AND cr.status = 'PENDING' "
                                + "AND cr.actionType IN :adoptTypes", Long.class)
                .setParameter("realmId", realm.getId())
                .setParameter("adoptTypes",
                        org.tidecloak.iga.replay.IgaReplayExtension.ALL_ADOPT_ACTION_TYPES)
                .getSingleResult();
        // PARTIAL-CLOSURE SIGN (2026-06-24): we DO NOT defer the closure stamp while ADOPT
        // CRs remain pending. The backfill enumerates the LIVE COMMITTED model and is
        // idempotent — it signs only NULL/stub columns and no-ops a unit whose owner row is
        // absent (IgaToggleOnBackfill.backfill PHASE 1b try/catch + PHASE 3 rows==0 skip), so
        // an intentionally-held (still-PENDING) ADOPT entity is simply left UNSIGNED and its
        // login fail-closes PER-LOGIN-SURFACE (IgaAttestationExporterProvider
        // .exportSignedAccessTokenUnits builds + reads ONLY one (client,user,scope) login's
        // closure), never blocking the committed subset. Already-committed entities get their
        // real 64B VVK sig at toggle; a held ADOPT later approved/committed re-fires this
        // converge (idempotent), incrementally completing the closure. The ONLY remaining
        // throw is a GENUINE ORK ceremony failure at PHASE 2 (fail-loud → rollback → PENDING);
        // a pending ADOPT no longer short-circuits the sign of everything else.
        if (pendingAdopt > 0) {
            log.infof("IGA post-commit convergence: realm %s has %d ADOPT CR(s) still PENDING — "
                    + "signing the COMMITTED-model closure subset now (partial); the pending "
                    + "entities are left unsigned and their logins fail-closed until approved, "
                    + "each later approve/commit re-fires this idempotent converge.",
                    realm.getName(), pendingAdopt);
        } else {
            log.infof("IGA post-commit convergence: realm %s ADOPT set fully approved — running the "
                    + "producer-driven full-closure stamp so EVERY login-emitted unit carries a real "
                    + "64B sig (covers composite_role + protocol_mapper + all 18 types).", realm.getName());
        }
        return backfill(session, realm);
    }

    /**
     * Is {@code stored} a real replayable firstAdmin envelope sig? Mirrors
     * {@code IgaAttestationExporterProvider.decodeReplayableSig}: a
     * {@code TIDE-FIRSTADMIN-v1:}+b64 string whose decoded body is EXACTLY 64 bytes.
     * A null / blank / wrong-prefix / 32-byte-stub value is NOT real → (re)sign.
     */
    static boolean isRealReplayableSig(String stored) {
        if (stored == null || stored.isBlank()) {
            return false;
        }
        if (!stored.startsWith(TideAttestor.FIRSTADMIN_SIG_PREFIX)) {
            return false;
        }
        String b64 = stored.substring(TideAttestor.FIRSTADMIN_SIG_PREFIX.length());
        try {
            return java.util.Base64.getDecoder().decode(b64).length == 64;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * The whitespace-joined union of every client's OPTIONAL client-scope NAMES.
     * Passing this as the requested scope makes the producer treat every optional
     * scope as active, emitting the maximal scope closure. Default scopes are always
     * active regardless, so they need not appear here.
     */
    static String maximalOptionalScopeString(List<ClientModel> clients) {
        Set<String> names = new LinkedHashSet<>();
        for (ClientModel c : clients) {
            for (ClientScopeModel s : c.getClientScopes(false).values()) {
                if (s.getName() != null) {
                    names.add(s.getName());
                }
            }
        }
        return String.join(" ", new ArrayList<>(names));
    }
}
