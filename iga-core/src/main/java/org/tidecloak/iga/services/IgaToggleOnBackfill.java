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
 * set the login emits. It does so by invoking the SAME
 * {@link RealmAttestationExporter#export} the login uses, over the MAXIMAL request
 * surface:
 * <ul>
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
        if (!TideAttestor.isRealSigningCapableRealm(realm)) {
            log.infof("IGA toggle-on backfill: realm %s is not real-signing-capable (no firstAdmin "
                    + "VVK material) — skipping; columns stay NULL and the dev/test login keeps "
                    + "its stub behaviour.", realm.getName());
            return Result.skipped("not_real_signing_capable");
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

        int signed = 0;
        int skipped = 0;
        // Dedup envelopes already processed this pass (same unit can appear in many
        // exports — realm/role/client units repeat across every user). Key = unit
        // type + target id; a real sign happens at most once per logical unit.
        Set<String> processed = new LinkedHashSet<>();

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
                    // Sign the EXACT producer envelope with the firstAdmin pack and stamp
                    // every owner row. Fail-closed inside signEnvelopeWithFirstAdminVvk.
                    byte[] envelope = unit.serialize();
                    String sig = TideAttestor.signEnvelopeWithFirstAdminVvk(realm, envelope);
                    int rows = UnitColumnMapping.stamp(em, unit, sig);
                    if (rows > 0) {
                        signed++;
                    } else {
                        // No owner row to stamp (entity/edge vanished mid-pass). The login
                        // won't emit this unit either (it builds from the same live model),
                        // so this is a benign no-op, not a coverage hole.
                        log.debugf("IGA toggle-on backfill: unit %s target %s had no row to stamp "
                                + "(skipped)", unit.type(), unit.targetId());
                    }
                }
            }
        }

        log.infof("IGA toggle-on backfill complete for realm %s: signed=%d, alreadyReal=%d, "
                        + "users=%d, clients=%d", realm.getName(), signed, skipped, users.size(),
                clients.size());
        return new Result(true, null, signed, skipped, users.size(), clients.size());
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
