package org.tidecloak.iga.producer;

import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.producer.units.AttestationUnit;
import org.tidecloak.iga.replay.IgaReplayDispatcher;

import java.util.ArrayList;
import java.util.List;

/**
 * ★ P4 — the generalized scratch-replay unit enumerator.
 *
 * <p>This is the generalization of {@link IgaCreateUnitBuilder} (the CREATE_*-only
 * from-REP_JSON node builder) to ALL actionTypes. Instead of hand-coding a per-type
 * {@code pre±delta} for SET_* / UPDATE_* / ASSIGN / SCOPE_MAPPING / PROTOCOL_MAPPER /
 * REALM / ORG, it replays the WHOLE change request in a nested rolled-back
 * {@code runJobInTransaction} ({@code IGA_REPLAY_ACTIVE=true}) — the SAME
 * {@link IgaReplayDispatcher#replay} entry the real commit uses — and then enumerates
 * EVERY producer {@link AttestationUnit} that CR affects from the now-POST-change scratch
 * model via the SAME {@link RealmAttestationExporter} builders the post-replay stampers
 * use, then ROLLS BACK so the scratch mutation never persists.
 *
 * <h2>★ Byte-identity (the load-bearing invariant)</h2>
 * Because the scratch tx runs the IDENTICAL {@code IgaReplayDispatcher.replay} the real
 * commit runs, the post-change scratch model is bit-for-bit the same model the post-replay
 * stamper reads at commit time — so the unit envelopes the phase-1 carrier frames here equal
 * the bytes the commit-time {@code distributeMultiAdminUnitSigs} stamps (and the login read
 * re-derives), for ALL actionTypes, by construction. The enumeration step itself is shared
 * verbatim between this phase-1 path and the commit path (the {@code enumerator} callback is
 * {@code TideAttestor#enumerateLiveCrUnits}, called over the live model at commit and over
 * the scratch model here), so framing and distribution CANNOT drift.
 *
 * <h2>Side-effect containment</h2>
 * The full replay can mutate more than a CREATE rebuild (attribute writes, edge
 * inserts/deletes, realm-config columns, org changes). It is contained two ways:
 * <ol>
 *   <li>{@code IGA_REPLAY_ACTIVE=true} is set on the scratch session, so the replayed
 *       model ops pass straight through the IGA capture wrappers (no new CRs / quarantine
 *       churn are emitted for the probe).</li>
 *   <li>{@code setRollbackOnly()} is called on the scratch tx BEFORE it can commit, so
 *       NOTHING the replay wrote (model rows, the CR's own {@code STATUS=APPROVED} flip,
 *       cache evictions bound to the scratch session) persists. The probe is read-only
 *       w.r.t. the durable store.</li>
 * </ol>
 * The enumerated units are self-contained: each {@link RealmAttestationExporter} builder
 * snapshots the model's values into the unit's {@code final} fields at construction (it holds
 * no live-entity / session references), so the returned list survives the scratch session
 * being torn down — its {@code serialize()} bytes and {@code type()}/{@code targetId()} are
 * already materialized.
 */
public final class IgaScratchUnitBuilder {

    private static final Logger log = Logger.getLogger(IgaScratchUnitBuilder.class);

    private IgaScratchUnitBuilder() {}

    /**
     * The shared enumeration callback: "given a POST-change live model (the {@code session}
     * + {@code realm} + {@code em} reflect the CR already applied), build EVERY producer
     * {@link AttestationUnit} this CR touches, in deterministic order". Implemented ONCE by
     * {@code TideAttestor#enumerateLiveCrUnits} and called by BOTH the commit path (live
     * model) and this scratch-replay path (scratch model) — so the two cannot diverge.
     */
    @FunctionalInterface
    public interface LiveUnitEnumerator {
        List<AttestationUnit> enumerate(KeycloakSession session, RealmModel realm,
                                        EntityManager em, IgaChangeRequestEntity cr);
    }

    /**
     * Replay the WHOLE CR in a scratch rolled-back transaction, then enumerate every producer
     * unit it affects from the post-change scratch model via the shared {@code enumerator},
     * and roll back. Returns the ordered list of detached {@link AttestationUnit}s (re-framed
     * from their serialized CBOR so they survive the scratch session teardown). Never returns
     * {@code null}; an empty list means the CR frames no producer unit.
     *
     * @throws RuntimeException (fail-closed) if the scratch replay throws — a byte-mismatch
     *         must never be shipped silently (we would rather fail the phase-1 framing than
     *         frame bytes that don't match what the commit will stamp).
     */
    public static List<AttestationUnit> unitsFromScratchReplay(KeycloakSession session,
                                                               RealmModel realm,
                                                               IgaChangeRequestEntity cr,
                                                               LiveUnitEnumerator enumerator) {
        final String realmId = realm.getId();
        final List<AttestationUnit> collected = new ArrayList<>();

        KeycloakModelUtils.runJobInTransaction(session.getKeycloakSessionFactory(), scratch -> {
            // IGA_REPLAY_ACTIVE is ALSO set internally by IgaReplayDispatcher.replay; we set
            // it here too so any enumeration read that goes through an IGA wrapper passes
            // through, and so the flag is present for the whole scratch lifetime.
            scratch.setAttribute("IGA_REPLAY_ACTIVE", "true");
            try {
                RealmModel scratchRealm = scratch.realms().getRealm(realmId);
                if (scratchRealm == null) {
                    throw new IllegalStateException(
                            "scratch-replay: realm " + realmId + " not loadable in scratch session");
                }
                // Bind the realm context on the nested scratch session BEFORE any user/entity
                // enumeration. Without this, the scratch session's context realm is null, so
                // user-storage reads (session.users().getUserById → validateUser →
                // isReadOnlyOrganizationMember → OrganizationProvider.getRealm() reading
                // scratch.getContext().getRealm()) throw "Session not bound to a realm".
                // Same class of fix as the startup backfillTideClaimsScope NPE. The scratch tx
                // is rolled back below, so restoring the prior (null) context is unnecessary.
                scratch.getContext().setRealm(scratchRealm);
                EntityManager em = scratch.getProvider(JpaConnectionProvider.class).getEntityManager();

                // Re-load the CR in the scratch persistence context so the replay's
                // STATUS=APPROVED flip (rolled back below) targets a managed scratch entity.
                IgaChangeRequestEntity scratchCr = em.find(IgaChangeRequestEntity.class, cr.getId());
                IgaChangeRequestEntity replayCr = scratchCr != null ? scratchCr : cr;

                // ★ Run the SAME full replay the real commit runs — applies the rep/delta to
                // the live scratch model for ANY actionType (CREATE / SET / UPDATE / ASSIGN /
                // SCOPE_MAPPING / PROTOCOL_MAPPER / REALM / ORG). The finalAttestation passed
                // here is a throwaway probe marker; it is stamped onto scratch rows that are
                // immediately rolled back, and it never reaches the enumerated unit ENVELOPES
                // (those are rebuilt from the model, not from the attestation columns).
                IgaReplayDispatcher.replay(scratch, replayCr, SCRATCH_PROBE_ATTESTATION,
                        /* setSigned (irrelevant for the probe — we re-enumerate the model) */ false);

                // IgaReplayDispatcher.replay removes IGA_REPLAY_ACTIVE in its own finally; the
                // enumeration below is read-only (no mutation → no capture), but re-assert the
                // flag so any read that routes through an IGA wrapper passes straight through.
                scratch.setAttribute("IGA_REPLAY_ACTIVE", "true");

                // Now the scratch model is POST-change. Enumerate via the shared helper.
                List<AttestationUnit> units = enumerator.enumerate(scratch, scratchRealm, em, replayCr);
                if (units != null) {
                    for (AttestationUnit u : units) {
                        if (u != null) {
                            // Each unit snapshots its model values into final fields at build
                            // time (no live-entity / scratch-session references), so it survives
                            // the scratch session teardown — its serialize() bytes and
                            // type()/targetId() are already materialized.
                            collected.add(u);
                        }
                    }
                }
            } finally {
                // The scratch mutation must NEVER persist — set rollback-only inside the SAME
                // tx, AFTER the enumeration read, BEFORE the job commits.
                scratch.getTransactionManager().setRollbackOnly();
                scratch.removeAttribute("IGA_REPLAY_ACTIVE");
            }
        });

        log.debugf("IgaScratchUnitBuilder: scratch-replay enumerated %d producer unit(s) for %s CR %s",
                collected.size(), cr.getActionType(), cr.getId());
        return collected;
    }

    /**
     * A throwaway attestation marker stamped onto scratch rows by the replay; immediately
     * rolled back. It is NEVER read back into a framed unit envelope (the enumerator rebuilds
     * units from the model, not from the {@code ATTESTATION} columns), so its value is inert.
     */
    private static final String SCRATCH_PROBE_ATTESTATION = "IGA-SCRATCH-PROBE";
}
