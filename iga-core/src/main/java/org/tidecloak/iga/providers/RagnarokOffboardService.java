package org.tidecloak.iga.providers;

import jakarta.persistence.EntityManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.Provider;

/**
 * SPI provider that runs the real Ragnarok realm-offboard teardown when a
 * governed {@code OFFBOARD_REALM} change request commits.
 *
 * <h2>Ownership split</h2>
 * <ul>
 *   <li><b>iga-core</b> (this module) only <em>defines</em> the SPI and
 *       <em>looks it up</em> at commit-replay time
 *       ({@code session.getProvider(RagnarokOffboardService.class)}). iga-core
 *       provides NO implementation and MUST NOT depend on ragnarok.</li>
 *   <li><b>ragnarok</b> depends on this iga-core artifact, implements this
 *       interface (plus a {@code ProviderFactory} + {@code META-INF/services}
 *       registration), and ships the real teardown. iga-core resolves it by
 *       type at runtime.</li>
 * </ul>
 *
 * <h2>Contract</h2>
 * The implementation runs the <b>full offboard inside the supplied replay
 * transaction</b> (the {@link EntityManager} is the replay tx's EM, and the
 * session has {@code IGA_REPLAY_ACTIVE=true} so model writes pass straight
 * through the IGA capture wrappers). It MUST be:
 * <ul>
 *   <li><b>offboard-last</b> — the CR's other commit-tail steps (status flip)
 *       run after this returns; the teardown itself should be the terminal
 *       mutation of the realm;</li>
 *   <li><b>idempotent</b> — a committable-retry after a transient failure must
 *       converge to the same end state;</li>
 *   <li><b>fail-closed</b> — on any failure throw
 *       {@link RagnarokOffboardException} so the replay tx rolls back and the CR
 *       stays committable-retry. Never swallow a failure and return success.</li>
 * </ul>
 *
 * @see org.tidecloak.iga.replay.IgaReplayDispatcher
 */
public interface RagnarokOffboardService extends Provider {

    /**
     * <b>Phase-1</b> of the OFFBOARD_REALM admin-quorum ceremony: build the
     * vendor-initialized {@code Offboard:1} approval carrier that iga-core
     * accumulates admin dokens into.
     *
     * <h3>Why ragnarok owns this</h3>
     * The {@code OFFBOARD_REALM} CR is NON-producer (its own CR attestation is
     * stub-signed — there is no {@code AttestationUnit} producer envelope to frame).
     * But the destructive {@code Midgard.Offboard} ORK ceremony the SPI runs at
     * commit DOES require a quorum of admin dokens. iga-core therefore needs a
     * real doken-bearing carrier to collect those dokens into — and only ragnarok
     * knows the {@code Offboard:1} request shape. iga-core calls this once on the
     * FIRST open of the approval popup (no recorded approvals), persists the
     * returned Base64 on the CR's {@code REQUEST_MODEL}, and the two-phase enclave
     * approval ({@code AddPolicyAuthorizationToSerializedRequest}) appends each
     * admin's doken onto it; the accumulated carrier is handed back to
     * {@link #offboardRealm} at commit.
     *
     * <h3>Implementation contract (mirror {@code RagnarokSettingProcessor.saveDraftReq})</h3>
     * <ul>
     *   <li>Build a {@code ModelRequest.New("Offboard","1","Policy:1",
     *       Tools.CreateTideMemory(gVRK, gVRKCertificate))} and
     *       {@code InitializeTideRequestWithVrk("Offboard:1")} so the carrier
     *       carries the seg-7 vendor creation-auth (the enclave's "approved
     *       initially by the vendor" check).</li>
     *   <li>Set a <b>long</b> expiry (admins sign asynchronously over hours/days;
     *       a short window expires the carrier mid-approval → "Expiry cannot be in
     *       the past"). iga-core uses a 7-day window for its other carriers; the SPI
     *       MUST set at least as long an expiry.</li>
     *   <li>Return {@code Base64(request.Encode())}.</li>
     * </ul>
     *
     * @param session the {@link KeycloakSession} (realm bound on the context)
     * @param realm   the realm an offboard is being proposed for
     * @return the Base64 of a vendor-initialized {@code Offboard:1} {@code ModelRequest}
     *         (the enclave appends admin dokens to it; long expiry)
     * @throws RagnarokOffboardException if the carrier cannot be built (e.g. the
     *         realm has no VRK material) — fail-closed: an offboard can never be
     *         approved without a real {@code Offboard:1} carrier to collect dokens.
     */
    String buildOffboardApprovalCarrier(KeycloakSession session, RealmModel realm)
            throws RagnarokOffboardException;

    /**
     * <b>Commit</b> of the OFFBOARD_REALM ceremony: run the full Ragnarok offboard
     * for {@code realm} inside the supplied (replay) transaction, using the
     * accumulated admin dokens. Offboard-last + idempotent.
     *
     * <p>The implementation does
     * {@code Midgard.Offboard(settings, ModelRequest.FromBytes(dokenCarrier), eVVK)}
     * with the collected dokens, then the local realm teardown.
     *
     * @param session         the replay {@link KeycloakSession} ({@code IGA_REPLAY_ACTIVE}
     *                        is set; realm is bound on the context)
     * @param realm           the realm being offboarded
     * @param em              the replay transaction's {@link EntityManager}
     * @param dokenCarrierB64 the CR's accumulated {@code REQUEST_MODEL} — the
     *                        {@code Offboard:1} carrier {@link #buildOffboardApprovalCarrier}
     *                        seeded, now bearing every approving admin's doken. Never
     *                        blank for a committed offboard (iga-core fail-closes if it is).
     * @return a {@link RagnarokOffboardResult} summarising the teardown
     * @throws RagnarokOffboardException if the teardown cannot complete — rolls
     *                                   back the replay tx (nothing torn down)
     */
    RagnarokOffboardResult offboardRealm(KeycloakSession session, RealmModel realm, EntityManager em,
                                         String dokenCarrierB64)
            throws RagnarokOffboardException;
}
