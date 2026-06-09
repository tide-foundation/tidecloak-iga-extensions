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
     * Run the full Ragnarok offboard for {@code realm} inside the supplied
     * (replay) transaction. Offboard-last + idempotent.
     *
     * @param session the replay {@link KeycloakSession} ({@code IGA_REPLAY_ACTIVE}
     *                is set; realm is bound on the context)
     * @param realm   the realm being offboarded
     * @param em      the replay transaction's {@link EntityManager}
     * @return a {@link RagnarokOffboardResult} summarising the teardown
     * @throws RagnarokOffboardException if the teardown cannot complete — rolls
     *                                   back the replay tx (nothing torn down)
     */
    RagnarokOffboardResult offboardRealm(KeycloakSession session, RealmModel realm, EntityManager em)
            throws RagnarokOffboardException;
}
