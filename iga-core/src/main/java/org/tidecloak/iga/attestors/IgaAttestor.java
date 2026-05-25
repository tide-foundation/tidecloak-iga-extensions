package org.tidecloak.iga.attestors;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.Provider;
import org.tidecloak.iga.entities.IgaAuthorizationEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;

import java.util.List;

/**
 * SPI for pluggable IGA approval/attestation mechanisms.
 *
 * Implementations record one admin's authorization on a change request and,
 * once the threshold is met, combine all authorizations into a final attestation
 * string that is written to the ATTESTATION column on commit.
 */
public interface IgaAttestor extends Provider {

    /** Identifier matching the corresponding factory id. */
    String getId();

    /**
     * Validate the admin can approve the given change request and persist the
     * authorization record. Implementations MUST consult any scope-based
     * approval policies attached to the entities affected by the CR
     * (see {@link IgaScopeResolver}) and throw a JAX-RS
     * {@link jakarta.ws.rs.ForbiddenException} when the admin lacks the
     * required approver role(s).
     *
     * @param session            Keycloak session
     * @param cr                 the change request being authorized
     * @param admin              the authorizing admin user
     * @param attestationPayload free-form input from caller (partial sig, "" or null for simple)
     * @return the persisted authorization entity
     */
    IgaAuthorizationEntity record(KeycloakSession session,
                                  IgaChangeRequestEntity cr,
                                  UserModel admin,
                                  String attestationPayload);

    /**
     * Once threshold met, produce the final string to write to the ATTESTATION column.
     */
    String combineFinal(KeycloakSession session,
                        IgaChangeRequestEntity cr,
                        List<IgaAuthorizationEntity> authorizations);

    /**
     * Threshold for THIS specific change request. Implementations consult
     * scope policies attached to the affected entities and the realm fallback
     * attribute {@code iga.threshold}.
     */
    int getThreshold(KeycloakSession session, RealmModel realm, IgaChangeRequestEntity cr);

    /**
     * Whether this attestor uses the per-(table, owner) SET-SIGNING model for
     * LINKAGE tables. When {@code true}, the replay dispatcher fans the final
     * attestation out across the WHOLE owner set (every row sharing the owner
     * key) rather than stamping only the single changed row. When {@code false}
     * (the default), the dispatcher keeps today's exact per-row / per-entity
     * stamp — Tideless ({@code simple}) realms MUST observe byte-identical
     * behaviour to before this SPI method existed.
     *
     * <p>This gating is the contract that lets a set-signing attestor coexist
     * with the per-row attestors without changing the per-row code path.
     */
    default boolean isSetSigned() {
        return false;
    }
}
