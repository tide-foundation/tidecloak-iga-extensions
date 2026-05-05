package org.tidecloak.iga.signers;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.Provider;
import org.tidecloak.iga.entities.IgaAuthorizationEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;

import java.util.List;

/**
 * SPI for pluggable IGA approval/signing mechanisms.
 *
 * Implementations record one admin's authorization on a change request and,
 * once the threshold is met, combine all authorizations into a final signature
 * string that is written to the SIGNATURE column on commit.
 */
public interface IgaSigner extends Provider {

    /** Identifier matching the corresponding factory id. */
    String getId();

    /**
     * Record one admin's authorization on a change request.
     *
     * @param session          Keycloak session
     * @param cr               the change request being authorized
     * @param admin            the authorizing admin user
     * @param signaturePayload free-form input from caller (partial sig, "" or null for simple)
     * @return the persisted authorization entity
     */
    IgaAuthorizationEntity record(KeycloakSession session,
                                  IgaChangeRequestEntity cr,
                                  UserModel admin,
                                  String signaturePayload);

    /**
     * Once threshold met, produce the final string to write to the SIGNATURE column.
     */
    String combineFinal(KeycloakSession session,
                        IgaChangeRequestEntity cr,
                        List<IgaAuthorizationEntity> authorizations);

    /**
     * Threshold for this realm. Defaults to realm attribute "iga.threshold" or 1.
     */
    int getThreshold(RealmModel realm);
}
