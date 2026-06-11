package org.tidecloak.iga.providers;

import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.tidecloak.iga.attestors.TideAttestor;
import org.tidecloak.iga.services.IgaSystemProvisioner;
import org.tidecloak.iga.services.IgaSystemProvisioner.TideUhoEnqueueResult;
import org.tidecloak.iga.services.IgaSystemProvisioner.TideUhoRemovalResult;

import jakarta.persistence.EntityManager;

import java.util.List;

/**
 * Default {@link IgaSystemProvisionerProvider} — a thin per-session wrapper that
 * delegates to {@link IgaSystemProvisioner}, sourcing the request-scoped
 * {@link EntityManager} from the session's {@link JpaConnectionProvider} (same
 * idiom as the rest of {@code iga-core}).
 */
public class DefaultIgaSystemProvisionerProvider implements IgaSystemProvisionerProvider {

    private final KeycloakSession session;

    public DefaultIgaSystemProvisionerProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public TideUhoEnqueueResult enqueueTideClaimsScopeProvisioning(
            RealmModel realm, ClientScopeRepresentation scopeRep, String requestedBy) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        return new IgaSystemProvisioner(session, em)
                .enqueueTideClaimsScopeProvisioning(realm, scopeRep, requestedBy);
    }

    @Override
    public TideUhoRemovalResult enqueueTideClaimsScopeRemoval(RealmModel realm, String requestedBy) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        return new IgaSystemProvisioner(session, em)
                .enqueueTideClaimsScopeRemoval(realm, requestedBy);
    }

    @Override
    public byte[] signAndStampUserIdentity(RealmModel realm, String userId,
                                           String tideAuthDataJson, String settingsSignedBlob,
                                           String settingsSigB64) {
        if (!"true".equalsIgnoreCase(realm.getAttribute("isIGAEnabled"))) {
            throw new IllegalStateException(
                "signAndStamp* called for IGA-disabled realm '" + realm.getName()
                + "'; the IGA-off bypass must skip the attestation ceremony at the idp call site");
        }
        return TideAttestor.signUserIdentityWithGVrk(
                session, realm, userId, tideAuthDataJson, settingsSignedBlob, settingsSigB64);
    }

    @Override
    public byte[] signAndStampInvitableUserIdentity(RealmModel realm, String userId, String userPublic,
                                                    String tideAuthDataJson, String settingsSignedBlob,
                                                    String settingsSigB64) {
        if (!"true".equalsIgnoreCase(realm.getAttribute("isIGAEnabled"))) {
            throw new IllegalStateException(
                "signAndStamp* called for IGA-disabled realm '" + realm.getName()
                + "'; the IGA-off bypass must skip the attestation ceremony at the idp call site");
        }
        return TideAttestor.signInvitableUserIdentityWithGVrk(
                session, realm, userId, userPublic, tideAuthDataJson, settingsSignedBlob, settingsSigB64);
    }

    @Override
    public boolean isUserIdentityCommitted(RealmModel realm, String userId) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        List<String> r = em.createQuery(
                "SELECT e.attestation FROM UserEntity e WHERE e.id = :id", String.class)
            .setParameter("id", userId)
            .setMaxResults(1)
            .getResultList();
        String att = r.isEmpty() ? null : r.get(0);
        return att != null && !att.isBlank();
    }

    @Override
    public void close() {
        // no-op: the EntityManager is owned by the JpaConnectionProvider.
    }
}
