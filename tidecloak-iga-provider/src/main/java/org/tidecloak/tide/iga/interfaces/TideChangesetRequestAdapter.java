package org.tidecloak.tide.iga.interfaces;

import jakarta.persistence.EntityManager;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.UserEntity;
import org.midgard.models.AdminAuthorization;
import org.tidecloak.base.iga.interfaces.ChangesetRequestAdapter;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.jpa.entities.AdminAuthorizationEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.UserClientAccessProofEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.models.UserContext;

import java.lang.reflect.Method;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

import static org.tidecloak.base.iga.interfaces.ChangesetRequestAdapter.createAdminAuthorizationEntity;

/**
 * New-engine adapter:
 * - Uses the admin's latest UserContext for the realm-management client as the AdminAuthorization "context"
 * - Persists the AdminAuthorization to the envelope (ChangesetRequestEntity)
 * - Advances envelope status using BasicIGAUtils.updateEnvelopeStatus(...)
 */
public class TideChangesetRequestAdapter extends ChangesetRequestAdapter {

    /**
     * Record the admin’s approval (or rejection) on an envelope.
     *
     * @param adminTideAuthMsg        optional Midgard auth message (if captured)
     * @param adminTideBlindSig       optional blind sig (if captured)
     * @param adminSessionApprovalSig optional session approval sig (if captured)
     */
    public static void saveAdminAuthorizaton(KeycloakSession session,
                                             String changeSetType,
                                             String changeSetRequestID,
                                             String changeSetActionType,
                                             UserModel adminUser,
                                             String adminTideAuthMsg,
                                             String adminTideBlindSig,
                                             String adminSessionApprovalSig) throws Exception {

        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        RealmModel realm = session.getContext().getRealm();

        // 1) Resolve envelope key
        final ChangeSetType cst;
        final ActionType act;
        try {
            cst = ChangeSetType.valueOf(changeSetType);
            act = ActionType.valueOf(changeSetActionType);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    "Unknown changeSetType/actionType: " + changeSetType + " / " + changeSetActionType, e);
        }

        ChangesetRequestEntity envelope = em.find(
                ChangesetRequestEntity.class,
                new ChangesetRequestEntity.Key(changeSetRequestID, cst)
        );
        if (envelope == null) {
            throw new IllegalStateException(
                    "No change-set request found for id=" + changeSetRequestID + " type=" + changeSetType);
        }

        // 2) Load the admin’s latest UC for the realm-management client
        ClientModel realmMgmt = session.clients()
                .getClientByClientId(realm, Constants.REALM_MANAGEMENT_CLIENT_ID);
        if (realmMgmt == null) {
            throw new IllegalStateException("Realm-management client not found in realm " + realm.getName());
        }

        UserEntity adminEntity = em.find(UserEntity.class, adminUser.getId());
        if (adminEntity == null) {
            throw new IllegalStateException("Admin user not found: " + adminUser.getId());
        }

        List<UserClientAccessProofEntity> ucRows = em
                .createNamedQuery("getAccessProofByUserAndClientId", UserClientAccessProofEntity.class)
                .setParameter("user", adminEntity)
                .setParameter("clientId", realmMgmt.getId())
                .getResultList();

        if (ucRows == null || ucRows.isEmpty()) {
            throw new IllegalStateException(
                    "Admin user has no UserContext for realm-management. " +
                            "Ensure default UCs exist and the admin has visited the Admin Console recently. " +
                            "userId=" + adminUser.getId());
        }

        // Prefer the newest UC by a best-effort timestamp; fallback to first
        Optional<UserClientAccessProofEntity> maybeLatest = ucRows.stream()
                .max(Comparator.comparingLong(TideChangesetRequestAdapter::extractCreatedEpochSafe));
        UserClientAccessProofEntity latest = maybeLatest.orElse(ucRows.get(0));

        // 3) Build AdminAuthorization from the UC JSON + its signature
        String adminUcJson = latest.getAccessProof();
        String adminUcSig  = latest.getAccessProofSig();
        if (adminUcJson == null || adminUcJson.isBlank()) {
            throw new IllegalStateException("Stored admin UserContext JSON is empty for userId=" + adminUser.getId());
        }

        // Validate UC shape
        try {
            new UserContext(adminUcJson);
        } catch (Throwable t) {
            throw new IllegalStateException("Admin UserContext is malformed for userId=" + adminUser.getId(), t);
        }

        AdminAuthorization adminAuthorization = new AdminAuthorization(
                adminUcJson,
                adminUcSig == null ? "" : adminUcSig,
                adminTideAuthMsg == null ? "" : adminTideAuthMsg,
                adminTideBlindSig == null ? "" : adminTideBlindSig,
                adminSessionApprovalSig == null ? "" : adminSessionApprovalSig
        );

        AdminAuthorizationEntity adminAuthEntity = createAdminAuthorizationEntity(
                changeSetRequestID,
                cst,
                adminAuthorization.ToString(),
                adminUser.getId(),
                em
        );

        // 4) Persist admin authorization on the envelope
        envelope.addAdminAuthorization(adminAuthEntity);

        // 5) Advance the envelope status using the central helper (new engine)
        BasicIGAUtils.updateEnvelopeStatus(session, em, cst, changeSetRequestID, act);

        em.flush();
    }

    /**
     * Try to extract a "created" epoch (seconds or millis) from the entity via common method names.
     * Returns 0 if no suitable method/value is found.
     */
    private static long extractCreatedEpochSafe(Object row) {
        if (row == null) return 0L;
        String[] candidates = new String[] {
                "getCreatedTimestamp", "getTimestamp", "getCreatedAt", "getCreatedOn", "getTime", "getUpdatedTimestamp"
        };
        for (String m : candidates) {
            try {
                Method mm = row.getClass().getMethod(m);
                Object v = mm.invoke(row);
                if (v instanceof Number n) {
                    long x = n.longValue();
                    // Heuristic: treat 13+ digit numbers as millis; normalize to millis for comparison
                    if (x > 3_000_000_000L) return x;           // already millis
                    if (x > 0) return x * 1000L;                 // seconds → millis
                }
            } catch (NoSuchMethodException ignored) {
            } catch (Throwable ignored) {
                // if a method exists but fails, just skip to the next
            }
        }
        return 0L;
    }
}
