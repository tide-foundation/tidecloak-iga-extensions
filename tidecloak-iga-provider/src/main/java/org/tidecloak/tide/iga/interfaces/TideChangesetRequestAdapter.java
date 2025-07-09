package org.tidecloak.tide.iga.interfaces;

import jakarta.persistence.EntityManager;
import org.keycloak.component.ComponentModel;
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

import java.util.List;

import static org.tidecloak.base.iga.interfaces.ChangesetRequestAdapter.createAdminAuthorizationEntity;

public class TideChangesetRequestAdapter extends ChangesetRequestAdapter {

    public static void saveAdminAuthorizaton(KeycloakSession session, String changeSetType, String changeSetRequestID, String changeSetActionType, UserModel adminUser, String adminTideAuthMsg, String adminTideBlindSig, String adminSessionApprovalSig) throws Exception {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        RealmModel realm = session.getContext().getRealm();


        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(changeSetRequestID, ChangeSetType.valueOf(changeSetType)));
        if(changesetRequestEntity == null){
            throw new Exception("No change set request found with this record id, " + changeSetRequestID);
        }
        UserEntity adminEntity = em.find(UserEntity.class, adminUser.getId());
        ClientModel client = session.getContext().getRealm().getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID);
        ComponentModel componentModel = realm.getComponentsStream()
                .filter(x -> "tide-vendor-key".equals(x.getProviderId()))  // Use .equals for string comparison
                .findFirst()
                .orElse(null);

        List<UserClientAccessProofEntity> adminAccessProof = em.createNamedQuery("getAccessProofByUserAndClientId", UserClientAccessProofEntity.class)
            .setParameter("user", adminEntity)
            .setParameter("clientId", client.getId()).getResultList();

        if ( adminAccessProof == null ){
            throw new Exception("This admin user does not have any realm management roles, " + adminUser.getId());
        }

        UserContext adminContext = new UserContext(adminAccessProof.get(0).getAccessProof());
        AdminAuthorization adminAuthorization = new AdminAuthorization(adminContext.ToString(), adminAccessProof.get(0).getAccessProofSig(), adminTideAuthMsg, adminTideBlindSig, adminSessionApprovalSig);
        AdminAuthorizationEntity adminAuthorizationEntity = createAdminAuthorizationEntity(changeSetRequestID, ChangeSetType.valueOf(changeSetType), adminAuthorization.ToString(), adminUser.getId(), em);
        changesetRequestEntity.addAdminAuthorization(adminAuthorizationEntity);

        List<?> draftRecordEntity= BasicIGAUtils.fetchDraftRecordEntityByRequestId(em, ChangeSetType.valueOf(changeSetType), changeSetRequestID);
        draftRecordEntity.forEach(d -> {
            try {
                BasicIGAUtils.updateDraftStatus(session,  ChangeSetType.valueOf(changeSetType), changeSetRequestID, ActionType.valueOf(changeSetActionType), d);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }


}
