package org.tidecloak.jpa.models;

import jakarta.persistence.EntityManager;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.UserEntity;
import org.midgard.models.AdminAuthorization;
import org.midgard.models.UserContext.UserContext;
import org.tidecloak.enums.ActionType;
import org.tidecloak.enums.ChangeSetType;
import org.tidecloak.enums.DraftStatus;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.UserClientAccessProofEntity;
import org.tidecloak.jpa.utils.IGAUtils;

import java.util.List;

import static org.tidecloak.TideRequests.TideRoleRequests.tideRealmAdminRole;
import static org.tidecloak.jpa.utils.IGAUtils.updateDraftStatus;

public class ChangesetRequestAdapter {

    public static void saveAdminAuthorizaton(KeycloakSession session, String changeSetType, String changeSetRequestID, String changeSetActionType, UserModel adminUser, String adminTideAuthMsg, String adminTideBlindSig, String adminSessionApprovalSig) throws Exception {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, changeSetRequestID);
        if(changesetRequestEntity == null){
            throw new Exception("No change set request found with this record id, " + changeSetRequestID);
        }
        UserEntity adminEntity = em.find(UserEntity.class, adminUser.getId());
        ClientModel client = session.getContext().getRealm().getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID);
        List<UserClientAccessProofEntity> userClientAccessProofEntity = em.createNamedQuery("getAccessProofByUserIdAndClientId", UserClientAccessProofEntity.class)
                .setParameter("user", adminEntity)
                .setParameter("clientId", client.getId()).getResultList();

        if ( userClientAccessProofEntity == null ){
            throw new Exception("This admin user does not have any realm management roles, " + adminUser.getId());
        }

        UserContext adminContext = new UserContext(userClientAccessProofEntity.get(0).getAccessProof());
        AdminAuthorization adminAuthorization = new AdminAuthorization(adminContext.ToString(), userClientAccessProofEntity.get(0).getAccessProofSig(), adminTideAuthMsg, adminTideBlindSig, adminSessionApprovalSig);
        changesetRequestEntity.addAdminAuthorization(adminAuthorization.ToString());

        Object draftRecordEntity= IGAUtils.fetchDraftRecordEntity(em, ChangeSetType.valueOf(changeSetType), changeSetRequestID);
        updateDraftStatus(session,  ChangeSetType.valueOf(changeSetType), changeSetRequestID, ActionType.valueOf(changeSetActionType), draftRecordEntity);
    }

    public static DraftStatus getChangeSetStatus(KeycloakSession session, String changeSetId) throws Exception {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        RoleModel tideRole = session.clients().getClientByClientId(session.getContext().getRealm(), Constants.REALM_MANAGEMENT_CLIENT_ID).getRole(tideRealmAdminRole);

        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, changeSetId);
        if(changesetRequestEntity == null){
            throw new Exception("No change set request found with this record id, " + changeSetId);
        }

        int authorizationCount = changesetRequestEntity.getAdminAuthorizations().size();

        if(authorizationCount < 1){
           return DraftStatus.DRAFT;
        }else if ( authorizationCount == Integer.parseInt(tideRole.getFirstAttribute("tideThreshold"))) {
            return DraftStatus.APPROVED;
        } else {
            return DraftStatus.PENDING;
        }
    }

    public static ChangesetRequestEntity getChangesetRequestEntity(KeycloakSession session, String changeSetId){
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        return em.find(ChangesetRequestEntity.class, changeSetId);
    }
}
