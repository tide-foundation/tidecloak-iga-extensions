package org.tidecloak.iga.interfaces;

import jakarta.persistence.EntityManager;
import org.checkerframework.checker.units.qual.A;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.midgard.models.AdminAuthorization;
import org.midgard.models.UserContext.UserContext;
import org.tidecloak.jpa.entities.AdminAuthorizationEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.iga.utils.IGAUtils;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.UserClientAccessProofEntity;

import java.util.List;
import java.util.stream.Collectors;

import static org.tidecloak.iga.utils.IGAUtils.processDraftRejections;
import static org.tidecloak.iga.utils.IGAUtils.updateDraftStatus;

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
        AdminAuthorizationEntity adminAuthorizationEntity = createAdminAuthorizationEntity(changeSetRequestID, adminAuthorization, userClientAccessProofEntity.get(0).getUser().getId(), em);

        changesetRequestEntity.addAdminAuthorization(adminAuthorizationEntity);

        Object draftRecordEntity= IGAUtils.fetchDraftRecordEntity(em, ChangeSetType.valueOf(changeSetType), changeSetRequestID);
        IGAUtils.updateDraftStatus(session,  ChangeSetType.valueOf(changeSetType), changeSetRequestID, ActionType.valueOf(changeSetActionType), draftRecordEntity);
    }

    public static void saveAdminRejection(KeycloakSession session, String changeSetType, String changeSetRequestID, String changeSetActionType, UserModel adminUser) throws Exception {
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

        AdminAuthorizationEntity adminAuthorizationEntity = createAdminAuthorizationEntity(changeSetRequestID, null, userClientAccessProofEntity.get(0).getUser().getId(), em);
        changesetRequestEntity.addAdminAuthorization(adminAuthorizationEntity);

        // Check if change request is no longer valid and process it
        Object draftRecordEntity= IGAUtils.fetchDraftRecordEntity(em, ChangeSetType.valueOf(changeSetType), changeSetRequestID);
        processDraftRejections(session,  ChangeSetType.valueOf(changeSetType),  ActionType.valueOf(changeSetActionType), draftRecordEntity, changesetRequestEntity);
    }

    public static DraftStatus getChangeSetStatus(KeycloakSession session, String changeSetId) throws Exception {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        RoleModel tideRole = session.clients().getClientByClientId(session.getContext().getRealm(), Constants.REALM_MANAGEMENT_CLIENT_ID).getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);

        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, changeSetId);
        if(changesetRequestEntity == null){
            throw new Exception("No change set request found with this record id, " + changeSetId);
        }

        int authorizationCount = changesetRequestEntity.getAdminAuthorizations().stream().filter(AdminAuthorizationEntity::getIsApproval).collect(Collectors.toSet()).size();

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

    private static AdminAuthorizationEntity createAdminAuthorizationEntity(String changeSetRequestId, AdminAuthorization adminAuthorization, String userId, EntityManager em) throws Exception {
        ChangesetRequestEntity changesetRequestEntity = em. find(ChangesetRequestEntity.class, changeSetRequestId);
        if(changesetRequestEntity == null){
            throw new Exception("No changeset request found with this id, " + changeSetRequestId);
        }

        boolean isApproval = adminAuthorization != null;
        String adminAuth = isApproval ? adminAuthorization.ToString() : null;

        AdminAuthorizationEntity adminAuthorizationEntity = new AdminAuthorizationEntity();
        adminAuthorizationEntity.setId(KeycloakModelUtils.generateId());
        adminAuthorizationEntity.setChangesetRequest(changesetRequestEntity);
        adminAuthorizationEntity.setUserId(userId);
        adminAuthorizationEntity.setAdminAuthorization(adminAuth);
        adminAuthorizationEntity.setIsApproval(isApproval);
        em.persist(adminAuthorizationEntity);
        em.flush();

        return adminAuthorizationEntity;

    }
}
