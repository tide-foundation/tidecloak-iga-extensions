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
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
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


        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(changeSetRequestID, ChangeSetType.valueOf(changeSetType)));
        if(changesetRequestEntity == null){
            throw new Exception("No change set request found with this record id, " + changeSetRequestID);
        }
        UserEntity adminEntity = em.find(UserEntity.class, adminUser.getId());
        ClientModel client = session.getContext().getRealm().getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID);
        var tideIdp = session.getContext().getRealm().getIdentityProviderByAlias("tide");

        if(IGAUtils.isIGAEnabled(session.getContext().getRealm()) && tideIdp == null) {
            AdminAuthorization adminAuthorization = new AdminAuthorization(adminUser.getId(), "approvedBy::"+adminUser.getId(), "", "", "");
            AdminAuthorizationEntity adminAuthorizationEntity = createAdminAuthorizationEntity(changeSetRequestID, ChangeSetType.valueOf(changeSetType), adminAuthorization, adminUser.getId(), em);
            changesetRequestEntity.addAdminAuthorization(adminAuthorizationEntity);
            Object draftRecordEntity= IGAUtils.fetchDraftRecordEntity(em, ChangeSetType.valueOf(changeSetType), changeSetRequestID);
            IGAUtils.updateDraftStatus(session,  ChangeSetType.valueOf(changeSetType), changeSetRequestID, ActionType.valueOf(changeSetActionType), draftRecordEntity);
            return;
        }

        List<UserClientAccessProofEntity> userClientAccessProofEntity = em.createNamedQuery("getAccessProofByUserAndClientId", UserClientAccessProofEntity.class)
            .setParameter("user", adminEntity)
            .setParameter("clientId", client.getId()).getResultList();

        if ( userClientAccessProofEntity == null ){
            throw new Exception("This admin user does not have any realm management roles, " + adminUser.getId());
        }

        UserContext adminContext = new UserContext(userClientAccessProofEntity.get(0).getAccessProof());
        AdminAuthorization adminAuthorization = new AdminAuthorization(adminContext.ToString(), userClientAccessProofEntity.get(0).getAccessProofSig(), adminTideAuthMsg, adminTideBlindSig, adminSessionApprovalSig);
        AdminAuthorizationEntity adminAuthorizationEntity = createAdminAuthorizationEntity(changeSetRequestID, ChangeSetType.valueOf(changeSetType), adminAuthorization, adminUser.getId(), em);
        changesetRequestEntity.addAdminAuthorization(adminAuthorizationEntity);

        Object draftRecordEntity= IGAUtils.fetchDraftRecordEntity(em, ChangeSetType.valueOf(changeSetType), changeSetRequestID);
        IGAUtils.updateDraftStatus(session,  ChangeSetType.valueOf(changeSetType), changeSetRequestID, ActionType.valueOf(changeSetActionType), draftRecordEntity);
    }

    public static void saveAdminRejection(KeycloakSession session, String changeSetType, String changeSetRequestID, String changeSetActionType, UserModel adminUser) throws Exception {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(changeSetRequestID, ChangeSetType.valueOf(changeSetType)));
        if(changesetRequestEntity == null){
            throw new Exception("No change set request found with this record id, " + changeSetRequestID);
        }
        UserEntity adminEntity = em.find(UserEntity.class, adminUser.getId());
        ClientModel client = session.getContext().getRealm().getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID);
        List<UserClientAccessProofEntity> userClientAccessProofEntity = em.createNamedQuery("getAccessProofByUserAndClientId", UserClientAccessProofEntity.class)
                .setParameter("user", adminEntity)
                .setParameter("clientId", client.getId()).getResultList();

        if ( userClientAccessProofEntity == null ){
            throw new Exception("This admin user does not have any realm management roles, " + adminUser.getId());
        }

        AdminAuthorizationEntity adminAuthorizationEntity = createAdminAuthorizationEntity(changeSetRequestID, ChangeSetType.valueOf(changeSetType), null, adminUser.getId(), em);
        changesetRequestEntity.addAdminAuthorization(adminAuthorizationEntity);

        // Check if change request is no longer valid and process it
        Object draftRecordEntity= IGAUtils.fetchDraftRecordEntity(em, ChangeSetType.valueOf(changeSetType), changeSetRequestID);
        IGAUtils.updateDraftStatus(session,  ChangeSetType.valueOf(changeSetType), changeSetRequestID, ActionType.valueOf(changeSetActionType), draftRecordEntity);
    }

    public static DraftStatus getChangeSetStatus(KeycloakSession session, String changeSetId, ChangeSetType changeSetType) throws Exception {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        RealmModel realm = session.getContext().getRealm();
        RoleModel tideRole = session.clients()
                .getClientByClientId(realm, Constants.REALM_MANAGEMENT_CLIENT_ID)
                .getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);


        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(changeSetId, changeSetType));
        if (changesetRequestEntity == null) {
            throw new Exception("No change set request found with ID: " + changeSetId);
        }

        int threshold = parseThreshold(tideRole);
        int numberOfAdmins = getNumberOfActiveAdmins(session, realm, tideRole, em);
        int numberOfRejections = (int) changesetRequestEntity.getAdminAuthorizations()
                .stream()
                .filter(a -> !a.getIsApproval())
                .count();

        // If remaining admins to approve are less than the threshold, deny the request
        if ((numberOfAdmins - numberOfRejections) < threshold) {
            return DraftStatus.DENIED;
        }

        int numberOfApprovals = (int) changesetRequestEntity.getAdminAuthorizations()
                .stream()
                .filter(AdminAuthorizationEntity::getIsApproval)
                .count();

        // Determine the draft status based on approval/rejection counts
        if (numberOfApprovals < 1 && numberOfRejections < 1) {
            return DraftStatus.DRAFT;
        } else if (numberOfApprovals >= threshold) {
            return DraftStatus.APPROVED;
        } else if ((numberOfAdmins - numberOfRejections) < threshold) {
            return DraftStatus.DENIED;
        } else {
            return DraftStatus.PENDING;
        }
    }

    public static ChangesetRequestEntity getChangesetRequestEntity(KeycloakSession session, String changeSetId, ChangeSetType changeSetType){
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        return em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(changeSetId, changeSetType));
    }

    private static AdminAuthorizationEntity createAdminAuthorizationEntity(String changeSetRequestId, ChangeSetType changeSetType, AdminAuthorization adminAuthorization, String userId, EntityManager em) throws Exception {

        ChangesetRequestEntity changesetRequestEntity = em. find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(changeSetRequestId, changeSetType));
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

    private static int parseThreshold(RoleModel tideRole) throws Exception {
        String thresholdAttr = tideRole.getFirstAttribute("tideThreshold");
        if (thresholdAttr == null || thresholdAttr.isEmpty()) {
            throw new Exception("Missing or invalid 'tideThreshold' attribute for role: " + tideRole.getName());
        }
        try {
            return Integer.parseInt(thresholdAttr);
        } catch (NumberFormatException e) {
            throw new Exception("Invalid 'tideThreshold' attribute value: " + thresholdAttr, e);
        }
    }

    private static int getNumberOfActiveAdmins(KeycloakSession session, RealmModel realm, RoleModel tideRole, EntityManager em) {
         return (int) session.users()
                .getRoleMembersStream(realm, tideRole).filter( u -> {
                    UserEntity user = em.find(UserEntity.class, u.getId());
                     List<TideUserRoleMappingDraftEntity> entity = em.createNamedQuery("getUserRoleAssignmentDraftEntityByStatus", TideUserRoleMappingDraftEntity.class)
                             .setParameter("user", user)
                             .setParameter("roleId", tideRole.getId())
                             .setParameter("draftStatus", DraftStatus.ACTIVE).getResultList();
                     return !entity.isEmpty();
                 }).count();

    }
}
