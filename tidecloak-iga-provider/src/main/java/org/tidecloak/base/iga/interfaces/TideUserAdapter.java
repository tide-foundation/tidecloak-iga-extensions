package org.tidecloak.base.iga.interfaces;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.*;
import org.keycloak.models.jpa.UserAdapter;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.jpa.entities.UserGroupMembershipEntity;
import org.keycloak.representations.idm.MembershipType;

import org.keycloak.models.utils.KeycloakModelUtils;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessor;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessorFactory;

import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessorFactoryProvider;
import org.tidecloak.base.iga.ChangeSetProcessors.utils.ClientUtils;
import org.tidecloak.base.iga.ChangeSetProcessors.utils.TideEntityUtils;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.jpa.entities.AuthorizerEntity;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.WorkflowType;
import org.tidecloak.shared.enums.models.WorkflowParams;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.drafting.TideUserGroupMembershipEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;

import java.util.*;
import java.util.stream.Stream;

import static org.keycloak.utils.StreamsUtil.closing;
import static org.tidecloak.base.iga.ChangeSetProcessors.utils.TideEntityUtils.wrapRoleModel;


public class TideUserAdapter extends UserAdapter {
    private final KeycloakSession session;
    private final RealmModel realm;
    private final ChangeSetProcessor<TideUserRoleMappingDraftEntity> processor;


    public TideUserAdapter(KeycloakSession session, RealmModel realm, EntityManager em, UserEntity user) {
        super(session, realm, em, user);
        this.session = session;
        this.realm = realm;

        ChangeSetProcessorFactory changeSetProcessorFactory = ChangeSetProcessorFactoryProvider.getFactory();
        this.processor = changeSetProcessorFactory.getProcessor(ChangeSetType.USER_ROLE);
    }

    private void stampRequestingAdmin() {
        BasicIGAUtils.stampRequestingAdmin(session);
    }

    @Override
    public void joinGroup(GroupModel group) {
        stampRequestingAdmin();
        try {
            // Don't draft for master realm — apply directly
            RealmModel masterRealm = session.realms().getRealmByName(Config.getAdminRealm());
            if (realm.equals(masterRealm)) {
                super.joinGroup(group);
                return;
            }

            TideUserGroupMembershipEntity entity = new TideUserGroupMembershipEntity();
            entity.setId(KeycloakModelUtils.generateId());
            entity.setUser(getEntity());
            entity.setGroupId(group.getId());
            entity.setDraftStatus(DraftStatus.DRAFT);
            entity.setAction(ActionType.CREATE);
            em.persist(entity);
            em.flush();

            ChangeSetProcessorFactory changeSetProcessorFactory = ChangeSetProcessorFactoryProvider.getFactory();
            ChangeSetProcessor<TideUserGroupMembershipEntity> membershipProcessor = changeSetProcessorFactory.getProcessor(ChangeSetType.USER_GROUP_MEMBERSHIP);
            WorkflowParams params = new WorkflowParams(DraftStatus.DRAFT, false, ActionType.CREATE, ChangeSetType.USER_GROUP_MEMBERSHIP);
            membershipProcessor.executeWorkflow(session, entity, em, WorkflowType.REQUEST, params, null);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void joinGroupImpl(GroupModel group) {
        UserGroupMembershipEntity entity = new UserGroupMembershipEntity();
        entity.setUser(getEntity());
        entity.setGroupId(group.getId());
        entity.setMembershipType(MembershipType.UNMANAGED);
        em.persist(entity);
        em.flush();
        em.detach(entity);
    }

    @Override
    public void leaveGroup(GroupModel group) {
        stampRequestingAdmin();
        try {
            // Don't draft for master realm — apply directly
            RealmModel masterRealm = session.realms().getRealmByName(Config.getAdminRealm());
            if (realm.equals(masterRealm)) {
                super.leaveGroup(group);
                return;
            }

            TideUserGroupMembershipEntity entity = new TideUserGroupMembershipEntity();
            entity.setId(KeycloakModelUtils.generateId());
            entity.setUser(getEntity());
            entity.setGroupId(group.getId());
            entity.setDraftStatus(DraftStatus.DRAFT);
            entity.setAction(ActionType.DELETE);
            em.persist(entity);
            em.flush();

            ChangeSetProcessorFactory changeSetProcessorFactory = ChangeSetProcessorFactoryProvider.getFactory();
            ChangeSetProcessor<TideUserGroupMembershipEntity> membershipProcessor = changeSetProcessorFactory.getProcessor(ChangeSetType.USER_GROUP_MEMBERSHIP);
            WorkflowParams params = new WorkflowParams(DraftStatus.DRAFT, true, ActionType.DELETE, ChangeSetType.USER_GROUP_MEMBERSHIP);
            membershipProcessor.executeWorkflow(session, entity, em, WorkflowType.REQUEST, params, null);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void grantRole(RoleModel roleModel) {
        stampRequestingAdmin();
        try {
            if(hasDirectRole(roleModel)) return;

            RoleModel role = wrapRoleModel(roleModel, session, realm);

            // if has an indirect role, we let it be added but we dont need it to be drafted.
            if(!hasDirectRole(roleModel) && hasRole(roleModel)) {
                super.grantRole(role);
                List<TideUserRoleMappingDraftEntity> entities = em.createNamedQuery("getUserRoleAssignmentDraftEntity", TideUserRoleMappingDraftEntity.class)
                        .setParameter("user", getEntity())
                        .setParameter("roleId", role.getId())
                        .getResultList();
                // Check if this has already been action before
                if(entities.isEmpty()){
                    TideUserRoleMappingDraftEntity draftUserRole = new TideUserRoleMappingDraftEntity();
                    draftUserRole.setId(KeycloakModelUtils.generateId());
                    draftUserRole.setRoleId(role.getId());
                    draftUserRole.setUser(this.getEntity());
                    draftUserRole.setAction(ActionType.CREATE);
                    draftUserRole.setDraftStatus(DraftStatus.ACTIVE);
                    em.persist(draftUserRole);
                }else{
                    entities.get(0).setDeleteStatus(null);
                    entities.get(0).setDraftStatus(DraftStatus.ACTIVE);
                    entities.get(0).setAction(ActionType.CREATE);
                }
                em.flush();
                return;

            };

            super.grantRole(role);

            // Dont draft for master realm
            RealmModel masterRealm = session.realms().getRealmByName(Config.getAdminRealm());
            if(realm.equals(masterRealm)){
                return;
            }

            boolean isTempAdmin = this.user.getAttributes().stream()
                    .anyMatch(attribute -> attribute.getName().equalsIgnoreCase(UserModel.IS_TEMP_ADMIN_ATTR_NAME));
            if (isTempAdmin) {
                return;
            }

            // Check if this has already been action before
            List<DraftStatus> statuses = Arrays.asList(DraftStatus.PENDING, DraftStatus.DRAFT, DraftStatus.APPROVED, DraftStatus.DENIED);
            List<TideUserRoleMappingDraftEntity> draftEntities = getDraftEntities(roleModel, statuses);


            // Add draft request
            if (draftEntities == null || draftEntities.isEmpty()) {
                if(role.getContainer() instanceof  RealmModel) {
                    // if realm role, check if theres any affected clients. If no affected clients then dont need to create draft.
                    List<ClientModel> affectedClients = ClientUtils.getUniqueClientList(session, realm, roleModel);
                    if(affectedClients.isEmpty() || role.equals(realm.getDefaultRole())){
                        TideUserRoleMappingDraftEntity draftUserRole = new TideUserRoleMappingDraftEntity();
                        draftUserRole.setId(KeycloakModelUtils.generateId());
                        draftUserRole.setRoleId(role.getId());
                        draftUserRole.setUser(this.getEntity());
                        draftUserRole.setAction(ActionType.CREATE);
                        draftUserRole.setDraftStatus(DraftStatus.ACTIVE);
                        em.persist(draftUserRole);
                        em.flush();
                        return;
                    }
                }

                // Create a draft record for new user role mapping
                TideUserRoleMappingDraftEntity draftUserRole = new TideUserRoleMappingDraftEntity();
                draftUserRole.setId(KeycloakModelUtils.generateId());
                draftUserRole.setRoleId(role.getId());
                draftUserRole.setUser(this.getEntity());
                draftUserRole.setAction(ActionType.CREATE);
                draftUserRole.setDraftStatus(DraftStatus.DRAFT);
                em.persist(draftUserRole);
                em.flush();

                WorkflowParams params = new WorkflowParams(DraftStatus.DRAFT, false, ActionType.CREATE, ChangeSetType.USER_ROLE);
                processor.executeWorkflow(session, draftUserRole, em, WorkflowType.REQUEST, params, null);
            }

        } catch(Exception e){
                throw new RuntimeException(e);
        }
    }


    @Override
    public void deleteRoleMapping(RoleModel roleModel) {
        stampRequestingAdmin();
        try {
            // If we are removing a direct role but this user has an indirect role assignment, we remove the direct role without drafting. No change to the user context
            boolean hasIndirectRole = getRoleMappingsStream().anyMatch(role -> !role.getId().equalsIgnoreCase(roleModel.getId()) && role.hasRole(roleModel));
            if(hasDirectRole(roleModel) && hasIndirectRole ){
                super.deleteRoleMapping(roleModel);
                List<TideUserRoleMappingDraftEntity> entities = em.createNamedQuery("getUserRoleAssignmentDraftEntity", TideUserRoleMappingDraftEntity.class)
                        .setParameter("user", getEntity())
                        .setParameter("roleId", roleModel.getId())
                        .getResultList();

                entities.forEach(e -> em.remove(e));
                return;
            }

            RoleModel role = wrapRoleModel(roleModel, session, realm);

            String igaAttribute = session.getContext().getRealm().getAttribute("isIGAEnabled");
            boolean isIGAEnabled = igaAttribute != null && igaAttribute.equalsIgnoreCase("true");

            // Dont draft for master realm
            RealmModel masterRealm = session.realms().getRealmByName(Config.getAdminRealm());
            if(realm.equals(masterRealm)){
                super.deleteRoleMapping(roleModel);
                return;
            }
            List<TideUserRoleMappingDraftEntity> entities = getDraftEntities(role);

            if (!isIGAEnabled){
                deleteRoleAndProofRecords(role, entities);
                return;
            }
            List<DraftStatus> statuses = Arrays.asList(DraftStatus.PENDING, DraftStatus.DRAFT, DraftStatus.APPROVED, DraftStatus.DENIED);
            List<TideUserRoleMappingDraftEntity> deleteDraftEntities = getDeleteDraftEntities(roleModel, statuses);

            // Check if this request has been actioned before
            if(!deleteDraftEntities.isEmpty()){
                return;
            }

            List<TideUserRoleMappingDraftEntity> activeDraftEntities = getActiveDraftEntities(role);

            if (activeDraftEntities.isEmpty()) {
                deleteRoleAndProofRecords(role, activeDraftEntities);
                return;
            }

            TideUserRoleMappingDraftEntity committedEntity = activeDraftEntities.get(0);
            if (committedEntity.getDeleteStatus() == DraftStatus.ACTIVE) {
                deleteRoleAndProofRecords(role, activeDraftEntities);
                return;
            }

            WorkflowParams params = new WorkflowParams(DraftStatus.DRAFT, true, ActionType.DELETE, ChangeSetType.USER_ROLE);
            processor.executeWorkflow(session, committedEntity, em, WorkflowType.REQUEST, params, null);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        em.flush();
    }

    public static List<TideUserRoleMappingDraftEntity> getActiveDraftEntities(EntityManager em, UserEntity user, RoleModel role) {
        return em.createNamedQuery("getUserRoleAssignmentDraftEntityByStatus", TideUserRoleMappingDraftEntity.class)
                .setParameter("user", user)
                .setParameter("roleId", role.getId())
                .setParameter("draftStatus", DraftStatus.ACTIVE)
                .getResultList();
    }
    public static List<TideUserRoleMappingDraftEntity> getDraftEntities(EntityManager em, UserEntity user, RoleModel role) {
        return em.createNamedQuery("getUserRoleAssignmentDraftEntity", TideUserRoleMappingDraftEntity.class)
                .setParameter("user", user)
                .setParameter("roleId", role.getId())
                .getResultList();
    }

    private List<TideUserRoleMappingDraftEntity> getActiveDraftEntities(RoleModel role) {
        return em.createNamedQuery("getUserRoleAssignmentDraftEntityByStatus", TideUserRoleMappingDraftEntity.class)
                .setParameter("user", getEntity())
                .setParameter("roleId", role.getId())
                .setParameter("draftStatus", DraftStatus.ACTIVE)
                .getResultList();
    }
    private List<TideUserRoleMappingDraftEntity> getDraftEntities(RoleModel role) {
        return em.createNamedQuery("getUserRoleAssignmentDraftEntity", TideUserRoleMappingDraftEntity.class)
                .setParameter("user", getEntity())
                .setParameter("roleId", role.getId())
                .getResultList();
    }
    private List<TideUserRoleMappingDraftEntity> getDraftEntities(RoleModel role, List<DraftStatus> statuses) {
        return em.createNamedQuery("getUserRoleAssignmentDraftEntityByStatuses", TideUserRoleMappingDraftEntity.class)
                .setParameter("user", getEntity())
                .setParameter("roleId", role.getId())
                .setParameter("draftStatuses", statuses)
                .getResultList();
    }
    private List<TideUserRoleMappingDraftEntity> getDeleteDraftEntities(RoleModel role, List<DraftStatus> statuses) {
        return em.createNamedQuery("getUserRoleAssignmentDraftEntityByDeleteStatuses", TideUserRoleMappingDraftEntity.class)
                .setParameter("user", getEntity())
                .setParameter("roleId", role.getId())
                .setParameter("draftStatuses", statuses)
                .getResultList();
    }

    public void deleteRoleAndProofRecords(RoleModel role, List<TideUserRoleMappingDraftEntity> activeDraftEntities) {
        String recordId = activeDraftEntities == null || activeDraftEntities.isEmpty() ? getDraftEntities(role).get(0).getId() : activeDraftEntities.get(0).getId();
        deleteProofRecordForUser(recordId);
        deleteUserRoleMappingDraftsByRoleAndRole(role.getId());
        super.deleteRoleMapping(role);
    }

    public void deleteRoleAndProofRecords(RoleModel role, List<TideUserRoleMappingDraftEntity> activeDraftEntities, ActionType actionType) {
        String recordId = activeDraftEntities == null || activeDraftEntities.isEmpty() ? getDraftEntities(role).get(0).getId() : activeDraftEntities.get(0).getId();
        deleteProofRecordForUser(recordId);
        if(!actionType.equals(ActionType.DELETE)){
            deleteUserRoleMappingDraftsByRoleAndRole(role.getId());
            super.deleteRoleMapping(role);

        } else {
            TideUserRoleMappingDraftEntity entity = em.find(TideUserRoleMappingDraftEntity.class, recordId);
            if(entity != null) {
                entity.setDeleteStatus(null);
            }
        }
    }


    private void deleteUserRoleMappingDraftsByRole(String roleId) {
        em.createNamedQuery("deleteUserRoleMappingDraftsByRoleAndUser")
                .setParameter("roleId", roleId)
                .executeUpdate();
    }

    private void deleteUserRoleMappingDraftsByRoleAndRole(String roleId) {
        em.createNamedQuery("deleteUserRoleMappingDraftsByRoleAndUser")
                .setParameter("roleId", roleId)
                .setParameter("user", getEntity())
                .executeUpdate();
    }

    private void deleteProofRecordForUser(String recordId) {
        em.createNamedQuery("deleteProofRecordForUser")
                .setParameter("recordId", recordId)
                .setParameter("user", getEntity())
                .executeUpdate();
    }

    private void deleteCompositeRoleProofRecords(RoleModel role) {
        List<AccessProofDetailEntity> proofRecords = em.createNamedQuery("FindUserWithCompositeRoleRecord", AccessProofDetailEntity.class)
                .setParameter("composite", TideEntityUtils.toRoleEntity(role, em))
                .setParameter("user", getEntity())
                .getResultList();
        proofRecords.forEach(em::remove);
    }

    private void markForDeletion(List<TideUserRoleMappingDraftEntity> activeDraftEntities) {
        if (activeDraftEntities != null && !activeDraftEntities.isEmpty()) {
            TideUserRoleMappingDraftEntity userRoleMapping = activeDraftEntities.get(0);
            userRoleMapping.setDeleteStatus(DraftStatus.DRAFT);
            userRoleMapping.setTimestamp(System.currentTimeMillis());
        }
    }

//    private void generateProofDrafts(RoleModel role, List<TideUserRoleMappingDraftEntity> activeDraftEntities) {
//        if (role.getContainer() instanceof ClientModel) {
//            List<ClientModel> clientList = getUniqueClientList(session, realm, role, em);
//
//            UserModel user = session.users().getUserById(realm, getEntity().getId());
//            UserModel wrappedUser = TideRolesUtil.wrapUserModel(user, session, realm);
//            TideAuthzProofUtil util = new TideAuthzProofUtil(session, realm, em);
//
//            clientList.forEach(client -> generateProofDraftForClient(role, client, wrappedUser, util, activeDraftEntities));
//        }
//    }

//    private void generateProofDraftForClient(RoleModel role, ClientModel client, UserModel wrappedUser, TideAuthzProofUtil util, List<TideUserRoleMappingDraftEntity> activeDraftEntities) {
//        Set<RoleModel> roleMappings = new HashSet<>();
//        roleMappings.add(role);
//        try {
//            String draftId = activeDraftEntities == null || activeDraftEntities.isEmpty() ? role.getId() : activeDraftEntities.get(0).getId();
//            util.generateAndSaveProofDraft(client, wrappedUser, roleMappings, draftId,
//                    ChangeSetType.USER_ROLE, ActionType.DELETE, client.isFullScopeAllowed());
//        } catch (Exception e) {
//            throw new RuntimeException(e);
//        }
//    }


    /**
     * Applies the group join directly to the base Keycloak table.
     * Called during the COMMIT phase after a draft has been approved.
     * Directly inserts into USER_GROUP_MEMBERSHIP to bypass the parent's
     * joinGroup chain (isDirectMember check, event firing, batch mode).
     */
    public void applyJoinGroup(GroupModel group) {
        UserGroupMembershipEntity entity = new UserGroupMembershipEntity();
        entity.setUser(getEntity());
        entity.setGroupId(group.getId());
        entity.setMembershipType(MembershipType.UNMANAGED);
        em.persist(entity);
        em.flush();
    }

    /**
     * Applies the group leave directly from the base Keycloak table.
     * Called during the COMMIT phase after a deletion draft has been approved.
     * Directly removes from USER_GROUP_MEMBERSHIP to bypass the parent's
     * leaveGroup chain.
     */
    public void applyLeaveGroup(GroupModel group) {
        List<UserGroupMembershipEntity> results = em.createNamedQuery("userMemberOf", UserGroupMembershipEntity.class)
                .setParameter("user", getEntity())
                .setParameter("groupId", group.getId())
                .getResultList();
        for (UserGroupMembershipEntity entity : results) {
            em.remove(entity);
        }
        em.flush();
    }

    @Override
    public Stream<RoleModel> getRoleMappingsStream() {
        // we query ids only as the role might be cached and following the @ManyToOne will result in a load
        // even if we're getting just the id.
        TypedQuery<String> query = em.createNamedQuery("userRoleMappingIds", String.class);
        query.setParameter("user", getEntity());
        return closing(query.getResultStream().map(realm::getRoleById).filter(Objects::nonNull));
    }

    public Stream<RoleModel> getRoleMappingsStreamByStatusAndAction(DraftStatus status, ActionType actionType) {
        TypedQuery<String> query = em.createNamedQuery("getUserRoleMappingDraftEntityIdsByStatusAndAction", String.class);
        query.setParameter("user", this.getEntity());
        query.setParameter("draftStatus", status);
        query.setParameter("actionType", actionType);
        return closing(query.getResultStream().map(realm::getRoleById).filter(Objects::nonNull));
    }

    public Stream<RoleModel> getRoleMappingsStreamByStatus(DraftStatus status) {
        TypedQuery<String> query = em.createNamedQuery("getUserRoleMappingDraftEntityIdsByStatus", String.class);
        query.setParameter("user", this.getEntity());
        query.setParameter("draftStatus", status);
        return closing(query.getResultStream().map(realm::getRoleById).filter(Objects::nonNull));
    }


}
