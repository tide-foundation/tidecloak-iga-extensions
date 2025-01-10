package org.tidecloak.models;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import org.keycloak.Config;
import org.keycloak.admin.ui.rest.model.ClientRole;
import org.keycloak.models.*;
import org.keycloak.models.jpa.UserAdapter;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.jpa.entities.UserGroupMembershipEntity;

import org.keycloak.models.utils.KeycloakModelUtils;
import org.tidecloak.changeset.ChangeSetProcessor;
import org.tidecloak.changeset.ChangeSetProcessorFactory;

import org.tidecloak.changeset.utils.RoleUtils;
import org.tidecloak.changeset.utils.TideEntityUtils;
import org.tidecloak.enums.ChangeSetType;
import org.tidecloak.enums.WorkflowType;
import org.tidecloak.enums.models.WorkflowParams;
import org.tidecloak.models.TideClientAdapter;
import org.tidecloak.utils.TideRolesUtil;
import org.tidecloak.enums.ActionType;
import org.tidecloak.enums.DraftStatus;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.drafting.TideUserGroupMembershipEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.utils.ProofGeneration;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.keycloak.utils.StreamsUtil.closing;
import static org.tidecloak.changeset.utils.TideEntityUtils.wrapRoleModel;


public class TideUserAdapter extends UserAdapter {
    private final KeycloakSession session;
    private final RealmModel realm;
    private final ChangeSetProcessor<TideUserRoleMappingDraftEntity> processor;


    public TideUserAdapter(KeycloakSession session, RealmModel realm, EntityManager em, UserEntity user) {
        super(session, realm, em, user);
        this.session = session;
        this.realm = realm;

        ChangeSetProcessorFactory changeSetProcessorFactory = new ChangeSetProcessorFactory();
        this.processor = changeSetProcessorFactory.getProcessor(ChangeSetType.USER_ROLE);

    }

    @Override
    public void joinGroup(GroupModel group) {
        super.joinGroup(group);
        TideUserGroupMembershipEntity entity = new TideUserGroupMembershipEntity();

        //TODO: !!!! CHECK IF THIS EXISTS BEFORE ADDING
        entity.setId(KeycloakModelUtils.generateId());
        entity.setUser(getEntity());
        entity.setGroupId(group.getId());
        entity.setDraftStatus(DraftStatus.DRAFT);
        entity.setAction(ActionType.CREATE);
        em.persist(entity);
        em.flush();
        em.detach(entity);
    }

    @Override
    protected void joinGroupImpl(GroupModel group) {
        UserGroupMembershipEntity entity = new UserGroupMembershipEntity();
        entity.setUser(getEntity());
        entity.setGroupId(group.getId());
        em.persist(entity);
        em.flush();
        em.detach(entity);
    }

    @Override
    public void leaveGroup(GroupModel group) {
        super.leaveGroup(group);
        ProofGeneration proofGeneration = new ProofGeneration(session, realm, em);
        List<ClientRole> effectiveGroupClientRoles = proofGeneration.getEffectiveGroupClientRoles(group);
        UserModel user = session.users().getUserById(realm, getEntity().getId());
        proofGeneration.regenerateProofsForMembers(effectiveGroupClientRoles, List.of(user));
    }

    @Override
    public void grantRole(RoleModel roleModel) {

        try {
            RoleModel role = wrapRoleModel(roleModel, session, realm);
            RealmModel adminRealm = session.realms().getRealmByName(Config.getAdminRealm());
            super.grantRole(role);
            boolean isTempAdmin = this.user.getAttributes().stream()
                    .anyMatch(attribute -> attribute.getName().equalsIgnoreCase(Constants.IS_TEMP_ADMIN_ATTR_NAME));
            if (isTempAdmin) {
                return;
            }

            // Check if this has already been action before
            List<TideUserRoleMappingDraftEntity> entity = em.createNamedQuery("getUserRoleAssignmentDraftEntityByStatusAndAction", TideUserRoleMappingDraftEntity.class)
                    .setParameter("user", getEntity())
                    .setParameter("roleId", role.getId())
                    .setParameter("draftStatus", DraftStatus.DRAFT)
                    .setParameter("actionType", ActionType.CREATE)
                    .getResultList();

            // Add draft request
            if (entity == null || entity.isEmpty()) {
                // Create a draft record for new user role mapping
                TideUserRoleMappingDraftEntity draftUserRole = new TideUserRoleMappingDraftEntity();
                draftUserRole.setId(KeycloakModelUtils.generateId());
                draftUserRole.setRoleId(role.getId());
                draftUserRole.setUser(this.getEntity());
                draftUserRole.setAction(ActionType.CREATE);
                draftUserRole.setDraftStatus(DraftStatus.DRAFT);
                em.persist(draftUserRole);

                WorkflowParams params = new WorkflowParams(DraftStatus.DRAFT, false, ActionType.CREATE);
                processor.executeWorkflow(session, draftUserRole, em, WorkflowType.REQUEST, params);
            }

        } catch(Exception e){
                throw new RuntimeException(e);
        }
    }


    @Override
    public void deleteRoleMapping(RoleModel roleModel) {
        try {
            RoleModel role = wrapRoleModel(roleModel, session, realm);

            String igaAttribute = session.getContext().getRealm().getAttribute("isIGAEnabled");
            boolean isIGAEnabled = igaAttribute != null && igaAttribute.equalsIgnoreCase("true");

            if (!isIGAEnabled){
                List<TideUserRoleMappingDraftEntity> draftEntities = getDraftEntities(role);
                deleteRoleAndProofRecords(role, draftEntities);
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

            WorkflowParams params = new WorkflowParams(DraftStatus.DRAFT, true, ActionType.DELETE);
            processor.executeWorkflow(session, committedEntity, em, WorkflowType.REQUEST, params);
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

//    private List<ClientModel> getUniqueClientList(KeycloakSession session, RealmModel realm, RoleModel role, EntityManager em) {
//        List<ClientModel> clientList = session.clients().getClientsStream(realm)
//                .map(client -> new TideClientAdapter(realm, em, session, em.find(ClientEntity.class, client.getId())))
//                .filter(TideClientAdapter::isFullScopeAllowed)
//                .collect(Collectors.toList());
//
//        if ( role.isClientRole()){
//            clientList.add((ClientModel) role.getContainer());
//        }
//
//        // need to expand role and get the clientlist here too
//        RoleEntity roleEntity = em.getReference(RoleEntity.class, role.getId());
//        Set<TideRoleAdapter> wrappedRoles = new HashSet<>();
//        wrappedRoles.add(new TideRoleAdapter(session, realm, em, roleEntity));
//
//        Set<RoleModel> activeCompositeRoles = RoleUtils.expandCompositeRoles(wrappedRoles,DraftStatus.ACTIVE);
//
//        activeCompositeRoles.forEach(activeCompRole -> {
//            if (activeCompRole.getContainer() instanceof ClientModel){
//                clientList.add((ClientModel) activeCompRole.getContainer());
//            }
//        });
//
//        return clientList.stream().distinct().collect(Collectors.toList());
//    }

    private void deleteRoleAndProofRecords(RoleModel role, List<TideUserRoleMappingDraftEntity> activeDraftEntities) {
        String recordId = activeDraftEntities == null || activeDraftEntities.isEmpty() ? getDraftEntities(role).get(0).getId() : activeDraftEntities.get(0).getId();
        deleteProofRecordForUser(recordId);
        deleteUserRoleMappingDraftsByRole(role.getId());

        if (role.isComposite()) {
            deleteCompositeRoleProofRecords(role);
        }
        super.deleteRoleMapping(role);
    }

    private void deleteUserRoleMappingDraftsByRole(String roleId) {
        em.createNamedQuery("deleteUserRoleMappingDraftsByRole")
                .setParameter("roleId", roleId)
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
                .setParameter("composite", TideRolesUtil.toRoleEntity(role, em))
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
