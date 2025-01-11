package org.tidecloak.models;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import org.keycloak.Config;
import org.keycloak.models.*;
import org.keycloak.models.jpa.RoleAdapter;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.models.jpa.entities.RoleEntity;

import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.tidecloak.changeset.ChangeSetProcessor;
import org.tidecloak.changeset.ChangeSetProcessorFactory;
import org.tidecloak.changeset.models.ChangeSetRequest;
import org.tidecloak.enums.ActionType;
import org.tidecloak.enums.ChangeSetType;
import org.tidecloak.enums.WorkflowType;
import org.tidecloak.enums.models.WorkflowParams;
import org.tidecloak.interfaces.DraftChangeSetRequest;
import org.tidecloak.enums.DraftStatus;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.drafting.TideCompositeRoleMappingDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.utils.TideAuthzProofUtil;
import org.tidecloak.utils.TideRolesUtil;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.keycloak.models.ImpersonationConstants.IMPERSONATION_ROLE;
import static org.tidecloak.changeset.utils.ChangeRequestUtils.getChangeSetRequestFromEntity;
import static org.tidecloak.changeset.utils.RoleUtils.commitDefaultRolesOnInitiation;
import static org.tidecloak.models.ChangesetRequestAdapter.getChangesetRequestEntity;

public class TideRoleAdapter extends RoleAdapter {
    private final KeycloakSession session;
    private final RealmModel realm;
    private final ChangeSetProcessorFactory changeSetProcessorFactory = new ChangeSetProcessorFactory();


    public TideRoleAdapter(KeycloakSession session, RealmModel realm, EntityManager em, RoleEntity role) {
        super(session, realm, em, role);
        this.session = session;
        this.realm  = realm;
    }

    @Override
    public void removeCompositeRole(RoleModel roleModel) {
        RoleModel role = TideRolesUtil.wrapRoleModel(roleModel, session, realm);
        RoleEntity roleEntity = toRoleEntity(role);
        List<TideCompositeRoleMappingDraftEntity> entity = findCompositeRoleMappingDrafts(getEntity(), roleEntity, DraftStatus.ACTIVE);
        String igaAttribute = session.getContext().getRealm().getAttribute("isIGAEnabled");
        boolean isIGAEnabled = igaAttribute != null && igaAttribute.equalsIgnoreCase("true");


        if (entity == null || entity.isEmpty() ) {
            handleUncommittedCompositeRole(role, roleEntity);
            return;
        }

        TideCompositeRoleMappingDraftEntity committedEntity = entity.get(0);

        List<TideUserAdapter> activeUsers =  session.users().getRoleMembersStream(realm, realm.getRoleById(getEntity().getId())).map(user -> {
            UserEntity userEntity = em.find(UserEntity.class, user.getId());
            List<TideUserRoleMappingDraftEntity> userRecords = em.createNamedQuery("getUserRoleAssignmentDraftEntityByStatus", TideUserRoleMappingDraftEntity.class)
                    .setParameter("draftStatus", DraftStatus.ACTIVE)
                    .setParameter("user", userEntity)
                    .setParameter("roleId", this.getEntity().getId())
                    .getResultList();


            if(userRecords == null || userRecords.isEmpty()){
                return null;
            }
            return new TideUserAdapter(session, realm, em, userEntity);
        }).filter(Objects::nonNull).toList();

        if(activeUsers.isEmpty() || committedEntity.getDeleteStatus() == DraftStatus.ACTIVE || !isIGAEnabled){
            try {
                ChangeSetRequest changesetRequest = getChangeSetRequestFromEntity(session, committedEntity);
                deleteCompositeRoleMapping(getEntity(), roleEntity);
                deleteProofRecords(committedEntity.getId());
                super.removeCompositeRole(role);
                changeSetProcessorFactory.getProcessor(changesetRequest.getType()).updateAffectedUserContexts(session, changesetRequest, committedEntity, em);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

        }else{
            try {
            ChangeSetRequest changesetRequest = getChangeSetRequestFromEntity(session, committedEntity);
            WorkflowParams params = new WorkflowParams(DraftStatus.DRAFT, true, ActionType.DELETE);
            changeSetProcessorFactory.getProcessor(changesetRequest.getType()).executeWorkflow(session, committedEntity, em, WorkflowType.REQUEST, params, null);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        em.flush();
    }

    @Override
    public void addCompositeRole(RoleModel roleModel) {
        try {
            super.addCompositeRole(roleModel);
            boolean isDefaultRoleCommit = commitDefaultRolesOnInitiation(session, realm, getEntity(), roleModel, em);
            String adminRealmName = Config.getAdminRealm();
            String realmName = roleModel.isClientRole() ? ((ClientModel) roleModel.getContainer()).getRealm().getName() : ((RealmModel) roleModel.getContainer()).getName();
            boolean isDefaultAdminRole = realmName.equalsIgnoreCase(adminRealmName) && AdminRoles.ALL_ROLES.contains(roleModel.getName());

            if (isDefaultRoleCommit || isDefaultAdminRole) {
                return;
            }

            RoleModel childRole = TideRolesUtil.wrapRoleModel(roleModel, session, realm);
            RoleEntity childEntity = toRoleEntity(childRole);
            TideCompositeRoleMappingDraftEntity draft = new TideCompositeRoleMappingDraftEntity();
            draft.setId(KeycloakModelUtils.generateId());
            draft.setComposite(getEntity());
            draft.setChildRole(childEntity);
            draft.setDraftStatus(DraftStatus.DRAFT);
            draft.setAction(ActionType.CREATE);
            em.persist(draft);

            ChangeSetRequest changeSetRequest = getChangeSetRequestFromEntity(session, draft);
            WorkflowParams params = new WorkflowParams(DraftStatus.DRAFT, false, ActionType.CREATE);
            changeSetProcessorFactory.getProcessor(changeSetRequest.getType()).executeWorkflow(session, draft, em, WorkflowType.REQUEST, params, null);
            em.flush();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }


    /**
     *
     * We are returning our TideRoleAdapter here. Everything else works the same as the super.
     *
     */

    @Override
    public Stream<RoleModel> getCompositesStream() {
        Stream<RoleModel> roles = super.getCompositesStream()
                .map(role -> {
                    RoleEntity roleEntity = em.getReference(RoleEntity.class, role.getId());
                    return new TideRoleAdapter(session, realm, em, roleEntity);
                });
        return roles.filter(Objects::nonNull);
    }

    public Stream<RoleModel> getCompositesStreamByStatus(DraftStatus draftStatus) {
        TypedQuery<RoleEntity> query = em.createNamedQuery("filterChildRoleByStatusAndParent", RoleEntity.class);
        query.setParameter("composite", getEntity());
        query.setParameter("draftStatus", draftStatus);

        Stream<RoleModel> roles = query.getResultStream()
                .map(role -> new TideRoleAdapter(session, realm, em, role));

        return roles.filter(Objects::nonNull);

    }

    private RoleEntity toRoleEntity(RoleModel model) {
        if (model instanceof TideRoleAdapter) {
            return ((TideRoleAdapter) model).getEntity();
        }
        return em.getReference(RoleEntity.class, model.getId());
    }


    private void handleUncommittedCompositeRole(RoleModel role, RoleEntity roleEntity) {
        deleteCompositeRoleMapping(getEntity(), roleEntity);

        List<TideCompositeRoleMappingDraftEntity> proofRecords = findCompositeRoleMappingDrafts(getEntity(), roleEntity, DraftStatus.DRAFT);
        if (proofRecords != null && !proofRecords.isEmpty()) {
            deleteProofRecords(proofRecords.get(0).getId());
        }

        super.removeCompositeRole(role);
    }

    private List<TideCompositeRoleMappingDraftEntity> findCompositeRoleMappingDrafts(RoleEntity composite, RoleEntity childRole, DraftStatus status) {
        return em.createNamedQuery("getCompositeRoleMappingDraftByStatus", TideCompositeRoleMappingDraftEntity.class)
                .setParameter("composite", composite)
                .setParameter("childRole", childRole)
                .setParameter("draftStatus", status)
                .getResultList();
    }

    private void deleteCompositeRoleMapping(RoleEntity composite, RoleEntity childRole) {
        em.createNamedQuery("deleteCompositeRoleMapping")
                .setParameter("composite", composite)
                .setParameter("childRole", childRole)
                .executeUpdate();
    }

    private void deleteProofRecords(String recordId) {
        em.createNamedQuery("deleteProofRecords")
                .setParameter("recordId", recordId)
                .executeUpdate();
    }
}
