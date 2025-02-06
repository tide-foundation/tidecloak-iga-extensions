package org.tidecloak.iga.interfaces;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import org.keycloak.Config;
import org.keycloak.models.*;
import org.keycloak.models.jpa.RoleAdapter;
import org.keycloak.models.jpa.entities.RoleEntity;

import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.tidecloak.iga.changesetprocessors.ChangeSetProcessorFactory;
import org.tidecloak.iga.changesetprocessors.models.ChangeSetRequest;
import org.tidecloak.iga.changesetprocessors.utils.TideEntityUtils;
import org.tidecloak.shared.Constants;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.WorkflowType;
import org.tidecloak.shared.enums.models.WorkflowParams;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.jpa.entities.drafting.TideCompositeRoleMappingDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;

import java.util.*;
import java.util.stream.Stream;

import static org.tidecloak.iga.changesetprocessors.utils.ChangeRequestUtils.getChangeSetRequestFromEntity;
import static org.tidecloak.iga.changesetprocessors.utils.RoleUtils.commitDefaultRolesOnInitiation;

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
        // Dont draft for master realm
        RealmModel masterRealm = session.realms().getRealmByName(Config.getAdminRealm());
        if(realm.equals(masterRealm)){
            super.removeCompositeRole(roleModel);
            return;
        }

        RoleModel role = TideEntityUtils.wrapRoleModel(roleModel, session, realm);
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
                changeSetProcessorFactory.getProcessor(changesetRequest.getType()).updateAffectedUserContexts(session, realm, changesetRequest, committedEntity, em);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

        }else{
            try {
            WorkflowParams params = new WorkflowParams(DraftStatus.DRAFT, true, ActionType.DELETE, ChangeSetType.COMPOSITE_ROLE);
            changeSetProcessorFactory.getProcessor(ChangeSetType.COMPOSITE_ROLE).executeWorkflow(session, committedEntity, em, WorkflowType.REQUEST, params, null);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        em.flush();
    }

    @Override
    public void addCompositeRole(RoleModel roleModel) {
        try {
            RoleEntity entity = toRoleEntity(roleModel);
            for (RoleEntity composite : getEntity().getCompositeRoles()) {
                if (composite.equals(entity)) return;
            }
            super.addCompositeRole(roleModel);
            // Dont draft for master realm
            RealmModel masterRealm = session.realms().getRealmByName(Config.getAdminRealm());
            if(realm.equals(masterRealm)){
                return;
            }
            RoleModel childRole = TideEntityUtils.wrapRoleModel(roleModel, session, realm);
            RoleEntity childEntity = toRoleEntity(childRole);
            TideCompositeRoleMappingDraftEntity draft = new TideCompositeRoleMappingDraftEntity();
            draft.setId(KeycloakModelUtils.generateId());
            draft.setComposite(getEntity());
            draft.setChildRole(childEntity);
            draft.setDraftStatus(DraftStatus.DRAFT);
            draft.setAction(ActionType.CREATE);
            em.persist(draft);

            if (realm.getRoleById(getEntity().getId()).getName().equalsIgnoreCase(Constants.TIDE_REALM_ADMIN)) {
                draft.setDraftStatus(DraftStatus.ACTIVE);
                draft.setAction(ActionType.CREATE);
                em.persist(draft);
                return;
            }
            draft.setDraftStatus(DraftStatus.DRAFT);
            draft.setAction(ActionType.CREATE);
            em.persist(draft);

            WorkflowParams params = new WorkflowParams(DraftStatus.DRAFT, false, ActionType.CREATE, ChangeSetType.COMPOSITE_ROLE);
            changeSetProcessorFactory.getProcessor(ChangeSetType.COMPOSITE_ROLE).executeWorkflow(session, draft, em, WorkflowType.REQUEST, params, null);
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

    public void removeChildRoleFromCompositeRoleRecords(TideCompositeRoleMappingDraftEntity entity){
        deleteCompositeRoleMapping(entity.getComposite(), entity.getChildRole());
        deleteProofRecords(entity.getId());
        RoleModel childRole = session.roles().getRoleById(realm, entity.getChildRole().getId());
        super.removeCompositeRole(childRole);
    }

    public void removeChildRoleFromCompositeRoleRecords(TideCompositeRoleMappingDraftEntity entity, ActionType actionType){
        deleteProofRecords(entity.getId());

        if(!actionType.equals(ActionType.DELETE)) {
            deleteCompositeRoleMapping(entity.getComposite(), entity.getChildRole());
            RoleModel childRole = session.roles().getRoleById(realm, entity.getChildRole().getId());
            super.removeCompositeRole(childRole);
        } else {
            entity.setDeleteStatus(null);
        }
    }
}
