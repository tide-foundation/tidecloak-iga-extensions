package org.tidecloak.changeset.processors;

import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.tidecloak.changeset.ChangeSetProcessor;
import org.tidecloak.changeset.models.ChangeSetRequest;
import org.tidecloak.enums.ActionType;
import org.tidecloak.enums.DraftStatus;
import org.tidecloak.enums.ChangeSetType;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.drafting.TideCompositeRoleMappingDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.models.TideUserAdapter;
import org.tidecloak.utils.TideRolesUtil;

import java.util.*;

import static org.tidecloak.changeset.utils.ChangeRequestUtils.getChangeSetRequestFromEntity;
import static org.tidecloak.changeset.utils.ClientUtils.getUniqueClientList;

public class CompositeRoleProcessor implements ChangeSetProcessor<TideCompositeRoleMappingDraftEntity> {

    protected static final Logger logger = Logger.getLogger(UserRoleProcessor.class);

    @Override
    public void request(KeycloakSession session, ChangeSetRequest change, TideCompositeRoleMappingDraftEntity entity, EntityManager em, ActionType action) {
        try {
            // Log the start of the request with detailed context
            logger.info(String.format(
                    "Starting workflow: REQUEST. Processor: %s, Action: %s, Entity ID: %s",
                    this.getClass().getSimpleName(),
                    action,
                    entity.getId()
            ));

            switch (action) {
                case CREATE:
                    logger.info(String.format("Initiating CREATE action for Mapping ID: %s in workflow: REQUEST", entity.getId()));
                    handleCreateRequest(session, entity, em);
                    break;
                case DELETE:
                    logger.info(String.format("Initiating DELETE action for Mapping ID: %s in workflow: REQUEST", entity.getId()));
                    handleDeleteRequest(session, entity, em);
                    break;
                default:
                    logger.warn(String.format("Unsupported action type: %s for Mapping ID: %s in workflow: REQUEST", action, entity.getId()));
                    throw new IllegalArgumentException("Unsupported action: " + action);
            }

            // Log successful completion
            logger.info(String.format(
                    "Successfully processed workflow: REQUEST. Processor: %s, Mapping ID: %s",
                    this.getClass().getSimpleName(),
                    entity.getId()
            ));

        } catch (Exception e) {
            logger.error(String.format(
                    "Error in workflow: REQUEST. Processor: %s, Mapping ID: %s, Action: %s. Error: %s",
                    this.getClass().getSimpleName(),
                    entity.getId(),
                    action,
                    e.getMessage()
            ), e);
            throw new RuntimeException("Failed to process COMPOSITE_ROLE request", e);
        }
    }

    @Override
    public  void commit(KeycloakSession session, ChangeSetRequest change, TideCompositeRoleMappingDraftEntity entity, EntityManager em, Runnable commitCallback) throws Exception {
        // Log the start of the request with detailed context
        logger.info(String.format(
                "Starting workflow: COMMIT. Processor: %s, Action: %s, Entity ID: %s",
                this.getClass().getSimpleName(),
                change.getActionType(),
                entity.getId()
        ));

        RealmModel realm = session.getContext().getRealm();
        Runnable callback = () -> {
            try {
                commitCallback(realm, change, entity);
            } catch (Exception e) {
                throw new RuntimeException("Error during commit callback", e);
            }
        };

        ChangeSetProcessor.super.commit(session, change, entity, em, callback);

        // Log successful completion
        logger.info(String.format(
                "Successfully processed workflow: COMMIT. Processor: %s, Entity ID: %s",
                this.getClass().getSimpleName(),
                entity.getId()
        ));
    }

    @Override
    public void handleCreateRequest(KeycloakSession session, TideCompositeRoleMappingDraftEntity entity, EntityManager em) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        RoleEntity parentEntity = entity.getComposite();
        RoleEntity childEntity = entity.getChildRole();
        RoleModel parentRole = realm.getRoleById(parentEntity.getId());
        RoleModel childRole = realm.getRoleById(childEntity.getId());

        List<TideUserAdapter> activeUsers =  session.users().getRoleMembersStream(realm, parentRole).map(user -> {
            UserEntity userEntity = em.find(UserEntity.class, user.getId());
            List<TideUserRoleMappingDraftEntity> userRecords = em.createNamedQuery("getUserRoleAssignmentDraftEntityByStatus", TideUserRoleMappingDraftEntity.class)
                    .setParameter("draftStatus", DraftStatus.ACTIVE)
                    .setParameter("user", userEntity)
                    .setParameter("roleId", parentRole.getId())
                    .getResultList();

            if(userRecords == null || userRecords.isEmpty()){
                return null;
            }
            return new TideUserAdapter(session, realm, em, userEntity);
        }).filter(Objects::nonNull).toList();

        List<ClientModel> clientList = getUniqueClientList(session, realm, childRole, em);

        if ( !activeUsers.isEmpty()){
            clientList.forEach(client -> {
                for (UserModel user : activeUsers) {
                    try {
                        UserEntity userEntity = em.getReference(UserEntity.class, user.getId());
                        List<TideUserRoleMappingDraftEntity> userCompositeRoleDraft = em.createNamedQuery("getUserRoleAssignmentDraftEntityByStatus", TideUserRoleMappingDraftEntity.class)
                                .setParameter("user", userEntity)
                                .setParameter("roleId", parentRole.getId())
                                .setParameter("draftStatus", DraftStatus.ACTIVE)
                                .getResultList();

                        // Check if user has been granted the composite\parent role.
                        if (userCompositeRoleDraft == null || userCompositeRoleDraft.isEmpty()){
                            continue;
                        }

                        UserModel wrappedUser = TideRolesUtil.wrapUserModel(user, session, realm);
                        Set<RoleModel> roleMappings = new HashSet<>();
                        roleMappings.add(childRole);// this is the new role we are adding to the parent role.
                        roleMappings.add(parentRole);// ensure the parent role is in there too

                        ChangeSetProcessor.super.generateAndSaveUserContextDraft(session, em, realm, client, wrappedUser, roleMappings, entity.getId(), ChangeSetType.COMPOSITE_ROLE, ActionType.CREATE, client.isFullScopeAllowed());
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }
            });
        } else {
            // if no users are affected, we commit the request immediately and check any affected change requests and update them.
            entity.setDraftStatus(DraftStatus.ACTIVE);
            ChangeSetRequest changeSetRequest = getChangeSetRequestFromEntity(session, entity);
            ChangeSetProcessor.super.updateAffectedUserContexts(session, changeSetRequest, entity, em);
            em.persist(entity);
            em.flush();
        }
    }

    @Override
    public void handleDeleteRequest(KeycloakSession session, TideCompositeRoleMappingDraftEntity mapping, EntityManager em) {
        mapping.setDeleteStatus(DraftStatus.DRAFT);
        mapping.setTimestamp(System.currentTimeMillis());
        processExistingRequest(session, em, session.getContext().getRealm(), mapping, ActionType.DELETE );
    }

    @Override
    public void updateAffectedUserContextDrafts(KeycloakSession session , AccessProofDetailEntity affectedUserContextDraft, Set<RoleModel> roles, ClientModel client, TideUserAdapter user, EntityManager em) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        TideCompositeRoleMappingDraftEntity affectedCompositeRoleEntity = em.find(TideCompositeRoleMappingDraftEntity.class, affectedUserContextDraft.getRecordId());
        if (affectedCompositeRoleEntity == null || (affectedCompositeRoleEntity.getDraftStatus() == DraftStatus.ACTIVE && affectedCompositeRoleEntity.getDeleteStatus() == null)){
            return;
        }
        ChangeSetRequest affectedChangeRequest = getChangeSetRequestFromEntity(session, affectedCompositeRoleEntity);

        RoleModel childRole = realm.getRoleById(affectedCompositeRoleEntity.getChildRole().getId());
        RoleModel compositeRole = realm.getRoleById(affectedCompositeRoleEntity.getComposite().getId());

        if ( affectedChangeRequest.getActionType() == ActionType.DELETE){
            affectedCompositeRoleEntity.setDeleteStatus(DraftStatus.DRAFT);
        } else if (affectedChangeRequest.getActionType() == ActionType.CREATE) {
            affectedCompositeRoleEntity.setDraftStatus(DraftStatus.DRAFT);
        }

        Set<RoleModel> roleToAddOrDelete = new HashSet<>();
        roleToAddOrDelete.add(childRole);
        roleToAddOrDelete.add(compositeRole);

        String userContextDraft = ChangeSetProcessor.super.generateUserContextDraft(session, realm, client, user, "openid", affectedChangeRequest.getActionType(), roleToAddOrDelete);
        affectedUserContextDraft.setProofDraft(userContextDraft);
    }


    @Override
    public RoleModel getRoleRequestFromEntity(KeycloakSession session, TideCompositeRoleMappingDraftEntity entity) {
        return session.getContext().getRealm().getRoleById(entity.getChildRole().getId());
    }


    private void commitCallback(RealmModel realm, ChangeSetRequest change, TideCompositeRoleMappingDraftEntity entity){
        if (change.getActionType() == ActionType.CREATE) {
            if(entity.getDraftStatus() != DraftStatus.APPROVED){
                throw new RuntimeException("Draft record has not been approved by all admins.");
            }
            entity.setDraftStatus(DraftStatus.ACTIVE);
        } else if (change.getActionType() == ActionType.DELETE) {
            if(entity.getDeleteStatus() != DraftStatus.APPROVED){
                throw new RuntimeException("Deletion has not been approved by all admins.");
            }
            entity.setDeleteStatus(DraftStatus.ACTIVE);
            RoleModel composite = realm.getRoleById(entity.getComposite().getId());
            RoleModel child = realm.getRoleById(entity.getChildRole().getId());
            composite.removeCompositeRole(child);
        }
    }
    private void processExistingRequest(KeycloakSession session, EntityManager em, RealmModel realm, TideCompositeRoleMappingDraftEntity compositeRoleEntity, ActionType action) {
        RoleEntity parentEntity = compositeRoleEntity.getComposite();
        RoleEntity childEntity = compositeRoleEntity.getChildRole();
        RoleModel parentRole = session.getContext().getRealm().getRoleById(parentEntity.getId());
        RoleModel childRole = session.getContext().getRealm().getRoleById(childEntity.getId());

        List<TideUserAdapter> users =  session.users().getRoleMembersStream(realm, parentRole).map(user -> {
                    UserEntity userEntity = em.find(UserEntity.class, user.getId());
                    List<TideUserRoleMappingDraftEntity> userRecords = em.createNamedQuery("getUserRoleAssignmentDraftEntityByStatus", TideUserRoleMappingDraftEntity.class)
                            .setParameter("draftStatus", DraftStatus.ACTIVE)
                            .setParameter("user", userEntity)
                            .setParameter("roleId", parentRole.getId())
                            .getResultList();

                    if(userRecords.isEmpty()){
                        return null;
                    }
                    return new TideUserAdapter(session, realm, em, userEntity);
                })
                .filter(Objects::nonNull)  // Filter out null values before collecting
                .toList();

        if(users.isEmpty()){
            return;
        }
        List<ClientModel> clientList = getUniqueClientList(session, realm, childRole ,em);
        clientList.forEach(client -> users.forEach(user -> {
            try {
                UserModel wrappedUser = TideRolesUtil.wrapUserModel(user, session, realm);
                Set<RoleModel> roleMappings = new HashSet<>(Collections.singleton(childRole));
                ChangeSetProcessor.super.generateAndSaveUserContextDraft(session, em, realm, client, wrappedUser, roleMappings, compositeRoleEntity.getId(), ChangeSetType.COMPOSITE_ROLE, action, client.isFullScopeAllowed());

            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }));
    }

}