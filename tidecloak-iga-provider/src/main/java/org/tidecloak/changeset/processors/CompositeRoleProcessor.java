package org.tidecloak.changeset.processors;

import jakarta.persistence.EntityManager;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.tidecloak.changeset.ChangeSetProcessor;
import org.tidecloak.changeset.models.ChangeSetRequest;
import org.tidecloak.enums.ActionType;
import org.tidecloak.enums.DraftStatus;
import org.tidecloak.interfaces.ChangeSetType;
import org.tidecloak.jpa.entities.drafting.TideCompositeRoleMappingDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.jpa.models.TideUserAdapter;
import org.tidecloak.jpa.utils.TideRolesUtil;

import java.util.*;

import static org.tidecloak.changeset.utils.ClientUtils.getUniqueClientList;

public class CompositeRoleProcessor implements ChangeSetProcessor<TideCompositeRoleMappingDraftEntity> {

    @Override
    public void handleCreateRequest(KeycloakSession session, TideCompositeRoleMappingDraftEntity mapping, EntityManager em) {

        RealmModel realm = session.getContext().getRealm();
        RoleEntity parentEntity = mapping.getComposite();
        RoleEntity childEntity = mapping.getChildRole();
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

                        this.generateAndSaveUserContextDraft(session, em, realm, client, wrappedUser, roleMappings, mapping.getId(), ChangeSetType.COMPOSITE_ROLE, ActionType.CREATE, client.isFullScopeAllowed());
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }
            });
        }
    }

    @Override
    public void handleDeleteRequest(KeycloakSession session, TideCompositeRoleMappingDraftEntity mapping, EntityManager em) {
        mapping.setDeleteStatus(DraftStatus.DRAFT);
        mapping.setTimestamp(System.currentTimeMillis());
        processExistingRequest(session, em, session.getContext().getRealm(), mapping, ActionType.DELETE );
    }

    @Override
    public void updateAffectedChangeRequests(KeycloakSession session, ChangeSetRequest change, TideCompositeRoleMappingDraftEntity entity, EntityManager em, List<ClientModel> affectedClients) {

    }

    @Override
    public RoleModel getRoleRequestFromEntity(KeycloakSession session, TideCompositeRoleMappingDraftEntity entity) {
        return session.getContext().getRealm().getRoleById(entity.getChildRole().getId());
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
                this.generateAndSaveUserContextDraft(session, em, realm, client, wrappedUser, roleMappings, compositeRoleEntity.getId(), ChangeSetType.COMPOSITE_ROLE, action, client.isFullScopeAllowed());

            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }));
    }

}