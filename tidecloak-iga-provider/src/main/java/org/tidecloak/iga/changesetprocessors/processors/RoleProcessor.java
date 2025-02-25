package org.tidecloak.iga.changesetprocessors.processors;

import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.models.*;
import org.keycloak.representations.AccessToken;
import org.tidecloak.iga.changesetprocessors.ChangeSetProcessor;
import org.tidecloak.iga.changesetprocessors.models.ChangeSetRequest;
import org.tidecloak.iga.changesetprocessors.utils.TideEntityUtils;
import org.tidecloak.iga.changesetprocessors.utils.UserContextUtils;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.drafting.TideRoleDraftEntity;
import org.tidecloak.iga.interfaces.TideUserAdapter;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Set;

import static org.tidecloak.iga.changesetprocessors.utils.ChangeRequestUtils.getChangeSetRequestFromEntity;
import static org.tidecloak.iga.changesetprocessors.utils.ClientUtils.getUniqueClientList;
import static org.tidecloak.iga.changesetprocessors.utils.UserContextUtils.addRoleToAccessToken;
import static org.tidecloak.iga.changesetprocessors.utils.UserContextUtils.removeRoleFromAccessToken;

public class RoleProcessor implements ChangeSetProcessor<TideRoleDraftEntity> {

    protected static final Logger logger = Logger.getLogger(RoleProcessor.class);

    @Override
    public void cancel(KeycloakSession session, TideRoleDraftEntity entity, EntityManager em, ActionType actionType){
        List<AccessProofDetailEntity> pendingChanges = em.createNamedQuery("getProofDetailsForDraftByChangeSetTypeAndId", AccessProofDetailEntity.class)
                .setParameter("recordId", entity.getId())
                .setParameter("changesetType", ChangeSetType.ROLE)
                .getResultList();
        pendingChanges.forEach(em::remove);

        List<TideRoleDraftEntity> pendingDrafts = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class)
                .setParameter("role", entity.getRole())
                .getResultList();

        pendingDrafts.forEach(d -> {
            d.setDeleteStatus(DraftStatus.NULL);
        });
        em.flush();
    }

    @Override
    public void commit(KeycloakSession session, ChangeSetRequest change, TideRoleDraftEntity entity, EntityManager em, Runnable commitCallback) throws Exception {
        logger.debug(String.format(
                "Starting workflow: COMMIT. Processor: %s, Action: %s, Entity ID: %s",
                this.getClass().getSimpleName(),
                change.getActionType(),
                entity.getId()
        ));

        RealmModel realm = session.getContext().getRealm();

        Runnable callback = () -> {
            try {
                commitRoleChangeRequest(realm, entity, change, em);
            } catch (Exception e) {
                throw new RuntimeException("Error during commit callback", e);
            }
        };

        ChangeSetProcessor.super.commit(session, change, entity, em, callback);

        // Log successful completion
        logger.debug(String.format(
                "Successfully processed workflow: COMMIT. Processor: %s, Mapping ID: %s",
                this.getClass().getSimpleName(),
                entity.getId()
        ));
    }

    @Override
    public void request(KeycloakSession session, TideRoleDraftEntity entity, EntityManager em, ActionType action, Runnable callback, ChangeSetType changeSetType) {
        try {
            // Log the start of the request with detailed context
            logger.debug(String.format(
                    "Starting workflow: REQUEST. Processor: %s, Action: %s, Entity ID: %s",
                    this.getClass().getSimpleName(),
                    action,
                    entity.getId()
            ));
            ChangeSetProcessor.super.createChangeRequestEntity(em, entity.getId(), changeSetType);
            switch (action) {
                case CREATE:
                    logger.debug(String.format("Initiating CREATE action for Mapping ID: %s in workflow: REQUEST", entity.getId()));
                    handleCreateRequest(session, entity, em, callback);
                    break;
                case DELETE:
                    logger.debug(String.format("Initiating DELETE action for Mapping ID: %s in workflow: REQUEST", entity.getId()));
                    handleDeleteRequest(session, entity, em, callback);
                    break;
                default:
                    logger.warn(String.format("Unsupported action type: %s for Mapping ID: %s in workflow: REQUEST", action, entity.getId()));
                    throw new IllegalArgumentException("Unsupported action: " + action);
            }

            // Log successful completion
            logger.debug(String.format(
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
            throw new RuntimeException("Failed to process ROLE request", e);
        }
    }

    @Override
    public void handleCreateRequest(KeycloakSession session, TideRoleDraftEntity entity, EntityManager em, Runnable callback) throws Exception {
        throw new Exception("ROLE creation not yet implementated");
    }

    @Override
    public void handleDeleteRequest(KeycloakSession session, TideRoleDraftEntity entity, EntityManager em, Runnable callback) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        RoleModel role = realm.getRoleById(entity.getRole().getId());
        List<UserModel> users = session.users().searchForUserStream(realm, new HashMap<>()).filter(u -> u.hasRole(role)).toList();

        List<ClientModel> clientList = getUniqueClientList(session, realm, role);
        clientList.forEach(client -> {
            users.forEach(user -> {
                UserModel wrappedUser = TideEntityUtils.wrapUserModel(user, session, realm);
                try {
                    ChangeSetProcessor.super.generateAndSaveTransformedUserContextDraft(session, em, realm, client, wrappedUser, entity.getId(),ChangeSetType.ROLE, entity);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
        });

    }

    @Override
    public void updateAffectedUserContextDrafts(KeycloakSession session, AccessProofDetailEntity affectedUserContextDraft, Set<RoleModel> uniqRoles, ClientModel client, TideUserAdapter user, EntityManager em) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        TideRoleDraftEntity affectedRoleEntity = em.find(TideRoleDraftEntity.class, affectedUserContextDraft.getRecordId());
        if (affectedRoleEntity == null || (affectedRoleEntity.getDraftStatus() == DraftStatus.ACTIVE && (affectedRoleEntity.getDeleteStatus() == null || affectedRoleEntity.getDeleteStatus().equals(DraftStatus.NULL))))
        {
            return;
        }
        ChangeSetRequest affectedChangeRequest = getChangeSetRequestFromEntity(session, affectedRoleEntity);
        if(affectedChangeRequest.getActionType() == ActionType.DELETE) {
            affectedRoleEntity.setDeleteStatus(DraftStatus.DRAFT);
        }else if (affectedChangeRequest.getActionType() == ActionType.CREATE) {
            affectedRoleEntity.setDraftStatus(DraftStatus.DRAFT);
        }

        String userContextDraft = ChangeSetProcessor.super.generateTransformedUserContext(session, realm, client, user, "openid", affectedRoleEntity);
        affectedUserContextDraft.setProofDraft(userContextDraft);
    }

    @Override
    public RoleModel getRoleRequestFromEntity(KeycloakSession session,  RealmModel realm,TideRoleDraftEntity entity) {
        return realm.getRoleById(entity.getRole().getId());
    }

    @Override
    public AccessToken transformUserContext(AccessToken token, KeycloakSession session, TideRoleDraftEntity entity, UserModel user, ClientModel clientModel){
        RealmModel realm = session.getContext().getRealm();
        RoleModel role = realm.getRoleById(entity.getRole().getId());

        Set<RoleModel> tideRoleModel = Set.of(TideEntityUtils.toTideRoleAdapter(role, session, realm));

        UserContextUtils userContextUtils = new UserContextUtils();
        Set<RoleModel> roleModelSet = userContextUtils.expandActiveCompositeRoles(session, tideRoleModel);

        ChangeSetRequest change = getChangeSetRequestFromEntity(session, entity);
        roleModelSet.forEach(r -> {
            if(change.getActionType().equals(ActionType.CREATE)){
                addRoleToAccessToken(token, r);
            } else if (change.getActionType().equals(ActionType.DELETE)) {
                removeRoleFromAccessToken(token, r);
            }
        });
        userContextUtils.normalizeAccessToken(token, clientModel.isFullScopeAllowed());
        return token;
    }


    private void commitRoleChangeRequest(RealmModel realm, TideRoleDraftEntity entity, ChangeSetRequest change, EntityManager em) {;
        RoleModel role = realm.getRoleById(entity.getRole().getId());
        if (role == null) return;

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
            realm.removeRole(role);
            cleanupRoleRecords(em, entity);
        }
    }


    private void cleanupRoleRecords(EntityManager em, TideRoleDraftEntity mapping) {
        List<String> recordsToRemove = new ArrayList<>(em.createNamedQuery("getUserRoleMappingDraftsByRole", String.class)
                .setParameter("roleId", mapping.getRole().getId())
                .getResultList());

        em.createNamedQuery("deleteUserRoleMappingDraftsByRole")
                .setParameter("roleId", mapping.getRole().getId())
                .executeUpdate();

        recordsToRemove.addAll(em.createNamedQuery("selectIdsForRemoval", String.class)
                .setParameter("role", mapping.getRole())
                .getResultList());
        recordsToRemove.add(mapping.getId());

        em.createNamedQuery("removeDraftRequestsOnRemovalOfRole")
                .setParameter("role", mapping.getRole())
                .executeUpdate();

        recordsToRemove.forEach(id -> em.createNamedQuery("deleteProofRecords")
                .setParameter("recordId", id)
                .executeUpdate());
    }
}
