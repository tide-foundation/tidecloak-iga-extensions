package org.tidecloak.iga.ChangeSetProcessors.utils;

import jakarta.persistence.EntityManager;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.tidecloak.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.drafting.TideClientDraftEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.jpa.entities.drafting.TideCompositeRoleMappingDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideRoleDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;

public class ChangeRequestUtils {

    public static ChangeSetRequest getChangeSetRequestFromEntity(KeycloakSession session, Object entity) {
        ChangeSetRequest changeSetRequest = new ChangeSetRequest();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        if (entity instanceof TideUserRoleMappingDraftEntity userRoleEntity) {
            ActionType actionType = userRoleEntity.getDeleteStatus() != null ? ActionType.DELETE : ActionType.CREATE;
            changeSetRequest.setChangeSetId(userRoleEntity.getChangeRequestId());
            changeSetRequest.setType(ChangeSetType.USER_ROLE);
            changeSetRequest.setActionType(actionType);

        } else if (entity instanceof TideCompositeRoleMappingDraftEntity compositeRoleEntity) {
            ActionType actionType = compositeRoleEntity.getDeleteStatus() != null ? ActionType.DELETE : ActionType.CREATE;
            changeSetRequest.setChangeSetId(compositeRoleEntity.getChangeRequestId());
            changeSetRequest.setType(ChangeSetType.COMPOSITE_ROLE);
            changeSetRequest.setActionType(actionType);
        } else if (entity instanceof TideRoleDraftEntity roleEntity) {
            ActionType actionType = roleEntity.getDeleteStatus() != null ? ActionType.DELETE : ActionType.CREATE;
            changeSetRequest.setChangeSetId(roleEntity.getChangeRequestId());
            changeSetRequest.setType(ChangeSetType.ROLE);
            changeSetRequest.setActionType(actionType);
        } else if (entity instanceof TideClientDraftEntity draftEntity) {
            boolean isFullScopeEnabledActive = draftEntity.getFullScopeEnabled() != null
                    && draftEntity.getFullScopeEnabled().equals(DraftStatus.ACTIVE);
            boolean isFullScopeDisabledActive = draftEntity.getFullScopeDisabled() != null
                    && draftEntity.getFullScopeDisabled().equals(DraftStatus.ACTIVE);

            // Ensure that both cannot be ACTIVE simultaneously
            if (isFullScopeEnabledActive && isFullScopeDisabledActive) {
                throw new IllegalStateException("Both FullScopeEnabled and FullScopeDisabled cannot be active at the same time.");
            }

            if((isFullScopeDisabledActive && draftEntity.getFullScopeEnabled().equals(DraftStatus.NULL)) || isFullScopeEnabledActive && draftEntity.getFullScopeDisabled().equals(DraftStatus.NULL)){
                changeSetRequest.setChangeSetId(draftEntity.getChangeRequestId());
                changeSetRequest.setType(ChangeSetType.CLIENT);
                changeSetRequest.setActionType(ActionType.CREATE);
                return changeSetRequest;
            }

            // Determine the ActionType based on the statuses
            ActionType actionType;
            if (isFullScopeDisabledActive) {
                actionType = ActionType.CREATE;
            } else if (isFullScopeEnabledActive) {
                actionType = ActionType.DELETE;
            } else {
                throw new IllegalStateException("Invalid status transition. Check FullScopeEnabled and FullScopeDisabled states.");
            }

            // Set the change set request
            changeSetRequest.setChangeSetId(draftEntity.getChangeRequestId());
            changeSetRequest.setType(ChangeSetType.CLIENT_FULLSCOPE);
            changeSetRequest.setActionType(actionType);
        }
        else {
            throw new IllegalArgumentException("Unsupported entity type: " + entity.getClass().getSimpleName());
        }

        return changeSetRequest;
    }

    public static ChangeSetRequest getChangeSetRequestFromEntity(KeycloakSession session, Object entity, ChangeSetType type) {
        ChangeSetRequest changeSetRequest = new ChangeSetRequest();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

        if (entity instanceof TideUserRoleMappingDraftEntity userRoleEntity) {
            ActionType actionType = userRoleEntity.getDeleteStatus() != null ? ActionType.DELETE : ActionType.CREATE;
            changeSetRequest.setChangeSetId(userRoleEntity.getChangeRequestId());
            changeSetRequest.setType(ChangeSetType.USER_ROLE);
            changeSetRequest.setActionType(actionType);

        } else if (entity instanceof TideCompositeRoleMappingDraftEntity compositeRoleEntity) {
            ActionType actionType = compositeRoleEntity.getDeleteStatus() != null ? ActionType.DELETE : ActionType.CREATE;
            changeSetRequest.setChangeSetId(compositeRoleEntity.getChangeRequestId());
            changeSetRequest.setType(ChangeSetType.COMPOSITE_ROLE);
            changeSetRequest.setActionType(actionType);
        } else if (entity instanceof TideRoleDraftEntity roleEntity) {
            ActionType actionType = roleEntity.getDeleteStatus() != null ? ActionType.DELETE : ActionType.CREATE;
            changeSetRequest.setChangeSetId(roleEntity.getChangeRequestId());
            changeSetRequest.setType(ChangeSetType.ROLE);
            changeSetRequest.setActionType(actionType);
        } else if (entity instanceof TideClientDraftEntity draftEntity) {
            if(type.equals(ChangeSetType.CLIENT)){
                changeSetRequest.setChangeSetId(draftEntity.getChangeRequestId());
                changeSetRequest.setType(ChangeSetType.CLIENT);
                changeSetRequest.setActionType(ActionType.CREATE);
                return changeSetRequest;
            }

            boolean isFullScopeEnabledActive = draftEntity.getFullScopeEnabled() != null
                    && draftEntity.getFullScopeEnabled().equals(DraftStatus.ACTIVE);
            boolean isFullScopeDisabledActive = draftEntity.getFullScopeDisabled() != null
                    && draftEntity.getFullScopeDisabled().equals(DraftStatus.ACTIVE);

            // Ensure that both cannot be ACTIVE simultaneously
            if (isFullScopeEnabledActive && isFullScopeDisabledActive) {
                throw new IllegalStateException("Both FullScopeEnabled and FullScopeDisabled cannot be active at the same time.");
            }

            // Determine the ActionType based on the statuses
            ActionType actionType;
            if (isFullScopeDisabledActive) {
                actionType = ActionType.CREATE;
            } else if (isFullScopeEnabledActive) {
                actionType = ActionType.DELETE;
            } else {
                throw new IllegalStateException("Invalid status transition. Check FullScopeEnabled and FullScopeDisabled states.");
            }

            // Set the change set request
            changeSetRequest.setChangeSetId(draftEntity.getChangeRequestId());
            changeSetRequest.setType(ChangeSetType.CLIENT_FULLSCOPE);
            changeSetRequest.setActionType(actionType);
        }
        else {
            throw new IllegalArgumentException("Unsupported entity type: " + entity.getClass().getSimpleName());
        }

        return changeSetRequest;
    }


    private static ChangeSetType getChangeSetType(EntityManager em, String recordId, ChangeSetType changeSetType){

        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(recordId, changeSetType));
        if(changesetRequestEntity == null) {
            throw new RuntimeException("No changeSet found with id: " + recordId);
        }
        return changesetRequestEntity.getChangesetType();

    }
}
