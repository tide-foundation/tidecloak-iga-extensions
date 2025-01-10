package org.tidecloak.changeset.utils;

import org.keycloak.models.KeycloakSession;
import org.tidecloak.changeset.models.ChangeSetRequest;
import org.tidecloak.enums.ActionType;
import org.tidecloak.enums.ChangeSetType;
import org.tidecloak.jpa.entities.drafting.TideCompositeRoleMappingDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;

public class ChangeRequestUtils {

    public static ChangeSetRequest getChangeSetRequestFromEntity(KeycloakSession session, Object entity) {
        ChangeSetRequest changeSetRequest = new ChangeSetRequest();

        if (entity instanceof TideUserRoleMappingDraftEntity userRoleEntity) {
            ActionType actionType = userRoleEntity.getDeleteStatus() != null ? ActionType.DELETE : ActionType.CREATE;
            changeSetRequest.setChangeSetId(userRoleEntity.getId());
            changeSetRequest.setType(ChangeSetType.USER_ROLE);
            changeSetRequest.setActionType(actionType);


        } else if (entity instanceof TideCompositeRoleMappingDraftEntity compositeRoleEntity) {
            ActionType actionType = compositeRoleEntity.getDeleteStatus() != null ? ActionType.DELETE : ActionType.CREATE;
            changeSetRequest.setChangeSetId(compositeRoleEntity.getId());
            changeSetRequest.setType(ChangeSetType.COMPOSITE_ROLE);
            changeSetRequest.setActionType(actionType);
        } else {
            throw new IllegalArgumentException("Unsupported entity type: " + entity.getClass().getSimpleName());
        }

        return changeSetRequest;
    }
}
