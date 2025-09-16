package org.tidecloak.base.iga.ChangeSetProcessors;

import jakarta.persistence.EntityManager;
import org.keycloak.models.KeycloakSession;
import org.tidecloak.shared.enums.WorkflowType;
import org.tidecloak.shared.enums.models.WorkflowParams;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;

import java.util.Collections;
import java.util.List;

public interface ChangeSetProcessor {

    default void executeWorkflow(KeycloakSession session,
                                 Object entity,
                                 EntityManager em,
                                 WorkflowType workflow,
                                 WorkflowParams params,
                                 Object context) throws Exception {
        // No-op in compat layer; replaced by preview/replay pipeline.
    }

    default List<ChangesetRequestEntity> combineChangeRequests(KeycloakSession session,
                                                               List<Object> entities,
                                                               EntityManager em) throws Exception {
        // No-op combine in compat; UI-side bundling now uses /token-preview/bundle.
        return Collections.emptyList();
    }
}
