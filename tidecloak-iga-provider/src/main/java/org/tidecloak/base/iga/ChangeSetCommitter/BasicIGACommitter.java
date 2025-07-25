package org.tidecloak.base.iga.ChangeSetCommitter;

import jakarta.persistence.EntityManager;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminAuth;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.shared.enums.WorkflowType;
import org.tidecloak.shared.enums.models.WorkflowParams;

public class BasicIGACommitter implements ChangeSetCommitter{
    @Override
    public Response commit(ChangeSetRequest changeSet, EntityManager em, KeycloakSession session, RealmModel realm, Object draftEntity, AdminAuth auth) throws Exception {
        org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessorFactory processorFactory = new org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessorFactory();
        WorkflowParams workflowParams = new WorkflowParams(null, false, null, changeSet.getType());
        processorFactory.getProcessor(changeSet.getType()).executeWorkflow(session, draftEntity, em, WorkflowType.COMMIT, workflowParams, null);
        return Response.ok("Change set approved and committed").build();

    }
}
