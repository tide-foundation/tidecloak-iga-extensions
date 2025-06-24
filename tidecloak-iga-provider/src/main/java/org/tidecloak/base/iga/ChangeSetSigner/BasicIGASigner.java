package org.tidecloak.base.iga.ChangeSetSigner;

import jakarta.persistence.EntityManager;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminAuth;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;

import java.util.List;

public class BasicIGASigner implements ChangeSetSigner{
    @Override
    public Response sign(ChangeSetRequest changeSet, EntityManager em, KeycloakSession session, RealmModel realm, Object draftEntity, AdminAuth adminAuth) throws Exception {
        // Approve directly without cryptographic signing
        List<AccessProofDetailEntity> proofDetails = BasicIGAUtils.getAccessProofs(em, BasicIGAUtils.getEntityChangeRequestId(draftEntity), changeSet.getType());;
        BasicIGAUtils.approveChangeRequest(session, adminAuth.getUser(), proofDetails, em, changeSet);
        BasicIGAUtils.updateDraftStatus(session, changeSet.getType(), changeSet.getChangeSetId(), changeSet.getActionType(), draftEntity);
        em.flush();
        return Response.ok("Change set approved by realm admin").build();
    }
}
