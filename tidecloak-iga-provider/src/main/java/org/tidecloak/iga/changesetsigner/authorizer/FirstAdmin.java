package org.tidecloak.iga.changesetsigner.authorizer;// FirstAdminSigner.java
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.ws.rs.core.Response;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.services.resources.admin.AdminAuth;
import org.midgard.models.InitializerCertificateModel.InitializerCertifcate;
import org.midgard.models.UserContext.UserContext;
import org.tidecloak.iga.changesetprocessors.models.ChangeSetRequest;
import org.tidecloak.iga.utils.IGAUtils;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.AuthorizerEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.drafting.TideRoleDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;

import java.util.*;
import java.util.stream.Stream;

public class FirstAdmin implements Authorizer {

    @Override
    public Response signWithAuthorizer(ChangeSetRequest changeSet, EntityManager em, KeycloakSession session, RealmModel realm, Object draftEntity, AdminAuth auth, AuthorizerEntity authorizer, ComponentModel componentModel) throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(changeSet.getChangeSetId(), changeSet.getType()));
        if (changesetRequestEntity == null){
            throw new Exception("No change-set request entity found with this recordId " + changeSet.getChangeSetId());
        }
        // Fetch proof details
        List<AccessProofDetailEntity> proofDetails = IGAUtils.getAccessProofs(em, IGAUtils.getEntityId(changeSet), changeSet.getType());

        List<UserContext> userContexts = new ArrayList<>();
        proofDetails.sort(Comparator.comparingLong(AccessProofDetailEntity::getCreatedTimestamp).reversed());
        proofDetails.forEach(p -> {
            userContexts.add(new UserContext(p.getProofDraft()));
        });
        Stream<UserContext> adminContexts = userContexts.stream().filter(x -> x.getInitCertHash() != null);
        Stream<UserContext> normalUserContext = userContexts.stream().filter(x -> x.getInitCertHash() == null);
        List<UserContext> orderedContext = Stream.concat(adminContexts, normalUserContext).toList();

        RoleModel tideRole = session.clients().getClientByClientId(realm, Constants.REALM_MANAGEMENT_CLIENT_ID).getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
        RoleEntity role = em.getReference(RoleEntity.class, tideRole.getId());
        TideRoleDraftEntity tideRoleEntity = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class)
                .setParameter("role", role).getSingleResult();

        InitializerCertifcate cert = InitializerCertifcate.FromString(tideRoleEntity.getInitCert());

        if(isAssigningTideRealmAdminRole(draftEntity, session)){
            List<String> signatures = IGAUtils.signInitialTideAdmin(componentModel.getConfig(), orderedContext.toArray(new UserContext[0]), cert, authorizer, changesetRequestEntity);
            Stream<AccessProofDetailEntity> adminproofs = proofDetails.stream().filter(x -> {
                UserContext userContext = new UserContext(x.getProofDraft());
                if(userContext.getInitCertHash() != null) {
                    return true;
                }
                return false;
            });
            Stream<AccessProofDetailEntity> normalProofs = proofDetails.stream().filter(x -> {
                UserContext userContext = new UserContext(x.getProofDraft());
                if(userContext.getInitCertHash() == null) {
                    return true;
                }
                return false;
            });

            List<AccessProofDetailEntity> orderedProofDetails = Stream.concat(adminproofs, normalProofs).toList();
            tideRoleEntity.setInitCertSig(signatures.get(0));
            for(int i = 0; i < orderedProofDetails.size(); i++){
                orderedProofDetails.get(i).setSignature(signatures.get(i + 1));
            }
            em.flush();
        } else {
            List<String> signatures = IGAUtils.signContextsWithVrk(componentModel.getConfig(), orderedContext.toArray(new UserContext[0]), authorizer, changesetRequestEntity);
            for(int i = 0; i < userContexts.size(); i++){
                proofDetails.get(i).setSignature(signatures.get(i));
            }
            em.flush();
        }

        Map<String, String> response = new HashMap<>();
        response.put("message", "Change set signed successfully.");
        response.put("uri", "");
        response.put("changeSetRequests", "");
        response.put("requiresApprovalPopup", "false");


        IGAUtils.updateDraftStatus(changeSet.getType(), changeSet.getActionType(), draftEntity);

        return Response.ok(objectMapper.writeValueAsString(response)).build();
    }

    private boolean isAssigningTideRealmAdminRole(Object draftEntity, KeycloakSession session){
        if(draftEntity instanceof TideUserRoleMappingDraftEntity tideUserRoleMappingDraftEntity){
            RoleModel tideRole = session.getContext().getRealm().getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID).getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
            return tideUserRoleMappingDraftEntity.getRoleId().equals(tideRole.getId());
        }
        return false;

    }
}
