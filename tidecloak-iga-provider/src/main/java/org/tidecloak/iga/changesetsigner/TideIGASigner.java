package org.tidecloak.iga.changesetsigner;

import jakarta.persistence.EntityManager;
import jakarta.ws.rs.core.Response;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminAuth;
import org.midgard.models.UserContext.UserContext;
import org.tidecloak.iga.changesetprocessors.models.ChangeSetRequest;
import org.tidecloak.iga.changesetsigner.authorizer.Authorizer;
import org.tidecloak.iga.changesetsigner.authorizer.AuthorizerFactory;
import org.tidecloak.iga.utils.IGAUtils;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.AuthorizerEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.shared.Constants;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class TideIGASigner implements ChangeSetSigner{
    @Override
    public Response sign(ChangeSetRequest changeSet, EntityManager em, KeycloakSession session, RealmModel realm, Object draftEntity, AdminAuth auth) throws Exception {
        // Check for key provider
        ComponentModel componentModel = realm.getComponentsStream()
                .filter(x -> x.getProviderId().equalsIgnoreCase(Constants.TIDE_VENDOR_KEY))  // Use .equals for string comparison
                .findFirst()
                .orElse(null);

        if (componentModel == null) {
            // No key provider, use non-IGA logic
            return null;
        }

        // Fetch authorizers
        List<AuthorizerEntity> realmAuthorizers = em.createNamedQuery("getAuthorizerByProviderIdAndTypes", AuthorizerEntity.class)
                .setParameter("ID", componentModel.getId())
                .setParameter("types", List.of("firstAdmin", "multiAdmin"))
                .getResultList();

        if (realmAuthorizers.isEmpty()) {
            throw new Exception("Authorizer not found for this realm.");
        }




        AuthorizerEntity primaryAuthorizer = realmAuthorizers.get(0);
        String authorizerType = primaryAuthorizer.getType();

        // Delegate to the appropriate sub-strategy
        Authorizer authorizerSigner = AuthorizerFactory.getSigner(authorizerType);
        if (authorizerSigner != null) {
            Response resp = authorizerSigner.signWithAuthorizer(changeSet, em, session, realm, draftEntity, auth, primaryAuthorizer, componentModel);
            IGAUtils.updateDraftStatus(changeSet.getType(), changeSet.getActionType(), draftEntity);
            return  resp;
        }

        return Response.status(Response.Status.BAD_REQUEST).entity("Unsupported authorizer type").build();

//        boolean isFirstAdmin = "firstAdmin".equalsIgnoreCase(primaryAuthorizer.getType());
//        boolean isMultiAdmin = "multiAdmin".equalsIgnoreCase(primaryAuthorizer.getType());
//
//        // Fetch user contexts
//        List<AccessProofDetailEntity> proofDetails = IGAUtils.getAccessProofs(em, IGAUtils.getEntityId(changeSet), changeSet.getType());
//        List<UserContext> userContexts = new ArrayList<>();
//        proofDetails.sort(Comparator.comparingLong(AccessProofDetailEntity::getCreatedTimestamp).reversed());
//        proofDetails.forEach(p -> userContexts.add(new UserContext(p.getProofDraft())));
//
//        // Sign based on authorizer type
//        if (isFirstAdmin && realmAuthorizers.size() == 1) {
//            List<String> signatures = IGAUtils.signInitialTideAdmin(componentModel.getConfig(), userContexts.toArray(new UserContext[0]), primaryAuthorizer, changeSet);
//            for (int i = 0; i < proofDetails.size(); i++) {
//                proofDetails.get(i).setSignature(signatures.get(i));
//            }
//            em.flush();
//            return Response.ok("FirstAdmin signing completed").build();
//        }
//
//        if (isMultiAdmin) {
//            ClientModel realmMgmt = session.getContext().getRealm().getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID);
//            if(!auth.hasAppRole(realmMgmt, org.tidecloak.shared.Constants.TIDE_REALM_ADMIN)){
//                return Response.status(Response.Status.BAD_REQUEST).entity("Current user account does not have permission to sign change requests.").build();
//            }
//            List<String> signatures = IGAUtils.signContextsWithVrk(componentModel.getConfig(), userContexts.toArray(new UserContext[0]), primaryAuthorizer, changeSet);
//            for (int i = 0; i < proofDetails.size(); i++) {
//                proofDetails.get(i).setSignature(signatures.get(i));
//            }
//            em.flush();
//            return Response.ok("MultiAdmin signing completed").build();
//        }
//
//        return Response.status(Response.Status.BAD_REQUEST).entity("Unsupported IGA configuration").build();
    }
}
