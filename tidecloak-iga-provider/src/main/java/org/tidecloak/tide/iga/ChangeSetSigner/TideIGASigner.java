package org.tidecloak.tide.iga.ChangeSetSigner;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminAuth;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.base.iga.ChangeSetSigner.ChangeSetSigner;
import org.tidecloak.base.iga.interfaces.ChangesetRequestAdapter;
import org.tidecloak.tide.iga.authorizer.Authorizer;
import org.tidecloak.tide.iga.authorizer.AuthorizerFactory;
import org.tidecloak.jpa.entities.AuthorizerEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.ServerCertDraftEntity;
import org.tidecloak.shared.Constants;
import org.tidecloak.shared.enums.ChangeSetType;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TideIGASigner implements ChangeSetSigner {
    @Override
    public Response sign(ChangeSetRequest changeSet, EntityManager em, KeycloakSession session, RealmModel realm, List<?> draftEntities, AdminAuth auth) throws Exception {
        // Check for key provider
        ComponentModel componentModel = realm.getComponentsStream()
                .filter(x -> x.getProviderId().equalsIgnoreCase(Constants.TIDE_VENDOR_KEY))  // Use .equals for string comparison
                .findFirst()
                .orElse(null);

        if (componentModel == null) {
            // No key provider, use non-IGA logic
            return null;
        }

        // SERVER_CERT: no enclave popup needed - just record admin approval
        if (changeSet.getType() == ChangeSetType.SERVER_CERT) {
            return signServerCert(changeSet, em, session, auth);
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
            return authorizerSigner.signWithAuthorizer(changeSet, em, session, realm, draftEntities, auth, primaryAuthorizer, componentModel);
        }

        return Response.status(Response.Status.BAD_REQUEST).entity("Unsupported authorizer type").build();
    }

    /**
     * Sign (approve) a SERVER_CERT change-set.
     * No enclave popup needed - the admin just records their approval.
     * The actual certificate signing happens at commit time.
     */
    private Response signServerCert(ChangeSetRequest changeSet, EntityManager em,
                                     KeycloakSession session, AdminAuth auth) throws Exception {
        ObjectMapper mapper = new ObjectMapper();

        ChangesetRequestEntity changesetReq = em.find(
                ChangesetRequestEntity.class,
                new ChangesetRequestEntity.Key(changeSet.getChangeSetId(), ChangeSetType.SERVER_CERT)
        );

        if (changesetReq == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("No SERVER_CERT change-set request found for ID: " + changeSet.getChangeSetId())
                    .build();
        }

        // Check if admin already approved
        String currentUserId = auth.getUser().getId();
        boolean alreadyApproved = changesetReq.getAdminAuthorizations().stream()
                .anyMatch(a -> a.getUserId().equals(currentUserId) && a.getIsApproval());

        if (alreadyApproved) {
            Map<String, Object> error = new HashMap<>();
            error.put("message", "You have already approved this server certificate request.");
            error.put("requiresApprovalPopup", false);
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(mapper.writeValueAsString(error))
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        // Record the admin's approval
        ChangesetRequestAdapter.saveAdminAuthorizaton(
                session,
                ChangeSetType.SERVER_CERT.name(),
                changeSet.getChangeSetId(),
                changeSet.getActionType() != null ? changeSet.getActionType().name() : "CREATE",
                auth.getUser()
        );

        // Return simple approval response - no enclave popup
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Server certificate request approved.");
        response.put("changesetId", changeSet.getChangeSetId());
        response.put("requiresApprovalPopup", false);

        return Response.ok(mapper.writeValueAsString(response))
                .type(MediaType.APPLICATION_JSON)
                .build();
    }
}
