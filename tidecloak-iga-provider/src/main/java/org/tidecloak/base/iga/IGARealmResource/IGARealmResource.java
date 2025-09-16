// 
package org.tidecloak.base.iga.IGARealmResource;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.persistence.NoResultException;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.cache.UserCache;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.tidecloak.base.iga.ChangeSetCommitter.ChangeSetCommitter;
import org.tidecloak.base.iga.ChangeSetCommitter.ChangeSetCommitterFactory;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequestList;
import org.tidecloak.base.iga.interfaces.ChangesetRequestAdapter;
import org.tidecloak.base.iga.interfaces.models.*;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.drafting.*;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.shared.enums.WorkflowType;
import org.tidecloak.shared.enums.models.WorkflowParams;

import java.util.*;
import java.util.stream.Collectors;

import static org.tidecloak.shared.utils.UserContextDraftUtil.findDraftsNotInAccessProof;

public class IGARealmResource {

    protected static final Logger logger = Logger.getLogger(IGARealmResource.class);
    private final KeycloakSession session;
    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;

    public IGARealmResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth) {
        this.session = session;
        this.realm = realm;
        this.auth = auth;
    }

    // ---- Unchanged helper groups/roles/clients processing methods (omitted for brevity) ----
    // NOTE: Keep your existing methods here; no dependency on old processors remains.

    @POST @Path("toggle-iga") @Produces(MediaType.TEXT_PLAIN)
    public Response toggleIGA(@FormParam("isIGAEnabled") boolean isEnabled) throws Exception {
        try {
            RealmModel masterRealm = session.realms().getRealmByName(Config.getAdminRealm());
            if (realm.equals(masterRealm)) return buildResponse(400, "Master realm does not support IGA.");

            EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
            auth.realm().requireManageRealm();
            session.getContext().getRealm().setAttribute("isIGAEnabled", isEnabled);
            logger.info("IGA has been toggled to : " + isEnabled);

            IdentityProviderModel tideIdp = session.identityProviders().getByAlias("tide");
            ComponentModel componentModel = realm.getComponentsStream()
                    .filter(x -> "tide-vendor-key".equals(x.getProviderId()))
                    .findFirst().orElse(null);

            if (tideIdp != null && componentModel != null) {
                String currentAlgorithm = session.getContext().getRealm().getDefaultSignatureAlgorithm();
                if (isEnabled) {
                    if (!"EdDSA".equalsIgnoreCase(currentAlgorithm)) {
                        session.getContext().getRealm().setDefaultSignatureAlgorithm("EdDSA");
                        logger.info("IGA enabled, default signature algorithm set to EdDSA");
                    }
                    // No-op: generation handled by new preview flow on demand
                } else {
                    if ("EdDSA".equalsIgnoreCase(currentAlgorithm)) {
                        session.getContext().getRealm().setDefaultSignatureAlgorithm("RS256");
                        logger.info("IGA disabled, default signature algorithm reset to RS256");
                    }
                }
            }
            return buildResponse(200, "IGA has been toggled to : " + isEnabled);
        } catch (Exception e) {
            logger.error("Error toggling IGA on realm: ", e);
            throw e;
        }
    }

    @POST @Path("add-rejection") @Produces(MediaType.TEXT_PLAIN)
    public Response AddRejection(@FormParam("changeSetId") String changeSetId,
                                 @FormParam("actionType") String actionType,
                                 @FormParam("changeSetType") String changeSetType) throws Exception {
        try {
            auth.realm().requireManageRealm();
            ChangesetRequestAdapter.saveAdminRejection(session, changeSetType, changeSetId, actionType, auth.adminAuth().getUser());
            return buildResponse(200, "Successfully added admin rejection to changeSetRequest with id " + changeSetId);
        } catch (Exception e) {
            logger.error("Error adding rejection to change set request with ID: " + changeSetId, e);
            return buildResponse(500, "Error adding rejection to change set request with ID: " + changeSetId + " ." + e.getMessage());
        }
    }

    // ---- sign / commit remain delegated to signer/committer (unchanged wiring) ----

    @POST @Consumes(MediaType.APPLICATION_JSON) @Path("change-set/sign")
    public Response signChangeset(ChangeSetRequest changeSet) throws Exception {
        try {
            List<String> result = signChangeSets(Collections.singletonList(changeSet));
            return Response.ok(result.get(0)).build();
        } catch (Exception ex) { return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(ex.getMessage()).build(); }
    }

    @POST @Consumes(MediaType.APPLICATION_JSON) @Path("change-set/sign/batch")
    public Response signMultipleChangeSets(ChangeSetRequestList changeSets) throws Exception {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            List<String> result = signChangeSets(changeSets.getChangeSets());
            return Response.ok(objectMapper.writeValueAsString(result)).build();
        } catch (Exception ex) { return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(ex.getMessage()).build(); }
    }

    public List<String> signChangeSets(List<ChangeSetRequest> changeSets) throws Exception {
        auth.realm().requireManageRealm();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        RealmModel realm = session.getContext().getRealm();
        var signer = org.tidecloak.base.iga.ChangeSetSigner.ChangeSetSignerFactory.getSigner(session);
        List<String> signedJsonList = new ArrayList<>();
        ObjectMapper objectMapper = new ObjectMapper();

        for (ChangeSetRequest changeSet : changeSets) {
            Object draftRecordEntity = BasicIGAUtils.fetchDraftRecordEntityByRequestId(em, changeSet.getType(), changeSet.getChangeSetId()).stream().findFirst().orElse(null);
            if (draftRecordEntity == null) throw new BadRequestException("Unsupported change set type for ID: " + changeSet.getChangeSetId());
            Response singleResp = signer.sign(changeSet, em, session, realm, draftRecordEntity, auth.adminAuth());
            signedJsonList.add(singleResp.readEntity(String.class));
        }
        return signedJsonList;
    }

    @POST @Consumes(MediaType.APPLICATION_JSON) @Path("change-set/commit")
    public Response commitChangeSet(ChangeSetRequest change) throws Exception {
        try {
            return commitChangeSets(Collections.singletonList(change));
        } catch (Exception ex) { return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(ex.getMessage()).build(); }
    }

    @POST @Consumes(MediaType.APPLICATION_JSON) @Path("change-set/commit/batch")
    public Response commitMultipleChangeSets(ChangeSetRequestList changeSets) throws Exception {
        try {
            return commitChangeSets(changeSets.getChangeSets());
        } catch (Exception ex) { return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(ex.getMessage()).build(); }
    }

    private Response commitChangeSets(List<ChangeSetRequest> changeSets) throws Exception {
        auth.realm().requireManageRealm();
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        RealmModel realm = session.getContext().getRealm();

        for (ChangeSetRequest changeSet : changeSets) {
            Object draftRecordEntity = BasicIGAUtils.fetchDraftRecordEntityByRequestId(em, changeSet.getType(), changeSet.getChangeSetId()).stream().findFirst().orElse(null);
            if (draftRecordEntity == null) return Response.status(Response.Status.BAD_REQUEST).entity("Unsupported change set type").build();
            ChangeSetCommitter committer = ChangeSetCommitterFactory.getCommitter(session);
            committer.commit(changeSet, em, session, realm, draftRecordEntity, auth.adminAuth());
        }
        return Response.ok("Change sets approved and committed").build();
    }

    // -------- existing query and helper endpoints can remain; removed old processor references --------

    private Response buildResponse(int status, String message) {
        return Response.status(status).entity(message).type(MediaType.TEXT_PLAIN).build();
    }

    // Local minimal helper to map a RoleModel to JPA RoleEntity when needed in queries
    private RoleEntity toRoleEntity(RoleModel role, EntityManager em) {
        return role == null ? null : em.find(RoleEntity.class, role.getId());
    }
}
