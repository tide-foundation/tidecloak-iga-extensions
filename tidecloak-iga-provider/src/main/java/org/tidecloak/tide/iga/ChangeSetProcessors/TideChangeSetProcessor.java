package org.tidecloak.tide.iga.ChangeSetProcessors;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.ws.rs.BadRequestException;
import jakarta.xml.bind.DatatypeConverter;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.midgard.models.RequestExtensions.UserContextSignRequest;
import org.midgard.models.UserContext.UserContext;
import org.midgard.models.*;
import org.midgard.Midgard;
import org.midgard.models.Policy.*;


import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessor;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessorFactory;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessorFactoryProvider;
import org.tidecloak.base.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.base.iga.ChangeSetProcessors.utils.TideEntityUtils;
import org.tidecloak.base.iga.interfaces.ChangesetRequestAdapter;
import org.tidecloak.base.iga.interfaces.TideUserAdapter;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.jpa.entities.*;
import org.tidecloak.jpa.entities.drafting.RoleInitializerCertificateDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideClientDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideRoleDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.shared.enums.WorkflowType;
import org.tidecloak.shared.enums.models.WorkflowParams;
import org.tidecloak.shared.models.SecretKeys;
import org.tidecloak.tide.iga.AdminResource.TideAdminRealmResource;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.tidecloak.base.iga.ChangeSetProcessors.utils.ChangeRequestUtils.getChangeSetRequestFromEntity;
import static org.tidecloak.base.iga.ChangeSetProcessors.utils.UserContextUtils.getUserContextDrafts;
import static org.tidecloak.base.iga.ChangeSetProcessors.utils.UserContextUtils.getUserContextDraftsForRealm;
import static org.tidecloak.tide.iga.AdminResource.TideAdminRealmResource.ConstructSignSettings;

public class TideChangeSetProcessor<T> implements ChangeSetProcessor<T> {

    /**
     * Updates all affected user context drafts triggered by a change request commit.
     * This method performs the following steps:
     * - Retrieves a list of affected clients based on the entity.
     * - Updates any related user contexts for these clients.
     *
     * @param session   The Keycloak session for the current context.
     * @param change    The change set request containing details of the change.
     * @param entity    The entity being processed.
     * @param em        The EntityManager for database interactions.
     * @throws Exception If an error occurs during the update process.
     */
    @Override
    public void updateAffectedUserContexts(KeycloakSession session, RealmModel realm, ChangeSetRequest change, T entity, EntityManager em) throws Exception {
        // Group proofDetails by changeRequestId
        Map<ChangeRequestKey, List<AccessProofDetailEntity>> groupedProofDetails = getUserContextDraftsForRealm(em, realm.getId()).stream()
                .filter(proof -> !Objects.equals(proof.getChangeRequestKey().getChangeRequestId(), change.getChangeSetId()))
                .sorted(Comparator.comparingLong(AccessProofDetailEntity::getCreatedTimestamp).reversed())
                .collect(Collectors.groupingBy(AccessProofDetailEntity::getChangeRequestKey));

        // Process each group
        groupedProofDetails.forEach((changeRequestKey, details) -> {
            try {
                // Create a list of UserContext for the current changeRequestId
                List<UserContext>  userContexts = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                        .setParameter("recordId", changeRequestKey.getChangeRequestId()).getResultStream().map(p -> new UserContext(p.getProofDraft())).collect(Collectors.toList());

                if(userContexts.isEmpty()){
                    return;
                }

                // Create UserContextSignRequest
                UserContextSignRequest updatedReq = new UserContextSignRequest("Policy:1");
                updatedReq.SetUserContexts(userContexts.toArray(new UserContext[0]));

                ChangeSetType changeSetType;
                if(details.get(0).getChangesetType().equals(ChangeSetType.CLIENT_DEFAULT_USER_CONTEXT)){
                    changeSetType = ChangeSetType.CLIENT_FULLSCOPE;
                }
                else if (details.get(0).getChangesetType().equals(ChangeSetType.DEFAULT_ROLES)) {
                    changeSetType = ChangeSetType.COMPOSITE_ROLE;
                }
                else{
                    changeSetType = details.get(0).getChangesetType();
                }

                ChangesetRequestEntity changesetRequestEntity = ChangesetRequestAdapter.getChangesetRequestEntity(session, changeRequestKey.getChangeRequestId(), changeSetType);
                if(changesetRequestEntity != null){
                    changesetRequestEntity.setDraftRequest(Base64.getEncoder().encodeToString(updatedReq.GetDraft()));
                }
                em.flush();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    /**
     * Commits a change request by finalizing the draft and applying changes to the database.
     *
     * @param session        The Keycloak session for the current context.
     * @param change         The change set request containing details of the change.
     * @param entity         The entity being processed.
     * @param em             The EntityManager for database interactions.
     * @param commitCallback A Runnable task to execute during the commit process for additional actions.
     * @throws Exception If any error occurs during the commit process.
     */
    @Override
    public void commit(KeycloakSession session, ChangeSetRequest change, T entity, EntityManager em, Runnable commitCallback) throws Exception {
        String realmId = session.getContext().getRealm().getId();
        // Retrieve the user context drafts
        List<AccessProofDetailEntity> userContextDrafts = getUserContextDrafts(em, change.getChangeSetId(), change.getType());

        if (userContextDrafts.isEmpty()) {
            throw new Exception("No user context drafts found for this change set id, " + change.getChangeSetId());
        }

        // Process each user context draft
        for (AccessProofDetailEntity userContextDraft : userContextDrafts) {
            try {
                UserEntity userEntity = userContextDraft.getUser();
                TideUserAdapter affectedUser = TideEntityUtils.toTideUserAdapter(userEntity, session, session.realms().getRealm(userContextDraft.getRealmId()));

                commitUserContextToDatabase(session, userContextDraft, em);
                em.remove(userContextDraft); // This user context draft is committed, so remove it
                em.flush();
            } catch (Exception e) {
                throw new RuntimeException("Error processing user context draft: " + e.getMessage(), e);
            }
        }

        // Execute the commit callback if provided
        if (commitCallback != null) {
            commitCallback.run();
        }
        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(change.getChangeSetId(), change.getType()));
        if (changesetRequestEntity != null) {
            em.remove(changesetRequestEntity);
        }

        // Regenerate for client full scope change request.
        List<Map.Entry<ChangesetRequestEntity,TideClientDraftEntity>> reqAndDrafts =
                em.createNamedQuery("getAllChangeRequestsByChangeSetType", ChangesetRequestEntity.class)
                        .setParameter("changesetType", ChangeSetType.CLIENT_FULLSCOPE)
                        .getResultStream()
                        .flatMap(cr -> {
                            // load drafts for this change-request
                            List<TideClientDraftEntity> drafts = em.createNamedQuery(
                                            "GetClientDraftEntityByRequestId", TideClientDraftEntity.class)
                                    .setParameter("requestId", cr.getChangesetRequestId())
                                    .getResultList();

                            // keep only those in our realm
                            List<TideClientDraftEntity> valid = drafts.stream()
                                    .filter(d -> d.getClient()
                                            .getRealmId()
                                            .equalsIgnoreCase(realmId))
                                    .collect(Collectors.toList());

                            // if none were valid, delete the CR & emit nothing
                            if (valid.isEmpty()) {
                                em.remove(cr);
                                return Stream.empty();
                            }

                            // otherwise emit a (request, draft) entry for each valid draft
                            return valid.stream()
                                    .map(d -> new AbstractMap.SimpleEntry<>(cr, d));
                        })
                        .collect(Collectors.toList());

        ChangeSetProcessorFactory changeSetProcessorFactory = ChangeSetProcessorFactoryProvider.getFactory();

        reqAndDrafts.forEach(entry -> {
            ChangesetRequestEntity req   = entry.getKey();
            TideClientDraftEntity  draft = entry.getValue();

            if (draft == null) return; // Skip if draft entity is missing

            ChangeSetRequest c = getChangeSetRequestFromEntity(session, draft, ChangeSetType.CLIENT_FULLSCOPE);

            // Remove associated admin authorizations
            req.getAdminAuthorizations().clear();

            // Remove associated proof details
            em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                    .setParameter("recordId", req.getChangesetRequestId())
                    .getResultStream()
                    .forEach(em::remove);

            // Remove the changeset request
            em.remove(req);

            // Process the workflow
            WorkflowParams params = new WorkflowParams(DraftStatus.DRAFT, c.getActionType().equals(ActionType.DELETE), c.getActionType(), ChangeSetType.CLIENT_FULLSCOPE);
            try {
                changeSetProcessorFactory.getProcessor(ChangeSetType.CLIENT_FULLSCOPE)
                        .executeWorkflow(session, draft, em, WorkflowType.REQUEST, params, null);
            } catch (Exception e) {
                throw new RuntimeException("Error executing workflow for request ID: " + req.getChangesetRequestId(), e);
            }
        });

        // Flush once after batch processing
        em.flush();
    }

    /**
     * Saves a user context draft to the database.
     * This method creates a draft entity and persists it along with additional metadata, such as the record ID and proof draft.
     *
     * @param session    The Keycloak session for the current context.
     * @param em         The EntityManager for database interactions.
     * @param realm      The realm associated with the operation.
     * @param clientModel The client model for which the draft is being saved.
     * @param user       The user entity associated with the draft.
     * @param changeRequestKey   The record ID of the change set.
     * @param type       The type of the change set.
     * @param proofDraft The serialized proof draft as a JSON string.
     * @throws Exception If an error occurs during the save operation.
     */
    @Override
    public void saveUserContextDraft(KeycloakSession session, EntityManager em, RealmModel realm, ClientModel clientModel, UserEntity user, ChangeRequestKey changeRequestKey, ChangeSetType type, String proofDraft) throws Exception {
//        ChangeSetProcessor.super.saveUserContextDraft(session, em, realm, clientModel, user, changeRequestKey, type, proofDraft);
        ComponentModel componentModel = session.getContext().getRealm().getComponentsStream()
                .filter(x -> "tide-vendor-key".equals(x.getProviderId()))  // Use .equals for string comparison
                .findFirst()
                .orElse(null);

        List<AccessProofDetailEntity> proofDetails = getUserContextDrafts(em, changeRequestKey.getChangeRequestId(), type);
        proofDetails.sort(Comparator.comparingLong(AccessProofDetailEntity::getCreatedTimestamp).reversed());

        List<UserContext> userContexts = new ArrayList<>();
        UserContextSignRequest req = new UserContextSignRequest("Policy:1");
        proofDetails.forEach(p -> {
            UserContext userContext = new UserContext(p.getProofDraft());
            userContexts.add(userContext);
        });
        req.SetUserContexts(userContexts.toArray(new UserContext[0]));
        String draft = Base64.getEncoder().encodeToString(req.GetDraft());

        ModelRequest modelReq = null;
        String authFlow = "VRK:1";
        if ( componentModel != null) {
            List<AuthorizerEntity> realmAuthorizers = em.createNamedQuery(
                            "getAuthorizerByProviderIdAndTypes", AuthorizerEntity.class)
                    .setParameter("ID", componentModel.getId())
                    .setParameter("types", List.of("firstAdmin", "multiAdmin"))
                    .getResultList();
            authFlow = realmAuthorizers.get(0).getType().equalsIgnoreCase("firstAdmin") ? "VRK:1" : "Policy:1";

            if(authFlow.equalsIgnoreCase("Policy:1")) {
                MultivaluedHashMap<String, String> config = componentModel.getConfig();

                String currentSecretKeys = config.getFirst("clientSecret");
                ObjectMapper objectMapper = new ObjectMapper();
                TideAdminRealmResource.SecretKeys secretKeys = objectMapper.readValue(currentSecretKeys, TideAdminRealmResource.SecretKeys.class);


                ClientModel realmManagement = session.clients().getClientByClientId(realm, Constants.REALM_MANAGEMENT_CLIENT_ID);

                RoleModel tideRole = realmManagement.getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
                TideRoleDraftEntity tideAdmin = em.createNamedQuery("getRoleDraftByRoleId", TideRoleDraftEntity.class)
                        .setParameter("roleId", tideRole.getId())
                        .getSingleResult();
                var policyString = tideAdmin.getInitCert();
                Policy policy = Policy.From(Base64.getDecoder().decode(policyString));
                SignRequestSettingsMidgard signedSettings = ConstructSignSettings(config, secretKeys.activeVrk);
                ModelRequest newModelReq = ModelRequest.New("UserContext", "1", authFlow, req.GetDraft(), policy.ToBytes());
                var expireAtTime = (System.currentTimeMillis() / 1000) + 2628000; // 1 month from now
                newModelReq.SetCustomExpiry(expireAtTime);
                modelReq = newModelReq.InitializeTideRequestWithVrk(newModelReq, signedSettings, "UserContext:1", DatatypeConverter.parseHexBinary(config.getFirst("gVRK")), Base64.getDecoder().decode(config.getFirst("gVRKCertificate")));

            }
        }

        ChangeSetType changeSetType;
        if(type.equals(ChangeSetType.CLIENT_DEFAULT_USER_CONTEXT)){
            changeSetType = ChangeSetType.CLIENT_FULLSCOPE;
        }
        else if (type.equals(ChangeSetType.DEFAULT_ROLES)) {
            changeSetType = ChangeSetType.COMPOSITE_ROLE;
        }
        else{
            changeSetType = type;
        }

        ChangesetRequestEntity.Key key =
                new ChangesetRequestEntity.Key(changeRequestKey.getChangeRequestId(), changeSetType);

        ChangesetRequestEntity entity = em.find(ChangesetRequestEntity.class, key);

        if (entity == null) {
            entity = new ChangesetRequestEntity();
            entity.setChangesetRequestId(changeRequestKey.getChangeRequestId());
            entity.setChangesetType(type);
            em.persist(entity);
        }

        entity.setDraftRequest(draft);

        if ("Policy:1".equalsIgnoreCase(authFlow)) {
            String encodedModel = Base64.getEncoder().encodeToString(modelReq.Encode());
            entity.setRequestModel(encodedModel);
        }

        // Usually you can rely on transaction commit to flush;
        // only do this if you *really* need an immediate flush.
        em.flush();

    }

    @Override
    public void handleCreateRequest(KeycloakSession session, T entity, EntityManager em, Runnable callback) throws Exception {
    }

    @Override
    public void handleDeleteRequest(KeycloakSession session, T entity, EntityManager em, Runnable callback) throws Exception {

    }

    @Override
    public void updateAffectedUserContextDrafts(KeycloakSession session, AccessProofDetailEntity userContextDraft, Set<RoleModel> uniqRoles, ClientModel client, TideUserAdapter user, EntityManager em) throws Exception {

    }

    @Override
    public RoleModel getRoleRequestFromEntity(KeycloakSession session, RealmModel realm, T entity) {
        return null;
    }


    // Helper methods

    private void commitUserContextToDatabase(KeycloakSession session, AccessProofDetailEntity userContext, EntityManager em) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        ComponentModel componentModel = realm.getComponentsStream()
                .filter(x -> "tide-vendor-key".equals(x.getProviderId()))  // Use .equals for string comparison
                .findFirst()
                .orElse(null);

        if(componentModel == null) {
            throw new Exception("There is no tide-vendor-key component set up for this realm, " + realm.getName());
        }

        String accessProofSig = userContext.getSignature();
        if(accessProofSig == null || accessProofSig.isEmpty()){
            throw new Exception("Could not find authorization signature for this user context. Request denied.");
        }

        if(userContext.getChangesetType().equals(ChangeSetType.DEFAULT_ROLES) || userContext.getChangesetType().equals(ChangeSetType.CLIENT) || userContext.getChangesetType().equals(ChangeSetType.CLIENT_DEFAULT_USER_CONTEXT)) {
            ClientEntity clientEntity = em.find(ClientEntity.class, userContext.getClientId());
            TideClientDraftEntity defaultUserContext = em.createNamedQuery("getClientFullScopeStatus", TideClientDraftEntity.class).setParameter("client", clientEntity).getSingleResult();
            defaultUserContext.setDefaultUserContext(userContext.getProofDraft());
            defaultUserContext.setDefaultUserContextSig(accessProofSig);
            em.flush();
            return;
        }

        UserClientAccessProofEntity userClientAccess = em.find(UserClientAccessProofEntity.class, new UserClientAccessProofEntity.Key(userContext.getUser(), userContext.getClientId()));

        if (userClientAccess == null){
            UserClientAccessProofEntity newAccess = new UserClientAccessProofEntity();
            newAccess.setUser(userContext.getUser());
            newAccess.setClientId(userContext.getClientId());
            newAccess.setAccessProof(userContext.getProofDraft());
            newAccess.setAccessProofSig(accessProofSig);
            newAccess.setIdProofSig("");
            newAccess.setAccessProofMeta("");
            em.persist(newAccess);

        } else{
            userClientAccess.setAccessProof(userContext.getProofDraft());
            userClientAccess.setAccessProofMeta("");
            userClientAccess.setAccessProofSig(accessProofSig);
            userClientAccess.setIdProofSig("");
            em.merge(userClientAccess);
        }
    }
}
