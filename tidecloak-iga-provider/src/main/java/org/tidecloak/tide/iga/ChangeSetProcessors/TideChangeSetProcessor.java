package org.tidecloak.tide.iga.ChangeSetProcessors;

import jakarta.persistence.EntityManager;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.midgard.models.InitializerCertificateModel.InitializerCertifcate;
import org.midgard.models.RequestExtensions.UserContextSignRequest;
import org.midgard.models.UserContext.UserContext;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessor;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessorFactory;
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

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.tidecloak.base.iga.ChangeSetProcessors.utils.ChangeRequestUtils.getChangeSetRequestFromEntity;
import static org.tidecloak.base.iga.ChangeSetProcessors.utils.UserContextUtils.getUserContextDrafts;
import static org.tidecloak.base.iga.ChangeSetProcessors.utils.UserContextUtils.getUserContextDraftsForRealm;
import static org.tidecloak.base.iga.TideRequests.TideRoleRequests.getDraftRoleInitCert;

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
//        ChangeSetProcessor.super.updateAffectedUserContexts(session, realm, change, entity, em);

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
                AtomicInteger numberOfNormalUserContext = new AtomicInteger();
                userContexts.forEach(x -> {
                    if(x.getInitCertHash() == null) {
                        numberOfNormalUserContext.getAndIncrement();
                    }
                });
                Stream<UserContext> normalUserContext = userContexts.stream().filter(x -> x.getInitCertHash() == null);
                Stream<UserContext> adminContexts = userContexts.stream().filter(x -> x.getInitCertHash() != null);
                List<UserContext> orderedContext = Stream.concat(adminContexts, normalUserContext).toList();

                // Create UserContextSignRequest
                UserContextSignRequest updatedReq = new UserContextSignRequest("Admin:1");
                updatedReq.SetUserContexts(orderedContext.toArray(new UserContext[0]));
                updatedReq.SetNumberOfUserContexts(numberOfNormalUserContext.get());

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

        ChangeSetProcessorFactory changeSetProcessorFactory = new ChangeSetProcessorFactory();

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

        // Update affected user contexts
        updateAffectedUserContexts(session, session.getContext().getRealm(), change, entity, em);
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

        List<AccessProofDetailEntity> proofDetails = getUserContextDrafts(em, changeRequestKey.getChangeRequestId(), type);
        proofDetails.sort(Comparator.comparingLong(AccessProofDetailEntity::getCreatedTimestamp).reversed());
        ClientModel realmManagement = session.clients().getClientByClientId(realm, Constants.REALM_MANAGEMENT_CLIENT_ID);
        RoleModel tideRole = realmManagement.getRole(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN);
        var tideIdp = session.identityProviders().getByAlias("tide");
        boolean hasInitCert;
        boolean isTideAdminRole;
        boolean isUnassignRole;
        UserModel originalUser;

        InitializerCertifcate cert = null;
        byte[] certHash = new byte[0];

        if (type.equals(ChangeSetType.USER_ROLE)) {
            TideUserRoleMappingDraftEntity roleMapping = (TideUserRoleMappingDraftEntity)BasicIGAUtils.fetchDraftRecordEntity(em, type, changeRequestKey.getMappingId());
            if (roleMapping == null) {
                throw new Exception("Invalid request, no user role mapping draft entity found for this record ID: " + changeRequestKey.getChangeRequestId());
            }
            List<TideRoleDraftEntity> tideRoleDraftEntity = em.createNamedQuery("getRoleDraftByRoleId", TideRoleDraftEntity.class)
                    .setParameter("roleId", roleMapping.getRoleId()).getResultList();
            if(tideRoleDraftEntity.isEmpty()){
                throw new Exception("Invalid request, no role draft entity found for this role ID: " + roleMapping.getRoleId());
            }

            isTideAdminRole = tideRole != null && roleMapping.getRoleId().equals(tideRole.getId());

            RoleInitializerCertificateDraftEntity roleInitCert = getDraftRoleInitCert(session, changeRequestKey.getChangeRequestId());

            hasInitCert = roleInitCert != null;
            ChangeSetRequest changeSetRequest = getChangeSetRequestFromEntity(session, roleMapping);
            isUnassignRole = changeSetRequest.getActionType().equals(ActionType.DELETE);
            originalUser = session.users().getUserById(realm, roleMapping.getUser().getId());
            ComponentModel componentModel = realm.getComponentsStream()
                    .filter(x -> "tide-vendor-key".equals(x.getProviderId()))  // Use .equals for string comparison
                    .findFirst()
                    .orElse(null);

            if(componentModel != null){
                List<AuthorizerEntity> realmAuthorizers = em.createNamedQuery("getAuthorizerByProviderIdAndTypes", AuthorizerEntity.class)
                        .setParameter("ID", componentModel.getId())
                        .setParameter("types", List.of("firstAdmin", "multiAdmin")).getResultList();

                if (realmAuthorizers.isEmpty()) {
                    throw new Exception("Authorizer not found for this realm.");
                }

                if(isTideAdminRole && realmAuthorizers.get(0).getType().equalsIgnoreCase("firstAdmin") && realmAuthorizers.size() == 1){
                    RoleEntity role = em.getReference(RoleEntity.class, tideRole.getId());

                    TideRoleDraftEntity tideRoleEntity = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class)
                            .setParameter("role", role).getSingleResult();
                    cert = InitializerCertifcate.FromString(tideRoleEntity.getInitCert());
                    certHash = cert.hash();
                }

                else if (hasInitCert) {
                    cert = InitializerCertifcate.FromString(roleInitCert.getInitCert());
                    certHash = cert.hash();
                }
            }
        } else {
            isTideAdminRole = false;
            hasInitCert = false;
            originalUser = null;
            isUnassignRole = false;
        }

        List<UserContext> userContexts = new ArrayList<>();
        UserContextSignRequest req = new UserContextSignRequest("Admin:1");


        InitializerCertifcate finalCert = cert;
        byte[] finalCertHash = certHash;

        proofDetails.forEach(p -> {
            UserContext userContext = new UserContext(p.getProofDraft());
            if (hasInitCert || isTideAdminRole) {
                try {
                    if(!isUnassignRole) {
                        userContext.setThreshold(finalCert.getPayload().getThreshold());
                        userContext.setInitCertHash(finalCertHash);
                    } else if (originalUser != null && !p.getUser().getId().equals(originalUser.getId())) {
                        userContext.setThreshold(finalCert.getPayload().getThreshold());
                        userContext.setInitCertHash(finalCertHash);
                    }
                    else {
                        userContext.setThreshold(0);
                        userContext.setInitCertHash(null);
                    }
                    p.setProofDraft(userContext.ToString());
                    em.flush();

                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
            userContexts.add(userContext);
        });

        AtomicInteger numberOfNormalUserContext = new AtomicInteger();
        userContexts.forEach( uc -> {
            if(uc.getInitCertHash() == null) {
                numberOfNormalUserContext.getAndIncrement();
            }
        });
        req.SetNumberOfUserContexts(numberOfNormalUserContext.get());

        if(hasInitCert || isTideAdminRole) { req.SetInitializationCertificate(finalCert); }

        // filter user contexts, admin contexts first then normal user context
        Stream<UserContext> normalUserContext = userContexts.stream().filter(x -> x.getInitCertHash() == null);
        Stream<UserContext> adminContexts = userContexts.stream().filter(x -> x.getInitCertHash() != null);
        List<UserContext> orderedContext = Stream.concat(adminContexts, normalUserContext).toList();

        req.SetUserContexts(orderedContext.toArray(new UserContext[0]));
        String draft = Base64.getEncoder().encodeToString(req.GetDraft());

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

        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(changeRequestKey.getChangeRequestId(), changeSetType));
        if (changesetRequestEntity == null) {
            ChangesetRequestEntity entity = new ChangesetRequestEntity();
            entity.setChangesetRequestId(changeRequestKey.getChangeRequestId());
            entity.setDraftRequest(draft);
            entity.setChangesetType(type);
            em.persist(entity);
            em.flush();
        } else {
            changesetRequestEntity.setDraftRequest(draft);
            em.flush();
        }
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
