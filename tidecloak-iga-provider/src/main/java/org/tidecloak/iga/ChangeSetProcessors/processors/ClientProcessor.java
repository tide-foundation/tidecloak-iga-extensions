package org.tidecloak.iga.ChangeSetProcessors.processors;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.AccessToken;
import org.tidecloak.iga.ChangeSetProcessors.ChangeSetProcessor;
import org.tidecloak.iga.ChangeSetProcessors.keys.UserClientKey;
import org.tidecloak.iga.ChangeSetProcessors.models.ChangeSetRequest;
import org.tidecloak.iga.ChangeSetProcessors.utils.ChangeRequestUtils;
import org.tidecloak.iga.interfaces.TideUserAdapter;
import org.tidecloak.iga.utils.IGAUtils;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.drafting.TideClientDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.tidecloak.iga.ChangeSetProcessors.utils.UserContextUtils.*;
import static org.tidecloak.iga.ChangeSetProcessors.utils.UserContextUtils.addRoleToAccessToken;


public class ClientProcessor implements ChangeSetProcessor<TideClientDraftEntity> {
    protected static final Logger logger = Logger.getLogger(ClientProcessor.class);

    @Override
    public void cancel(KeycloakSession session, TideClientDraftEntity entity, EntityManager em, ActionType actionType) {
        if(!entity.getFullScopeDisabled().equals(DraftStatus.ACTIVE)){
            entity.setFullScopeDisabled(DraftStatus.NULL);
        }else if (!entity.getFullScopeEnabled().equals(DraftStatus.ACTIVE)){
            entity.setFullScopeEnabled(DraftStatus.NULL);
        }

        // Find any pending changes
        List<AccessProofDetailEntity> pendingChanges = em.createNamedQuery("getProofDetailsForDraftByChangeSetTypeAndId", AccessProofDetailEntity.class)
                .setParameter("recordId", entity.getChangeRequestId())
                .setParameter("changesetType", ChangeSetType.CLIENT)
                .getResultList();

        pendingChanges.forEach(em::remove);
        em.flush();

        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(entity.getChangeRequestId(), ChangeSetType.CLIENT));
        if(changesetRequestEntity != null){
            em.remove(changesetRequestEntity);
            em.flush();
        }

    }

    @Override
    public  void commit(KeycloakSession session, ChangeSetRequest change, TideClientDraftEntity entity, EntityManager em, Runnable commitCallback) throws Exception {
        // Log the start of the request with detailed context
        logger.debug(String.format(
                "Starting workflow: COMMIT. Processor: %s, Action: %s, Entity ID: %s, Change Request ID: %s",
                this.getClass().getSimpleName(),
                change.getActionType(),
                entity.getId(),
                entity.getChangeRequestId()
        ));

        RealmModel realm = session.getContext().getRealm();
        Runnable callback = () -> {
            try {
                commitDefaultUserContext(realm, entity, change);
            } catch (Exception e) {
                throw new RuntimeException("Error during commit callback", e);
            }
        };

        ChangeSetProcessor.super.commit(session, change, entity, em, callback);


        // Log successful completion
        logger.debug(String.format(
                "Successfully processed workflow: COMMIT. Processor: %s, Entity ID: %s, Change Request ID: %s",
                this.getClass().getSimpleName(),
                entity.getId(),
                entity.getChangeRequestId()
        ));
    }

    @Override
    public void request(KeycloakSession session, TideClientDraftEntity entity, EntityManager em, ActionType action, Runnable callback, ChangeSetType changeSetType) {
        try {
            // Log the start of the request with detailed context
            logger.debug(String.format(
                    "Starting workflow: REQUEST. Processor: %s, Action: %s, Entity ID: %s, Change Request ID: %s",
                    this.getClass().getSimpleName(),
                    action,
                    entity.getId(),
                    entity.getChangeRequestId()
            ));
            ChangeSetProcessor.super.createChangeRequestEntity(em, entity.getChangeRequestId(), changeSetType);
            switch (action) {
                case CREATE:
                    logger.debug(String.format("Initiating CREATE action for Mapping ID: %s in workflow: REQUEST. Change Request ID: %s", entity.getId(), entity.getChangeRequestId()));
                    handleCreateRequest(session, entity, em, callback);
                    break;
                case DELETE:
                    logger.debug("Client Processor has no implementation for DELETE.");
                    break;
                default:
                    logger.warn(String.format("Unsupported action type: %s for Mapping ID: %s in workflow: REQUEST. Change Request ID: %s", action, entity.getId(), entity.getChangeRequestId()));
                    throw new IllegalArgumentException("Unsupported action: " + action);
            }

            // Log successful completion
            logger.debug(String.format(
                    "Successfully processed workflow: REQUEST. Processor: %s, Mapping ID: %s, Change Request ID: %s",
                    this.getClass().getSimpleName(),
                    entity.getId(),
                    entity.getChangeRequestId()
            ));

        } catch (Exception e) {
            logger.error(String.format(
                    "Error in workflow: REQUEST. Processor: %s, Mapping ID: %s, Change Request ID: %s, Action: %s. Error: %s",
                    this.getClass().getSimpleName(),
                    entity.getId(),
                    entity.getChangeRequestId(),
                    action,
                    e.getMessage()
            ), e);
            throw new RuntimeException("Failed to process CLIENT request", e);
        }
    }

    @Override
    public void handleCreateRequest(KeycloakSession session, TideClientDraftEntity entity, EntityManager em, Runnable callback) throws Exception {
        RealmModel realm = session.realms().getRealm(entity.getClient().getRealmId());
        ClientModel client = realm.getClientById(entity.getClient().getId());
        String defaultFullScopeUserContext = generateRealmDefaultUserContext(session, realm, client, em);
        ChangeSetProcessor.super.saveUserContextDraft(session, em, realm, client, null, entity.getChangeRequestId(), ChangeSetType.CLIENT, defaultFullScopeUserContext);
    }

    @Override
    public void handleDeleteRequest(KeycloakSession session, TideClientDraftEntity entity, EntityManager em, Runnable callback) throws Exception {

    }

    @Override
    public void updateAffectedUserContextDrafts(KeycloakSession session, AccessProofDetailEntity userContextDraft, Set<RoleModel> uniqRoles, ClientModel client, TideUserAdapter user, EntityManager em) throws Exception {
        RealmModel realm = session.realms().getRealm(userContextDraft.getRealmId());
        String defaultFullScopeUserContext = generateRealmDefaultUserContext(session, realm, client, em);
        em.remove(userContextDraft);
        this.saveUserContextDraft(session, em, session.getContext().getRealm(), client, null, userContextDraft.getRecordId(), ChangeSetType.CLIENT, defaultFullScopeUserContext);
    }

    @Override
    public RoleModel getRoleRequestFromEntity(KeycloakSession session, RealmModel realm, TideClientDraftEntity entity) {
        return null;
    }

    private void commitDefaultUserContext(RealmModel realm, TideClientDraftEntity entity, ChangeSetRequest change) {;
        ClientModel clientModel = realm.getClientByClientId(entity.getClient().getClientId());
        if (clientModel == null) return;

        if (change.getActionType() == ActionType.CREATE) {
            if(entity.getDraftStatus() != DraftStatus.APPROVED){
                throw new RuntimeException("Draft record has not been approved by all admins.");
            }
            entity.setDraftStatus(DraftStatus.ACTIVE);

        } else if (change.getActionType() == ActionType.DELETE) {
            throw new RuntimeException("CLIENT has no implementation for DELETE");

        }
    }

    @Override
    public void combineChangeRequests(KeycloakSession session, List<TideClientDraftEntity> userRoleEntities, UserModel user, ClientModel client, EntityManager em) {
        RealmModel realm = session.getContext().getRealm();
        UserEntity userEntity = em.find(UserEntity.class, user.getId());
        Map<UserClientKey, List<AccessProofDetailEntity>> groupedChangeRequests =  ChangeSetProcessor.super.groupChangeRequests(userRoleEntities,em);
        ObjectMapper objectMapper = new ObjectMapper();

        // combine for each user
        // loop through user + client access proof and combine, update id ??? record id??? and save new proof in a new accessproofentity with this record id and remove the others.
        groupedChangeRequests.forEach((userClientAccess, accessProofs) -> {

            String changeRequestId = KeycloakModelUtils.generateId();
            AtomicReference<String> trackTokenString = new AtomicReference<>("");
            // generate a new ID
            accessProofs.forEach(proof -> {
                try {
                    TideClientDraftEntity entity = (TideClientDraftEntity) IGAUtils.fetchDraftRecordEntityByRequestId(em, proof.getChangesetType(), proof.getRecordId());
                    if(entity == null){
                        throw new Exception("Could not find entity with change request id " + proof.getRecordId());
                    }
                    AccessToken accessToken = objectMapper.readValue(proof.getProofDraft(), AccessToken.class);
                    trackTokenString.set(this.combinedTransformedUserContext(session, realm, client, user, "openId", entity, accessToken));
                    entity.setChangeRequestId(changeRequestId);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });

            AccessProofDetailEntity combinedProof = new AccessProofDetailEntity();
            combinedProof.setUser(userEntity);
            combinedProof.setProofDraft(String.valueOf(trackTokenString));
            combinedProof.setId(KeycloakModelUtils.generateId());
            combinedProof.setClientId(client.getId());
            combinedProof.setChangesetType(ChangeSetType.USER_ROLE);
            combinedProof.setRealmId(realm.getId());
            combinedProof.setRecordId(changeRequestId);

            // remove once we have merged
            accessProofs.forEach(em::remove);
        });
    }

    private String generateRealmDefaultUserContext(KeycloakSession session, RealmModel realm, ClientModel client, EntityManager em) throws Exception {
        List<String> clients = List.of(Constants.ADMIN_CLI_CLIENT_ID, Constants.ADMIN_CONSOLE_CLIENT_ID);
        String id = KeycloakModelUtils.generateId();
        UserModel dummyUser = session.users().addUser(realm, id, id, true, false);
        AccessToken accessToken = ChangeSetProcessor.super.generateAccessToken(session, realm, client, dummyUser);
        if(clients.contains(client.getClientId())){
            accessToken.subject(null);
            session.users().removeUser(realm, dummyUser);
            return ChangeSetProcessor.super.cleanAccessToken(accessToken, List.of("preferred_username", "scope"), client.isFullScopeAllowed());
        } else {
            Set<RoleModel> rolesToAdd = getAllAccess(session, Set.of(realm.getDefaultRole()), client, client.getClientScopes(true).values().stream(), client.isFullScopeAllowed(), null);
            rolesToAdd.forEach(r -> {
                if ( realm.getName().equalsIgnoreCase(Config.getAdminRealm())){
                    addRoleToAccessTokenMasterRealm(accessToken, r, realm, em);
                }
                else{
                    addRoleToAccessToken(accessToken, r);
                }
            });
        }
            accessToken.subject(null);
            session.users().removeUser(realm, dummyUser);
            return ChangeSetProcessor.super.cleanAccessToken(accessToken, List.of("preferred_username", "scope"), client.isFullScopeAllowed());
    }
}
