package org.tidecloak.iga.changesetprocessors.processors;

import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.AccessToken;
import org.tidecloak.iga.changesetprocessors.ChangeSetProcessor;
import org.tidecloak.iga.changesetprocessors.models.ChangeSetRequest;
import org.tidecloak.iga.changesetprocessors.utils.TideEntityUtils;
import org.tidecloak.iga.changesetprocessors.utils.UserContextUtils;
import org.tidecloak.iga.interfaces.TideRoleAdapter;
import org.tidecloak.jpa.entities.drafting.TideCompositeRoleMappingDraftEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.iga.interfaces.TideUserAdapter;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.drafting.TideClientDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.iga.interfaces.TideClientAdapter;

import java.util.*;

import static org.tidecloak.iga.changesetprocessors.utils.ChangeRequestUtils.getChangeSetRequestFromEntity;
import static org.tidecloak.iga.changesetprocessors.utils.UserContextUtils.*;

public class ClientFullScopeProcessor implements ChangeSetProcessor<TideClientDraftEntity> {
    protected static final Logger logger = Logger.getLogger(ClientFullScopeProcessor.class);

    @Override
    public void cancel(KeycloakSession session, TideClientDraftEntity entity, EntityManager em, ActionType actionType) {
        if(!entity.getFullScopeDisabled().equals(DraftStatus.ACTIVE)){
            entity.setFullScopeDisabled(DraftStatus.NULL);
        }else if (!entity.getFullScopeEnabled().equals(DraftStatus.ACTIVE)){
            entity.setFullScopeEnabled(DraftStatus.NULL);
        }

        // Find any pending changes
        List<AccessProofDetailEntity> pendingChanges = em.createNamedQuery("getProofDetailsForDraftByChangeSetTypeAndId", AccessProofDetailEntity.class)
                .setParameter("recordId", entity.getId())
                .setParameter("changesetType", ChangeSetType.CLIENT_FULLSCOPE)
                .getResultList();

        pendingChanges.forEach(em::remove);
        em.flush();

    }

    @Override
    public void commit(KeycloakSession session, ChangeSetRequest change, TideClientDraftEntity entity, EntityManager em, Runnable commitCallback) throws Exception {
        logger.debug(String.format(
                "Starting workflow: COMMIT. Processor: %s, Action: %s, Entity ID: %s",
                this.getClass().getSimpleName(),
                change.getActionType(),
                entity.getId()
        ));

        RealmModel realm = session.getContext().getRealm();
        ClientModel client = new TideClientAdapter(realm, em, session, entity.getClient());

        Runnable callback = () -> {
            try {
                commitCallback(change, entity, client);
                em.merge(entity);
                em.flush();
            } catch (Exception e) {
                throw new RuntimeException("Error during commit callback", e);
            }
        };

        ChangeSetProcessor.super.commit(session, change, entity, em, callback);

        // Log successful completion
        logger.debug(String.format(
                "Successfully processed workflow: COMMIT. Processor: %s, Mapping ID: %s",
                this.getClass().getSimpleName(),
                entity.getId()
        ));
    }

    @Override
    public void request(KeycloakSession session, TideClientDraftEntity entity, EntityManager em, ActionType action, Runnable callback, ChangeSetType changeSetType) {
        try {
            // Log the start of the request with detailed context
            logger.debug(String.format(
                    "Starting workflow: REQUEST. Processor: %s, Action: %s, Entity ID: %s",
                    this.getClass().getSimpleName(),
                    action,
                    entity.getId()
            ));
            RealmModel realm = session.realms().getRealm(entity.getClient().getRealmId());
            String igaAttribute = realm.getAttribute("isIGAEnabled");
            boolean isIGAEnabled = igaAttribute != null && igaAttribute.equalsIgnoreCase("true");
            ChangeSetProcessor.super.createChangeRequestEntity(em, entity.getId(), changeSetType);
            switch (action) {
                case CREATE:
                    logger.debug(String.format("Initiating CREATE (enable) action for Mapping ID: %s in workflow: REQUEST", entity.getId()));
                    handleCreateRequest(session, entity, em, callback);
                    if (!isIGAEnabled){
                        if (entity.getFullScopeEnabled().equals(DraftStatus.ACTIVE)){
                            entity.setFullScopeDisabled(DraftStatus.NULL);
                        }
                        callback.run();
                    }
                    break;
                case DELETE:
                    logger.debug(String.format("Initiating DELETE (disable) action for Mapping ID: %s in workflow: REQUEST", entity.getId()));
                    handleDeleteRequest(session, entity, em, callback);
                    if (!isIGAEnabled){
                        if (entity.getFullScopeDisabled().equals(DraftStatus.ACTIVE)){
                            entity.setFullScopeEnabled(DraftStatus.NULL);
                        }
                        callback.run();
                    }
                    break;
                default:
                    logger.warn(String.format("Unsupported action type: %s for Mapping ID: %s in workflow: REQUEST", action, entity.getId()));
                    throw new IllegalArgumentException("Unsupported action: " + action);
            }


        } catch (Exception e) {
            logger.error(String.format(
                    "Error in workflow: REQUEST. Processor: %s, Mapping ID: %s, Action: %s. Error: %s",
                    this.getClass().getSimpleName(),
                    entity.getId(),
                    action,
                    e.getMessage()
            ), e);
            throw new RuntimeException("Failed to process CLIENT_FULLSCOPE request", e);

        }
    }

    @Override
    public void handleCreateRequest(KeycloakSession session, TideClientDraftEntity entity, EntityManager em, Runnable callback) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        ClientModel client = realm.getClientByClientId(entity.getClient().getClientId());
        entity.setFullScopeEnabled(DraftStatus.DRAFT);
        em.persist(entity);
        em.flush();

        List<UserModel> usersInRealm = session.users().searchForUserStream(realm, new HashMap<>()).toList();
        usersInRealm.forEach(user -> {
            try{
                // Find any pending changes
                List<AccessProofDetailEntity> pendingChanges = em.createNamedQuery("getProofDetailsForDraftByChangeSetTypeAndId", AccessProofDetailEntity.class)
                        .setParameter("recordId", entity.getId())
                        .setParameter("changesetType", ChangeSetType.CLIENT_FULLSCOPE)
                        .getResultList();

                if(pendingChanges != null && !pendingChanges.isEmpty()){
                    return;
                }

                UserModel wrappedUser = TideEntityUtils.wrapUserModel(user, session, realm);

                ChangeSetProcessor.super.generateAndSaveTransformedUserContextDraft(session, em, realm, client, wrappedUser, entity.getId(),
                        ChangeSetType.CLIENT_FULLSCOPE, entity);

            }
            catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        // Update Default user context for client aswell
        ChangeSetRequest change = getChangeSetRequestFromEntity(session, entity);
        String defaultFullScopeUserContext = generateRealmDefaultUserContext(session, realm, client, em, change);
        ChangeSetProcessor.super.saveUserContextDraft(session, em, realm, client, null, entity.getId(), ChangeSetType.CLIENT_DEFAULT_USER_CONTEXT, defaultFullScopeUserContext);

    }

    @Override
    public void handleDeleteRequest(KeycloakSession session, TideClientDraftEntity entity, EntityManager em, Runnable callback) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        ClientModel client = realm.getClientByClientId(entity.getClient().getClientId());
        List<UserModel> usersInClient = new ArrayList<>();
        client.getRolesStream().forEach(role -> session.users().getRoleMembersStream(realm, role).forEach(user -> {
            UserEntity userEntity = em.find(UserEntity.class, user.getId());
            List<TideUserRoleMappingDraftEntity> userRecords = em.createNamedQuery("getUserRoleAssignmentDraftEntityByStatus", TideUserRoleMappingDraftEntity.class)
                    .setParameter("draftStatus", DraftStatus.ACTIVE)
                    .setParameter("user", userEntity)
                    .setParameter("roleId", role.getId())
                    .getResultList();

            if (userRecords != null && !userRecords.isEmpty() && !usersInClient.contains(user)) {
                usersInClient.add(TideEntityUtils.wrapUserModel(user, session, realm));
            }
        }));
        if(usersInClient.isEmpty()){
            if (callback != null) {
                callback.run();
            }
            approveFullScope(entity, false);
            ChangeSetRequest changeSetRequest = getChangeSetRequestFromEntity(session, entity);
            ChangeSetProcessor.super.updateAffectedUserContexts(session, realm, changeSetRequest, entity, em);
            return;
        }

        entity.setFullScopeDisabled(DraftStatus.DRAFT);
        em.merge(entity);
        em.flush();

        usersInClient.forEach(user -> {
            // Find any pending changes
            List<AccessProofDetailEntity> pendingChanges = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                    .setParameter("recordId", entity.getId())
                    .getResultList();

            if ( pendingChanges != null && !pendingChanges.isEmpty()) {
                return;
            }
            try {
                ChangeSetProcessor.super.generateAndSaveTransformedUserContextDraft(session, em, realm, client, user, entity.getId(), ChangeSetType.CLIENT_FULLSCOPE, entity);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        // Update Default user context for client aswell
        ChangeSetRequest change = getChangeSetRequestFromEntity(session, entity);
        String defaultFullScopeUserContext = generateRealmDefaultUserContext(session, realm, client, em, change);
        ChangeSetProcessor.super.saveUserContextDraft(session, em, realm, client, null, entity.getId(), ChangeSetType.CLIENT_DEFAULT_USER_CONTEXT, defaultFullScopeUserContext);
    }

    @Override
    public void updateAffectedUserContextDrafts(KeycloakSession session, AccessProofDetailEntity affectedUserContextDraft, Set<RoleModel> uniqRoles, ClientModel client, TideUserAdapter user, EntityManager em) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        TideClientDraftEntity affectedClientFullScopeEntity = em.find(TideClientDraftEntity.class, affectedUserContextDraft.getRecordId());
        if (affectedClientFullScopeEntity == null ||
                isValidStatusPair(affectedClientFullScopeEntity.getFullScopeDisabled(), affectedClientFullScopeEntity.getFullScopeEnabled()) ||
                isValidStatusPair(affectedClientFullScopeEntity.getFullScopeEnabled(), affectedClientFullScopeEntity.getFullScopeDisabled())) {
            return;
        }
        ChangeSetRequest affectedChangeRequest = getChangeSetRequestFromEntity(session, affectedClientFullScopeEntity);

        if(affectedChangeRequest.getActionType() == ActionType.DELETE) {
            affectedClientFullScopeEntity.setFullScopeDisabled(DraftStatus.DRAFT);
        }else if (affectedChangeRequest.getActionType() == ActionType.CREATE) {
            affectedClientFullScopeEntity.setFullScopeEnabled(DraftStatus.DRAFT);
        }

        String userContextDraft = ChangeSetProcessor.super.generateTransformedUserContext(session, realm, client, user, "openid", affectedClientFullScopeEntity);
        affectedUserContextDraft.setProofDraft(userContextDraft);

    }

    @Override
    public RoleModel getRoleRequestFromEntity(KeycloakSession session, RealmModel realm, TideClientDraftEntity entity) {
        return null;
    }

    @Override
    public AccessToken transformUserContext(AccessToken token, KeycloakSession session, TideClientDraftEntity entity, UserModel user, ClientModel clientModel) {
        RealmModel realm = session.getContext().getRealm();
        ClientModel client = realm.getClientByClientId(entity.getClient().getClientId());

        // Ensure token components are initialized
        if (token.getRealmAccess() == null) {
            token.setRealmAccess(new AccessToken.Access());
        }
        if (token.getResourceAccess() == null) {
            token.setResourceAccess(new HashMap<>());
        }

        UserContextUtils userContextUtils = new UserContextUtils();
        Set<RoleModel> activeRoles = userContextUtils.getDeepUserRoleMappings(user, session, realm, DraftStatus.ACTIVE);

        ChangeSetRequest change = getChangeSetRequestFromEntity(session, entity);
        Set<RoleModel> roleModelSet = UserContextUtils.getAccess(
                activeRoles,
                client,
                client.getClientScopes(true).values().stream(),
                change.getActionType().equals(ActionType.CREATE)
        );

        if (change.getActionType().equals(ActionType.DELETE)) {
            // Clear existing roles if realm access exists
            if (token.getRealmAccess() != null && token.getRealmAccess().getRoles() != null) {
                token.getRealmAccess().getRoles().clear();
            }

            // Clear resource access if it exists
            if (token.getResourceAccess() != null) {
                token.getResourceAccess().clear();
            }
        }

        // Add roles to token
        roleModelSet.forEach(role -> {
            addRoleToAccessToken(token, role);
        });

        // Update token audience
        userContextUtils.normalizeAccessToken(token, client.isFullScopeAllowed());

        return token;
    }

    private void commitCallback(ChangeSetRequest change, TideClientDraftEntity entity, ClientModel client){
        if (change.getActionType() == ActionType.CREATE) {
            if(entity.getFullScopeEnabled() != DraftStatus.APPROVED){
                throw new RuntimeException("Draft record has not been approved by all admins.");
            }
            entity.setFullScopeEnabled(DraftStatus.ACTIVE);
            entity.setFullScopeDisabled(DraftStatus.NULL);
            entity.getClient().setFullScopeAllowed(true);
        } else if (change.getActionType() == ActionType.DELETE) {
            if(entity.getFullScopeDisabled() != DraftStatus.APPROVED){
                throw new RuntimeException("Deletion has not been approved by all admins.");
            }
            entity.setFullScopeDisabled(DraftStatus.ACTIVE);
            entity.setFullScopeEnabled(DraftStatus.NULL);
            client.setFullScopeAllowed(false);
            entity.getClient().setFullScopeAllowed(true);
        }
    }

    private void approveFullScope(TideClientDraftEntity clientFullScopeStatuses, boolean isEnabled) {
        if (isEnabled) {
            clientFullScopeStatuses.setFullScopeDisabled(DraftStatus.NULL);
            clientFullScopeStatuses.setFullScopeEnabled(DraftStatus.ACTIVE);
        } else {
            clientFullScopeStatuses.setFullScopeEnabled(DraftStatus.NULL);
            clientFullScopeStatuses.setFullScopeDisabled(DraftStatus.ACTIVE);
        }

    }

    private boolean isValidStatusPair(DraftStatus activeStatus, DraftStatus inactiveStatus) {
        // Valid if the active status is ACTIVE and the inactive status is null or NULL
        return activeStatus == DraftStatus.ACTIVE &&
                (inactiveStatus == null || inactiveStatus == DraftStatus.NULL);
    }

    private String generateRealmDefaultUserContext(KeycloakSession session, RealmModel realm, ClientModel client, EntityManager em, ChangeSetRequest change) throws Exception {
        List<String> clients = List.of(Constants.ADMIN_CLI_CLIENT_ID, Constants.ADMIN_CONSOLE_CLIENT_ID, Constants.ACCOUNT_CONSOLE_CLIENT_ID);
        String id = KeycloakModelUtils.generateId();
        UserModel dummyUser = session.users().addUser(realm, id, id, true, false);
        AccessToken accessToken = ChangeSetProcessor.super.generateAccessToken(session, realm, client, dummyUser);
        boolean isFullscope = change.getActionType().equals(ActionType.CREATE);
        if(clients.contains(client.getClientId())){
            accessToken.subject(null);
            session.users().removeUser(realm, dummyUser);
            return ChangeSetProcessor.super.cleanAccessToken(accessToken, List.of("preferred_username", "scope"), isFullscope);
        } else {
            Set<RoleModel> rolesToAdd = getAllAccess(session, Set.of(realm.getDefaultRole()), client, client.getClientScopes(true).values().stream(), isFullscope, null);
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
        return ChangeSetProcessor.super.cleanAccessToken(accessToken, List.of("preferred_username", "scope"), isFullscope);
    }
}
