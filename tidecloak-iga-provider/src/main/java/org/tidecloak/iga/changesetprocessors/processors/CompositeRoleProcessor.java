package org.tidecloak.iga.changesetprocessors.processors;

import com.fasterxml.jackson.core.JsonProcessingException;
import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.*;
import org.keycloak.models.jpa.UserAdapter;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.Urls;
import org.keycloak.util.TokenUtil;
import org.tidecloak.iga.changesetprocessors.ChangeSetProcessor;
import org.tidecloak.iga.changesetprocessors.models.ChangeSetRequest;
import org.tidecloak.iga.changesetprocessors.utils.TideEntityUtils;
import org.tidecloak.iga.changesetprocessors.utils.UserContextUtils;
import org.tidecloak.iga.interfaces.TideRoleAdapter;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.iga.interfaces.TideUserAdapter;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.drafting.TideCompositeRoleMappingDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;

import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static org.tidecloak.iga.changesetprocessors.utils.ChangeRequestUtils.getChangeSetRequestFromEntity;
import static org.tidecloak.iga.changesetprocessors.utils.ClientUtils.getUniqueClientList;
import static org.tidecloak.iga.changesetprocessors.utils.RoleUtils.commitDefaultRolesOnInitiation;
import static org.tidecloak.iga.changesetprocessors.utils.UserContextUtils.*;

public class CompositeRoleProcessor implements ChangeSetProcessor<TideCompositeRoleMappingDraftEntity> {

    protected static final Logger logger = Logger.getLogger(UserRoleProcessor.class);

    @Override
    public void cancel(KeycloakSession session, TideCompositeRoleMappingDraftEntity entity, EntityManager em, ActionType actionType){
        RealmModel realm = session.getContext().getRealm();
        TideRoleAdapter tideRoleAdapter = new TideRoleAdapter(session, realm, em, entity.getComposite());
        tideRoleAdapter.removeChildRoleFromCompositeRoleRecords(entity, actionType);
    }

    @Override
    public void request(KeycloakSession session, TideCompositeRoleMappingDraftEntity entity, EntityManager em, ActionType action, Runnable callback, ChangeSetType changeSetType) {
        try {
            // Log the start of the request with detailed context
            logger.debug(String.format(
                    "Starting workflow: REQUEST. Processor: %s, Action: %s, Entity ID: %s",
                    this.getClass().getSimpleName(),
                    action,
                    entity.getId()
            ));
            ChangeSetProcessor.super.createChangeRequestEntity(em, entity.getId(), changeSetType);
            switch (action) {
                case CREATE:
                    logger.debug(String.format("Initiating CREATE action for Mapping ID: %s in workflow: REQUEST", entity.getId()));
                    handleCreateRequest(session, entity, em, callback);
                    break;
                case DELETE:
                    logger.debug(String.format("Initiating DELETE action for Mapping ID: %s in workflow: REQUEST", entity.getId()));
                    handleDeleteRequest(session, entity, em, callback);
                    break;
                default:
                    logger.warn(String.format("Unsupported action type: %s for Mapping ID: %s in workflow: REQUEST", action, entity.getId()));
                    throw new IllegalArgumentException("Unsupported action: " + action);
            }

            // Log successful completion
            logger.debug(String.format(
                    "Successfully processed workflow: REQUEST. Processor: %s, Mapping ID: %s",
                    this.getClass().getSimpleName(),
                    entity.getId()
            ));

        } catch (Exception e) {
            logger.error(String.format(
                    "Error in workflow: REQUEST. Processor: %s, Mapping ID: %s, Action: %s. Error: %s",
                    this.getClass().getSimpleName(),
                    entity.getId(),
                    action,
                    e.getMessage()
            ), e);
            throw new RuntimeException("Failed to process COMPOSITE_ROLE request", e);
        }
    }

    @Override
    public  void commit(KeycloakSession session, ChangeSetRequest change, TideCompositeRoleMappingDraftEntity entity, EntityManager em, Runnable commitCallback) throws Exception {
        // Log the start of the request with detailed context
        logger.debug(String.format(
                "Starting workflow: COMMIT. Processor: %s, Action: %s, Entity ID: %s",
                this.getClass().getSimpleName(),
                change.getActionType(),
                entity.getId()
        ));

        RealmModel realm = session.getContext().getRealm();
        Runnable callback = () -> {
            try {
                commitCallback(realm, change, entity);
            } catch (Exception e) {
                throw new RuntimeException("Error during commit callback", e);
            }
        };

        ChangeSetProcessor.super.commit(session, change, entity, em, callback);


        // Log successful completion
        logger.debug(String.format(
                "Successfully processed workflow: COMMIT. Processor: %s, Entity ID: %s",
                this.getClass().getSimpleName(),
                entity.getId()
        ));
    }

    @Override
    public void handleCreateRequest(KeycloakSession session, TideCompositeRoleMappingDraftEntity entity, EntityManager em, Runnable callback) throws Exception {
        RoleEntity parentEntity = entity.getComposite();
        RoleEntity childEntity = entity.getChildRole();
        RealmModel realm = session.realms().getRealm(parentEntity.getRealmId());
        RoleModel parentRole = realm.getRoleById(parentEntity.getId());
        RoleModel childRole = realm.getRoleById(childEntity.getId());

        List<TideUserAdapter> activeUsers =  session.users().getRoleMembersStream(realm, parentRole).map(user -> {
            UserEntity userEntity = em.find(UserEntity.class, user.getId());
            List<TideUserRoleMappingDraftEntity> userRecords = em.createNamedQuery("getUserRoleAssignmentDraftEntityByStatus", TideUserRoleMappingDraftEntity.class)
                    .setParameter("draftStatus", DraftStatus.ACTIVE)
                    .setParameter("user", userEntity)
                    .setParameter("roleId", parentRole.getId())
                    .getResultList();

            if(userRecords == null || userRecords.isEmpty()){
                return null;
            }
            return new TideUserAdapter(session, realm, em, userEntity);
        }).filter(Objects::nonNull).toList();


        if (activeUsers.isEmpty() || commitDefaultRolesOnInitiation(session, realm, parentEntity, childRole, em) ) {
            if(realm.getName().equalsIgnoreCase(Config.getAdminRealm())) return;

            // if no users are affected, we commit the request immediately and check any affected change requests and update them.
            entity.setDraftStatus(DraftStatus.ACTIVE);
            ChangeSetRequest changeSetRequest = getChangeSetRequestFromEntity(session, entity);
            ChangeSetProcessor.super.updateAffectedUserContexts(session, realm, changeSetRequest, entity, em);
            em.persist(entity);
            ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, entity.getId());
            if(changesetRequestEntity != null) {
                em.remove(changesetRequestEntity);
            }
            em.flush();

            List<AccessProofDetailEntity> clientEntities = em.createNamedQuery("getProofDetailsForDraftByChangeSetTypeAndRealm", AccessProofDetailEntity.class)
                    .setParameter("changesetType", ChangeSetType.CLIENT)
                    .setParameter("realmId", realm.getId()).getResultList();

            if(parentRole.equals(realm.getDefaultRole())){
                 if (!clientEntities.isEmpty()) {
                     clientEntities.forEach(c -> {
                         try {
                             ClientModel client = realm.getClientById(c.getClientId());
                             String defaultFullScopeUserContext = generateRealmDefaultUserContext(session, realm, client, childRole, em, false);
                             em.remove(c);
                             ChangeSetProcessor.super.saveUserContextDraft(session, em, realm, client, null, c.getRecordId(), ChangeSetType.CLIENT, defaultFullScopeUserContext);
                         } catch (Exception e) {
                             throw new RuntimeException(e);
                         }
                     });
                }
            }
        }
        else {
            List<ClientModel> clientList = getUniqueClientList(session, realm, childRole, em);
            clientList.forEach(client -> {
                for (UserModel user : activeUsers) {
                    try {
                        UserModel wrappedUser = TideEntityUtils.wrapUserModel(user, session, realm);
                        ChangeSetProcessor.super.generateAndSaveTransformedUserContextDraft(session, em, realm, client, wrappedUser, entity.getId(), ChangeSetType.COMPOSITE_ROLE, entity);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }
                try {
                    if(parentRole.equals(realm.getDefaultRole())) {
                        String defaultFullScopeUserContext = generateRealmDefaultUserContext(session, realm, client, childRole, em, false);
                        ChangeSetProcessor.super.saveUserContextDraft(session, em, realm, client, null, entity.getId(), ChangeSetType.DEFAULT_ROLES, defaultFullScopeUserContext);
                    }
                }
                catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
        }
    }

    @Override
    public void handleDeleteRequest(KeycloakSession session, TideCompositeRoleMappingDraftEntity mapping, EntityManager em, Runnable callback) {
        mapping.setDeleteStatus(DraftStatus.DRAFT);
        mapping.setTimestamp(System.currentTimeMillis());
        processExistingRequest(session, em, session.getContext().getRealm(), mapping, ActionType.DELETE );
    }

    @Override
    public AccessToken transformUserContext(AccessToken token, KeycloakSession session, TideCompositeRoleMappingDraftEntity entity, UserModel user, ClientModel clientModel){
        RealmModel realm = session.getContext().getRealm();
        RoleModel childRole = realm.getRoleById(entity.getChildRole().getId());
        RoleModel compositeRole = realm.getRoleById(entity.getComposite().getId());
        UserContextUtils userContextUtils = new UserContextUtils();

        ChangeSetRequest change = getChangeSetRequestFromEntity(session, entity);
        if (change.getActionType().equals(ActionType.CREATE)){
            Set<RoleModel> roleToAdd = getAllAccess(session, Set.of(realm.getDefaultRole()), clientModel, clientModel.getClientScopes(true).values().stream(), clientModel.isFullScopeAllowed(), childRole);
            roleToAdd.forEach(r -> {
                if(change.getActionType().equals(ActionType.CREATE)){
                    addRoleToAccessToken(token, r);
                } else if (change.getActionType().equals(ActionType.DELETE)) {
                    removeRoleFromAccessToken(token, r);
                }
            });
        }
        else if (change.getActionType().equals(ActionType.DELETE)) {
            Set<RoleModel> rolesToDelete = expandCompositeRoles(session, Set.of(childRole));
            rolesToDelete.add(childRole);
            rolesToDelete.forEach(r -> {
                removeRoleFromAccessToken(token, r);
            });
        }

        userContextUtils.normalizeAccessToken(token, true);
        return token;
    }

    @Override
    public void updateAffectedUserContextDrafts(KeycloakSession session , AccessProofDetailEntity affectedUserContextDraft, Set<RoleModel> roles, ClientModel client, TideUserAdapter user, EntityManager em) throws Exception {

        RealmModel realm = session.getContext().getRealm();
        TideCompositeRoleMappingDraftEntity affectedCompositeRoleEntity = em.find(TideCompositeRoleMappingDraftEntity.class, affectedUserContextDraft.getRecordId());
        if (affectedCompositeRoleEntity == null){
            return;
        }

        ChangeSetRequest affectedChangeRequest = getChangeSetRequestFromEntity(session, affectedCompositeRoleEntity);

        if(affectedUserContextDraft.getChangesetType().equals(ChangeSetType.DEFAULT_ROLES)) {
            RoleModel childRole = realm.getRoleById(affectedCompositeRoleEntity.getChildRole().getId());
            ClientModel clientModel = realm.getClientById(affectedUserContextDraft.getClientId());
            String defaultFullScopeUserContext = generateRealmDefaultUserContext(session, realm, clientModel, childRole, em, affectedChangeRequest.getActionType() == ActionType.DELETE);
            affectedUserContextDraft.setProofDraft(defaultFullScopeUserContext);
            return;
        }

        if ((affectedCompositeRoleEntity.getDraftStatus() == DraftStatus.ACTIVE && affectedCompositeRoleEntity.getDeleteStatus() == null)){
            return;
        }

        if ( affectedChangeRequest.getActionType() == ActionType.DELETE){
            affectedCompositeRoleEntity.setDeleteStatus(DraftStatus.DRAFT);
        } else if (affectedChangeRequest.getActionType() == ActionType.CREATE) {
            affectedCompositeRoleEntity.setDraftStatus(DraftStatus.DRAFT);
        }

        String userContextDraft = ChangeSetProcessor.super.generateTransformedUserContext(session, realm, client, user, "openid", affectedCompositeRoleEntity);
        affectedUserContextDraft.setProofDraft(userContextDraft);
    }


    @Override
    public RoleModel getRoleRequestFromEntity(KeycloakSession session, RealmModel realm,TideCompositeRoleMappingDraftEntity entity) {
        return realm.getRoleById(entity.getChildRole().getId());
    }


    private void commitCallback(RealmModel realm, ChangeSetRequest change, TideCompositeRoleMappingDraftEntity entity){
        if (change.getActionType() == ActionType.CREATE) {
            if(entity.getDraftStatus() != DraftStatus.APPROVED){
                throw new RuntimeException("Draft record has not been approved by all admins.");
            }
            entity.setDraftStatus(DraftStatus.ACTIVE);
        } else if (change.getActionType() == ActionType.DELETE) {
            if(entity.getDeleteStatus() != DraftStatus.APPROVED){
                throw new RuntimeException("Deletion has not been approved by all admins.");
            }
            entity.setDeleteStatus(DraftStatus.ACTIVE);
            RoleModel composite = realm.getRoleById(entity.getComposite().getId());
            RoleModel child = realm.getRoleById(entity.getChildRole().getId());
            composite.removeCompositeRole(child);
        }
    }
    private void processExistingRequest(KeycloakSession session, EntityManager em, RealmModel realm, TideCompositeRoleMappingDraftEntity compositeRoleEntity, ActionType action) {
            RoleEntity parentEntity = compositeRoleEntity.getComposite();
            RoleEntity childEntity = compositeRoleEntity.getChildRole();
            RoleModel parentRole = session.getContext().getRealm().getRoleById(parentEntity.getId());
            RoleModel childRole = session.getContext().getRealm().getRoleById(childEntity.getId());

            List<TideUserAdapter> users =  session.users().getRoleMembersStream(realm, parentRole).map(user -> {
                        UserEntity userEntity = em.find(UserEntity.class, user.getId());
                        List<TideUserRoleMappingDraftEntity> userRecords = em.createNamedQuery("getUserRoleAssignmentDraftEntityByStatus", TideUserRoleMappingDraftEntity.class)
                                .setParameter("draftStatus", DraftStatus.ACTIVE)
                                .setParameter("user", userEntity)
                                .setParameter("roleId", parentRole.getId())
                                .getResultList();

                        if(userRecords.isEmpty()){
                            return null;
                        }
                        return new TideUserAdapter(session, realm, em, userEntity);
                    })
                    .filter(Objects::nonNull)  // Filter out null values before collecting
                    .toList();

            if(users.isEmpty()){
                return;
            }

            List<ClientModel> clientList = getUniqueClientList(session, realm, childRole ,em);
            clientList.forEach(client -> {
                try {
                    users.forEach(user -> {
                        UserModel wrappedUser = TideEntityUtils.wrapUserModel(user, session, realm);
                        try {
                            ChangeSetProcessor.super.generateAndSaveTransformedUserContextDraft(session, em, realm, client, wrappedUser, compositeRoleEntity.getId(), ChangeSetType.COMPOSITE_ROLE, compositeRoleEntity);
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }

                    });
                    if(parentRole.equals(realm.getDefaultRole())) {
                        String defaultFullScopeUserContext = generateRealmDefaultUserContext(session, realm, client, childRole, em, true);
                        ChangeSetProcessor.super.saveUserContextDraft(session, em, realm, client, null, compositeRoleEntity.getId(), ChangeSetType.DEFAULT_ROLES, defaultFullScopeUserContext);
                    }
                } catch (Exception ex) {
                    throw  new RuntimeException(ex);
                }
            });
    }

    private String generateRealmDefaultUserContext(KeycloakSession session, RealmModel realm, ClientModel client, RoleModel childRole, EntityManager em, Boolean isDelete) throws Exception {
        List<String> clients = List.of(Constants.ADMIN_CLI_CLIENT_ID, Constants.ADMIN_CONSOLE_CLIENT_ID, Constants.ACCOUNT_CONSOLE_CLIENT_ID);
        String id = KeycloakModelUtils.generateId();
        UserModel dummyUser = session.users().addUser(realm, id, id, true, false);

        AccessToken accessToken = ChangeSetProcessor.super.generateAccessToken(session, realm, client, dummyUser);
        Set<RoleModel> rolesToAdd = getAllAccess(session, Set.of(realm.getDefaultRole()), client, client.getClientScopes(true).values().stream(), client.isFullScopeAllowed(), null);
        rolesToAdd.forEach(r -> {
            if ( realm.getName().equalsIgnoreCase(Config.getAdminRealm())){
                addRoleToAccessTokenMasterRealm(accessToken, r, realm, em);
            }
            else{
                addRoleToAccessToken(accessToken, r);
            }
        });

        if(clients.contains(client.getClientId())){
            accessToken.subject(null);
            session.users().removeUser(realm, dummyUser);
            return ChangeSetProcessor.super.cleanAccessToken(accessToken, List.of("preferred_username"), client.isFullScopeAllowed());
        } else {
            if(isDelete){
                Set<RoleModel> rolesToDelete = expandCompositeRoles(session, Set.of(childRole));
                rolesToDelete.add(childRole);
                rolesToDelete.forEach(r -> {
                    if ( realm.getName().equalsIgnoreCase(Config.getAdminRealm())){
                        removeRoleFromAccessTokenMasterRealm(accessToken, r, realm, em);
                    }
                    else{
                        removeRoleFromAccessToken(accessToken, r);
                    }
                });
            }
            accessToken.subject(null);
            session.users().removeUser(realm, dummyUser);
            return ChangeSetProcessor.super.cleanAccessToken(accessToken, List.of("preferred_username"), client.isFullScopeAllowed());
        }
    }
}