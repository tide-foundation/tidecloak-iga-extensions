package org.tidecloak.iga.changesetprocessors.processors;

import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.representations.AccessToken;
import org.tidecloak.iga.changesetprocessors.ChangeSetProcessor;
import org.tidecloak.iga.changesetprocessors.models.ChangeSetRequest;
import org.tidecloak.iga.changesetprocessors.utils.ClientUtils;
import org.tidecloak.iga.changesetprocessors.utils.TideEntityUtils;
import org.tidecloak.iga.changesetprocessors.utils.UserContextUtils;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.iga.interfaces.TideRoleAdapter;
import org.tidecloak.iga.interfaces.TideUserAdapter;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.shared.enums.ActionType;


import java.util.*;
import java.util.stream.Collectors;

import static org.tidecloak.iga.changesetprocessors.utils.ChangeRequestUtils.getChangeSetRequestFromEntity;
import static org.tidecloak.iga.changesetprocessors.utils.UserContextUtils.addRoleToAccessToken;
import static org.tidecloak.iga.changesetprocessors.utils.UserContextUtils.removeRoleFromAccessToken;

public class UserRoleProcessor implements ChangeSetProcessor<TideUserRoleMappingDraftEntity> {

    protected static final Logger logger = Logger.getLogger(UserRoleProcessor.class);

    @Override
    public void commit(KeycloakSession session, ChangeSetRequest change, TideUserRoleMappingDraftEntity entity, EntityManager em, Runnable commitCallback) throws Exception {
        logger.info(String.format(
                "Starting workflow: COMMIT. Processor: %s, Action: %s, Entity ID: %s",
                this.getClass().getSimpleName(),
                change.getActionType(),
                entity.getId()
        ));

        RealmModel realm = session.getContext().getRealm();
        UserModel user = session.users().getUserById(realm, entity.getUser().getId());

        Runnable callback = () -> {
            try {
                commitUserRoleChangeRequest(user, realm, entity, change);
            } catch (Exception e) {
                throw new RuntimeException("Error during commit callback", e);
            }
        };

        ChangeSetProcessor.super.commit(session, change, entity, em, callback);

        // Log successful completion
        logger.info(String.format(
                "Successfully processed workflow: COMMIT. Processor: %s, Mapping ID: %s",
                this.getClass().getSimpleName(),
                entity.getId()
        ));
    }

    @Override
    public void request(KeycloakSession session, TideUserRoleMappingDraftEntity entity, EntityManager em, ActionType action, Runnable callback) {
        try {
            // Log the start of the request with detailed context
            logger.info(String.format(
                    "Starting workflow: REQUEST. Processor: %s, Action: %s, Entity ID: %s",
                    this.getClass().getSimpleName(),
                    action,
                    entity.getId()
            ));

            switch (action) {
                case CREATE:
                    logger.info(String.format("Initiating CREATE action for Mapping ID: %s in workflow: REQUEST", entity.getId()));
                    handleCreateRequest(session, entity, em, callback);
                    break;
                case DELETE:
                    logger.info(String.format("Initiating DELETE action for Mapping ID: %s in workflow: REQUEST", entity.getId()));
                    handleDeleteRequest(session, entity, em, callback);
                    break;
                default:
                    logger.warn(String.format("Unsupported action type: %s for Mapping ID: %s in workflow: REQUEST", action, entity.getId()));
                    throw new IllegalArgumentException("Unsupported action: " + action);
            }

            // Log successful completion
            logger.info(String.format(
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
            throw new RuntimeException("Failed to process USER_ROLE request", e);
        }
    }


    @Override
    public void handleCreateRequest(KeycloakSession session, TideUserRoleMappingDraftEntity mapping, EntityManager em, Runnable callback) {
        RealmModel realm = session.getContext().getRealm();
        RoleModel role = realm.getRoleById(mapping.getRoleId());
        UserModel userModel = TideEntityUtils.toTideUserAdapter(mapping.getUser(), session, realm);

        Set<RoleModel> roleMappings = Collections.singleton(role);
        List<ClientModel> clientList = ClientUtils.getUniqueClientList(session, realm, role, em);

        if (role.isClientRole() && isRealmManagementClient(role)) {
            processRealmManagementRoleAssignment(session, em, realm, clientList, mapping, userModel);
        } else {
            processRoles(session, em, realm, clientList, roleMappings, mapping, userModel);
        }

        em.flush();
    }

    @Override
    public void handleDeleteRequest(KeycloakSession session, TideUserRoleMappingDraftEntity entity, EntityManager em, Runnable callback) {
        RealmModel realm = session.getContext().getRealm();
        RoleEntity roleEntity = em.find(RoleEntity.class, entity.getRoleId());
        RoleModel tideRoleModel = TideEntityUtils.toTideRoleAdapter(roleEntity, session, realm);
        List<TideUserRoleMappingDraftEntity> activeDraftEntities = TideUserAdapter.getActiveDraftEntities(em, entity.getUser(), tideRoleModel);
        if ( activeDraftEntities.isEmpty()){
            return;
        }

        TideUserRoleMappingDraftEntity userRoleMapping = activeDraftEntities.get(0);

        // Mark entities as pending delete.
        userRoleMapping.setDeleteStatus(DraftStatus.DRAFT);
        userRoleMapping.setTimestamp(System.currentTimeMillis());

        List<ClientModel> clientList = ClientUtils.getUniqueClientList(session, realm, tideRoleModel, em);
        UserModel wrappedUser = TideEntityUtils.toTideUserAdapter(entity.getUser(), session, realm);

        clientList.forEach(client -> {
            try {
                ChangeSetProcessor.super.generateAndSaveTransformedUserContextDraft(session, em, realm, client, wrappedUser, userRoleMapping.getId(),
                        ChangeSetType.USER_ROLE, userRoleMapping);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    @Override
    public RoleModel getRoleRequestFromEntity(KeycloakSession session, RealmModel realm, TideUserRoleMappingDraftEntity entity) {
        return realm.getRoleById(entity.getRoleId());
    }

    @Override
    public void updateAffectedUserContextDrafts(KeycloakSession session, AccessProofDetailEntity affectedUserContextDraft, Set<RoleModel> roles, ClientModel client, TideUserAdapter user, EntityManager em) throws Exception {
        RealmModel realm = session.getContext().getRealm();
        TideUserRoleMappingDraftEntity affectedUserRoleEntity = em.find(TideUserRoleMappingDraftEntity.class, affectedUserContextDraft.getRecordId());
        if (affectedUserRoleEntity == null || (affectedUserRoleEntity.getDraftStatus() == DraftStatus.ACTIVE && (affectedUserRoleEntity.getDeleteStatus() == null || affectedUserRoleEntity.getDeleteStatus().equals(DraftStatus.NULL)))){
            return;
        }

        ChangeSetRequest affectedChangeRequest = getChangeSetRequestFromEntity(session, affectedUserRoleEntity);

        if(affectedChangeRequest.getActionType() == ActionType.DELETE) {
            affectedUserRoleEntity.setDeleteStatus(DraftStatus.DRAFT);
        }else if (affectedChangeRequest.getActionType() == ActionType.CREATE) {
            affectedUserRoleEntity.setDraftStatus(DraftStatus.DRAFT);
        }

        String userContextDraft = ChangeSetProcessor.super.generateTransformedUserContext(session, realm, client, user, "openid", affectedUserRoleEntity);
        affectedUserContextDraft.setProofDraft(userContextDraft);
    }

    @Override
    public AccessToken transformUserContext(AccessToken token, KeycloakSession session, TideUserRoleMappingDraftEntity entity, UserModel user){
        RealmModel realm = session.getContext().getRealm();
        RoleModel role = realm.getRoleById(entity.getRoleId());

        Set<RoleModel> tideRoleModel = Set.of(TideEntityUtils.toTideRoleAdapter(role, session, realm));

        UserContextUtils userContextUtils = new UserContextUtils();
        Set<RoleModel> roleModelSet = userContextUtils.expandActiveCompositeRoles(session, tideRoleModel);

        ChangeSetRequest change = getChangeSetRequestFromEntity(session, entity);
        roleModelSet.forEach(r -> {
            if(change.getActionType().equals(ActionType.CREATE)){
                addRoleToAccessToken(token, r);
            } else if (change.getActionType().equals(ActionType.DELETE)) {
                removeRoleFromAccessToken(token, r);
            }
        });
        userContextUtils.normalizeAccessToken(token);
        return token;
    }

    // Helper Methods
    private void commitUserRoleChangeRequest(UserModel user, RealmModel realm, TideUserRoleMappingDraftEntity entity, ChangeSetRequest change) {;
        RoleModel role = realm.getRoleById(entity.getRoleId());
        if (role == null) return;

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
            user.deleteRoleMapping(role);
        }
    }

    private boolean isRealmManagementClient(RoleModel role) {
        return ((ClientModel) role.getContainer()).getClientId().equalsIgnoreCase(Constants.REALM_MANAGEMENT_CLIENT_ID);
    }

    private void processRealmManagementRoleAssignment(KeycloakSession session, EntityManager em, RealmModel realm, List<ClientModel> clientList,
                                                       TideUserRoleMappingDraftEntity entity, UserModel userModel) {
        clientList.forEach(client -> {
            try {
                boolean isRealmManagementClient = client.getClientId().equalsIgnoreCase(Constants.REALM_MANAGEMENT_CLIENT_ID);
                if (isRealmManagementClient) {
                    ChangeSetProcessor.super.generateAndSaveTransformedUserContextDraft(session, em, realm, client, userModel, entity.getId(),
                            ChangeSetType.USER_ROLE, entity);
                } else {
                    // Create empty user contexts for ADMIN-CLI and SECURITY-ADMIN-CONSOLE
                    ChangeSetProcessor.super.generateAndSaveDefaultUserContextDraft(session, em, realm, client, userModel, entity.getId(),
                            ChangeSetType.USER_ROLE);
                }
            } catch (Exception e) {
                throw new RuntimeException("Error processing client: " + client.getClientId(), e);
            }
        });
    }

    private void processRoles(KeycloakSession session, EntityManager em, RealmModel realm, List<ClientModel> clientList,
                                                  Set<RoleModel> roleMappings, TideUserRoleMappingDraftEntity entity, UserModel userModel) {
        clientList.forEach(client -> {
            try {
                if (isAdminClient(client)) {
                    return;
                }
                ChangeSetProcessor.super.generateAndSaveTransformedUserContextDraft(session, em, realm, client, userModel, entity.getId(),
                        ChangeSetType.USER_ROLE, entity);
            } catch (Exception e) {
                throw new RuntimeException("Error processing client: " + client.getClientId(), e);
            }
        });
    }

    private boolean isAdminClient(ClientModel client) {
        return client.getClientId().equalsIgnoreCase(Constants.ADMIN_CONSOLE_CLIENT_ID) ||
                client.getClientId().equalsIgnoreCase(Constants.ADMIN_CLI_CLIENT_ID);
    }


    private Set<TideRoleAdapter> wrapRolesAsTideAdapters(Set<RoleModel> roles, KeycloakSession session, RealmModel realm, EntityManager em) {
        return roles.stream()
                .map(r -> new TideRoleAdapter(session, realm, em, em.getReference(RoleEntity.class, r.getId())))
                .collect(Collectors.toSet());
    }

    private Set<RoleModel> expandAllCompositeRoles(Set<TideRoleAdapter> wrappedRoles) {
        Set<RoleModel> compositeRoles = new HashSet<>();
        compositeRoles.addAll(TideEntityUtils.expandCompositeRoles(wrappedRoles, DraftStatus.DRAFT));
        compositeRoles.addAll(TideEntityUtils.expandCompositeRoles(wrappedRoles, DraftStatus.PENDING));
        compositeRoles.addAll(TideEntityUtils.expandCompositeRoles(wrappedRoles, DraftStatus.APPROVED));
        compositeRoles.addAll(TideEntityUtils.expandCompositeRoles(wrappedRoles, DraftStatus.ACTIVE));

        return compositeRoles.stream().filter(Objects::nonNull).collect(Collectors.toSet());
    }

    private List<AccessProofDetailEntity> getUserContextDrafts(EntityManager em, ClientModel client, TideUserRoleMappingDraftEntity entity) {
        UserEntity user = entity.getUser();
        return em.createNamedQuery("getProofDetailsForUserByClient", AccessProofDetailEntity.class)
                .setParameter("user", user)
                .setParameter("clientId", client.getId())
                .getResultList();
    }


    private List<TideUserRoleMappingDraftEntity> getUserRoleMappings(EntityManager em, String changeSetId, ActionType action, RealmModel realm) {
        String queryName = action == ActionType.CREATE ? "getUserRoleMappingsByStatusAndRealmAndRecordId" : "getUserRoleMappingsByDeleteStatusAndRealmAndRecordId";
        return em.createNamedQuery(queryName, TideUserRoleMappingDraftEntity.class)
                .setParameter(action == ActionType.CREATE ? "draftStatus" : "deleteStatus", DraftStatus.APPROVED)
                .setParameter("changesetId", changeSetId)
                .setParameter("realmId", realm.getId())
                .getResultList();
    }

}
