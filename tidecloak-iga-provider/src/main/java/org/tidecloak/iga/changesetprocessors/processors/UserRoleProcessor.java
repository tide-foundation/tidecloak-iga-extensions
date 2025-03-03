package org.tidecloak.iga.changesetprocessors.processors;

import jakarta.persistence.EntityManager;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.representations.AccessToken;
import org.midgard.models.InitializerCertificateModel.InitializerCertifcate;
import org.midgard.models.UserContext.UserContext;
import org.tidecloak.iga.changesetprocessors.ChangeSetProcessor;
import org.tidecloak.iga.changesetprocessors.models.ChangeSetRequest;
import org.tidecloak.iga.changesetprocessors.utils.ClientUtils;
import org.tidecloak.iga.changesetprocessors.utils.TideEntityUtils;
import org.tidecloak.iga.changesetprocessors.utils.UserContextUtils;
import org.tidecloak.jpa.entities.AuthorizerEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.drafting.RoleInitializerCertificateDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideRoleDraftEntity;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.iga.interfaces.TideRoleAdapter;
import org.tidecloak.iga.interfaces.TideUserAdapter;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.shared.enums.ActionType;


import java.util.*;
import java.util.stream.Collectors;

import static org.tidecloak.iga.TideRequests.TideRoleRequests.commitRoleInitCert;
import static org.tidecloak.iga.TideRequests.TideRoleRequests.createRoleInitCertDraft;
import static org.tidecloak.iga.changesetprocessors.utils.ChangeRequestUtils.getChangeSetRequestFromEntity;
import static org.tidecloak.iga.changesetprocessors.utils.UserContextUtils.addRoleToAccessToken;
import static org.tidecloak.iga.changesetprocessors.utils.UserContextUtils.removeRoleFromAccessToken;

public class UserRoleProcessor implements ChangeSetProcessor<TideUserRoleMappingDraftEntity> {

    protected static final Logger logger = Logger.getLogger(UserRoleProcessor.class);

    @Override
    public void cancel(KeycloakSession session, TideUserRoleMappingDraftEntity entity, EntityManager em, ActionType actionType){
        RealmModel realmModel = session.realms().getRealm(entity.getUser().getRealmId());
        RoleModel role = realmModel.getRoleById(entity.getRoleId());
        TideUserAdapter user = new TideUserAdapter(session, realmModel, em, entity.getUser());
        List<AccessProofDetailEntity> accessProofDetailEntities = UserContextUtils.getUserContextDrafts(em, entity.getId());
        accessProofDetailEntities.forEach(em::remove);

        List<TideUserRoleMappingDraftEntity> pendingDrafts = em.createNamedQuery("getUserRoleAssignmentDraftEntityByStatusNotEqualTo", TideUserRoleMappingDraftEntity.class)
                .setParameter("user", entity.getUser())
                .setParameter("roleId", role.getId())
                .setParameter("draftStatus", DraftStatus.ACTIVE)
                .getResultList();
        user.deleteRoleAndProofRecords(role, pendingDrafts, actionType);
        em.flush();

        ChangesetRequestEntity changesetRequestEntity = em.find(ChangesetRequestEntity.class, new ChangesetRequestEntity.Key(entity.getId(), ChangeSetType.USER_ROLE));
        if(changesetRequestEntity != null){
            em.remove(changesetRequestEntity);
            em.flush();
        }
    }

    @Override
    public void commit(KeycloakSession session, ChangeSetRequest change, TideUserRoleMappingDraftEntity entity, EntityManager em, Runnable commitCallback) throws Exception {
        logger.debug(String.format(
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

        // Recreate for tide-admin-realm assignment here
        RoleModel role = realm.getRoleById(entity.getRoleId());

        if(Objects.equals(role.getName(), org.tidecloak.shared.Constants.TIDE_REALM_ADMIN)) {
            ComponentModel componentModel = realm.getComponentsStream()
                    .filter(x -> "tide-vendor-key".equals(x.getProviderId()))  // Use .equals for string comparison
                    .findFirst()
                    .orElse(null);

            if(componentModel == null) {
                throw new Exception("There is no tide-vendor-key component set up for this realm, " + realm.getName());
            }
            List<AuthorizerEntity> realmAuthorizers = em.createNamedQuery("getAuthorizerByProviderId", AuthorizerEntity.class)
                    .setParameter("ID", componentModel.getId()).getResultList();
            if (realmAuthorizers.isEmpty()){
                throw new Exception("Authorizer not found for this realm.");
            }

            List<TideUserRoleMappingDraftEntity> tideAdminRealmRoleRequests = em.createNamedQuery("getUserRoleMappingDraftsByRoleAndStatusNotEqualTo", TideUserRoleMappingDraftEntity.class)
                    .setParameter("roleId", role.getId())
                    .setParameter("draftStatus", DraftStatus.ACTIVE)
                    .getResultList();

            List<ClientModel> clientList = ClientUtils.getUniqueClientList(session, realm, role, em);

            tideAdminRealmRoleRequests.forEach(request -> {
                try {
                    UserModel u = session.users().getUserById(realm, request.getUser().getId());
                    List<ChangesetRequestEntity> changesetRequestEntity = em.createNamedQuery("getAllChangeRequestsByRecordId", ChangesetRequestEntity.class).setParameter("changesetRequestId", request.getId()).getResultList();
                    if(!changesetRequestEntity.isEmpty()) {
                        changesetRequestEntity.forEach(em::remove);
                    }
                    em.flush();
                    List<AccessProofDetailEntity> accessProofs = em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                            .setParameter("recordId", request.getId()).getResultList();
                    accessProofs.forEach(p -> {
                        em.remove(p);
                        em.flush();
                    });
                    List<RoleInitializerCertificateDraftEntity> roleInitializerCertificateDraftEntity = em.createNamedQuery("getInitCertByChangeSetId", RoleInitializerCertificateDraftEntity.class).setParameter("changesetId", request.getId()).getResultList();
                    if(!roleInitializerCertificateDraftEntity.isEmpty()){
                        em.remove(roleInitializerCertificateDraftEntity.get(0));
                        em.flush();
                    }
                    //createRoleInitCertDraft(session, request.getId(), "1", 0.7, 1);
                    processRealmManagementRoleAssignment(session, em, realm, clientList, request, u);

                } catch (Exception e) {
                    throw new RuntimeException(e);
                }

            });
        }


        // Log successful completion
        logger.debug(String.format(
                "Successfully processed workflow: COMMIT. Processor: %s, Mapping ID: %s",
                this.getClass().getSimpleName(),
                entity.getId()
        ));
    }

    @Override
    public void request(KeycloakSession session, TideUserRoleMappingDraftEntity entity, EntityManager em, ActionType action, Runnable callback, ChangeSetType changeSetType) {
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
        UserModel affectedUser = session.users().getUserById(realm, entity.getUser().getId());
        Set<UserModel> users = new TreeSet<>(Comparator.comparing(UserModel::getId));
        users.add(affectedUser);
        if(roleEntity != null && roleEntity.getName().equalsIgnoreCase(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN)){
            Set<UserModel> adminUsers = em.createNamedQuery("getUserRoleMappingsByStatusAndRole", TideUserRoleMappingDraftEntity.class)
                    .setParameter("draftStatus", DraftStatus.ACTIVE)
                    .setParameter("roleId", entity.getRoleId())
                    .getResultList().stream()
                    .map(t -> session.users().getUserById(realm, t.getUser().getId()))
                    .collect(Collectors.toSet());

            users.addAll(adminUsers);
        }

        RoleModel tideRoleModel = TideEntityUtils.toTideRoleAdapter(roleEntity, session, realm);
        List<TideUserRoleMappingDraftEntity> activeDraftEntities = TideUserAdapter.getActiveDraftEntities(em, entity.getUser(), tideRoleModel);
        if ( activeDraftEntities.isEmpty()){
            return;
        }

        TideUserRoleMappingDraftEntity userRoleMapping = activeDraftEntities.get(0);
        
        if(userRoleMapping.getDeleteStatus() != null)
        {
            return;
        }

        // Mark entities as pending delete.
        userRoleMapping.setDeleteStatus(DraftStatus.DRAFT);
        userRoleMapping.setTimestamp(System.currentTimeMillis());

        List<ClientModel> clientList = ClientUtils.getUniqueClientList(session, realm, tideRoleModel, em);

        clientList.forEach(client -> {
            users.forEach(user -> {
                    try {
                        UserEntity u = em.find(UserEntity.class, user.getId());
                        UserModel wrappedUser = TideEntityUtils.toTideUserAdapter(u, session, realm);
                        ChangeSetProcessor.super.generateAndSaveTransformedUserContextDraft(session, em, realm, client, wrappedUser, userRoleMapping.getId(),
                            ChangeSetType.USER_ROLE, userRoleMapping);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                });
        });
    }

    @Override
    public RoleModel getRoleRequestFromEntity(KeycloakSession session, RealmModel realm, TideUserRoleMappingDraftEntity entity) {
        return realm.getRoleById(entity.getRoleId());
    }

    @Override
    public void updateAffectedUserContextDrafts(KeycloakSession session, AccessProofDetailEntity affectedUserContextDraft, Set<RoleModel> roles, ClientModel client, TideUserAdapter userChangesMadeTo, EntityManager em) throws Exception {
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

        UserEntity userEntity = affectedUserContextDraft.getUser();
        TideUserAdapter affectedUser = TideEntityUtils.toTideUserAdapter(userEntity, session, realm);

        String userContextDraft = ChangeSetProcessor.super.generateTransformedUserContext(session, realm, client, affectedUser, "openId", affectedUserRoleEntity);

        if(client.getClientId().equals(Constants.REALM_MANAGEMENT_CLIENT_ID)) {
            RoleEntity roleEntity = em.find(RoleEntity.class, affectedUserRoleEntity.getRoleId());
            if(roleEntity.getName().equalsIgnoreCase(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN)) {
                List<TideRoleDraftEntity> tideRoleDraftEntity = em.createNamedQuery("getRoleDraftByRole", TideRoleDraftEntity.class)
                        .setParameter("role", roleEntity).getResultList();
                if(tideRoleDraftEntity.isEmpty()){
                    throw new RuntimeException("Tide realm admin role doesnt exist");
                }
                UserContext userContext = new UserContext(userContextDraft);
                InitializerCertifcate initializerCertifcate = InitializerCertifcate.FromString(tideRoleDraftEntity.get(0).getInitCert());
                userContext.setInitCertHash(initializerCertifcate.hash());

                UserContext oldUserContext = new UserContext(affectedUserContextDraft.getProofDraft());
                if(oldUserContext.getInitCertHash() != null || oldUserContext.getThreshold() != 0){
                    userContext.setThreshold(initializerCertifcate.getPayload().getThreshold());
                    affectedUserContextDraft.setProofDraft(userContext.ToString());
                }

                return;
            }
        }

        affectedUserContextDraft.setProofDraft(userContextDraft);
    }

    @Override
    public AccessToken transformUserContext(AccessToken token, KeycloakSession session, TideUserRoleMappingDraftEntity entity, UserModel user, ClientModel clientModel){
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
                if(Objects.equals(entity.getUser().getId(), user.getId())) {
                    removeRoleFromAccessToken(token, r);
                }
            }
        });
        userContextUtils.normalizeAccessToken(token, clientModel.isFullScopeAllowed());
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
        Set<UserModel> adminUsers = new HashSet<>();
        adminUsers.add(userModel);
        ClientModel realmManagementClient = realm.getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID);
        RoleEntity roleEntity = em.find(RoleEntity.class, entity.getRoleId());
        RoleModel role = realmManagementClient.getRole(roleEntity.getName());
        if(role != null && role.getName().equalsIgnoreCase(org.tidecloak.shared.Constants.TIDE_REALM_ADMIN)){
            Set<UserModel> users = em.createNamedQuery("getUserRoleMappingsByStatusAndRole", TideUserRoleMappingDraftEntity.class)
                    .setParameter("draftStatus", DraftStatus.ACTIVE)
                    .setParameter("roleId", entity.getRoleId())
                    .getResultList().stream()
                    .map(t -> session.users().getUserById(realm, t.getUser().getId()))
                    .collect(Collectors.toSet());

            adminUsers.addAll(users);
        }
        clientList.forEach(client -> {
            try {
                boolean isAdminClient = client.getClientId().equalsIgnoreCase(Constants.ADMIN_CONSOLE_CLIENT_ID) || client.getClientId().equalsIgnoreCase(Constants.ADMIN_CLI_CLIENT_ID);
                adminUsers.forEach(u -> {
                    try {
                        if (isAdminClient){
                            // Create empty user contexts for ADMIN-CLI and SECURITY-ADMIN-CONSOLE
                            ChangeSetProcessor.super.generateAndSaveDefaultUserContextDraft(session, em, realm, client, u, entity.getId(),
                                    ChangeSetType.USER_ROLE);
                        } else {
                            ChangeSetProcessor.super.generateAndSaveTransformedUserContextDraft(session, em, realm, client, u, entity.getId(),
                                    ChangeSetType.USER_ROLE, entity);
                        }
                    }catch (Exception e) {
                        throw new RuntimeException("Error processing client: " + client.getClientId(), e);
                    }
                });
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
