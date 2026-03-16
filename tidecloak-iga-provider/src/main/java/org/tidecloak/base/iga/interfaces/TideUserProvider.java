package org.tidecloak.base.iga.interfaces;

import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import org.keycloak.Config;
import org.keycloak.models.*;
import org.keycloak.models.jpa.JpaUserProvider;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;

import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessor;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessorFactory;
import org.tidecloak.base.iga.ChangeSetProcessors.ChangeSetProcessorFactoryProvider;
import org.tidecloak.base.iga.utils.BasicIGAUtils;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;
import org.tidecloak.shared.enums.WorkflowType;
import org.tidecloak.shared.enums.models.WorkflowParams;
import org.tidecloak.jpa.entities.drafting.TideUserDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;

import java.util.*;
import java.util.stream.Stream;

public class TideUserProvider extends JpaUserProvider {
    private final KeycloakSession session;
    private final ChangeSetProcessorFactory changeSetProcessorFactory = ChangeSetProcessorFactoryProvider.getFactory();

    public TideUserProvider(KeycloakSession session, EntityManager em) {
        super(session, em);
        this.session = session;
    }

    @Override
    public UserModel addUser(RealmModel realm, String username) {
        BasicIGAUtils.stampRequestingAdmin(session);
        // Call the existing functionality from the superclass
        UserModel user = super.addUser(realm, username);

        // Dont draft for master realm
        RealmModel masterRealm = session.realms().getRealmByName(Config.getAdminRealm());
        if(realm.equals(masterRealm)){
            return user;
        }

        UserEntity userEntity = em.getReference(UserEntity.class, user.getId());

        // Add draft record for user
        TideUserDraftEntity draftUser = new TideUserDraftEntity();
        draftUser.setId(KeycloakModelUtils.generateId());
        draftUser.setChangeRequestId(KeycloakModelUtils.generateId());
        draftUser.setUser(userEntity);
        draftUser.setDraftStatus(DraftStatus.DRAFT);
        draftUser.setAction(ActionType.CREATE);
        em.persist(draftUser);

        RoleModel defaultRole =  realm.getDefaultRole();
        TideUserRoleMappingDraftEntity draftDefaultRoleUserRole = new TideUserRoleMappingDraftEntity();
        draftDefaultRoleUserRole.setId(KeycloakModelUtils.generateId());
        draftDefaultRoleUserRole.setChangeRequestId(KeycloakModelUtils.generateId());
        draftDefaultRoleUserRole.setRoleId(defaultRole.getId());
        draftDefaultRoleUserRole.setUser(userEntity);
        draftDefaultRoleUserRole.setAction(ActionType.CREATE);
        draftDefaultRoleUserRole.setDraftStatus(DraftStatus.ACTIVE);
        em.persist(draftDefaultRoleUserRole);
        em.flush();

        return new TideUserAdapter(session, realm, em, userEntity);
    }

    @Override
    public boolean removeUser(RealmModel realm, UserModel user) {
        System.out.println("[TideUserProvider.removeUser] CALLED for user=" + user.getUsername() + " realm=" + realm.getName());
        BasicIGAUtils.stampRequestingAdmin(session);
        UserEntity userEntity = em.find(UserEntity.class, user.getId(), LockModeType.PESSIMISTIC_WRITE);
        if (userEntity == null) return false;

        String igaAttribute = realm.getAttribute("isIGAEnabled");
        boolean isIGAEnabled = igaAttribute != null && igaAttribute.equalsIgnoreCase("true");
        RealmModel masterRealm = session.realms().getRealmByName(Config.getAdminRealm());

        // Skip IGA drafting for internal/dummy user removals (e.g. default user context generation)
        Boolean skipIGA = session.getAttribute("skipIGADraftingForRemove", Boolean.class);
        if (!isIGAEnabled || realm.equals(masterRealm) || Boolean.TRUE.equals(skipIGA)) {
            directRemoveUser(userEntity);
            return true;
        }

        try {
            List<TideUserDraftEntity> userDrafts = em.createNamedQuery("getTideUserDraftEntity", TideUserDraftEntity.class)
                    .setParameter("user", userEntity)
                    .getResultList();

            if (userDrafts.isEmpty()) {
                // Create a draft entity for pre-existing users so deletion goes through IGA
                TideUserDraftEntity newDraft = new TideUserDraftEntity();
                newDraft.setId(KeycloakModelUtils.generateId());
                newDraft.setChangeRequestId(KeycloakModelUtils.generateId());
                newDraft.setUser(userEntity);
                newDraft.setDraftStatus(DraftStatus.ACTIVE);
                newDraft.setAction(ActionType.CREATE);
                newDraft.setDeleteStatus(DraftStatus.DRAFT);
                newDraft.setTimestamp(System.currentTimeMillis());
                em.persist(newDraft);
                em.flush();

                WorkflowParams params = new WorkflowParams(DraftStatus.DRAFT, true, ActionType.DELETE, ChangeSetType.USER);
                changeSetProcessorFactory.getProcessor(ChangeSetType.USER).executeWorkflow(session, newDraft, em, WorkflowType.REQUEST, params, null);
                return true;
            }

            TideUserDraftEntity draft = userDrafts.get(0);

            // Check if this is an approved deletion being committed
            if (draft.getDeleteStatus() == DraftStatus.ACTIVE) {
                em.remove(draft);
                em.flush();
                directRemoveUser(userEntity);
                return true;
            }

            // Already has a pending delete draft
            if (draft.getDeleteStatus() == DraftStatus.DRAFT || draft.getDeleteStatus() == DraftStatus.PENDING) {
                return true;
            }

            // Create delete request
            draft.setDeleteStatus(DraftStatus.DRAFT);
            draft.setTimestamp(System.currentTimeMillis());
            em.flush();

            WorkflowParams params = new WorkflowParams(DraftStatus.DRAFT, true, ActionType.DELETE, ChangeSetType.USER);
            changeSetProcessorFactory.getProcessor(ChangeSetType.USER).executeWorkflow(session, draft, em, WorkflowType.REQUEST, params, null);
            return true;
        } catch (Exception e) {
            System.err.println("[TideUserProvider.removeUser] ERROR during delete draft workflow: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    /**
     * Directly removes a user and all associated records. Called after approval or when IGA is disabled.
     */
    public void directRemoveUser(UserEntity user) {
        em.createNamedQuery("deleteProofByUser").setParameter("user", user).executeUpdate();
        em.createNamedQuery("deleteAllDraftProofRecordsForUser").setParameter("user", user).executeUpdate();
        em.createNamedQuery("deleteUserDrafts").setParameter("user", user).executeUpdate();
        em.createNamedQuery("deleteUserRoleMappingDraftsByUser").setParameter("user", user).executeUpdate();
        em.createNamedQuery("deleteUserRoleMappingsByUser").setParameter("user", user).executeUpdate();
        em.createNamedQuery("deleteUserGroupMembershipsByUser").setParameter("user", user).executeUpdate();
        em.createNamedQuery("deleteUserConsentClientScopesByUser").setParameter("user", user).executeUpdate();
        em.createNamedQuery("deleteUserConsentsByUser").setParameter("user", user).executeUpdate();

        em.remove(user);
        em.flush();
    }

    @Override
    public void preRemove(RealmModel realm){
        ClientModel masterAdminClient = realm.getMasterAdminClient();
        RealmModel masterRealm =  this.session.realms().getRealmByName(Config.getAdminRealm());
        ClientModel client = this.session.clients().getClientById(masterRealm, masterAdminClient.getId());
        if (client != null){
            client.getRolesStream().forEach(r -> {
                em.createNamedQuery("DeleteAllCompositeRoleMappingsByRoleId")
                        .setParameter("roleId", r.getId())
                        .executeUpdate();
                em.createNamedQuery("DeleteAllCompositeRoleDraftsByRole")
                        .setParameter("roleId", r.getId())
                        .executeUpdate();
                em.createNamedQuery("DeleteRoleDraftByRole")
                        .setParameter("id", r.getId())
                        .executeUpdate();
                em.createNamedQuery("DeleteAllUserRoleMappingDraftsByRole")
                        .setParameter("roleId", r.getId())
                        .executeUpdate();
            });
            em.createNamedQuery("DeleteAllAccessProofsByClient")
                    .setParameter("clientId", client.getId())
                    .executeUpdate();
        }

        em.createNamedQuery("deleteClientFullScopeStatusByRealm")
                .setParameter("realmId", realm.getId())
                .executeUpdate();
        em.createNamedQuery("DeleteAllCompositeRoleDraftsByRealm")
                .setParameter("realmId", realm.getId())
                .executeUpdate();
        em.createNamedQuery("DeleteAllCompositeRoleMappingsByRealm").setParameter("realmId", realm.getId()).executeUpdate();
        em.createNamedQuery("DeleteRoleDraftByRealm").setParameter("realmId", realm.getId()).executeUpdate();
        em.createNamedQuery("DeleteAllUserProofsByRealm").setParameter("realmId", realm.getId()).executeUpdate();
        em.createNamedQuery("DeleteAllAccessProofsByRealm").setParameter("realmId", realm.getId()).executeUpdate();
        em.createNamedQuery("DeleteAllTideUserDraftEntityByRealm").setParameter("realmId", realm.getId()).executeUpdate();
        em.createNamedQuery("DeleteAllUserRoleMappingDraftsByRealm").setParameter("realmId", realm.getId()).executeUpdate();
        em.createNamedQuery("deleteUserConsentClientScopesByRealm")
                .setParameter("realmId", realm.getId()).executeUpdate();
        em.createNamedQuery("deleteUserConsentsByRealm")
                .setParameter("realmId", realm.getId()).executeUpdate();
        em.createNamedQuery("deleteUserRoleMappingsByRealm")
                .setParameter("realmId", realm.getId()).executeUpdate();
        em.createNamedQuery("deleteUserRequiredActionsByRealm")
                .setParameter("realmId", realm.getId()).executeUpdate();
        em.createNamedQuery("deleteFederatedIdentityByRealm")
                .setParameter("realmId", realm.getId()).executeUpdate();
        em.createNamedQuery("deleteCredentialsByRealm")
                .setParameter("realmId", realm.getId()).executeUpdate();
        em.createNamedQuery("deleteUserAttributesByRealm")
                .setParameter("realmId", realm.getId()).executeUpdate();
        em.createNamedQuery("deleteUserGroupMembershipByRealm")
                .setParameter("realmId", realm.getId()).executeUpdate();
        em.createNamedQuery("deleteUsersByRealm")
                .setParameter("realmId", realm.getId()).executeUpdate();
        
    }

    /**
     *
     * We are returning our TideUserAdapter here. Everything else works the same as the super.
     *
     */

    @Override
    public Stream<UserModel> getGroupMembersStream(RealmModel realm, GroupModel group) {
        return super.getGroupMembersStream(realm, group)
                .map(user -> {
                    UserEntity userEntity = em.find(UserEntity.class, user.getId());
                    return new TideUserAdapter(session, realm, em, userEntity);
                });
    }

    @Override
    public Stream<UserModel> getRoleMembersStream(RealmModel realm, RoleModel role) {
        Stream<UserModel> activeMembers = super.getRoleMembersStream(realm, role)
                .map(user -> {
                    UserEntity userEntity = em.find(UserEntity.class, user.getId());
                    List<TideUserRoleMappingDraftEntity> userRecords = em.createNamedQuery("getUserRoleAssignmentDraftEntityByStatus", TideUserRoleMappingDraftEntity.class)
                            .setParameter("draftStatus", DraftStatus.ACTIVE)
                            .setParameter("user", userEntity)
                            .setParameter("roleId", role.getId())
                            .getResultList();


                    if(userRecords == null || userRecords.isEmpty()){
                        return null;
                    }
                    return new TideUserAdapter(session, realm, em, userEntity);
                });

        return activeMembers.filter(Objects::nonNull);
    }


    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        UserModel userModel = super.getUserByUsername(realm, username);
        if ( userModel == null) {
            return null;
        }
        UserEntity userEntity = em.find(UserEntity.class, userModel.getId());
        return new TideUserAdapter(session, realm, em, userEntity);
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        UserModel userModel = super.getUserByEmail(realm, email);
        if (userModel != null) {
            UserEntity userEntity = em.find(UserEntity.class, userModel.getId());
            ensureEmailConstraint(Collections.singletonList(userEntity), realm);
            return new TideUserAdapter(session, realm, em, userEntity);
        }
        return null;
    }

    @Override
    public Stream<UserModel> getGroupMembersStream(RealmModel realm, GroupModel group, Integer firstResult, Integer maxResults) {
        return super.getGroupMembersStream(realm, group, firstResult, maxResults)
                .map(user -> {
                    UserEntity userEntity = em.find(UserEntity.class, user.getId());
                    return new TideUserAdapter(session, realm, em, userEntity);
                });
    }

    @Override
    public Stream<UserModel> getRoleMembersStream(RealmModel realm, RoleModel role, Integer firstResult, Integer maxResults) {
        return super.getRoleMembersStream(realm, role, firstResult, maxResults)
                .map(user -> {
                    UserEntity userEntity = em.find(UserEntity.class, user.getId());
                    return new TideUserAdapter(session, realm, em, userEntity);
                });
    }

    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        UserModel userModel = super.getUserById(realm, id);
        if ( userModel == null) {
            return null;
        }
        UserEntity userEntity = em.find(UserEntity.class, userModel.getId());
        return new TideUserAdapter(session, realm, em, userEntity);
    }

    @Override
    public UserModel getUserByFederatedIdentity(RealmModel realm, FederatedIdentityModel identity) {
        UserModel userModel = super.getUserByFederatedIdentity(realm, identity);
        if (userModel == null) {
            return null;
        } else if (userModel instanceof List && ((List<?>) userModel).size() > 1) {
            throw new IllegalStateException("More results found for identityProvider=" + identity.getIdentityProvider() +
                    ", userId=" + identity.getUserId() + ", results=" + userModel);
        } else {
            UserEntity userEntity = em.find(UserEntity.class, userModel.getId());
            return new TideUserAdapter(session, realm, em, userEntity);
        }
    }

    @Override
    public UserModel getServiceAccount(ClientModel client) {
        UserModel userModel = super.getServiceAccount(client);
        if (userModel == null) {
            return null;
        } else if (userModel instanceof List && ((List<?>) userModel).size() > 1) {
            throw new IllegalStateException("More service account linked users found for client=" + client.getClientId() +
                    ", results=" + userModel);
        } else {
            UserEntity userEntity = em.find(UserEntity.class, userModel.getId());
            return new TideUserAdapter(session, client.getRealm(), em, userEntity);
        }
    }

    @Override
    public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realm, String attrName, String attrValue) {
        return super.searchForUserByUserAttributeStream(realm, attrName, attrValue)
                .map(user -> {
                    UserEntity userEntity = em.find(UserEntity.class, user.getId());
                    return new TideUserAdapter(session, realm, em, userEntity);
                });
    }
}
