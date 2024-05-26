package org.tidecloak.jpa.models;

import com.fasterxml.jackson.core.JsonProcessingException;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.persistence.TypedQuery;
import org.keycloak.Config;
import org.keycloak.admin.ui.rest.model.ClientRole;
import org.keycloak.models.*;
import org.keycloak.models.jpa.JpaUserProvider;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.storage.jpa.JpaHashUtils;

import org.tidecloak.interfaces.ActionType;
import org.tidecloak.interfaces.ChangeSetType;
import org.tidecloak.interfaces.DraftStatus;
import org.tidecloak.jpa.entities.drafting.TideUserDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.jpa.utils.ProofGeneration;
import org.tidecloak.jpa.utils.TideAuthzProofUtil;
import org.tidecloak.jpa.utils.TideRolesUtil;

import java.util.*;
import java.util.stream.Stream;

import static org.keycloak.models.jpa.PaginationUtils.paginateQuery;
import static org.keycloak.storage.jpa.JpaHashUtils.predicateForFilteringUsersByAttributes;
import static org.keycloak.utils.StreamsUtil.*;

public class TideUserProvider extends JpaUserProvider {
    private final KeycloakSession session;

    public TideUserProvider(KeycloakSession session, EntityManager em) {
        super(session, em);
        this.session = session;
    }

    @Override
    public UserModel addUser(RealmModel realm, String username) {
        // Call the existing functionality from the superclass
        UserModel user = super.addUser(realm, username);
        UserEntity userEntity = em.getReference(UserEntity.class, user.getId());

        // Add draft record for user
        TideUserDraftEntity draftUser = new TideUserDraftEntity();
        draftUser.setId(KeycloakModelUtils.generateId());
        draftUser.setUser(userEntity);
        draftUser.setDraftStatus(DraftStatus.DRAFT);
        draftUser.setAction(ActionType.CREATE);
        em.persist(draftUser);

        // Add draft record for user groups. DEFAULT ROLES ARE COMMITED BY DEFAULT FOR NOW
        // TODO: have a step here that goes and gets it signed by VVK automatically and save final proof to DB
        RoleModel defaultRole =  realm.getDefaultRole();
        var draftDefaultRoleUserRole = new TideUserRoleMappingDraftEntity();
        draftDefaultRoleUserRole.setId(KeycloakModelUtils.generateId());
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
        UserEntity userEntity = em.find(UserEntity.class, user.getId(), LockModeType.PESSIMISTIC_WRITE);
        if (userEntity == null) return false;
        removeUser(userEntity);
        return true;
    }

    private void removeUser(UserEntity user) {
        String id = user.getId();
        em.createNamedQuery("deleteProofByUser").setParameter("user", user).executeUpdate();
        em.createNamedQuery("deleteUserDrafts").setParameter("user", user).executeUpdate();
        em.createNamedQuery("deleteUserRoleMappingDraftsByUser").setParameter("user", user).executeUpdate();
        em.createNamedQuery("deleteUserRoleMappingsByUser").setParameter("user", user).executeUpdate();
        em.createNamedQuery("deleteUserGroupMembershipsByUser").setParameter("user", user).executeUpdate();
        em.createNamedQuery("deleteUserConsentClientScopesByUser").setParameter("user", user).executeUpdate();
        em.createNamedQuery("deleteUserConsentsByUser").setParameter("user", user).executeUpdate();

        em.remove(user);
        em.flush();
    }


    /**
     *
     * We are returning our TideUserAdapter here. Everything else works the same as the super.
     *
     */

    @Override
    public Stream<UserModel> getGroupMembersStream(RealmModel realm, GroupModel group) {
        return super.getGroupMembersStream(realm, group)
                .map(userEntity -> new TideUserAdapter(session, realm, em, (UserEntity) userEntity));
    }

    @Override
    public Stream<UserModel> getRoleMembersStream(RealmModel realm, RoleModel role) {
        return super.getRoleMembersStream(realm, role)
                .map(userEntity -> new TideUserAdapter(session, realm, em, (UserEntity) userEntity));
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        UserModel userModel = super.getUserByUsername(realm, username);
        return userModel != null ? new TideUserAdapter(session, realm, em, (UserEntity) userModel) : null;
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        UserModel userModel = super.getUserByEmail(realm, email);
        if (userModel != null) {
            ensureEmailConstraint(Collections.singletonList((UserEntity) userModel), realm);
            return new TideUserAdapter(session, realm, em, (UserEntity) userModel);
        }
        return null;
    }

    @Override
    public Stream<UserModel> getGroupMembersStream(RealmModel realm, GroupModel group, Integer firstResult, Integer maxResults) {
        return super.getGroupMembersStream(realm, group, firstResult, maxResults)
                .map(userEntity -> new TideUserAdapter(session, realm, em, (UserEntity) userEntity));
    }

    @Override
    public Stream<UserModel> getRoleMembersStream(RealmModel realm, RoleModel role, Integer firstResult, Integer maxResults) {
        return super.getRoleMembersStream(realm, role, firstResult, maxResults)
                .map(userEntity -> new TideUserAdapter(session, realm, em, (UserEntity) userEntity));
    }

    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        UserModel userModel = super.getUserById(realm, id);
        return userModel != null ? new TideUserAdapter(session, realm, em, (UserEntity) userModel) : null;
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
            return new TideUserAdapter(session, realm, em, (UserEntity) userModel);
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
            return new TideUserAdapter(session, client.getRealm(), em, (UserEntity) userModel);
        }
    }

    @Override
    public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realm, String attrName, String attrValue) {
        return super.searchForUserByUserAttributeStream(realm, attrName, attrValue)
                .map(userEntity -> new TideUserAdapter(session, realm, em, (UserEntity) userEntity));
    }
}
