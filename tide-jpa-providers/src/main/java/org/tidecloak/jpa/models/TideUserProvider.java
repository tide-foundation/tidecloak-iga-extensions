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

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
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

        // Add draft record for user groups. DEFAULT ROLES ARE APPROVED BY DEFAULT FOR NOW
        // TODO: have a step here that goes and gets it signed by VVK automatically and save final proof to DB
        RoleModel defaultRole =  realm.getDefaultRole();
        var draftDefaultRoleUserRole = new TideUserRoleMappingDraftEntity();
        draftDefaultRoleUserRole.setId(KeycloakModelUtils.generateId());
        draftDefaultRoleUserRole.setRoleId(defaultRole.getId());
        draftDefaultRoleUserRole.setUser(userEntity);
        draftDefaultRoleUserRole.setAction(ActionType.CREATE);
        draftDefaultRoleUserRole.setDraftStatus(DraftStatus.APPROVED);
        em.persist(draftDefaultRoleUserRole);
        em.flush();


//        // do we care about previously approved client full scopes ?
//        // We generate proof requests for all full-scoped enabled clients for this client
//        TideAuthzProofUtil util = new TideAuthzProofUtil(session, realm, em);
//        UserModel wrappedUser = TideRolesUtil.wrapUserModel(user, session, realm);
//        Set<RoleModel> roleMappings = new HashSet<>();
//        realm.getClientsStream().forEach(client -> {
//            try {
//                util.generateAndSaveProofDraft(client, wrappedUser, roleMappings, draftUser.getId(), ChangeSetType.USER, ActionType.CREATE);
//            } catch (JsonProcessingException e) {
//                throw new RuntimeException(e);
//            }
//        });
//
//        em.flush();

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

//    @Override
//    public void preRemove(RealmModel realm, GroupModel group){
//
//        ProofGeneration proofGeneration = new ProofGeneration(session, realm, em);
//
//        // get effective roles
//        //List<ClientRole> effectiveGroupClientRoles = proofGeneration.getEffectiveGroupClientRoles(group);
//        //List<UserModel> affectedUsers = proofGeneration.getAllGroupMembersIncludingSubgroups(realm, group);
//
//        super.preRemove(realm, group);
//
//        //proofGeneration.regenerateProofsForMembers(effectiveGroupClientRoles, affectedUsers);
//
//    }

    /**
     *
     * We are returning our TideUserAdapter here. Everything else works the same as the super.
     *
     */

    @Override
    public Stream<UserModel> getGroupMembersStream(RealmModel realm, GroupModel group) {
        TypedQuery<UserEntity> query = em.createNamedQuery("groupMembership", UserEntity.class);
        query.setParameter("groupId", group.getId());
        return closing(query.getResultStream().map(entity -> new TideUserAdapter(session, realm, em, entity)));
    }

    @Override
    public Stream<UserModel> getRoleMembersStream(RealmModel realm, RoleModel role) {
        TypedQuery<UserEntity> query = em.createNamedQuery("usersInRole", UserEntity.class);
        query.setParameter("roleId", role.getId());
        return closing(query.getResultStream().map(entity -> new TideUserAdapter(session, realm, em, entity)));
    }


    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        TypedQuery<UserEntity> query = em.createNamedQuery("getRealmUserByUsername", UserEntity.class);
        query.setParameter("username", username.toLowerCase());
        query.setParameter("realmId", realm.getId());
        List<UserEntity> results = query.getResultList();
        if (results.isEmpty()) return null;
        return new TideUserAdapter(session, realm, em, results.get(0));
    }
    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        TypedQuery<UserEntity> query = em.createNamedQuery("getRealmUserByEmail", UserEntity.class);
        query.setParameter("email", email.toLowerCase());
        query.setParameter("realmId", realm.getId());
        List<UserEntity> results = query.getResultList();

        if (results.isEmpty()) return null;

        ensureEmailConstraint(results, realm);

        return new TideUserAdapter(session, realm, em, results.get(0));
    }

    @Override
    public Stream<UserModel> getGroupMembersStream(RealmModel realm, GroupModel group, Integer firstResult, Integer maxResults) {
        TypedQuery<UserEntity> query = em.createNamedQuery("groupMembership", UserEntity.class);
        query.setParameter("groupId", group.getId());

        return closing(paginateQuery(query, firstResult, maxResults).getResultStream().map(user -> new TideUserAdapter(session, realm, em, user)));
    }

    @Override
    public Stream<UserModel> getRoleMembersStream(RealmModel realm, RoleModel role, Integer firstResult, Integer maxResults) {
        TypedQuery<UserEntity> query = em.createNamedQuery("usersInRole", UserEntity.class);
        query.setParameter("roleId", role.getId());

        return closing(paginateQuery(query, firstResult, maxResults).getResultStream().map(user -> new TideUserAdapter(session, realm, em, user)));
    }

    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        UserEntity userEntity = em.find(UserEntity.class, id);
        if (userEntity == null || !realm.getId().equals(userEntity.getRealmId())) return null;
        return new TideUserAdapter(session, realm, em, userEntity);
    }

    @Override
    public UserModel getUserByFederatedIdentity(RealmModel realm, FederatedIdentityModel identity) {
        TypedQuery<UserEntity> query = em.createNamedQuery("findUserByFederatedIdentityAndRealm", UserEntity.class);
        query.setParameter("realmId", realm.getId());
        query.setParameter("identityProvider", identity.getIdentityProvider());
        query.setParameter("userId", identity.getUserId());
        List<UserEntity> results = query.getResultList();
        if (results.isEmpty()) {
            return null;
        } else if (results.size() > 1) {
            throw new IllegalStateException("More results found for identityProvider=" + identity.getIdentityProvider() +
                    ", userId=" + identity.getUserId() + ", results=" + results);
        } else {
            UserEntity user = results.get(0);
            return new TideUserAdapter(session, realm, em, user);
        }
    }

    @Override
    public UserModel getServiceAccount(ClientModel client) {
        TypedQuery<UserEntity> query = em.createNamedQuery("getRealmUserByServiceAccount", UserEntity.class);
        query.setParameter("realmId", client.getRealm().getId());
        query.setParameter("clientInternalId", client.getId());
        List<UserEntity> results = query.getResultList();
        if (results.isEmpty()) {
            return null;
        } else if (results.size() > 1) {
            throw new IllegalStateException("More service account linked users found for client=" + client.getClientId() +
                    ", results=" + results);
        } else {
            UserEntity user = results.get(0);
            return new TideUserAdapter(session, client.getRealm(), em, user);
        }
    }

    @Override
    public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realm, String attrName, String attrValue) {
        boolean longAttribute = attrValue != null && attrValue.length() > 255;
        TypedQuery<UserEntity> query = longAttribute ?
                em.createNamedQuery("getRealmUsersByAttributeNameAndLongValue", UserEntity.class)
                        .setParameter("realmId", realm.getId())
                        .setParameter("name", attrName)
                        .setParameter("longValueHash", JpaHashUtils.hashForAttributeValue(attrValue)):
                em.createNamedQuery("getRealmUsersByAttributeNameAndValue", UserEntity.class)
                        .setParameter("realmId", realm.getId())
                        .setParameter("name", attrName)
                        .setParameter("value", attrValue);

        return closing(query.getResultStream()
                // following check verifies that there are no collisions with hashes
                .filter(longAttribute ? predicateForFilteringUsersByAttributes(Map.of(attrName, attrValue), JpaHashUtils::compareSourceValue) : u -> true)
                .map(userEntity -> new TideUserAdapter(session, realm, em, userEntity)));
    }
}
