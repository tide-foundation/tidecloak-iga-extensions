package org.tidecloak.jpa.models;

import com.fasterxml.jackson.core.JsonProcessingException;
import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import org.keycloak.models.*;
import org.keycloak.models.jpa.RoleAdapter;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.models.jpa.entities.RoleEntity;

import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.tidecloak.interfaces.ActionType;
import org.tidecloak.interfaces.ChangeSetType;
import org.tidecloak.interfaces.DraftStatus;
import org.tidecloak.jpa.entities.drafting.TideCompositeRoleMappingDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;
import org.tidecloak.jpa.utils.TideAuthzProofUtil;
import org.tidecloak.jpa.utils.TideRolesUtil;

import java.util.*;
import java.util.stream.Stream;

import static org.keycloak.models.ImpersonationConstants.IMPERSONATION_ROLE;

public class TideRoleAdapter extends RoleAdapter {
    private final KeycloakSession session;
    private final RealmModel realm;


    public TideRoleAdapter(KeycloakSession session, RealmModel realm, EntityManager em, RoleEntity role) {
        super(session, realm, em, role);
        this.session = session;
        this.realm  = realm;
    }

    @Override
    public void removeCompositeRole(RoleModel roleModel) {
        RoleModel role = TideRolesUtil.wrapRoleModel(roleModel, session, realm);
        RoleEntity roleEntity = toRoleEntity(role);
        List<TideCompositeRoleMappingDraftEntity> entity = findCompositeRoleMappingDrafts(getEntity(), roleEntity, DraftStatus.ACTIVE);

        if (entity.isEmpty()) {
            handleUncommittedCompositeRole(role, roleEntity);
            return;
        }

        TideCompositeRoleMappingDraftEntity committedEntity = entity.get(0);

        if (committedEntity.getDeleteStatus() == DraftStatus.APPROVED) {
            deleteCompositeRoleMapping(getEntity(), roleEntity);
            deleteProofRecords(committedEntity.getId());
            super.removeCompositeRole(role);
        } else {
            updateCompositeRoleForDeletion(committedEntity);
            handleClientRoleProofs(role, committedEntity);
            em.flush();
        }
    }

    private void handleUncommittedCompositeRole(RoleModel role, RoleEntity roleEntity) {
        deleteCompositeRoleMapping(getEntity(), roleEntity);

        List<TideCompositeRoleMappingDraftEntity> proofRecords = findCompositeRoleMappingDrafts(getEntity(), roleEntity, DraftStatus.DRAFT);
        if (!proofRecords.isEmpty()) {
            deleteProofRecords(proofRecords.get(0).getId());
        }

        super.removeCompositeRole(role);
    }

    private List<TideCompositeRoleMappingDraftEntity> findCompositeRoleMappingDrafts(RoleEntity composite, RoleEntity childRole, DraftStatus status) {
        return em.createNamedQuery("getCompositeRoleMappingDraftByStatus", TideCompositeRoleMappingDraftEntity.class)
                .setParameter("composite", composite)
                .setParameter("childRole", childRole)
                .setParameter("draftStatus", status)
                .getResultList();
    }

    private void deleteCompositeRoleMapping(RoleEntity composite, RoleEntity childRole) {
        em.createNamedQuery("deleteCompositeRoleMapping")
                .setParameter("composite", composite)
                .setParameter("childRole", childRole)
                .executeUpdate();
    }

    private void deleteProofRecords(String recordId) {
        em.createNamedQuery("deleteProofRecords")
                .setParameter("recordId", recordId)
                .executeUpdate();
    }

    private void updateCompositeRoleForDeletion(TideCompositeRoleMappingDraftEntity compositeRoleEntity) {
        compositeRoleEntity.setDeleteStatus(DraftStatus.DRAFT);
        compositeRoleEntity.setTimestamp(System.currentTimeMillis());
    }

    private void handleClientRoleProofs(RoleModel role, TideCompositeRoleMappingDraftEntity compositeRoleEntity) {
        if (role.getContainer() instanceof ClientModel) {
            RoleModel compositeRole = realm.getRoleById(getEntity().getId());
            List<UserModel> users = session.users().getRoleMembersStream(realm, compositeRole).toList();
            List<ClientModel> clientList = getClientList();

            TideAuthzProofUtil util = new TideAuthzProofUtil(session, realm, em);
            clientList.forEach(client -> users.forEach(user -> {
                UserModel wrappedUser = TideRolesUtil.wrapUserModel(user, session, realm);
                Set<RoleModel> roleMappings = new HashSet<>(Collections.singleton(role));

                try {
                    util.generateAndSaveProofDraft(client, wrappedUser, roleMappings, compositeRoleEntity.getId(), ChangeSetType.COMPOSITE_ROLE, ActionType.DELETE, client.isFullScopeAllowed());
                } catch (JsonProcessingException e) {
                    throw new RuntimeException(e);
                }
            }));
        }
    }

    private List<ClientModel> getClientList() {
        return new ArrayList<>(session.clients().getClientsStream(realm).map(client -> {
            ClientEntity clientEntity = em.getReference(ClientEntity.class, client.getId());
            return new TideClientAdapter(realm, em, session, clientEntity);
        }).filter(TideClientAdapter::isFullScopeAllowed).toList());
    }

    private Boolean commitDefaultRolesOnInitiation(RoleModel child) {
        RoleModel role = TideRolesUtil.wrapRoleModel(child, session, realm);
        RoleEntity entity = toRoleEntity(role);
        String entityName = getEntity().getName();
        String childName = child.getName();

        if (isRealmAdmin(entityName) && (isInAllRealmRoles(childName) || isCreateRealm(childName) || isImpersonation(childName))) {
            persistDraft(entity);
            return true;
        } else if (isManageAccount(entityName) && isManageAccountLinks(childName)) {
            persistDraft(entity);
            return true;
        } else if (isManageConsent(entityName) && isViewConsent(childName)) {
            persistDraft(entity);
            return true;
        } else if (isViewClients(entityName) && (isQueryClients(childName) || isQueryGroups(childName))) {
            persistDraft(entity);
            return true;
        } else if (isDefaultRole(entityName) && isDefaultAccountRole(childName)) {
            persistDraft(entity);
            return true;
        } else if (isAdminViewUsers(entityName) && (isQueryUsers(childName) || isQueryGroups(childName))) {
            return true;
        } else if (isAdminViewClients(entityName) && isQueryClients(childName)) {
            return true;
        }

        return false;
    }

    private boolean isRealmAdmin(String entityName) {
        return Objects.equals(entityName, AdminRoles.REALM_ADMIN);
    }

    private boolean isInAllRealmRoles(String childName) {
        return Arrays.asList(AdminRoles.ALL_REALM_ROLES).contains(childName);
    }

    private boolean isCreateRealm(String childName) {
        return Objects.equals(childName, AdminRoles.CREATE_REALM);
    }

    private boolean isManageAccount(String entityName) {
        return Objects.equals(entityName, AccountRoles.MANAGE_ACCOUNT);
    }

    private boolean isManageAccountLinks(String childName) {
        return Objects.equals(childName, AccountRoles.MANAGE_ACCOUNT_LINKS);
    }

    private boolean isManageConsent(String entityName) {
        return Objects.equals(entityName, AccountRoles.MANAGE_CONSENT);
    }
    private boolean isAdminViewUsers(String entityName) {

        return Objects.equals(entityName, AdminRoles.VIEW_USERS);
    }

    private boolean isAdminViewClients(String entityName) {

        return Objects.equals(entityName, AdminRoles.VIEW_CLIENTS);
    }

    private boolean isQueryUsers(String childName) {
        return Objects.equals(childName, AdminRoles.QUERY_USERS);
    }

    private boolean isViewConsent(String childName) {
        return Objects.equals(childName, AccountRoles.VIEW_CONSENT);
    }

    private boolean isViewClients(String entityName) {
        return Objects.equals(entityName, AdminRoles.VIEW_CLIENTS);
    }

    private boolean isQueryClients(String childName) {
        return Objects.equals(childName, AdminRoles.QUERY_CLIENTS);
    }

    private boolean isQueryGroups(String childName) {
        return Objects.equals(childName, AdminRoles.QUERY_GROUPS);
    }

    private boolean isImpersonation(String childName) {
        return Objects.equals(childName, IMPERSONATION_ROLE );
    }


    private boolean isDefaultRole(String entityName) {
        return Objects.equals(entityName, realm.getDefaultRole().getName());
    }

    private boolean isDefaultAccountRole(String childName) {
        return Arrays.asList(AccountRoles.DEFAULT).contains(childName);
    }

    private void persistDraft(RoleEntity entity) {
        TideCompositeRoleMappingDraftEntity draft = new TideCompositeRoleMappingDraftEntity();
        draft.setId(KeycloakModelUtils.generateId());
        draft.setComposite(getEntity());
        draft.setChildRole(entity);
        draft.setAction(ActionType.CREATE);
        draft.setDraftStatus(DraftStatus.ACTIVE);
        em.persist(draft);
        em.flush();
    }

    @Override
    public void addCompositeRole(RoleModel roleModel) {
        if(commitDefaultRolesOnInitiation(roleModel)){
            super.addCompositeRole(roleModel);
            return;
        }
        // don't care about realm roles
        if(!getEntity().isClientRole()){
            super.addCompositeRole(roleModel);
            RoleModel role = TideRolesUtil.wrapRoleModel(roleModel, session, realm);
            RoleEntity entity = toRoleEntity(role);
            persistDraft(entity);
            return;
        }
        RoleModel role = TideRolesUtil.wrapRoleModel(roleModel, session, realm);
        RoleEntity entity = toRoleEntity(role);

        super.addCompositeRole(roleModel);

        TideCompositeRoleMappingDraftEntity draft = new TideCompositeRoleMappingDraftEntity();
        draft.setId(KeycloakModelUtils.generateId());
        draft.setComposite(getEntity());
        draft.setChildRole(entity);
        draft.setDraftStatus(DraftStatus.DRAFT);
        draft.setAction(ActionType.CREATE);

        em.persist(draft);

        if (role.getContainer() instanceof ClientModel) {
            RoleModel compositeRole = realm.getRoleById(getEntity().getId());
            List<UserModel> users =  session.users().getRoleMembersStream(realm, compositeRole).toList();
            List<ClientModel> clientList = new ArrayList<>(session.clients().getClientsStream(realm).map(client -> {
                        ClientEntity clientEntity = em.getReference(ClientEntity.class, client.getId());
                        return new TideClientAdapter(realm, em, session, clientEntity);
                    })
                    .filter(TideClientAdapter::isFullScopeAllowed).toList());
            TideAuthzProofUtil util = new TideAuthzProofUtil(session, realm, em);
            clientList.forEach(client -> {
                for( UserModel user : users) {
                    UserEntity userEntity = em.getReference(UserEntity.class, user.getId());
                    List<TideUserRoleMappingDraftEntity> userCompositeRoleDraft = em.createNamedQuery("getUserRoleAssignmentDraftEntityByStatus", TideUserRoleMappingDraftEntity.class)
                            .setParameter("user", userEntity)
                            .setParameter("roleId", compositeRole.getId())
                            .setParameter("draftStatus", DraftStatus.ACTIVE)
                            .getResultList();
                    // Check if user has been granted the composite\parent role.
                    if (userCompositeRoleDraft.isEmpty()){
                        continue;
                    }
                    UserModel wrappedUser = TideRolesUtil.wrapUserModel(user, session, realm);
                    Set<RoleModel> roleMappings = new HashSet<>();
                    roleMappings.add(role);// this is the new role we are adding to the parent role.
                    roleMappings.add(realm.getRoleById(getEntity().getId()));// ensure the parent role is in there too
                    try {
                        util.generateAndSaveProofDraft(client, wrappedUser, roleMappings, draft.getId(), ChangeSetType.COMPOSITE_ROLE, ActionType.CREATE, client.isFullScopeAllowed());
                    } catch (JsonProcessingException e) {
                        throw new RuntimeException(e);
                    }
                };
            });
        }

        em.flush();
    }


    /**
     *
     * We are returning our TideRoleAdapter here. Everything else works the same as the super.
     *
     */

    @Override
    public Stream<RoleModel> getCompositesStream() {
        Stream<RoleModel> roles = super.getCompositesStream()
                .map(role -> {
                    RoleEntity roleEntity = em.getReference(RoleEntity.class, role.getId());
                    return new TideRoleAdapter(session, realm, em, roleEntity);
                });
        return roles.filter(Objects::nonNull);
    }

    public Stream<RoleModel> getCompositesStreamByStatus(DraftStatus draftStatus) {
        TypedQuery<RoleEntity> query = em.createNamedQuery("filterChildRoleByStatusAndParent", RoleEntity.class);
        query.setParameter("composite", getEntity());
        query.setParameter("draftStatus", draftStatus);

        Stream<RoleModel> roles = query.getResultStream()
                .map(role -> new TideRoleAdapter(session, realm, em, role));

        return roles.filter(Objects::nonNull);

    }

    public Stream<RoleModel> getCompositesStreamByStatusAndAction(DraftStatus draftStatus, ActionType actionType) {
        TypedQuery<RoleEntity> query = em.createNamedQuery("filterChildRoleByStatusAndParentAndAction", RoleEntity.class);
        query.setParameter("composite", getEntity());
        query.setParameter("draftStatus", draftStatus);
        query.setParameter("actionType", actionType);

        Stream<RoleModel> roles = query.getResultStream()
                .map(role -> new TideRoleAdapter(session, realm, em, role));
        return roles.filter(Objects::nonNull);
    }

    public Stream<RoleModel> getCompositesStreamByStatus(String search, Integer first, Integer max, DraftStatus draftStatus) {
        TypedQuery<RoleEntity> query = em.createNamedQuery("filterChildRoleByStatusAndParent", RoleEntity.class);
        query.setParameter("composite", getEntity());
        query.setParameter("draftStatus", draftStatus);

        Stream<String> composites = query.getResultStream().map(RoleEntity::getId);

        Stream<RoleModel> roles = session.roles().getRolesStream(realm, composites, search, first, max)
                .map(role -> {
                    RoleEntity roleEntity = em.getReference(RoleEntity.class, role.getId());
                    return new TideRoleAdapter(session, realm, em, roleEntity);
                });
        return roles.filter(Objects::nonNull);
    }

    private RoleEntity toRoleEntity(RoleModel model) {
        if (model instanceof TideRoleAdapter) {
            return ((TideRoleAdapter) model).getEntity();
        }
        return em.getReference(RoleEntity.class, model.getId());
    }

}
