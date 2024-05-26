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
        // Check if composite role is commited already
        List<TideCompositeRoleMappingDraftEntity> entity =  em.createNamedQuery("getCompositeRoleMappingDraftByStatus", TideCompositeRoleMappingDraftEntity.class)
                .setParameter("composite", getEntity())
                .setParameter("childRole", toRoleEntity(role))
                .setParameter("draftStatus", DraftStatus.ACTIVE)
                .getResultList();

        if (entity.isEmpty()) {
            throw new IllegalStateException("No commited change found for the specified composite and child role.");
        }
        TideCompositeRoleMappingDraftEntity commitedEntity = entity.get(0);

        if(commitedEntity.getDeleteStatus() == DraftStatus.APPROVED) {
            em.createNamedQuery("deleteCompositeRoleMapping")
                    .setParameter("composite", getEntity())
                    .setParameter("childRole", toRoleEntity(role))
                    .executeUpdate();
            // Remove all draft access proofs affected by this draft record change
            em.createNamedQuery("deleteProofRecords")
                    .setParameter("recordId", entity.get(0).getId())
                    .executeUpdate();
            super.removeCompositeRole(role);
        } else {
            TideCompositeRoleMappingDraftEntity compositeRoleEntity =  em.createNamedQuery("getCompositeRoleMappingDraftByStatus", TideCompositeRoleMappingDraftEntity.class)
                    .setParameter("composite", getEntity())
                    .setParameter("childRole", toRoleEntity(role))
                    .setParameter("draftStatus", DraftStatus.ACTIVE)
                    .getSingleResult();
            // GET APPROVAL FOR DELETION
            compositeRoleEntity.setDeleteStatus(DraftStatus.DRAFT);
            compositeRoleEntity.setTimestamp(System.currentTimeMillis());

            if (role.getContainer() instanceof ClientModel) {
                RoleModel compositeRole = realm.getRoleById(getEntity().getId());
                List<UserModel> users =  session.users().getRoleMembersStream(realm, compositeRole).toList();
                List<ClientModel> clientList = new ArrayList<>(session.clients().getClientsStream(realm).map(client -> {
                            ClientEntity clientEntity = em.find(ClientEntity.class, client.getId());
                            return new TideClientAdapter(realm, em, session, clientEntity);
                        })
                        .filter(TideClientAdapter::isFullScopeAllowed).toList());
                TideAuthzProofUtil util = new TideAuthzProofUtil(session, realm, em);
                clientList.forEach(client -> {
                    users.forEach(user -> {
                        UserModel wrappedUser = TideRolesUtil.wrapUserModel(user, session, realm);
                        Set<RoleModel> roleMappings = new HashSet<>();
                        roleMappings.add(role); // this is the new role we are removing from the parent role.

                        try {
                            util.generateAndSaveProofDraft(client, wrappedUser, roleMappings, compositeRoleEntity.getId(), ChangeSetType.COMPOSITE_ROLE, ActionType.DELETE, client.isFullScopeAllowed());
                        } catch (JsonProcessingException e) {
                            throw new RuntimeException(e);
                        }
                    });
                });
            }

            em.flush();
        }
    }

    private Boolean commitDefaultRolesOnInitiation(RoleModel child){
        RoleModel role = TideRolesUtil.wrapRoleModel(child, session, realm);
        RoleEntity entity = toRoleEntity(role);

        if (Objects.equals(getEntity().getName(), AdminRoles.REALM_ADMIN)) {
            if (Arrays.stream(AdminRoles.ALL_REALM_ROLES).toList().contains(child.getName()) || Objects.equals(child.getName(), AdminRoles.CREATE_REALM)) {
                TideCompositeRoleMappingDraftEntity draft = new TideCompositeRoleMappingDraftEntity();
                draft.setId(KeycloakModelUtils.generateId());
                draft.setComposite(getEntity());
                draft.setChildRole(entity);
                draft.setAction(ActionType.CREATE);
                draft.setDraftStatus(DraftStatus.ACTIVE);
                em.persist(draft);
                em.flush();
                return true;
            }
        }
        else if (Objects.equals(getEntity().getName(), AccountRoles.MANAGE_ACCOUNT)){
            if (Objects.equals(child.getName(), AccountRoles.MANAGE_ACCOUNT_LINKS)){
                TideCompositeRoleMappingDraftEntity draft = new TideCompositeRoleMappingDraftEntity();
                draft.setId(KeycloakModelUtils.generateId());
                draft.setComposite(getEntity());
                draft.setChildRole(entity);
                draft.setAction(ActionType.CREATE);
                draft.setDraftStatus(DraftStatus.ACTIVE);
                em.persist(draft);
                em.flush();
                return true;
            }
        }
        else if (Objects.equals(getEntity().getName(), AccountRoles.MANAGE_CONSENT)){
            if (Objects.equals(child.getName(), AccountRoles.VIEW_CONSENT)){
                TideCompositeRoleMappingDraftEntity draft = new TideCompositeRoleMappingDraftEntity();
                draft.setId(KeycloakModelUtils.generateId());
                draft.setComposite(getEntity());
                draft.setChildRole(entity);
                draft.setAction(ActionType.CREATE);
                draft.setDraftStatus(DraftStatus.ACTIVE);
                em.persist(draft);
                em.flush();
                return true;
            }
        }
        else if (Objects.equals(getEntity().getName(), AdminRoles.VIEW_CLIENTS)){
            if (Objects.equals(child.getName(), AdminRoles.QUERY_CLIENTS) || child.getName() == AdminRoles.QUERY_GROUPS){
                TideCompositeRoleMappingDraftEntity draft = new TideCompositeRoleMappingDraftEntity();
                draft.setId(KeycloakModelUtils.generateId());
                draft.setComposite(getEntity());
                draft.setChildRole(entity);
                draft.setAction(ActionType.CREATE);
                draft.setDraftStatus(DraftStatus.ACTIVE);
                em.persist(draft);
                em.flush();
                return true;
            }
        }
        else if (Objects.equals(getEntity().getName(), realm.getDefaultRole().getName())){
            if (Arrays.stream(AccountRoles.DEFAULT).toList().contains(child.getName())){
                TideCompositeRoleMappingDraftEntity draft = new TideCompositeRoleMappingDraftEntity();
                draft.setId(KeycloakModelUtils.generateId());
                draft.setComposite(getEntity());
                draft.setChildRole(entity);
                draft.setAction(ActionType.CREATE);
                draft.setDraftStatus(DraftStatus.ACTIVE);
                em.persist(draft);
                em.flush();
                return true;
            }
        }

        return false;
    }

    @Override
    public void addCompositeRole(RoleModel roleModel) {
        if(commitDefaultRolesOnInitiation(roleModel)){
            super.addCompositeRole(roleModel);
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
                        ClientEntity clientEntity = em.find(ClientEntity.class, client.getId());
                        return new TideClientAdapter(realm, em, session, clientEntity);
                    })
                    .filter(TideClientAdapter::isFullScopeAllowed).toList());
            TideAuthzProofUtil util = new TideAuthzProofUtil(session, realm, em);
            clientList.forEach(client -> {
                for( UserModel user : users) {
                    UserEntity userEntity = em.find(UserEntity.class, user.getId());
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
                .map(role -> new TideRoleAdapter(session, realm, em, (RoleEntity) role));
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
                .map(role -> new TideRoleAdapter(session, realm, em, (RoleEntity) role));
        return roles.filter(Objects::nonNull);
    }

    private RoleEntity toRoleEntity(RoleModel model) {
        if (model instanceof TideRoleAdapter) {
            return ((TideRoleAdapter) model).getEntity();
        }
        return em.getReference(RoleEntity.class, model.getId());
    }

}
