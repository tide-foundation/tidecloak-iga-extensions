package org.tidecloak.jpa.models;

import com.fasterxml.jackson.core.JsonProcessingException;
import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import org.keycloak.models.*;
import org.keycloak.models.jpa.RoleAdapter;
import org.keycloak.models.jpa.entities.RoleEntity;

import org.keycloak.models.utils.KeycloakModelUtils;
import org.tidecloak.interfaces.ActionType;
import org.tidecloak.interfaces.ChangeSetType;
import org.tidecloak.interfaces.DraftStatus;
import org.tidecloak.jpa.entities.AccessProofDetailDependencyEntity;
import org.tidecloak.jpa.entities.drafting.TideCompositeRoleDraftEntity;
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
        // Check if role mapping is a draft
        Stream<TideCompositeRoleDraftEntity> entity =  em.createNamedQuery("getCompositeRoleDraft", TideCompositeRoleDraftEntity.class)
                .setParameter("composite", toRoleEntity(role))
                .setParameter("draftStatus", DraftStatus.DRAFT)
                .getResultStream();

        if(!entity.toList().isEmpty()){
            em.createNamedQuery("deleteCompositeRole")
                    .setParameter("composite", toRoleEntity(role))
                    .executeUpdate();
            super.removeCompositeRole(role);
        } else {
            // GET APPROVAL FOR DELETION
            TideCompositeRoleDraftEntity newEntity = new TideCompositeRoleDraftEntity();
            newEntity.setId(KeycloakModelUtils.generateId());
            newEntity.setComposite(toRoleEntity(role));
            newEntity.setDraftStatus(DraftStatus.DRAFT);
            newEntity.setAction(ActionType.DELETE);
            em.persist(newEntity);

            if (role.getContainer() instanceof ClientModel) {
                RoleModel compositeRole = realm.getRoleById(getEntity().getId());
                List<UserModel> users =  session.users().getRoleMembersStream(realm, compositeRole).toList();
                List<ClientModel> clientList = new ArrayList<>(session.clients().getClientsStream(realm).filter(ClientModel::isFullScopeAllowed).toList());
                TideAuthzProofUtil util = new TideAuthzProofUtil(session, realm, em);
                clientList.forEach(client -> {
                    session.getContext().setClient(client);
                    users.forEach(user -> {
                        UserModel wrappedUser = TideRolesUtil.wrapUserModel(user, session, realm);
                        Set<RoleModel> roleMappings = new HashSet<>();
                        roleMappings.add(role); // this is the new role we are adding to the parent role.

                        try {
                            util.generateAndSaveProofDraft(client, wrappedUser, roleMappings, newEntity.getId(), ChangeSetType.COMPOSITE_ROLE, ActionType.DELETE);
                        } catch (JsonProcessingException e) {
                            throw new RuntimeException(e);
                        }
                    });
                });
            }

            em.flush();
        }
    }

    @Override
    public void addCompositeRole(RoleModel roleModel) {
        RoleModel role = TideRolesUtil.wrapRoleModel(roleModel, session, realm);
        RoleEntity entity = toRoleEntity(role);
        for (RoleEntity composite : getEntity().getCompositeRoles()) {
            if (composite.equals(entity)) return;
        }
        getEntity().getCompositeRoles().add(entity);

        TideCompositeRoleMappingDraftEntity draft = new TideCompositeRoleMappingDraftEntity();
        draft.setId(KeycloakModelUtils.generateId());
        draft.setComposite(getEntity());
        draft.setChildRole(entity);
        draft.setDraftStatus(DraftStatus.DRAFT);
        draft.setAction(ActionType.CREATE);
        draft.setCreatedTimestamp(System.currentTimeMillis());

        em.persist(draft);

        if (role.getContainer() instanceof ClientModel) {
            RoleModel compositeRole = realm.getRoleById(getEntity().getId());
            List<UserModel> users =  session.users().getRoleMembersStream(realm, compositeRole).toList();
            List<ClientModel> clientList = new ArrayList<>(session.clients().getClientsStream(realm).filter(ClientModel::isFullScopeAllowed).toList());
            TideAuthzProofUtil util = new TideAuthzProofUtil(session, realm, em);
            clientList.forEach(client -> {
                session.getContext().setClient(client);
                users.forEach(user -> {
                    UserModel wrappedUser = TideRolesUtil.wrapUserModel(user, session, realm);
                    Set<RoleModel> roleMappings = new HashSet<>();
                    roleMappings.add(role);// this is the new role we are adding to the parent role.
                    roleMappings.add(realm.getRoleById(getEntity().getId()));// ensure the parent role is in there too
                    try {
                        util.generateAndSaveProofDraft(client, wrappedUser, roleMappings, draft.getId(), ChangeSetType.COMPOSITE_ROLE, ActionType.CREATE);
                    } catch (JsonProcessingException e) {
                        throw new RuntimeException(e);
                    }
                });
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
        Stream<RoleModel> composites = getEntity().getCompositeRoles().stream().map(c -> new TideRoleAdapter(session, realm, em, c));
        return composites.filter(Objects::nonNull);
    }

    public Stream<RoleModel> getCompositesStreamByStatus(DraftStatus draftStatus) {
        TypedQuery<RoleEntity> query = em.createNamedQuery("filterChildRoleByStatusAndParent", RoleEntity.class);
        query.setParameter("composite", getEntity());
        query.setParameter("draftStatus", draftStatus);

        Stream<RoleModel> composites = query.getResultStream().map(c -> new TideRoleAdapter(session, realm, em, c));

        return composites.filter(Objects::nonNull);

    }
    public Stream<RoleModel> getCompositesStreamByStatusAndAction(DraftStatus draftStatus, ActionType actionType) {
        TypedQuery<RoleEntity> query = em.createNamedQuery("filterChildRoleByStatusAndParentAndAction", RoleEntity.class);
        query.setParameter("composite", getEntity());
        query.setParameter("draftStatus", draftStatus);
        query.setParameter("actionType", actionType);

        Stream<RoleModel> composites = query.getResultStream().map(c -> new TideRoleAdapter(session, realm, em, c));

        return composites.filter(Objects::nonNull);

    }

    public Stream<RoleModel> getCompositesStreamByStatus(String search, Integer first, Integer max, DraftStatus draftStatus) {

        TypedQuery<RoleEntity> query = em.createNamedQuery("filterChildRoleByStatusAndParent", RoleEntity.class);
        query.setParameter("composite", getEntity());
        query.setParameter("draftStatus", draftStatus);

        Stream<String> composites = query.getResultStream().map(RoleEntity::getId);

        System.out.println(session.roles().getRolesStream(realm,
                composites,
                search, first, max));

        return session.roles().getRolesStream(realm,
                composites,
                search, first, max);
    }


    private RoleEntity toRoleEntity(RoleModel model) {
        if (model instanceof TideRoleAdapter) {
            return ((TideRoleAdapter) model).getEntity();
        }
        return em.getReference(RoleEntity.class, model.getId());
    }
}
