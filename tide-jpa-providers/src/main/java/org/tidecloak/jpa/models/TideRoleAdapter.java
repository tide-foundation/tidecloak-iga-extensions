package org.tidecloak.jpa.models;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import org.keycloak.models.*;
import org.keycloak.models.jpa.RoleAdapter;
import org.keycloak.models.jpa.entities.RoleEntity;

import org.keycloak.models.utils.KeycloakModelUtils;
import org.tidecloak.interfaces.ActionType;
import org.tidecloak.interfaces.DraftStatus;
import org.tidecloak.jpa.entities.drafting.TideCompositeRoleDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideCompositeRoleMappingDraftEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;

import java.util.Objects;
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
    public void removeCompositeRole(RoleModel role) {
        //RoleEntity entity = toRoleEntity(role);
        //getEntity().getCompositeRoles().remove(entity);

        // Check if role mapping is a draft
        Stream<TideCompositeRoleDraftEntity> entity =  em.createNamedQuery("getCompositeRoleDraft", TideCompositeRoleDraftEntity.class)
                .setParameter("roleId", toRoleEntity(role))
                .setParameter("draftStatus", DraftStatus.DRAFT)
                .getResultStream();

        if(!entity.toList().isEmpty()){
            em.createNamedQuery("deleteUserRoleMappingDraftsByRole")
                    .setParameter("roleId", role.getId())
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
            em.flush();
            em.detach(newEntity);
        }
    }
    @Override
    public void addCompositeRole(RoleModel role) {
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

        em.persist(draft);
        em.flush();
    }


    public boolean isApprovedForComposite(String parentRoleId) {
        RoleModel parentRole = realm.getRoleById(parentRoleId);

        TypedQuery<TideCompositeRoleMappingDraftEntity> query = em.createNamedQuery("getCompositeRoleMappingDraftByStatus", TideCompositeRoleMappingDraftEntity.class);
        query.setParameter("composite", toRoleEntity(parentRole));
        query.setParameter("childRole", getEntity());
        query.setParameter("draftStatus", DraftStatus.APPROVED);
        var result = query.getResultList();

        return result.isEmpty();

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
