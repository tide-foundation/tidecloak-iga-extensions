package org.tidecloak.jpa.models;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import org.keycloak.models.*;
import org.keycloak.models.jpa.RoleAdapter;
import org.keycloak.models.jpa.entities.RoleEntity;

import org.tidecloak.interfaces.ActionType;
import org.tidecloak.interfaces.DraftStatus;
import org.tidecloak.jpa.entities.drafting.TideCompositeRoleDraftEntity;

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
    public void addCompositeRole(RoleModel role) {
        RoleEntity entity = toRoleEntity(role);
        for (RoleEntity composite : getEntity().getCompositeRoles()) {
            if (composite.equals(entity)) return;
        }
        getEntity().getCompositeRoles().add(entity);

        TideCompositeRoleDraftEntity draft = new TideCompositeRoleDraftEntity();
        draft.setComposite(getEntity());
        draft.setChildRole(entity);
        draft.setDraftStatus(DraftStatus.DRAFT);
        draft.setAction(ActionType.CREATE);

        em.persist(draft);
        em.flush();
    }


    public boolean isApprovedForComposite(String parentRoleId) {
        RoleModel parentRole = realm.getRoleById(parentRoleId);
        var entity = em.find(TideCompositeRoleDraftEntity.class, new TideCompositeRoleDraftEntity.Key(toRoleEntity(parentRole), getEntity()));

        return entity.getDraftStatus() == DraftStatus.APPROVED;

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
