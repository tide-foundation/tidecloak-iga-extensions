package org.tidecloak.jpa.entities.drafting;

import jakarta.persistence.*;
import org.keycloak.models.jpa.entities.RoleEntity;
import org.tidecloak.interfaces.ActionType;
import org.tidecloak.interfaces.DraftStatus;

import java.io.Serializable;

@NamedQueries({
        @NamedQuery(name="filterChildRoleByStatusAndParent", query="select r.childRole from TideCompositeRoleDraftEntity r where r.composite = :composite and r.draftStatus = :draftStatus"),
})

@Entity
@Table(name="COMPOSITE_ROLE_DRAFT")
@IdClass(TideCompositeRoleDraftEntity.Key.class)
public class TideCompositeRoleDraftEntity {

    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "COMPOSITE", referencedColumnName = "ID")  // Ensure 'ID' is the correct primary key field name in RoleEntity
    private RoleEntity composite;

    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "CHILD_ROLE", referencedColumnName = "ID")
    private RoleEntity childRole;


    @Enumerated(EnumType.STRING)
    @Column(name = "DRAFT_STATUS")
    private DraftStatus draftStatus;

    @Enumerated(EnumType.STRING)
    @Column(name = "ACTION_TYPE")
    private ActionType actionType;

    public RoleEntity getComposite() {
        return composite;
    }

    public void setComposite(RoleEntity composite) {
        this.composite = composite;
    }

    public RoleEntity getChildRole() {
        return childRole;
    }

    public void setChildRole(RoleEntity childRole) {
        this.childRole = childRole;
    }

    // Getters and setters for new fields
    public DraftStatus getDraftStatus() {
        return draftStatus;
    }

    public void setDraftStatus(DraftStatus draftStatus) {
        this.draftStatus = draftStatus;
    }

    public ActionType getAction() {
        return actionType;
    }

    public void setAction(ActionType actionType) {
        this.actionType = actionType;
    }

    @Embeddable
    public static class Key implements Serializable {

        protected RoleEntity composite;

        protected RoleEntity childRole;

        public Key() {
        }

        public Key(RoleEntity composite, RoleEntity childRole) {
            this.composite = composite;
            this.childRole = childRole;
        }

        public RoleEntity getComposite() {
            return composite;
        }

        public RoleEntity getChildRole() {
            return childRole;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            TideCompositeRoleDraftEntity.Key key = (TideCompositeRoleDraftEntity.Key) o;

            if (!childRole.equals(key.childRole)) return false;
            if (!composite.equals(key.composite)) return false;

            return true;
        }

        @Override
        public int hashCode() {
            int result = composite.hashCode();
            result = 31 * result + childRole.hashCode();
            return result;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof TideCompositeRoleDraftEntity)) return false;

        TideCompositeRoleDraftEntity key = (TideCompositeRoleDraftEntity) o;

        if (!childRole.equals(key.childRole)) return false;
        if (!composite.equals(key.composite)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = composite.hashCode();
        result = 31 * result + childRole.hashCode();
        return result;
    }
}
