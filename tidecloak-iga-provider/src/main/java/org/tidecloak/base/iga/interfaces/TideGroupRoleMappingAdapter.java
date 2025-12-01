
package org.tidecloak.base.iga.interfaces;

import jakarta.persistence.EntityManager;
import org.keycloak.models.RealmModel;
import org.keycloak.models.jpa.entities.GroupEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.drafting.TideGroupRoleMappingEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;

import java.util.UUID;

public class TideGroupRoleMappingAdapter {

    private final RealmModel realm;
    private final EntityManager em;
    private final GroupEntity group;

    public TideGroupRoleMappingAdapter(RealmModel realm, EntityManager em, GroupEntity group) {
        this.realm = realm;
        this.em = em;
        this.group = group;
    }

    public ChangesetRequestEntity request(String roleId, ActionType action) {
        String changeReqId = UUID.randomUUID().toString();

        TideGroupRoleMappingEntity draft = new TideGroupRoleMappingEntity();
        draft.setId(UUID.randomUUID().toString());
        draft.setChangeRequestId(changeReqId);
        draft.setGroup(group);
        draft.setRoleId(roleId);
        draft.setAction(action);
        draft.setDraftStatus(DraftStatus.DRAFT);
        em.persist(draft);

        ChangesetRequestEntity req = new ChangesetRequestEntity();
        req.setChangesetRequestId(changeReqId);
        req.setChangesetType(ChangeSetType.GROUP_ROLE);
        em.persist(req);
        em.flush();
        return req;
    }
}
