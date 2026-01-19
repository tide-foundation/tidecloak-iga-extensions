
package org.tidecloak.base.iga.interfaces;

import jakarta.persistence.EntityManager;
import org.keycloak.models.RealmModel;
import org.keycloak.models.jpa.entities.UserEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.drafting.TideUserGroupMembershipEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;

import java.util.UUID;

public class TideUserGroupMembershipAdapter {

    private final RealmModel realm;
    private final EntityManager em;
    private final UserEntity user;

    public TideUserGroupMembershipAdapter(RealmModel realm, EntityManager em, UserEntity user) {
        this.realm = realm;
        this.em = em;
        this.user = user;
    }

    public ChangesetRequestEntity request(String groupId, ActionType action) {
        String changeReqId = UUID.randomUUID().toString();

        TideUserGroupMembershipEntity draft = new TideUserGroupMembershipEntity();
        draft.setId(UUID.randomUUID().toString());
        draft.setChangeRequestId(changeReqId);
        draft.setUser(user);
        draft.setGroupId(groupId);
        draft.setAction(action);
        draft.setDraftStatus(DraftStatus.DRAFT);
        em.persist(draft);

        ChangesetRequestEntity req = new ChangesetRequestEntity();
        req.setChangesetRequestId(changeReqId);
        req.setChangesetType(ChangeSetType.USER_GROUP_MEMBERSHIP);
        em.persist(req);
        em.flush();
        return req;
    }
}
