
package org.tidecloak.base.iga.interfaces;

import jakarta.persistence.EntityManager;
import org.keycloak.models.RealmModel;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.tidecloak.jpa.entities.ChangesetRequestEntity;
import org.tidecloak.jpa.entities.drafting.TideClientScopeMappingDraftEntity;
import org.tidecloak.shared.enums.ActionType;
import org.tidecloak.shared.enums.ChangeSetType;
import org.tidecloak.shared.enums.DraftStatus;

import java.util.UUID;

public class TideClientScopeMappingAdapter {

    private final RealmModel realm;
    private final EntityManager em;
    private final ClientEntity client;

    public TideClientScopeMappingAdapter(RealmModel realm, EntityManager em, ClientEntity client) {
        this.realm = realm;
        this.em = em;
        this.client = client;
    }

    public ChangesetRequestEntity request(String clientScopeId, boolean defaultScope, ActionType action) {
        String changeReqId = UUID.randomUUID().toString();

        TideClientScopeMappingDraftEntity draft = new TideClientScopeMappingDraftEntity();
        draft.setId(UUID.randomUUID().toString());
        draft.setChangeRequestId(changeReqId);
        draft.setClientId(client.getId());
        draft.setClientScopeId(clientScopeId);
        draft.setDefaultScope(defaultScope);
        draft.setAction(action);
        draft.setDraftStatus(DraftStatus.DRAFT);
        em.persist(draft);

        ChangesetRequestEntity req = new ChangesetRequestEntity();
        req.setChangesetRequestId(changeReqId);
        req.setChangesetType(ChangeSetType.CLIENT_DEFAULT_USER_CONTEXT);
        em.persist(req);
        em.flush();
        return req;
    }
}
