package org.tidecloak.shared.utils;

import jakarta.persistence.EntityManager;
import org.keycloak.models.RealmModel;
import org.tidecloak.jpa.entities.drafting.TideClientDraftEntity;
import org.tidecloak.shared.enums.DraftStatus;

import java.util.List;

public class UserContextDraftUtil {

    public static List<TideClientDraftEntity> findDraftsNotInAccessProof(EntityManager em, RealmModel realm) {
        return em.createNamedQuery("TideClientDraftEntity.findDraftsNotInAccessProof", TideClientDraftEntity.class)
                .setParameter("draftStatus", DraftStatus.DRAFT)
                .setParameter("realmId", realm.getId())
                .getResultList();
    }
}