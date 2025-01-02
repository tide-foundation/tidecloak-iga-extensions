package org.tidecloak.changeset.utils;

import jakarta.persistence.EntityManager;
import org.keycloak.models.ClientModel;
import org.keycloak.models.jpa.entities.UserEntity;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;
import org.tidecloak.jpa.entities.drafting.TideUserRoleMappingDraftEntity;

import java.util.List;
import java.util.stream.Collectors;

public class UserContextUtils {

    public static List<AccessProofDetailEntity> getUserContextDrafts(EntityManager em, String recordId) {
        return em.createNamedQuery("getProofDetailsForDraft", AccessProofDetailEntity.class)
                .setParameter("recordId", recordId)
                .getResultStream()
                .collect(Collectors.toList());
    }

    public static List<AccessProofDetailEntity> getUserContextDrafts(EntityManager em, ClientModel client, String recordId) {
        return em.createNamedQuery("getProofDetailsByClient", AccessProofDetailEntity.class)
                .setParameter("clientId", client.getId())
                .getResultList();
    }
}
