package org.tidecloak.changeset.utils;

import jakarta.persistence.EntityManager;
import org.keycloak.models.*;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.representations.AccessToken;
import org.tidecloak.enums.ActionType;
import org.tidecloak.jpa.entities.AccessProofDetailEntity;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.BinaryOperator;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collector;
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
