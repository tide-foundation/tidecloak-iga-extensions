package org.tidecloak.iga.providers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.entities.TidePolicyEntity;

import jakarta.persistence.EntityManager;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class TidePolicyService {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final KeycloakSession session;
    private final EntityManager em;

    public TidePolicyService(KeycloakSession session) {
        this.session = session;
        // Same EntityManager acquisition idiom the providers use
        // (IgaUserProviderFactory.create / IgaUserProvider.recordAndThrow):
        // Keycloak's shared request-scoped EM off JpaConnectionProvider.
        this.em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
    }

    public IgaChangeRequestEntity create(RealmModel realm, String id, String data, String notes, String requestedBy){
        IgaChangeRequestService igaService = new IgaChangeRequestService(em, session);
        if(igaService.isIgaEnabled(realm)){
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("ID", id);
            row.put("REALM_ID", realm.getId());
            row.put("DATA", data);
            row.put("REP_JSON", serializePolicy(id, realm.getId(), data, notes));
            return igaService.create(realm, "TIDE_POLICY", id, "CREATE_TIDE_POLICY", List.of(row), requestedBy);
        }
        writePolicy(realm, id, data, notes);
        return null;
    }

    public void writePolicy(RealmModel realm, String id, String data, String notes){
        TidePolicyEntity entity = new TidePolicyEntity();
        entity.setId(id);
        entity.setData(data);
        entity.setRealmId(realm.getId());
        entity.setCreatedAt(System.currentTimeMillis());
        entity.setNotes(notes);
        em.persist(entity);
        em.flush();
    }

    public TidePolicyEntity getPolicy(String id) {
        List<TidePolicyEntity> results = em.createNamedQuery("TidePolicy.findById", TidePolicyEntity.class)
                .setParameter("id", id)
                .getResultList();
        return results.isEmpty() ? null : results.get(0);
    }

    public List<TidePolicyEntity> listPolicies(RealmModel realm) {
        return em.createNamedQuery("TidePolicy.findByRealm", TidePolicyEntity.class)
                .setParameter("realmId", realm.getId())
                .getResultList();
    }

    private static String serializePolicy(String id, String realmId, String data, String notes){
        Map<String, Object> rep = new LinkedHashMap<>();
        rep.put("id", id);
        rep.put("realmId", realmId);
        rep.put("data", data);
        rep.put("notes", notes);
        try {
            return MAPPER.writeValueAsString(rep);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize TidePolicyEntity REP_JSON", e);
        }
    }
}
