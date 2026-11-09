package org.tidecloak.iga.providers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.midgard.models.Policy.Policy;
import org.tidecloak.iga.attestors.TideAttestor;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.entities.TidePolicyEntity;

import jakarta.persistence.EntityManager;
import java.util.Arrays;
import java.util.Base64;
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

    /**
     * @throws IllegalArgumentException if {@code data} is not an unsigned Policy
     *         (see {@link #decodeUnsignedPolicy}) — rejected at draft, not at commit.
     */
    public IgaChangeRequestEntity create(RealmModel realm, String id, String data, String notes, String requestedBy){
        decodeUnsignedPolicy(data);
        IgaChangeRequestService igaService = new IgaChangeRequestService(em, session);
        if(igaService.isIgaEnabled(realm)){
            if (TideAttestor.tidePolicyRequiresMultiAdmin(session, realm)) {
                throw new IllegalArgumentException("A Tide policy can only be signed by the "
                        + "tide-realm-admin quorum; this realm has no tide-realm-admin yet");
            }
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

    /**
     * Decode a policy's {@code data} — Base64 of an UNSIGNED Midgard {@code Policy.ToBytes()},
     * the same encoding {@code IGA_ROLE_POLICY.POLICY} uses. A policy that already carries a
     * signature is refused: the signature is only ever attached here, after the realm's
     * authorizers approved the change request.
     */
    public static byte[] decodeUnsignedPolicy(String data) {
        Policy policy;
        byte[] bytes;
        try {
            bytes = Base64.getDecoder().decode(data);
            policy = Policy.From(bytes);
        } catch (Exception e) {
            throw new IllegalArgumentException("'data' must be Base64 of a Tide Policy: " + e.getMessage(), e);
        }
        if (policy.getSignature() != null) {
            throw new IllegalArgumentException("'data' must be an unsigned Policy; it already carries a signature");
        }
        // The ORK signs the bytes as sent; attachSignature re-serializes via ToBytes(). Refuse
        // an encoding that does not round-trip, or the stored signature would not verify.
        if (!Arrays.equals(policy.ToBytes(), bytes)) {
            throw new IllegalArgumentException("'data' is not a canonically encoded Policy");
        }
        return bytes;
    }

    /**
     * Attach the VVK signature to the policy itself and re-encode it for storage:
     * {@code Base64(Policy.ToBytes())} with the signature as the Policy's own segment.
     *
     * @param data   Base64 of the unsigned {@code Policy.ToBytes()} the authorizers approved
     * @param vvkSig Base64 VVK signature returned by the signing ceremony
     */
    public static String attachSignature(String data, String vvkSig) {
        Policy policy = Policy.From(decodeUnsignedPolicy(data));
        policy.AddSignature(Base64.getDecoder().decode(vvkSig));
        return Base64.getEncoder().encodeToString(policy.ToBytes());
    }

    /**
     * The policy {@code data} of a CREATE_TIDE_POLICY row. REP_JSON is the full CREATE
     * snapshot ({id, realmId, data, notes}) and the authoritative source; the top-level
     * DATA key is the fallback for a bare row without one.
     */
    public static String dataOf(Map<String, Object> row) {
        Map<String, Object> rep = repOf(row);
        Object data = rep != null ? rep.get("data") : row.get("DATA");
        return data != null ? data.toString() : null;
    }

    /** The policy {@code notes} of a CREATE_TIDE_POLICY row — carried only in REP_JSON. */
    public static String notesOf(Map<String, Object> row) {
        Map<String, Object> rep = repOf(row);
        Object notes = rep != null ? rep.get("notes") : null;
        return notes != null ? notes.toString() : null;
    }

    private static Map<String, Object> repOf(Map<String, Object> row) {
        Object repJson = row.get("REP_JSON");
        if (repJson == null || repJson.toString().isEmpty()) {
            return null;
        }
        try {
            return MAPPER.readValue(repJson.toString(), new TypeReference<Map<String, Object>>() {});
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to deserialize REP_JSON for a CREATE_TIDE_POLICY row (id="
                    + row.get("ID") + ")", e);
        }
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
