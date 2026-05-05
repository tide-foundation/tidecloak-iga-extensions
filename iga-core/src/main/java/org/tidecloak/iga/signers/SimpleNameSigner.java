package org.tidecloak.iga.signers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.tidecloak.iga.entities.IgaAuthorizationEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;

import jakarta.persistence.EntityManager;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Default {@link IgaSigner} that performs no cryptography. It simply records
 * the authorizing admin's username as the "signature" and combines all the
 * recorded usernames + timestamps into a small JSON array.
 */
public class SimpleNameSigner implements IgaSigner {

    public static final String ID = "simple";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public SimpleNameSigner(KeycloakSession session) {
        // session is supplied via the per-call parameter; constructor arg is kept
        // to match the factory's create(session) wiring.
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public IgaAuthorizationEntity record(KeycloakSession session,
                                         IgaChangeRequestEntity cr,
                                         UserModel admin,
                                         String signaturePayload) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        IgaAuthorizationEntity auth = new IgaAuthorizationEntity();
        auth.setId(UUID.randomUUID().toString());
        auth.setChangeRequest(cr);
        auth.setAuthorizedBy(admin.getId());
        // The "name" is the signature for the simple signer; ignore signaturePayload.
        auth.setPartialSig(admin.getUsername());
        auth.setCreatedAt(System.currentTimeMillis());
        em.persist(auth);
        em.flush();
        return auth;
    }

    @Override
    public String combineFinal(KeycloakSession session,
                               IgaChangeRequestEntity cr,
                               List<IgaAuthorizationEntity> authorizations) {
        List<Map<String, Object>> list = new ArrayList<>();
        if (authorizations != null) {
            for (IgaAuthorizationEntity a : authorizations) {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("by", a.getPartialSig());
                entry.put("at", a.getCreatedAt());
                list.add(entry);
            }
        }
        try {
            return MAPPER.writeValueAsString(list);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize SimpleNameSigner final signature", e);
        }
    }

    @Override
    public int getThreshold(RealmModel realm) {
        String val = realm.getAttribute("iga.threshold");
        if (val != null) {
            try {
                return Integer.parseInt(val);
            } catch (NumberFormatException ignored) {
            }
        }
        return 1;
    }

    @Override
    public void close() {
    }
}
