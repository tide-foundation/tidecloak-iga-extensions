package org.tidecloak.iga.producer;

import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.Test;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.jpa.entities.ProtocolMapperEntity;
import org.tidecloak.iga.producer.units.ParentType;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * protocol_mapper unit config comes from the stored row, so a mapper that writes into the
 * cached model at token time (GroupMembershipMapper adds multivalued=true) can't change it.
 */
class ProtocolMapperUnitStoredConfigTest {

    private static final String REALM_ID = "realm-1";
    private static final String CLIENT_UUID = "client-1";
    private static final String MAPPER_ID = "pm-1";

    private static Map<String, String> storedConfig() {
        Map<String, String> c = new HashMap<>();
        c.put("full.path", "false");
        c.put("introspection.token.claim", "true");
        c.put("userinfo.token.claim", "true");
        c.put("id.token.claim", "true");
        c.put("lightweight.claim", "false");
        c.put("access.token.claim", "true");
        c.put("claim.name", "groups");
        return c;
    }

    private static ProtocolMapperModel model(Map<String, String> config) {
        ProtocolMapperModel pm = new ProtocolMapperModel();
        pm.setId(MAPPER_ID);
        pm.setName("g");
        pm.setProtocol("openid-connect");
        pm.setProtocolMapper("oidc-group-membership-mapper");
        pm.setConfig(config);
        return pm;
    }

    private static KeycloakSession sessionFinding(ProtocolMapperEntity entity) {
        KeycloakSession session = mock(KeycloakSession.class);
        JpaConnectionProvider jpa = mock(JpaConnectionProvider.class);
        EntityManager em = mock(EntityManager.class);
        when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa);
        when(jpa.getEntityManager()).thenReturn(em);
        when(em.find(ProtocolMapperEntity.class, MAPPER_ID)).thenReturn(entity);
        return session;
    }

    private static ProtocolMapperEntity entity(Map<String, String> config) {
        ProtocolMapperEntity e = new ProtocolMapperEntity();
        e.setId(MAPPER_ID);
        e.setConfig(config);
        return e;
    }

    private static byte[] modelOnly(ProtocolMapperModel pm) {
        return RealmAttestationExporter.protocolMapperUnit(pm, ParentType.client, CLIENT_UUID, REALM_ID)
                .serialize();
    }

    @Test
    void mutatedCachedModel_usesStoredRow() {
        Map<String, String> mutated = storedConfig();
        mutated.put("multivalued", "true");
        KeycloakSession session = sessionFinding(entity(storedConfig()));

        byte[] actual = RealmAttestationExporter.protocolMapperUnit(session, model(mutated),
                ParentType.client, CLIENT_UUID, REALM_ID).serialize();

        assertArrayEquals(modelOnly(model(storedConfig())), actual);
        assertFalse(new String(actual, java.nio.charset.StandardCharsets.ISO_8859_1).contains("multivalued"));
    }

    @Test
    void noStoredRow_fallsBackToModel() {
        Map<String, String> cfg = storedConfig();
        cfg.put("multivalued", "true");
        KeycloakSession session = sessionFinding(null);

        byte[] actual = RealmAttestationExporter.protocolMapperUnit(session, model(cfg),
                ParentType.client, CLIENT_UUID, REALM_ID).serialize();

        assertArrayEquals(modelOnly(model(cfg)), actual);
    }

    @Test
    void storedNullValue_emittedAsEmptyString() {
        Map<String, String> withNull = storedConfig();
        withNull.put("claim.name", null);
        Map<String, String> withEmpty = storedConfig();
        withEmpty.put("claim.name", "");
        KeycloakSession session = sessionFinding(entity(withNull));

        byte[] actual = RealmAttestationExporter.protocolMapperUnit(session, model(storedConfig()),
                ParentType.client, CLIENT_UUID, REALM_ID).serialize();

        assertArrayEquals(modelOnly(model(withEmpty)), actual);
    }

    @Test
    void nullSession_usesModel() {
        Map<String, String> cfg = storedConfig();
        cfg.put("multivalued", "true");

        byte[] actual = RealmAttestationExporter.protocolMapperUnit(null, model(cfg),
                ParentType.client, CLIENT_UUID, REALM_ID).serialize();

        assertArrayEquals(modelOnly(model(cfg)), actual);
    }
}
