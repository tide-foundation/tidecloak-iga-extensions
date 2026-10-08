package org.tidecloak.iga.replay;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientProvider;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.ClientScopeProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.mockito.ArgumentCaptor;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;

/**
 * ADD_PROTOCOL_MAPPER replay must stamp only the new mapper's own row, even on the
 * set-signed (tide) lane. Fanning the CR's value out over every sibling mapper of the
 * same client / client scope overwrote their real unit sigs with a stub on multiAdmin.
 */
class ReplayAddProtocolMapperStampTest {

    private static final String SIG = "TIDE-DUMMY-v1:x";

    private static Method replayAddProtocolMapper() throws Exception {
        Method m = IgaReplayDispatcher.class.getDeclaredMethod(
                "replayAddProtocolMapper", KeycloakSession.class, RealmModel.class,
                IgaChangeRequestEntity.class, List.class, String.class,
                EntityManager.class, boolean.class);
        m.setAccessible(true);
        return m;
    }

    private static List<Map<String, Object>> row(String ownerKey, String ownerValue) {
        Map<String, Object> row = new HashMap<>();
        row.put("ID", "m-2");
        row.put("NAME", "mapper-two");
        row.put("PROTOCOL", "openid-connect");
        row.put("PROTOCOL_MAPPER_NAME", "oidc-hardcoded-claim-mapper");
        row.put(ownerKey, ownerValue);
        List<Map<String, Object>> rows = new ArrayList<>();
        rows.add(row);
        return rows;
    }

    private static void invoke(KeycloakSession session, RealmModel realm,
                               List<Map<String, Object>> rows, EntityManager em) throws Exception {
        try {
            replayAddProtocolMapper().invoke(null, session, realm,
                    mock(IgaChangeRequestEntity.class), rows, SIG, em, true);
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException re) throw re;
            throw new RuntimeException(e.getCause());
        }
    }

    private static void assertOnlyPerIdStamp(EntityManager em, Query q) {
        ArgumentCaptor<String> jpql = ArgumentCaptor.forClass(String.class);
        verify(em).createQuery(jpql.capture());
        assertEquals(1, jpql.getAllValues().size());
        String only = jpql.getValue();
        assertEquals("UPDATE ProtocolMapperEntity e SET e.attestation = :sig WHERE e.id = :id", only);
        assertFalse(only.contains(":owner"));
        verify(q).setParameter("sig", SIG);
        verify(q).setParameter("id", "m-2");
        verify(q).executeUpdate();
    }

    @Test
    void clientOwned_setSigned_stampsOnlyTheNewMapper() throws Exception {
        RealmModel realm = mock(RealmModel.class);
        KeycloakSession session = mock(KeycloakSession.class);
        ClientProvider clients = mock(ClientProvider.class);
        ClientModel client = mock(ClientModel.class);
        when(client.getClientId()).thenReturn("client-a");
        when(clients.getClientById(realm, "client-a")).thenReturn(client);
        when(session.clients()).thenReturn(clients);

        EntityManager em = mock(EntityManager.class);
        Query q = mock(Query.class);
        when(em.createQuery(anyString())).thenReturn(q);
        when(q.setParameter(anyString(), any())).thenReturn(q);
        when(q.executeUpdate()).thenReturn(1);

        invoke(session, realm, row("CLIENT_UUID", "client-a"), em);

        verify(client).addProtocolMapper(any(ProtocolMapperModel.class));
        assertOnlyPerIdStamp(em, q);
    }

    @Test
    void scopeOwned_setSigned_stampsOnlyTheNewMapper() throws Exception {
        RealmModel realm = mock(RealmModel.class);
        KeycloakSession session = mock(KeycloakSession.class);
        ClientScopeProvider scopes = mock(ClientScopeProvider.class);
        ClientScopeModel scope = mock(ClientScopeModel.class);
        when(scope.getName()).thenReturn("scope-a");
        when(scopes.getClientScopeById(realm, "scope-a")).thenReturn(scope);
        when(session.clientScopes()).thenReturn(scopes);

        EntityManager em = mock(EntityManager.class);
        Query q = mock(Query.class);
        when(em.createQuery(anyString())).thenReturn(q);
        when(q.setParameter(anyString(), any())).thenReturn(q);
        when(q.executeUpdate()).thenReturn(1);

        invoke(session, realm, row("CLIENT_SCOPE_ID", "scope-a"), em);

        verify(scope).addProtocolMapper(any(ProtocolMapperModel.class));
        assertOnlyPerIdStamp(em, q);
    }
}
