package org.tidecloak.iga.attestors;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.tidecloak.iga.entities.IgaAuthorizerEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.producer.RealmAttestationExporter;
import org.tidecloak.iga.producer.units.ParentType;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import jakarta.persistence.TypedQuery;

import java.security.MessageDigest;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * firstAdmin-lane coverage for the CREATE_CLIENT full-owned-family stamp
 * ({@code TideAttestor.stampCreateClientUnitFamily}, routed from the CREATE_CLIENT case
 * of {@code stampProducerUnitColumns}).
 *
 * <p>Regression guard for the governed-client first-login fail-close: committing a
 * CREATE_CLIENT CR historically stamped ONLY the {@code client_config} node column
 * (ClientEntity.attestation), leaving CLIENT_SCOPE_ASSIGNMENT_ATTESTATION,
 * CLIENT_MAPPER_SET_ATTESTATION, SCOPE_ROLE_ALLOWLIST_ATTESTATION and each folded
 * mapper's ProtocolMapperEntity.attestation NULL. The login exporter emits those units
 * for the requesting client, so the first login to the new client fail-closed in
 * {@code IgaAttestationExporterProvider.replayOrFailClosed}. On firstAdmin realms the
 * post-commit convergence self-healed the NULLs; the stamp itself must still be complete
 * (the multiAdmin lane, which has NO convergence backstop, shares the SAME
 * {@code clientOwnedUnits} enumeration; see TideAttestorBuildAllCrUnitsTest).
 *
 * <p>Runs the NON-capable stub path (no tide-vendor-key component), so the stamped
 * value is the deterministic SHA-256 stub over the envelope bytes; asserting the stub
 * value therefore ALSO asserts the signed envelope bytes equal the
 * {@link RealmAttestationExporter} builder bytes the login read replays (the
 * byte-identity that makes the real 64-byte VVK sig verify).
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TideAttestorCreateClientFamilyStampTest {

    private static final String REALM_ID = "realm-uuid-createclientfam";
    private static final String CLIENT_UUID = "client-uuid-ccf";
    private static final String MAPPER_ID = "mapper-ccf-1";

    // UnitColumnMapping's exact JPQL for the four client-owned columns + the mapper column.
    private static final String JPQL_CLIENT_CONFIG =
            "UPDATE ClientEntity e SET e.attestation = :sig WHERE e.id = :id";
    private static final String JPQL_SCOPE_ASSIGNMENT =
            "UPDATE ClientEntity e SET e.clientScopeAssignmentAttestation = :sig WHERE e.id = :id";
    private static final String JPQL_MAPPER_SET =
            "UPDATE ClientEntity e SET e.clientMapperSetAttestation = :sig WHERE e.id = :id";
    private static final String JPQL_ALLOWLIST =
            "UPDATE ClientEntity e SET e.scopeRoleAllowlistAttestation = :sig WHERE e.id = :id";
    private static final String JPQL_PROTOCOL_MAPPER =
            "UPDATE ProtocolMapperEntity e SET e.attestation = :sig WHERE e.id = :id";

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock JpaConnectionProvider jpa;
    @Mock EntityManager em;
    @Mock IgaChangeRequestEntity cr;

    private TideAttestor attestor;

    /** jpql -> the :sig value the stamp bound when executeUpdate ran. */
    private final Map<String, Object> stampedByJpql = new LinkedHashMap<>();

    @BeforeEach
    void setUp() {
        when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa);
        when(jpa.getEntityManager()).thenReturn(em);
        when(realm.getId()).thenReturn(REALM_ID);
        when(realm.getName()).thenReturn("ccf-realm");

        // resolveMode: no IgaAuthorizer row + iga.attestor=tide -> MODE_FIRST_ADMIN.
        @SuppressWarnings("unchecked")
        TypedQuery<IgaAuthorizerEntity> nq = mock(TypedQuery.class);
        when(em.createNamedQuery(eq("IgaAuthorizer.findByRealm"), eq(IgaAuthorizerEntity.class)))
                .thenReturn(nq);
        when(nq.setParameter(anyString(), any())).thenReturn(nq);
        when(nq.getResultStream()).thenAnswer(inv -> Stream.empty());
        when(realm.getAttribute("iga.attestor")).thenReturn(TideAttestor.ID);

        // No tide-vendor-key component -> NOT real-signing-capable -> deterministic stub
        // sigs (the routing contract pinned by TideAttestorAdoptProducerSignRoutingTest).
        // Fresh stream per call (a single Stream instance would throw "already operated upon").
        when(realm.getComponentsStream()).thenAnswer(inv -> Stream.empty());

        // Record every UPDATE the stampers execute: jpql -> the bound :sig value.
        when(em.createQuery(anyString())).thenAnswer(inv -> {
            String jpql = inv.getArgument(0);
            Query q = mock(Query.class);
            Map<String, Object> params = new HashMap<>();
            when(q.setParameter(anyString(), any())).thenAnswer(pinv -> {
                params.put(pinv.getArgument(0), pinv.getArgument(1));
                return q;
            });
            when(q.executeUpdate()).thenAnswer(einv -> {
                stampedByJpql.put(jpql, params.get("sig"));
                return 1;
            });
            when(q.getResultList()).thenReturn(java.util.Collections.emptyList());
            return q;
        });

        // No phase-1 carrier (single-phase firstAdmin commit).
        when(cr.getRequestModel()).thenReturn(null);

        attestor = new TideAttestor(session);
    }

    private ClientModel mockClient(org.keycloak.models.ProtocolMapperModel... mappers) {
        ClientModel client = mock(ClientModel.class);
        when(client.getId()).thenReturn(CLIENT_UUID);
        when(client.getClientId()).thenReturn("governed-app");
        when(client.getClientScopes(org.mockito.ArgumentMatchers.anyBoolean()))
                .thenReturn(java.util.Collections.emptyMap());
        when(client.getScopeMappingsStream()).thenAnswer(inv -> Stream.empty());
        when(client.getProtocolMappersStream()).thenAnswer(inv -> Stream.of(mappers));
        for (org.keycloak.models.ProtocolMapperModel pm : mappers) {
            when(client.getProtocolMapperById(pm.getId())).thenReturn(pm);
        }
        when(client.isServiceAccountsEnabled()).thenReturn(false);
        when(realm.getClientById(CLIENT_UUID)).thenReturn(client);
        return client;
    }

    private static String stubFor(byte[] envelope) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(envelope);
        return TideAttestor.FIRSTADMIN_SIG_PREFIX + Base64.getEncoder().encodeToString(digest);
    }

    @Test
    void createClientCommit_stampsAllFourClientColumns_andEachFoldedMapperColumn() throws Exception {
        org.keycloak.models.ProtocolMapperModel folded = new org.keycloak.models.ProtocolMapperModel();
        folded.setId(MAPPER_ID);
        folded.setName("custom-audience");
        folded.setProtocol("openid-connect");
        folded.setProtocolMapper("oidc-audience-mapper");
        folded.setConfig(java.util.Map.of("included.custom.audience", "aud-x"));
        ClientModel client = mockClient(folded);

        when(cr.getActionType()).thenReturn("CREATE_CLIENT");
        when(cr.getRowsJson()).thenReturn(
                "[{\"ID\":\"" + CLIENT_UUID + "\",\"CLIENT_ID\":\"governed-app\"}]");

        attestor.stampProducerUnitColumns(session, realm, cr);

        // ALL FOUR client-owned columns must be written, not just ClientEntity.attestation.
        assertTrue(stampedByJpql.containsKey(JPQL_CLIENT_CONFIG),
                "client_config node column must be stamped");
        assertTrue(stampedByJpql.containsKey(JPQL_SCOPE_ASSIGNMENT),
                "CLIENT_SCOPE_ASSIGNMENT_ATTESTATION must be stamped (the folded default-scope "
                        + "attachments' set; its NULL was the first-login fail-close)");
        assertTrue(stampedByJpql.containsKey(JPQL_MAPPER_SET),
                "CLIENT_MAPPER_SET_ATTESTATION must be stamped");
        assertTrue(stampedByJpql.containsKey(JPQL_ALLOWLIST),
                "SCOPE_ROLE_ALLOWLIST_ATTESTATION must be stamped");
        assertTrue(stampedByJpql.containsKey(JPQL_PROTOCOL_MAPPER),
                "each folded protocol_mapper's own attestation column must be stamped");

        // The stamped stub is deterministic over the envelope bytes, so equality with a stub
        // computed over the EXPORTER's builder bytes proves the signed envelope equals what
        // RealmAttestationExporter would export for this client (the login-replay bytes).
        assertEquals(stubFor(RealmAttestationExporter
                        .clientScopeAssignmentSet(client, REALM_ID).serialize()),
                stampedByJpql.get(JPQL_SCOPE_ASSIGNMENT),
                "the scope-assignment stamp must sign the exporter's exact envelope bytes");
        assertEquals(stubFor(RealmAttestationExporter
                        .clientConfig(session, client, REALM_ID).serialize()),
                stampedByJpql.get(JPQL_CLIENT_CONFIG));
        assertEquals(stubFor(RealmAttestationExporter
                        .clientMapperSet(client, REALM_ID).serialize()),
                stampedByJpql.get(JPQL_MAPPER_SET));
        assertEquals(stubFor(RealmAttestationExporter
                        .scopeRoleAllowlistSet(ParentType.client, CLIENT_UUID, client, REALM_ID)
                        .serialize()),
                stampedByJpql.get(JPQL_ALLOWLIST));
        assertEquals(stubFor(RealmAttestationExporter
                        .protocolMapperUnit(folded, ParentType.client, CLIENT_UUID, REALM_ID)
                        .serialize()),
                stampedByJpql.get(JPQL_PROTOCOL_MAPPER));
    }

    @Test
    void setClientAttributeCommit_staysNodeOnly_noDerivedSetOverStamp() {
        // Contrast guard: SET_CLIENT_ATTRIBUTE (and the other client UPDATE_* actions) must
        // keep stamping ONLY the client_config node. The derived owner-sets were signed at
        // create / by their own CRs; re-stamping them here would re-sign already-attested
        // units on every client tweak.
        mockClient();
        when(cr.getActionType()).thenReturn("SET_CLIENT_ATTRIBUTE");
        when(cr.getRowsJson()).thenReturn("[{\"CLIENT_UUID\":\"" + CLIENT_UUID + "\"}]");

        attestor.stampProducerUnitColumns(session, realm, cr);

        assertTrue(stampedByJpql.containsKey(JPQL_CLIENT_CONFIG),
                "the client_config node column must be stamped");
        assertFalse(stampedByJpql.containsKey(JPQL_SCOPE_ASSIGNMENT),
                "SET_CLIENT_ATTRIBUTE must NOT re-stamp the scope-assignment set");
        assertFalse(stampedByJpql.containsKey(JPQL_MAPPER_SET),
                "SET_CLIENT_ATTRIBUTE must NOT re-stamp the mapper set");
        assertFalse(stampedByJpql.containsKey(JPQL_ALLOWLIST),
                "SET_CLIENT_ATTRIBUTE must NOT re-stamp the allowlist set");
    }
}
