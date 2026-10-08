package org.tidecloak.iga.attestors;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.tidecloak.iga.entities.IgaAuthorizerEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.producer.units.AttestationUnit;
import org.tidecloak.iga.producer.units.AttestationUnitType;
import org.tidecloak.iga.producer.units.ClientMapperSetUnit;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import jakarta.persistence.TypedQuery;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * REPRODUCTION + fix coverage for the SAME bulk-approve set-signature clobber that
 * {@link TideAttestorSetUnitCoalescingTest} pins for the eight edge actions, on the action
 * family that was still exposed to it: the protocol-mapper change requests.
 *
 * <p>{@code client_mapper_set} is an owner-keyed derived set exactly like
 * {@code role_composite_children_set}, but {@code ADD_PROTOCOL_MAPPER} is not one of the eight
 * {@code isProducerEnvelopeSignedAction} actions, so before this fix a mapper change request
 * produced a {@code null} owner key and was invisible to BOTH guards the edge actions have:
 * contested-owner detection (hence framing batches) and per-batch coalescing. Two mapper adds
 * against one client in a bulk drain therefore each stamped {@code client_mapper_set} with a
 * signature over {@code pre-set + that change request's own mapper}, and the second write won.
 *
 * <p>A second, independent gap is covered here too: the change request framed only the owner
 * set, never the new mapper's own {@code protocol_mapper} unit, so
 * {@code ProtocolMapperEntity.attestation} was left NULL or stubbed. On firstAdmin the
 * convergence backfill repaired that later; on multiAdmin there is no such backstop.
 *
 * <p><b>Harness boundary.</b> Same as the edge-action sibling: Mockito, no database and no ork,
 * so the batch is driven at the coalescing seam and the signature is the realm's deterministic
 * non-capable stub rather than a real 64-byte VVK signature. The bytes SIGNED are the real
 * producer envelopes, so the set-membership property the ork verifies is exercised exactly.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TideAttestorMapperSetCoalescingTest {

    private static final String REALM_ID = "realm-uuid-mapper-coalesce";
    private static final String REALM_NAME = "mapper-coalesce-realm";
    private static final String CLIENT_UUID = "client-uuid-1";

    private static final String PRE_MAPPER = "m-aaa";
    private static final String CR1_MAPPER = "m-bbb";
    private static final String CR2_MAPPER = "m-ccc";

    /** A JWT-body-relevant factory: emitted in the owner set AND as its own unit. */
    private static final String RELEVANT_FACTORY = "oidc-usermodel-attribute-mapper";
    /** A JWT-body-IRRELEVANT factory: emitted in NEITHER (see JWT_BODY_IRRELEVANT_FACTORIES). */
    private static final String IRRELEVANT_FACTORY = "oidc-acr-mapper";

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock JpaConnectionProvider jpa;
    @Mock EntityManager em;

    /** client uuid -> the attestation stored on ClientEntity.clientMapperSetAttestation. */
    private final Map<String, String> mapperSetColumn = new HashMap<>();
    /** mapper id -> the attestation stored on ProtocolMapperEntity.attestation. */
    private final Map<String, String> protocolMapperColumn = new HashMap<>();
    /** Every owner the client_mapper_set fan-out UPDATE was issued for, in order. */
    private final List<String> stampedOwners = new ArrayList<>();
    /** mapper id -> the mapper's factory, for every mapper the committed client holds. */
    private final Map<String, String> committedMappers = new LinkedHashMap<>();

    private TideAttestor attestor;

    @BeforeEach
    void setUp() {
        when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa);
        when(jpa.getEntityManager()).thenReturn(em);
        when(realm.getId()).thenReturn(REALM_ID);
        when(realm.getName()).thenReturn(REALM_NAME);
        // Tide discriminator with no authorizer row -> firstAdmin; no tide-vendor-key
        // component -> not real-signing-capable, so signing is the deterministic stub.
        when(realm.getAttribute("iga.attestor")).thenReturn(TideAttestor.ID);
        when(realm.getComponentsStream()).thenAnswer(inv -> Stream.empty());

        @SuppressWarnings("unchecked")
        TypedQuery<IgaAuthorizerEntity> authorizerQuery = mock(TypedQuery.class);
        when(em.createNamedQuery(eq("IgaAuthorizer.findByRealm"), eq(IgaAuthorizerEntity.class)))
                .thenReturn(authorizerQuery);
        when(authorizerQuery.setParameter(anyString(), any())).thenReturn(authorizerQuery);
        when(authorizerQuery.getResultStream()).thenAnswer(inv -> Stream.empty());

        wireMapperColumns();
        attestor = new TideAttestor(session);
    }

    /**
     * Back {@code ClientEntity.clientMapperSetAttestation} and
     * {@code ProtocolMapperEntity.attestation} with in-memory maps so the owner fan-out, the
     * per-mapper stamp and the {@code UnitColumnMapping} read the post-stamp verification
     * performs all operate on the same state a real batch would leave behind.
     */
    private void wireMapperColumns() {
        when(em.createQuery(anyString())).thenAnswer(inv -> {
            String jpql = inv.getArgument(0);
            Query q = mock(Query.class);
            Map<String, Object> params = new HashMap<>();
            when(q.setParameter(anyString(), any())).thenAnswer(p -> {
                params.put(p.getArgument(0), p.getArgument(1));
                return q;
            });
            when(q.setMaxResults(anyInt())).thenReturn(q);
            if (jpql.startsWith("UPDATE ClientEntity e SET e.clientMapperSetAttestation")) {
                when(q.executeUpdate()).thenAnswer(x -> {
                    String owner = (String) params.get("id");
                    stampedOwners.add(owner);
                    mapperSetColumn.put(owner, (String) params.get("sig"));
                    return 1;
                });
            } else if (jpql.startsWith("UPDATE ProtocolMapperEntity e SET e.attestation")) {
                when(q.executeUpdate()).thenAnswer(x -> {
                    protocolMapperColumn.put((String) params.get("id"), (String) params.get("sig"));
                    return 1;
                });
            } else if (jpql.startsWith("SELECT e.clientMapperSetAttestation FROM ClientEntity")) {
                when(q.getResultList()).thenAnswer(x -> {
                    String stored = mapperSetColumn.get((String) params.get("id"));
                    return stored == null ? List.of() : List.of(stored);
                });
            } else if (jpql.startsWith("SELECT e.attestation FROM ProtocolMapperEntity")) {
                when(q.getResultList()).thenAnswer(x -> {
                    String stored = protocolMapperColumn.get((String) params.get("id"));
                    return stored == null ? List.of() : List.of(stored);
                });
            } else {
                when(q.getResultList()).thenAnswer(x -> List.of());
            }
            return q;
        });
    }

    /** Register the committed client whose mappers are {@code committedMappers}. */
    private ClientModel committedClient() {
        ClientModel client = mock(ClientModel.class);
        when(client.getId()).thenReturn(CLIENT_UUID);
        when(client.getProtocolMappersStream()).thenAnswer(inv ->
                committedMappers.keySet().stream().map(this::mapperModel));
        when(client.getProtocolMapperById(anyString())).thenAnswer(inv -> {
            String id = inv.getArgument(0, String.class);
            return committedMappers.containsKey(id) ? mapperModel(id) : null;
        });
        when(realm.getClientById(eq(CLIENT_UUID))).thenReturn(client);
        return client;
    }

    private ProtocolMapperModel mapperModel(String mapperId) {
        ProtocolMapperModel pm = new ProtocolMapperModel();
        pm.setId(mapperId);
        pm.setName("mapper-" + mapperId);
        pm.setProtocol("openid-connect");
        pm.setProtocolMapper(committedMappers.get(mapperId));
        pm.setConfig(new java.util.HashMap<>());
        return pm;
    }

    /** Put a mapper into the COMMITTED model with the given factory. */
    private void committedMapper(String mapperId, String factory) {
        committedMappers.put(mapperId, factory);
    }

    private IgaChangeRequestEntity addMapperCr(String crId, String... mapperIds) {
        return mapperCr(crId, "ADD_PROTOCOL_MAPPER", mapperIds);
    }

    private IgaChangeRequestEntity mapperCr(String crId, String actionType, String... mapperIds) {
        IgaChangeRequestEntity cr = mock(IgaChangeRequestEntity.class);
        when(cr.getId()).thenReturn(crId);
        when(cr.getRealmId()).thenReturn(REALM_ID);
        when(cr.getActionType()).thenReturn(actionType);
        when(cr.getEntityId()).thenReturn(CLIENT_UUID);
        when(cr.getRequestModel()).thenReturn(null);
        // coalesceOrCreate folds several same-request mapper adds into ONE change request
        // carrying one row per mapper, so the rows are a list, not a single row.
        String rows = java.util.Arrays.stream(mapperIds)
                .map(id -> "{\"ID\":\"" + id + "\",\"CLIENT_UUID\":\"" + CLIENT_UUID + "\"}")
                .collect(Collectors.joining(",", "[", "]"));
        when(cr.getRowsJson()).thenReturn(rows);
        return cr;
    }

    /** The stub signature the non-capable firstAdmin realm produces over a client mapper set. */
    private static String expectedSetSig(String... mapperIds) {
        return stub(new ClientMapperSetUnit(REALM_ID, CLIENT_UUID, List.of(mapperIds)).serialize());
    }

    private static String stub(byte[] envelope) {
        try {
            return TideAttestor.FIRSTADMIN_SIG_PREFIX + Base64.getEncoder()
                    .encodeToString(MessageDigest.getInstance("SHA-256").digest(envelope));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private List<AttestationUnit> framedUnits(IgaChangeRequestEntity cr) {
        return attestor.enumerateLiveCrUnits(session, realm, em, cr);
    }

    // -------------------------------------------------------------------------
    // The reproduction: coalescing
    // -------------------------------------------------------------------------

    @Test
    void twoMapperCrsOnOneClient_leaveOneSignatureOverTheFullCommittedSet() {
        // The bulk batch: CR1 adds m-bbb and CR2 adds m-ccc to the SAME client, which already
        // carried m-aaa. Both replays are applied, so the committed set is all three.
        committedMapper(PRE_MAPPER, RELEVANT_FACTORY);
        committedMapper(CR1_MAPPER, RELEVANT_FACTORY);
        committedMapper(CR2_MAPPER, RELEVANT_FACTORY);
        committedClient();
        IgaChangeRequestEntity cr1 = addMapperCr("cr-1", CR1_MAPPER);
        IgaChangeRequestEntity cr2 = addMapperCr("cr-2", CR2_MAPPER);

        attestor.stampCoalescedSetUnits(session, realm, List.of(cr1, cr2));

        assertEquals(List.of(CLIENT_UUID), stampedOwners,
                "the two mapper change requests share one owner set, so exactly ONE fan-out "
                        + "must be issued (a per-change-request stamp lets the last write clobber "
                        + "the first, which is the production failure)");
        assertEquals(expectedSetSig(PRE_MAPPER, CR1_MAPPER, CR2_MAPPER),
                mapperSetColumn.get(CLIENT_UUID),
                "the stored signature must cover the FULL committed mapper set, which is what "
                        + "the ork re-derives at token issue");
        assertNotEquals(expectedSetSig(PRE_MAPPER, CR1_MAPPER),
                mapperSetColumn.get(CLIENT_UUID),
                "a signature over pre-set + ONE change request's mapper is the production "
                        + "failure: the database holds three mappers");
        assertNotEquals(expectedSetSig(PRE_MAPPER, CR2_MAPPER),
                mapperSetColumn.get(CLIENT_UUID),
                "likewise for the other change request's partial set");
    }

    @Test
    void singleMapperCr_control_signsTheCommittedSet() {
        committedMapper(PRE_MAPPER, RELEVANT_FACTORY);
        committedMapper(CR1_MAPPER, RELEVANT_FACTORY);
        committedClient();

        attestor.stampCoalescedSetUnits(session, realm, List.of(addMapperCr("cr-1", CR1_MAPPER)));

        assertEquals(List.of(CLIENT_UUID), stampedOwners);
        assertEquals(expectedSetSig(PRE_MAPPER, CR1_MAPPER), mapperSetColumn.get(CLIENT_UUID));
    }

    // -------------------------------------------------------------------------
    // Reachability: the machinery must SEE a mapper change request at all
    // -------------------------------------------------------------------------

    @Test
    void mapperCrYieldsAnOwnerKey_soContestedDetectionAndFramingSeeIt() {
        committedMapper(CR1_MAPPER, RELEVANT_FACTORY);
        committedMapper(CR2_MAPPER, RELEVANT_FACTORY);
        committedClient();
        IgaChangeRequestEntity cr1 = addMapperCr("cr-1", CR1_MAPPER);
        IgaChangeRequestEntity cr2 = addMapperCr("cr-2", CR2_MAPPER);

        String key = attestor.setUnitOwnerKey(session, realm, cr1);

        assertNotNull(key, "a mapper change request perturbs client_mapper_set, so it MUST yield "
                + "an owner key; a null key is what hid it from every #115 guard");
        assertEquals(AttestationUnitType.CLIENT_MAPPER_SET.wireName() + '|' + CLIENT_UUID, key);
        assertEquals(key, attestor.setUnitOwnerKey(session, realm, cr2),
                "both change requests target the same client, so they must share one owner key");

        Map<String, List<String>> contested =
                attestor.findContestedSetOwners(session, realm, List.of(cr1, cr2));
        assertEquals(Map.of(key, List.of("cr-1", "cr-2")), contested,
                "two mapper change requests against one client are a CONTESTED owner set, which "
                        + "is what drives the framing batch on a frozen-carrier realm");
    }

    @Test
    void twoMapperCrsOnDifferentClients_areNotContested() {
        committedMapper(CR1_MAPPER, RELEVANT_FACTORY);
        committedClient();
        ClientModel other = mock(ClientModel.class);
        when(other.getId()).thenReturn("client-uuid-2");
        when(other.getProtocolMappersStream()).thenAnswer(inv -> Stream.empty());
        when(realm.getClientById(eq("client-uuid-2"))).thenReturn(other);

        IgaChangeRequestEntity cr1 = addMapperCr("cr-1", CR1_MAPPER);
        IgaChangeRequestEntity cr2 = mock(IgaChangeRequestEntity.class);
        when(cr2.getId()).thenReturn("cr-2");
        when(cr2.getActionType()).thenReturn("ADD_PROTOCOL_MAPPER");
        when(cr2.getRowsJson()).thenReturn(
                "[{\"ID\":\"m-zzz\",\"CLIENT_UUID\":\"client-uuid-2\"}]");

        assertTrue(attestor.findContestedSetOwners(session, realm, List.of(cr1, cr2)).isEmpty(),
                "distinct owners are never contested");
    }

    // -------------------------------------------------------------------------
    // The per-mapper column (the second gap)
    // -------------------------------------------------------------------------

    @Test
    void addMapperCr_framesAndStampsTheMappersOwnProtocolMapperUnit() {
        committedMapper(PRE_MAPPER, RELEVANT_FACTORY);
        committedMapper(CR1_MAPPER, RELEVANT_FACTORY);
        committedClient();
        IgaChangeRequestEntity cr = addMapperCr("cr-1", CR1_MAPPER);

        List<AttestationUnit> units = framedUnits(cr);

        assertEquals(AttestationUnitType.CLIENT_MAPPER_SET, units.get(0).type(),
                "the owner set stays at index 0: the carrier stamps sigs[i] onto units.get(i), "
                        + "so framing order is a wire contract");
        assertEquals(List.of(CR1_MAPPER),
                units.stream().filter(u -> u.type() == AttestationUnitType.PROTOCOL_MAPPER)
                        .map(AttestationUnit::targetId).collect(Collectors.toList()),
                "the mapper this change request adds must carry its OWN protocol_mapper unit; "
                        + "framing only the owner set left ProtocolMapperEntity.attestation NULL, "
                        + "which the uniform login read rejects fail-closed");

        attestor.stampProducerUnitColumns(session, realm, cr);

        assertNotNull(protocolMapperColumn.get(CR1_MAPPER),
                "the new mapper's own attestation column must be stamped by the commit that "
                        + "created it; on multiAdmin there is no convergence backstop to repair it");
        assertFalse(protocolMapperColumn.get(CR1_MAPPER).startsWith(TideAttestor.DUMMY_SIG_PREFIX),
                "a TIDE-DUMMY-v1 stub is exactly what the login read fail-closes on");
    }

    @Test
    void removeMapperCr_framesTheOwnerSetOnly() {
        // The removed row is gone from the post-change model, so there is no column left to
        // carry a per-mapper signature and the owner set alone describes the change.
        committedMapper(PRE_MAPPER, RELEVANT_FACTORY);
        committedClient();
        IgaChangeRequestEntity cr = mapperCr("cr-1", "REMOVE_PROTOCOL_MAPPER", CR1_MAPPER);

        List<AttestationUnit> units = framedUnits(cr);

        assertEquals(1, units.size(), "a removal frames the owner set and nothing else");
        assertEquals(AttestationUnitType.CLIENT_MAPPER_SET, units.get(0).type());
    }

    @Test
    void coalescedMultiMapperCr_framesEveryMapperItCarries() {
        // coalesceOrCreate folds several same-request adds into ONE change request with N rows;
        // firstRowKey would have seen only the first, leaving the rest unsigned.
        committedMapper(CR1_MAPPER, RELEVANT_FACTORY);
        committedMapper(CR2_MAPPER, RELEVANT_FACTORY);
        committedClient();
        IgaChangeRequestEntity cr = addMapperCr("cr-1", CR1_MAPPER, CR2_MAPPER);

        assertEquals(List.of(CR1_MAPPER, CR2_MAPPER),
                framedUnits(cr).stream()
                        .filter(u -> u.type() == AttestationUnitType.PROTOCOL_MAPPER)
                        .map(AttestationUnit::targetId).collect(Collectors.toList()),
                "every mapper the coalesced change request carries needs its own unit");
    }

    // -------------------------------------------------------------------------
    // The ork's atomic-filter invariant
    // -------------------------------------------------------------------------

    /**
     * The ork's Stage 4 resolves each id in the owner set's {@code protocol_mapper_ids} through
     * an UNGUARDED dictionary indexer, so an id present in the set but with no
     * {@code protocol_mapper} unit is an uncaught {@code KeyNotFoundException}, i.e. a 500
     * rather than a clean attestation failure. The JWT-relevance filter must therefore be
     * applied ATOMICALLY: a mapper dropped from unit emission must ALSO be absent from the
     * owner set's member list. Dropping it from both is safe.
     *
     * <p>This holds by construction because both sides call the same
     * {@code RealmAttestationExporter.jwtRelevantMapperIds} over the same parent stream. This
     * test pins that so a future change cannot introduce a second, independent filter.
     */
    @Test
    void jwtIrrelevantMapper_isAbsentFromBothTheOwnerSetAndTheUnits() {
        committedMapper(PRE_MAPPER, RELEVANT_FACTORY);
        committedMapper(CR1_MAPPER, IRRELEVANT_FACTORY);
        committedClient();
        IgaChangeRequestEntity cr = addMapperCr("cr-1", CR1_MAPPER);

        List<AttestationUnit> units = framedUnits(cr);
        List<String> setMembers = ownerSetMembers(units.get(0));
        List<String> unitTargets = units.stream()
                .filter(u -> u.type() == AttestationUnitType.PROTOCOL_MAPPER)
                .map(AttestationUnit::targetId).collect(Collectors.toList());

        assertFalse(setMembers.contains(CR1_MAPPER),
                "a JWT-body-irrelevant factory is filtered out of the owner set");
        assertFalse(unitTargets.contains(CR1_MAPPER),
                "and out of unit emission, atomically: in the set but not emitted is a 500 in "
                        + "the ork's unguarded Stage 4 indexer");
        assertEquals(List.of(PRE_MAPPER), setMembers,
                "the relevant sibling is unaffected");
    }

    @Test
    void everyEmittedMapperUnitIsAMemberOfTheOwnerSet() {
        // The direction that crashes the ork is "in the set, no unit". The converse direction
        // is asserted here too so the two emissions can never drift apart in either direction.
        committedMapper(PRE_MAPPER, RELEVANT_FACTORY);
        committedMapper(CR1_MAPPER, RELEVANT_FACTORY);
        committedMapper(CR2_MAPPER, IRRELEVANT_FACTORY);
        committedClient();
        IgaChangeRequestEntity cr = addMapperCr("cr-1", CR1_MAPPER, CR2_MAPPER);

        List<AttestationUnit> units = framedUnits(cr);
        List<String> setMembers = ownerSetMembers(units.get(0));

        for (AttestationUnit u : units) {
            if (u.type() == AttestationUnitType.PROTOCOL_MAPPER) {
                assertTrue(setMembers.contains(u.targetId()),
                        "emitted protocol_mapper " + u.targetId() + " must be a member of the "
                                + "owner set it belongs to");
            }
        }
        assertEquals(List.of(PRE_MAPPER, CR1_MAPPER), setMembers,
                "the irrelevant mapper is in neither the set nor the units");
    }

    @SuppressWarnings("unchecked")
    private static List<String> ownerSetMembers(AttestationUnit ownerSet) {
        assertEquals(AttestationUnitType.CLIENT_MAPPER_SET, ownerSet.type());
        return (List<String>) ownerSet.payload().get("protocol_mapper_ids");
    }
}
