package org.tidecloak.iga.attestors;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
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
import org.tidecloak.iga.producer.units.ClientScopeMapperSetUnit;

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
 * BOTH commit flows (bulk drain and single change request) across BOTH signing lanes, for the
 * derived owner-set families.
 *
 * <h2>What a unit test can and cannot reach here</h2>
 *
 * <p>{@code isRealSigningCapable} cannot be made true from a unit test: it needs a provisioned
 * {@code tide-vendor-key} component AND the {@code THRESHOLD_T/N} environment (the same boundary
 * {@link TideAttestorFramingBatchTest} and {@link TideAttestorSetUnitCoalescingTest} document).
 * So the real multiAdmin lane, {@code stampProducerUnitColumns} to
 * {@code distributeMultiAdminUnitSigs} to a {@code Policy:1} ORK ceremony, is NOT entered here
 * and the actual quorum signature bytes are NOT asserted anywhere in this module.
 *
 * <p>What IS asserted, and what the production defect actually consisted of:
 * <ul>
 *   <li>the ORDERED unit list each change request frames, which is what the carrier freezes at
 *       approval AND what commit-time distribution re-derives to stamp {@code sigs[i]} onto
 *       {@code units.get(i)}. A wrong list is the whole bug;</li>
 *   <li>owner-key resolution and contested grouping, which drive the framing batch and the
 *       bulk refusal. These are deliberately independent of signing capability;</li>
 *   <li>the action-type filter the two PENDING lookups use, which decides whether a sibling
 *       change request is ever SEEN by the framing batch or the stale-carrier sweep;</li>
 *   <li>per-owner stamping arithmetic on the lane this class does sign.</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TideAttestorMapperFlowsTest {

    private static final String REALM_ID = "realm-uuid-flows";
    private static final String REALM_NAME = "flows-realm";
    private static final String CLIENT_A = "client-uuid-a";
    private static final String CLIENT_B = "client-uuid-b";
    private static final String SCOPE_C = "scope-id-c";

    private static final String FACTORY = "oidc-usermodel-attribute-mapper";

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock JpaConnectionProvider jpa;
    @Mock EntityManager em;

    /** owner id -> stored owner-set attestation. */
    private final Map<String, String> setColumn = new HashMap<>();
    /** mapper id -> stored ProtocolMapperEntity.attestation. */
    private final Map<String, String> mapperColumn = new HashMap<>();
    /** Every owner a set fan-out was issued for, in order (duplicates are the bug). */
    private final List<String> stampedOwners = new ArrayList<>();
    /** parent id -> its committed mapper ids, in insertion order. */
    private final Map<String, List<String>> parentMappers = new LinkedHashMap<>();

    /** The authorizer row's mode; null means no row (falls back to the attr -> firstAdmin). */
    private String mode;

    private TideAttestor attestor;

    @BeforeEach
    void setUp() {
        when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa);
        when(jpa.getEntityManager()).thenReturn(em);
        when(realm.getId()).thenReturn(REALM_ID);
        when(realm.getName()).thenReturn(REALM_NAME);
        when(realm.getAttribute("iga.attestor")).thenReturn(TideAttestor.ID);
        when(realm.getComponentsStream()).thenAnswer(inv -> Stream.empty());

        @SuppressWarnings("unchecked")
        TypedQuery<IgaAuthorizerEntity> authorizerQuery = mock(TypedQuery.class);
        when(em.createNamedQuery(eq("IgaAuthorizer.findByRealm"), eq(IgaAuthorizerEntity.class)))
                .thenReturn(authorizerQuery);
        when(authorizerQuery.setParameter(anyString(), any())).thenReturn(authorizerQuery);
        when(authorizerQuery.getResultStream()).thenAnswer(inv -> {
            if (mode == null) {
                return Stream.empty();
            }
            IgaAuthorizerEntity row = new IgaAuthorizerEntity();
            row.setRealmId(REALM_ID);
            row.setMode(mode);
            return Stream.of(row);
        });

        wireColumns();
        attestor = new TideAttestor(session);
    }

    /** firstAdmin: no authorizer row, Tide discriminator supplies the mode. */
    private void asFirstAdmin() {
        mode = null;
    }

    /**
     * multiAdmin, NOT real-signing-capable (no tide-vendor-key). The mode discriminator is real;
     * the signature is the deterministic stub, because a unit test cannot reach the ORK.
     */
    private void asMultiAdmin() {
        mode = TideAttestor.MODE_MULTI_ADMIN;
    }

    private void wireColumns() {
        when(em.createQuery(anyString())).thenAnswer(inv -> {
            String jpql = inv.getArgument(0);
            Query q = mock(Query.class);
            Map<String, Object> params = new HashMap<>();
            when(q.setParameter(anyString(), any())).thenAnswer(p -> {
                params.put(p.getArgument(0), p.getArgument(1));
                return q;
            });
            when(q.setMaxResults(anyInt())).thenReturn(q);
            if (jpql.startsWith("UPDATE ProtocolMapperEntity e SET e.attestation")) {
                when(q.executeUpdate()).thenAnswer(x -> {
                    mapperColumn.put((String) params.get("id"), (String) params.get("sig"));
                    return 1;
                });
            } else if (jpql.startsWith("UPDATE ")) {
                when(q.executeUpdate()).thenAnswer(x -> {
                    String owner = (String) params.get("id");
                    stampedOwners.add(owner);
                    setColumn.put(owner, (String) params.get("sig"));
                    return 1;
                });
            } else if (jpql.startsWith("SELECT e.attestation FROM ProtocolMapperEntity")) {
                when(q.getResultList()).thenAnswer(x -> {
                    String s = mapperColumn.get((String) params.get("id"));
                    return s == null ? List.of() : List.of(s);
                });
            } else if (jpql.startsWith("SELECT ")) {
                when(q.getResultList()).thenAnswer(x -> {
                    String s = setColumn.get((String) params.get("id"));
                    return s == null ? List.of() : List.of(s);
                });
            } else {
                when(q.getResultList()).thenAnswer(x -> List.of());
            }
            return q;
        });
    }

    private ProtocolMapperModel mapperModel(String id) {
        ProtocolMapperModel pm = new ProtocolMapperModel();
        pm.setId(id);
        pm.setName("mapper-" + id);
        pm.setProtocol("openid-connect");
        pm.setProtocolMapper(FACTORY);
        pm.setConfig(new HashMap<>());
        return pm;
    }

    /** Register a client whose COMMITTED mapper set is {@code mapperIds}. */
    private void client(String clientUuid, String... mapperIds) {
        parentMappers.put(clientUuid, List.of(mapperIds));
        ClientModel c = mock(ClientModel.class);
        when(c.getId()).thenReturn(clientUuid);
        when(c.getProtocolMappersStream()).thenAnswer(inv ->
                parentMappers.get(clientUuid).stream().map(this::mapperModel));
        when(c.getProtocolMapperById(anyString())).thenAnswer(inv -> {
            String id = inv.getArgument(0, String.class);
            return parentMappers.get(clientUuid).contains(id) ? mapperModel(id) : null;
        });
        when(realm.getClientById(eq(clientUuid))).thenReturn(c);
    }

    /** Register a client scope whose COMMITTED mapper set is {@code mapperIds}. */
    private void clientScope(String scopeId, String... mapperIds) {
        parentMappers.put(scopeId, List.of(mapperIds));
        ClientScopeModel s = mock(ClientScopeModel.class);
        when(s.getId()).thenReturn(scopeId);
        when(s.getProtocolMappersStream()).thenAnswer(inv ->
                parentMappers.get(scopeId).stream().map(this::mapperModel));
        when(s.getProtocolMapperById(anyString())).thenAnswer(inv -> {
            String id = inv.getArgument(0, String.class);
            return parentMappers.get(scopeId).contains(id) ? mapperModel(id) : null;
        });
        when(realm.getClientScopeById(eq(scopeId))).thenReturn(s);
    }

    private IgaChangeRequestEntity clientMapperCr(String crId, String clientUuid, String... mapperIds) {
        return cr(crId, "ADD_PROTOCOL_MAPPER", java.util.Arrays.stream(mapperIds)
                .map(id -> "{\"ID\":\"" + id + "\",\"CLIENT_UUID\":\"" + clientUuid + "\"}")
                .collect(Collectors.joining(",", "[", "]")));
    }

    private IgaChangeRequestEntity scopeMapperCr(String crId, String scopeId, String... mapperIds) {
        return cr(crId, "ADD_PROTOCOL_MAPPER", java.util.Arrays.stream(mapperIds)
                .map(id -> "{\"ID\":\"" + id + "\",\"CLIENT_SCOPE_ID\":\"" + scopeId + "\"}")
                .collect(Collectors.joining(",", "[", "]")));
    }

    private IgaChangeRequestEntity cr(String crId, String action, String rowsJson) {
        IgaChangeRequestEntity cr = mock(IgaChangeRequestEntity.class);
        when(cr.getId()).thenReturn(crId);
        when(cr.getRealmId()).thenReturn(REALM_ID);
        when(cr.getActionType()).thenReturn(action);
        when(cr.getRequestModel()).thenReturn(null);
        when(cr.getRowsJson()).thenReturn(rowsJson);
        return cr;
    }

    /**
     * The deterministic stub this realm produces over {@code envelope}.
     *
     * <p>The PREFIX is lane-dependent and that is pre-existing, deliberate behaviour:
     * {@code signProducerEnvelope} uses {@code TIDE-FIRSTADMIN-v1} for firstAdmin and
     * {@code TIDE-DUMMY-v1} for every other mode. A non-capable multiAdmin realm is a dev/test
     * realm that cannot really sign, so it stubs under DUMMY by design. A PRODUCTION multiAdmin
     * realm is real-signing-capable and never reaches this code at all: it returns early into
     * {@code distributeMultiAdminUnitSigs} and stamps real ORK signatures. That branch is not
     * reachable from a unit test, so what these tests pin is WHICH columns are written, HOW MANY
     * times, and over WHICH bytes, never the signature's authenticity.
     */
    private String stub(byte[] envelope) {
        String prefix = mode == null
                ? TideAttestor.FIRSTADMIN_SIG_PREFIX
                : TideAttestor.DUMMY_SIG_PREFIX;
        try {
            return prefix + Base64.getEncoder()
                    .encodeToString(MessageDigest.getInstance("SHA-256").digest(envelope));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private String expectedClientSetSig(String clientUuid, String... mapperIds) {
        return stub(new ClientMapperSetUnit(REALM_ID, clientUuid, List.of(mapperIds)).serialize());
    }

    /** The signature the commit must leave on {@code mapperId}'s OWN protocol_mapper column. */
    private String expectedMapperSig(String clientUuid, String mapperId) {
        return stub(org.tidecloak.iga.producer.RealmAttestationExporter.protocolMapperUnit(
                        mapperModel(mapperId),
                        org.tidecloak.iga.producer.units.ParentType.client,
                        clientUuid, REALM_ID)
                .serialize());
    }

    private List<String> mapperUnitTargets(List<AttestationUnit> units) {
        return units.stream().filter(u -> u.type() == AttestationUnitType.PROTOCOL_MAPPER)
                .map(AttestationUnit::targetId).collect(Collectors.toList());
    }

    // =========================================================================
    // Item 1 - BULK, N change requests against ONE owner
    // =========================================================================

    @Test
    void bulk_threeMapperCrsOnOneClient_signTheOwnerSetOnceOverTheFinalState() {
        asMultiAdmin();
        client(CLIENT_A, "m-1", "m-2", "m-3", "m-4");
        List<IgaChangeRequestEntity> drain = List.of(
                clientMapperCr("cr-1", CLIENT_A, "m-2"),
                clientMapperCr("cr-2", CLIENT_A, "m-3"),
                clientMapperCr("cr-3", CLIENT_A, "m-4"));

        attestor.stampCoalescedSetUnits(session, realm, drain);

        assertEquals(List.of(CLIENT_A), stampedOwners,
                "three change requests, one owner: exactly ONE fan-out over the post-batch state");
        assertEquals(expectedClientSetSig(CLIENT_A, "m-1", "m-2", "m-3", "m-4"),
                setColumn.get(CLIENT_A),
                "the surviving signature must cover all four committed mappers");
    }

    @Test
    void bulk_everyCrFramesItsOwnMapperUnit_soNoColumnIsLeftUnsigned() {
        asMultiAdmin();
        client(CLIENT_A, "m-1", "m-2", "m-3");
        List<IgaChangeRequestEntity> drain = List.of(
                clientMapperCr("cr-1", CLIENT_A, "m-2"),
                clientMapperCr("cr-2", CLIENT_A, "m-3"));

        // Each change request's carrier frames, and its commit stamps, its OWN mapper unit.
        for (IgaChangeRequestEntity cr : drain) {
            List<AttestationUnit> units = attestor.buildAllCrUnits(session, realm, cr, true);
            assertEquals(AttestationUnitType.CLIENT_MAPPER_SET, units.get(0).type(),
                    "owner set stays at index 0: sigs[i] is stamped onto units.get(i)");
            assertEquals(1, mapperUnitTargets(units).size(),
                    "each change request frames exactly the mapper it adds");
            attestor.stampProducerUnitColumns(session, realm, cr);
        }

        // Stronger than "not null": each mapper's column must carry the signature over THAT
        // mapper's own envelope, so a per-mapper stamp cannot be satisfied by writing the
        // owner-set signature (or a sibling's) into every column.
        for (String id : List.of("m-2", "m-3")) {
            assertNotNull(mapperColumn.get(id),
                    "mapper " + id + " was left unattested, which the login read rejects");
            assertEquals(expectedMapperSig(CLIENT_A, id), mapperColumn.get(id),
                    "mapper " + id + " must carry the signature over its OWN unit envelope");
        }
        assertNotEquals(mapperColumn.get("m-2"), mapperColumn.get("m-3"),
                "two different mappers cannot share a signature");
    }

    // =========================================================================
    // Item 2 - BULK, MIXED owners
    // =========================================================================

    @Test
    void bulk_mixedOwners_eachOwnerSetReflectsOnlyItsOwnMembers() {
        asMultiAdmin();
        client(CLIENT_A, "a-1", "a-2");
        client(CLIENT_B, "b-1");
        clientScope(SCOPE_C, "c-1");

        attestor.stampCoalescedSetUnits(session, realm, List.of(
                clientMapperCr("cr-a1", CLIENT_A, "a-2"),
                clientMapperCr("cr-a2", CLIENT_A, "a-1"),
                clientMapperCr("cr-b", CLIENT_B, "b-1"),
                scopeMapperCr("cr-c", SCOPE_C, "c-1")));

        assertEquals(List.of(CLIENT_A, CLIENT_B, SCOPE_C), stampedOwners,
                "three distinct owners, one fan-out each, and the two change requests against "
                        + "client A collapse into a single stamp");
        assertEquals(expectedClientSetSig(CLIENT_A, "a-1", "a-2"), setColumn.get(CLIENT_A));
        assertEquals(expectedClientSetSig(CLIENT_B, "b-1"), setColumn.get(CLIENT_B),
                "client B's signature must cover ONLY client B's members");
        assertEquals(stub(new ClientScopeMapperSetUnit(REALM_ID, SCOPE_C, List.of("c-1")).serialize()),
                setColumn.get(SCOPE_C),
                "the client scope is a separate owner with its own unit type and column");
    }

    @Test
    void bulk_mixedOwners_areNotContestedWithEachOther() {
        asMultiAdmin();
        client(CLIENT_A, "a-1");
        client(CLIENT_B, "b-1");
        clientScope(SCOPE_C, "c-1");

        assertTrue(attestor.findContestedSetOwners(session, realm, List.of(
                        clientMapperCr("cr-a", CLIENT_A, "a-1"),
                        clientMapperCr("cr-b", CLIENT_B, "b-1"),
                        scopeMapperCr("cr-c", SCOPE_C, "c-1"))).isEmpty(),
                "distinct owners never contest, so a mixed drain is not needlessly refused");
    }

    // =========================================================================
    // Item 3 - SINGLE change request, correct BY CONSTRUCTION
    // =========================================================================

    @Test
    void single_multiAdmin_framesOwnerSetOverTheLiveModelNotPreSetPlusOwnDelta() {
        asMultiAdmin();
        // The committed model already holds m-1 and m-2; this change request added m-2.
        client(CLIENT_A, "m-1", "m-2");
        IgaChangeRequestEntity cr = clientMapperCr("cr-1", CLIENT_A, "m-2");

        List<AttestationUnit> units = attestor.buildAllCrUnits(session, realm, cr, true);

        // Correct BY CONSTRUCTION: the owner set is re-derived from the live post-change model,
        // so it names every committed member, not just this change request's own delta.
        assertEquals(List.of("m-1", "m-2"), ownerSetMembers(units.get(0)),
                "the framed owner set is the LIVE committed set, which is what the ork "
                        + "re-derives; a pre-set plus own delta framing is the defect");
        assertEquals(List.of("m-2"), mapperUnitTargets(units),
                "plus this change request's own mapper unit");
    }

    @Test
    void single_multiAdmin_stampsBothTheOwnerSetAndTheMapperColumn() {
        asMultiAdmin();
        client(CLIENT_A, "m-1", "m-2");
        IgaChangeRequestEntity cr = clientMapperCr("cr-1", CLIENT_A, "m-2");

        attestor.stampProducerUnitColumns(session, realm, cr);

        assertEquals(List.of(CLIENT_A), stampedOwners, "one owner, one fan-out");
        assertNotNull(setColumn.get(CLIENT_A));
        assertNotNull(mapperColumn.get("m-2"),
                "the single-commit flow must stamp the mapper's own column too");
    }

    // =========================================================================
    // Item 4 - SINGLE, repeated: approved together, committed one at a time
    // =========================================================================

    @Test
    void twoMapperCrsApprovedTogether_areFramedAsOneBatch() {
        // resolveFramingBatch is what makes the two carriers describe the SAME post-group state.
        // It filters the pending pool by action type; before the fix that filter listed only the
        // eight edge actions, so a pending mapper change request was never returned and each
        // carrier was framed alone. Committing them one at a time then left the second signature
        // over a set the database no longer held, with no bulk drain involved at all.
        asMultiAdmin();
        client(CLIENT_A, "m-1", "m-2");
        IgaChangeRequestEntity cr1 = clientMapperCr("cr-1", CLIENT_A, "m-1");
        IgaChangeRequestEntity cr2 = clientMapperCr("cr-2", CLIENT_A, "m-2");
        stubPendingPool(List.of(cr1, cr2));

        List<IgaChangeRequestEntity> batch = attestor.resolveFramingBatch(session, realm, cr1);

        assertEquals(List.of("cr-1", "cr-2"),
                batch.stream().map(IgaChangeRequestEntity::getId).collect(Collectors.toList()),
                "both change requests share an owner set, so the phase-1 carrier must be framed "
                        + "over the whole group; a single-element batch is the defect");
    }

    @Test
    void aMapperCrWithNoSibling_isFramedAlone() {
        asMultiAdmin();
        client(CLIENT_A, "m-1");
        IgaChangeRequestEntity cr1 = clientMapperCr("cr-1", CLIENT_A, "m-1");
        stubPendingPool(List.of(cr1));

        assertEquals(1, attestor.resolveFramingBatch(session, realm, cr1).size(),
                "an uncontested change request frames exactly as before");
    }

    @Test
    void ownerSetActionTypes_containsEveryDerivedActionSoThePendingLookupsSeeThem() {
        // The two PENDING lookups (resolveFramingBatch and invalidateStaleSetUnitCarriers)
        // filter server-side on this list. An action that is a derived owner-set action but is
        // missing from the list resolves an owner key yet is invisible to both, which is the
        // exact shape of the defect this test guards.
        for (String action : TideAttestor.DERIVED_OWNER_SET_ACTION_TYPES) {
            assertTrue(TideAttestor.isDerivedOwnerSetAction(action),
                    action + " is in the list so the predicate must accept it");
            assertTrue(TideAttestor.OWNER_SET_ACTION_TYPES.contains(action),
                    action + " must be in the list the pending lookups filter on");
        }
        for (String action : TideAttestor.EDGE_SET_ACTION_TYPES) {
            assertTrue(TideAttestor.OWNER_SET_ACTION_TYPES.contains(action),
                    "the edge actions must remain in the pending-lookup filter");
        }
        assertEquals(TideAttestor.EDGE_SET_ACTION_TYPES.size()
                        + TideAttestor.DERIVED_OWNER_SET_ACTION_TYPES.size(),
                TideAttestor.OWNER_SET_ACTION_TYPES.size(),
                "the union carries every owner-set action and nothing else");
        assertFalse(TideAttestor.isDerivedOwnerSetAction("SET_REALM_ATTRIBUTE"),
                "and nothing that perturbs no owner set");
    }

    // =========================================================================
    // Item 5 - the firstAdmin lane must not regress
    // =========================================================================

    @Test
    void firstAdmin_bulk_signsTheOwnerSetOnceOverTheFinalState() {
        asFirstAdmin();
        client(CLIENT_A, "m-1", "m-2", "m-3");

        attestor.stampCoalescedSetUnits(session, realm, List.of(
                clientMapperCr("cr-1", CLIENT_A, "m-2"),
                clientMapperCr("cr-2", CLIENT_A, "m-3")));

        assertEquals(List.of(CLIENT_A), stampedOwners);
        assertEquals(expectedClientSetSig(CLIENT_A, "m-1", "m-2", "m-3"), setColumn.get(CLIENT_A));
    }

    @Test
    void firstAdmin_single_stampsTheOwnerSetAndTheMapperColumn() {
        asFirstAdmin();
        client(CLIENT_A, "m-1", "m-2");

        attestor.stampProducerUnitColumns(session, realm, clientMapperCr("cr-1", CLIENT_A, "m-2"));

        assertEquals(List.of(CLIENT_A), stampedOwners);
        assertNotNull(setColumn.get(CLIENT_A));
        assertNotNull(mapperColumn.get("m-2"));
    }

    // =========================================================================
    // Item 6 - coalesced multi-row change requests
    // =========================================================================

    @Test
    void coalescedCr_stampsEveryMapperColumnItCarries_onBothLanes() {
        for (boolean firstAdmin : List.of(true, false)) {
            setColumn.clear();
            mapperColumn.clear();
            stampedOwners.clear();
            parentMappers.clear();
            if (firstAdmin) {
                asFirstAdmin();
            } else {
                asMultiAdmin();
            }
            client(CLIENT_A, "m-1", "m-2", "m-3");

            attestor.stampProducerUnitColumns(session, realm,
                    clientMapperCr("cr-1", CLIENT_A, "m-1", "m-2", "m-3"));

            for (String id : List.of("m-1", "m-2", "m-3")) {
                assertNotNull(mapperColumn.get(id),
                        "coalesced mapper " + id + " must be stamped (firstAdmin=" + firstAdmin
                                + "); reading only the first row leaves the rest unattested");
            }
            assertEquals(List.of(CLIENT_A), stampedOwners,
                    "one coalesced change request still stamps its owner set once");
        }
    }

    // ---- helpers ----

    /** Back the {@code listPendingByActionTypeIn} JPQL the pending lookups issue. */
    private void stubPendingPool(List<IgaChangeRequestEntity> pending) {
        @SuppressWarnings("unchecked")
        TypedQuery<IgaChangeRequestEntity> q = mock(TypedQuery.class);
        when(em.createQuery(anyString(), eq(IgaChangeRequestEntity.class))).thenReturn(q);
        when(q.setParameter(anyString(), any())).thenReturn(q);
        when(q.setMaxResults(anyInt())).thenReturn(q);
        when(q.getResultList()).thenReturn(pending);
    }

    @SuppressWarnings("unchecked")
    private static List<String> ownerSetMembers(AttestationUnit ownerSet) {
        return (List<String>) ownerSet.payload().get("protocol_mapper_ids");
    }
}
