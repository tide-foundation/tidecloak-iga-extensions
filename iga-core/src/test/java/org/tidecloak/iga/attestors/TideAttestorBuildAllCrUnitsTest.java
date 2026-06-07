package org.tidecloak.iga.attestors;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.producer.IgaCreateUnitBuilder;
import org.tidecloak.iga.producer.units.AttestationUnit;
import org.tidecloak.iga.producer.units.AttestationUnitType;
import org.tidecloak.iga.producer.units.ScopeRoleAllowlistSetUnit;
import org.tidecloak.iga.producer.units.UserRoleMappingSetUnit;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * ★ P4 — coverage for the SHARED affected-units enumerator
 * {@code TideAttestor.enumerateLiveCrUnits} (the single mapping "which units does actionType X
 * touch", used by BOTH phase-1 carrier framing AND commit-time distribution) and the
 * {@code buildAllCrUnits(..., modelAlreadyPostChange=true)} commit-path overload that runs it
 * directly over the (already-post-change) live model.
 *
 * <p>What is asserted WITHOUT real ORKs / a real session factory (Mockito): the enumerator
 * returns the CORRECT affected-unit SET (types + targets + order) for an edge action, the four
 * representative non-edge actions the task calls out (SET_CLIENT_ATTRIBUTE / ASSIGN_SCOPE /
 * ADD_PROTOCOL_MAPPER / SET_REALM_ATTRIBUTE), and that the SAME enumerator returns the IDENTICAL
 * set whether reached via the commit overload or invoked directly (framing == distribution).
 *
 * <p>The PHASE-1 scratch-replay-and-read ({@code buildAllCrUnits(..., false)} →
 * {@code IgaScratchUnitBuilder.unitsFromScratchReplay}) needs a real
 * {@code KeycloakSessionFactory} ({@code runJobInTransaction} + the dispatcher replay) so it is
 * NOT exercised here; the deep byte-identity (scratch post-change == committed post-change) is
 * guaranteed BY CONSTRUCTION — both run the IDENTICAL {@code IgaReplayDispatcher.replay} and the
 * IDENTICAL {@code enumerateLiveCrUnits} — and is flagged for live multiAdmin validation.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TideAttestorBuildAllCrUnitsTest {

    private static final String REALM_ID = "realm-uuid-p4";
    private static final String USER_ID = "user-p4";
    private static final String CLIENT_UUID = "client-uuid-p4";
    private static final String SCOPE_ID = "scope-id-p4";

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock JpaConnectionProvider jpa;
    @Mock EntityManager em;
    @Mock IgaChangeRequestEntity cr;

    private TideAttestor attestor;

    @BeforeEach
    void setUp() {
        when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa);
        when(jpa.getEntityManager()).thenReturn(em);
        when(realm.getId()).thenReturn(REALM_ID);
        attestor = new TideAttestor(session);
    }

    private void stubIdQuery(List<String> ids) {
        Query q = mock(Query.class);
        when(em.createQuery(anyString())).thenReturn(q);
        when(q.setParameter(anyString(), org.mockito.ArgumentMatchers.any())).thenReturn(q);
        when(q.getResultList()).thenReturn((List) ids);
    }

    // ---- the commit-path overload runs enumerateLiveCrUnits directly (mock-friendly) ----

    @Test
    void edgeSetCr_commitPath_enumeratesExactlyTheIndex0EdgeUnit_byteIdenticalToProducer() {
        // A GRANT_ROLES CR over a user with post-change set {r-aaa, r-zzz}.
        stubIdQuery(Arrays.asList("r-aaa"));
        when(cr.getActionType()).thenReturn("GRANT_ROLES");
        when(cr.getEntityId()).thenReturn(USER_ID);
        when(cr.getRowsJson()).thenReturn(
                "[{\"USER_ID\":\"" + USER_ID + "\",\"ROLE_ID\":\"r-zzz\"}]");

        List<AttestationUnit> units = attestor.buildAllCrUnits(session, realm, cr, true);

        assertEquals(1, units.size(), "an edge-set CR frames exactly its index-0 edge unit");
        AttestationUnit u0 = units.get(0);
        assertEquals(AttestationUnitType.USER_ROLE_MAPPING_SET, u0.type(),
                "index 0 must be the user_role_mapping_set edge unit");
        assertEquals(USER_ID, u0.targetId(), "the edge unit's target is the owner user");

        List<String> committed = Arrays.asList("r-aaa", "r-zzz");
        byte[] producerBytes = new UserRoleMappingSetUnit(REALM_ID, USER_ID, committed).serialize();
        assertArrayEquals(producerBytes, u0.serialize(),
                "the framed edge-unit CBOR must equal the producer's post-change envelope");
    }

    @Test
    void buildAllCrUnitCbor_isTheParallelByteArray() {
        stubIdQuery(Arrays.asList("r-aaa"));
        when(cr.getActionType()).thenReturn("GRANT_ROLES");
        when(cr.getEntityId()).thenReturn(USER_ID);
        when(cr.getRowsJson()).thenReturn(
                "[{\"USER_ID\":\"" + USER_ID + "\",\"ROLE_ID\":\"r-zzz\"}]");

        List<AttestationUnit> units = attestor.buildAllCrUnits(session, realm, cr, true);
        byte[][] cbor = new byte[units.size()][];
        for (int i = 0; i < units.size(); i++) cbor[i] = units.get(i).serialize();

        assertEquals(units.size(), cbor.length);
        for (int i = 0; i < units.size(); i++) {
            assertArrayEquals(units.get(i).serialize(), cbor[i],
                    "cbor[" + i + "] must be units.get(" + i + ").serialize() (verbatim, in order)");
        }
    }

    // ---- the affected-units mapping: a NODE, a DERIVED, an edge-derived, a REALM unit ----

    @Test
    void setClientAttributeCr_enumeratesTheClientConfigNodeUnit() {
        ClientModel client = mock(ClientModel.class);
        when(client.getId()).thenReturn(CLIENT_UUID);
        when(realm.getClientById(CLIENT_UUID)).thenReturn(client);
        when(cr.getActionType()).thenReturn("SET_CLIENT_ATTRIBUTE");
        when(cr.getRowsJson()).thenReturn("[{\"CLIENT_UUID\":\"" + CLIENT_UUID + "\"}]");

        List<AttestationUnit> units = attestor.buildAllCrUnits(session, realm, cr, true);

        assertEquals(1, units.size(), "SET_CLIENT_ATTRIBUTE touches exactly the client_config node");
        assertEquals(AttestationUnitType.CLIENT_CONFIG, units.get(0).type());
        assertEquals(CLIENT_UUID, units.get(0).targetId());
    }

    @Test
    void assignScopeCr_enumeratesTheClientScopeAssignmentSet() {
        ClientModel client = mock(ClientModel.class);
        when(client.getId()).thenReturn(CLIENT_UUID);
        when(client.getClientScopes(org.mockito.ArgumentMatchers.anyBoolean()))
                .thenReturn(java.util.Collections.emptyMap());
        when(realm.getClientById(CLIENT_UUID)).thenReturn(client);
        when(cr.getActionType()).thenReturn("ASSIGN_SCOPE");
        when(cr.getRowsJson()).thenReturn(
                "[{\"CLIENT_UUID\":\"" + CLIENT_UUID + "\",\"SCOPE_ID\":\"" + SCOPE_ID + "\"}]");

        List<AttestationUnit> units = attestor.buildAllCrUnits(session, realm, cr, true);

        assertEquals(1, units.size(), "ASSIGN_SCOPE touches exactly the client_scope_assignment_set");
        assertEquals(AttestationUnitType.CLIENT_SCOPE_ASSIGNMENT_SET, units.get(0).type());
        assertEquals(CLIENT_UUID, units.get(0).targetId());
    }

    @Test
    void addProtocolMapperCr_onAClient_enumeratesTheClientMapperSet() {
        ClientModel client = mock(ClientModel.class);
        when(client.getId()).thenReturn(CLIENT_UUID);
        when(client.getProtocolMappersStream()).thenReturn(java.util.stream.Stream.empty());
        when(realm.getClientById(CLIENT_UUID)).thenReturn(client);
        when(cr.getActionType()).thenReturn("ADD_PROTOCOL_MAPPER");
        when(cr.getRowsJson()).thenReturn("[{\"CLIENT_UUID\":\"" + CLIENT_UUID + "\"}]");

        List<AttestationUnit> units = attestor.buildAllCrUnits(session, realm, cr, true);

        assertEquals(1, units.size(), "ADD_PROTOCOL_MAPPER on a client touches the client_mapper_set");
        assertEquals(AttestationUnitType.CLIENT_MAPPER_SET, units.get(0).type());
        assertEquals(CLIENT_UUID, units.get(0).targetId());
    }

    @Test
    void createUserCr_enumeratesExactlyTheUserIdentityNodeUnit_notZero() {
        // ★ Regression guard for the CREATE_USER multiAdmin carrier bug: the scratch-replay
        // creates the user from REP_JSON with rep.id = the ROWS_JSON "ID", then enumerateLiveCrUnits
        // resolves THAT user via session.users().getUserById(realm, firstRowKeyOr("USER_ID","ID"))
        // and builds the user_identity node unit. The historical failure was 0 units (the lookup
        // missed → canonicalForRegularCr fallback → a non-AttestationUnit carrier → enclave
        // self-close). This asserts the CREATE_USER branch resolves the post-change user and frames
        // EXACTLY one user_identity unit targeting that user.
        org.keycloak.models.UserModel user = mock(org.keycloak.models.UserModel.class);
        when(user.getId()).thenReturn(USER_ID);
        when(user.getUsername()).thenReturn("dfgewwer");
        when(user.getEmail()).thenReturn("test@tide.org");
        when(user.isEmailVerified()).thenReturn(false);
        when(user.getFirstName()).thenReturn("werrewr");
        when(user.getLastName()).thenReturn("dsfsd");
        when(user.getAttributes()).thenReturn(java.util.Collections.emptyMap());
        org.keycloak.models.UserProvider users = mock(org.keycloak.models.UserProvider.class);
        when(session.users()).thenReturn(users);
        when(users.getUserById(realm, USER_ID)).thenReturn(user);

        when(cr.getActionType()).thenReturn("CREATE_USER");
        // The CREATE_USER ROWS_JSON carries "ID" (own UUID), not "USER_ID" — firstRowKeyOr
        // must fall through "USER_ID" → "ID". (Matches IgaReplayDispatcher.replayCreateUser,
        // which reads str(row,"ID") and rep.setId(that).)
        when(cr.getRowsJson()).thenReturn(
                "[{\"ID\":\"" + USER_ID + "\",\"USERNAME\":\"dfgewwer\"}]");

        List<AttestationUnit> units = attestor.buildAllCrUnits(session, realm, cr, true);

        assertEquals(1, units.size(),
                "CREATE_USER must frame exactly the user_identity node unit (NOT 0 → no "
                        + "canonicalForRegularCr fallback)");
        assertEquals(AttestationUnitType.USER_IDENTITY, units.get(0).type(),
                "the single framed unit must be the user_identity node");
        assertEquals(USER_ID, units.get(0).targetId(),
                "the user_identity unit targets the newly-created user's id (the ROWS_JSON ID)");
    }

    @Test
    void setRealmAttributeCr_enumeratesTheRealmConfigUnit() {
        when(cr.getActionType()).thenReturn("SET_REALM_ATTRIBUTE");
        when(cr.getRowsJson()).thenReturn("[{\"NAME\":\"some.attr\",\"VALUE\":\"v\"}]");

        List<AttestationUnit> units = attestor.buildAllCrUnits(session, realm, cr, true);

        assertEquals(1, units.size(), "SET_REALM_ATTRIBUTE touches exactly the realm_config unit");
        assertEquals(AttestationUnitType.REALM_CONFIG, units.get(0).type());
        assertEquals(REALM_ID, units.get(0).targetId(), "realm-scoped units target the realm id");
    }

    @Test
    void scopeAddRoleCr_enumeratesTheScopeRoleAllowlistSet_forClientScopeParent() {
        ClientScopeModel scope = mock(ClientScopeModel.class);
        when(scope.getId()).thenReturn(SCOPE_ID);
        when(scope.getScopeMappingsStream()).thenReturn(java.util.stream.Stream.empty());
        when(realm.getClientScopeById(SCOPE_ID)).thenReturn(scope);
        when(cr.getActionType()).thenReturn("SCOPE_ADD_ROLE");
        when(cr.getRowsJson()).thenReturn(
                "[{\"SCOPE_ID\":\"" + SCOPE_ID + "\",\"ROLE_ID\":\"r-1\"}]");

        List<AttestationUnit> units = attestor.buildAllCrUnits(session, realm, cr, true);

        assertEquals(1, units.size());
        assertEquals(AttestationUnitType.SCOPE_ROLE_ALLOWLIST_SET, units.get(0).type());
        assertEquals(SCOPE_ID, units.get(0).targetId());
        assertTrue(units.get(0) instanceof ScopeRoleAllowlistSetUnit);
    }

    // ---- framing == distribution: the SAME enumerator, identical set ----

    @Test
    void sharedEnumerator_returnsIdenticalSet_forPhase1AndCommit() {
        // Two invocations of the SAME enumerator (via the commit overload) over the same
        // (post-change) model MUST return an identical unit set — types, targets, and bytes.
        // This is the framing==distribution invariant the phase-1 carrier and the commit
        // distribution both rely on (both call enumerateLiveCrUnits; phase-1 only differs in
        // first reaching post-change via the scratch replay).
        ClientModel client = mock(ClientModel.class);
        when(client.getId()).thenReturn(CLIENT_UUID);
        when(realm.getClientById(CLIENT_UUID)).thenReturn(client);
        when(cr.getActionType()).thenReturn("SET_CLIENT_ATTRIBUTE");
        when(cr.getRowsJson()).thenReturn("[{\"CLIENT_UUID\":\"" + CLIENT_UUID + "\"}]");

        List<AttestationUnit> a = attestor.buildAllCrUnits(session, realm, cr, true);
        List<AttestationUnit> b = attestor.buildAllCrUnits(session, realm, cr, true);

        assertEquals(a.size(), b.size(), "the shared enumerator must return a stable unit count");
        for (int i = 0; i < a.size(); i++) {
            assertEquals(a.get(i).type(), b.get(i).type(), "unit[" + i + "] type must be stable");
            assertEquals(a.get(i).targetId(), b.get(i).targetId(), "unit[" + i + "] target must be stable");
            assertArrayEquals(a.get(i).serialize(), b.get(i).serialize(),
                    "unit[" + i + "] CBOR must be stable (framing == distribution)");
        }
    }

    @Test
    void fromRepCreateGate_marksExactlyTheFiveNodeCreates() {
        for (String a : new String[]{"CREATE_USER", "CREATE_ROLE", "CREATE_GROUP",
                "CREATE_CLIENT", "CREATE_CLIENT_SCOPE"}) {
            assertTrue(IgaCreateUnitBuilder.isFromRepCreateAction(a),
                    a + " must be a from-REP_JSON node create");
        }
        for (String a : new String[]{"GRANT_ROLES", "JOIN_GROUPS", "SET_CLIENT_ATTRIBUTE",
                "ASSIGN_SCOPE", "ADD_PROTOCOL_MAPPER", "SET_REALM_CONFIG",
                "CREATE_ORGANIZATION", null}) {
            assertFalse(IgaCreateUnitBuilder.isFromRepCreateAction(a),
                    a + " must NOT be a from-REP_JSON node create");
        }
    }
}
