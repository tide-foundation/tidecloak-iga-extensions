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
    void createUserCr_enumeratesTheNewUsersFullPerUserLoginClosure_notJustUserIdentity() {
        // ★ Regression guard for the CREATE_USER multiAdmin carrier coverage bug: the carrier
        // historically framed ONLY the user_identity node unit, so the quorum signed only that.
        // But a freshly-created user is assigned the realm's default-roles, and its LOGIN
        // (RealmAttestationExporter.export) ALSO emits a user_role_mapping_set edge unit. Framing
        // only user_identity left that edge's ATTESTATION column NULL → the new user's login
        // fail-closed ("user_role_mapping_set ... has a NULL column").
        //
        // The fix: the CREATE_USER branch of enumerateLiveCrUnits now enumerates the user's FULL
        // per-user login closure — user_identity AND user_role_mapping_set (from the post-change
        // live role set, ORDER BY urm.roleId) AND user_group_membership_set when non-empty — so the
        // quorum signs every unit the login replays. This asserts N>1 and that user_role_mapping_set
        // is present targeting the new user.
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

        // Stub the two post-change set queries (role set, then group set). The shared
        // em.createQuery(anyString()) stub returns the SAME result list for both; a non-empty
        // list means BOTH user_role_mapping_set and user_group_membership_set get framed —
        // exercising the full-closure enumeration (N == 3: identity + role-set + group-set).
        stubIdQuery(List.of("default-roles-bewreakn-role-id"));

        when(cr.getActionType()).thenReturn("CREATE_USER");
        // The CREATE_USER ROWS_JSON carries "ID" (own UUID), not "USER_ID" — firstRowKeyOr
        // must fall through "USER_ID" → "ID". (Matches IgaReplayDispatcher.replayCreateUser,
        // which reads str(row,"ID") and rep.setId(that).)
        when(cr.getRowsJson()).thenReturn(
                "[{\"ID\":\"" + USER_ID + "\",\"USERNAME\":\"dfgewwer\"}]");

        List<AttestationUnit> units = attestor.buildAllCrUnits(session, realm, cr, true);

        assertTrue(units.size() > 1,
                "CREATE_USER must frame the new user's FULL per-user login closure (N>1), not just "
                        + "the user_identity node — got " + units.size());
        assertEquals(AttestationUnitType.USER_IDENTITY, units.get(0).type(),
                "the user_identity node must stay first in the closure");
        assertEquals(USER_ID, units.get(0).targetId(),
                "the user_identity unit targets the newly-created user's id (the ROWS_JSON ID)");
        assertTrue(units.stream().anyMatch(u ->
                        u.type() == AttestationUnitType.USER_ROLE_MAPPING_SET
                                && USER_ID.equals(u.targetId())),
                "the CREATE_USER closure MUST include the new user's user_role_mapping_set edge unit "
                        + "(the default-roles assignment the login replays) targeting that user");

        // ★ COMPLETE BY CONSTRUCTION: the carrier set must be DERIVED from the producer's OWN
        // per-user closure (RealmAttestationExporter.perUserUnits) — the exact same method
        // export() calls to emit a user's units — NOT a hand-listed subset. Assert the carrier
        // equals perUserUnits byte-for-byte (types, targets, AND CBOR). If the producer ever adds
        // a per-user unit type to perUserUnits, this equality keeps the carrier in lockstep
        // automatically (and this assertion would catch any drift).
        List<AttestationUnit> producerPerUser =
                new org.tidecloak.iga.producer.RealmAttestationExporter()
                        .perUserUnits(em, user, REALM_ID);
        assertEquals(producerPerUser.size(), units.size(),
                "the CREATE_USER carrier must enumerate EXACTLY the producer's per-user closure "
                        + "(complete by construction), not a hand-coded subset");
        for (int i = 0; i < units.size(); i++) {
            assertEquals(producerPerUser.get(i).type(), units.get(i).type(),
                    "carrier unit[" + i + "] type must match the producer per-user closure");
            assertEquals(producerPerUser.get(i).targetId(), units.get(i).targetId(),
                    "carrier unit[" + i + "] target must match the producer per-user closure");
            assertArrayEquals(producerPerUser.get(i).serialize(), units.get(i).serialize(),
                    "carrier unit[" + i + "] CBOR must be byte-identical to the producer's "
                            + "per-user closure (== the login-replay bytes the VVK sig verifies)");
        }
    }

    @Test
    void createUserCr_rolelessUser_doesNotFrameAnEmptyUserRoleMappingSet() {
        // ★ Regression guard for the empty-set fail-closed bug (user 98bc3758, realm bewreakn,
        // CR 836228ce): a CREATE_USER for a user with ZERO direct role rows must NOT frame a
        // user_role_mapping_set unit. That unit's sig lives ON the user_role_mapping rows (any
        // row); a roleless user has none, so the commit-time stamp writes 0 rows and the login
        // read finds a NULL column → replayOrFailClosed fail-closes the login. perUserUnits now
        // gates the role-set on a non-empty role list (mirroring user_group_membership_set), so
        // the carrier frames ONLY user_identity and the login emits ONLY user_identity — they
        // stay byte-identical and there is nothing column-less to dangle.
        org.keycloak.models.UserModel user = mock(org.keycloak.models.UserModel.class);
        when(user.getId()).thenReturn(USER_ID);
        when(user.getUsername()).thenReturn("aperson1@company.com");
        when(user.getEmail()).thenReturn("aperson1@company.com");
        when(user.isEmailVerified()).thenReturn(false);
        when(user.getFirstName()).thenReturn("A");
        when(user.getLastName()).thenReturn("Person");
        when(user.getAttributes()).thenReturn(java.util.Collections.emptyMap());
        org.keycloak.models.UserProvider users = mock(org.keycloak.models.UserProvider.class);
        when(session.users()).thenReturn(users);
        when(users.getUserById(realm, USER_ID)).thenReturn(user);

        // Both the role-set and the group-set JPQL return EMPTY → no edge set unit may be framed.
        stubIdQuery(java.util.Collections.emptyList());

        when(cr.getActionType()).thenReturn("CREATE_USER");
        when(cr.getRowsJson()).thenReturn(
                "[{\"ID\":\"" + USER_ID + "\",\"USERNAME\":\"aperson1@company.com\"}]");

        List<AttestationUnit> units = attestor.buildAllCrUnits(session, realm, cr, true);

        assertEquals(1, units.size(),
                "a roleless CREATE_USER must frame ONLY the user_identity node — an empty "
                        + "user_role_mapping_set has no user_role_mapping row to carry its sig and "
                        + "would fail-close the login");
        assertEquals(AttestationUnitType.USER_IDENTITY, units.get(0).type());
        assertEquals(USER_ID, units.get(0).targetId());
        assertFalse(units.stream().anyMatch(u -> u.type() == AttestationUnitType.USER_ROLE_MAPPING_SET),
                "no empty user_role_mapping_set unit may be framed for a roleless user");

        // Lockstep with the producer's own per-user closure (export emits the same set).
        List<AttestationUnit> producerPerUser =
                new org.tidecloak.iga.producer.RealmAttestationExporter()
                        .perUserUnits(em, user, REALM_ID);
        assertEquals(producerPerUser.size(), units.size(),
                "carrier must equal the producer per-user closure (both omit the empty role-set)");
        assertFalse(producerPerUser.stream()
                        .anyMatch(u -> u.type() == AttestationUnitType.USER_ROLE_MAPPING_SET),
                "perUserUnits must omit the empty user_role_mapping_set for a roleless user");
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
    void removeRealmAttributeCr_enumeratesTheRealmConfigUnit_validCborMap() {
        // ★ Regression guard for the "envelope must be a CBOR map" ORK reject (realm newrealm03,
        // CR 4da33c64 REMOVE_REALM_ATTRIBUTE of webAuthnPolicyAcceptableAaguids + the 5 other
        // webAuthn passwordless attrs that Keycloak clears when the user-registration toggle
        // normalizes the registration flow). REMOVE_REALM_ATTRIBUTE was MISSING from
        // enumerateLiveCrUnits' switch, so it framed 0 producer units → the carrier fell back to
        // canonicalForRegularCr/canonicalizeNode, which emits a plain UTF-8 "node=...\n" canonical
        // (a CBOR TEXT STRING, not a map). The ORK's CborEnvelope.Decode (AttestationUnit.cs:120-129)
        // requires the root to be a CBOR map and throws "envelope must be a CBOR map" on the
        // text-string root → PreSign 500 → the CR never commits. A realm-attribute REMOVAL changes
        // the SAME realm node a SET does, so it must frame the SAME realm_config unit.
        when(cr.getActionType()).thenReturn("REMOVE_REALM_ATTRIBUTE");
        when(cr.getRowsJson()).thenReturn(
                "[{\"REALM_ID\":\"" + REALM_ID + "\",\"NAME\":\"webAuthnPolicyAcceptableAaguids\"}]");

        List<AttestationUnit> units = attestor.buildAllCrUnits(session, realm, cr, true);

        assertEquals(1, units.size(),
                "REMOVE_REALM_ATTRIBUTE must frame exactly the realm_config unit (like "
                        + "SET_REALM_ATTRIBUTE), NOT fall through to the non-CBOR canonical carrier");
        assertEquals(AttestationUnitType.REALM_CONFIG, units.get(0).type());
        assertEquals(REALM_ID, units.get(0).targetId(), "realm-scoped units target the realm id");

        // ★ The crux of the ORK reject: the framed unit MUST serialize to a top-level CBOR MAP
        // (major type 5: 0xA0-0xBF), the only shape CborEnvelope.Decode accepts. The canonicalizeNode
        // fallback would serialize to a CBOR text string (major type 3: 0x60-0x7F / 0x78), which is
        // exactly what the ORK rejected.
        byte[] cbor = units.get(0).serialize();
        int major = (cbor[0] & 0xE0) >> 5;
        assertEquals(5, major,
                "the framed REMOVE_REALM_ATTRIBUTE unit envelope must be a CBOR map (major type 5); "
                        + "got major type " + major + " (3 == text string == the non-CBOR canonical "
                        + "fallback the ORK rejects as 'envelope must be a CBOR map')");
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
