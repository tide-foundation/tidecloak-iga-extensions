package org.tidecloak.iga.attestors;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.connections.jpa.JpaConnectionProvider;
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
 * ★ P4 — coverage for the full-CR unit enumerator {@code TideAttestor.buildAllCrUnits} /
 * {@code buildAllCrUnitCbor} (the single shared descriptor list phase-1 framing and
 * commit-time distribution both run) and the {@link IgaCreateUnitBuilder} routing gate.
 *
 * <p>What is asserted WITHOUT real ORKs / a real session factory:
 * <ul>
 *   <li>An edge-set CR enumerates EXACTLY one unit (the index-0 edge-set unit) and its
 *       serialized CBOR equals the producer's post-change envelope — i.e. the unit the
 *       carrier frames is byte-identical to what the login replays.</li>
 *   <li>{@code buildAllCrUnitCbor} returns the parallel {@code byte[][]} (same order /
 *       length) — the verbatim CBOR {@code SetUnits} frames.</li>
 *   <li>The CREATE_* routing gate {@link IgaCreateUnitBuilder#isFromRepCreateAction} marks
 *       exactly the five from-REP_JSON node creates (so they get a framed node unit) and
 *       nothing else.</li>
 * </ul>
 *
 * <p>The deep byte-identity of the CREATE_* from-REP_JSON node unit (its
 * {@code nodeUnitCborFromRep} bytes == the post-replay stamper bytes for the same REP_JSON)
 * is guaranteed BY CONSTRUCTION — both paths run the SAME
 * {@code IgaReplayDispatcher.rebuildCreate*FromRow} helper into a scratch entity + the SAME
 * {@code RealmAttestationExporter} node builder — and is exercised live in the multiAdmin
 * ceremony; it cannot be unit-tested here because the scratch rebuild needs a real
 * {@code KeycloakSessionFactory} ({@code runJobInTransaction} + {@code RepresentationToModel}).
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TideAttestorBuildAllCrUnitsTest {

    private static final String REALM_ID = "realm-uuid-p4";
    private static final String USER_ID = "user-p4";

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

    @Test
    void edgeSetCr_enumeratesExactlyTheIndex0EdgeUnit_byteIdenticalToProducer() {
        // A GRANT_ROLES CR over a user with pre-set {r-aaa} granting r-zzz.
        stubIdQuery(Arrays.asList("r-aaa"));
        when(cr.getActionType()).thenReturn("GRANT_ROLES");
        when(cr.getEntityId()).thenReturn(USER_ID);
        when(cr.getRowsJson()).thenReturn(
                "[{\"USER_ID\":\"" + USER_ID + "\",\"ROLE_ID\":\"r-zzz\"}]");

        List<AttestationUnit> units = attestor.buildAllCrUnits(session, realm, cr);

        // Exactly ONE unit (the edge-set unit at index 0) — no node/derived framed for an
        // edge action.
        assertEquals(1, units.size(), "an edge-set CR frames exactly its index-0 edge unit");
        AttestationUnit u0 = units.get(0);
        assertEquals(AttestationUnitType.USER_ROLE_MAPPING_SET, u0.type(),
                "index 0 must be the user_role_mapping_set edge unit");
        assertEquals(USER_ID, u0.targetId(), "the edge unit's target is the owner user");

        // Byte-identical to the producer's post-change emission (sorted pre ∪ delta).
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

        List<AttestationUnit> units = attestor.buildAllCrUnits(session, realm, cr);
        byte[][] cbor = attestor.buildAllCrUnitCbor(session, realm, cr);

        assertEquals(units.size(), cbor.length,
                "buildAllCrUnitCbor must be the same length as buildAllCrUnits");
        for (int i = 0; i < units.size(); i++) {
            assertArrayEquals(units.get(i).serialize(), cbor[i],
                    "cbor[" + i + "] must be units.get(" + i + ").serialize() (verbatim, in order)");
        }
    }

    @Test
    void fromRepCreateGate_marksExactlyTheFiveNodeCreates() {
        for (String a : new String[]{"CREATE_USER", "CREATE_ROLE", "CREATE_GROUP",
                "CREATE_CLIENT", "CREATE_CLIENT_SCOPE"}) {
            assertTrue(IgaCreateUnitBuilder.isFromRepCreateAction(a),
                    a + " must be a from-REP_JSON node create (framed at phase-1)");
        }
        // NOT from-REP_JSON: edge actions, SET_*, derived, realm, org-create, null.
        for (String a : new String[]{"GRANT_ROLES", "JOIN_GROUPS", "SET_CLIENT_ATTRIBUTE",
                "ASSIGN_SCOPE", "ADD_PROTOCOL_MAPPER", "SET_REALM_CONFIG",
                "CREATE_ORGANIZATION", null}) {
            assertFalse(IgaCreateUnitBuilder.isFromRepCreateAction(a),
                    a + " must NOT be a from-REP_JSON node create");
        }
    }
}
