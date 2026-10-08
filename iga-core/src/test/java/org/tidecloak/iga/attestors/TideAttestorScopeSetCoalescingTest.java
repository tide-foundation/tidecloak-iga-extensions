package org.tidecloak.iga.attestors;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.tidecloak.iga.entities.IgaAuthorizerEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.producer.units.AttestationUnitType;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import jakarta.persistence.TypedQuery;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The three remaining derived owner-set families, which carried the SAME exposure as the
 * protocol-mapper actions: {@code client_scope_assignment_set} ({@code ASSIGN_SCOPE} /
 * {@code REMOVE_SCOPE}) and {@code scope_role_allowlist_set} for both parent types
 * ({@code SCOPE_MAPPING_ADD} / {@code REMOVE} on a client, {@code SCOPE_ADD_ROLE} /
 * {@code SCOPE_REMOVE_ROLE} on a client scope).
 *
 * <p>Each is an owner-keyed fan-out with no member predicate, so two change requests against
 * one owner in a bulk drain each stamped a signature over pre-set plus their own delta and the
 * second write won. None of them were {@code isProducerEnvelopeSignedAction}, so like the mapper
 * actions they produced a null owner key and were invisible to contested-owner detection and to
 * per-batch coalescing.
 *
 * <p>Unlike the mapper family there is no second gap here: the members of these sets are scopes
 * and roles, which own their own units and are signed by their own change requests. Only the
 * owner-set half applies.
 *
 * <p><b>Harness boundary.</b> As in the sibling coalescing tests: Mockito, no database and no
 * ork, driven at the coalescing seam with the realm's deterministic non-capable stub signature.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TideAttestorScopeSetCoalescingTest {

    private static final String REALM_ID = "realm-uuid-scope-coalesce";
    private static final String REALM_NAME = "scope-coalesce-realm";
    private static final String CLIENT_UUID = "client-uuid-1";
    private static final String SCOPE_ID = "scope-id-1";

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock JpaConnectionProvider jpa;
    @Mock EntityManager em;

    /** owner id -> the attestation stored on the owner's column. */
    private final Map<String, String> column = new HashMap<>();
    /** Every owner a fan-out UPDATE was issued for, in order. */
    private final List<String> stampedOwners = new ArrayList<>();
    /** The scope ids the committed client has assigned as DEFAULT scopes. */
    private final Map<String, ClientScopeModel> assignedScopes = new LinkedHashMap<>();
    /** The role ids the committed container has in its scope mappings. */
    private final List<String> scopeMappingRoleIds = new ArrayList<>();

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
        when(authorizerQuery.getResultStream()).thenAnswer(inv -> Stream.empty());

        wireColumns();
        attestor = new TideAttestor(session);
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
            if (jpql.startsWith("UPDATE ")) {
                when(q.executeUpdate()).thenAnswer(x -> {
                    String owner = (String) params.get("id");
                    stampedOwners.add(owner);
                    column.put(owner, (String) params.get("sig"));
                    return 1;
                });
            } else if (jpql.startsWith("SELECT ")) {
                when(q.getResultList()).thenAnswer(x -> {
                    String stored = column.get((String) params.get("id"));
                    return stored == null ? List.of() : List.of(stored);
                });
            } else {
                when(q.getResultList()).thenAnswer(x -> List.of());
            }
            return q;
        });
    }

    private ClientModel committedClient() {
        ClientModel client = mock(ClientModel.class);
        when(client.getId()).thenReturn(CLIENT_UUID);
        when(client.getClientScopes(anyBoolean())).thenAnswer(inv ->
                Boolean.TRUE.equals(inv.getArgument(0)) ? assignedScopes : Map.of());
        when(client.getScopeMappingsStream()).thenAnswer(inv -> roleStream());
        when(realm.getClientById(eq(CLIENT_UUID))).thenReturn(client);
        return client;
    }

    private ClientScopeModel committedScope() {
        ClientScopeModel scope = mock(ClientScopeModel.class);
        when(scope.getId()).thenReturn(SCOPE_ID);
        when(scope.getScopeMappingsStream()).thenAnswer(inv -> roleStream());
        when(realm.getClientScopeById(eq(SCOPE_ID))).thenReturn(scope);
        return scope;
    }

    private Stream<RoleModel> roleStream() {
        List<RoleModel> roles = new ArrayList<>();
        for (String roleId : scopeMappingRoleIds) {
            RoleModel r = mock(RoleModel.class);
            when(r.getId()).thenReturn(roleId);
            roles.add(r);
        }
        return roles.stream();
    }

    private void assignedScope(String scopeId) {
        ClientScopeModel s = mock(ClientScopeModel.class);
        when(s.getId()).thenReturn(scopeId);
        assignedScopes.put(scopeId, s);
    }

    private IgaChangeRequestEntity cr(String crId, String actionType, String rowsJson) {
        IgaChangeRequestEntity cr = mock(IgaChangeRequestEntity.class);
        when(cr.getId()).thenReturn(crId);
        when(cr.getRealmId()).thenReturn(REALM_ID);
        when(cr.getActionType()).thenReturn(actionType);
        when(cr.getRequestModel()).thenReturn(null);
        when(cr.getRowsJson()).thenReturn(rowsJson);
        return cr;
    }

    private IgaChangeRequestEntity clientCr(String crId, String actionType) {
        return cr(crId, actionType, "[{\"CLIENT_UUID\":\"" + CLIENT_UUID + "\"}]");
    }

    private IgaChangeRequestEntity scopeCr(String crId, String actionType) {
        return cr(crId, actionType, "[{\"SCOPE_ID\":\"" + SCOPE_ID + "\"}]");
    }

    // -------------------------------------------------------------------------

    @Test
    void twoAssignScopeCrsOnOneClient_stampTheOwnerSetExactlyOnce() {
        assignedScope("scope-a");
        assignedScope("scope-b");
        committedClient();

        attestor.stampCoalescedSetUnits(session, realm,
                List.of(clientCr("cr-1", "ASSIGN_SCOPE"), clientCr("cr-2", "ASSIGN_SCOPE")));

        assertEquals(List.of(CLIENT_UUID), stampedOwners,
                "two scope assignments against one client share an owner set, so exactly ONE "
                        + "fan-out must be issued over the post-batch state");
        assertNotNull(column.get(CLIENT_UUID));
    }

    @Test
    void assignScopeCr_yieldsAnOwnerKey() {
        assignedScope("scope-a");
        committedClient();

        String key = attestor.setUnitOwnerKey(session, realm, clientCr("cr-1", "ASSIGN_SCOPE"));

        assertEquals(AttestationUnitType.CLIENT_SCOPE_ASSIGNMENT_SET.wireName() + '|' + CLIENT_UUID,
                key, "ASSIGN_SCOPE perturbs client_scope_assignment_set and must be visible to "
                        + "contested-owner detection");
    }

    @Test
    void scopeMappingCrOnClient_yieldsAnOwnerKeyAndIsContestedWithItsSibling() {
        scopeMappingRoleIds.add("role-a");
        committedClient();
        IgaChangeRequestEntity add = clientCr("cr-1", "SCOPE_MAPPING_ADD");
        IgaChangeRequestEntity remove = clientCr("cr-2", "SCOPE_MAPPING_REMOVE");

        String key = attestor.setUnitOwnerKey(session, realm, add);

        assertEquals(AttestationUnitType.SCOPE_ROLE_ALLOWLIST_SET.wireName() + '|' + CLIENT_UUID,
                key);
        assertEquals(Map.of(key, List.of("cr-1", "cr-2")),
                attestor.findContestedSetOwners(session, realm, List.of(add, remove)),
                "an add and a remove against one client's allowlist contest the same owner set");
    }

    @Test
    void scopeRoleCrOnClientScope_yieldsAnOwnerKeyKeyedOnTheScope() {
        scopeMappingRoleIds.add("role-a");
        committedScope();

        String key = attestor.setUnitOwnerKey(session, realm, scopeCr("cr-1", "SCOPE_ADD_ROLE"));

        assertEquals(AttestationUnitType.SCOPE_ROLE_ALLOWLIST_SET.wireName() + '|' + SCOPE_ID, key,
                "the client_scope parent type keys the same unit type on the SCOPE id, so a "
                        + "client and a scope never collide in one batch");
    }

    @Test
    void clientAndScopeAllowlistCrs_areNotContestedWithEachOther() {
        scopeMappingRoleIds.add("role-a");
        committedClient();
        committedScope();

        assertTrue(attestor.findContestedSetOwners(session, realm, List.of(
                        clientCr("cr-1", "SCOPE_MAPPING_ADD"),
                        scopeCr("cr-2", "SCOPE_ADD_ROLE"))).isEmpty(),
                "same unit type, different owners: not contested");
    }

    @Test
    void unrelatedActionStillYieldsNoOwnerKey() {
        assertEquals(null, attestor.setUnitOwnerKey(session, realm,
                        cr("cr-1", "SET_REALM_ATTRIBUTE", "[{\"KEY\":\"v\"}]")),
                "widening the derived-owner-set predicate must not sweep in actions that "
                        + "perturb no owner set");
    }
}
