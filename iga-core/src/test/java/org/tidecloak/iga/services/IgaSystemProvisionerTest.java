package org.tidecloak.iga.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientProvider;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.providers.IgaChangeRequestService;
import org.tidecloak.iga.replay.IgaReplayExtension;
import org.tidecloak.iga.services.IgaSystemProvisioner.TideUhoEnqueueResult;
import org.tidecloak.iga.services.IgaSystemProvisioner.TideUhoRemovalResult;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link IgaSystemProvisioner#enqueueTideClaimsScopeProvisioning}.
 *
 * <p>Drives the one-pass enqueue / idempotency / self-heal logic against a
 * MOCKED {@link IgaChangeRequestService} (injected via the package-private seam
 * constructor) and a mocked {@link KeycloakSession}. No live EntityManager —
 * the service's persist/flush/JPQL are out of scope here; we assert the
 * provisioner's filing decisions, the deterministic SCOPE_ID, and the dependsOn
 * wiring.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class IgaSystemProvisionerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String REALM_ID = "realm-uuid-123";
    private static final String SCOPE_NAME = "tide-claims";

    // Deterministic scope id must match IgaSystemProvisioner.deterministicScopeId.
    private static final String DETERMINISTIC_ID =
            UUID.nameUUIDFromBytes(("tide-claims|" + REALM_ID).getBytes(java.nio.charset.StandardCharsets.UTF_8))
                    .toString();

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock ClientProvider clients;
    @Mock IgaChangeRequestService service;

    private IgaSystemProvisioner provisioner;

    /** Records every service.create(...) call so tests can assert on filed CRs. */
    private final List<CreatedCr> created = new ArrayList<>();

    private record CreatedCr(String entityType, String entityId, String actionType,
                             List<Map<String, Object>> rows, List<String> dependsOn) {}

    @BeforeEach
    void setUp() {
        when(realm.getId()).thenReturn(REALM_ID);
        when(session.clients()).thenReturn(clients);
        // parseRows delegates to a real Jackson round-trip so the dedup helpers
        // (rowsReferenceScope) behave exactly as in production.
        lenient().when(service.parseRows(anyString())).thenAnswer(inv -> {
            String json = inv.getArgument(0);
            return MAPPER.readValue(json,
                    new com.fasterxml.jackson.core.type.TypeReference<List<Map<String, Object>>>() {});
        });
        // Capture both create(...) overloads. The 6-arg overload (no dependsOn)
        // maps to an empty list; the 7-arg carries the prerequisite list.
        lenient().when(service.create(any(), anyString(), anyString(), anyString(), any(), anyString()))
                .thenAnswer(inv -> recordCreate(inv.getArgument(1), inv.getArgument(2),
                        inv.getArgument(3), inv.getArgument(4), Collections.emptyList()));
        lenient().when(service.create(any(), anyString(), anyString(), anyString(), any(), anyString(), any()))
                .thenAnswer(inv -> recordCreate(inv.getArgument(1), inv.getArgument(2),
                        inv.getArgument(3), inv.getArgument(4), inv.getArgument(6)));
        provisioner = new IgaSystemProvisioner(session, service);
    }

    @SuppressWarnings("unchecked")
    private IgaChangeRequestEntity recordCreate(String entityType, String entityId, String actionType,
                                                Object rows, Object dependsOn) {
        List<String> deps = dependsOn == null ? Collections.emptyList() : (List<String>) dependsOn;
        created.add(new CreatedCr(entityType, entityId, actionType,
                (List<Map<String, Object>>) rows, deps));
        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setId(UUID.randomUUID().toString());
        cr.setActionType(actionType);
        return cr;
    }

    private ClientScopeRepresentation tideClaimsRep() {
        ClientScopeRepresentation rep = new ClientScopeRepresentation();
        rep.setName(SCOPE_NAME);
        rep.setProtocol("openid-connect");
        ProtocolMapperRepresentation mapper = new ProtocolMapperRepresentation();
        mapper.setName("t.uho");
        mapper.setProtocol("openid-connect");
        mapper.setProtocolMapper("oidc-usermodel-attribute-mapper");
        mapper.setConfig(Map.of("claim.name", "t\\.uho"));
        rep.setProtocolMappers(List.of(mapper));
        return rep;
    }

    private ClientModel mockClient(String uuid, String clientId, boolean hasScope) {
        ClientModel c = mock(ClientModel.class);
        lenient().when(c.getId()).thenReturn(uuid);
        lenient().when(c.getClientId()).thenReturn(clientId);
        if (hasScope) {
            ClientScopeModel s = mock(ClientScopeModel.class);
            lenient().when(s.getId()).thenReturn(DETERMINISTIC_ID);
            lenient().when(c.getClientScopes(true)).thenReturn(Map.of(SCOPE_NAME, s));
            lenient().when(c.getClientScopes(false)).thenReturn(Collections.emptyMap());
        } else {
            lenient().when(c.getClientScopes(true)).thenReturn(Collections.emptyMap());
            lenient().when(c.getClientScopes(false)).thenReturn(Collections.emptyMap());
        }
        return c;
    }

    private CreatedCr only(String actionType) {
        List<CreatedCr> matches = created.stream().filter(c -> c.actionType().equals(actionType)).toList();
        assertEquals(1, matches.size(), "expected exactly one " + actionType + " CR, got " + matches);
        return matches.get(0);
    }

    // ---------------------------------------------------------------------
    // Scope does NOT exist: one-pass files all 3 CR types with dependsOn.
    // ---------------------------------------------------------------------

    @Test
    void onePassFilesAllThreeCrTypesWithDeterministicScopeAndDependsOn() {
        // No scope yet; no pending CRs; two clients lacking the scope.
        when(realm.getClientScopesStream()).thenReturn(Stream.empty());
        when(service.findPending(REALM_ID, IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE, DETERMINISTIC_ID))
                .thenReturn(null);
        when(service.findPendingByAction(anyString(), anyString(), anyString()))
                .thenReturn(Collections.emptyList());
        ClientModel c1 = mockClient("client-uuid-1", "app1", false);
        ClientModel c2 = mockClient("client-uuid-2", "app2", false);
        when(clients.getClientsStream(realm)).thenReturn(Stream.of(c1, c2));

        TideUhoEnqueueResult r =
                provisioner.enqueueTideClaimsScopeProvisioning(realm, tideClaimsRep(), "system");

        // CREATE_CLIENT_SCOPE filed, pinned to the deterministic id.
        CreatedCr create = only("CREATE_CLIENT_SCOPE");
        assertEquals(IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE, create.entityType());
        assertEquals(DETERMINISTIC_ID, create.entityId());
        assertEquals(DETERMINISTIC_ID, create.rows().get(0).get("ID"));
        assertTrue(create.dependsOn().isEmpty(), "the create itself has no prerequisite");
        assertNotNull(r.createScopeCrId);
        assertFalse(r.scopeAlreadyExisted);

        // REALM_DEFAULT_SCOPE_ADD references the deterministic id and depends on create.
        CreatedCr def = only("REALM_DEFAULT_SCOPE_ADD");
        assertEquals(DETERMINISTIC_ID, def.rows().get(0).get("SCOPE_ID"));
        assertEquals(List.of(r.createScopeCrId), def.dependsOn());

        // One ASSIGN_SCOPE per client, each deterministic-id + dependsOn=[create].
        List<CreatedCr> assigns = created.stream()
                .filter(c -> c.actionType().equals("ASSIGN_SCOPE")).toList();
        assertEquals(2, assigns.size());
        for (CreatedCr a : assigns) {
            assertEquals(IgaReplayExtension.ENTITY_TYPE_CLIENT, a.entityType());
            assertEquals(DETERMINISTIC_ID, a.rows().get(0).get("SCOPE_ID"));
            assertEquals(List.of(r.createScopeCrId), a.dependsOn());
        }
        assertEquals(2, r.assignScopeCrIds.size());
    }

    // ---------------------------------------------------------------------
    // Idempotency: second pass with create + dependents already PENDING files
    // nothing new.
    // ---------------------------------------------------------------------

    @Test
    void idempotentWhenCreateAndDependentsAlreadyPending() {
        when(realm.getClientScopesStream()).thenReturn(Stream.empty());

        // CREATE already pending (dedup via findPending by deterministic id).
        IgaChangeRequestEntity pendingCreate = new IgaChangeRequestEntity();
        pendingCreate.setId("pending-create-cr");
        when(service.findPending(REALM_ID, IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE, DETERMINISTIC_ID))
                .thenReturn(pendingCreate);

        // REALM_DEFAULT_SCOPE_ADD already pending for this scope.
        IgaChangeRequestEntity pendingDef = new IgaChangeRequestEntity();
        pendingDef.setRowsJson("[{\"SCOPE_ID\":\"" + DETERMINISTIC_ID + "\"}]");
        when(service.findPendingByAction(REALM_ID, "REALM", "REALM_DEFAULT_SCOPE_ADD"))
                .thenReturn(List.of(pendingDef));

        // ASSIGN_SCOPE already pending for the single client (scope-discriminated).
        IgaChangeRequestEntity pendingAssign = new IgaChangeRequestEntity();
        pendingAssign.setEntityId("client-uuid-1");
        pendingAssign.setRowsJson("[{\"SCOPE_ID\":\"" + DETERMINISTIC_ID + "\"}]");
        when(service.findPendingByAction(REALM_ID, IgaReplayExtension.ENTITY_TYPE_CLIENT, "ASSIGN_SCOPE"))
                .thenReturn(List.of(pendingAssign));

        ClientModel c1 = mockClient("client-uuid-1", "app1", false);
        when(clients.getClientsStream(realm)).thenReturn(Stream.of(c1));

        TideUhoEnqueueResult r =
                provisioner.enqueueTideClaimsScopeProvisioning(realm, tideClaimsRep(), "system");

        // Nothing new filed at all (no duplicate create/default/assign).
        assertTrue(created.isEmpty(), "no new CRs should be filed; got " + created);
        // The reused pending create is surfaced as the prerequisite id (the
        // dependents would block on it), but no NEW create row was filed.
        assertEquals("pending-create-cr", r.createScopeCrId);
        assertNull(r.realmDefaultCrId);
        assertTrue(r.assignScopeCrIds.isEmpty());
    }

    @Test
    void assignScopeDedupIsScopeDiscriminated() {
        // A pending ASSIGN_SCOPE for the client exists but for a DIFFERENT scope
        // — it must NOT suppress filing our tide-claims assign.
        when(realm.getClientScopesStream()).thenReturn(Stream.empty());
        when(service.findPending(REALM_ID, IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE, DETERMINISTIC_ID))
                .thenReturn(null);
        when(service.findPendingByAction(REALM_ID, "REALM", "REALM_DEFAULT_SCOPE_ADD"))
                .thenReturn(Collections.emptyList());
        IgaChangeRequestEntity otherScopeAssign = new IgaChangeRequestEntity();
        otherScopeAssign.setEntityId("client-uuid-1");
        otherScopeAssign.setRowsJson("[{\"SCOPE_ID\":\"some-other-scope\"}]");
        when(service.findPendingByAction(REALM_ID, IgaReplayExtension.ENTITY_TYPE_CLIENT, "ASSIGN_SCOPE"))
                .thenReturn(List.of(otherScopeAssign));
        ClientModel c1 = mockClient("client-uuid-1", "app1", false);
        when(clients.getClientsStream(realm)).thenReturn(Stream.of(c1));

        TideUhoEnqueueResult r =
                provisioner.enqueueTideClaimsScopeProvisioning(realm, tideClaimsRep(), "system");

        assertEquals(1, r.assignScopeCrIds.size(), "unrelated-scope pending assign must not suppress ours");
        CreatedCr assign = only("ASSIGN_SCOPE");
        assertEquals(DETERMINISTIC_ID, assign.rows().get(0).get("SCOPE_ID"));
    }

    // ---------------------------------------------------------------------
    // Self-heal: scope already exists (committed) -> dependents filed with
    // EMPTY dependsOn against the live scope id, no create.
    // ---------------------------------------------------------------------

    @Test
    void selfHealFilesDependentsWithEmptyDependsOnWhenScopeExists() {
        String liveScopeId = "live-scope-uuid";
        ClientScopeModel existing = mock(ClientScopeModel.class);
        when(existing.getName()).thenReturn(SCOPE_NAME);
        lenient().when(existing.getId()).thenReturn(liveScopeId);
        when(realm.getClientScopesStream()).thenReturn(Stream.of(existing));
        // Not yet a realm default.
        when(realm.getDefaultClientScopesStream(true)).thenReturn(Stream.empty());
        when(service.findPendingByAction(anyString(), anyString(), anyString()))
                .thenReturn(Collections.emptyList());
        // One client missing the scope.
        ClientModel c1 = mock(ClientModel.class);
        lenient().when(c1.getId()).thenReturn("client-uuid-1");
        lenient().when(c1.getClientId()).thenReturn("app1");
        lenient().when(c1.getClientScopes(true)).thenReturn(Collections.emptyMap());
        lenient().when(c1.getClientScopes(false)).thenReturn(Collections.emptyMap());
        when(clients.getClientsStream(realm)).thenReturn(Stream.of(c1));

        TideUhoEnqueueResult r =
                provisioner.enqueueTideClaimsScopeProvisioning(realm, tideClaimsRep(), "system");

        // No CREATE_CLIENT_SCOPE filed.
        assertTrue(created.stream().noneMatch(c -> c.actionType().equals("CREATE_CLIENT_SCOPE")));
        assertNull(r.createScopeCrId);
        assertTrue(r.scopeAlreadyExisted);

        // Dependents reference the LIVE scope id with EMPTY dependsOn (prereq met).
        CreatedCr def = only("REALM_DEFAULT_SCOPE_ADD");
        assertEquals(liveScopeId, def.rows().get(0).get("SCOPE_ID"));
        assertTrue(def.dependsOn().isEmpty());
        CreatedCr assign = only("ASSIGN_SCOPE");
        assertEquals(liveScopeId, assign.rows().get(0).get("SCOPE_ID"));
        assertTrue(assign.dependsOn().isEmpty());
    }

    @Test
    void selfHealSkipsClientThatAlreadyHasScopeAndAlreadyDefault() {
        String liveScopeId = DETERMINISTIC_ID;
        ClientScopeModel existing = mock(ClientScopeModel.class);
        when(existing.getName()).thenReturn(SCOPE_NAME);
        lenient().when(existing.getId()).thenReturn(liveScopeId);
        when(realm.getClientScopesStream()).thenReturn(Stream.of(existing));
        // Already a realm default.
        ClientScopeModel defScope = mock(ClientScopeModel.class);
        lenient().when(defScope.getId()).thenReturn(liveScopeId);
        when(realm.getDefaultClientScopesStream(true)).thenReturn(Stream.of(defScope));
        when(service.findPendingByAction(anyString(), anyString(), anyString()))
                .thenReturn(Collections.emptyList());
        // One client that already HAS the scope -> skipped.
        ClientModel c1 = mockClient("client-uuid-1", "app1", true);
        when(clients.getClientsStream(realm)).thenReturn(Stream.of(c1));

        TideUhoEnqueueResult r =
                provisioner.enqueueTideClaimsScopeProvisioning(realm, tideClaimsRep(), "system");

        assertTrue(created.isEmpty(), "fully-provisioned realm files nothing; got " + created);
        assertNull(r.realmDefaultCrId);
        assertTrue(r.assignScopeCrIds.isEmpty());
    }

    // ---------------------------------------------------------------------
    // Governance: enqueue only ever FILES CRs (never authorizes/commits).
    // ---------------------------------------------------------------------

    @Test
    void enqueueNeverAuthorizesOrDenies() {
        when(realm.getClientScopesStream()).thenReturn(Stream.empty());
        when(service.findPending(anyString(), anyString(), anyString())).thenReturn(null);
        when(service.findPendingByAction(anyString(), anyString(), anyString()))
                .thenReturn(Collections.emptyList());
        when(clients.getClientsStream(realm)).thenReturn(Stream.empty());

        provisioner.enqueueTideClaimsScopeProvisioning(realm, tideClaimsRep(), "system");

        // The SPI surface must never auto-approve a system-filed CR — the
        // approver-role + threshold gate at commit time is the only path that
        // applies a change.
        verify(service, never()).authorize(anyString(), anyString(), anyString());
        verify(service, never()).deny(anyString(), anyString());
    }

    // ---------------------------------------------------------------------
    // Input validation.
    // ---------------------------------------------------------------------

    @Test
    void rejectsNullRealmScopeOrName() {
        assertThrows(IllegalArgumentException.class,
                () -> provisioner.enqueueTideClaimsScopeProvisioning(null, tideClaimsRep(), "system"));
        assertThrows(IllegalArgumentException.class,
                () -> provisioner.enqueueTideClaimsScopeProvisioning(realm, null, "system"));
        ClientScopeRepresentation noName = new ClientScopeRepresentation();
        assertThrows(IllegalArgumentException.class,
                () -> provisioner.enqueueTideClaimsScopeProvisioning(realm, noName, "system"));
    }

    // =====================================================================
    // Removal (teardown) — enqueueTideClaimsScopeRemoval
    // =====================================================================

    private ClientScopeModel mockExistingTideClaims(String scopeId) {
        ClientScopeModel existing = mock(ClientScopeModel.class);
        lenient().when(existing.getName()).thenReturn(SCOPE_NAME);
        lenient().when(existing.getId()).thenReturn(scopeId);
        when(realm.getClientScopesStream()).thenReturn(Stream.of(existing));
        return existing;
    }

    // ---------------------------------------------------------------------
    // Scope exists, no pending removal: files ONE DELETE_CLIENT_SCOPE CR
    // (single cascade CR, no dependsOn, keyed on the live scope id).
    // ---------------------------------------------------------------------

    @Test
    void removalFilesSingleDeleteCrWhenScopeExists() {
        String liveScopeId = DETERMINISTIC_ID;
        mockExistingTideClaims(liveScopeId);
        when(service.findPending(REALM_ID, IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE, liveScopeId))
                .thenReturn(null);

        TideUhoRemovalResult r = provisioner.enqueueTideClaimsScopeRemoval(realm, "system");

        // Exactly one DELETE_CLIENT_SCOPE CR, no detach/remove-default CRs.
        CreatedCr del = only("DELETE_CLIENT_SCOPE");
        assertEquals(IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE, del.entityType());
        assertEquals(liveScopeId, del.entityId());
        assertEquals(liveScopeId, del.rows().get(0).get("ID"));
        assertTrue(del.dependsOn().isEmpty(), "the single removal CR has no prerequisite");
        assertEquals(1, created.size(), "exactly one CR filed; got " + created);

        assertNotNull(r.removeScopeCrId);
        assertTrue(r.filed());
        assertFalse(r.scopeAbsent);
        assertFalse(r.removalAlreadyPending);
    }

    // ---------------------------------------------------------------------
    // Scope absent: no-op (nothing to remove).
    // ---------------------------------------------------------------------

    @Test
    void removalNoOpWhenScopeAbsent() {
        when(realm.getClientScopesStream()).thenReturn(Stream.empty());

        TideUhoRemovalResult r = provisioner.enqueueTideClaimsScopeRemoval(realm, "system");

        assertTrue(created.isEmpty(), "no CR should be filed when scope absent; got " + created);
        assertNull(r.removeScopeCrId);
        assertTrue(r.scopeAbsent);
        assertFalse(r.filed());
        // Must never touch findPending when there is no scope to key on.
        verify(service, never()).findPending(anyString(), anyString(), anyString());
    }

    // ---------------------------------------------------------------------
    // Idempotency: a DELETE_CLIENT_SCOPE CR already pending -> no duplicate.
    // ---------------------------------------------------------------------

    @Test
    void removalIdempotentWhenDeleteAlreadyPending() {
        String liveScopeId = DETERMINISTIC_ID;
        mockExistingTideClaims(liveScopeId);

        IgaChangeRequestEntity pendingDelete = new IgaChangeRequestEntity();
        pendingDelete.setId("pending-delete-cr");
        pendingDelete.setActionType("DELETE_CLIENT_SCOPE");
        when(service.findPending(REALM_ID, IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE, liveScopeId))
                .thenReturn(pendingDelete);

        TideUhoRemovalResult r = provisioner.enqueueTideClaimsScopeRemoval(realm, "system");

        assertTrue(created.isEmpty(), "no new CR when a removal is already pending; got " + created);
        assertEquals("pending-delete-cr", r.removeScopeCrId);
        assertTrue(r.removalAlreadyPending);
        assertFalse(r.filed());
    }

    // ---------------------------------------------------------------------
    // A pending CR on the same scope id that is NOT a DELETE must not be
    // mistaken for a pending removal — we still file the delete.
    // ---------------------------------------------------------------------

    @Test
    void removalNotSuppressedByNonDeletePendingCrOnSameScope() {
        String liveScopeId = DETERMINISTIC_ID;
        mockExistingTideClaims(liveScopeId);

        // e.g. a SET_CLIENT_SCOPE_ATTRIBUTE CR pending on the same scope id.
        IgaChangeRequestEntity otherPending = new IgaChangeRequestEntity();
        otherPending.setId("other-cr");
        otherPending.setActionType("SET_CLIENT_SCOPE_ATTRIBUTE");
        when(service.findPending(REALM_ID, IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE, liveScopeId))
                .thenReturn(otherPending);

        TideUhoRemovalResult r = provisioner.enqueueTideClaimsScopeRemoval(realm, "system");

        CreatedCr del = only("DELETE_CLIENT_SCOPE");
        assertEquals(liveScopeId, del.entityId());
        assertTrue(r.filed());
        assertFalse(r.removalAlreadyPending);
    }

    @Test
    void removalRejectsNullRealm() {
        assertThrows(IllegalArgumentException.class,
                () -> provisioner.enqueueTideClaimsScopeRemoval(null, "system"));
    }

    @Test
    void removalNeverAuthorizesOrDenies() {
        mockExistingTideClaims(DETERMINISTIC_ID);
        when(service.findPending(anyString(), anyString(), anyString())).thenReturn(null);

        provisioner.enqueueTideClaimsScopeRemoval(realm, "system");

        verify(service, never()).authorize(anyString(), anyString(), anyString());
        verify(service, never()).deny(anyString(), anyString());
    }
}
