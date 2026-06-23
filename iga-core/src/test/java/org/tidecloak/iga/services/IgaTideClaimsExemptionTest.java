package org.tidecloak.iga.services;

import org.junit.jupiter.api.Test;
import org.keycloak.models.RealmModel;
import org.tidecloak.iga.replay.IgaReplayExtension;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The tide-claims (Tide-identity) client scope must be treated by the ADOPT
 * scan as a hard-pinned system entity → attestation-only ADOPT CR, NEVER a
 * quarantine sidecar. If it were quarantined, IgaClientScopeAdapter
 * .getProtocolMappersStream() would return Stream.empty() until the ADOPT CR
 * committed, STRIPPING the tideuserkey/vuid/t.uho mappers from the login token
 * (ORK Validate → "Tide user key missing from token") AND emptying the
 * producer's client_scope_mapper_set unit (login bytes != signed bytes →
 * replay fail-close).
 *
 * <p>Other operator-authored custom scopes are NOT exempt — they still
 * quarantine under governance.</p>
 */
class IgaTideClaimsExemptionTest {

    private RealmModel realm() {
        RealmModel realm = mock(RealmModel.class);
        lenient().when(realm.getName()).thenReturn("bvnvbncvb");
        return realm;
    }

    @Test
    void tideClaimsScope_isAttestationOnly_neverQuarantined() {
        RealmModel realm = realm();
        // includeSystem=false (default) AND includeSystem=true (hard-pin): both
        // must classify tide-claims as system (attestation-only, no sidecar).
        assertTrue(IgaSystemEntityFilter.shouldSkip(realm,
                        IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE,
                        "any-uuid", IgaSystemEntityFilter.TIDE_CLAIMS_SCOPE_NAME,
                        null, false),
                "tide-claims must be attestation-only (never quarantined) by default");
        assertTrue(IgaSystemEntityFilter.shouldSkip(realm,
                        IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE,
                        "any-uuid", IgaSystemEntityFilter.TIDE_CLAIMS_SCOPE_NAME,
                        null, true),
                "tide-claims exemption is HARD-pinned — not lifted by includeSystem=true");
    }

    @Test
    void tideClaimsOwnedEdges_areAttestationOnly() {
        RealmModel realm = realm();
        // Scope-owned edges (mapper edge, scope->client, scope->role,
        // default-scope) resolve ownerNodeType=CLIENT_SCOPE, ownerNodeName=
        // "tide-claims" → must skip (attestation-only) exactly as the node does.
        assertTrue(IgaSystemEntityFilter.shouldSkipEdge(realm,
                        IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE,
                        IgaSystemEntityFilter.TIDE_CLAIMS_SCOPE_NAME, null, false),
                "edges owned by tide-claims must be attestation-only too");
    }

    @Test
    void otherCustomScope_stillQuarantines() {
        RealmModel realm = realm();
        // An operator-authored custom scope (not a KC default, not tide-claims)
        // is NOT exempt — it falls through and IS quarantined.
        assertFalse(IgaSystemEntityFilter.shouldSkip(realm,
                        IgaReplayExtension.ENTITY_TYPE_CLIENT_SCOPE,
                        "any-uuid", "p6b-scope", null, false),
                "other custom scopes must still be governed (quarantined)");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // tide-admin-console — Tide-realm default client (auto-created at Tide
    // enablement by VendorResource.setupTideAdminConsole). It must be classified
    // by the ADOPT scan exactly like KC's built-in admin/account consoles:
    // system → attestation-only ADOPT CR (marked ATTESTATION_ONLY) → auto-signed
    // by the narrowed firstAdmin auto-commit sweep. A custom/admin-authored
    // client must NOT be classified as system → its ADOPT stays MANUAL.
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    void tideAdminConsoleClient_isSystemDefault_attestationOnly() {
        RealmModel realm = realm();
        // CLIENT entity whose clientId is "tide-admin-console" → soft-skip
        // (system) under default settings → the scan stamps ATTESTATION_ONLY →
        // its ADOPT_CLIENT CR auto-signs under the narrowed firstAdmin scope.
        assertTrue(IgaSystemEntityFilter.shouldSkip(realm,
                        IgaReplayExtension.ENTITY_TYPE_CLIENT,
                        "client-uuid", "tide-admin-console", null, false),
                "tide-admin-console is a Tide-realm default client → system/attestation-only ADOPT");
    }

    @Test
    void tideAdminConsoleClientRoles_softSkipWithParent() {
        RealmModel realm = realm();
        // A client-role under tide-admin-console (parentClientId="tide-admin-console")
        // soft-skips as a unit with its parent client, exactly like roles under
        // realm-management/account.
        assertTrue(IgaSystemEntityFilter.shouldSkip(realm,
                        IgaReplayExtension.ENTITY_TYPE_ROLE,
                        "role-uuid", "some-client-role", "tide-admin-console", false),
                "client-roles under tide-admin-console soft-skip with their parent");
    }

    @Test
    void customClient_isNotSystem_adoptStaysManual() {
        RealmModel realm = realm();
        // An admin-authored client (not a built-in, not tide-admin-console) is
        // NOT system → no ATTESTATION_ONLY marker → its ADOPT_CLIENT stays MANUAL.
        assertFalse(IgaSystemEntityFilter.shouldSkip(realm,
                        IgaReplayExtension.ENTITY_TYPE_CLIENT,
                        "client-uuid", "my-custom-app", null, false),
                "an admin-authored client must NOT be classified system → ADOPT stays manual");
    }
}
