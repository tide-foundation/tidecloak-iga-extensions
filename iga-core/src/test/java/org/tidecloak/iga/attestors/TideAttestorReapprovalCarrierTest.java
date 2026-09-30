package org.tidecloak.iga.attestors;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.midgard.models.RequestExtensions.AttestationUnitSignRequest;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.tidecloak.iga.entities.IgaAuthorizationEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Re-approval must not poison the accumulated doken carrier.
 *
 * <p>THE DEFECT: phase 1 hands the 2nd..Nth approver the ACCUMULATED carrier, and the enclave
 * appends its doken onto whatever it is handed. So an admin who approves a second time returns a
 * carrier naming themselves TWICE. Phase 2 used to persist that unconditionally — the approval
 * RECORD was deduped, the carrier write was not. Every ORK then refuses the commit at PreSign with
 * {@code PolicyAuthorizationFlowException: Not all dokens provided are distinct. User repetitions
 * found}, and because the poisoned carrier is now stored the change request can never be committed
 * again: quorum satisfied on paper, permanently stuck.
 *
 * <p>Reachable far beyond the flow that caught it. Re-approving is a SUPPORTED action — it is how
 * the UI re-drives a change request that met quorum while a commit gate refused it. Any refusal
 * (dependency not met, REGEN ordering, the admin quorum floor, a transient ORK error) followed by
 * the documented "hit Authorize again" reproduces it, as does a double-click.
 *
 * <p>The real prevention is upstream in {@code IgaAdminResource}, which no longer sends an admin
 * who has already approved back through the enclave. This is the backstop at the choke point every
 * caller passes through, including scripted ones that post a carrier directly.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TideAttestorReapprovalCarrierTest {

    private static final String CR_ID = "cr-reapproval";
    private static final String ADMIN_ID = "admin-user-id";
    private static final String ADMIN_NAME = "alice";

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock JpaConnectionProvider jpa;
    @Mock EntityManager em;
    @Mock UserModel admin;

    private TideAttestor attestor;

    @BeforeEach
    void setUp() {
        when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa);
        when(jpa.getEntityManager()).thenReturn(em);
        when(admin.getId()).thenReturn(ADMIN_ID);
        when(admin.getUsername()).thenReturn(ADMIN_NAME);
        attestor = new TideAttestor(session);
    }

    /**
     * A real, parseable carrier — phase 2 validates via {@code ModelRequest.FromBytes} before it
     * decides anything, so a placeholder string would fail for the wrong reason. {@code marker}
     * distinguishes the stored carrier from the returned one.
     */
    private static String carrier(String marker) {
        AttestationUnitSignRequest req = new AttestationUnitSignRequest("Policy:1");
        req.SetUnits(new byte[][]{ marker.getBytes(StandardCharsets.UTF_8) });
        req.SetPolicy("admin-policy-bytes".getBytes(StandardCharsets.UTF_8));
        try {
            // Materialize Draft before Encode(), as the phase-1 build does. GetDraft is the only
            // checked-throwing call here; wrapped so the five callers stay throws-free like the
            // other helpers. A failure is broken scaffolding, not a failed assertion.
            req.GetDraft();
        } catch (Exception e) {
            throw new IllegalStateException("could not build the test carrier fixture", e);
        }
        return Base64.getEncoder().encodeToString(req.Encode());
    }

    private IgaChangeRequestEntity crWithCarrier(String storedCarrier) {
        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setId(CR_ID);
        cr.setStatus("PENDING");
        cr.setActionType("GRANT_ROLES");
        cr.setEntityType("USER");
        cr.setRequestModel(storedCarrier);
        return cr;
    }

    /** This admin already has a recorded approval for the CR. */
    @SuppressWarnings("unchecked")
    private void stubExistingApprovalByThisAdmin() {
        IgaAuthorizationEntity existing = new IgaAuthorizationEntity();
        existing.setId("auth-1");
        existing.setAuthorizedBy(ADMIN_ID);
        existing.setApproval(ADMIN_NAME);
        TypedQuery<IgaAuthorizationEntity> q = mock(TypedQuery.class);
        when(em.createNamedQuery(eq("IgaAuthorization.findByChangeRequest"),
                eq(IgaAuthorizationEntity.class))).thenReturn(q);
        when(q.setParameter(anyString(), any())).thenReturn(q);
        when(q.getResultList()).thenReturn(List.of(existing));
    }

    // ---------------------------------------------------------------------

    @Test
    void reapprovalAfterARefusedCommitDoesNotPoisonTheCarrier() {
        // The exact live sequence: alice approves (carrier stored, approval recorded), the commit
        // gate refuses, alice hits Authorize again and her enclave hands back a carrier that now
        // holds her doken twice. The stored carrier must survive untouched.
        String stored = carrier("first-approval-carrier");
        String returnedWithDuplicateDoken = carrier("second-approval-carrier-same-admin");
        IgaChangeRequestEntity cr = crWithCarrier(stored);
        stubExistingApprovalByThisAdmin();

        boolean recorded = attestor.acceptMultiAdminApprovalModel(
                session, realm, cr, returnedWithDuplicateDoken, admin);

        assertFalse(recorded, "a repeat approval by the same admin records nothing");
        assertEquals(stored, cr.getRequestModel(),
                "the stored carrier must be KEPT — saving the returned one would carry this admin "
                        + "twice and the ORKs would refuse the commit forever");
    }

    @Test
    void repeatedReapprovalsNeverDisplaceTheStoredCarrier() {
        // Idempotent under retry: a UI that retries on a 500, or an admin clicking twice, must not
        // eventually win. Every attempt leaves the same stored carrier.
        String stored = carrier("first-approval-carrier");
        IgaChangeRequestEntity cr = crWithCarrier(stored);
        stubExistingApprovalByThisAdmin();

        for (int attempt = 0; attempt < 3; attempt++) {
            assertFalse(attestor.acceptMultiAdminApprovalModel(
                    session, realm, cr, carrier("retry-" + attempt), admin));
            assertEquals(stored, cr.getRequestModel(),
                    "attempt " + attempt + " must leave the stored carrier untouched");
        }
    }

    @Test
    void anAlreadyApprovedAdminStillRepairsAChangeRequestThatHasNoCarrier() {
        // The one case the pre-existing unconditional write was genuinely protecting, preserved.
        // An approval row with NO stored carrier cannot commit either: this admin's doken is the
        // only copy, so it is accepted. There is nothing to duplicate, so there is nothing to poison.
        String returned = carrier("repair-carrier");
        IgaChangeRequestEntity cr = crWithCarrier(null);
        stubExistingApprovalByThisAdmin();

        boolean recorded = attestor.acceptMultiAdminApprovalModel(session, realm, cr, returned, admin);

        assertFalse(recorded, "still no NEW approval recorded — the dedup is unchanged");
        assertEquals(returned, cr.getRequestModel(),
                "a change request holding an approval but no carrier accepts this admin's carrier");
    }

    @Test
    void aBlankCarrierIsTreatedAsNoCarrier() {
        String returned = carrier("repair-carrier");
        IgaChangeRequestEntity cr = crWithCarrier("   ");
        stubExistingApprovalByThisAdmin();

        attestor.acceptMultiAdminApprovalModel(session, realm, cr, returned, admin);

        assertEquals(returned, cr.getRequestModel());
    }

    @Test
    void theAdminIsMatchedByIdEvenWhenTheUsernameDiffers() {
        // IgaAuthorizationEntity carries both, and either may be the populated one. Matching on
        // only one of them would let a duplicate through under the other.
        String stored = carrier("first-approval-carrier");
        IgaChangeRequestEntity cr = crWithCarrier(stored);
        IgaAuthorizationEntity existing = new IgaAuthorizationEntity();
        existing.setId("auth-1");
        existing.setAuthorizedBy(ADMIN_ID);
        existing.setApproval("a-different-recorded-name");
        @SuppressWarnings("unchecked")
        TypedQuery<IgaAuthorizationEntity> q = mock(TypedQuery.class);
        when(em.createNamedQuery(eq("IgaAuthorization.findByChangeRequest"),
                eq(IgaAuthorizationEntity.class))).thenReturn(q);
        when(q.setParameter(anyString(), any())).thenReturn(q);
        when(q.getResultList()).thenReturn(List.of(existing));

        boolean recorded = attestor.acceptMultiAdminApprovalModel(
                session, realm, cr, carrier("second-approval"), admin);

        assertFalse(recorded, "matched on user id, so this is still the same admin");
        assertEquals(stored, cr.getRequestModel());
    }
}
