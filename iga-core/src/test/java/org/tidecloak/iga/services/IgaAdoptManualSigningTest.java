package org.tidecloak.iga.services;

import org.junit.jupiter.api.Test;
import org.keycloak.models.RealmModel;
import org.mockito.ArgumentCaptor;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.entities.IgaUnsignedEntityEntity;
import org.tidecloak.iga.providers.IgaChangeRequestService;
import org.tidecloak.iga.replay.IgaReplayExtension;

import jakarta.persistence.EntityManager;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Manual-signing redesign (2026-06-06): the toggle-on ADOPT scan no longer auto-signs;
 * it creates ADOPT CRs that an admin approves, and the commit-time signer stamps the
 * producer columns at approval. The KC system/infrastructure entities (and the realm
 * node) that fail-closed the uniform login read must now be CR-covered too — as
 * ATTESTATION-ONLY CRs (signed on commit, NEVER quarantined → no IGA_UNSIGNED_ENTITY
 * sidecar row).
 *
 * <p>These tests pin the two contracts that don't need a live DB:</p>
 * <ol>
 *   <li>{@link IgaChangeRequestService#createAdoptRealmCr} emits an ADOPT_REALM / REALM
 *       attestation-only CR and writes NO sidecar row;</li>
 *   <li>the realm-node ADOPT action joins the bootstrap-onramp bypass
 *       ({@link IgaReplayExtension#isAdoptAction}).</li>
 * </ol>
 */
class IgaAdoptManualSigningTest {

    @Test
    void createAdoptRealmCr_emits_attestationOnly_REALM_cr_with_no_sidecar() {
        EntityManager em = mock(EntityManager.class);
        RealmModel realm = mock(RealmModel.class);
        when(realm.getId()).thenReturn("realm-123");

        IgaChangeRequestService svc = new IgaChangeRequestService(em, /*session*/ null);
        String crId = svc.createAdoptRealmCr(realm, "admin-user-id");

        ArgumentCaptor<Object> persisted = ArgumentCaptor.forClass(Object.class);
        verify(em).persist(persisted.capture());
        Object p = persisted.getValue();
        assertTrue(p instanceof IgaChangeRequestEntity,
                "the realm ADOPT must persist exactly the CR entity (no sidecar)");

        IgaChangeRequestEntity cr = (IgaChangeRequestEntity) p;
        assertEquals(IgaReplayExtension.ACTION_ADOPT_REALM, cr.getActionType());
        assertEquals(IgaReplayExtension.ENTITY_TYPE_REALM, cr.getEntityType());
        assertEquals("realm-123", cr.getEntityId());
        assertEquals("PENDING", cr.getStatus());
        assertEquals(cr.getId(), crId);
        assertTrue(cr.getRowsJson().contains("ATTESTATION_ONLY"),
                "rowsJson must carry the attestation-only audit marker");

        // The realm node is NEVER quarantineable — no IGA_UNSIGNED_ENTITY sidecar row
        // may be persisted (a sidecar would fail-close realm reads at quarantine time).
        verify(em, never()).persist(any(IgaUnsignedEntityEntity.class));
    }

    @Test
    void adoptRealm_is_a_bootstrap_onramp_action() {
        // ADOPT_REALM must share the ADOPT_* threshold=1 / no-approver-role bypass so a
        // fresh realm can sign its realm_config + realm_default_groups_set closure without
        // the chicken-and-egg gate deadlock the other node ADOPTs avoid.
        assertTrue(IgaReplayExtension.isAdoptAction(IgaReplayExtension.ACTION_ADOPT_REALM));
        // Sanity: a normal governing action is NOT an ADOPT bypass.
        assertFalse(IgaReplayExtension.isAdoptAction("GRANT_ROLES"));
        assertFalse(IgaReplayExtension.isAdoptAction(null));
    }
}
