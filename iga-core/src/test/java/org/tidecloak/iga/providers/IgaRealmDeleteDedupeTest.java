package org.tidecloak.iga.providers;

import org.junit.jupiter.api.Test;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * A repeated governed realm delete must answer with the DELETE_REALM change request
 * that is already pending, not file another one.
 */
class IgaRealmDeleteDedupeTest {

    private static final String REALM_ID = "realm-id";

    @Test
    void pendingDeleteRealm_returnsItsId() {
        IgaChangeRequestEntity existing = new IgaChangeRequestEntity();
        existing.setId("existing-cr");
        IgaChangeRequestService service = mock(IgaChangeRequestService.class);
        when(service.findPendingByAction(REALM_ID, "REALM", "DELETE_REALM"))
                .thenReturn(List.of(existing));

        assertEquals("existing-cr", IgaRealmProvider.pendingDeleteRealmCrId(service, REALM_ID));
    }

    @Test
    void nothingPending_returnsNull() {
        IgaChangeRequestService service = mock(IgaChangeRequestService.class);
        when(service.findPendingByAction(REALM_ID, "REALM", "DELETE_REALM")).thenReturn(List.of());

        assertNull(IgaRealmProvider.pendingDeleteRealmCrId(service, REALM_ID));
    }

    @Test
    void otherPendingRealmActions_areNotMistakenForADelete() {
        // The lookup is by action type, so a pending DISABLE_IGA or OFFBOARD_REALM
        // (same entity type and id) never short-circuits a delete.
        IgaChangeRequestService service = mock(IgaChangeRequestService.class);
        when(service.findPendingByAction(REALM_ID, "REALM", "DISABLE_IGA"))
                .thenReturn(List.of(new IgaChangeRequestEntity()));

        assertNull(IgaRealmProvider.pendingDeleteRealmCrId(service, REALM_ID));
    }
}
