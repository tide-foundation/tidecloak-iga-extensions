package org.tidecloak.iga.entities;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for the {@code DEPENDS_ON} dependency-contract storage on
 * {@link IgaChangeRequestEntity}: the comma-separated TEXT column and its
 * list (de)serialization. These are the back-compat / round-trip guarantees the
 * fail-closed commit gate relies on (an existing row backfills to NULL = no
 * prerequisites; a set list parses back identically).
 */
class IgaChangeRequestEntityDependsOnTest {

    @Test
    void defaultDependsOnIsNullAndListIsEmpty() {
        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        // A freshly-constructed CR (and any legacy row backfilled to NULL) has
        // no prerequisites — the commit gate must treat this as "not blocked".
        assertNull(cr.getDependsOn());
        assertTrue(cr.getDependsOnList().isEmpty());
    }

    @Test
    void setDependsOnListRoundTrips() {
        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        List<String> ids = List.of(
                "11111111-1111-1111-1111-111111111111",
                "22222222-2222-2222-2222-222222222222");
        cr.setDependsOnList(ids);
        assertEquals(String.join(",", ids), cr.getDependsOn());
        assertEquals(ids, cr.getDependsOnList());
    }

    @Test
    void setDependsOnListWithNullClearsColumn() {
        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setDependsOnList(List.of("aaaa"));
        cr.setDependsOnList(null);
        assertNull(cr.getDependsOn());
        assertTrue(cr.getDependsOnList().isEmpty());
    }

    @Test
    void setDependsOnListWithEmptyClearsColumn() {
        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setDependsOnList(List.of("aaaa"));
        cr.setDependsOnList(List.of());
        assertNull(cr.getDependsOn());
        assertTrue(cr.getDependsOnList().isEmpty());
    }

    @Test
    void getDependsOnListTrimsAndDropsBlanks() {
        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        // Defensive parse: whitespace and empty segments (e.g. a trailing
        // comma) must not yield phantom prerequisite ids that would wedge the
        // commit gate on a non-existent "MISSING" CR forever.
        cr.setDependsOn(" a , ,b, ");
        assertEquals(List.of("a", "b"), cr.getDependsOnList());
    }

    @Test
    void blankDependsOnYieldsEmptyList() {
        IgaChangeRequestEntity cr = new IgaChangeRequestEntity();
        cr.setDependsOn("   ");
        assertTrue(cr.getDependsOnList().isEmpty());
    }
}
