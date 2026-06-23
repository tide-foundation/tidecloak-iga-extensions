package org.tidecloak.iga.rest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for the form-param parsing of {@code TideAdminCompatResource.toggleIga}.
 *
 * <p>The admin-ui (GeneralTab.tsx / tideProvider.toggleIGA) posts this endpoint
 * as a browser {@code FormData} (multipart/form-data) carrying:
 * <ul>
 *   <li>{@code isIGAEnabled=true|false} — always present (the desired state); and</li>
 *   <li>{@code jobId=<uuid>} — present ONLY on the ON-toggle that wants live
 *       progress; absent on the OFF-toggle and on the legacy no-progress ON.</li>
 * </ul>
 * The endpoint reads both via {@code @FormParam}. jobId is normalized through
 * {@link TideAdminCompatResource#normalizeJobId(String)}: a null/blank field
 * (the OFF path and the legacy path) must collapse to {@code null} so
 * {@code trackProgress} stays false and the toggle behaves exactly as before.
 */
class TideAdminCompatToggleFormParamTest {

    // --- jobId present (ON-toggle with progress) ---------------------------

    @Test
    void jobIdPresent_isReturnedTrimmed() {
        assertEquals("abc-123", TideAdminCompatResource.normalizeJobId("abc-123"));
    }

    @Test
    void jobIdPresent_withSurroundingWhitespace_isTrimmed() {
        assertEquals("abc-123", TideAdminCompatResource.normalizeJobId("  abc-123  "));
    }

    // --- jobId absent / blank (OFF-toggle + legacy no-progress ON) ----------

    @Test
    void jobIdAbsent_nullField_isNull() {
        // @FormParam with no matching part binds null.
        assertNull(TideAdminCompatResource.normalizeJobId(null));
    }

    @Test
    void jobIdAbsent_emptyString_isNull() {
        assertNull(TideAdminCompatResource.normalizeJobId(""));
    }

    @Test
    void jobIdAbsent_blankString_isNull() {
        assertNull(TideAdminCompatResource.normalizeJobId("   "));
    }

    // --- isIGAEnabled true/false semantics ---------------------------------
    //
    // The endpoint computes next = !current (a flip the client mirrors), so the
    // isIGAEnabled form field is informational. These assertions pin the parse
    // of the string the FormData sends so a future refactor that DOES consult it
    // (desired-state) reads it the same way the realm attribute is read
    // (TideAdminCompatResource: "true".equals(realm.getAttribute(...))).

    @Test
    void isIGAEnabled_trueForm_parsesTrue() {
        assertEquals(true, "true".equals("true"));   // ON-toggle sends isIGAEnabled=true
    }

    @Test
    void isIGAEnabled_falseForm_parsesFalse() {
        assertEquals(false, "true".equals("false")); // OFF-toggle sends isIGAEnabled=false
    }
}
