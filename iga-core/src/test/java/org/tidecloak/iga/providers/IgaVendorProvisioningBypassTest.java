package org.tidecloak.iga.providers;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.KeycloakSession;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the scoped vendor/system provisioning capture bypass —
 * {@link IgaChangeRequestService#IGA_VENDOR_PROVISIONING} +
 * {@link IgaChangeRequestService#isVendorProvisioning()}.
 *
 * <p>{@code isVendorProvisioning()} is the single decision every IGA
 * {@code isIgaActive()} chokepoint (realm-config / realm-attribute setters,
 * ASSIGN_SCOPE, CREATE_*, the pending-CR conflict guard) consults to decide
 * whether to SUPPRESS capture (apply directly, no CR, no conflict) for the
 * VendorResource license/keygen provisioning flow. These tests pin its
 * contract:
 * <ul>
 *   <li>SET ({@link Boolean#TRUE}) → bypass active (capture suppressed).</li>
 *   <li>ABSENT → bypass INERT (normal writes stay governed/captured).</li>
 *   <li>Robust to the string {@code "true"} idiom and a null session.</li>
 * </ul>
 * The {@link EntityManager} is irrelevant to this decision (it reads only the
 * session attribute) so it is passed as {@code null}.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class IgaVendorProvisioningBypassTest {

    private IgaChangeRequestService service(KeycloakSession session) {
        return new IgaChangeRequestService(null, session);
    }

    @Test
    void flagKeyConstant_isStable() {
        // The constant is the cross-jar contract idp-extensions' VendorResource
        // references; pin its exact value so a rename can't silently desync the
        // caller's session.setAttribute(...) from the honoring side.
        assertEquals("iga.vendorProvisioning",
                IgaChangeRequestService.IGA_VENDOR_PROVISIONING);
    }

    @Test
    void flagSet_booleanTrue_bypassActive() {
        KeycloakSession session = mock(KeycloakSession.class);
        when(session.getAttribute(IgaChangeRequestService.IGA_VENDOR_PROVISIONING))
                .thenReturn(Boolean.TRUE);
        assertTrue(service(session).isVendorProvisioning(),
                "Boolean.TRUE (the way VendorResource sets it) must activate the bypass");
    }

    @Test
    void flagSet_stringTrue_bypassActive() {
        KeycloakSession session = mock(KeycloakSession.class);
        when(session.getAttribute(IgaChangeRequestService.IGA_VENDOR_PROVISIONING))
                .thenReturn("true");
        assertTrue(service(session).isVendorProvisioning(),
                "string \"true\" (IGA_REPLAY_ACTIVE-style idiom) must also activate the bypass");
    }

    @Test
    void flagAbsent_bypassInert_writesStayGoverned() {
        KeycloakSession session = mock(KeycloakSession.class);
        when(session.getAttribute(IgaChangeRequestService.IGA_VENDOR_PROVISIONING))
                .thenReturn(null);
        assertFalse(service(session).isVendorProvisioning(),
                "absent flag → bypass inert → normal admin writes stay captured/governed");
    }

    @Test
    void flagFalse_bypassInert() {
        KeycloakSession session = mock(KeycloakSession.class);
        when(session.getAttribute(IgaChangeRequestService.IGA_VENDOR_PROVISIONING))
                .thenReturn(Boolean.FALSE);
        assertFalse(service(session).isVendorProvisioning(),
                "an explicit FALSE must not activate the bypass");
        when(session.getAttribute(IgaChangeRequestService.IGA_VENDOR_PROVISIONING))
                .thenReturn("false");
        assertFalse(service(session).isVendorProvisioning(),
                "string \"false\" must not activate the bypass");
    }

    @Test
    void nullSession_bypassInert() {
        assertFalse(service(null).isVendorProvisioning(),
                "a null session must be treated as not-provisioning (inert)");
    }
}
