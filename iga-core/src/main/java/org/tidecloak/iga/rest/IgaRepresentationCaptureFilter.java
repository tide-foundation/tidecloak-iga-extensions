package org.tidecloak.iga.rest;

import org.keycloak.models.KeycloakSession;

/**
 * <h2>Deprecated capture transport — shim only</h2>
 *
 * This class used to be a JAX-RS {@code @Provider @PreMatching}
 * {@code ContainerRequestFilter}/{@code ContainerResponseFilter} that buffered
 * the admin REST POST body and stashed the raw representation as a
 * {@link KeycloakSession} attribute so the model-layer {@code CREATE_*} capture
 * sites could fold it into the change request as {@code REP_JSON}.
 *
 * <p><b>It never worked in production.</b> Keycloak 26.5.5 loads provider jars
 * through its own {@code ProviderManager} classloader, OUTSIDE the Quarkus
 * application-archive scan that RESTEasy uses to discover {@code @Provider}
 * {@code ContainerRequestFilter}s. The filter was therefore never registered
 * and never invoked (runtime-confirmed: all IGA SPI factories load via
 * {@code KC-SERVICES0047}, the filter absent, the "no pending rep" WARN always
 * firing). Note this is specific to request/response <em>filters</em>:
 * {@code ExceptionMapper} providers (e.g.
 * {@link IgaPendingApprovalExceptionMapper}) ARE discovered, which is why the
 * 202 mapping still works.</p>
 *
 * <p>The CLIENT create path has been migrated to a model-layer
 * accumulate-then-veto: {@code IgaRealmProvider.addClient} now creates the real
 * (scratch) entity and returns {@code IgaClientAdapter} in capture mode, which
 * snapshots the fully-built model into a {@code ClientRepresentation} at the
 * terminal seam {@code IgaClientAdapter#updateClient} (no JAX-RS filter
 * involved). See that class and {@code IgaRealmProvider.addClient}.</p>
 *
 * <p>This shim is intentionally retained (NOT deleted) because the other
 * rep-captured creates — {@code CREATE_USER} ({@code IgaUserProvider}),
 * {@code CREATE_ROLE}/{@code CREATE_GROUP}/{@code CREATE_CLIENT_SCOPE}
 * ({@code IgaRealmProvider}) and Organizations create/update
 * ({@code IgaOrganizationProvider}/{@code IgaOrganizationModel}) — still call
 * {@link #pendingRepJson(KeycloakSession, String)} and reference the
 * {@code TYPE_*} discriminators. Those sites are staged follow-ups (see the
 * report). Keeping the constants and a {@code pendingRepJson} that returns
 * {@code null} preserves their EXACT current behaviour (they already always
 * fell back to a bare create because the filter never ran) with zero behaviour
 * change, and lets them compile until each is migrated to the same model-layer
 * capture mechanism. The dead {@code @Provider}/{@code @PreMatching}
 * filter/response-filter machinery and the body-buffering / session-attribute
 * plumbing have been removed.</p>
 */
public final class IgaRepresentationCaptureFilter {

    private IgaRepresentationCaptureFilter() {
    }

    /** Envelope type discriminators (also the {@code CREATE_*} suffix). */
    public static final String TYPE_USER = "USER";
    public static final String TYPE_ROLE = "ROLE";
    public static final String TYPE_GROUP = "GROUP";
    public static final String TYPE_CLIENT_SCOPE = "CLIENT_SCOPE";
    public static final String TYPE_CLIENT = "CLIENT";
    public static final String TYPE_ORGANIZATION = "ORGANIZATION";

    /**
     * Always returns {@code null}: there is no JAX-RS capture transport any
     * more. This is the HONEST current behaviour for the not-yet-migrated
     * creates (user/role/group/client-scope/organization) — the dead filter
     * never populated a session attribute, so these sites already always took
     * the bare-create safety net. They will be migrated to the model-layer
     * capture seam (as CLIENT was) as staged follow-ups; until then this keeps
     * their behaviour identical and bit-for-bit unchanged.
     *
     * @param session       unused (kept for call-site source compatibility)
     * @param expectedType  one of the {@code TYPE_*} discriminators (unused)
     * @return always {@code null}
     */
    public static String pendingRepJson(KeycloakSession session, String expectedType) {
        return null;
    }
}
