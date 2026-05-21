package org.tidecloak.iga.rest;

import jakarta.enterprise.inject.Vetoed;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.tidecloak.iga.entities.IgaAuthorizationEntity;
import org.tidecloak.iga.entities.IgaAuthorizerEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.entities.IgaCommentEntity;
import org.tidecloak.iga.entities.IgaForsetiContractEntity;
import org.tidecloak.iga.entities.IgaLicenseHistoryEntity;
import org.tidecloak.iga.entities.IgaLicensingDraftEntity;
import org.tidecloak.iga.entities.IgaRolePolicyEntity;
import org.tidecloak.iga.entities.IgaServerCertDraftEntity;
import org.tidecloak.iga.providers.IgaAuthorizerService;
import org.tidecloak.iga.providers.IgaChangeRequestService;
import org.tidecloak.iga.providers.IgaConflictException;
import org.tidecloak.iga.providers.IgaFirstAdminSignPreviewService;
import org.tidecloak.iga.providers.IgaForsetiContractService;
import org.tidecloak.iga.providers.IgaLicenseHistoryService;
import org.tidecloak.iga.providers.IgaLicensingDraftService;
import org.tidecloak.iga.providers.IgaRolePolicyService;
import org.tidecloak.iga.providers.IgaServerCertDraftService;
import org.tidecloak.iga.replay.EntityVanishedException;
import org.tidecloak.iga.replay.IgaReplayDispatcher;
import org.tidecloak.iga.replay.IgaReplayExtension;
import org.tidecloak.iga.attestors.IgaAttestor;
import org.tidecloak.iga.attestors.IgaAttestors;
import org.tidecloak.iga.attestors.IgaScopeResolver;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * JAX-RS resource at path "iga" providing change request approval workflow endpoints.
 */
@Path("iga")
@Vetoed
public class IgaAdminResource {

    private static final Logger log = Logger.getLogger(IgaAdminResource.class);

    private final KeycloakSession session;
    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;

    public IgaAdminResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth) {
        this.session = session;
        this.realm = realm;
        this.auth = auth;
    }

    private EntityManager getEm() {
        return session.getProvider(JpaConnectionProvider.class).getEntityManager();
    }

    private IgaChangeRequestService getService() {
        return new IgaChangeRequestService(getEm(), session);
    }

    private IgaAuthorizerService getAuthorizerService() {
        return new IgaAuthorizerService(getEm());
    }

    private IgaRolePolicyService getRolePolicyService() {
        return new IgaRolePolicyService(getEm());
    }

    private IgaForsetiContractService getForsetiContractService() {
        return new IgaForsetiContractService(getEm());
    }

    private IgaServerCertDraftService getServerCertDraftService() {
        return new IgaServerCertDraftService(getEm(), getService());
    }

    private IgaLicensingDraftService getLicensingDraftService() {
        return new IgaLicensingDraftService(getEm(), getService());
    }

    private IgaLicenseHistoryService getLicenseHistoryService() {
        return new IgaLicenseHistoryService(getEm());
    }

    private IgaFirstAdminSignPreviewService getFirstAdminSignPreviewService() {
        return new IgaFirstAdminSignPreviewService(
                getEm(),
                session,
                realm,
                getService(),
                getRolePolicyService(),
                getAuthorizerService(),
                getForsetiContractService());
    }

    private String currentUserId() {
        try {
            if (auth != null && auth.adminAuth() != null && auth.adminAuth().getUser() != null) {
                return auth.adminAuth().getUser().getId();
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private UserModel currentUser() {
        try {
            if (auth != null && auth.adminAuth() != null) {
                return auth.adminAuth().getUser();
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    /**
     * True iff the action type is one of the five ADOPT_* variants owned by
     * the Phase 6+ extension router. ADOPT actions are uniquely resumable
     * from the CANCELLED terminal status because (a) the underlying entity
     * row was never modified (capture-then-veto's whole point is the entity
     * already exists), (b) the entity's attestation column is still NULL
     * after a toggle-off cancel, and (c) the operator may still want to
     * complete the adoption on a subsequent admin pass.
     */
    private static boolean isAdoptAction(String actionType) {
        // Delegate to the canonical predicate in IgaReplayExtension so the
        // five ADOPT_* strings live in exactly one place.
        return IgaReplayExtension.isAdoptAction(actionType);
    }

    // -------------------------------------------------------------------------
    // GET /iga/change-requests
    // -------------------------------------------------------------------------

    @GET
    @Path("change-requests")
    @Produces(MediaType.APPLICATION_JSON)
    public List<IgaChangeRequestRepresentation> listChangeRequests(
            @QueryParam("status") String status) {

        auth.realm().requireManageRealm();

        String effectiveStatus = (status != null && !status.isBlank()) ? status : "PENDING";
        EntityManager em = getEm();

        TypedQuery<IgaChangeRequestEntity> query = em.createNamedQuery(
                "IgaChangeRequest.findPendingByRealm", IgaChangeRequestEntity.class);
        query.setParameter("realmId", realm.getId());

        List<IgaChangeRequestEntity> results;
        if ("PENDING".equals(effectiveStatus)) {
            results = query.getResultList();
        } else {
            // For non-PENDING statuses fall back to a simple JPQL query
            results = em.createQuery(
                    "SELECT cr FROM IgaChangeRequestEntity cr WHERE cr.realmId = :realmId AND cr.status = :status ORDER BY cr.createdAt DESC",
                    IgaChangeRequestEntity.class)
                    .setParameter("realmId", realm.getId())
                    .setParameter("status", effectiveStatus)
                    .getResultList();
        }

        IgaChangeRequestService service = getService();
        return results.stream()
                .map(cr -> toRepresentation(cr, service))
                .collect(Collectors.toList());
    }

    // -------------------------------------------------------------------------
    // GET /iga/change-requests/{id}
    // -------------------------------------------------------------------------

    @GET
    @Path("change-requests/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getChangeRequest(@PathParam("id") String id) {
        auth.realm().requireManageRealm();

        EntityManager em = getEm();
        IgaChangeRequestEntity cr = em.find(IgaChangeRequestEntity.class, id);
        if (cr == null || !realm.getId().equals(cr.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        return Response.ok(toRepresentation(cr, getService())).build();
    }

    // -------------------------------------------------------------------------
    // POST /iga/change-requests/{id}/authorize
    // -------------------------------------------------------------------------

    @POST
    @Path("change-requests/{id}/authorize")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response authorize(@PathParam("id") String id, Map<String, Object> body) {
        auth.realm().requireManageRealm();

        EntityManager em = getEm();
        IgaChangeRequestEntity cr = em.find(IgaChangeRequestEntity.class, id);
        if (cr == null || !realm.getId().equals(cr.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        // ADOPT_* CRs are resumable from the CANCELLED terminal status: the
        // Phase 6d toggle-off cancel marks every still-PENDING ADOPT as
        // CANCELLED so the realm can flip OFF cleanly, but the entity row
        // is left untouched (attestation still NULL) and the operator may
        // still want to complete the adoption on a subsequent admin pass.
        // For ADOPT_* we therefore accept CANCELLED as authorize-input and
        // promote it back to PENDING here; the per-admin auth record is
        // accumulated normally, and the commit handler's replayAdopt tail
        // flips to APPROVED. All other action types (CREATE_*/UPDATE_*/etc.)
        // remain strictly PENDING-only — CANCELLED for those is genuinely
        // terminal because the captured entity-create has been rolled back.
        boolean isAdoptResume = isAdoptAction(cr.getActionType())
                && "CANCELLED".equals(cr.getStatus());
        if (isAdoptResume) {
            cr.setStatus("PENDING");
            cr.setResolvedAt(null);
            log.infof("IGA ADOPT authorize: resuming CANCELLED CR %s (action=%s entity=%s/%s) — flipping back to PENDING",
                    cr.getId(), cr.getActionType(), cr.getEntityType(), cr.getEntityId());
        }
        if (!"PENDING".equals(cr.getStatus())) {
            return Response.status(Response.Status.CONFLICT)
                    .entity(Map.of("error", "Change request is not in PENDING state"))
                    .build();
        }

        String partialSig = body != null ? (String) body.get("partialSig") : null;

        UserModel admin = currentUser();
        if (admin == null) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(Map.of("error", "No authenticated admin user"))
                    .build();
        }

        // Reject a duplicate signature from the same admin (SimpleNameAttestor
        // stores the admin's username in PARTIAL_SIG — see SimpleNameAttestor.record).
        List<IgaAuthorizationEntity> existing = em.createNamedQuery(
                        "IgaAuthorization.findByChangeRequest", IgaAuthorizationEntity.class)
                .setParameter("changeRequestId", cr.getId())
                .getResultList();
        for (IgaAuthorizationEntity a : existing) {
            if (admin.getUsername() != null && admin.getUsername().equals(a.getPartialSig())) {
                return Response.status(Response.Status.CONFLICT)
                        .entity(Map.of("error",
                                "Caller has already signed this change request"))
                        .build();
            }
            if (admin.getId() != null && admin.getId().equals(a.getAuthorizedBy())) {
                return Response.status(Response.Status.CONFLICT)
                        .entity(Map.of("error",
                                "Caller has already signed this change request"))
                        .build();
            }
        }

        IgaAttestor attestor = IgaAttestors.resolveAttestor(session, realm);
        // record() also enforces IgaScopeResolver.requireApprover() internally.
        attestor.record(session, cr, admin, partialSig);

        // NOTE: Even when authCount >= threshold we DO NOT invoke combineFinal()
        // or IgaReplayDispatcher.replay() here. Commit is now an explicit step
        // via POST /iga/change-requests/{id}/commit.

        IgaChangeRequestService service = getService();
        IgaChangeRequestEntity updated = em.find(IgaChangeRequestEntity.class, id);
        return Response.ok(toRepresentation(updated, service)).build();
    }

    // -------------------------------------------------------------------------
    // POST /iga/change-requests/{id}/commit
    // -------------------------------------------------------------------------

    @POST
    @Path("change-requests/{id}/commit")
    @Produces(MediaType.APPLICATION_JSON)
    public Response commit(@PathParam("id") String id) {
        auth.realm().requireManageRealm();

        EntityManager em = getEm();
        IgaChangeRequestEntity cr = em.find(IgaChangeRequestEntity.class, id);
        if (cr == null || !realm.getId().equals(cr.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        // ADOPT_* CRs are resumable from CANCELLED — see authorize() for the
        // semantic justification. We mirror the same lane here so a commit
        // call (e.g. after a separate authorize that already resumed) or a
        // commit-only call (threshold=0/auto-authorize) lands the ADOPT.
        boolean isAdoptResume = isAdoptAction(cr.getActionType())
                && "CANCELLED".equals(cr.getStatus());
        if (isAdoptResume) {
            cr.setStatus("PENDING");
            cr.setResolvedAt(null);
            log.infof("IGA ADOPT commit: resuming CANCELLED CR %s (action=%s entity=%s/%s) — flipping back to PENDING for replay",
                    cr.getId(), cr.getActionType(), cr.getEntityType(), cr.getEntityId());
        }
        if (!"PENDING".equals(cr.getStatus())) {
            return Response.status(Response.Status.CONFLICT)
                    .entity(Map.of("error",
                            "Change request is not in PENDING state (current=" + cr.getStatus() + ")"))
                    .build();
        }

        UserModel admin = currentUser();
        if (admin == null) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(Map.of("error", "No authenticated admin user"))
                    .build();
        }

        // Same approver-role gate the authorize path uses (via SimpleNameAttestor.record).
        // ADOPT_* CRs short-circuit inside requireApprover (system-bootstrap
        // bypass) so a single manage-realm signature commits them.
        IgaScopeResolver.ResolvedScope scope = IgaScopeResolver.resolve(session, realm, cr);
        IgaScopeResolver.requireApprover(session, realm, admin, scope, cr);

        IgaAttestor attestor = IgaAttestors.resolveAttestor(session, realm);
        List<IgaAuthorizationEntity> all = em.createNamedQuery(
                        "IgaAuthorization.findByChangeRequest", IgaAuthorizationEntity.class)
                .setParameter("changeRequestId", cr.getId())
                .getResultList();
        int threshold = attestor.getThreshold(session, realm, cr);
        if (all.size() < threshold) {
            int needed = threshold - all.size();
            return Response.status(Response.Status.PRECONDITION_FAILED)
                    .entity(Map.of(
                            "error", "Need " + needed + " more signature" + (needed == 1 ? "" : "s"),
                            "threshold", threshold,
                            "authCount", all.size()))
                    .build();
        }

        String finalAttestation = attestor.combineFinal(session, cr, all);
        // Phase 6+ ADOPT_* actions are handled by the extension router; every
        // other action type falls through to the dispatcher (whose tail also
        // sets status=APPROVED + resolvedAt on the managed CR — same as the
        // extension does).
        //
        // EntityVanishedException is the typed signal raised by the ADOPT
        // existence check when the underlying USER/ROLE/GROUP/CLIENT/
        // CLIENT_SCOPE was deleted out-of-band between ADOPT-create and
        // ADOPT-commit. We catch it here (BEFORE the CR-status flip ever
        // happens in the extension's tail) and translate to a structured
        // 404 ENTITY_VANISHED with one INFO log line — rather than letting it
        // bubble through KC's generic uncaught-exception handler, which would
        // emit a full stack at ERROR severity and a generic 500 unknown_error.
        // The CR remains PENDING (the flip never executed; JPA tx rolls back).
        try {
            if (!IgaReplayExtension.tryReplay(session, cr, finalAttestation)) {
                IgaReplayDispatcher.replay(session, cr, finalAttestation);
            }
        } catch (EntityVanishedException ev) {
            log.infof("IGA ADOPT commit refused: entity %s/%s no longer exists in realm %s (CR %s) — returning 404 ENTITY_VANISHED",
                    ev.getEntityType(), ev.getEntityId(), ev.getRealmId(), cr.getId());
            return Response.status(Response.Status.NOT_FOUND)
                    .entity(Map.of(
                            "error", "ENTITY_VANISHED",
                            "entityType", ev.getEntityType(),
                            "entityId", ev.getEntityId(),
                            "realmId", ev.getRealmId()))
                    .build();
        }
        IgaChangeRequestService service = getService();
        IgaChangeRequestEntity updated = em.find(IgaChangeRequestEntity.class, id);
        return Response.ok(toRepresentation(updated, service)).build();
    }

    // -------------------------------------------------------------------------
    // POST /iga/change-requests/bulk-authorize  — Phase 6e
    //
    // Operator one-shot to drain large PENDING ADOPT_* (or any other action)
    // queues. The body selects CRs by action-type list and an optional
    // createdAt upper-bound; the loop reuses the SAME per-CR
    // authorize+commit gate the per-CR endpoints use, so:
    //   - ADOPT_*  → threshold=1, approver-role bypass (system-bootstrap
    //                short-circuit inside IgaScopeResolver.requireApprover /
    //                resolveThreshold via the action-type-aware overloads).
    //   - CREATE_* / UPDATE_* / etc. → full threshold + approver-role gate.
    //     A caller without the required role will see that CR rejected in
    //     the results array; the bulk response is still HTTP 200 because the
    //     bulk endpoint itself succeeded — see the rejected[] entries.
    //
    // The endpoint is idempotent: a CR observed PENDING at filter time but
    // committed/denied/cancelled by another caller mid-bulk is detected as
    // non-PENDING in the per-CR re-fetch and surfaces in skipped[].
    //
    // Concurrency: per-realm cluster-safe mutex via {@link IgaBulkLock},
    // which delegates to KC's canonical
    // ClusterProvider.executeIfNotExecuted(...) primitive. Two simultaneous
    // bulk calls against the same realm — whether they land on the same
    // JVM or different cluster nodes — race the same Infinispan-backed
    // lock; the loser gets 429. The per-CR gate inside the loop is still
    // the real correctness floor (idempotent: a CR already-resolved by a
    // concurrent caller is detected as non-PENDING and skipped — see
    // processOneCr below).
    //
    // Response is buffered JSON (option b in the Phase 6 brief). Streaming
    // (option a) was rejected because (1) KC's JAX-RS stack has no
    // ergonomic incremental-array primitive, (2) the hard cap of 1000
    // bounds the response size, and (3) the summary block at the tail
    // requires the totals — buffered preserves a single read pass for the
    // caller.
    // -------------------------------------------------------------------------

    /** Default cap when no {@code limit} is supplied in the body. */
    private static final int BULK_DEFAULT_LIMIT = 100;
    /** Hard upper-bound on per-call {@code limit}. */
    private static final int BULK_MAX_LIMIT = 1000;

    @POST
    @Path("change-requests/bulk-authorize")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @SuppressWarnings("unchecked")
    public Response bulkAuthorize(Map<String, Object> body) {
        auth.realm().requireManageRealm();

        // -- Body / limit validation ------------------------------------------
        if (body == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "Missing JSON body"))
                    .build();
        }
        Object actionTypeInObj = body.get("actionTypeIn");
        if (!(actionTypeInObj instanceof List<?>) || ((List<?>) actionTypeInObj).isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error",
                            "actionTypeIn is required and must be a non-empty list of action-type strings"))
                    .build();
        }
        List<String> actionTypes = new ArrayList<>();
        for (Object o : (List<Object>) actionTypeInObj) {
            if (o == null) continue;
            String s = o.toString();
            if (!s.isBlank()) actionTypes.add(s);
        }
        if (actionTypes.isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error",
                            "actionTypeIn must contain at least one non-blank action-type string"))
                    .build();
        }

        Long olderThan = null;
        Object olderThanObj = body.get("olderThan");
        if (olderThanObj instanceof Number) {
            olderThan = ((Number) olderThanObj).longValue();
        } else if (olderThanObj instanceof String && !((String) olderThanObj).isBlank()) {
            try {
                olderThan = Long.parseLong((String) olderThanObj);
            } catch (NumberFormatException nfe) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(Map.of("error",
                                "olderThan must be a numeric epoch-millis value"))
                        .build();
            }
        }

        int limit = BULK_DEFAULT_LIMIT;
        Object limitObj = body.get("limit");
        if (limitObj instanceof Number) {
            limit = ((Number) limitObj).intValue();
        } else if (limitObj instanceof String && !((String) limitObj).isBlank()) {
            try {
                limit = Integer.parseInt((String) limitObj);
            } catch (NumberFormatException nfe) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(Map.of("error", "limit must be an integer"))
                        .build();
            }
        }
        if (limit <= 0) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "limit must be > 0"))
                    .build();
        }
        if (limit > BULK_MAX_LIMIT) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error",
                            "limit must be <= " + BULK_MAX_LIMIT + " (got " + limit + ")",
                            "maxLimit", BULK_MAX_LIMIT))
                    .build();
        }

        UserModel admin = currentUser();
        if (admin == null) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(Map.of("error", "No authenticated admin user"))
                    .build();
        }

        // -- Per-realm cluster-safe concurrency lock --------------------------
        // Wrap the whole bulk loop in ClusterProvider.executeIfNotExecuted via
        // IgaBulkLock. If another node (or another in-flight call on this
        // node) already holds the lock for this realm, the wrapper returns
        // notHeld and we respond 429. Lock auto-expires after
        // BULK_LOCK_TIMEOUT_SECONDS in case the holder crashes — see
        // IgaBulkLock for the timeout justification.
        final int finalLimit = limit;
        final Long finalOlderThan = olderThan;
        final List<String> finalActionTypes = actionTypes;
        final UserModel finalAdmin = admin;

        IgaBulkLock.Result<Map<String, Object>> lockResult = IgaBulkLock.runIfNotRunning(
                session,
                realm.getId(),
                () -> {
                    long startedAt = System.currentTimeMillis();
                    List<Map<String, Object>> results = new ArrayList<>();
                    long committed = 0;
                    long rejected = 0;
                    long skipped = 0;

                    IgaChangeRequestService service = getService();
                    List<IgaChangeRequestEntity> candidates =
                            service.listPendingByActionTypeIn(realm.getId(), finalActionTypes, finalOlderThan, finalLimit);

                    for (IgaChangeRequestEntity candidate : candidates) {
                        String crId = candidate.getId();
                        Map<String, Object> outcome = processOneCr(crId, finalAdmin);
                        results.add(outcome);
                        String status = String.valueOf(outcome.get("status"));
                        if ("COMMITTED".equals(status)) committed++;
                        else if ("REJECTED".equals(status)) rejected++;
                        else skipped++;
                    }

                    Map<String, Object> summary = new LinkedHashMap<>();
                    summary.put("total", results.size());
                    summary.put("committed", committed);
                    summary.put("rejected", rejected);
                    summary.put("skipped", skipped);
                    summary.put("durationMs", System.currentTimeMillis() - startedAt);
                    summary.put("limit", finalLimit);
                    summary.put("defaultLimit", BULK_DEFAULT_LIMIT);
                    summary.put("maxLimit", BULK_MAX_LIMIT);

                    Map<String, Object> response = new LinkedHashMap<>();
                    response.put("results", results);
                    response.put("summary", summary);
                    return response;
                });

        if (!lockResult.isHeld()) {
            // Preserve the existing 429 response shape so the existing
            // phase6e-bulk-authorize.spec.ts "concurrent bulk lock" case
            // (regex /already running/i + realm name) still passes — the
            // underlying lock is now cluster-safe (executeIfNotExecuted),
            // see IgaBulkLock.
            return Response.status(429)
                    .entity(Map.of("error",
                            "Another bulk-authorize is already running for this realm",
                            "realm", realm.getName()))
                    .build();
        }

        return Response.ok(lockResult.getValue()).build();
    }

    /**
     * Authorize + commit a single CR on behalf of {@code admin}, returning a
     * per-CR outcome record for the bulk response. NEVER throws — every
     * exception is converted into a {@code REJECTED} or {@code SKIPPED}
     * outcome with a stable error code so the caller can post-process the
     * whole array uniformly.
     *
     * <p>Status values:
     * <ul>
     *   <li>{@code COMMITTED} — CR replayed and now APPROVED.</li>
     *   <li>{@code REJECTED} — the per-CR gate refused this CR (missing
     *       signature, threshold not met, approver-role missing, vanished
     *       entity, dispatcher error, etc.). Error code in {@code error}.</li>
     *   <li>{@code SKIPPED} — CR existed at filter time but was no longer
     *       PENDING by the time we re-fetched it (concurrent
     *       commit/deny/cancel).</li>
     * </ul>
     *
     * <p>The body intentionally mirrors the per-CR endpoint flow rather than
     * extracting a private helper from authorize/commit: the per-CR endpoints
     * have HTTP-shaped early-returns (404/409/etc) that don't translate
     * cleanly into "rejected per-CR" outcomes — so this method walks the
     * same gate (record → threshold → combineFinal → tryReplay/dispatch)
     * directly and converts every failure into a per-CR result row.</p>
     */
    private Map<String, Object> processOneCr(String crId, UserModel admin) {
        Map<String, Object> outcome = new LinkedHashMap<>();
        outcome.put("crId", crId);

        EntityManager em = getEm();
        IgaChangeRequestEntity cr = em.find(IgaChangeRequestEntity.class, crId);
        if (cr == null || !realm.getId().equals(cr.getRealmId())) {
            outcome.put("status", "SKIPPED");
            outcome.put("error", "NOT_FOUND");
            return outcome;
        }
        outcome.put("actionType", cr.getActionType());
        outcome.put("entityType", cr.getEntityType());
        outcome.put("entityId", cr.getEntityId());

        // Idempotent: a CR resolved by another caller mid-bulk is no longer
        // PENDING — skip rather than error. The bulk endpoint explicitly
        // contracts to handle in-flight concurrency.
        if (!"PENDING".equals(cr.getStatus())) {
            outcome.put("status", "SKIPPED");
            outcome.put("error", "ALREADY_RESOLVED");
            outcome.put("crStatus", cr.getStatus());
            return outcome;
        }

        // -- authorize step: record() enforces requireApprover() internally;
        //    ADOPT_* CRs short-circuit the approver gate inside the resolver.
        try {
            // Reject a duplicate signature from the same admin — mirrors the
            // per-CR authorize endpoint's pre-check. In bulk this typically
            // means the operator already ran a previous bulk that partially
            // signed but didn't commit; we then proceed straight to commit
            // rather than fail (the existing signature counts toward
            // threshold).
            List<IgaAuthorizationEntity> existing = em.createNamedQuery(
                            "IgaAuthorization.findByChangeRequest", IgaAuthorizationEntity.class)
                    .setParameter("changeRequestId", cr.getId())
                    .getResultList();
            boolean alreadySigned = false;
            for (IgaAuthorizationEntity a : existing) {
                if (admin.getUsername() != null && admin.getUsername().equals(a.getPartialSig())) {
                    alreadySigned = true;
                    break;
                }
                if (admin.getId() != null && admin.getId().equals(a.getAuthorizedBy())) {
                    alreadySigned = true;
                    break;
                }
            }

            if (!alreadySigned) {
                IgaAttestor attestor = IgaAttestors.resolveAttestor(session, realm);
                attestor.record(session, cr, admin, null);
            }
        } catch (ForbiddenException fe) {
            // Approver-role gate refused this caller for THIS CR. Per the
            // Phase 6 brief: non-ADOPT CRs must NOT be shortcut — surface
            // the per-CR rejection in the results array.
            outcome.put("status", "REJECTED");
            outcome.put("error", "FORBIDDEN_APPROVER_ROLE");
            outcome.put("httpStatus", 403);
            String msg = fe.getMessage();
            if (msg != null) outcome.put("message", msg);
            return outcome;
        } catch (RuntimeException rex) {
            outcome.put("status", "REJECTED");
            outcome.put("error", "AUTHORIZE_FAILED");
            String msg = rex.getMessage();
            if (msg != null) outcome.put("message", msg);
            log.warnf(rex, "IGA bulk-authorize: CR %s authorize step failed", crId);
            return outcome;
        }

        // -- commit step: same gate the per-CR commit runs (requireApprover
        //    + threshold + combineFinal + tryReplay/dispatch).
        try {
            IgaScopeResolver.ResolvedScope scope = IgaScopeResolver.resolve(session, realm, cr);
            IgaScopeResolver.requireApprover(session, realm, admin, scope, cr);

            IgaAttestor attestor = IgaAttestors.resolveAttestor(session, realm);
            List<IgaAuthorizationEntity> all = em.createNamedQuery(
                            "IgaAuthorization.findByChangeRequest", IgaAuthorizationEntity.class)
                    .setParameter("changeRequestId", cr.getId())
                    .getResultList();
            int threshold = attestor.getThreshold(session, realm, cr);
            if (all.size() < threshold) {
                outcome.put("status", "REJECTED");
                outcome.put("error", "THRESHOLD_NOT_MET");
                outcome.put("threshold", threshold);
                outcome.put("authCount", all.size());
                return outcome;
            }

            String finalAttestation = attestor.combineFinal(session, cr, all);
            try {
                if (!IgaReplayExtension.tryReplay(session, cr, finalAttestation)) {
                    IgaReplayDispatcher.replay(session, cr, finalAttestation);
                }
            } catch (EntityVanishedException ev) {
                outcome.put("status", "REJECTED");
                outcome.put("error", "ENTITY_VANISHED");
                outcome.put("vanishedEntityType", ev.getEntityType());
                outcome.put("vanishedEntityId", ev.getEntityId());
                log.infof("IGA bulk-authorize: CR %s vanished entity %s/%s — skipped",
                        crId, ev.getEntityType(), ev.getEntityId());
                return outcome;
            }
            outcome.put("status", "COMMITTED");
            return outcome;
        } catch (ForbiddenException fe) {
            outcome.put("status", "REJECTED");
            outcome.put("error", "FORBIDDEN_APPROVER_ROLE");
            outcome.put("httpStatus", 403);
            String msg = fe.getMessage();
            if (msg != null) outcome.put("message", msg);
            return outcome;
        } catch (RuntimeException rex) {
            outcome.put("status", "REJECTED");
            outcome.put("error", "COMMIT_FAILED");
            String msg = rex.getMessage();
            if (msg != null) outcome.put("message", msg);
            log.warnf(rex, "IGA bulk-authorize: CR %s commit step failed", crId);
            return outcome;
        }
    }

    // -------------------------------------------------------------------------
    // POST /iga/change-requests/{id}/first-admin-sign-preview
    // -------------------------------------------------------------------------

    /**
     * Resolve a change request to its full signing payload (all foreign keys
     * expanded to full entity data), log it, and return it. No cryptography is
     * performed — this is a prototype for the FirstAdmin signing flow. The real
     * Midgard.signClaims() call will replace the log line once Midgard is updated.
     */
    @POST
    @Path("change-requests/{id}/first-admin-sign-preview")
    @Produces(MediaType.APPLICATION_JSON)
    public Response firstAdminSignPreview(@PathParam("id") String id) {
        auth.realm().requireManageRealm();

        Map<String, Object> payload = getFirstAdminSignPreviewService().buildAndLog(id);
        if (payload == null) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        return Response.ok(payload).build();
    }

    // -------------------------------------------------------------------------
    // PUT /iga/change-requests/{id}
    // -------------------------------------------------------------------------

    @PUT
    @Path("change-requests/{id}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @SuppressWarnings("unchecked")
    public Response updateChangeRequest(@PathParam("id") String id, Map<String, Object> body) {
        auth.realm().requireManageRealm();

        EntityManager em = getEm();
        IgaChangeRequestEntity cr = em.find(IgaChangeRequestEntity.class, id);
        if (cr == null || !realm.getId().equals(cr.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        List<Map<String, Object>> newRows = (List<Map<String, Object>>) body.get("rows");
        if (newRows == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "Missing 'rows' field"))
                    .build();
        }

        IgaChangeRequestService service = getService();
        service.updateRows(id, newRows);

        IgaChangeRequestEntity updated = em.find(IgaChangeRequestEntity.class, id);
        return Response.ok(toRepresentation(updated, service)).build();
    }

    // -------------------------------------------------------------------------
    // POST /iga/change-requests/{id}/deny
    // -------------------------------------------------------------------------

    @POST
    @Path("change-requests/{id}/deny")
    public Response deny(@PathParam("id") String id) {
        auth.realm().requireManageRealm();

        EntityManager em = getEm();
        IgaChangeRequestEntity cr = em.find(IgaChangeRequestEntity.class, id);
        if (cr == null || !realm.getId().equals(cr.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        IgaChangeRequestService service = getService();
        service.deny(id, currentUserId());
        return Response.noContent().build();
    }

    // -------------------------------------------------------------------------
    // POST /iga/adopt — Phase 6a: create an ADOPT_<type> change request for an
    // entity that already exists in the realm but has not yet been attested.
    //
    // Phase 6b will drive this from the toggle-on scan; Phase 6a exposes it on
    // the existing admin surface so the E2E can exercise the round-trip
    // (CR create → sidecar row → authorize+commit → attestation stamped, row
    // deleted) without shipping a separate test-only endpoint.
    // -------------------------------------------------------------------------

    @POST
    @Path("adopt")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response createAdopt(Map<String, Object> body) {
        auth.realm().requireManageRealm();
        if (body == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "Missing JSON body"))
                    .build();
        }
        Object entityTypeObj = body.get("entityType");
        Object entityIdObj = body.get("entityId");
        String entityType = entityTypeObj != null ? entityTypeObj.toString() : null;
        String entityId = entityIdObj != null ? entityIdObj.toString() : null;
        if (entityType == null || entityId == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "Missing entityType or entityId"))
                    .build();
        }
        try {
            String crId = getService().createAdoptCr(realm, entityType, entityId, currentUserId());
            return Response.status(Response.Status.CREATED)
                    .entity(Map.of("changeRequestId", crId,
                            "entityType", entityType,
                            "entityId", entityId))
                    .build();
        } catch (IgaChangeRequestService.AlreadyAttestedException aae) {
            // Phase 6b — entity already carries an attestation (a prior ADOPT
            // already committed). Refuse with 409 so a manual driver doesn't
            // create a CR whose replay would be a JPQL no-op against
            // attestation IS NULL.
            return Response.status(Response.Status.CONFLICT)
                    .entity(Map.of("error", "ALREADY_ATTESTED",
                            "entityType", aae.getEntityType(),
                            "entityId", aae.getEntityId()))
                    .build();
        } catch (IllegalArgumentException iae) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", iae.getMessage()))
                    .build();
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    // -------------------------------------------------------------------------
    // Comments
    // -------------------------------------------------------------------------

    @GET
    @Path("change-requests/{id}/comments")
    @Produces(MediaType.APPLICATION_JSON)
    public Response listComments(@PathParam("id") String id) {
        auth.realm().requireManageRealm();

        EntityManager em = getEm();
        IgaChangeRequestEntity cr = em.find(IgaChangeRequestEntity.class, id);
        if (cr == null || !realm.getId().equals(cr.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        List<IgaCommentEntity> comments = getService().listComments(id);
        List<IgaCommentRepresentation> reps = comments.stream()
                .map(this::toCommentRepresentation)
                .collect(Collectors.toList());
        return Response.ok(reps).build();
    }

    @POST
    @Path("change-requests/{id}/comments")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response addComment(@PathParam("id") String id, Map<String, Object> body) {
        auth.realm().requireManageRealm();

        EntityManager em = getEm();
        IgaChangeRequestEntity cr = em.find(IgaChangeRequestEntity.class, id);
        if (cr == null || !realm.getId().equals(cr.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        String comment = body != null ? (String) body.get("comment") : null;
        Response validation = validateCommentText(comment);
        if (validation != null) return validation;

        UserModel user = currentUser();
        if (user == null) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(Map.of("error", "No authenticated admin user"))
                    .build();
        }

        IgaCommentEntity created = getService().addComment(id, user.getId(), user.getUsername(), comment);
        return Response.status(Response.Status.CREATED)
                .entity(toCommentRepresentation(created))
                .build();
    }

    @PUT
    @Path("change-requests/{id}/comments/{commentId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateComment(@PathParam("id") String id,
                                   @PathParam("commentId") String commentId,
                                   Map<String, Object> body) {
        auth.realm().requireManageRealm();

        EntityManager em = getEm();
        IgaChangeRequestEntity cr = em.find(IgaChangeRequestEntity.class, id);
        if (cr == null || !realm.getId().equals(cr.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        IgaCommentEntity existing = em.find(IgaCommentEntity.class, commentId);
        if (existing == null || existing.getChangeRequest() == null
                || !id.equals(existing.getChangeRequest().getId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        String currentUserId = currentUserId();
        if (currentUserId == null || !currentUserId.equals(existing.getUserId())) {
            return Response.status(Response.Status.FORBIDDEN)
                    .entity(Map.of("error", "Only the comment author may edit this comment"))
                    .build();
        }

        String newText = body != null ? (String) body.get("comment") : null;
        Response validation = validateCommentText(newText);
        if (validation != null) return validation;

        IgaCommentEntity updated = getService().updateComment(commentId, newText);
        return Response.ok(toCommentRepresentation(updated)).build();
    }

    @DELETE
    @Path("change-requests/{id}/comments/{commentId}")
    public Response deleteComment(@PathParam("id") String id,
                                   @PathParam("commentId") String commentId) {
        // Both authors and realm admins may delete; we don't pre-call requireManageRealm()
        // here because authors who lack manage-realm should still be able to delete their own.
        EntityManager em = getEm();
        IgaChangeRequestEntity cr = em.find(IgaChangeRequestEntity.class, id);
        if (cr == null || !realm.getId().equals(cr.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        IgaCommentEntity existing = em.find(IgaCommentEntity.class, commentId);
        if (existing == null || existing.getChangeRequest() == null
                || !id.equals(existing.getChangeRequest().getId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        String currentUserId = currentUserId();
        boolean isAuthor = currentUserId != null && currentUserId.equals(existing.getUserId());
        boolean isAdmin = false;
        if (!isAuthor) {
            try {
                auth.realm().requireManageRealm();
                isAdmin = true;
            } catch (Exception e) {
                // not a realm admin
            }
        }
        if (!isAuthor && !isAdmin) {
            return Response.status(Response.Status.FORBIDDEN)
                    .entity(Map.of("error", "Only the comment author or a realm admin may delete this comment"))
                    .build();
        }

        getService().deleteComment(commentId);
        return Response.noContent().build();
    }

    // -------------------------------------------------------------------------
    // Authorizers
    // -------------------------------------------------------------------------

    @GET
    @Path("authorizers")
    @Produces(MediaType.APPLICATION_JSON)
    public List<IgaAuthorizerRepresentation> listAuthorizers(@QueryParam("type") String type) {
        auth.realm().requireManageRealm();

        IgaAuthorizerService service = getAuthorizerService();
        List<IgaAuthorizerEntity> results;
        if (type != null && !type.isBlank()) {
            results = service.listByRealmAndType(realm.getId(), type);
        } else {
            results = service.listByRealm(realm.getId());
        }
        return results.stream()
                .map(this::toAuthorizerRepresentation)
                .collect(Collectors.toList());
    }

    @GET
    @Path("authorizers/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAuthorizer(@PathParam("id") String id) {
        auth.realm().requireManageRealm();

        IgaAuthorizerEntity entity = getAuthorizerService().findById(id);
        if (entity == null || !realm.getId().equals(entity.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        return Response.ok(toAuthorizerRepresentation(entity)).build();
    }

    @POST
    @Path("authorizers")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response createAuthorizer(IgaAuthorizerRepresentation rep) {
        auth.realm().requireManageRealm();

        if (rep == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "Missing request body"))
                    .build();
        }
        if (rep.getProviderId() == null || rep.getProviderId().isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "providerId is required"))
                    .build();
        }
        if (rep.getType() == null || rep.getType().isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "type is required"))
                    .build();
        }
        if (rep.getAuthorizer() == null || rep.getAuthorizer().isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "authorizer is required"))
                    .build();
        }
        if (rep.getAuthorizerCertificate() == null || rep.getAuthorizerCertificate().isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "authorizerCertificate is required"))
                    .build();
        }

        IgaAuthorizerEntity created = getAuthorizerService().create(
                realm.getId(),
                rep.getProviderId(),
                rep.getType(),
                rep.getAuthorizer(),
                rep.getAuthorizerCertificate());
        return Response.status(Response.Status.CREATED)
                .entity(toAuthorizerRepresentation(created))
                .build();
    }

    @DELETE
    @Path("authorizers/{id}")
    public Response deleteAuthorizer(@PathParam("id") String id) {
        auth.realm().requireManageRealm();

        IgaAuthorizerService service = getAuthorizerService();
        IgaAuthorizerEntity entity = service.findById(id);
        if (entity == null || !realm.getId().equals(entity.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        service.delete(id);
        return Response.noContent().build();
    }

    // -------------------------------------------------------------------------
    // Role Policies
    // -------------------------------------------------------------------------

    @GET
    @Path("role-policies")
    @Produces(MediaType.APPLICATION_JSON)
    public List<IgaRolePolicyRepresentation> listRolePolicies() {
        auth.realm().requireManageRealm();

        return getRolePolicyService().listByRealm(realm.getId()).stream()
                .map(this::toRolePolicyRepresentation)
                .collect(Collectors.toList());
    }

    @GET
    @Path("role-policies/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getRolePolicy(@PathParam("id") String id) {
        auth.realm().requireManageRealm();

        IgaRolePolicyEntity entity = getRolePolicyService().findById(id);
        if (entity == null || !realm.getId().equals(entity.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        return Response.ok(toRolePolicyRepresentation(entity)).build();
    }

    @GET
    @Path("role-policies/role/{roleId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getRolePolicyByRole(@PathParam("roleId") String roleId) {
        auth.realm().requireManageRealm();

        IgaRolePolicyEntity entity = getRolePolicyService()
                .findByRealmAndRole(realm.getId(), roleId);
        if (entity == null) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        return Response.ok(toRolePolicyRepresentation(entity)).build();
    }

    @POST
    @Path("role-policies")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response upsertRolePolicy(IgaRolePolicyRepresentation rep) {
        auth.realm().requireManageRealm();

        if (rep == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "Missing request body"))
                    .build();
        }
        if (rep.getRoleId() == null || rep.getRoleId().isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "roleId is required"))
                    .build();
        }
        if (rep.getPolicy() == null || rep.getPolicy().isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "policy is required"))
                    .build();
        }
        if (rep.getPolicySig() == null || rep.getPolicySig().isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "policySig is required"))
                    .build();
        }
        if (rep.getPolicySig().length() > 512) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "policySig exceeds maximum length of 512 characters"))
                    .build();
        }

        IgaRolePolicyEntity upserted = getRolePolicyService().upsert(
                realm.getId(),
                rep.getRoleId(),
                rep.getPolicy(),
                rep.getPolicySig(),
                rep.getContractId(),
                rep.getApprovalType(),
                rep.getExecutionType(),
                rep.getThreshold(),
                rep.getPolicyData());
        return Response.ok(toRolePolicyRepresentation(upserted)).build();
    }

    @DELETE
    @Path("role-policies/role/{roleId}")
    public Response deleteRolePolicyByRole(@PathParam("roleId") String roleId) {
        auth.realm().requireManageRealm();

        IgaRolePolicyService service = getRolePolicyService();
        IgaRolePolicyEntity existing = service.findByRealmAndRole(realm.getId(), roleId);
        if (existing == null) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        service.deleteByRealmAndRole(realm.getId(), roleId);
        return Response.noContent().build();
    }

    @DELETE
    @Path("role-policies/{id}")
    public Response deleteRolePolicy(@PathParam("id") String id) {
        auth.realm().requireManageRealm();

        IgaRolePolicyService service = getRolePolicyService();
        IgaRolePolicyEntity existing = service.findById(id);
        if (existing == null || !realm.getId().equals(existing.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        service.deleteById(id);
        return Response.noContent().build();
    }

    // -------------------------------------------------------------------------
    // Forseti Contracts
    // -------------------------------------------------------------------------

    @GET
    @Path("forseti-contracts")
    @Produces(MediaType.APPLICATION_JSON)
    public List<IgaForsetiContractRepresentation> listForsetiContracts() {
        auth.realm().requireManageRealm();

        return getForsetiContractService().listByRealm(realm.getId()).stream()
                .map(this::toForsetiContractRepresentation)
                .collect(Collectors.toList());
    }

    @GET
    @Path("forseti-contracts/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getForsetiContract(@PathParam("id") String id) {
        auth.realm().requireManageRealm();

        IgaForsetiContractEntity entity = getForsetiContractService().findById(id);
        if (entity == null || !realm.getId().equals(entity.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        return Response.ok(toForsetiContractRepresentation(entity)).build();
    }

    @POST
    @Path("forseti-contracts")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response upsertForsetiContract(IgaForsetiContractRepresentation rep) {
        auth.realm().requireManageRealm();

        if (rep == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "Missing request body"))
                    .build();
        }
        if (rep.getContractCode() == null || rep.getContractCode().isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "contractCode is required"))
                    .build();
        }
        if (rep.getContractCode().length() > 1_048_576) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "contractCode exceeds maximum length of 1048576 characters"))
                    .build();
        }

        IgaForsetiContractEntity upserted = getForsetiContractService().upsert(
                realm.getId(),
                rep.getContractCode(),
                rep.getName());
        return Response.ok(toForsetiContractRepresentation(upserted)).build();
    }

    @DELETE
    @Path("forseti-contracts/{id}")
    public Response deleteForsetiContract(@PathParam("id") String id) {
        auth.realm().requireManageRealm();

        IgaForsetiContractService service = getForsetiContractService();
        IgaForsetiContractEntity existing = service.findById(id);
        if (existing == null || !realm.getId().equals(existing.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        service.deleteById(id);
        return Response.noContent().build();
    }

    // -------------------------------------------------------------------------
    // Server Cert Drafts (workload TLS / SPIFFE cert request flow)
    // -------------------------------------------------------------------------

    @GET
    @Path("server-certs")
    @Produces(MediaType.APPLICATION_JSON)
    public List<IgaServerCertDraftRepresentation> listServerCerts() {
        auth.realm().requireManageRealm();
        return getServerCertDraftService().listByRealm(realm.getId()).stream()
                .map(this::toServerCertDraftRepresentation)
                .collect(Collectors.toList());
    }

    @GET
    @Path("server-certs/active")
    @Produces(MediaType.APPLICATION_JSON)
    public List<IgaServerCertDraftRepresentation> listActiveServerCerts() {
        auth.realm().requireManageRealm();
        return getServerCertDraftService().listActive(realm.getId()).stream()
                .map(this::toServerCertDraftRepresentation)
                .collect(Collectors.toList());
    }

    @GET
    @Path("server-certs/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getServerCert(@PathParam("id") String id) {
        auth.realm().requireManageRealm();
        IgaServerCertDraftEntity entity = getServerCertDraftService().findById(id);
        if (entity == null || !realm.getId().equals(entity.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        return Response.ok(toServerCertDraftRepresentation(entity)).build();
    }

    @GET
    @Path("server-certs/instance/{instanceId}")
    @Produces(MediaType.APPLICATION_JSON)
    public List<IgaServerCertDraftRepresentation> listServerCertsByInstance(
            @PathParam("instanceId") String instanceId) {
        auth.realm().requireManageRealm();
        return getServerCertDraftService()
                .findByRealmAndInstance(realm.getId(), instanceId).stream()
                .map(this::toServerCertDraftRepresentation)
                .collect(Collectors.toList());
    }

    @POST
    @Path("server-certs/request")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response requestServerCert(IgaServerCertDraftRepresentation rep) {
        auth.realm().requireManageRealm();

        if (rep == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "Missing request body"))
                    .build();
        }
        if (rep.getClientId() == null || rep.getClientId().isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "clientId is required"))
                    .build();
        }
        if (rep.getInstanceId() == null || rep.getInstanceId().isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "instanceId is required"))
                    .build();
        }
        if (rep.getPublicKey() == null || rep.getPublicKey().isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "publicKey is required"))
                    .build();
        }
        if (rep.getPublicKey().length() > 4096) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "publicKey exceeds maximum length of 4096 characters"))
                    .build();
        }
        if (rep.getSpiffeId() != null && rep.getSpiffeId().length() > 512) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "spiffeId exceeds maximum length of 512 characters"))
                    .build();
        }
        if (rep.getSignedPolicy() != null && rep.getSignedPolicy().length() > 8192) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "signedPolicy exceeds maximum length of 8192 characters"))
                    .build();
        }

        IgaServerCertDraftEntity created = getServerCertDraftService().createRequest(
                realm,
                currentUserId(),
                rep.getClientId(),
                rep.getInstanceId(),
                rep.getSpiffeId(),
                rep.getPublicKey(),
                rep.getPublicKeyFingerprint(),
                rep.getRequestedLifetime(),
                rep.getSignedPolicy());
        return Response.status(Response.Status.CREATED)
                .entity(toServerCertDraftRepresentation(created))
                .build();
    }

    @POST
    @Path("server-certs/{id}/issue")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response issueServerCert(@PathParam("id") String id, Map<String, Object> body) {
        auth.realm().requireManageRealm();

        IgaServerCertDraftService service = getServerCertDraftService();
        IgaServerCertDraftEntity entity = service.findById(id);
        if (entity == null || !realm.getId().equals(entity.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        String certificate = body != null ? (String) body.get("certificate") : null;
        String trustBundle = body != null ? (String) body.get("trustBundle") : null;
        if (certificate == null || certificate.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "certificate is required"))
                    .build();
        }
        if (trustBundle == null || trustBundle.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "trustBundle is required"))
                    .build();
        }

        IgaServerCertDraftEntity updated = service.issueCert(id, certificate, trustBundle);
        return Response.ok(toServerCertDraftRepresentation(updated)).build();
    }

    @POST
    @Path("server-certs/{id}/revoke")
    @Produces(MediaType.APPLICATION_JSON)
    public Response revokeServerCert(@PathParam("id") String id) {
        auth.realm().requireManageRealm();

        IgaServerCertDraftService service = getServerCertDraftService();
        IgaServerCertDraftEntity entity = service.findById(id);
        if (entity == null || !realm.getId().equals(entity.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        IgaServerCertDraftEntity updated = service.revoke(id);
        return Response.ok(toServerCertDraftRepresentation(updated)).build();
    }

    @DELETE
    @Path("server-certs/{id}")
    public Response deleteServerCert(@PathParam("id") String id) {
        auth.realm().requireManageRealm();

        IgaServerCertDraftService service = getServerCertDraftService();
        IgaServerCertDraftEntity entity = service.findById(id);
        if (entity == null || !realm.getId().equals(entity.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        service.deleteById(id);
        return Response.noContent().build();
    }

    // -------------------------------------------------------------------------
    // Licensing Drafts (realm license install/rotate flow)
    // -------------------------------------------------------------------------

    @POST
    @Path("licensing/trigger")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response triggerLicensing(Map<String, Object> body) {
        auth.realm().requireManageRealm();

        String actionType = body != null ? (String) body.get("actionType") : null;
        if (actionType == null || actionType.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "actionType is required"))
                    .build();
        }
        if (!"INSTALL_LICENSE".equals(actionType) && !"ROTATE_LICENSE".equals(actionType)) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "actionType must be INSTALL_LICENSE or ROTATE_LICENSE"))
                    .build();
        }

        IgaLicensingDraftEntity created = getLicensingDraftService().createRequest(
                realm,
                currentUserId(),
                actionType);
        return Response.status(Response.Status.CREATED)
                .entity(toLicensingDraftRepresentation(created))
                .build();
    }

    @GET
    @Path("licensing/drafts")
    @Produces(MediaType.APPLICATION_JSON)
    public List<IgaLicensingDraftRepresentation> listLicensingDrafts() {
        auth.realm().requireManageRealm();
        return getLicensingDraftService().listByRealm(realm.getId()).stream()
                .map(this::toLicensingDraftRepresentation)
                .collect(Collectors.toList());
    }

    @GET
    @Path("licensing/drafts/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getLicensingDraft(@PathParam("id") String id) {
        auth.realm().requireManageRealm();
        IgaLicensingDraftEntity entity = getLicensingDraftService().findById(id);
        if (entity == null || !realm.getId().equals(entity.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        return Response.ok(toLicensingDraftRepresentation(entity)).build();
    }

    @DELETE
    @Path("licensing/drafts/{id}")
    public Response deleteLicensingDraft(@PathParam("id") String id) {
        auth.realm().requireManageRealm();

        IgaLicensingDraftService service = getLicensingDraftService();
        IgaLicensingDraftEntity entity = service.findById(id);
        if (entity == null || !realm.getId().equals(entity.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        service.deleteById(id);
        return Response.noContent().build();
    }

    // -------------------------------------------------------------------------
    // License History (append-only audit log) + issuance endpoint
    // -------------------------------------------------------------------------

    @GET
    @Path("licensing/history")
    @Produces(MediaType.APPLICATION_JSON)
    public List<IgaLicenseHistoryRepresentation> listLicenseHistory() {
        auth.realm().requireManageRealm();
        return getLicenseHistoryService().listByRealm(realm.getId()).stream()
                .map(this::toLicenseHistoryRepresentation)
                .collect(Collectors.toList());
    }

    @GET
    @Path("licensing/history/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getLicenseHistory(@PathParam("id") String id) {
        auth.realm().requireManageRealm();
        IgaLicenseHistoryEntity entity = getLicenseHistoryService().findById(id);
        if (entity == null || !realm.getId().equals(entity.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        return Response.ok(toLicenseHistoryRepresentation(entity)).build();
    }

    @GET
    @Path("licensing/history/excluding-active")
    @Produces(MediaType.APPLICATION_JSON)
    public List<IgaLicenseHistoryRepresentation> listLicenseHistoryExcludingActive(
            @QueryParam("activeGvrk") String activeGvrk) {
        auth.realm().requireManageRealm();

        List<IgaLicenseHistoryEntity> all = getLicenseHistoryService().listByRealm(realm.getId());
        if (activeGvrk == null || activeGvrk.isBlank()) {
            return all.stream()
                    .map(this::toLicenseHistoryRepresentation)
                    .collect(Collectors.toList());
        }
        return all.stream()
                .filter(h -> !activeGvrk.equals(h.getGvrk()))
                .map(this::toLicenseHistoryRepresentation)
                .collect(Collectors.toList());
    }

    @POST
    @Path("licensing/drafts/{draftId}/issue")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response issueLicense(@PathParam("draftId") String draftId, Map<String, Object> body) {
        auth.realm().requireManageRealm();

        IgaLicensingDraftService draftService = getLicensingDraftService();
        IgaLicensingDraftEntity draft = draftService.findById(draftId);
        if (draft == null || !realm.getId().equals(draft.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        if (body == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "Missing request body"))
                    .build();
        }

        String providerId = (String) body.get("providerId");
        String vrk = (String) body.get("vrk");
        String gvrk = (String) body.get("gvrk");
        String signature = (String) body.get("signature");

        if (providerId == null || providerId.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "providerId is required"))
                    .build();
        }
        if (vrk == null || vrk.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "vrk is required"))
                    .build();
        }
        if (gvrk == null || gvrk.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "gvrk is required"))
                    .build();
        }
        if (signature == null || signature.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "signature is required"))
                    .build();
        }

        String gvrkCertificate = (String) body.get("gvrkCertificate");
        String vvkId = (String) body.get("vvkId");
        String customerId = (String) body.get("customerId");
        String vendorId = (String) body.get("vendorId");
        String payerPub = (String) body.get("payerPub");
        String walletId = (String) body.get("walletId");
        Object expiryRaw = body.get("expiry");
        Long expiry = null;
        if (expiryRaw instanceof Number) {
            expiry = ((Number) expiryRaw).longValue();
        } else if (expiryRaw instanceof String && !((String) expiryRaw).isBlank()) {
            try { expiry = Long.parseLong((String) expiryRaw); } catch (NumberFormatException ignored) {}
        }

        IgaLicenseHistoryEntity history = getLicenseHistoryService().record(
                realm.getId(),
                providerId,
                vrk,
                gvrk,
                gvrkCertificate,
                vvkId,
                customerId,
                vendorId,
                payerPub,
                walletId,
                expiry);

        draftService.setSignature(draftId, signature);

        return Response.ok(Map.of(
                "historyId", history.getId(),
                "draftId", draftId
        )).build();
    }

    private IgaLicenseHistoryRepresentation toLicenseHistoryRepresentation(IgaLicenseHistoryEntity entity) {
        IgaLicenseHistoryRepresentation rep = new IgaLicenseHistoryRepresentation();
        rep.setId(entity.getId());
        rep.setRealmId(entity.getRealmId());
        rep.setProviderId(entity.getProviderId());
        rep.setVrk(entity.getVrk());
        rep.setGvrk(entity.getGvrk());
        rep.setGvrkCertificate(entity.getGvrkCertificate());
        rep.setVvkId(entity.getVvkId());
        rep.setCustomerId(entity.getCustomerId());
        rep.setVendorId(entity.getVendorId());
        rep.setPayerPub(entity.getPayerPub());
        rep.setWalletId(entity.getWalletId());
        rep.setExpiry(entity.getExpiry());
        rep.setCreatedAt(entity.getCreatedAt());
        return rep;
    }

    private IgaLicensingDraftRepresentation toLicensingDraftRepresentation(IgaLicensingDraftEntity entity) {
        IgaLicensingDraftRepresentation rep = new IgaLicensingDraftRepresentation();
        rep.setId(entity.getId());
        rep.setChangeRequestId(entity.getChangeRequest() != null ? entity.getChangeRequest().getId() : null);
        rep.setRealmId(entity.getRealmId());
        rep.setActionType(entity.getActionType());
        rep.setSignature(entity.getSignature());
        rep.setCreatedAt(entity.getCreatedAt());
        rep.setUpdatedAt(entity.getUpdatedAt());
        return rep;
    }

    private IgaServerCertDraftRepresentation toServerCertDraftRepresentation(IgaServerCertDraftEntity entity) {
        IgaServerCertDraftRepresentation rep = new IgaServerCertDraftRepresentation();
        rep.setId(entity.getId());
        rep.setChangeRequestId(entity.getChangeRequest() != null ? entity.getChangeRequest().getId() : null);
        rep.setRealmId(entity.getRealmId());
        rep.setClientId(entity.getClientId());
        rep.setInstanceId(entity.getInstanceId());
        rep.setSpiffeId(entity.getSpiffeId());
        rep.setPublicKey(entity.getPublicKey());
        rep.setPublicKeyFingerprint(entity.getPublicKeyFingerprint());
        rep.setRequestedLifetime(entity.getRequestedLifetime());
        rep.setCertificate(entity.getCertificate());
        rep.setTrustBundle(entity.getTrustBundle());
        rep.setSignedPolicy(entity.getSignedPolicy());
        rep.setRevoked(entity.isRevoked());
        rep.setRevokedAt(entity.getRevokedAt());
        rep.setCreatedAt(entity.getCreatedAt());
        rep.setUpdatedAt(entity.getUpdatedAt());
        return rep;
    }

    private IgaForsetiContractRepresentation toForsetiContractRepresentation(IgaForsetiContractEntity entity) {
        IgaForsetiContractRepresentation rep = new IgaForsetiContractRepresentation();
        rep.setId(entity.getId());
        rep.setRealmId(entity.getRealmId());
        rep.setContractHash(entity.getContractHash());
        rep.setContractCode(entity.getContractCode());
        rep.setName(entity.getName());
        rep.setCreatedAt(entity.getCreatedAt());
        rep.setUpdatedAt(entity.getUpdatedAt());
        return rep;
    }

    private IgaRolePolicyRepresentation toRolePolicyRepresentation(IgaRolePolicyEntity entity) {
        IgaRolePolicyRepresentation rep = new IgaRolePolicyRepresentation();
        rep.setId(entity.getId());
        rep.setRealmId(entity.getRealmId());
        rep.setRoleId(entity.getRoleId());
        rep.setPolicy(entity.getPolicy());
        rep.setPolicySig(entity.getPolicySig());
        rep.setContractId(entity.getContractId());
        rep.setApprovalType(entity.getApprovalType());
        rep.setExecutionType(entity.getExecutionType());
        rep.setThreshold(entity.getThreshold());
        rep.setPolicyData(entity.getPolicyData());
        rep.setCreatedAt(entity.getCreatedAt());
        rep.setUpdatedAt(entity.getUpdatedAt());
        return rep;
    }

    private IgaAuthorizerRepresentation toAuthorizerRepresentation(IgaAuthorizerEntity entity) {
        IgaAuthorizerRepresentation rep = new IgaAuthorizerRepresentation();
        rep.setId(entity.getId());
        rep.setRealmId(entity.getRealmId());
        rep.setProviderId(entity.getProviderId());
        rep.setType(entity.getType());
        rep.setAuthorizer(entity.getAuthorizer());
        rep.setAuthorizerCertificate(entity.getAuthorizerCertificate());
        rep.setCreatedAt(entity.getCreatedAt());
        return rep;
    }

    private Response validateCommentText(String comment) {
        if (comment == null || comment.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "Comment text must be non-empty"))
                    .build();
        }
        if (comment.length() > 2000) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "Comment text exceeds maximum length of 2000 characters"))
                    .build();
        }
        return null;
    }

    private IgaCommentRepresentation toCommentRepresentation(IgaCommentEntity entity) {
        IgaCommentRepresentation rep = new IgaCommentRepresentation();
        rep.setId(entity.getId());
        rep.setUserId(entity.getUserId());
        rep.setUsername(entity.getUsername());
        rep.setComment(entity.getComment());
        rep.setCreatedAt(entity.getCreatedAt());
        rep.setUpdatedAt(entity.getUpdatedAt());
        return rep;
    }

    private IgaChangeRequestRepresentation toRepresentation(IgaChangeRequestEntity cr,
                                                              IgaChangeRequestService service) {
        IgaChangeRequestRepresentation rep = new IgaChangeRequestRepresentation();
        rep.setId(cr.getId());
        rep.setRealmId(cr.getRealmId());
        rep.setEntityType(cr.getEntityType());
        rep.setEntityId(cr.getEntityId());
        rep.setActionType(cr.getActionType());
        rep.setStatus(cr.getStatus());
        rep.setRequestedBy(cr.getRequestedBy());
        rep.setCreatedAt(cr.getCreatedAt());
        rep.setResolvedAt(cr.getResolvedAt());
        rep.setResolvedBy(cr.getResolvedBy());
        try {
            rep.setRows(service.parseRows(cr.getRowsJson()));
        } catch (Exception ignored) {
        }
        long authCount = service.countAuthorizations(cr.getId());
        rep.setAuthorizationCount(authCount);

        // Authorizers list — wrapped so a malformed CR can't break list endpoints.
        try {
            List<IgaAuthorizationEntity> rows = getEm().createNamedQuery(
                            "IgaAuthorization.findByChangeRequest", IgaAuthorizationEntity.class)
                    .setParameter("changeRequestId", cr.getId())
                    .getResultList();
            List<IgaCrAuthorizerRepresentation> authorizers = rows.stream()
                    .map(a -> new IgaCrAuthorizerRepresentation(
                            a.getPartialSig(),
                            a.getCreatedAt() != null ? a.getCreatedAt() : 0L))
                    .collect(Collectors.toList());
            rep.setAuthorizers(authorizers);
        } catch (Exception ignored) {
        }

        // readyToCommit = PENDING && authCount >= threshold. Threshold resolution
        // depends on rows_json + realm state, so guard it.
        try {
            if ("PENDING".equals(cr.getStatus())) {
                IgaAttestor attestor = IgaAttestors.resolveAttestor(session, realm);
                int threshold = attestor.getThreshold(session, realm, cr);
                rep.setReadyToCommit(authCount >= threshold);
            }
        } catch (Exception ignored) {
        }

        // Scope-based approval metadata for the admin UI. Resolve once and reuse
        // for both the threshold and the required approver roles to avoid walking
        // the affected entities twice.
        try {
            IgaScopeResolver.ResolvedScope scope = IgaScopeResolver.resolve(session, realm, cr);
            // ADOPT_* CRs report threshold=1 (system-bootstrap bypass) so the
            // admin UI sees the same gate the server enforces at commit.
            rep.setThreshold(IgaScopeResolver.resolveThreshold(session, realm, scope, cr));
            rep.setRequiredApproverRoles(new java.util.ArrayList<>(scope.requiredApproverRoles));
            // scopeMode is realm-level today (see IgaScopeResolver.requireApprover);
            // mirror that derivation exactly so the UI sees the same gate the
            // server enforces. Default is "any" when the realm attribute is unset
            // or anything other than "all" (case-insensitive).
            String mode = realm.getAttribute(IgaScopeResolver.ATTR_SCOPE_MODE);
            rep.setScopeMode("all".equalsIgnoreCase(mode) ? "all" : "any");
        } catch (Exception ignored) {
            // Resolver failures (e.g. malformed rows) should never break the
            // list/detail endpoint; leave the new fields at their defaults.
        }
        return rep;
    }
}
