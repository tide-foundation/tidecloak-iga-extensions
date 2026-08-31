package org.tidecloak.iga.rest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.tidecloak.iga.entities.IgaAuthorizationEntity;
import org.tidecloak.iga.entities.IgaAuthorizerEntity;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.entities.IgaCommentEntity;
import org.tidecloak.iga.entities.IgaForsetiContractEntity;
import org.tidecloak.iga.entities.IgaLicenseHistoryEntity;
import org.tidecloak.iga.entities.IgaLicensingDraftEntity;
import org.midgard.models.Policy.Policy;
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
import org.tidecloak.iga.replay.IgaMapperConflictException;
import org.tidecloak.iga.replay.IgaReplayDispatcher;
import org.tidecloak.iga.replay.IgaReplayExtension;
import org.tidecloak.iga.attestors.IgaAttestor;
import org.tidecloak.iga.attestors.IgaAttestors;
import org.tidecloak.iga.attestors.IgaScopeResolver;
import org.tidecloak.iga.attestors.TideAttestor;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Base64;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * JAX-RS resource at path "iga" providing change request approval workflow endpoints.
 */
@Path("iga")
@Vetoed
public class IgaAdminResource {

    private static final Logger log = Logger.getLogger(IgaAdminResource.class);

    /** Parses ROWS_JSON into a generic tree for the diagnostic dump (preserves exact shape). */
    private static final ObjectMapper DIAG_MAPPER = new ObjectMapper();

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
     * the extension router. ADOPT actions are uniquely resumable
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

    /**
     * Security guard for the LEGACY simple authorize+commit lane: a tide-MULTIADMIN
     * change request MUST be driven through the approval enclave
     * ({@code POST /iga/change-requests/{id}/approve}), which collects an admin
     * doken quorum and Policy:1-signs the carrier. The simple authorize/commit path
     * cannot collect a doken and would otherwise stub-sign a non-producer multiAdmin
     * CR (CREATE_*, DELETE_*, SET_REALM_ATTRIBUTE, REGEN_ADMIN_POLICY, DISABLE_IGA,
     * OFFBOARD_REALM), letting a SINGLE manage-realm admin bypass the enclave quorum
     * entirely. Returns a 409 CONFLICT {@link Response} when the lane must be refused,
     * or {@code null} when the call is allowed to proceed.
     *
     * <p>SCOPED to tide-MULTIADMIN ONLY. firstAdmin (single-signer bootstrap, whose
     * wizard {@code drainPendingCRs} legitimately uses authorize+commit) and Tideless
     * ({@link org.tidecloak.iga.attestors.SimpleNameAttestor}) are NEVER refused.
     *
     * <p>EXEMPTIONS (these legitimately need the simple lane even in multiAdmin):
     * <ul>
     *   <li><b>ADOPT_*</b> CRs - toggle-on attestation of pre-existing state; they
     *       short-circuit to threshold 1 and carry no producer quorum obligation.</li>
     *   <li><b>vendor / system provisioning</b> ({@code IGA_VENDOR_PROVISIONING}) and
     *       <b>replay</b> ({@code IGA_REPLAY_ACTIVE}) sessions - these internal flows
     *       drive CRs straight through without the interactive enclave ceremony.</li>
     * </ul>
     */
    private Response refuseLegacyLaneForMultiAdmin(IgaChangeRequestEntity cr) {
        // ADOPT_* is exempt - resumable, threshold-1, no producer quorum.
        if (isAdoptAction(cr.getActionType())) {
            return null;
        }
        // The actual gate, computed CHEAPLY (authorizer-row / iga.attestor read only - no
        // attestor-provider lookup): a tide realm whose authorizer mode is multiAdmin. A
        // non-tide / firstAdmin realm short-circuits here, so this guard never resolves an
        // attestor or touches getService() for them (keeps the legacy lane fully unaffected
        // for firstAdmin/Tideless and avoids perturbing the early dependency/ordering gates).
        if (!TideAttestor.isMultiAdminMode(session, realm)) {
            return null;
        }
        // Internal provisioning / replay sessions bypass the interactive enclave.
        if ("true".equals(session.getAttribute("IGA_REPLAY_ACTIVE"))) {
            return null;
        }
        IgaChangeRequestService svc = getService();
        if (svc != null && svc.isVendorProvisioning()) {
            return null;
        }
        log.warnf("IGA legacy-lane refusal: CR %s (action=%s) on multiAdmin realm %s rejected - "
                        + "the simple authorize/commit path cannot sign a multiAdmin change request; "
                        + "use the approval enclave (POST .../approve).",
                cr.getId(), cr.getActionType(), realm.getName());
        return Response.status(Response.Status.CONFLICT)
                .entity(Map.of(
                        "error", "MULTIADMIN_REQUIRES_APPROVAL_ENCLAVE",
                        "message", "multiAdmin change requests must be approved via the approval "
                                + "enclave (POST /iga/change-requests/{id}/approve); the simple "
                                + "authorize/commit path cannot sign a multiAdmin change request.",
                        "changeRequestId", cr.getId(),
                        "actionType", cr.getActionType()))
                .build();
    }

    /**
     * Quorum gate for the DECOUPLED {@code POST /iga/change-requests/{id}/commit}
     * endpoint on a tide-MULTIADMIN realm. Approve (sign) and commit (apply) are now
     * two separate explicit actions: the per-admin dokens are collected via prior
     * {@code POST .../approve} calls (each persists an {@link IgaAuthorizationEntity}
     * on the CR), and {@code .../commit} applies the CR.
     *
     * <p>Unlike {@link #refuseLegacyLaneForMultiAdmin} (which the deprecated
     * {@code .../authorize} path still uses to refuse multiAdmin OUTRIGHT), this guard
     * ALLOWS the apply when the quorum has genuinely been collected
     * ({@code authCount >= threshold}) and refuses with {@code 412 QUORUM_NOT_MET}
     * ONLY when it has not. This preserves the original security property — a single
     * manage-realm admin can never stub-commit PAST the quorum — because the apply is
     * gated on a real quorum of recorded approver dokens (and {@link #commitResolved}
     * re-verifies the same threshold internally, defense in depth). It NEVER records a
     * new signature, so {@code .../commit} cannot self-approve.
     *
     * <p>Same cheap multiAdmin short-circuit + same exemptions as
     * {@link #refuseLegacyLaneForMultiAdmin}: ADOPT_* (threshold-1, resumable),
     * {@code IGA_REPLAY_ACTIVE} and vendor-provisioning sessions pass through, and a
     * non-tide / firstAdmin / Tideless realm returns {@code null} immediately (its
     * commitResolved threshold gate is the floor). Returns a {@link Response} when the
     * commit must be refused, or {@code null} when it may proceed.
     */
    private Response refuseSubQuorumCommitForMultiAdmin(IgaChangeRequestEntity cr, EntityManager em) {
        // ADOPT_* is exempt — resumable, threshold-1, no producer quorum.
        if (isAdoptAction(cr.getActionType())) {
            return null;
        }
        // Only tide-multiAdmin CRs are quorum-gated here; firstAdmin / Tideless /
        // non-tide fall through to commitResolved's own threshold gate unchanged.
        if (!TideAttestor.isMultiAdminMode(session, realm)) {
            return null;
        }
        // Internal provisioning / replay sessions bypass the interactive enclave.
        if ("true".equals(session.getAttribute("IGA_REPLAY_ACTIVE"))) {
            return null;
        }
        IgaChangeRequestService svc = getService();
        if (svc != null && svc.isVendorProvisioning()) {
            return null;
        }
        // The real gate: refuse to APPLY a multiAdmin CR that has not yet reached its
        // doken quorum. commitResolved re-checks this same threshold internally, but
        // we surface a clear, action-specific 412 here so the operator knows to drive
        // more approvals through POST .../approve before committing.
        IgaAttestor attestor = IgaAttestors.resolveAttestor(session, realm);
        int threshold = attestor.getThreshold(session, realm, cr);
        int authCount = authCount(em, cr);
        if (authCount < threshold) {
            int needed = threshold - authCount;
            log.infof("IGA commit refused (QUORUM_NOT_MET): CR %s (action=%s) on multiAdmin realm %s "
                            + "has %d/%d approvals — approve to quorum before committing.",
                    cr.getId(), cr.getActionType(), realm.getName(), authCount, threshold);
            return Response.status(Response.Status.PRECONDITION_FAILED)
                    .entity(Map.of(
                            "error", "QUORUM_NOT_MET",
                            "message", "Approve to quorum before committing — need " + needed
                                    + " more approval" + (needed == 1 ? "" : "s")
                                    + " (POST /iga/change-requests/{id}/approve).",
                            "threshold", threshold,
                            "authCount", authCount,
                            "changeRequestId", cr.getId(),
                            "actionType", cr.getActionType()))
                    .build();
        }
        return null;
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

        // Approval-enclave open: when the admin lists the PENDING change requests to approve
        // them, ensure the steady-state multiAdmin threshold-policy CR exists (or is folded /
        // cancelled) for the CURRENT pending tide-realm-admin membership set. This is the single
        // source of truth for the REGEN_ADMIN_POLICY CR — robust to tide-realm-admin grants
        // captured before the hook existed and grants that coalesce into an existing pending CR
        // (neither reaches the capture path). Runs in its OWN transaction and swallows any error
        // so it can never poison the read; it is idempotent across repeated enclave opens.
        if ("PENDING".equals(effectiveStatus)) {
            ensureThresholdPolicyCrForEnclave();
        }

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

        // Auto-bundle hint: resolve the realm's current PENDING threshold-policy CR + the pending
        // tide-realm-admin assignment set it covers ONCE per list call (not per-CR), so each
        // assignment CR's representation can carry relatedPolicyCrId. READ-ONLY (multiAdmin only;
        // none() otherwise). Guarded so it can never break the listing.
        TideAttestor.PolicyCrLinkage policyLinkage;
        try {
            policyLinkage = new TideAttestor(session).resolvePolicyCrLinkage(session, realm);
        } catch (RuntimeException ex) {
            log.warnf(ex, "IGA relatedPolicyCrId linkage resolution failed for realm %s "
                    + "(listing unaffected; relatedPolicyCrId left null).", realm.getName());
            policyLinkage = TideAttestor.PolicyCrLinkage.none();
        }
        final TideAttestor.PolicyCrLinkage linkage = policyLinkage;

        return results.stream()
                .map(cr -> toRepresentation(cr, service, linkage))
                .collect(Collectors.toList());
    }

    /**
     * Approval-enclave-open ensure of the steady-state multiAdmin threshold-policy CR. Runs in an
     * INDEPENDENT {@link KeycloakModelUtils#runJobInTransaction} session (so it commits its own
     * create/fold/cancel without entangling the surrounding read tx) and SWALLOWS any error (so a
     * failed ensure can never break the pending-CR listing the admin needs). The ensure itself is
     * a no-op for non-multiAdmin realms and idempotent across repeated opens
     * ({@link TideAttestor#ensureThresholdPolicyCrForEnclave}).
     */
    private void ensureThresholdPolicyCrForEnclave() {
        try {
            KeycloakModelUtils.runJobInTransaction(session.getKeycloakSessionFactory(), newSession -> {
                RealmModel newRealm = newSession.realms().getRealm(realm.getId());
                if (newRealm == null) {
                    return;
                }
                // Bind the realm onto the fresh job session's KeycloakContext. Without this,
                // downstream user-stream lookups (countActiveTideRealmAdmins →
                // session.users().getRoleMembersStream) hit the Infinispan org-provider guard
                // reading session.getContext().getRealm() and throw
                // "Session not bound to a realm", which the wrapper's best-effort try/catch
                // then swallows as a WARN — so the policy CR is never created. Mirror IgaAdoptScan.
                newSession.getContext().setRealm(newRealm);
                new TideAttestor(newSession).ensureThresholdPolicyCrForEnclave(newSession, newRealm);
            });
        } catch (RuntimeException ex) {
            // Best-effort: never let the policy-CR ensure break the enclave listing. The next
            // enclave open re-attempts it (idempotent).
            log.warnf(ex, "IGA threshold-policy CR ensure at enclave open failed for realm %s "
                    + "(listing unaffected); will retry on next open.", realm.getName());
        }
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
    // GET /iga/change-requests/{id}/diagnostic-bundle
    // -------------------------------------------------------------------------

    /**
     * Diagnostics EXPORT — Schema 3 (CR dump only). Returns a READ-ONLY JSON
     * diagnostic dump for a single change request so a dev can inspect it
     * offline. This is NOT engine-replayed — it's a faithful snapshot of the
     * {@link IgaChangeRequestEntity} + its {@link IgaAuthorizationEntity} rows,
     * plus the effective threshold/approver-role the commit gate would apply.
     *
     * <p>The shape (discriminated by {@code "diag_kind":"iga_cr_bundle"} so the
     * offline harness can tell it apart from the token-mint bundle):
     * <pre>
     * { "diag_kind":"iga_cr_bundle", "schema_version":1, "realm_id":"&lt;uuid&gt;",
     *   "cr": { id, entity_type, entity_id, action_type, status, requested_by,
     *           created_at, depends_on:[...], rows_json:&lt;parsed&gt;,
     *           request_model:"&lt;base64 carrier|null&gt;" },
     *   "authorizations": [ { authorized_by, approval, created_at }, ... ],
     *   "threshold": &lt;int&gt;, "approver_role": "&lt;role|null&gt;" }
     * </pre>
     *
     * <p><b>SENSITIVE:</b> contains NO private-key material. {@code request_model}
     * is the public Base64 {@code Policy:1} carrier; {@code approval} dokens are
     * public signatures/usernames. No VVK/VRK private keys, no eddsaPrivateKey.
     */
    @GET
    @Path("change-requests/{id}/diagnostic-bundle")
    @Produces(MediaType.APPLICATION_JSON)
    public Response diagnosticBundle(@PathParam("id") String id) {
        auth.realm().requireManageRealm();

        EntityManager em = getEm();
        IgaChangeRequestEntity cr = em.find(IgaChangeRequestEntity.class, id);
        if (cr == null || !realm.getId().equals(cr.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("diag_kind", "iga_cr_bundle");
        out.put("schema_version", 1);
        out.put("realm_id", cr.getRealmId());

        // --- cr block ---
        Map<String, Object> crMap = new LinkedHashMap<>();
        crMap.put("id", cr.getId());
        crMap.put("entity_type", cr.getEntityType());
        crMap.put("entity_id", cr.getEntityId());
        crMap.put("action_type", cr.getActionType());
        crMap.put("status", cr.getStatus());
        crMap.put("requested_by", cr.getRequestedBy());
        crMap.put("created_at", cr.getCreatedAt());
        crMap.put("depends_on", cr.getDependsOnList());
        // rows_json: faithfully parsed tree (preserves the exact array/object shape).
        JsonNode rows = null;
        try {
            String rj = cr.getRowsJson();
            if (rj != null && !rj.isBlank()) {
                rows = DIAG_MAPPER.readTree(rj);
            }
        } catch (Exception ex) {
            log.warnf(ex, "diagnostic-bundle: failed to parse ROWS_JSON for CR %s (emitting null)", cr.getId());
        }
        crMap.put("rows_json", rows);
        // request_model is ALREADY the Base64 of the Policy:1 carrier (public), or null.
        crMap.put("request_model", cr.getRequestModel());
        out.put("cr", crMap);

        // --- authorizations (IgaAuthorizationEntity rows) ---
        List<Map<String, Object>> authsOut = new ArrayList<>();
        List<IgaAuthorizationEntity> auths = em.createNamedQuery(
                        "IgaAuthorization.findByChangeRequest", IgaAuthorizationEntity.class)
                .setParameter("changeRequestId", cr.getId())
                .getResultList();
        for (IgaAuthorizationEntity a : auths) {
            Map<String, Object> am = new LinkedHashMap<>();
            am.put("authorized_by", a.getAuthorizedBy());
            am.put("approval", a.getApproval());
            am.put("created_at", a.getCreatedAt());
            authsOut.add(am);
        }
        out.put("authorizations", authsOut);

        // --- threshold + approver_role: resolved the SAME way the commit gate does ---
        // threshold via the attestor (delegates to IgaScopeResolver.resolveThreshold for
        // simple; dynamic/ADOPT bypass for tide) — identical to the value commit enforces.
        Integer threshold = null;
        try {
            IgaAttestor attestor = IgaAttestors.resolveAttestor(session, realm);
            threshold = attestor.getThreshold(session, realm, cr);
        } catch (Exception ex) {
            log.warnf(ex, "diagnostic-bundle: threshold resolution failed for CR %s", cr.getId());
        }
        out.put("threshold", threshold);
        out.put("approver_role", resolveApproverRoleForDump(cr));

        return Response.ok(out).build();
    }

    /**
     * Resolve the approver role the commit gate ({@code IgaScopeResolver.requireApprover})
     * would enforce for this CR, collapsed to a single string for the dump.
     * Resolution order mirrors enforcement: the per-scope required-approver-role set
     * (from ROWS_JSON) wins; if empty, fall back to the realm-level {@code iga.approverRole}
     * attribute; null if neither is set (any manage-realm admin may sign). When the scope
     * yields multiple roles, they are comma-joined.
     */
    private String resolveApproverRoleForDump(IgaChangeRequestEntity cr) {
        try {
            IgaScopeResolver.ResolvedScope scope = IgaScopeResolver.resolve(session, realm, cr);
            if (scope != null && !scope.requiredApproverRoles.isEmpty()) {
                return String.join(",", scope.requiredApproverRoles);
            }
        } catch (Exception ex) {
            log.warnf(ex, "diagnostic-bundle: approver-role scope resolution failed for CR %s", cr.getId());
        }
        String realmRole = realm.getAttribute(IgaScopeResolver.ATTR_APPROVER_ROLE);
        return (realmRole != null && !realmRole.isBlank()) ? realmRole.trim() : null;
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
        // toggle-off cancel marks every still-PENDING ADOPT as
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

        // NOTE: the inbound JSON key is "approval", matching the
        // column/field APPROVAL. This payload is the
        // attestationPayload arg to record(), which both attestors ignore (they
        // overwrite with the admin username), so the key name is vestigial.
        String approval = body != null ? (String) body.get("approval") : null;

        UserModel admin = currentUser();
        if (admin == null) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(Map.of("error", "No authenticated admin user"))
                    .build();
        }

        // Reject a duplicate signature from the same admin (SimpleNameAttestor
        // stores the admin's username in APPROVAL — see SimpleNameAttestor.record).
        List<IgaAuthorizationEntity> existing = em.createNamedQuery(
                        "IgaAuthorization.findByChangeRequest", IgaAuthorizationEntity.class)
                .setParameter("changeRequestId", cr.getId())
                .getResultList();
        for (IgaAuthorizationEntity a : existing) {
            if (admin.getUsername() != null && admin.getUsername().equals(a.getApproval())) {
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

        // Refuse the legacy simple-attestor lane for a tide-multiAdmin CR: it cannot
        // collect the enclave doken quorum and must go through POST .../approve.
        Response refusal = refuseLegacyLaneForMultiAdmin(cr);
        if (refusal != null) {
            return refusal;
        }
        IgaAttestor attestor = IgaAttestors.resolveAttestor(session, realm);
        // record() also enforces IgaScopeResolver.requireApprover() internally.
        attestor.record(session, cr, admin, approval);

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

        // Quorum gate for a tide-multiAdmin CR. Approve and commit are now TWO
        // SEPARATE explicit actions: the dokens are collected via prior POST
        // .../approve calls (each persists an IgaAuthorization row on this CR), and
        // .../commit APPLIES the already-quorum-approved CR. We therefore no longer
        // refuse multiAdmin outright — instead we refuse ONLY when the quorum has
        // NOT yet been collected (412 QUORUM_NOT_MET). When quorum IS met, the apply
        // is allowed: commitResolved re-verifies threshold (defense in depth) and
        // drives the per-unit-doken -> VVK signing from the persisted approvals, so
        // .../commit cannot bypass or self-approve the quorum. ADOPT_*, replay and
        // vendor-provisioning sessions are exempt (handled inside the guard, threshold
        // 1 / internal flows). A non-tide / firstAdmin realm passes straight through
        // to commitResolved exactly as before (the guard's multiAdmin check is cheap).
        Response refusal = refuseSubQuorumCommitForMultiAdmin(cr, em);
        if (refusal != null) {
            return refusal;
        }

        // Apply-only: commitResolved re-verifies the dependency / REGEN-ordering /
        // approver-role / threshold gates (defense in depth) and replays the CR.
        // On success it returns 200 with the CR representation; surface a top-level
        // {committed:true, status:"APPROVED", ...} envelope per the decoupled contract
        // (the representation is retained under "changeRequest" for back-compat).
        Response commitResp = commitResolved(cr, em, id);
        if (commitResp.getStatus() != Response.Status.OK.getStatusCode()) {
            // A gate refused (DEPENDENCY_NOT_MET / PENDING_ADMIN_GRANTS / threshold /
            // FORBIDDEN_APPROVER_ROLE / ENTITY_VANISHED / MAPPER_CLAIM_CONFLICT) —
            // surface verbatim. Nothing was applied; the CR stays PENDING.
            return commitResp;
        }
        IgaChangeRequestEntity applied = em.find(IgaChangeRequestEntity.class, id);
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("committed", true);
        resp.put("changeRequestId", id);
        resp.put("status", applied != null ? applied.getStatus() : "APPROVED");
        resp.put("changeRequest", commitResp.getEntity());
        return Response.ok(resp).build();
    }

    /**
     * The full commit pipeline for a CR that has already been fetched, ownership-checked,
     * adopt-resumed, and PENDING-validated by the caller. Extracted so BOTH the standalone
     * {@code POST .../commit} endpoint and the unified {@code POST .../approve} endpoint run
     * the IDENTICAL dependency / REGEN-ordering / approver-role / threshold gates, the same
     * replay + producer-column stamp + convergence + idp-settings re-sign tail. Returns the
     * REST {@link Response} (200 with the updated representation on success, or the relevant
     * 4xx error response from one of the gates).
     *
     * <p>Runs under the SAME per-realm {@link IgaBulkLock} mutex the bulk lane holds. A commit
     * signs a per-(table, owner) SET over the owner's post-change member set and fans that one
     * signature across every row of the owner set, so two commits racing on one owner (two
     * single-CR commits, or a single-CR commit alongside a bulk drain) can interleave
     * read-set / sign / stamp and leave a signature over a set the DB no longer holds. Sharing
     * the bulk task key serialises all three combinations; the loser gets the same 429 contract
     * the bulk endpoint already returns.
     */
    private Response commitResolved(IgaChangeRequestEntity cr, EntityManager em, String id) {
        IgaBulkLock.Result<Response> lockResult = IgaBulkLock.runIfNotRunning(
                session, realm.getId(), () -> {
                    try {
                        return commitResolvedLocked(cr, em, id);
                    } catch (org.tidecloak.iga.attestors.FramingBatchException fbe) {
                        return framingBatchRefusal(fbe);
                    }
                });
        if (!lockResult.isHeld()) {
            return Response.status(429)
                    .entity(Map.of("error",
                            "Another IGA commit is already running for this realm",
                            "realm", realm.getName()))
                    .build();
        }
        return lockResult.getValue();
    }

    /** Set while {@link #commitFramingBatch} is applying a framed group member by member. */
    private boolean framingBatchDriveActive;

    /** The commit pipeline body; always invoked under the per-realm mutex above. */
    private Response commitResolvedLocked(IgaChangeRequestEntity cr, EntityManager em, String id) {
        // A carrier framed over a batch describes the state after EVERY member of that batch
        // has applied, so a member cannot be committed on its own. Drive the whole group here,
        // in one transaction, before the single-CR body runs.
        if (!framingBatchDriveActive) {
            Response batched = commitFramingBatch(cr, em, id);
            if (batched != null) {
                return batched;
            }
        }

        // Fail-closed dependency gate: refuse to commit a CR whose dependsOn
        // set contains any CR not yet APPROVED. This makes the silent-no-op of
        // a dependent replay (REALM_DEFAULT_SCOPE_ADD / ASSIGN_SCOPE applied
        // before its CREATE_CLIENT_SCOPE prerequisite) impossible via the API /
        // bulk / race — independent of any UI gating. Uses 412 PRECONDITION
        // FAILED, consistent with the threshold check below.
        BlockState block = computeBlockState(cr.getDependsOnList());
        if (block.blocked) {
            return Response.status(Response.Status.PRECONDITION_FAILED)
                    .entity(Map.of(
                            "error", "DEPENDENCY_NOT_MET",
                            "message", block.reason,
                            "dependsOn", cr.getDependsOnList()))
                    .build();
        }

        // Fail-closed ordering gate for the multiAdmin threshold flip: a
        // REGEN_ADMIN_POLICY commit writes IGA_ROLE_POLICY.threshold 1->2 (the
        // tide-realm-admin admin-count bump), which instantly RE-GATES every
        // still-PENDING tide-realm-admin GRANT/REVOKE assignment CR from 1/1 to
        // 1/2 — stranding them with a 412 "need 1 more signature". The admin UI
        // commits CRs per-CR in selection order (NOT via bulkAuthorize, so the
        // REGEN-last sort there does not cover this path), so if the policy CR
        // is committed before its grants, the grants strand. Refuse to commit
        // the policy CR while ANY tide-realm-admin assignment CR it covers is
        // still PENDING — forcing the grants to commit first so the threshold
        // bump only lands after they're attested at the old (1) threshold.
        //
        // Commit-only guard: this lives ONLY here, NOT in the SIGN/authorize/
        // approval-model paths and NOT via dependsOn/computeBlockState — so the
        // policy CR's cr.blocked stays false and it remains signable alongside
        // the grants in one enclave session (the exact reason dependsOn was
        // removed for this linkage). Reuses the existing READ-ONLY policy/
        // assignment linkage (same source as relatedPolicyCrId). A no-op for
        // non-REGEN CRs, for firstAdmin/non-tide realms (linkage == none()), and
        // for REGEN CRs whose grants are all already committed (empty set).
        if (TideAttestor.ACTION_REGEN_ADMIN_POLICY.equals(cr.getActionType())) {
            TideAttestor.PolicyCrLinkage policyLinkage;
            try {
                policyLinkage = new TideAttestor(session).resolvePolicyCrLinkage(session, realm);
            } catch (RuntimeException ex) {
                log.warnf(ex, "IGA REGEN_ADMIN_POLICY commit-ordering linkage resolution failed "
                        + "for realm %s (CR %s) — failing closed.", realm.getName(), cr.getId());
                policyLinkage = null;
            }
            if (policyLinkage != null && cr.getId().equals(policyLinkage.policyCrId)
                    && !policyLinkage.assignmentCrIds.isEmpty()) {
                return Response.status(Response.Status.PRECONDITION_FAILED)
                        .entity(Map.of(
                                "error", "PENDING_ADMIN_GRANTS",
                                "message", "Commit the tide-realm-admin grant change request(s) "
                                        + "first — the threshold policy must be applied last.",
                                "pendingAssignmentCrIds", List.copyOf(policyLinkage.assignmentCrIds)))
                        .build();
            }
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
        // ADOPT_* actions are handled by the extension router; every
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
            if (!IgaReplayExtension.tryReplay(session, cr, finalAttestation, attestor.isSetSigned())) {
                // Gate set-fan-out on the resolved attestor: tide → fan the set
                // signature across the whole owner set; simple → per-row (today's
                // exact behaviour, unchanged).
                IgaReplayDispatcher.replay(session, cr, finalAttestation, attestor.isSetSigned());
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
        } catch (IgaMapperConflictException mc) {
            // Layer-C guard (IgaReplayDispatcher): a governed ADD/UPDATE_PROTOCOL_MAPPER would
            // leave the client/scope with two active access-token mappers writing the same claim
            // at equal priority — a non-deterministic collision the Tide ORK rejects at PreSign
            // (today an opaque token-endpoint 500, after the bad config already committed). The
            // guard fired BEFORE the model write, so nothing persisted and the CR stays PENDING;
            // surface a clean 409 the admin can fix (distinct priority, or drop the duplicate)
            // before the next login.
            log.infof("IGA commit refused (mapper conflict, CR %s): %s", cr.getId(), mc.getMessage());
            return Response.status(Response.Status.CONFLICT)
                    .entity(Map.of(
                            "error", "MAPPER_CLAIM_CONFLICT",
                            "owner", mc.getOwner(),
                            "claim", mc.getClaim(),
                            "priority", mc.getPriority(),
                            "mappers", List.of(mc.getMapperA(), mc.getMapperB()),
                            "message", mc.getMessage()))
                    .build();
        }

        // POST-replay per-unit-type column stamp (uniform Design B). The dispatcher /
        // extension has now applied the CR and the live entity exists, so the
        // node/derived/realm producer attestation-units can be signed from committed
        // state and stamped into their DEDICATED per-unit columns (commit bytes ==
        // login bytes by construction). Set-signing (tide) only; a no-op on simple.
        // Runs in the SAME JPA transaction as the replay above.
        // SKIP for DELETE_REALM: the replay above deleted the realm outright, so `realm`
        // is now a removed/detached adapter — resolving modes and stamping producer
        // columns against it is meaningless (and DELETE_REALM frames no producer unit
        // anyway). All other actions (incl. DISABLE_IGA / OFFBOARD_REALM, whose realm
        // survives) still stamp.
        if (attestor instanceof org.tidecloak.iga.attestors.TideAttestor tideAttestor
                && !org.tidecloak.iga.attestors.TideAttestor.ACTION_DELETE_REALM.equals(cr.getActionType())) {
            tideAttestor.stampProducerUnitColumns(session, realm, cr);
            // STRICT byte-provenance for the frozen-carrier lane: the units re-derived from
            // the model must hash to what this CR's approval carrier framed. Only correct at
            // the moment the carrier's whole framing basis has applied, which for the lane
            // that reaches here (a one-member batch, or a legacy carrier) is now. When a
            // multi-member group is being driven, the driver owns the verification and fires
            // each member at ITS OWN basis point instead. Fail-closed.
            if (!framingBatchDriveActive) {
                tideAttestor.verifyFramedUnitHashWhenBasisApplied(session, realm, cr);
            }
            // Coalesced SET-unit stamp: the IDENTICAL call the bulk lane makes after its
            // batch drains, here over the single CR this commit applied. Re-derives the
            // owner's set from the committed model, signs it once, stamps it as the LAST
            // write for the owner, and runs the fail-closed post-stamp verification, so the
            // single-CR lane carries the same invariant rather than relying on its
            // one-CR-per-request session for it. No-op for non-edge action types.
            tideAttestor.stampCoalescedSetUnits(session, realm, List.of(cr));
        }

        // ROOT-cause complete-coverage stamp (uniform Design B). The hand-coded per-CR
        // stampers above cover each adopted node's OWN unit family, but that hand-listing is
        // incomplete (composite_role + 23/39 protocol_mappers, esp. on SYSTEM entities, stayed
        // stub/NULL -> login fail-closed on role_composite_children_set). Once this approval
        // leaves the realm fully-adopted (no pending ADOPT CR remains), run the PROVEN-COMPLETE
        // producer-driven full-closure stamp (the SAME RealmAttestationExporter.export ->
        // signEnvelopesWithFirstAdminVvk -> UnitColumnMapping.stamp the login read consumes), so
        // EVERY login-emitted unit (all 18 types) carries a real 64B sig BY CONSTRUCTION.
        // Idempotent (only NULL/stub columns), firstAdmin+capable gated, fail-closed. Fires
        // whenever a commit drains the last pending ADOPT CR — at MANUAL admin approval AND,
        // since the sign-at-toggle change (2026-06-24), at TOGGLE time via the firstAdmin
        // sign-defaults sweep (which auto-commits the ADOPT set through the bulk core). No-op
        // while ADOPT CRs pend.
        //
        // SKIP for DISABLE_IGA, OFFBOARD_REALM and DELETE_REALM: the convergence does an
        // ORK signing ceremony (on a firstAdmin real-signing realm once no ADOPTs pend).
        // Turning IGA OFF must never be blocked by ORK reachability, and re-stamping
        // producer columns on a realm being disabled is pointless. OFFBOARD_REALM tears
        // the realm down entirely (ragnarok teardown ran in the replay above), so
        // re-stamping its producer columns is likewise pointless and must not block the
        // offboard on ORK reachability. DELETE_REALM removed the realm outright in the
        // replay above — there is no realm left to converge over — so it must be skipped
        // too (convergeAfterCommit would otherwise run against a deleted realm).
        if (!"DISABLE_IGA".equals(cr.getActionType())
                && !org.tidecloak.iga.attestors.TideAttestor.ACTION_OFFBOARD_REALM.equals(cr.getActionType())
                && !org.tidecloak.iga.attestors.TideAttestor.ACTION_DELETE_REALM.equals(cr.getActionType())) {
            org.tidecloak.iga.services.IgaToggleOnBackfill.convergeAfterCommit(session, realm);
        }

        // Re-sign the Tide IdP settings when this commit changed a realm-config
        // field that feeds the enclave-verified VendorSettings (RegOn =
        // realm.isRegistrationAllowed()). The replay above already applied the
        // new value to realm state, so signIdpSettings re-runs over the UPDATED
        // realm and the stored settingsSig stays valid. Fail-closed: a signer
        // failure (no active VRK / ORKs unreachable) throws out of here, rolling
        // back this whole commit tx rather than leaving a stale settingsSig.
        // No-op on Tideless realms (no IdpSettingsSigner provider registered) and
        // on any non-(setRegistrationAllowed) CR. This is the COMMON single-CR /
        // multiAdmin commit tail; bulk has the identical call in processOneCr.
        org.tidecloak.iga.signing.IgaIdpSettingsResign.maybeReSign(session, realm, cr);

        // Also re-sign when this commit changed CLIENT settings that feed the
        // VVK-signed IdP-settings bundle (per-client web origins + the realm's
        // client-origin list). client-settings saves coalesce into per-action CRs
        // (SET_CLIENT_ATTRIBUTE / UPDATE_CLIENT_WEB_ORIGINS / UPDATE_CLIENT_REDIRECT_URIS
        // / UPDATE_CLIENT_PROPERTY / protocol-mapper + scope-mapping writes); committing
        // any of them can leave the stored clientAuth:* signatures stale — this replaces
        // the manual "re-sign settings" step admins ran after a client save. This is the
        // single-CR commit lane (commit() and /approve via commitIfReady), which applies
        // exactly ONE CR, so at most one re-sign fires here; the bulk lane coalesces to
        // one re-sign per batch (see runBulkLocked). Disjoint from the RegOn predicate
        // above (SET_REALM_CONFIG is not a client action type), so no double-sign. Same
        // fail-closed / Tideless-no-op contract as maybeReSign (a signer failure throws
        // out of here and rolls this commit tx back rather than leaving stale sigs).
        if (org.tidecloak.iga.signing.IgaIdpSettingsResign.changesClientSignedSetting(cr)) {
            org.tidecloak.iga.signing.IgaIdpSettingsResign.reSignForClientSettings(session, realm);
        }

        IgaChangeRequestService service = getService();
        IgaChangeRequestEntity updated = em.find(IgaChangeRequestEntity.class, id);
        return Response.ok(toRepresentation(updated, service)).build();
    }

    // -------------------------------------------------------------------------
    // Framing batches: committing a group whose carriers were framed together
    // -------------------------------------------------------------------------

    /**
     * Apply the whole framing batch {@code cr} belongs to, in one transaction, or refuse.
     * Returns {@code null} when {@code cr} carries no multi-member batch, in which case the
     * caller runs the ordinary single-CR pipeline.
     *
     * <p>A multiAdmin approval carrier freezes the unit bytes the enclave framed, and phase 1
     * frames them over the state after EVERY currently-approvable PENDING change request that
     * perturbs the same owner set. That is what lets two change requests against one owner
     * carry identical bytes for it, but it also means a member's bytes describe the
     * post-batch model, so committing one on its own would leave the owner set signed for a
     * state the database does not hold. The group therefore applies together:
     *
     * <ul>
     *   <li>a member that is already APPROVED has applied, which is what the framing assumed;</li>
     *   <li>a member that is DENIED / CANCELLED / gone means the framing describes a state that
     *       will never exist: refuse fail-closed and invalidate the group's carriers so the
     *       admin re-approves the survivors, which re-frames them correctly;</li>
     *   <li>a member that is PENDING but short of quorum or dependency-blocked is a WAIT, not a
     *       corruption: refuse with 412 and leave every carrier intact so the collected dokens
     *       are not thrown away.</li>
     * </ul>
     *
     * <p>Members are applied in the persisted (deterministic bulk commit) order, each through
     * the ordinary single-CR pipeline, so every existing gate still runs per member. Each
     * member's own byte-provenance check runs immediately after its own replay, which is the
     * state its framing projected.
     */
    private Response commitFramingBatch(IgaChangeRequestEntity cr, EntityManager em, String id) {
        List<String> closure = framingBatchClosure(em, cr);
        if (closure.size() <= 1) {
            return null;
        }
        String batchId = TideAttestor.framingBatchId(realm.getId(), closure);

        List<IgaChangeRequestEntity> toCommit = new ArrayList<>();
        List<String> broken = new ArrayList<>();
        List<Map<String, Object>> notReady = new ArrayList<>();
        IgaAttestor attestor = IgaAttestors.resolveAttestor(session, realm);
        for (String memberId : closure) {
            IgaChangeRequestEntity member = em.find(IgaChangeRequestEntity.class, memberId);
            if (member == null || !realm.getId().equals(member.getRealmId())) {
                broken.add(memberId);
                continue;
            }
            if ("APPROVED".equals(member.getStatus())) {
                continue;
            }
            if (!"PENDING".equals(member.getStatus())) {
                broken.add(memberId);
                continue;
            }
            BlockState memberBlock = computeBlockState(member.getDependsOnList());
            int memberThreshold = attestor.getThreshold(session, realm, member);
            int memberAuthCount = authCount(em, member);
            if (memberBlock.blocked || memberAuthCount < memberThreshold) {
                Map<String, Object> pendingMember = new LinkedHashMap<>();
                pendingMember.put("crId", memberId);
                pendingMember.put("actionType", member.getActionType());
                pendingMember.put("authCount", memberAuthCount);
                pendingMember.put("threshold", memberThreshold);
                if (memberBlock.blocked) {
                    pendingMember.put("blocked", memberBlock.reason);
                }
                notReady.add(pendingMember);
                continue;
            }
            toCommit.add(member);
        }

        if (!broken.isEmpty()) {
            log.warnf("IGA framing batch %s in realm %s is broken: member(s) %s are no longer "
                            + "approvable, so every carrier framed with them describes a state that "
                            + "will never exist. Invalidating the group; the survivors must be "
                            + "re-approved.", batchId, realm.getName(), broken);
            new TideAttestor(session).invalidateFramingBatch(session, realm, em, cr);
            return Response.status(Response.Status.CONFLICT)
                    .entity(Map.of(
                            "error", org.tidecloak.iga.attestors.FramingBatchException.CODE_BATCH_BROKEN,
                            "message", "Another change request approved alongside this one is no longer "
                                    + "approvable, so the approvals no longer describe the change being "
                                    + "made. The approvals have been cleared. Re-approve the remaining "
                                    + "change requests.",
                            "batchId", batchId,
                            "batch", closure,
                            "brokenMembers", broken))
                    .build();
        }
        if (!notReady.isEmpty()) {
            return Response.status(Response.Status.PRECONDITION_FAILED)
                    .entity(Map.of(
                            "error", "FRAMING_BATCH_NOT_READY",
                            "message", "This change request was approved together with other change "
                                    + "requests against the same membership set; they all apply at once. "
                                    + "Approve the remaining change request(s) first.",
                            "batchId", batchId,
                            "batch", closure,
                            "pendingMembers", notReady))
                    .build();
        }

        // Byte-provenance for the group. A member's carrier describes the model after its
        // WHOLE framing batch has applied, so verifying it right after its own replay would
        // compare against pre + that member's delta and mismatch by construction for every
        // member but the last. Each member is instead verified at the point its own basis
        // first becomes fully applied, which the pass below re-evaluates after every replay,
        // and the final requireAll refuses to let any member through unverified.
        TideAttestor batchAttestor = attestor instanceof TideAttestor tide ? tide : null;
        java.util.Set<String> verified = new java.util.LinkedHashSet<>();
        framingBatchDriveActive = true;
        try {
            for (IgaChangeRequestEntity member : toCommit) {
                Response memberResp = commitResolvedLocked(member, em, member.getId());
                if (memberResp.getStatus() != Response.Status.OK.getStatusCode()) {
                    // A member's own gate refused after earlier members already applied in this
                    // transaction. Roll the whole group back rather than leave it half applied,
                    // and surface that member's error verbatim.
                    session.getTransactionManager().setRollbackOnly();
                    log.warnf("IGA framing batch %s in realm %s aborted: member %s refused with %d.",
                            batchId, realm.getName(), member.getId(), memberResp.getStatus());
                    return memberResp;
                }
                if (batchAttestor != null) {
                    batchAttestor.verifyFramedUnitsWithAppliedBasis(session, realm, toCommit, verified);
                }
            }
            if (batchAttestor != null) {
                batchAttestor.requireAllFramedUnitsVerified(toCommit, verified);
            }
        } finally {
            framingBatchDriveActive = false;
        }

        log.infof("IGA framing batch %s committed as one operation in realm %s (%d member(s): %s).",
                batchId, realm.getName(), toCommit.size(), closure);
        IgaChangeRequestEntity updated = em.find(IgaChangeRequestEntity.class, id);
        return Response.ok(toRepresentation(updated, getService())).build();
    }

    /**
     * The transitive closure of {@code cr}'s framing batch, in the deterministic bulk commit
     * order: {@code cr}'s own persisted member list, plus the member list of every PENDING
     * member reachable from it.
     *
     * <p>The closure is needed because framing batches nest rather than partition. A change
     * request framed while it was alone carries a one-member batch; one filed against the same
     * owner afterwards frames over both. Committing the later one must therefore apply the
     * earlier one first, and it is the closure (not either list alone) that names everything
     * the resulting model state depends on.
     */
    private List<String> framingBatchClosure(EntityManager em, IgaChangeRequestEntity cr) {
        List<String> closure = new ArrayList<>(cr.getRequestBatchList());
        if (closure.isEmpty()) {
            return closure;
        }
        if (!closure.contains(cr.getId())) {
            closure.add(cr.getId());
        }
        List<IgaChangeRequestEntity> resolved = new ArrayList<>();
        for (int i = 0; i < closure.size() && i < FRAMING_BATCH_CLOSURE_LIMIT; i++) {
            IgaChangeRequestEntity member = em.find(IgaChangeRequestEntity.class, closure.get(i));
            if (member == null || !realm.getId().equals(member.getRealmId())) {
                continue;
            }
            resolved.add(member);
            for (String reachable : member.getRequestBatchList()) {
                if (!closure.contains(reachable)) {
                    closure.add(reachable);
                }
            }
        }
        // Order the closure the way the batch was framed and the way a bulk drain applies:
        // oldest first, DELETE_REALM strictly last, REGEN_ADMIN_POLICY last among the rest.
        // Ids that no longer resolve keep their discovery position; the caller reports them as
        // broken members rather than silently dropping them.
        resolved.sort(Comparator.comparing(IgaChangeRequestEntity::getCreatedAt,
                Comparator.nullsLast(Comparator.<Long>naturalOrder())));
        resolved.sort(TideAttestor.BULK_COMMIT_ORDER);
        List<String> ordered = new ArrayList<>(TideAttestor.framingBatchIds(resolved));
        for (String memberId : closure) {
            if (!ordered.contains(memberId)) {
                ordered.add(memberId);
            }
        }
        return ordered;
    }

    /** Upper bound on the framing-batch closure walk. */
    private static final int FRAMING_BATCH_CLOSURE_LIMIT = 200;

    /**
     * Bulk-lane counterpart of {@link #commitFramingBatch}: record a refusal for every
     * candidate whose framed group would not apply IN FULL in this drain.
     *
     * <p>A framed group's members carry bytes describing the model after all of them, so a
     * drain that would commit only part of the group must commit none of it. A member counts
     * as covered when it is already APPROVED (it has applied) or is itself a candidate that is
     * unblocked and at quorum. Anything else refuses the whole group, before any replay, so
     * nothing is half applied. Carriers are NOT invalidated here: the group is intact, it just
     * is not all present, and throwing away collected dokens would make the admin re-run the
     * enclave for nothing.
     */
    private void refuseIncompleteFramingBatches(List<IgaChangeRequestEntity> candidates,
                                                Map<String, Map<String, Object>> refusals) {
        EntityManager em = getEm();
        IgaAttestor attestor = IgaAttestors.resolveAttestor(session, realm);
        Map<String, IgaChangeRequestEntity> candidateById = new LinkedHashMap<>();
        for (IgaChangeRequestEntity candidate : candidates) {
            candidateById.put(candidate.getId(), candidate);
        }
        for (IgaChangeRequestEntity candidate : candidates) {
            if (candidate.getRequestBatchList().isEmpty() || refusals.containsKey(candidate.getId())) {
                continue;
            }
            List<String> closure = framingBatchClosure(em, candidate);
            if (closure.size() <= 1) {
                continue;
            }
            List<String> uncovered = new ArrayList<>();
            for (String memberId : closure) {
                IgaChangeRequestEntity member = em.find(IgaChangeRequestEntity.class, memberId);
                if (member != null && "APPROVED".equals(member.getStatus())) {
                    continue;
                }
                if (member == null || !"PENDING".equals(member.getStatus())
                        || !candidateById.containsKey(memberId)
                        || computeBlockState(member.getDependsOnList()).blocked
                        || authCount(em, member) < attestor.getThreshold(session, realm, member)) {
                    uncovered.add(memberId);
                }
            }
            if (uncovered.isEmpty()) {
                continue;
            }
            String batchId = TideAttestor.framingBatchId(realm.getId(), closure);
            for (String memberId : closure) {
                if (!candidateById.containsKey(memberId)) {
                    continue;
                }
                Map<String, Object> refusal = new LinkedHashMap<>();
                refusal.put("error", "FRAMING_BATCH_INCOMPLETE");
                refusal.put("message", "This change request was approved together with other change "
                        + "requests against the same membership set; they all apply at once. Approve "
                        + "the remaining change request(s), then commit them together.");
                refusal.put("batchId", batchId);
                refusal.put("batch", closure);
                refusal.put("uncoveredMembers", uncovered);
                refusals.put(memberId, refusal);
            }
        }
    }

    /**
     * Convert a fail-closed framing-batch refusal into a 409, roll the commit back, and clear
     * the group's carriers OUT OF BAND so the invalidation survives that rollback (the same
     * separate-transaction device the capture path uses to persist a change request through
     * its own rollback). The admin re-approves, which re-frames against current state.
     */
    private Response framingBatchRefusal(org.tidecloak.iga.attestors.FramingBatchException fbe) {
        session.getTransactionManager().setRollbackOnly();
        log.warnf(fbe, "IGA commit refused (framing batch %s, change request %s): %s",
                fbe.getBatchId(), fbe.getChangeRequestId(), fbe.getMessage());
        invalidateFramingBatchOutOfBand(fbe.getChangeRequestId());
        return Response.status(Response.Status.CONFLICT)
                .entity(Map.of(
                        "error", fbe.getCode(),
                        "message", "The approvals collected for this change request no longer describe "
                                + "the change being made, so committing them would leave the affected "
                                + "membership unverifiable. The approvals have been cleared. Re-approve "
                                + "to sign the current state.",
                        "batchId", String.valueOf(fbe.getBatchId()),
                        "changeRequestId", fbe.getChangeRequestId(),
                        "detail", String.valueOf(fbe.getMessage())))
                .build();
    }

    /** {@link TideAttestor#invalidateFramingBatch} on a fresh transaction. */
    private void invalidateFramingBatchOutOfBand(String crId) {
        KeycloakModelUtils.runJobInTransaction(session.getKeycloakSessionFactory(), job -> {
            RealmModel jobRealm = job.realms().getRealm(realm.getId());
            if (jobRealm == null) {
                return;
            }
            job.getContext().setRealm(jobRealm);
            EntityManager jobEm = job.getProvider(JpaConnectionProvider.class).getEntityManager();
            IgaChangeRequestEntity jobCr = jobEm.find(IgaChangeRequestEntity.class, crId);
            if (jobCr == null) {
                return;
            }
            new TideAttestor(job).invalidateFramingBatch(job, jobRealm, jobEm, jobCr);
        });
    }

    // -------------------------------------------------------------------------
    // multiAdmin two-phase approval (M1 doken-collection seam)
    //
    // GET  /iga/change-requests/{id}/approval-model  — phase 1: build + return the
    //      per-CR Policy:1 ModelRequest the admin's browser enclave (Heimdall)
    //      approves. The admin-UI hands ONLY the serialized request to the enclave.
    // POST /iga/change-requests/{id}/approval-model  — phase 2: accept the
    //      doken-embedded serialized ModelRequest back, persist it, and record the
    //      approving admin toward threshold (dedup once-per-admin).
    //
    // Both are multiAdmin-only — firstAdmin keeps its single-phase authorize/commit
    // path untouched. A firstAdmin / Tideless / simple realm gets 409 CONFLICT so the
    // caller falls back to the single-phase flow. The real Midgard.SignModel(Policy:1)
    // over the collected-doken carrier runs at COMMIT time (M2 —
    // TideAttestor.combineFinal -> signMultiAdminUnitViaPolicy), capability-gated +
    // fail-closed; these two endpoints only build + collect the carrier and count
    // approvals toward threshold.
    // -------------------------------------------------------------------------

    /**
     * Phase 1 — build + persist the per-CR {@code Policy:1} approval
     * {@link org.midgard.models.ModelRequest} and return its Base64 serialization for
     * the admin's browser enclave to approve. multiAdmin-only.
     */
    @GET
    @Path("change-requests/{id}/approval-model")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getApprovalModel(@PathParam("id") String id) {
        auth.realm().requireManageRealm();

        EntityManager em = getEm();
        IgaChangeRequestEntity cr = em.find(IgaChangeRequestEntity.class, id);
        if (cr == null || !realm.getId().equals(cr.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        if (!"PENDING".equals(cr.getStatus())) {
            return Response.status(Response.Status.CONFLICT)
                    .entity(Map.of("error", "Change request is not in PENDING state",
                            "crStatus", cr.getStatus()))
                    .build();
        }
        // multiAdmin-only gate. firstAdmin / Tideless realms have no two-phase ceremony.
        if (!TideAttestor.isMultiAdminMode(session, realm)) {
            return Response.status(Response.Status.CONFLICT)
                    .entity(Map.of("error", "NOT_MULTI_ADMIN",
                            "message", "Two-phase approval applies only to multiAdmin-mode realms; "
                                    + "use the single-phase authorize/commit flow"))
                    .build();
        }
        IgaAttestor attestor = IgaAttestors.resolveAttestor(session, realm);
        if (!(attestor instanceof TideAttestor tide)) {
            // Defensive: multiAdmin mode implies the tide attestor — but never NPE if not.
            return Response.status(Response.Status.CONFLICT)
                    .entity(Map.of("error", "NOT_TIDE_ATTESTOR",
                            "message", "Resolved attestor does not support the two-phase approval ceremony"))
                    .build();
        }
        try {
            String serializedModel = tide.buildMultiAdminApprovalModel(session, realm, cr);
            // Shape mirrors the gold-reference response: the serialized request the
            // admin-UI hands to the enclave, keyed by CR id.
            return Response.ok(Map.of(
                            "changeRequestId", cr.getId(),
                            "actionType", cr.getActionType(),
                            "requiresApprovalPopup", true,
                            "requestModel", serializedModel))
                    .build();
        } catch (RuntimeException rex) {
            log.warnf(rex, "IGA multiAdmin approval (phase 1): failed to build approval model for CR %s", id);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of("error", "APPROVAL_MODEL_BUILD_FAILED",
                            "message", String.valueOf(rex.getMessage())))
                    .build();
        }
    }

    /**
     * Phase 2 — accept the doken-embedded serialized {@code ModelRequest} back from the
     * admin's enclave, persist it on the CR carrier, and record the approving admin
     * toward threshold (dedup once-per-admin). multiAdmin-only.
     *
     * <p>Body: {@code {"requestModel": "<base64 doken-embedded ModelRequest.Encode()>"}}.
     */
    @POST
    @Path("change-requests/{id}/approval-model")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response submitApprovalModel(@PathParam("id") String id, Map<String, Object> body) {
        auth.realm().requireManageRealm();

        EntityManager em = getEm();
        IgaChangeRequestEntity cr = em.find(IgaChangeRequestEntity.class, id);
        if (cr == null || !realm.getId().equals(cr.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        if (!"PENDING".equals(cr.getStatus())) {
            return Response.status(Response.Status.CONFLICT)
                    .entity(Map.of("error", "Change request is not in PENDING state",
                            "crStatus", cr.getStatus()))
                    .build();
        }
        if (!TideAttestor.isMultiAdminMode(session, realm)) {
            return Response.status(Response.Status.CONFLICT)
                    .entity(Map.of("error", "NOT_MULTI_ADMIN",
                            "message", "Two-phase approval applies only to multiAdmin-mode realms; "
                                    + "use the single-phase authorize/commit flow"))
                    .build();
        }
        String requestModel = body != null ? (String) body.get("requestModel") : null;
        if (requestModel == null || requestModel.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "requestModel is required (the doken-embedded "
                            + "serialized ModelRequest returned by the enclave)"))
                    .build();
        }
        UserModel admin = currentUser();
        if (admin == null) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(Map.of("error", "No authenticated admin user"))
                    .build();
        }
        IgaAttestor attestor = IgaAttestors.resolveAttestor(session, realm);
        if (!(attestor instanceof TideAttestor tide)) {
            return Response.status(Response.Status.CONFLICT)
                    .entity(Map.of("error", "NOT_TIDE_ATTESTOR",
                            "message", "Resolved attestor does not support the two-phase approval ceremony"))
                    .build();
        }
        boolean recorded;
        try {
            recorded = tide.acceptMultiAdminApprovalModel(session, realm, cr, requestModel, admin);
        } catch (ForbiddenException fe) {
            // Approver-role gate refused this admin for this CR (raised inside record()).
            return Response.status(Response.Status.FORBIDDEN)
                    .entity(Map.of("error", "FORBIDDEN_APPROVER_ROLE",
                            "message", String.valueOf(fe.getMessage())))
                    .build();
        } catch (RuntimeException rex) {
            log.warnf(rex, "IGA multiAdmin approval (phase 2): failed to accept approval model for CR %s", id);
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "APPROVAL_MODEL_INVALID",
                            "message", String.valueOf(rex.getMessage())))
                    .build();
        }
        // Report the current approval count vs threshold so the caller knows whether the
        // CR is ready for commit (the commit endpoint still does the real gate).
        List<IgaAuthorizationEntity> all = em.createNamedQuery(
                        "IgaAuthorization.findByChangeRequest", IgaAuthorizationEntity.class)
                .setParameter("changeRequestId", cr.getId())
                .getResultList();
        int threshold = tide.getThreshold(session, realm, cr);
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("changeRequestId", cr.getId());
        resp.put("recorded", recorded);
        resp.put("authCount", all.size());
        resp.put("threshold", threshold);
        resp.put("readyForCommit", all.size() >= threshold);
        return Response.ok(resp).build();
    }

    // -------------------------------------------------------------------------
    // POST /iga/change-requests/{id}/approve  — UNIFIED approval endpoint
    //
    // ONE endpoint the admin-UI Approvals inbox calls. The server decides which
    // ceremony applies (it knows the attestor + firstAdmin/multiAdmin mode); the
    // client no longer probes approval-model then 409-falls-back to authorize.
    //
    // Branching (server-side):
    //   1. SimpleNameAttestor (Tideless) OR TideAttestor firstAdmin
    //      → record the caller's authorization INLINE (same dedup + approver-role
    //        gate as POST .../authorize), then if authCount >= threshold run the
    //        FULL commit pipeline (commitResolved — identical to POST .../commit).
    //        Single round-trip, no enclave, no carrier.
    //        Response: {mode:"recorded", committed:bool, authCount, threshold,
    //                   changeRequestId, crStatus}.
    //
    //   2. TideAttestor multiAdmin — inherently two-phase (the operator must sign
    //      the Policy:1 carrier in the browser enclave). SAME endpoint, called twice:
    //      a. NO signed doken in the body (phase 1) → build + persist the per-CR
    //         Policy:1 carrier and return it for the enclave (what GET approval-model
    //         did). Response: {mode:"needs-approval", requestModel:<base64>,
    //                          authCount, threshold, changeRequestId, actionType}.
    //      b. signed doken in the body (phase 2, body.requestModel set) → record it
    //         toward threshold (what POST approval-model did), then if authCount >=
    //         threshold run commitResolved. Response: {mode:"recorded", committed,
    //         authCount, threshold, changeRequestId, crStatus}.
    //
    // Security semantics are IDENTICAL to the endpoints this subsumes: the
    // multiAdmin doken verification (acceptMultiAdminApprovalModel), the Policy:1
    // carrier (buildMultiAdminApprovalModel), the per-admin dedup, the threshold
    // accumulation, the approver-role gate, and the full commit replay.
    //
    // This is now the SOLE admin-UI lane for authorizing AND committing a CR: both
    // admin UIs (the tide-console SPA and the keycloak-IGA console) drive every CR
    // authorize/commit through POST .../approve. The lower-level POST .../authorize,
    // POST .../commit and the approval-model handlers are PRESERVED only as
    // deprecated / internally-guarded endpoints (server-side reuse such as
    // bulkAuthorize's per-CR commit gate, plus back-compat) — no admin-UI caller
    // hits them any more. Because /approve is the sole lane, the firstAdmin/simple
    // case where THIS admin already signed an at-quorum-but-blocked-then-unblocked
    // CR must still be able to drive the commit gate from /approve (it has no
    // legacy /commit fall-back to lean on): see the alreadySigned fall-through below.
    // -------------------------------------------------------------------------

    @POST
    @Path("change-requests/{id}/approve")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response approve(@PathParam("id") String id, Map<String, Object> body) {
        auth.realm().requireManageRealm();

        EntityManager em = getEm();
        IgaChangeRequestEntity cr = em.find(IgaChangeRequestEntity.class, id);
        if (cr == null || !realm.getId().equals(cr.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        // ADOPT_* CRs are resumable from CANCELLED — mirror authorize()/commit().
        boolean isAdoptResume = isAdoptAction(cr.getActionType())
                && "CANCELLED".equals(cr.getStatus());
        if (isAdoptResume) {
            cr.setStatus("PENDING");
            cr.setResolvedAt(null);
            log.infof("IGA approve: resuming CANCELLED ADOPT CR %s (action=%s) — flipping back to PENDING",
                    cr.getId(), cr.getActionType());
        }
        if (!"PENDING".equals(cr.getStatus())) {
            return Response.status(Response.Status.CONFLICT)
                    .entity(Map.of("error", "Change request is not in PENDING state",
                            "crStatus", cr.getStatus()))
                    .build();
        }

        UserModel admin = currentUser();
        if (admin == null) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(Map.of("error", "No authenticated admin user"))
                    .build();
        }

        IgaAttestor attestor = IgaAttestors.resolveAttestor(session, realm);
        boolean multiAdmin = (attestor instanceof TideAttestor)
                && TideAttestor.isMultiAdminMode(session, realm);

        // ---------------------------------------------------------------------
        // multiAdmin lane — two-phase enclave ceremony over the SAME endpoint.
        // ---------------------------------------------------------------------
        if (multiAdmin) {
            TideAttestor tide = (TideAttestor) attestor;
            String requestModel = body != null ? (String) body.get("requestModel") : null;

            if (requestModel == null || requestModel.isBlank()) {
                // Phase 1: build + persist the Policy:1 carrier for the enclave.
                try {
                    String serializedModel = tide.buildMultiAdminApprovalModel(session, realm, cr);
                    int threshold = tide.getThreshold(session, realm, cr);
                    Map<String, Object> resp = new LinkedHashMap<>();
                    resp.put("mode", "needs-approval");
                    resp.put("changeRequestId", cr.getId());
                    resp.put("actionType", cr.getActionType());
                    resp.put("requestModel", serializedModel);
                    resp.put("authCount", authCount(em, cr));
                    resp.put("threshold", threshold);
                    return Response.ok(resp).build();
                } catch (RuntimeException rex) {
                    log.warnf(rex, "IGA approve (multiAdmin phase 1): failed to build approval model for CR %s", id);
                    return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                            .entity(Map.of("error", "APPROVAL_MODEL_BUILD_FAILED",
                                    "message", String.valueOf(rex.getMessage())))
                            .build();
                }
            }

            // Phase 2: record the signed doken toward threshold, then AUTO-COMMIT if
            // the quorum is now met (the "Authorize" button = approve AND commit). The
            // doken is persisted on the CR's authorization entities and, once the
            // quorum is collected, commitIfReady drives the per-unit-doken -> VVK
            // signed apply (commitResolved) inline. An already-signed caller is a
            // NO-OP record (acceptMultiAdminApprovalModel dedups once-per-admin and
            // returns false), but still falls through to commitIfReady so a final
            // approver re-hitting Authorize on a now-at-quorum CR applies it.
            try {
                tide.acceptMultiAdminApprovalModel(session, realm, cr, requestModel, admin);
            } catch (ForbiddenException fe) {
                return Response.status(Response.Status.FORBIDDEN)
                        .entity(Map.of("error", "FORBIDDEN_APPROVER_ROLE",
                                "message", String.valueOf(fe.getMessage())))
                        .build();
            } catch (RuntimeException rex) {
                log.warnf(rex, "IGA approve (multiAdmin phase 2): failed to accept approval model for CR %s", id);
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(Map.of("error", "APPROVAL_MODEL_INVALID",
                                "message", String.valueOf(rex.getMessage())))
                        .build();
            }
            return commitIfReady(cr, em, id, attestor);
        }

        // ---------------------------------------------------------------------
        // firstAdmin / Tideless / simple lane — inline record, then commit if ready
        // (the "Authorize" button = approve AND commit). Mirrors POST .../authorize
        // (dedup + record via attestor, which enforces the approver-role gate
        // internally).
        //
        // Dedup, but NOT a hard 409: if THIS admin has already signed the CR there
        // is nothing new to record, yet the CR may be at-quorum-but-not-yet-applied
        // (e.g. it met threshold while BLOCKED by a dependency and is now unblocked).
        // In that case the caller needs the commit gate RE-RUN, not a 409. So when
        // the caller already signed we SKIP the re-record and fall straight through
        // to commitIfReady, which idempotently re-checks threshold + the dependency /
        // REGEN-ordering / approver-role gates and applies the change if it is now
        // committable (and is a clean no-op — committed:false — if it is not). This
        // is what lets the SPA's "Authorize" affordance drive a once-blocked
        // firstAdmin CR to apply through /approve alone. The separate POST .../commit
        // lane (apply-only) remains available for the "Commit" button.
        // ---------------------------------------------------------------------
        boolean alreadySigned = false;
        for (IgaAuthorizationEntity a : authorizationsOf(em, cr)) {
            if (admin.getUsername() != null && admin.getUsername().equals(a.getApproval())) {
                alreadySigned = true;
                break;
            }
            if (admin.getId() != null && admin.getId().equals(a.getAuthorizedBy())) {
                alreadySigned = true;
                break;
            }
        }
        if (!alreadySigned) {
            String approval = body != null ? (String) body.get("approval") : null;
            try {
                // record() enforces IgaScopeResolver.requireApprover() internally.
                attestor.record(session, cr, admin, approval);
            } catch (ForbiddenException fe) {
                return Response.status(Response.Status.FORBIDDEN)
                        .entity(Map.of("error", "FORBIDDEN_APPROVER_ROLE",
                                "message", String.valueOf(fe.getMessage())))
                        .build();
            }
        }
        return commitIfReady(cr, em, id, attestor);
    }

    /**
     * After an authorization has been recorded toward {@code cr} (or recognised as
     * already recorded — a no-op re-approve), commit it IF the threshold is now met
     * (running the full {@link #commitResolved} pipeline) and report the outcome in
     * the unified {@code /approve} response shape. This is the "Authorize" button =
     * approve AND commit behavior. When the threshold is not yet met, return
     * {@code committed:false} so the caller knows the approval was recorded but the
     * change is still queued. Shared by both the firstAdmin/simple and multiAdmin
     * phase-2 lanes of {@link #approve}.
     *
     * <p>Response: {@code {mode:"recorded", changeRequestId, committed, authCount,
     * threshold, readyToCommit:(authCount>=threshold), status}}. {@code committed} is
     * true iff the apply ran at quorum; {@code readyToCommit} tells the UI the quorum
     * is met. The apply runs the IDENTICAL {@link #commitResolved} gates (threshold
     * re-check, dependency / REGEN-ordering / approver-role), so {@code /approve}
     * can never apply sub-quorum.
     */
    private Response commitIfReady(IgaChangeRequestEntity cr, EntityManager em, String id, IgaAttestor attestor) {
        int authCount = authCount(em, cr);
        int threshold = attestor.getThreshold(session, realm, cr);

        boolean committed = false;
        // Re-read the CR so the reported status reflects any adopt-resume PENDING flip
        // performed earlier in approve().
        IgaChangeRequestEntity pre = em.find(IgaChangeRequestEntity.class, id);
        String crStatus = pre != null ? pre.getStatus() : cr.getStatus();
        if (authCount >= threshold) {
            Response commitResp = commitResolved(cr, em, id);
            if (commitResp.getStatus() != Response.Status.OK.getStatusCode()
                    && !isFramingBatchWait(commitResp)) {
                // A commit gate refused (dependency / REGEN-ordering / approver-role /
                // threshold / ENTITY_VANISHED). Surface that error verbatim: the
                // authorization was recorded, but the change is not yet applied.
                return commitResp;
            }
            if (commitResp.getStatus() == Response.Status.OK.getStatusCode()) {
                committed = true;
                IgaChangeRequestEntity post = em.find(IgaChangeRequestEntity.class, id);
                crStatus = post != null ? post.getStatus() : "APPROVED";
                // authCount is unchanged by commit; threshold likewise.
            }
        }

        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("mode", "recorded");
        resp.put("changeRequestId", id);
        resp.put("committed", committed);
        resp.put("authCount", authCount);
        resp.put("threshold", threshold);
        resp.put("readyToCommit", authCount >= threshold);
        resp.put("status", crStatus);
        return Response.ok(resp).build();
    }

    /**
     * Is this commit refusal the "the rest of the framed group is not approved yet" wait
     * state? That is not an error for the approve lane: the caller's approval WAS recorded,
     * and the group applies once its last member reaches quorum. Reporting it as
     * {@code committed:false} keeps the Authorize button behaving as it does for any other
     * sub-quorum approval, instead of surfacing a failure for every member but the last.
     */
    private static boolean isFramingBatchWait(Response commitResp) {
        return commitResp.getStatus() == Response.Status.PRECONDITION_FAILED.getStatusCode()
                && commitResp.getEntity() instanceof Map<?, ?> body
                && "FRAMING_BATCH_NOT_READY".equals(body.get("error"));
    }

    /** All authorization rows currently recorded against a CR. */
    private List<IgaAuthorizationEntity> authorizationsOf(EntityManager em, IgaChangeRequestEntity cr) {
        return em.createNamedQuery("IgaAuthorization.findByChangeRequest", IgaAuthorizationEntity.class)
                .setParameter("changeRequestId", cr.getId())
                .getResultList();
    }

    /** Count of authorizations currently recorded against a CR. */
    private int authCount(EntityManager em, IgaChangeRequestEntity cr) {
        return authorizationsOf(em, cr).size();
    }

    // -------------------------------------------------------------------------
    // POST /iga/change-requests/bulk-authorize
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
    // Response is buffered JSON. Streaming was rejected because (1) KC's JAX-RS stack has no
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
        // Optional per-CR id selector. When present + non-empty it takes
        // precedence over actionTypeIn: candidates are exactly those PENDING CRs
        // whose id is listed. The firstAdmin auto-commit sweep uses this because
        // eligibility is decided PER CR (a single action type may hold both
        // eligible and ineligible CRs — e.g. a system ADOPT_CLIENT vs an
        // admin-authored ADOPT_CLIENT), so an action-type-only drain would
        // over-commit. Existing callers (admin-UI bulk-approve) keep using
        // actionTypeIn and are byte-for-byte unaffected.
        List<String> crIdIn = new ArrayList<>();
        Object crIdInObj = body.get("crIdIn");
        if (crIdInObj instanceof List<?>) {
            for (Object o : (List<?>) crIdInObj) {
                if (o == null) continue;
                String s = o.toString();
                if (!s.isBlank()) crIdIn.add(s);
            }
        }
        boolean byId = !crIdIn.isEmpty();

        List<String> actionTypes = new ArrayList<>();
        Object actionTypeInObj = body.get("actionTypeIn");
        if (!byId) {
            if (!(actionTypeInObj instanceof List<?>) || ((List<?>) actionTypeInObj).isEmpty()) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(Map.of("error",
                                "actionTypeIn is required and must be a non-empty list of action-type strings"))
                        .build();
            }
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

        IgaBulkLock.Result<Map<String, Object>> lockResult;
        try {
            lockResult = runBulkLocked(admin, byId, crIdIn, actionTypes, olderThan, limit,
                    /*deferConverge*/ false);
        } catch (org.tidecloak.iga.attestors.FramingBatchException fbe) {
            // A framed group's carrier does not describe what this drain produced. It is not a
            // per-CR outcome (earlier members are already applied in this transaction), so the
            // whole drain rolls back and the group is invalidated out of band.
            return framingBatchRefusal(fbe);
        }

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
     * Internal, NON-HTTP bulk authorize+commit entry used by the firstAdmin
     * sign-at-toggle sweep ({@code TideAdminCompatResource.runFirstAdminAutoCommitSweep}).
     *
     * <p>Differs from the public {@link #bulkAuthorize} endpoint in exactly two ways:
     * (1) it does NOT call {@code auth.realm().requireManageRealm()} — the caller is
     * the toggle endpoint, already manage-realm gated, running this on a child
     * {@code KeycloakModelUtils.runJobInTransaction} session that has NO admin-auth
     * context; (2) the {@code admin} signer is passed in explicitly (resolved by id in
     * the job session) rather than read from {@code currentUser()}. It returns the SAME
     * {@code {results, summary}} map shape so the sweep's per-CR outcome parsing is
     * unchanged.</p>
     *
     * <p>CRUCIAL (sign-at-toggle Option 1 = rollback-to-PENDING): the per-CR commit
     * flips ({@code processOneCr} → APPROVED) AND the final
     * {@link org.tidecloak.iga.services.IgaToggleOnBackfill#convergeAfterCommit} ORK
     * signing ceremony BOTH run on the {@code session}/{@code realm} this instance was
     * constructed with. The sweep constructs this instance on a dedicated job session,
     * so a converge throw (ORK down / threshold / pack) rolls back the whole job tx —
     * every APPROVED flip reverts to its scan-created PENDING state — WITHOUT touching
     * the outer toggle request tx (IGA-enable flag + the ADOPT scan stay committed). The
     * throw propagates to the sweep caller, which catches it, records a warning, and
     * returns HTTP 200 completed_with_warnings.</p>
     *
     * <p>{@code deferConverge} (2026-06-25): when {@code true} the per-chunk
     * {@code convergeAfterCommit} call inside the bulk core is SKIPPED. The sweep chunks
     * the eligible ADOPT set and calls this once per chunk; since the partial-closure relax
     * (016e661) made converge sign on EVERY call, a per-chunk converge fired ~one ORK
     * full-closure ceremony per chunk. The sweep now passes {@code true} and runs
     * {@code convergeAfterCommit} EXACTLY ONCE after all chunks drain (still inside its
     * dedicated job tx, so the rollback-on-failure semantics are preserved, just batched).
     * The public {@link #bulkAuthorize} endpoint and the single-CR commit path pass
     * {@code false} and keep their existing converge behaviour.</p>
     */
    Response bulkAuthorizeInternal(UserModel admin, List<String> crIdIn, int limit,
            boolean deferConverge) {
        IgaBulkLock.Result<Map<String, Object>> lockResult =
                runBulkLocked(admin, /*byId*/ true, crIdIn, java.util.Collections.emptyList(),
                        /*olderThan*/ null, limit, deferConverge);
        if (!lockResult.isHeld()) {
            return Response.status(429)
                    .entity(Map.of("error",
                            "Another bulk-authorize is already running for this realm",
                            "realm", realm.getName()))
                    .build();
        }
        return Response.ok(lockResult.getValue()).build();
    }

    /**
     * Shared bulk authorize+commit core (the per-realm cluster mutex, the candidate
     * load, the policy-last sort, the per-CR {@code processOneCr} loop, and the single
     * post-batch {@link org.tidecloak.iga.services.IgaToggleOnBackfill#convergeAfterCommit}
     * full-closure stamp). Used by both the public {@link #bulkAuthorize} endpoint and the
     * internal {@link #bulkAuthorizeInternal} sweep entry. Does NOT enforce authz — callers
     * gate access (the endpoint via {@code requireManageRealm}; the sweep via the toggle
     * endpoint that spawned it). Runs everything on this instance's {@code session}/{@code
     * realm}, so the caller controls the transaction boundary (the sweep runs it inside a
     * dedicated job tx so a converge failure rolls back the commit flips).
     */
    private IgaBulkLock.Result<Map<String, Object>> runBulkLocked(
            UserModel admin, boolean byId, List<String> crIdIn, List<String> actionTypes,
            Long olderThan, int limit, boolean deferConverge) {
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
        final List<String> finalCrIdIn = crIdIn;
        final boolean finalById = byId;
        final UserModel finalAdmin = admin;
        final boolean finalDeferConverge = deferConverge;

        return IgaBulkLock.runIfNotRunning(
                session,
                realm.getId(),
                () -> {
                    long startedAt = System.currentTimeMillis();
                    List<Map<String, Object>> results = new ArrayList<>();
                    long committed = 0;
                    long rejected = 0;
                    long skipped = 0;

                    IgaChangeRequestService service = getService();
                    List<IgaChangeRequestEntity> candidates = finalById
                            ? service.listPendingByIdIn(realm.getId(), finalCrIdIn, finalLimit)
                            : service.listPendingByActionTypeIn(realm.getId(), finalActionTypes, finalOlderThan, finalLimit);

                    // REGEN_ADMIN_POLICY must commit LAST — its commit writes the new
                    // IGA_ROLE_POLICY.threshold, which re-gates any still-pending grants upward;
                    // grants must commit under the old threshold first. The commit gate reads the
                    // ENCODED threshold (1b08bb0), so if the policy CR drained first it would bump
                    // 1->2 and strand the still-PENDING tide-realm-admin GRANT_ROLES at 1/2. The
                    // loop below commits candidates in list order, so this stable sort (which only
                    // pushes REGEN_ADMIN_POLICY to the end, preserving the relative order of every
                    // other CR) strictly enforces policy-last in the COMMIT, not just the listing.
                    // DELETE_REALM must commit STRICTLY LAST (rank 2): its replay removes the
                    // realm outright, so any CR after it in the batch would run against a
                    // deleted realm. REGEN_ADMIN_POLICY stays commit-last-among-the-rest
                    // (rank 1) for the threshold-ordering reason below. The stable sort keeps
                    // every other CR's relative order.
                    candidates = new ArrayList<>(candidates);
                    candidates.sort(TideAttestor.BULK_COMMIT_ORDER);

                    // Track whether ANY committed CR in this batch changed client
                    // settings that feed the signed IdP-settings bundle, so the re-sign
                    // ceremony runs ONCE after the whole batch drains (a client save
                    // coalesces into up to 10 per-action CRs — see the post-loop block).
                    boolean anyClientReSign = false;
                    // Every CR this batch commits, so the per-(unit type, owner) SET units the
                    // batch perturbs can be signed ONCE after the whole batch drains (see the
                    // post-loop block). A per-CR set signature is computed PRE-replay over
                    // pre-set + THAT CR's delta and fanned across the owner's whole set with no
                    // member predicate, so two CRs against one owner leave a signature that
                    // commits to a set the DB no longer holds.
                    List<IgaChangeRequestEntity> committedCrs = new ArrayList<>();

                    // Pre-replay gate for a realm whose edge sets are signed from a doken-bound
                    // approval carrier, where the unit bytes are FROZEN when the enclave frames
                    // them. Two change requests against ONE owner set are handled at APPROVAL
                    // time now: phase 1 frames both over the state after the whole group, so
                    // they carry identical bytes for that owner and the group is committable,
                    // provided every member of the group is in this drain and ready. What is
                    // refused here, before any replay, so the batch half-applies nothing:
                    //
                    //   FRAMING_BATCH_INCOMPLETE: a member of a framed group is missing from
                    //     this drain, not at quorum, blocked, or already resolved. The group's
                    //     bytes describe the post-group model, so no member may apply alone.
                    //   CONTESTED_SET_OWNER: the legacy backstop, now scoped to carriers that
                    //     predate the framing batch (no member list persisted). Those really
                    //     were framed as pre-set + own delta and cannot be reconciled.
                    Map<String, Map<String, Object>> refusals = new LinkedHashMap<>();
                    // Byte-provenance state for this drain: the attestor that owns the check
                    // (null on a lane with no frozen carriers) and the change requests already
                    // checked, so each is verified exactly once, at its own basis point.
                    TideAttestor framedUnitVerifier = null;
                    java.util.Set<String> framedUnitsVerified = new java.util.LinkedHashSet<>();
                    if (IgaAttestors.resolveAttestor(session, realm) instanceof TideAttestor frozenAttestor
                            && TideAttestor.usesFrozenApprovalCarrier(session, realm)) {
                        framedUnitVerifier = frozenAttestor;
                        refuseIncompleteFramingBatches(candidates, refusals);
                        List<IgaChangeRequestEntity> legacyCarriers = new ArrayList<>();
                        for (IgaChangeRequestEntity candidate : candidates) {
                            if (candidate.getRequestBatchList().isEmpty()
                                    && !refusals.containsKey(candidate.getId())) {
                                legacyCarriers.add(candidate);
                            }
                        }
                        Map<String, List<String>> contestedOwners =
                                frozenAttestor.findContestedSetOwners(session, realm, legacyCarriers);
                        for (List<String> crIds : contestedOwners.values()) {
                            for (String contestedId : crIds) {
                                Map<String, Object> refusal = new LinkedHashMap<>();
                                refusal.put("error", "CONTESTED_SET_OWNER");
                                refusal.put("message", "Another change request in this batch changes the "
                                        + "same membership set, and this one was approved before the "
                                        + "approval covered the whole group. Re-approve it, then commit.");
                                refusal.put("contestedOwners", contestedOwners);
                                refusals.put(contestedId, refusal);
                            }
                        }
                        if (!refusals.isEmpty()) {
                            log.warnf("IGA bulk-authorize: refusing %d change request(s) in realm %s whose "
                                            + "approval carriers do not describe the state this drain would "
                                            + "produce: %s", refusals.size(), realm.getName(), refusals.keySet());
                        }
                    }

                    for (IgaChangeRequestEntity candidate : candidates) {
                        String crId = candidate.getId();
                        Map<String, Object> refusal = refusals.get(crId);
                        if (refusal != null) {
                            Map<String, Object> refused = new LinkedHashMap<>();
                            refused.put("crId", crId);
                            refused.put("actionType", candidate.getActionType());
                            refused.put("entityType", candidate.getEntityType());
                            refused.put("entityId", candidate.getEntityId());
                            refused.put("status", "REJECTED");
                            refused.putAll(refusal);
                            results.add(refused);
                            rejected++;
                            continue;
                        }
                        Map<String, Object> outcome = processOneCr(crId, finalAdmin);
                        results.add(outcome);
                        String status = String.valueOf(outcome.get("status"));
                        if ("COMMITTED".equals(status)) {
                            committed++;
                            committedCrs.add(candidate);
                            if (org.tidecloak.iga.signing.IgaIdpSettingsResign.changesClientSignedSetting(candidate)) {
                                anyClientReSign = true;
                            }
                            // Byte-provenance, re-evaluated after EVERY replay. A carrier
                            // describes the model after its whole framing batch has applied,
                            // so each committed change request is checked at the point its own
                            // basis first becomes fully applied, never after its own replay
                            // alone (which for a group member is a projection nothing ever
                            // framed) and never only at the end (which is past the basis of a
                            // member framed before the group grew).
                            if (framedUnitVerifier != null) {
                                framedUnitVerifier.verifyFramedUnitsWithAppliedBasis(
                                        session, realm, committedCrs, framedUnitsVerified);
                            }
                        }
                        else if ("REJECTED".equals(status)) rejected++;
                        else skipped++;
                    }
                    if (framedUnitVerifier != null) {
                        framedUnitVerifier.requireAllFramedUnitsVerified(committedCrs, framedUnitsVerified);
                    }

                    // Coalesced SET-unit stamp (ONCE per owner set per batch). Every replay
                    // above is applied, so each owner's set is now at its FINAL post-batch
                    // state: re-derive it, sign it once, and fan that one signature across the
                    // owner's rows, the last write for the owner, so no later fan-out can
                    // replace it with a signature over a stale set. Ordered before the
                    // convergence stamp below so converge observes the real set signatures.
                    // Fail-closed: the post-stamp verification throws out of here and rolls the
                    // batch's commit flips back rather than leaving a set signed over bytes the
                    // ork will re-derive differently. Re-resolve the live realm in case a batch
                    // member removed it (mirrors the DELETE_REALM guard below). No-op on simple
                    // and on batches that touched no owner set.
                    if (!committedCrs.isEmpty()) {
                        RealmModel liveRealmForSets = session.realms().getRealm(realm.getId());
                        if (liveRealmForSets != null
                                && IgaAttestors.resolveAttestor(session, liveRealmForSets)
                                        instanceof TideAttestor tideAttestor) {
                            tideAttestor.stampCoalescedSetUnits(session, liveRealmForSets, committedCrs);
                        }
                    }

                    // ROOT-cause complete-coverage stamp (uniform Design B), once per bulk call
                    // AFTER the whole batch drains the ADOPT set. The per-CR hand-coded stampers
                    // (processOneCr -> stampProducerUnitColumns) cover each adopted node's OWN
                    // unit family, but that hand-listing is incomplete (composite_role + 23/39
                    // protocol_mappers, esp. on SYSTEM entities, stayed stub/NULL -> login fail-
                    // closed). Once this bulk-approve leaves the realm fully-adopted (no pending
                    // ADOPT CR remains), run the PROVEN-COMPLETE producer-driven full-closure stamp
                    // (the SAME RealmAttestationExporter.export -> signEnvelopesWithFirstAdminVvk ->
                    // UnitColumnMapping.stamp the login read consumes), so EVERY login-emitted unit
                    // (all 18 types incl composite_role + protocol_mapper) carries a real 64B sig BY
                    // CONSTRUCTION. Idempotent, firstAdmin+capable gated, fail-closed. Fires whenever
                    // a bulk-approve drains the last pending ADOPT CR — at MANUAL admin approval AND,
                    // since the sign-at-toggle change (2026-06-24), at TOGGLE time once the firstAdmin
                    // sign-defaults sweep auto-commits the whole ADOPT set (the sweep drives this same
                    // bulk core via bulkAuthorizeInternal). FAIL-CLOSED: a converge ORK failure throws
                    // out of here; the sweep runs this core inside a dedicated job tx, so the throw
                    // rolls back every APPROVED flip back to PENDING (Option 1) without un-enabling
                    // IGA. No-op while ADOPT CRs still pend.
                    //
                    // ONCE-AT-END FOR THE SWEEP (deferConverge, 2026-06-25): the firstAdmin toggle
                    // sweep chunks the eligible ADOPT set (chunkSize 25) and calls this bulk core
                    // ONCE PER CHUNK. Since the partial-closure relax (016e661) made converge do real
                    // signing work on EVERY call (no longer deferring while ADOPT_* pend), a per-chunk
                    // converge fired the full-closure ORK ceremony ~once per chunk (~9 small round-trips
                    // for a ~200-CR provisioning closure) instead of one batched (2x100) sign. The
                    // sweep now passes deferConverge=true so this per-chunk call is SKIPPED, and the
                    // sweep runs convergeAfterCommit EXACTLY ONCE after all chunks drain — still inside
                    // its dedicated job tx, so the rollback-on-ORK-failure (fail-loud → PENDING)
                    // semantics are preserved, just batched. The public bulkAuthorize endpoint and the
                    // single-CR commit path keep deferConverge=false (their existing per-call converge
                    // is unchanged).
                    if (!finalDeferConverge) {
                        // A DELETE_REALM committed in this batch (sorted LAST, see above)
                        // removed the realm outright — re-check existence before the converge
                        // ORK ceremony rather than running it against a deleted realm.
                        RealmModel liveRealm = session.realms().getRealm(realm.getId());
                        if (liveRealm != null) {
                            org.tidecloak.iga.services.IgaToggleOnBackfill.convergeAfterCommit(session, liveRealm);
                        }
                    }

                    // Coalesced client-settings re-sign (ONCE per batch). If any CR
                    // committed above changed client settings that feed the VVK-signed
                    // IdP-settings bundle (per-client web origins), re-run the signing
                    // ceremony EXACTLY ONCE for the whole batch — a client save coalesces
                    // into up to 10 per-action CRs, so a per-CR re-sign (10 ORK round-trips)
                    // would be wasteful; one re-sign rebuilds the whole signed bundle from
                    // current realm state. Not gated on deferConverge: the firstAdmin ADOPT
                    // sweep commits ADOPT_* CRs (never client CRs), so anyClientReSign is
                    // false there and this is a no-op. Same fail-closed contract as the
                    // convergeAfterCommit above (a signer failure throws here and rolls back
                    // the batch's commit flips rather than leaving stale clientAuth:*
                    // signatures). No-op on Tideless realms. Re-resolve the live realm in
                    // case a batch member removed it (mirrors the DELETE_REALM guard above).
                    if (anyClientReSign) {
                        RealmModel liveRealmForResign = session.realms().getRealm(realm.getId());
                        if (liveRealmForResign != null) {
                            org.tidecloak.iga.signing.IgaIdpSettingsResign.reSignForClientSettings(session, liveRealmForResign);
                        }
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

        // Fail-closed dependency gate (same as the per-CR commit endpoint): a
        // CR whose dependsOn set has any non-APPROVED prerequisite is REJECTED
        // here — neither signed nor committed in bulk. Surfaced per-CR so the
        // operator can see why it was held back.
        BlockState block = computeBlockState(cr.getDependsOnList());
        if (block.blocked) {
            outcome.put("status", "REJECTED");
            outcome.put("error", "DEPENDENCY_NOT_MET");
            outcome.put("message", block.reason);
            outcome.put("dependsOn", cr.getDependsOnList());
            return outcome;
        }

        // -- authorize step: record() enforces requireApprover() internally;
        //    ADOPT_* CRs short-circuit the approver gate inside the resolver.
        try {
            // Reject a duplicate signature from the same admin — mirrors the
            // per-CR authorize endpoint's pre-check. In bulk this typically
            // means the operator already ran a previous bulk that partially
            // signed but didn't commit; proceed straight to commit
            // rather than fail (the existing signature counts toward
            // threshold).
            List<IgaAuthorizationEntity> existing = em.createNamedQuery(
                            "IgaAuthorization.findByChangeRequest", IgaAuthorizationEntity.class)
                    .setParameter("changeRequestId", cr.getId())
                    .getResultList();
            // admin may be null on the system-bootstrap firstAdmin sweep (a cross-realm
            // super-admin not resolvable in the job session). A null admin cannot have
            // an existing signature attributed to it, so treat it as not-yet-signed and
            // let record() stamp the system principal — never deref a null admin here.
            boolean alreadySigned = false;
            if (admin != null) {
                for (IgaAuthorizationEntity a : existing) {
                    if (admin.getUsername() != null && admin.getUsername().equals(a.getApproval())) {
                        alreadySigned = true;
                        break;
                    }
                    if (admin.getId() != null && admin.getId().equals(a.getAuthorizedBy())) {
                        alreadySigned = true;
                        break;
                    }
                }
            }

            if (!alreadySigned) {
                IgaAttestor attestor = IgaAttestors.resolveAttestor(session, realm);
                attestor.record(session, cr, admin, null);
            }
        } catch (ForbiddenException fe) {
            // Approver-role gate refused this caller for THIS CR. non-ADOPT
            // CRs must NOT be shortcut — surface the per-CR rejection in the
            // results array.
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
                if (!IgaReplayExtension.tryReplay(session, cr, finalAttestation, attestor.isSetSigned())) {
                    IgaReplayDispatcher.replay(session, cr, finalAttestation, attestor.isSetSigned());
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

            // POST-replay per-unit-type column stamp (uniform Design B) — IDENTICAL to the
            // single-CR commit path (commit()). Without this, a bulk-approved CR
            // (e.g. the toggle-on ADOPT closure) replays but never stamps the node/derived/
            // realm producer attestation-units into their DEDICATED per-unit columns. On a
            // firstAdmin real-signing-capable realm those stampers route through
            // signProducerEnvelope -> the REAL 64B VVK ceremony; skipping them left
            // realm_config / realm_default_groups / the derived-set columns / user_role_mapping
            // NULL and the node columns carrying only combineFinal's stub. Runs in the SAME
            // JPA transaction as the replay above. Set-signing (tide) only; no-op on simple.
            // SKIP for DELETE_REALM: the replay above deleted the realm outright, so `realm`
            // is a removed/detached adapter and DELETE_REALM frames no producer unit anyway
            // (identical guard to the single-CR commit() tail).
            if (attestor instanceof org.tidecloak.iga.attestors.TideAttestor tideAttestor
                    && !org.tidecloak.iga.attestors.TideAttestor.ACTION_DELETE_REALM.equals(cr.getActionType())) {
                tideAttestor.stampProducerUnitColumns(session, realm, cr);
                // NO byte-provenance check here. This lane commits a framed group one change
                // request per loop iteration, so at this point only THIS member's delta is in
                // the model while its carrier described the whole group's. runBulkLocked runs
                // the check after every iteration instead, firing each member when its own
                // framing basis is first fully applied.
            }

            // Re-sign Tide IdP settings if this CR changed a signed VendorSettings
            // field (RegOn) — IDENTICAL to the single-CR commit tail (commit():
            // after convergeAfterCommit). Fires per committed setRegistrationAllowed
            // CR so a bulk-approve that includes one keeps the enclave's signed
            // settings valid. Fail-closed: a signer failure throws out of
            // processOneCr and is caught below as a per-CR REJECTED/COMMIT_FAILED
            // (the CR's replay rolls back with the tx), never silently committed
            // with a stale settingsSig. No-op on Tideless / non-signed-field CRs.
            org.tidecloak.iga.signing.IgaIdpSettingsResign.maybeReSign(session, realm, cr);

            outcome.put("status", "COMMITTED");
            return outcome;
        } catch (ForbiddenException fe) {
            outcome.put("status", "REJECTED");
            outcome.put("error", "FORBIDDEN_APPROVER_ROLE");
            outcome.put("httpStatus", 403);
            String msg = fe.getMessage();
            if (msg != null) outcome.put("message", msg);
            return outcome;
        } catch (org.tidecloak.iga.attestors.FramingBatchException fbe) {
            // NOT a per-CR outcome. The carrier's frozen bytes do not describe the state this
            // batch is committing, and earlier members of the batch are already applied in this
            // transaction, and converting this to a REJECTED row would leave the batch half
            // applied. Propagate so the whole bulk transaction rolls back.
            throw fbe;
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
        // The rows changed, so this change request's own carrier is void (updateRows already
        // drops its authorizations) AND so is every carrier framed on the assumption that the
        // OLD rows would apply.
        TideAttestor.clearFramingCarrier(em, cr);
        invalidateFramingBatchMembers(em, id);

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
        // Any carrier framed on the assumption that this change request would apply now
        // describes a state that will never exist. Clear the group so the survivors are
        // re-approved and re-framed over what is actually left, rather than discovering it at
        // commit. Only touches carriers that name this change request in their framing batch.
        invalidateFramingBatchMembers(em, id);
        return Response.noContent().build();
    }

    /**
     * Clear the carriers of every PENDING change request whose framing batch contains
     * {@code crId}, after that change request has left the approvable pool. No-op on a realm
     * that does not use frozen approval carriers, and no-op when nothing was framed with it.
     */
    private void invalidateFramingBatchMembers(EntityManager em, String crId) {
        if (!(IgaAttestors.resolveAttestor(session, realm) instanceof TideAttestor tide)
                || !TideAttestor.usesFrozenApprovalCarrier(session, realm)) {
            return;
        }
        tide.invalidateFramingBatchOf(session, realm, em, crId);
    }

    // -------------------------------------------------------------------------
    // POST /iga/adopt — create an ADOPT_<type> change request for an
    // entity that already exists in the realm but has not yet been attested.
    //
    // The toggle-on scan drives this; it is also exposed on
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
            // Entity already carries an attestation (a prior ADOPT
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

        // Accept either {"comment":"..."} or {"body":"..."} — the admin-client SDK
        // (`Iga.addComment`) sends the text under the `body` key because it strips
        // url-param keys (`id`) and serialises the remainder; legacy/manual callers
        // may send `comment`. Either is honoured; `comment` wins if both are set.
        String comment = null;
        if (body != null) {
            Object c = body.get("comment");
            if (c instanceof String) comment = (String) c;
            if (comment == null) {
                Object b = body.get("body");
                if (b instanceof String) comment = (String) b;
            }
        }
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

        // Accept either {"comment":"..."} or {"body":"..."} — mirrors addComment.
        String newText = null;
        if (body != null) {
            Object c = body.get("comment");
            if (c instanceof String) newText = (String) c;
            if (newText == null) {
                Object b = body.get("body");
                if (b instanceof String) newText = (String) b;
            }
        }
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

    // Realm-level named policy records (keyed by realm + name). The
    // tide-realm-admin M0 admin-quorum policy uses the reserved IMMUTABLE name
    // {@link TideAttestor#TIDE_REALM_ADMIN_POLICY_KEY}; operators may not create,
    // rename to, or delete that name via this surface — the M0 writer owns it.
    //
    // LIST/FIND/READ require only authentication (reaching this admin resource
    // already requires a valid realm-admin token); they do NOT require
    // manage-realm. The write endpoints (POST upsert / DELETE) stay role-gated.

    @GET
    @Path("role-policies")
    @Produces(MediaType.APPLICATION_JSON)
    public List<IgaRolePolicyRepresentation> listRolePolicies() {
        // Read: authenticated-only (no requireManageRealm).
        return getRolePolicyService().listByRealm(realm.getId()).stream()
                .map(this::toRolePolicyRepresentation)
                .collect(Collectors.toList());
    }

    @GET
    @Path("role-policies/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getRolePolicy(@PathParam("id") String id) {
        // Read: authenticated-only (no requireManageRealm).
        IgaRolePolicyEntity entity = getRolePolicyService().findById(id);
        if (entity == null || !realm.getId().equals(entity.getRealmId())) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        return Response.ok(toRolePolicyRepresentation(entity)).build();
    }

    @GET
    @Path("role-policies/name/{name}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getRolePolicyByName(@PathParam("name") String name) {
        // Read: authenticated-only (no requireManageRealm).
        IgaRolePolicyEntity entity = getRolePolicyService()
                .findByRealmAndName(realm.getId(), name);
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
        if (rep.getName() == null || rep.getName().isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "name is required"))
                    .build();
        }
        // The reserved M0 key is owned by the M0 writer; operators may not
        // create or upsert a policy bearing it via this endpoint.
        if (TideAttestor.TIDE_REALM_ADMIN_POLICY_KEY.equals(rep.getName())) {
            return Response.status(Response.Status.FORBIDDEN)
                    .entity(Map.of("error", "policy name '"
                            + TideAttestor.TIDE_REALM_ADMIN_POLICY_KEY
                            + "' is reserved and may not be created or modified via this endpoint"))
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

        // EXPIRY is DERIVED from the signed policy, never taken from the request body. The column
        // is a read-back of what POLICY already contains, so deriving it is what makes it unable to
        // disagree with the bytes the ork will verify. A caller-supplied value could claim a
        // lifetime the signed policy does not carry, and nothing downstream would notice.
        Long expiry;
        try {
            expiry = Policy.From(Base64.getDecoder().decode(rep.getPolicy())).getExpiry();
        } catch (Exception e) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "policy could not be parsed: " + e.getMessage()))
                    .build();
        }

        // An already-expired policy is refused here rather than stored. PolicySignRequest will not
        // sign one and PolicyAuthorizationFlow will not honour it, so storing it would only defer
        // the failure to somewhere further from the cause.
        if (expiry != null && expiry < (System.currentTimeMillis() / 1000L)) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "policy expired at " + expiry))
                    .build();
        }

        IgaRolePolicyEntity upserted = getRolePolicyService().upsert(
                realm.getId(),
                rep.getName(),
                rep.getPolicy(),
                rep.getPolicySig(),
                rep.getContractId(),
                rep.getApprovalType(),
                rep.getExecutionType(),
                rep.getThreshold(),
                rep.getPolicyData(),
                expiry);
        return Response.ok(toRolePolicyRepresentation(upserted)).build();
    }

    @DELETE
    @Path("role-policies/name/{name}")
    public Response deleteRolePolicyByName(@PathParam("name") String name) {
        auth.realm().requireManageRealm();

        // The reserved M0 key may not be deleted via this surface.
        if (TideAttestor.TIDE_REALM_ADMIN_POLICY_KEY.equals(name)) {
            return Response.status(Response.Status.FORBIDDEN)
                    .entity(Map.of("error", "policy name '"
                            + TideAttestor.TIDE_REALM_ADMIN_POLICY_KEY
                            + "' is reserved and may not be deleted via this endpoint"))
                    .build();
        }
        IgaRolePolicyService service = getRolePolicyService();
        IgaRolePolicyEntity existing = service.findByRealmAndName(realm.getId(), name);
        if (existing == null) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        service.deleteByRealmAndName(realm.getId(), name);
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
        // The reserved M0 key may not be deleted via this surface.
        if (TideAttestor.TIDE_REALM_ADMIN_POLICY_KEY.equals(existing.getName())) {
            return Response.status(Response.Status.FORBIDDEN)
                    .entity(Map.of("error", "policy name '"
                            + TideAttestor.TIDE_REALM_ADMIN_POLICY_KEY
                            + "' is reserved and may not be deleted via this endpoint"))
                    .build();
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
        rep.setName(entity.getName());
        rep.setPolicy(entity.getPolicy());
        rep.setPolicySig(entity.getPolicySig());
        rep.setContractId(entity.getContractId());
        rep.setApprovalType(entity.getApprovalType());
        rep.setExecutionType(entity.getExecutionType());
        rep.setThreshold(entity.getThreshold());
        rep.setPolicyData(entity.getPolicyData());
        rep.setExpiry(entity.getExpiry());
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
        if (entity.getChangeRequest() != null) {
            rep.setChangeRequestId(entity.getChangeRequest().getId());
        }
        rep.setUserId(entity.getUserId());
        rep.setUsername(entity.getUsername());
        rep.setComment(entity.getComment());
        rep.setCreatedAt(entity.getCreatedAt());
        rep.setUpdatedAt(entity.getUpdatedAt());
        return rep;
    }

    private IgaChangeRequestRepresentation toRepresentation(IgaChangeRequestEntity cr,
                                                              IgaChangeRequestService service) {
        // Single-CR callers (GET /{id}, authorize/commit/PUT responses): resolve the policy-CR
        // linkage on the fly (READ-ONLY; multiAdmin only) so they tag relatedPolicyCrId too.
        // The list endpoint uses the 3-arg overload and resolves the linkage ONCE per call.
        TideAttestor.PolicyCrLinkage linkage;
        try {
            linkage = new TideAttestor(session).resolvePolicyCrLinkage(session, realm);
        } catch (RuntimeException ex) {
            linkage = TideAttestor.PolicyCrLinkage.none();
        }
        return toRepresentation(cr, service, linkage);
    }

    private IgaChangeRequestRepresentation toRepresentation(IgaChangeRequestEntity cr,
                                                              IgaChangeRequestService service,
                                                              TideAttestor.PolicyCrLinkage policyLinkage) {
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
                            a.getApproval(),
                            a.getCreatedAt() != null ? a.getCreatedAt() : 0L))
                    .collect(Collectors.toList());
            rep.setAuthorizers(authorizers);
        } catch (Exception ignored) {
        }

        // threshold + readyToCommit. Both MUST come from the SAME authoritative
        // value the commit gate enforces (IgaAdminResource.commit →
        // attestor.getThreshold), so the representation can never report a number
        // that disagrees with enforcement. Threshold resolution depends on
        // rows_json + realm state, so guard it.
        //   - simple (Tideless) attestor → getThreshold delegates to the static
        //     IgaScopeResolver.resolveThreshold(...) — same number as before.
        //   - tide/firstAdmin            → 1 (single-signer onboarding).
        //   - tide/multiAdmin            → dynamic floor(0.7 × activeTideAdmins),
        //     unless a per-scope override or ADOPT_* bypass wins (both honoured
        //     inside getThreshold). ADOPT_* still reports threshold=1.
        try {
            IgaAttestor attestor = IgaAttestors.resolveAttestor(session, realm);
            int threshold = attestor.getThreshold(session, realm, cr);
            rep.setThreshold(threshold);
            if ("PENDING".equals(cr.getStatus())) {
                rep.setReadyToCommit(authCount >= threshold);
            }
        } catch (Exception ignored) {
        }

        // Scope-based approval metadata for the admin UI (required approver roles
        // + scope mode). The threshold itself is resolved above via the attestor;
        // here we only need the scope's role set and the realm scope mode.
        try {
            IgaScopeResolver.ResolvedScope scope = IgaScopeResolver.resolve(session, realm, cr);
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

        // Dependency contract: surface the prerequisite CR ids + a server-
        // computed blocked flag/reason. A CR is blocked iff any prerequisite CR
        // is not APPROVED — the SAME gate the commit path enforces (so the UI
        // never offers a commit the server would 412). Guarded so a malformed
        // CR can't break the list/detail endpoints.
        try {
            List<String> deps = cr.getDependsOnList();
            rep.setDependsOn(deps);
            if (!deps.isEmpty()) {
                BlockState bs = computeBlockState(deps);
                rep.setBlocked(bs.blocked);
                rep.setBlockedReason(bs.reason);
            }
        } catch (Exception ignored) {
        }

        // relatedPolicyCrId — INFORMATIONAL auto-bundle hint for the admin UI (NOT a blocking
        // dependsOn). For a PENDING tide-realm-admin GRANT/REVOKE assignment CR covered by the
        // realm's current pending REGEN_ADMIN_POLICY CR, point at that policy CR's id so the UI
        // can auto-include it when the admin selects the assignment. The policy CR itself and all
        // other CRs (non-tide-realm-admin, firstAdmin, non-tide realms) stay null.
        try {
            if (policyLinkage != null && policyLinkage.policyCrId != null
                    && policyLinkage.assignmentCrIds.contains(cr.getId())) {
                rep.setRelatedPolicyCrId(policyLinkage.policyCrId);
            }
        } catch (Exception ignored) {
        }
        return rep;
    }

    /**
     * Holds the resolved blocked state of a CR's prerequisite set.
     */
    private static final class BlockState {
        final boolean blocked;
        final String reason;
        BlockState(boolean blocked, String reason) {
            this.blocked = blocked;
            this.reason = reason;
        }
    }

    /**
     * Compute whether a CR with the given prerequisite CR ids is blocked, and a
     * short human reason. Blocked iff any prerequisite CR's status != APPROVED
     * (including a missing/denied/cancelled prerequisite — anything other than
     * APPROVED keeps the dependent blocked, fail-closed). Shared by the
     * representation builder and the commit gate so the reported and enforced
     * states cannot diverge.
     */
    private BlockState computeBlockState(List<String> dependsOn) {
        if (dependsOn == null || dependsOn.isEmpty()) {
            return new BlockState(false, null);
        }
        EntityManager em = getEm();
        for (String prereqId : dependsOn) {
            IgaChangeRequestEntity prereq = em.find(IgaChangeRequestEntity.class, prereqId);
            String status = prereq == null ? "MISSING" : prereq.getStatus();
            if (!"APPROVED".equals(status)) {
                String actionType = prereq == null ? null : prereq.getActionType();
                String reason;
                if ("CREATE_CLIENT_SCOPE".equals(actionType)) {
                    reason = "Waiting on: create tide-claims scope";
                } else if (actionType != null) {
                    reason = "Waiting on prerequisite change request (" + actionType + ", " + status + ")";
                } else {
                    reason = "Waiting on prerequisite change request (" + status + ")";
                }
                return new BlockState(true, reason);
            }
        }
        return new BlockState(false, null);
    }
}
