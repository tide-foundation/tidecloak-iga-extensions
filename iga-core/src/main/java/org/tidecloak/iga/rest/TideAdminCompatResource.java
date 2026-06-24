package org.tidecloak.iga.rest;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.enterprise.inject.Vetoed;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.AdminRoles;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.cache.CacheRealmProvider;
import org.keycloak.models.cache.UserCache;
import org.keycloak.models.OrganizationModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.organization.OrganizationProvider;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.keycloak.storage.UserStorageUtil;
import org.tidecloak.iga.crypto.SecretKeys;
import org.tidecloak.iga.replay.SidecarCapExceededException;
import org.tidecloak.iga.entities.IgaChangeRequestEntity;
import org.tidecloak.iga.providers.IgaChangeRequestService;
import org.tidecloak.iga.services.IgaAdoptCancel;
import org.tidecloak.iga.services.IgaAdoptScan;
import org.tidecloak.iga.services.IgaApproverRoleRepointer;
import org.tidecloak.iga.services.IgaFirstAdminAutoCommit;
import org.tidecloak.iga.services.IgaToggleJobService;

import jakarta.persistence.EntityManager;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Backwards-compat admin resource at /admin/realms/{realm}/tide-admin
 * Replaces the old IGA's IGARealmResource.toggleIga endpoint so the existing admin UI works.
 *
 * <p>On OFF→ON the handler triggers a one-shot {@link IgaAdoptScan}
 * in its own {@code runJobInTransaction} so a scan failure cannot abort the
 * toggle attribute write that just succeeded.</p>
 *
 * <p>On ON→OFF the handler triggers a one-shot {@link IgaAdoptCancel}
 * in its own {@code runJobInTransaction} that cancels every PENDING ADOPT_*
 * CR and clears the entire sidecar register for the realm. The toggle-on path
 * also gains a sidecar cap check: if the realm already has more than
 * {@link IgaAdoptScan#SIDECAR_CAP_DEFAULT} unattested rows at scan-start, the
 * toggle is refused with 409 SIDECAR_CAP_EXCEEDED and the realm-attribute
 * write rolled back.</p>
 */
@Path("tide-admin")
@Vetoed
public class TideAdminCompatResource {

    private static final Logger logger = Logger.getLogger(TideAdminCompatResource.class);
    private static final String IGA_ATTRIBUTE = "isIGAEnabled";
    private static final String INCLUDE_SYSTEM_ATTRIBUTE = "iga.adopt.includeSystem";
    private static final String IGA_ATTESTOR_ATTRIBUTE = "iga.attestor";
    private static final String TIDE_VENDOR_KEY_PROVIDER_ID = "tide-vendor-key";
    private static final String CFG_CLIENT_ID = "clientId";
    private static final String CFG_CLIENT_SECRET = "clientSecret";
    private static final String CFG_VVK_ID = "vvkId";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final KeycloakSession session;
    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;

    public TideAdminCompatResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth) {
        this.session = session;
        this.realm = realm;
        this.auth = auth;
    }

    @POST
    @Path("toggle-iga")
    // The admin-ui posts this as a browser FormData (see GeneralTab.tsx /
    // tideProvider.toggleIGA): no explicit Content-Type is set on the request,
    // so the browser emits multipart/form-data. We also accept
    // application/x-www-form-urlencoded for non-browser callers. This is the
    // original (pre-progress-feature) content type the FormData client has
    // always produced — the JSON @Consumes briefly introduced with the progress
    // feature broke that client with a 415 / unbound body. Both isIGAEnabled and
    // the optional jobId are read as @FormParam from this same form payload.
    @Consumes({MediaType.MULTIPART_FORM_DATA, MediaType.APPLICATION_FORM_URLENCODED})
    @Produces(MediaType.APPLICATION_JSON)
    public Response toggleIga(@FormParam("isIGAEnabled") String isIGAEnabledParam,
                              @FormParam("jobId") String jobIdParam) {
        auth.realm().requireManageRealm();
        boolean current = "true".equals(realm.getAttribute(IGA_ATTRIBUTE));
        boolean next = !current;

        // LOCKED CONTRACT: the admin-ui may supply a jobId (uuid) as a form field
        // so it can poll GET .../toggle-iga/status/{jobId} for live progress while
        // this synchronous toggle runs. jobId is OPTIONAL: when absent (or this is
        // an OFF-toggle, which carries no progress), every progress call is a no-op
        // and the endpoint behaves exactly as before — fully back-compatible. The
        // isIGAEnabled form field carries the client's desired state but is purely
        // informational here: the toggle has always been computed as next=!current
        // (a flip), which the client mirrors (it sends the opposite of the current
        // attribute). We keep that flip semantics for exact back-compat.
        final String jobId = normalizeJobId(jobIdParam);
        final IgaToggleJobService jobService = new IgaToggleJobService(session);

        if (logger.isDebugEnabled()) {
            logger.debugf("IGA toggle-iga: realm=%s currentEnabled=%s -> next=%s (client isIGAEnabled=%s, jobId=%s)",
                    realm.getName(), current, next, isIGAEnabledParam, jobId);
        }

        // Progress tracking is only meaningful for a real OFF→ON on a
        // non-master realm (the only path that does slow work). For everything
        // else trackProgress stays false and every jobService call is a no-op
        // (jobId-null short-circuits inside the service too). Initialize the
        // full stage checklist (all pending) up-front so the UI can render it
        // immediately.
        final boolean trackProgress = jobId != null && !current && next && !"master".equals(realm.getName());
        if (trackProgress) {
            jobService.start(jobId, realm.getId(), IgaToggleJobService.stages(
                    new IgaToggleJobService.Stage("setup-realm", "Setting up realm"),
                    new IgaToggleJobService.Stage("adopt-scan", "Adopting existing configuration"),
                    new IgaToggleJobService.Stage("refresh-sessions", "Refreshing sessions"),
                    new IgaToggleJobService.Stage("sign-defaults", "Signing default roles & config"),
                    new IgaToggleJobService.Stage("finalize", "Finalizing")));
            jobService.stageRunning(jobId, "setup-realm", null, null);
        }

        // Response body, populated as the toggle progresses. Declared up-front
        // so the switch-to-Tide approver-role repoint (pre-flip) can record its
        // per-surface counts under "approverRoleRepoint".
        Map<String, Object> body = new LinkedHashMap<>();

        // NON-BLOCKING end-summary accumulators (revised contract 2026-06-24).
        // The toggle processes every CR / entity BEST-EFFORT and never aborts on
        // a per-CR / per-entity failure: it COMPLETES and at the END surfaces a
        // structured summary listing whatever failed. Only a truly-fatal pre-work
        // error (the IGA flag write itself) or the sidecar-cap capacity precondition
        // returns non-2xx; everything else returns 200, with the realm left IGA-on
        // and a "warnings" object naming the failures. The job ends
        // completed_with_warnings (not failed) when any of these are populated.
        //
        //  - adoptScanFailed : set when the WHOLE ADOPT scan threw (softened Tier 1
        //                      — record + continue, NO rollback, NO 500). The realm
        //                      stays IGA-on; the summary tells the admin to re-scan.
        //  - commitFailures  : the firstAdmin sign-defaults sweep per-CR outcomes
        //                      that did NOT commit (crId / actionType / outcome).
        // (adopt per-entity failures come from ScanResult.failedEntities; the
        //  approver-role repoint error is recorded into body directly below.)
        String[] adoptScanFailed = new String[1];
        List<Map<String, Object>> commitFailures = new ArrayList<>();

        // OFF→ON, non-master: auto-create the tide-realm-admin approver
        // role BEFORE the isIGAEnabled flip below. Creating it pre-flip means
        // IGA is still OFF, so the addRole/addCompositeRole/setSingleAttribute
        // writes are PLAIN model writes and are NOT captured as a CREATE_ROLE
        // CR. After the flip, the IgaAdoptScan picks up this newly-created
        // (still-unattested) role and emits an ADOPT_ROLE CR — the intended
        // attestation path (firstAdmin commits it). Idempotency guard ported
        // verbatim from the old createRealmAdminPolicy: only create when the
        // role does not already exist on realm-management.
        if (!current && next && !"master".equals(realm.getName())) {
            ClientModel realmManagement = realm.getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID);
            if (realmManagement != null
                    && session.roles().getClientRole(realmManagement, "tide-realm-admin") == null) {
                RoleModel tideRealmAdmin = realmManagement.addRole("tide-realm-admin");
                tideRealmAdmin.addCompositeRole(realmManagement.getRole(AdminRoles.REALM_ADMIN));
                tideRealmAdmin.setSingleAttribute("tideThreshold", "1");
                logger.infof("IGA toggle-on: created approver role 'tide-realm-admin' (composite of %s, tideThreshold=1) on realm-management for realm %s before isIGAEnabled flip",
                        AdminRoles.REALM_ADMIN, realm.getName());
            }
        }

        // OFF→ON, Tide realm: a realm's defaultSignatureAlgorithm = EdDSA iff
        // (a `tide` IdP exists) AND (IGA is on). The IGA toggle is therefore the
        // single place that sets EdDSA on enable (and reverts it to RS256 on
        // disable — see the ON→OFF branch below). This also sets
        // iga.attestor=tide so the realm enters firstAdmin/multiAdmin Tide mode
        // (no production code set this before — it was a manual step). Both
        // writes happen BEFORE the isIGAEnabled flip (so they are plain model
        // writes, not captured as CRs) and BEFORE the ADOPT scan (so the
        // firstAdmin authorizer can seed against attestor=tide). Idempotent: a
        // re-run on an already-tide realm is a no-op for both. Tide detection
        // mirrors the ON→OFF branch (tide IdP + tide-vendor-key component).
        if (!current && next) {
            IdentityProviderModel tideIdp = session.identityProviders().getByAlias("tide");
            ComponentModel tideVendorKey = realm.getComponentsStream()
                    .filter(x -> TIDE_VENDOR_KEY_PROVIDER_ID.equals(x.getProviderId()))
                    .findFirst()
                    .orElse(null);
            final boolean tideRealm = tideIdp != null && tideVendorKey != null;

            // SIGN-AT-TOGGLE FIX (Option A, deadlock-corrected 2026-06-24): DURABLE
            // realm-state commit runs FIRST — before ANY request-tx write touches the
            // realm row. 95d84f7 ran this AFTER the request tx had already written (and
            // locked) iga.attestor / defaultSignatureAlgorithm / isIGAEnabled on the
            // realm row, so the nested job tx's write to the SAME row deadlocked against
            // the request tx's uncommitted lock (the request tx was synchronously waiting
            // for the nested runJobInTransaction to return) → the toggle HUNG. Committing
            // here FIRST means the nested tx acquires + releases the realm-row lock fully
            // before the request tx ever touches that row; the request-tx in-memory writes
            // below then run against rows no other tx still holds. NON-master OFF→ON always
            // commits isIGAEnabled=true durably (so the scan/sweep job sessions observe it);
            // the tide discriminator + EdDSA are committed only for a Tide realm. The
            // desired sig-alg is decided HERE from the VRK-active probe (EdDSA when active,
            // else the realm's current algorithm unchanged) — NOT read back from the request
            // realm (which has not yet applied the switch at this point).
            if (!"master".equals(realm.getName())) {
                final String desiredSigAlg = (tideRealm && isVrkActive(tideVendorKey))
                        ? "EdDSA"
                        : realm.getDefaultSignatureAlgorithm();
                persistRealmStateForSweep(realm.getId(), tideRealm, desiredSigAlg);
            }

            if (tideRealm) {
                // (a) iga.attestor=tide — must be set before the ADOPT scan so
                // the firstAdmin authorizer can seed. Write via the suppressed
                // helper for consistency (IGA is still OFF here, so it is a
                // plain realm.setAttribute under the IGA_REPLAY_ACTIVE guard).
                // The DB row was already committed above; this in-memory write
                // makes the REQUEST realm adapter reflect tide for the request-side
                // sweep/repoint gates (isFirstAdminMode / resolveMode read the
                // request realm). It contends with no other tx (the durable commit
                // above already released its lock).
                if (!"tide".equals(realm.getAttribute(IGA_ATTESTOR_ATTRIBUTE))) {
                    writeIgaAttributeDirect(IGA_ATTESTOR_ATTRIBUTE, "tide");
                    logger.infof("IGA toggle-on: set iga.attestor=tide for realm %s (firstAdmin/multiAdmin Tide mode)",
                            realm.getName());
                }

                // (b) defaultSignatureAlgorithm=EdDSA — GUARDED on the VRK
                // being ACTIVE. EdDSA with an empty/unprovisioned active key
                // breaks all signing, so we only switch when the tide-vendor-key
                // config carries live active-key material: a non-empty clientId
                // (the active EdDSA public point), a non-empty vvkId (the
                // active-VRK proxy), AND a non-blank activeVrk parsed from the
                // clientSecret SecretKeys blob. If active → switch to EdDSA
                // (only if not already EdDSA). If not active → keep
                // iga.attestor=tide set, but defer the EdDSA switch and warn.
                if (isVrkActive(tideVendorKey)) {
                    String currentAlgorithm = realm.getDefaultSignatureAlgorithm();
                    if (!"EdDSA".equalsIgnoreCase(currentAlgorithm)) {
                        writeDefaultSignatureAlgorithmDirect("EdDSA");
                        logger.infof("IGA toggle-on: VRK active, default signature algorithm set to EdDSA for realm %s",
                                realm.getName());
                    }
                } else {
                    logger.warnf("IGA toggle-on: VRK not yet active for realm %s, deferring EdDSA switch (iga.attestor=tide still set)",
                            realm.getName());
                }

                // (c) Repoint EVERY declared iga.approverRole to the canonical
                // Tide approver role tide-realm-admin (created above in stage 1).
                // In Tideless IGA an operator may pin approvals to a custom /
                // attribute-derived role; in Tide mode the multiAdmin quorum
                // consults tide-realm-admin, so a stale Tideless approver role on
                // any surface (realm / role / client / group / idp / org) must be
                // repointed or it would mis-gate (or silently bypass) a post-flip
                // commit. Runs BEFORE the isIGAEnabled flip (plain model writes,
                // not captured as SET_*_ATTRIBUTE CRs) and is idempotent — a
                // re-toggle on an already-Tide realm only rewrites surfaces that
                // are not already tide-realm-admin (typically zero). firstAdmin
                // is unaffected (it bypasses requireApprover); the repointed value
                // becomes load-bearing only once the realm flips to multiAdmin.
                // Best-effort: a per-surface failure never aborts the toggle.
                try {
                    IgaApproverRoleRepointer.Result repoint =
                            IgaApproverRoleRepointer.repointToTideRealmAdmin(session, realm);
                    if (repoint.total() > 0) {
                        body.put("approverRoleRepoint", repoint.toMap());
                    }
                } catch (RuntimeException repointEx) {
                    logger.errorf(repointEx,
                            "IGA toggle-on: approver-role repoint to tide-realm-admin FAILED for realm %s "
                                    + "— toggle continues; some surfaces may still carry a stale iga.approverRole.",
                            realm.getName());
                    // Pre-flip, not a tracked stage, so this never hard-stops the
                    // toggle. But the failure was previously invisible: record it in
                    // the response body so an operator can see a stale iga.approverRole
                    // may remain on some surface and re-run / fix it manually.
                    Map<String, Object> repointErr = new LinkedHashMap<>();
                    repointErr.put("error", repointEx.getClass().getSimpleName());
                    repointErr.put("message", String.valueOf(repointEx.getMessage()));
                    body.put("approverRoleRepointError", repointErr);
                }
            }
        }

        // ON→OFF (non-master): turning IGA OFF is itself a privileged, governed
        // change — a single manage-realm admin must NOT be able to unilaterally
        // disable governance. Instead of flipping isIGAEnabled=false and running
        // the teardown inline here, CAPTURE the disable into a governed
        // DISABLE_IGA change request and return 202 pending-approval. The flag
        // STAYS true until that CR commits; the teardown (cancel ADOPTs, evict
        // caches, RS256 revert, and the actual isIGAEnabled=false write) runs in
        // IgaReplayDispatcher.replayDisableIga on commit. This applies in BOTH
        // firstAdmin AND multiAdmin (DISABLE_IGA is deliberately NOT on the
        // IgaFirstAdminAutoCommit allow-list, so even a firstAdmin must
        // explicitly authorize+commit it). The CR is created on a FRESH session/
        // transaction (the same emit pattern the Iga*Adapters use) so it survives
        // the request-tx rollback the 202 triggers; the request tx is then marked
        // rollback-only and IgaPendingApprovalException is thrown (→ 202 +
        // Location). DISABLE_IGA is a non-producer action, so its commit produces
        // a stub signature with no ORK/Policy:1 round-trip — OFF is never blocked
        // by ORK reachability. master is excluded by symmetry (IGA is never on for
        // master; the master-realm escape hatch keeps its direct-write behavior
        // below).
        if (current && !next && !"master".equals(realm.getName())) {
            String requestedBy = currentUserId();
            String realmId = realm.getId();
            String[] crIdHolder = new String[1];
            KeycloakModelUtils.runJobInTransaction(
                    session.getKeycloakSessionFactory(),
                    crSession -> {
                        RealmModel crRealm = crSession.realms().getRealm(realmId);
                        if (crRealm == null) {
                            throw new IllegalStateException(
                                    "DISABLE_IGA capture: realm " + realmId + " not loadable in CR session");
                        }
                        EntityManager crEm = crSession.getProvider(JpaConnectionProvider.class).getEntityManager();
                        IgaChangeRequestService crService = new IgaChangeRequestService(crEm, crSession);
                        // Single-pending-REALM-CR rule (shared with the other
                        // realm-attribute/config CRs): if a REALM-scoped CR is
                        // already pending on this realm, refuse with a clean 409
                        // rather than stacking a second pending REALM CR. The
                        // IgaConflictException maps to 409 (not 500).
                        IgaChangeRequestEntity existing =
                                crService.findPending(realmId, "REALM", realmId);
                        if (existing != null) {
                            throw new org.tidecloak.iga.providers.IgaConflictException(existing.getId());
                        }
                        // ROWS_JSON carries the isIGAEnabled=false write the
                        // replay applies; shape mirrors a realm-attribute row so
                        // the teardown can set it under IGA_REPLAY_ACTIVE.
                        Map<String, Object> row = new LinkedHashMap<>();
                        row.put("REALM_ID", realmId);
                        row.put("NAME", IGA_ATTRIBUTE);
                        row.put("VALUE", "false");
                        crIdHolder[0] = crService.create(
                                crRealm, "REALM", realmId, "DISABLE_IGA",
                                List.of(row), requestedBy).getId();
                    });
            session.getTransactionManager().setRollbackOnly();
            logger.infof("IGA toggle ON->OFF for realm %s captured as DISABLE_IGA change request %s "
                            + "(awaiting admin approval; isIGAEnabled stays true until commit).",
                    realm.getName(), crIdHolder[0]);
            throw new org.tidecloak.iga.providers.IgaPendingApprovalException(
                    crIdHolder[0], "REALM", "DISABLE_IGA");
        }

        // The toggle endpoint IS the governing action (gated by
        // requireManageRealm); routing the toggle attribute write through the
        // IGA capture interceptor would create a SET_REALM_ATTRIBUTE CR
        // instead of actually flipping the flag — leaving the realm in a
        // "lying" state (response says enabled=false but isIGAEnabled still
        // "true" pending CR approval) and arming a one-pending-CR-per-realm
        // 409 trap on the next toggle. IGA_REPLAY_ACTIVE bypasses the
        // wrapper for the duration of the attribute write so the realm
        // attribute is actually flipped (matching the cancel + scan
        // contracts that assume the attribute is real after toggle).
        // NOTE: the ON->OFF (non-master) case never reaches here — it 202'd
        // above. This write therefore only ever flips OFF->ON, or master.
        writeIgaAttributeDirect(IGA_ATTRIBUTE, Boolean.toString(next));
        logger.infof("IGA has been toggled to : %s for realm %s", next, realm.getName());

        // SIGN-AT-TOGGLE durable realm-state commit (iga.attestor + isIGAEnabled +
        // EdDSA) already ran EARLIER — at the TOP of the OFF→ON block, BEFORE any
        // request-tx realm-row write — via persistRealmStateForSweep(realmId, ...).
        // It is no longer invoked HERE: running it after the request tx had locked
        // those same realm-attribute rows is exactly what caused the nested-tx vs
        // request-tx self-deadlock that hung the toggle in 95d84f7. The request-tx
        // writes above (iga.attestor / EdDSA / isIGAEnabled) are kept as IN-MEMORY
        // visibility for the REQUEST realm adapter only (the request-side sweep/repoint
        // gates read it); the durable row is already committed and the scan/sweep job
        // sessions read it through the evicted realm cache.

        // setup-realm complete: approver role + attestor/EdDSA + the
        // isIGAEnabled flip are all done. (If the scan below 409s on the
        // sidecar cap the flag is rolled back, but the stage record will be
        // overwritten with a failed/finalized state at that point.)
        if (trackProgress) {
            jobService.stageDone(jobId, "setup-realm", null, null);
        }

        body.put("enabled", next);

        // OFF→ON: run the one-shot ADOPT scan inside its own
        // transaction. Master is excluded by design — the master-realm
        // escape hatch must remain unconditionally usable for recovery.
        if (!current && next && !"master".equals(realm.getName())) {
            boolean includeSystem = "true".equals(realm.getAttribute(INCLUDE_SYSTEM_ATTRIBUTE));
            String requestedBy = currentUserId();
            String realmId = realm.getId();

            if (trackProgress) {
                jobService.stageRunning(jobId, "adopt-scan", null, null);
            }

            IgaAdoptScan.ScanResult[] resultHolder = new IgaAdoptScan.ScanResult[1];
            SidecarCapExceededException[] capHolder = new SidecarCapExceededException[1];
            Throwable[] errHolder = new Throwable[1];
            try {
                KeycloakModelUtils.runJobInTransaction(
                        session.getKeycloakSessionFactory(),
                        scanSession -> {
                            RealmModel scanRealm = scanSession.realms().getRealm(realmId);
                            if (scanRealm == null) {
                                throw new IllegalStateException(
                                        "IGA toggle-on scan: realm " + realmId + " not loadable in scan session");
                            }
                            resultHolder[0] = IgaAdoptScan.scan(scanSession, scanRealm, requestedBy, includeSystem);
                        });
            } catch (SidecarCapExceededException cap) {
                // Sidecar cap exceeded. Roll back the realm-attribute
                // write so IGA stays OFF — half-enabling is more confusing
                // than refusing — and 409 SIDECAR_CAP_EXCEEDED with the
                // numbers in the body. One INFO log line, no stack.
                capHolder[0] = cap;
                logger.infof("IGA toggle-on refused for realm %s — sidecar cap %d exceeded (current=%d); " +
                                "isIGAEnabled rolled back to false.",
                        realm.getName(), cap.getCap(), cap.getCurrent());
            } catch (RuntimeException ex) {
                // TOTAL scan failure. Captured here and RECORDED + CONTINUED in the
                // errHolder[0] branch below (softened contract 2026-06-24): the
                // user wants the toggle NON-BLOCKING, so a whole-scan failure no
                // longer rolls back isIGAEnabled and no longer 500s. The realm stays
                // IGA-on and the failure is carried into the end-summary
                // (warnings.adoptScanFailed) so the admin can re-scan. (The
                // sidecar-cap precondition above remains a hard-stop — that is a
                // legitimate CAPACITY refusal, not a per-CR processing failure.)
                errHolder[0] = ex;
            }

            if (capHolder[0] != null) {
                // Roll back the realm-attribute write — same outer
                // transaction, so this resets isIGAEnabled to its pre-toggle
                // value (false) before the response is sent. Bypass the
                // IGA capture (the just-written "true" would otherwise make
                // isIgaActive() route this revert through SET_REALM_ATTRIBUTE
                // CR creation instead of an actual rollback).
                writeIgaAttributeDirect(IGA_ATTRIBUTE, Boolean.toString(current));
                // SIGN-AT-TOGGLE FIX (2026-06-24): the request-tx revert above is no
                // longer sufficient on its own — persistRealmStateForSweep COMMITTED
                // isIGAEnabled=true in a separate tx so the request-tx rollback would
                // not undo it. Durably revert isIGAEnabled (and re-evict the realm
                // cache) so a sidecar-cap 409 leaves the realm genuinely IGA-OFF, as
                // before. iga.attestor=tide is intentionally LEFT — it is an idempotent
                // discriminator, harmless while IGA is off, and re-running the toggle
                // is a no-op for it.
                revertIgaEnabledDurably(realm.getId(), current);
                if (trackProgress) {
                    jobService.fail(jobId, "adopt-scan",
                            "SIDECAR_CAP_EXCEEDED: cap=" + capHolder[0].getCap()
                                    + " current=" + capHolder[0].getCurrent());
                }
                Map<String, Object> capBody = new LinkedHashMap<>();
                capBody.put("error", "SIDECAR_CAP_EXCEEDED");
                capBody.put("realmId", capHolder[0].getRealmId());
                capBody.put("cap", capHolder[0].getCap());
                capBody.put("current", capHolder[0].getCurrent());
                return Response.status(Response.Status.CONFLICT).entity(capBody).build();
            }

            if (resultHolder[0] != null) {
                // adopt-scan done — report entities scanned as current/total
                // (scanned == total examined; the scan is complete).
                if (trackProgress) {
                    long scanned = resultHolder[0].totalEntitiesScanned;
                    jobService.stageDone(jobId, "adopt-scan", scanned, scanned);
                    jobService.stageRunning(jobId, "refresh-sessions", null, null);
                }
                // Invalidate every live user session on the realm
                // so any user newly quarantined by the OFF→ON scan cannot
                // ride an existing cookie/refresh token past the toggle. The
                // design memo's recommendation (accept the re-login storm —
                // simpler than tracking which users were just quarantined and
                // strictly correct) is implemented here as a single bulk
                // removeUserSessions(realm) call against the request-scoped
                // session.sessions() provider. Surface the count in the
                // response so operators see exactly how many sessions were
                // dropped. The bulk method exists in KC 26.5.5.
                long invalidated = invalidateRealmSessions(session, realm);
                // Direct-grant miss: also evict the
                // infinispan user-cache for this realm. KC's UserCacheSession
                // returns a CachedUser-backed UserAdapter whose isEnabled() reads
                // the snapshot stored at cache-load time and does NOT
                // delegate to the underlying IgaUserAdapter on each call. If a
                // user was loaded BEFORE the OFF→ON toggle (e.g. a pre-IGA
                // direct-grant seeded the cache with enabled=true), the cache
                // entry keeps returning enabled=true after the toggle even
                // though the IGA quarantine guards on IgaUserAdapter.isEnabled
                // would have refused. Symmetric to removeUserSessions(realm)
                // (login-session invalidation), evict the user-cache so the
                // next session.users() lookup re-loads through
                // IgaUserProvider → IgaUserAdapter and the quarantine override
                // fires. The eviction is per-realm and best-effort: a failure
                // must never abort the toggle (the attribute is already
                // committed and the response is about to be sent).
                evictRealmUserCache(session, realm);
                // CLIENT quarantine miss, symmetric to the user-cache eviction
                // above. KC's RealmCacheSession caches client snapshots as
                // CachedClient and the resulting ClientAdapter.isEnabled() returns
                // cached.isEnabled() rather than delegating to
                // IgaClientAdapter.isEnabled() (quarantine REFUSE hook). A
                // confidential client whose entry was loaded pre-IGA (e.g. a
                // pre-toggle client_credentials call) keeps returning enabled=true
                // after the OFF→ON toggle, so the unsigned-client client_credentials
                // is wrongly granted a 200. Evict the per-realm
                // client/role/group/scope cache entries so the next read
                // re-loads through the IGA wrappers and the quarantine fires.
                // Same best-effort contract as the user-cache eviction — never
                // abort the toggle on cache failure.
                evictRealmCache(session, realm);
                body.put("scan", resultHolder[0]
                        .withSessionsInvalidated(invalidated).toMap());

                if (trackProgress) {
                    jobService.stageDone(jobId, "refresh-sessions", invalidated, invalidated);
                    jobService.stageRunning(jobId, "sign-defaults", null, null);
                }

                // NO auto-sign at toggle (redesign 2026-06-06). The toggle now ONLY
                // emits PENDING ADOPT CRs for the full login closure (governed entities
                // get a normal quarantining ADOPT CR; KC system/infrastructure entities
                // get an attestation-only ADOPT CR that signs WITHOUT quarantining). An
                // admin reviews + bulk-approves those CRs; the commit-time signer
                // (TideAttestor.stampProducerUnitColumns, invoked from
                // IgaAdminResource.commit) stamps each unit's producer column at
                // approval. The previous inline IgaToggleOnBackfill auto-sign — which did
                // an ORK ceremony for the whole closure inside the toggle request — is
                // removed: the toggle must return promptly and no signing happens here.
                // The login read fail-closes until the admin approves the ADOPT CRs;
                // that is the intended manual-signing model.

                // firstAdmin baseline-config AUTO-COMMIT (Option A). On a fresh realm
                // while it is still in firstAdmin mode, the default/baseline settings &
                // configuration CRs (the ALLOW-LIST in IgaFirstAdminAutoCommit:
                // ADOPT_*, realm-attribute/config, default-scope/group, client-scope,
                // client/role/group creation, protocol mappers, and a BENIGN
                // default-role ADD_COMPOSITE) are auto-approved + auto-committed here
                // — the firstAdmin never has to manually authorize+commit default config.
                // The sweep is double-gated (firstAdmin mode AND the firstAdmin VRK pack
                // active, the SAME isRealSigningCapableRealm probe the commit-time
                // producer-column stamper uses) and a no-op once the realm flips to
                // multiAdmin. Governed actions (CREATE_USER / GRANT_ROLES / privileged
                // composites) are EXCLUDED and stay PENDING for the normal manual flow.
                // If the VRK is not active the sweep is SKIPPED entirely (no stub stamps,
                // no rollback) and the CRs stay PENDING. The sweep reuses the hardened,
                // mutex-guarded bulk authorize+commit engine (IgaAdminResource.bulkAuthorize
                // -> processOneCr -> stampProducerUnitColumns + convergeAfterCommit), so
                // MF2 (DefaultRoleCompositeGuard) and the per-CR PENDING re-check (which
                // re-asserts firstAdmin via isAutoCommittable filtering before the request)
                // are inherited verbatim. Best-effort: a sweep failure must never abort
                // the toggle (the attribute is committed and the response is about to send).
                try {
                    IgaFirstAdminAutoCommit.SweepResult sweep =
                            runFirstAdminAutoCommitSweep(trackProgress ? jobService : null,
                                    trackProgress ? jobId : null, commitFailures);
                    if (sweep != null) {
                        body.put("autoCommit", sweep.toMap());
                    }
                    if (trackProgress) {
                        // committed/eligible as the final count; a skipped sweep
                        // (gates not met) reports 0/0 — still a completed stage.
                        long committed = sweep != null ? sweep.committed : 0L;
                        long eligible = sweep != null ? sweep.eligible : 0L;
                        jobService.stageDone(jobId, "sign-defaults", committed, eligible);
                    }
                } catch (RuntimeException sweepEx) {
                    logger.errorf(sweepEx, "IGA toggle-on firstAdmin auto-commit sweep FAILED for realm %s "
                            + "— toggle remains enabled; baseline-config CRs stay PENDING for manual handling.",
                            realm.getName());
                    // SIGN-AT-TOGGLE failure copy (Option 1 = rollback-to-PENDING).
                    // The sweep ran the commit flips + the converge ORK ceremony in a
                    // DEDICATED job tx; this throw means that tx already ROLLED BACK, so
                    // every ADOPT CR reverted to its scan-created PENDING state (NOT
                    // committed, NOT stub-committed) and the login closure is UNSIGNED.
                    final String closureUnsignedMsg =
                            "Default-config signing failed during toggle (likely the ORK "
                            + "network was unreachable or below threshold). IGA stays ENABLED "
                            + "and the baseline ADOPT change-requests were rolled back to "
                            + "PENDING — nothing was committed unsigned. Because the login "
                            + "closure is unsigned, logins FAIL CLOSED until an admin "
                            + "re-approves the PENDING ADOPT set (which rebuilds and re-signs "
                            + "the closure). Re-approve while the firstAdmin signing pack is "
                            + "still valid — it has a limited lifetime; if it expires before "
                            + "re-approval the realm must be re-provisioned.";
                    Map<String, Object> sweepErr = new LinkedHashMap<>();
                    sweepErr.put("error", sweepEx.getClass().getSimpleName());
                    sweepErr.put("message", String.valueOf(sweepEx.getMessage()));
                    sweepErr.put("warning", closureUnsignedMsg);
                    body.put("autoCommit", sweepErr);
                    // SOFTENED (2026-06-24): a sign-defaults sweep failure is a WARNING,
                    // not a hard failure. The toggle stays NON-BLOCKING — the attribute is
                    // committed, the realm is IGA-on, and (sign-at-toggle) the ADOPT set was
                    // ROLLED BACK to PENDING by the dedicated sweep tx (so it is genuinely
                    // PENDING, never committed-but-unsigned). The failure is carried into the
                    // end-summary as a commitFailures entry so the response returns 200 +
                    // completed_with_warnings (NOT failed / 500).
                    //
                    // This synthetic CONVERGE-failure entry is for the case where converge
                    // (the closure-signing ORK ceremony) itself threw. It now COEXISTS with
                    // the per-CR commitFailures entries that the engine ALREADY recorded
                    // in-lambda (per chunk) before the throw — those survived the job-tx
                    // rollback because commitFailures is request-scoped. The distinct
                    // sentinel crId="(sign-defaults sweep)" + converge-specific message keeps
                    // this entry visibly separate from the per-CR rows, so the UI can show
                    // BOTH "N CRs failed authorize/commit" AND "closure signing failed, left
                    // PENDING". The synthetic entry also guarantees the end-summary marks
                    // completed_with_warnings even if converge threw before any per-CR row.
                    Map<String, Object> sweepFail = new LinkedHashMap<>();
                    sweepFail.put("crId", "(sign-defaults sweep)");
                    sweepFail.put("actionType", "SIGN_DEFAULTS_SWEEP");
                    sweepFail.put("outcome", "CONVERGE_FAILED:"
                            + sweepEx.getClass().getSimpleName() + ": " + sweepEx.getMessage());
                    sweepFail.put("message", "Closure signing (convergeAfterCommit) failed; the "
                            + "baseline ADOPT set was rolled back to PENDING. " + closureUnsignedMsg);
                    commitFailures.add(sweepFail);
                    if (trackProgress) {
                        // Close the stage out (it was left running) WITHOUT failing
                        // the whole job — the finalize block below decides the job's
                        // terminal state (completed_with_warnings) once all warnings
                        // are collected. A stageDone here keeps the checklist from
                        // hanging on a never-finished sign-defaults stage; the
                        // sign-defaults stage gets its warning marker from the single
                        // completeWithWarnings call in the finalize block.
                        jobService.stageDone(jobId, "sign-defaults", 0L, 0L);
                    }
                }

                // finalize — advisory admin-coverage warning + job completion.
                // Skipped if the sweep already marked the job failed above (a
                // failed job must not be flipped back to running/completed —
                // stageRunning/complete guard on STATE==running internally).
                if (trackProgress) {
                    jobService.stageRunning(jobId, "finalize", null, null);
                }
                String warning = buildAdminCoverageWarning(session, realm);
                if (warning != null) {
                    body.put("warning", warning);
                }
                if (trackProgress) {
                    jobService.stageDone(jobId, "finalize", null, null);
                }

                // Per-entity ADOPT failures (IgaAdoptScan caught them per row,
                // incremented ScanResult.errors, collected each into
                // failedEntities, and CONTINUED so one poison entity cannot abort
                // adopting the rest). Record the count/headline into the body here;
                // the unified end-summary block below lists the failed entities and
                // sets the completed_with_warnings job state. NON-BLOCKING: the
                // toggle succeeded, the realm is enabled.
                long adoptErrors = resultHolder[0].errors;
                if (adoptErrors > 0) {
                    String adoptWarning = adoptErrors + " entit"
                            + (adoptErrors == 1 ? "y" : "ies")
                            + " failed to adopt; review the server log and re-scan.";
                    body.put("adoptErrors", adoptErrors);
                    body.put("adoptWarning", adoptWarning);
                    logger.warnf("IGA toggle-on: %d entit%s failed to adopt for realm %s "
                                    + "(per-entity errors, best-effort continue) — surfaced as a warning.",
                            adoptErrors, adoptErrors == 1 ? "y" : "ies", realm.getName());
                }
            } else if (errHolder[0] != null) {
                // SOFTENED (2026-06-24): TOTAL scan failure (the whole scan threw
                // before emitting any ADOPT CR). Previously a HARD-STOP (rollback +
                // 500). The user now wants the toggle NON-BLOCKING: do NOT roll back
                // isIGAEnabled and do NOT abort. RECORD the scan failure into the
                // end-summary (warnings.adoptScanFailed) and CONTINUE — the realm
                // stays IGA-on and the response is a 200 + completed_with_warnings.
                // The summary tells the admin the scan failed and to re-scan. (A
                // half-enabled realm fails logins closed until the admin re-scans;
                // that is the accepted trade for non-blocking, per the user.)
                adoptScanFailed[0] = errHolder[0].getClass().getSimpleName()
                        + ": " + errHolder[0].getMessage();
                logger.errorf(errHolder[0],
                        "IGA toggle-on scan failed entirely for realm %s — isIGAEnabled LEFT ENABLED "
                                + "(non-blocking); recorded in the warnings summary, admin should re-scan.",
                        realm.getName());
                body.put("scanError", adoptScanFailed[0]);
                // finalize stage record + advisory admin-coverage warning still run
                // on this path so the job/checklist reaches a terminal state.
                if (trackProgress) {
                    jobService.stageRunning(jobId, "finalize", null, null);
                }
                String warningTotal = buildAdminCoverageWarning(session, realm);
                if (warningTotal != null) {
                    body.put("warning", warningTotal);
                }
                if (trackProgress) {
                    jobService.stageDone(jobId, "finalize", null, null);
                }
            }

            // ----- UNIFIED END-SUMMARY (revised non-blocking contract 2026-06-24) -----
            // One structured "warnings" object collecting every best-effort failure
            // from this toggle so the UI can render it at the end. The toggle is
            // ALREADY non-blocking above (nothing rolled back, nothing 500'd on a
            // per-CR / per-entity / total-scan failure); this block only decides the
            // terminal JOB STATE and assembles the summary. completed_with_warnings
            // when ANY warning source is populated, else completed.
            List<Map<String, Object>> adoptFailures = resultHolder[0] != null
                    ? resultHolder[0].failedEntities
                    : java.util.Collections.emptyList();
            boolean anyWarnings = !adoptFailures.isEmpty()
                    || adoptScanFailed[0] != null
                    || !commitFailures.isEmpty()
                    || body.containsKey("approverRoleRepointError");
            if (anyWarnings) {
                Map<String, Object> warnings = new LinkedHashMap<>();
                warnings.put("adoptFailures", adoptFailures);
                warnings.put("adoptScanFailed", adoptScanFailed[0]);
                warnings.put("commitFailures", commitFailures);
                warnings.put("approverRoleRepointError", body.get("approverRoleRepointError"));
                body.put("warnings", warnings);

                String summaryMsg = "Toggle completed with warnings: "
                        + adoptFailures.size() + " entit" + (adoptFailures.size() == 1 ? "y" : "ies")
                        + " failed to adopt, "
                        + commitFailures.size() + " CR" + (commitFailures.size() == 1 ? "" : "s")
                        + " failed to commit"
                        + (adoptScanFailed[0] != null ? ", ADOPT scan failed (re-scan required)" : "")
                        + ".";
                body.put("warningsSummary", summaryMsg);
                logger.warnf("IGA toggle-on for realm %s: %s", realm.getName(), summaryMsg);
                if (trackProgress) {
                    // completed_with_warnings (non-fatal). The adopt-scan stage
                    // carries the warning marker + the concise summary message.
                    jobService.completeWithWarnings(jobId, "adopt-scan", summaryMsg);
                }
            } else if (trackProgress) {
                jobService.complete(jobId);
            }
        }

        // ON→OFF teardown MOVED to commit. The inline ON→OFF teardown that used
        // to live here (cancel PENDING ADOPTs + clear sidecar, evict the
        // user/realm caches, RS256 revert, and the isIGAEnabled=false write) is
        // now executed by IgaReplayDispatcher.replayDisableIga when the
        // DISABLE_IGA change request created above commits — NOT synchronously at
        // toggle time. A non-master ON→OFF therefore 202'd before reaching this
        // point and never falls through here; master keeps the direct-write path
        // (the writeIgaAttributeDirect above) with no teardown, exactly as before
        // (IGA is never on for master, so there is nothing to tear down).

        // NON-BLOCKING contract (revised 2026-06-24): the toggle ALWAYS returns 200
        // when it completes, whether clean or completed_with_warnings. Per-CR /
        // per-entity / total-scan failures never produce a non-2xx — they are
        // recorded in body.warnings (assembled in the unified end-summary above) and
        // the job ends completed_with_warnings. The ONLY non-2xx exits are the
        // sidecar-cap CAPACITY precondition (409, returned earlier) and a
        // truly-fatal pre-work error such as the IGA flag write throwing (which
        // would propagate as a 500 from writeIgaAttributeDirect before reaching
        // here). The removed Tier-3 toggleFailed/500 guard is intentionally gone.
        return Response.ok(body).build();
    }

    @GET
    @Path("iga-status")
    @Produces(MediaType.APPLICATION_JSON)
    public Response status() {
        auth.realm().requireViewRealm();
        boolean enabled = "true".equals(realm.getAttribute(IGA_ATTRIBUTE));
        return Response.ok(Map.of("enabled", enabled)).build();
    }

    /**
     * Live-progress poll for a toggle-on job (LOCKED CONTRACT). Returns the
     * {@code IGA_TOGGLE_JOB} row for {@code jobId} as:
     * <pre>{ jobId, state(running|completed|failed), currentStageId,
     *        stages:[ {id,label,status,current,total} ], error|null }</pre>
     * 404 if the jobId is unknown. Authz: same realm-admin gate as the toggle
     * (manage-realm).
     */
    @GET
    @Path("toggle-iga/status/{jobId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response toggleIgaStatus(@PathParam("jobId") String jobId) {
        auth.realm().requireManageRealm();
        Map<String, Object> status = new IgaToggleJobService(session).getStatus(session, jobId);
        if (status == null) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity(Map.of("error", "UNKNOWN_JOB", "jobId", String.valueOf(jobId)))
                    .build();
        }
        return Response.ok(status).build();
    }

    /**
     * SIGN-AT-TOGGLE FIX (Option A, deadlock-corrected 2026-06-24): durably COMMIT the
     * OFF→ON realm-state the downstream scan / firstAdmin-sweep / convergeAfterCommit
     * job sessions read, so they no longer see a STALE request-tx realm.
     *
     * <p><b>Ordering is load-bearing (deadlock fix).</b> This runs as the VERY FIRST
     * realm-row write of the OFF→ON path — BEFORE the request transaction sets any of
     * {@code iga.attestor} / {@code defaultSignatureAlgorithm} / {@code isIGAEnabled}
     * on the realm row. An EARLIER revision (95d84f7) ran this AFTER the request tx had
     * already written (and locked) those same realm-attribute rows; the nested job tx's
     * write to the SAME rows then blocked on the request tx's uncommitted lock while the
     * request tx synchronously waited for this nested {@code runJobInTransaction} to
     * return → self-deadlock → the toggle HUNG. Running this committed write FIRST means
     * it acquires, holds, and RELEASES the realm-row lock entirely before the request tx
     * touches that row; the request tx's later in-memory writes (kept only so the
     * REQUEST realm adapter reflects tide+enabled for the request-side sweep/repoint
     * gates) then flush against rows no other tx still holds — no two transactions ever
     * contend for the realm row.</p>
     *
     * <p>Why durable at all: the request-session writes alone live only on the
     * UNCOMMITTED request transaction. The ADOPT scan ({@code IgaAdoptScan}), the
     * firstAdmin auto-commit sweep, and its {@code IgaToggleOnBackfill.convergeAfterCommit}
     * each open their OWN {@code runJobInTransaction} session and re-resolve a fresh
     * {@code session.realms().getRealm(realmId)} that does NOT observe the request tx's
     * pending writes. {@code IgaAttestors.resolveAttestor} (reads realm attr
     * {@code iga.attestor}) and {@code TideAttestor.resolveMode} (its no-authorizer-row
     * branch also reads {@code iga.attestor}) would therefore resolve {@code null} →
     * {@code simple} / non-tide in the job session: the sweep would sign via
     * {@code SimpleNameAttestor} and the firstAdmin backfill would be skipped, deferring
     * the real ORK signing to a later manual commit. Committing the state HERE — in a
     * dedicated job tx that commits before those job sessions open — makes it visible to
     * all of them.</p>
     *
     * <p>{@code desiredSigAlg} is computed by the caller from the VRK-active probe
     * (EdDSA when active, else the pre-toggle algorithm unchanged) and persisted here so
     * the durable row matches the request-side decision exactly. All writes go under
     * {@code IGA_REPLAY_ACTIVE} in the job session so the IGA capture interceptor does
     * not re-route them into a {@code SET_REALM_ATTRIBUTE} CR.</p>
     *
     * <p>After the commit we evict the realm cache on the REQUEST session (extended to
     * invalidate the realm singleton itself) so a {@code RealmCacheSession} opened by a
     * later job session re-loads the realm from the DB rather than serving the
     * pre-toggle {@code CachedRealm} snapshot.</p>
     *
     * <p>Best-effort on the cache eviction (a failure must never abort the toggle); the
     * durable write itself is load-bearing, so a write failure propagates (the toggle's
     * outer non-blocking contract still applies to everything AFTER this point).</p>
     */
    private void persistRealmStateForSweep(String realmId, boolean tideRealm, String desiredSigAlg) {
        KeycloakModelUtils.runJobInTransaction(
                session.getKeycloakSessionFactory(),
                stateSession -> {
                    RealmModel stateRealm = stateSession.realms().getRealm(realmId);
                    if (stateRealm == null) {
                        throw new IllegalStateException(
                                "IGA toggle persistRealmStateForSweep: realm " + realmId
                                        + " not loadable in state session");
                    }
                    Object prior = stateSession.getAttribute("IGA_REPLAY_ACTIVE");
                    stateSession.setAttribute("IGA_REPLAY_ACTIVE", "true");
                    try {
                        // iga.attestor=tide — the discriminator resolveAttestor /
                        // resolveMode read in the job session. Only on a Tide realm
                        // (tide IdP + tide-vendor-key present); a non-Tide OFF→ON realm
                        // commits only isIGAEnabled and leaves the attestor untouched.
                        if (tideRealm
                                && !"tide".equals(stateRealm.getAttribute(IGA_ATTESTOR_ATTRIBUTE))) {
                            stateRealm.setAttribute(IGA_ATTESTOR_ATTRIBUTE, "tide");
                        }
                        // isIGAEnabled=true — the firstAdmin/quarantine gate.
                        stateRealm.setAttribute(IGA_ATTRIBUTE, Boolean.TRUE.toString());
                        // Mirror the request-side default-sig-alg decision (EdDSA iff the
                        // VRK-active probe passed; otherwise the realm's current algorithm,
                        // so this is a no-op write when unchanged).
                        if (desiredSigAlg != null
                                && !desiredSigAlg.equals(stateRealm.getDefaultSignatureAlgorithm())) {
                            stateRealm.setDefaultSignatureAlgorithm(desiredSigAlg);
                        }
                    } finally {
                        if (prior == null) {
                            stateSession.removeAttribute("IGA_REPLAY_ACTIVE");
                        } else {
                            stateSession.setAttribute("IGA_REPLAY_ACTIVE", prior);
                        }
                    }
                });
        // The state tx has committed. Evict the realm cache (incl. the realm singleton)
        // on the request session so a later job session re-reads the committed attrs.
        evictRealmCache(session, realm);
        logger.infof("IGA toggle-on: committed sweep-visible realm state for realm %s "
                        + "(iga.attestor=tide, isIGAEnabled=true, defaultSignatureAlgorithm=%s) "
                        + "and evicted realm cache so the scan/sweep job sessions resolve TideAttestor.",
                realm.getName(), desiredSigAlg);
    }

    /**
     * SIGN-AT-TOGGLE FIX (2026-06-24): durably revert {@code isIGAEnabled} to its
     * pre-toggle value when the OFF→ON path refuses on the sidecar-cap precondition
     * (409). {@link #persistRealmStateForSweep} committed {@code isIGAEnabled=true} in a
     * separate tx, so the request-tx rollback alone would leave the realm half-enabled.
     * This re-opens a job tx and writes the pre-toggle value durably (under
     * {@code IGA_REPLAY_ACTIVE}), then re-evicts the realm cache. {@code iga.attestor}
     * is intentionally LEFT at tide — a harmless, idempotent discriminator while IGA is
     * off. Best-effort cache eviction; the durable write propagates on failure.
     */
    private void revertIgaEnabledDurably(String realmId, boolean priorEnabled) {
        KeycloakModelUtils.runJobInTransaction(
                session.getKeycloakSessionFactory(),
                stateSession -> {
                    RealmModel stateRealm = stateSession.realms().getRealm(realmId);
                    if (stateRealm == null) {
                        throw new IllegalStateException(
                                "IGA toggle revertIgaEnabledDurably: realm " + realmId
                                        + " not loadable in state session");
                    }
                    Object prior = stateSession.getAttribute("IGA_REPLAY_ACTIVE");
                    stateSession.setAttribute("IGA_REPLAY_ACTIVE", "true");
                    try {
                        stateRealm.setAttribute(IGA_ATTRIBUTE, Boolean.toString(priorEnabled));
                    } finally {
                        if (prior == null) {
                            stateSession.removeAttribute("IGA_REPLAY_ACTIVE");
                        } else {
                            stateSession.setAttribute("IGA_REPLAY_ACTIVE", prior);
                        }
                    }
                });
        evictRealmCache(session, realm);
        logger.infof("IGA toggle-on refused (sidecar cap): durably reverted isIGAEnabled=%s for realm %s.",
                priorEnabled, realm.getName());
    }

    /**
     * Normalize the optional {@code jobId} form field. Null when absent / blank
     * (the OFF-toggle and the legacy no-jobId POST send no jobId field at all) —
     * in which case the toggle runs exactly as before with no progress tracking.
     */
    static String normalizeJobId(String jobId) {
        if (jobId == null) {
            return null;
        }
        String s = jobId.trim();
        return s.isEmpty() ? null : s;
    }

    /**
     * Write the realm IGA attribute while bypassing the IGA realm-adapter
     * capture interceptor.
     *
     * <p>{@link org.tidecloak.iga.providers.IgaRealmAdapter#setAttribute}
     * intercepts every realm-attribute write when IGA is currently ON and
     * routes it through a {@code SET_REALM_ATTRIBUTE} change request instead
     * of writing directly. That behaviour is correct for arbitrary realm
     * attributes but fatal for the toggle attribute itself: turning IGA OFF
     * via this endpoint would emit a CR (response lies "enabled=false" while
     * isIGAEnabled stays "true"), the toggle-off cancel runs against a still-ON
     * realm, and the next toggle hits {@code checkNoPendingCr} → 500 because
     * the prior toggle-off CR is still PENDING.</p>
     *
     * <p>The toggle endpoint IS the governing action (gated by
     * requireManageRealm), so the {@link
     * org.tidecloak.iga.replay.IgaReplayExtension} bypass token
     * {@code IGA_REPLAY_ACTIVE=true} is the correct, established way to
     * declare "this write is the act of governance itself; do not capture
     * it". The wrapper checks the session attribute and short-circuits to
     * {@code super.setAttribute}.</p>
     *
     * <p>try/finally is mandatory — the session is request-scoped and a
     * lingering IGA_REPLAY_ACTIVE on this thread/session would silently
     * disable ALL subsequent IGA capture for the rest of the request,
     * including any nested provider calls invoked by the scan/cancel
     * follow-ups.</p>
     */
    private void writeIgaAttributeDirect(String name, String value) {
        Object prior = session.getAttribute("IGA_REPLAY_ACTIVE");
        session.setAttribute("IGA_REPLAY_ACTIVE", "true");
        try {
            realm.setAttribute(name, value);
        } finally {
            if (prior == null) {
                session.removeAttribute("IGA_REPLAY_ACTIVE");
            } else {
                session.setAttribute("IGA_REPLAY_ACTIVE", prior);
            }
        }
    }

    /**
     * Sibling of {@link #writeIgaAttributeDirect}: write the realm's default
     * signature algorithm while bypassing the IGA realm-adapter capture
     * interceptor.
     *
     * <p>Prior investigation found {@link
     * org.tidecloak.iga.providers.IgaRealmAdapter} does NOT override
     * {@code setDefaultSignatureAlgorithm}, so this write would pass straight
     * through and is not captured. We still wrap it under the same
     * {@code IGA_REPLAY_ACTIVE} suppression as {@link #writeIgaAttributeDirect}
     * for safety and consistency: should the adapter ever start intercepting
     * this setter, the bypass already declares "this write is the act of
     * governance itself; do not capture it". The try/finally restore is
     * mandatory for the same reason documented on {@link
     * #writeIgaAttributeDirect} — a lingering IGA_REPLAY_ACTIVE on this
     * request-scoped session would silently disable all subsequent IGA
     * capture for the rest of the request.</p>
     */
    private void writeDefaultSignatureAlgorithmDirect(String value) {
        Object prior = session.getAttribute("IGA_REPLAY_ACTIVE");
        session.setAttribute("IGA_REPLAY_ACTIVE", "true");
        try {
            realm.setDefaultSignatureAlgorithm(value);
        } finally {
            if (prior == null) {
                session.removeAttribute("IGA_REPLAY_ACTIVE");
            } else {
                session.setAttribute("IGA_REPLAY_ACTIVE", prior);
            }
        }
    }

    /**
     * VRK-active gate for the OFF→ON EdDSA switch. Switching a realm's default
     * signature algorithm to EdDSA before the realm's active VRK is
     * provisioned breaks ALL signing (EdDSA selected with an empty active key),
     * so the toggle only flips to EdDSA when the {@code tide-vendor-key}
     * component config proves the active key material is present:
     *
     * <ul>
     *   <li>{@code clientId} non-empty — the active EdDSA public point;</li>
     *   <li>{@code vvkId} non-empty — the active-VRK proxy;</li>
     *   <li>{@code activeVrk} non-blank — parsed from the {@code clientSecret}
     *       {@link SecretKeys} JSON blob (mirrors how
     *       {@code TideAttestor.isRealSigningCapable} reads it); a
     *       {@code clientSecret='{}'} fails here.</li>
     * </ul>
     *
     * <p>Non-throwing: a missing config or an unparseable {@code clientSecret}
     * is treated as "not active" (defer EdDSA), never an error — consistent
     * with the firstAdmin capability probe.</p>
     */
    private static boolean isVrkActive(ComponentModel tideVendorKey) {
        if (tideVendorKey == null || tideVendorKey.getConfig() == null) {
            return false;
        }
        MultivaluedHashMap<String, String> config = tideVendorKey.getConfig();
        String clientId = config.getFirst(CFG_CLIENT_ID);
        if (clientId == null || clientId.isBlank()) {
            return false;
        }
        String vvkId = config.getFirst(CFG_VVK_ID);
        if (vvkId == null || vvkId.isBlank()) {
            return false;
        }
        String clientSecret = config.getFirst(CFG_CLIENT_SECRET);
        if (clientSecret == null || clientSecret.isBlank()) {
            return false;
        }
        try {
            SecretKeys secretKeys = MAPPER.readValue(clientSecret, SecretKeys.class);
            return secretKeys != null && secretKeys.activeVrk != null && !secretKeys.activeVrk.isBlank();
        } catch (Exception parseFail) {
            return false; // unparseable clientSecret → treat as not-active (defer EdDSA).
        }
    }

    /**
     * Bulk-invalidate every live user session on the realm after a
     * successful OFF→ON ADOPT scan, returning the number of sessions that
     * were dropped.
     *
     * <p>We invalidate ALL user sessions in
     * the realm and accept the re-login storm rather than tracking which
     * users were just quarantined: it is simpler, strictly correct (any user
     * whose roles/groups were quarantined will reflect the new state on their
     * next token issuance), and the alternative would require a per-user
     * walk on the same session that just did the scan. KC 26.5.5
     * UserSessionProvider exposes {@code removeUserSessions(RealmModel)} as
     * the bulk primitive (the same call backing the realm-wide "logout all"
     * admin endpoint), which is exactly the call we need.</p>
     *
     * <p>Counting: KC's bulk method returns void, so we count by streaming the
     * pre-existing sessions per user via {@code getUserSessionsStream} before
     * the bulk removal — but that would be a full table scan. Instead we
     * count by iterating {@code session.users().getUsersStream} and summing
     * the per-user session count via
     * {@code session.sessions().getActiveUserSessions(realm, /*client*&#x2f;null)}
     * — actually the cleanest portable count uses
     * {@code getUserSessionsCount(realm, /*client*&#x2f;null)} but KC 26.5.5
     * only exposes a per-client variant. So the pragmatic, low-overhead
     * approach: call {@code getActiveClientSessionStats(realm, false)} to get
     * the total active count across clients (sum of values), then call the
     * bulk remove. The count is best-effort (logged on overflow) — its
     * primary purpose is operator visibility, not byte-accurate accounting.
     * </p>
     *
     * <p>NB: this method is called on the REQUEST session ({@link #session}),
     * NOT the fresh scan session — the scan-session is closed before the
     * scan returns to its caller, and a fresh runJobInTransaction session
     * does not have a UserSessionProvider wired (it is JPA-only). The
     * request session here is the admin token's session, which has both
     * the JPA provider and the user-session provider.</p>
     */
    private static long invalidateRealmSessions(KeycloakSession session, RealmModel realm) {
        long count = 0L;
        try {
            // Best-effort count BEFORE invalidation. KC's active-client stats
            // returns Map<String,Long> per-client active-session counts;
            // summing approximates the realm-wide live count. If the call
            // raises (some providers don't implement it on every storage
            // backend) we still proceed with the bulk remove and report 0.
            try {
                Map<String, Long> stats =
                        session.sessions().getActiveClientSessionStats(realm, false);
                if (stats != null) {
                    for (Long v : stats.values()) {
                        if (v != null) count += v;
                    }
                }
            } catch (RuntimeException counts) {
                logger.debugf(counts,
                        "invalidateRealmSessions: pre-count failed (best-effort) — proceeding with bulk remove");
            }
            session.sessions().removeUserSessions(realm);
            logger.infof("IGA toggle-on session invalidation: realm=%s sessionsInvalidated~=%d",
                    realm.getName(), count);
        } catch (RuntimeException ex) {
            // Never let a session-invalidation failure abort the toggle —
            // the realm attribute is already committed and the response is
            // about to be sent. Log and return whatever we counted.
            logger.errorf(ex,
                    "IGA toggle-on session invalidation FAILED for realm %s — toggle remains enabled; existing sessions may persist past quarantine.",
                    realm.getName());
        }
        return count;
    }

    /**
     * Direct-grant miss eviction — evict every cached user
     * entry for the realm so subsequent {@code session.users().getUserBy*}
     * lookups re-load through {@code IgaUserProvider} and the
     * {@code IgaUserAdapter#isEnabled} quarantine override fires.
     *
     * <p>The infinispan user-cache ({@code model/infinispan UserCacheSession})
     * returns a {@code CachedUser}-backed {@code UserAdapter} whose
     * {@code isEnabled()} reads the snapshot recorded at cache-load time
     * and does NOT delegate
     * to the underlying {@code IgaUserAdapter} on each call. Without an
     * eviction, the OFF→ON toggle does not affect users whose cache entry was
     * seeded before the toggle (e.g. a pre-IGA direct-grant or admin REST read
     * cached {@code enabled=true}); KC's quarantine override is then never
     * consulted on the next direct-grant and an unsigned user incorrectly
     * receives a token.</p>
     *
     * <p>The eviction primitive is {@link UserCache#evict(RealmModel)}
     * (bulk per-realm eviction). It is the right
     * grain because the OFF→ON scan may have quarantined any number of users
     * in the realm (no per-user information is plumbed back from the scan)
     * and the toggle is a rare admin action — the re-warm cost is acceptable
     * and bounded.</p>
     *
     * <p>Best-effort: if the cache provider isn't installed
     * ({@code UserStorageUtil.userCache(session)} returns {@code null} when
     * the deployment runs without infinispan) or the eviction throws, log
     * and continue. The toggle attribute is already committed and the
     * response is about to be sent — a cache-eviction failure must never
     * abort the toggle.</p>
     */
    private static void evictRealmUserCache(KeycloakSession session, RealmModel realm) {
        // Delegated to the shared util so the DISABLE_IGA commit-replay teardown
        // (IgaReplayDispatcher.replayDisableIga, a different package) runs the
        // IDENTICAL eviction this toggle path runs.
        org.tidecloak.iga.services.IgaRealmCacheEviction.evictRealmUserCache(session, realm);
    }

    /**
     * CLIENT quarantine eviction, symmetric to
     * {@link #evictRealmUserCache} — evict every cached client / role / group
     * / client-scope entry for the realm so subsequent
     * {@code session.clients()} / {@code realm.getRole*} / {@code realm.getGroup*}
     * / {@code realm.getClientScopes*} reads re-load through the IGA wrappers
     * ({@link org.tidecloak.iga.providers.IgaClientAdapter} and friends) and
     * the quarantine overrides ({@code isEnabled()} REFUSE on clients,
     * {@code getScopeMappingsStream} STRIP on client scopes, etc.) fire on
     * the next call.
     *
     * <p>KC's realm-cache ({@code model/infinispan RealmCacheSession})
     * returns a {@code CachedClient}-backed {@link
     * org.keycloak.models.cache.infinispan.ClientAdapter} whose
     * {@code isEnabled()} reads the snapshot recorded at cache-load time
     * and does NOT delegate to the
     * underlying {@link org.tidecloak.iga.providers.IgaClientAdapter} on each
     * call. Without an eviction, the OFF→ON toggle does not affect clients
     * whose realm-cache entry was seeded before the toggle (e.g. a pre-IGA
     * {@code client_credentials} call cached {@code enabled=true}); the
     * quarantine REFUSE hook is then never consulted on the next
     * {@code client_credentials} and the unsigned client incorrectly receives
     * a token. The same snapshot-bypass applies to cached
     * {@code CachedRole}/{@code CachedGroup}/{@code CachedClientScope} for the
     * realm: each has an IGA wrapper whose enforcement is skipped when the
     * realm-cache returns its own adapter.</p>
     *
     * <p>API choice: {@code CacheRealmProvider.registerRealmInvalidation(id, name)}
     * invalidates only the realm entry + its by-name key — it does NOT cascade
     * to clients/roles/groups/scopes. The coarser primitive
     * {@code RealmCacheSession.evictRealmOnRemoval} sweeps everything in-realm
     * but emits a {@link
     * org.keycloak.models.cache.infinispan.events.RealmRemovedEvent} that
     * would falsely tell the cluster the realm is gone — not safe to reuse.
     * The surgical correct primitive is per-entity:
     * {@code registerClientInvalidation(uuid, clientId, realmId)} +
     * {@code registerRoleInvalidation(id, name, containerId)} +
     * {@code registerGroupInvalidation(id)} +
     * {@code registerClientScopeInvalidation(id, realmId)}, each of which
     * drops the corresponding cache entry on transaction commit. We iterate
     * the four entity collections on the realm and call each. The iterators
     * ({@code realm.getClientsStream}, {@code session.roles().getRealmRolesStream},
     * {@code realm.getGroupsStream}, {@code realm.getClientScopesStream}) all
     * delegate past the cache, so iteration does
     * not re-warm what we are about to evict.</p>
     *
     * <p>The toggle is a rare admin action; the re-warm cost is bounded by
     * the realm's entity counts and acceptable. Best-effort wrapping: if the
     * {@link CacheRealmProvider} is not installed (deployment running without
     * the infinispan realm-cache layer) the lookup returns {@code null} and
     * we log and return. If any individual register-invalidation throws, we
     * catch and continue with the next entity — the toggle attribute is
     * already committed and the response is about to be sent; a partial
     * eviction is preferable to an aborted toggle.</p>
     */
    private static void evictRealmCache(KeycloakSession session, RealmModel realm) {
        // Delegated to the shared util so the DISABLE_IGA commit-replay teardown
        // (IgaReplayDispatcher.replayDisableIga, a different package) runs the
        // IDENTICAL client/role/group/scope/org/idp eviction this toggle path runs.
        org.tidecloak.iga.services.IgaRealmCacheEviction.evictRealmCache(session, realm);
    }

    /**
     * Best-effort current admin id for stamping the emitted CRs' requestedBy
     * column. Mirrors {@code IgaAdminResource#currentUserId}.
     */
    private String currentUserId() {
        try {
            if (auth != null && auth.adminAuth() != null && auth.adminAuth().getUser() != null) {
                return auth.adminAuth().getUser().getId();
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    /**
     * Drive the firstAdmin baseline-config auto-commit sweep on the OFF→ON toggle
     * tail (Option A). Delegates all gating + classification to
     * {@link IgaFirstAdminAutoCommit#sweep}: the two gates (firstAdmin mode + the
     * firstAdmin VRK pack active) and the allow-list / MF2 per-CR filter live there;
     * this method only assembles the inputs and provides the engine.
     *
     * <p>Candidate CRs are fetched as the PENDING CRs whose action type is in the
     * baseline-config allow-list (so governed CRs — CREATE_USER, GRANT_ROLES, etc. —
     * are never even loaded); {@code IgaFirstAdminAutoCommit.isAutoCommittable} then
     * applies the ADD_COMPOSITE default-role + MF2 fine filter. The injected
     * {@link IgaFirstAdminAutoCommit.BulkEngine} delegates to the SAME hardened
     * {@code IgaAdminResource.bulkAuthorize} engine the admin UI's bulk-approve uses
     * (per-realm {@code IgaBulkLock}, per-CR PENDING re-check, producer-column
     * stamping, full-closure backfill), constructed with the toggle's own
     * {@code session}/{@code realm}/{@code auth} so {@code requireManageRealm} and the
     * firstAdmin signer resolve identically.</p>
     *
     * <p>Returns {@code null} only if there is nothing to do at the gate level (the
     * gates short-circuit inside {@code sweep}, which still returns a SweepResult);
     * never throws for a normal skip — only a genuine engine failure propagates and
     * is caught by the caller as best-effort.</p>
     */
    private IgaFirstAdminAutoCommit.SweepResult runFirstAdminAutoCommitSweep(
            IgaToggleJobService jobService, String jobId,
            List<Map<String, Object>> commitFailures) {
        IgaChangeRequestService service = new IgaChangeRequestService(
                session.getProvider(JpaConnectionProvider.class).getEntityManager(), session);
        // Pull only the baseline-config allow-list action types as candidates (governed
        // CRs are never loaded). High limit — a fresh-realm provisioning closure is well
        // under this; the per-CR MF2/default-role filter happens in isAutoCommittable.
        List<String> allowList = new ArrayList<>(IgaFirstAdminAutoCommit.BASELINE_CONFIG_ACTION_TYPES);
        List<IgaChangeRequestEntity> candidates =
                service.listPendingByActionTypeIn(realm.getId(), allowList, null, 100_000);

        UserModel admin = currentUserModel();
        // Resolve the firstAdmin signer by ID so the job-tx engine can re-load the
        // same admin in its OWN session (a UserModel is bound to the session that
        // created it and must not cross the request → job-session boundary).
        //
        // CROSS-REALM CAPTURE (2026-06-24 NPE fix): also capture the realm the admin
        // actually LIVES in. The toggle caller is frequently a master-realm / cross-realm
        // super-admin who does NOT exist in the target realm, so re-resolving solely via
        // sweepSession.users().getUserById(targetRealm, adminId) returns null → every CR
        // NPEs at SimpleNameAttestor.record. The admin's home realm comes from the
        // AdminAuth (auth.adminAuth().getRealm()); the sweep re-loads them from THAT realm
        // first, falling back to the target realm for the same-realm case. The attestor is
        // additionally null-tolerant (records a system principal) so a still-unresolved
        // admin can never abort the system-bootstrap sweep again.
        final String adminId = admin != null ? admin.getId() : null;
        final String adminRealmId = currentAdminRealmId();
        final String realmId = realm.getId();

        IgaFirstAdminAutoCommit.BulkEngine engine = crIdIn -> {
            // Drive the bulk engine by the EXACT per-CR-eligible ids (not action
            // type): the narrowed scope means a single action type can hold both
            // eligible and ineligible CRs (system vs admin-authored ADOPT, benign
            // vs non-default composite), so an action-type drain would over-commit.
            //
            // SIGN-AT-TOGGLE TX SCOPING (Option 1 = rollback-to-PENDING, 2026-06-24):
            // the per-CR commit flips (processOneCr → APPROVED) AND the post-batch
            // converge (IgaToggleOnBackfill.convergeAfterCommit → the firstAdmin VVK
            // ORK ceremony) run inside ONE dedicated KeycloakModelUtils.runJobInTransaction
            // — a SEPARATE session/tx from the outer toggle request tx. Two end-states:
            //   • ORK sign SUCCEEDS → the job tx commits: the whole ADOPT set is APPROVED
            //     and the full login closure carries real 64B sigs.
            //   • ORK sign FAILS (ORK down / threshold / pack) → convergeAfterCommit throws
            //     out of the bulk core; runJobInTransaction ROLLS BACK the job tx, so every
            //     APPROVED flip reverts to its scan-created PENDING state. The throw
            //     propagates to runFirstAdminAutoCommitSweep's caller, which records a
            //     warning and returns 200 completed_with_warnings. CRUCIALLY this rollback
            //     is scoped to the sweep: the outer request tx (IGA-enable flag) and the
            //     ADOPT scan (its own already-committed job tx) are untouched — IGA stays
            //     ENABLED and the PENDING ADOPT CRs persist for a later manual re-approve
            //     (which rebuilds the sign request fresh and re-fires converge).
            // The whole eligible set runs in a SINGLE job tx (chunked only for the bulk
            // core's internal limit) so a failure rolls back ALL flips, never a partial
            // commit. Progress is reported on the REQUEST jobService (separate from the
            // job tx) so the live count is not part of what a sweep rollback reverts.
            final int total = crIdIn.size();
            final int chunkSize = 25;
            List<Map<String, Object>> out = new ArrayList<>();
            // committed counter is written INSIDE the job lambda (per chunk) so the
            // request-side progress report below reflects the real committed count even
            // though the per-CR collection now happens in-lambda. A 1-element holder is
            // used because a lambda can only capture effectively-final locals.
            final int[] committedHolder = {0};
            if (jobId != null) {
                jobService.stageProgress(jobId, "sign-defaults", 0L, (long) total);
            }

            KeycloakModelUtils.runJobInTransaction(
                    session.getKeycloakSessionFactory(),
                    sweepSession -> {
                        RealmModel sweepRealm = sweepSession.realms().getRealm(realmId);
                        if (sweepRealm == null) {
                            throw new IllegalStateException(
                                    "IGA firstAdmin sweep: realm " + realmId + " not loadable in sweep session");
                        }
                        sweepSession.getContext().setRealm(sweepRealm);
                        // Re-resolve the toggle-calling admin inside the JOB session. Try the
                        // admin's HOME realm first (handles the master/cross-realm super-admin
                        // who does not exist in the target realm), then fall back to the target
                        // realm (same-realm admin). May still be null (e.g. no AdminAuth on a
                        // service-driven toggle) — the attestor tolerates that and records a
                        // system principal rather than NPEing the whole sweep.
                        UserModel sweepAdmin = null;
                        if (adminId != null) {
                            if (adminRealmId != null && !adminRealmId.equals(realmId)) {
                                RealmModel adminRealm = sweepSession.realms().getRealm(adminRealmId);
                                if (adminRealm != null) {
                                    sweepAdmin = sweepSession.users().getUserById(adminRealm, adminId);
                                }
                            }
                            if (sweepAdmin == null) {
                                sweepAdmin = sweepSession.users().getUserById(sweepRealm, adminId);
                            }
                        }
                        // Construct the bulk engine on the JOB session (auth=null is safe:
                        // bulkAuthorizeInternal does NOT call requireManageRealm — the toggle
                        // endpoint already gated this; the signer is passed explicitly).
                        IgaAdminResource sweepResource =
                                new IgaAdminResource(sweepSession, sweepRealm, null);
                        for (int from = 0; from < total; from += chunkSize) {
                            int to = Math.min(from + chunkSize, total);
                            List<String> chunk = new ArrayList<>(crIdIn.subList(from, to));
                            // bulkAuthorizeInternal commits each chunk's eligible CRs + runs
                            // convergeAfterCommit when the last ADOPT drains. A converge throw
                            // here propagates → the whole job tx rolls back (Option 1).
                            Response resp = sweepResource.bulkAuthorizeInternal(sweepAdmin, chunk, 1000);
                            Object entity = resp.getEntity();
                            if (entity instanceof Map<?, ?> respMap) {
                                Object results = respMap.get("results");
                                if (results instanceof List<?> list) {
                                    for (Object o : list) {
                                        if (o instanceof Map<?, ?> m) {
                                            @SuppressWarnings("unchecked")
                                            Map<String, Object> cast = (Map<String, Object>) m;
                                            out.add(cast);
                                            // SURFACING HARDENING (2026-06-24): convert each
                                            // per-CR outcome into commitFailures/committed count
                                            // HERE, per chunk, INSIDE the job lambda — BEFORE the
                                            // NEXT chunk's bulkAuthorizeInternal (which may fire
                                            // convergeAfterCommit and THROW out of the lambda).
                                            // commitFailures is a REQUEST-scope list (it lives on
                                            // the outer request tx, NOT this job tx), so entries
                                            // added here SURVIVE a job-tx rollback caused by a
                                            // later converge throw. Previously this conversion ran
                                            // AFTER the lambda returned, so a converge throw
                                            // discarded every per-CR row in `out` along with the
                                            // rolled-back job tx, leaving only the coarse synthetic
                                            // SIGN_DEFAULTS_SWEEP entry from the caller's catch.
                                            String status = String.valueOf(cast.get("status"));
                                            if ("COMMITTED".equals(status)) {
                                                committedHolder[0]++;
                                            } else {
                                                Map<String, Object> fail = new LinkedHashMap<>();
                                                fail.put("crId", cast.get("crId"));
                                                fail.put("actionType", cast.get("actionType"));
                                                Object err = cast.get("error");
                                                fail.put("outcome", err != null ? status + ":" + err : status);
                                                commitFailures.add(fail);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    });

            // The job tx COMMITTED (no converge throw). The per-CR outcomes were already
            // converted into commitFailures (non-COMMITTED) / committedHolder (COMMITTED)
            // INSIDE the lambda above, per chunk, so they survive even on a converge throw
            // (which rolls the job tx back but NOT the request-scope commitFailures list).
            // Do NOT re-walk `out` here — that would DOUBLE-count the same rows. This block
            // only mirrors the final committed count into the request-side progress report
            // (a sweep rollback never reaches this line — it threw out of the lambda).
            if (jobId != null) {
                jobService.stageProgress(jobId, "sign-defaults", (long) committedHolder[0], (long) total);
            }
            return out;
        };

        return IgaFirstAdminAutoCommit.sweep(session, realm, admin, candidates, engine);
    }

    /** Best-effort current admin {@link UserModel} for the auto-commit sweep signer. */
    private UserModel currentUserModel() {
        try {
            if (auth != null && auth.adminAuth() != null) {
                return auth.adminAuth().getUser();
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    /**
     * Best-effort id of the realm the toggle-calling admin actually LIVES in (the realm
     * they authenticated against — master for a cross-realm super-admin). Used by the
     * auto-commit sweep to re-resolve the {@link UserModel} in the correct realm inside
     * its job session: {@code getUserById(targetRealm, masterAdminId)} would return null
     * for a cross-realm caller and NPE the attestor. Null when no AdminAuth is present.
     */
    private String currentAdminRealmId() {
        try {
            if (auth != null && auth.adminAuth() != null && auth.adminAuth().getRealm() != null) {
                return auth.adminAuth().getRealm().getId();
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    /**
     * Heuristic admin-coverage check. Once quarantine enforcement is active, a
     * realm whose only admin holder is the realm's first (governance-only) user
     * will lock itself out the moment we start enforcing PENDING ADOPT_USER. We
     * warn so the operator can provision a second admin / configure approver-roles
     * before that.
     *
     * <p>Heuristic: count distinct holders of {@code realm-management:
     * manage-realm} + any role named by an existing {@code iga.approverRole}
     * realm attribute. If the union is &lt; 2, emit the warning. We
     * deliberately do NOT 4xx — the user can still proceed; the warning is
     * advisory and the master-realm escape hatch is the supported recovery
     * path.</p>
     */
    private static String buildAdminCoverageWarning(KeycloakSession session, RealmModel realm) {
        try {
            int holders = 0;
            // realm-management:manage-realm holders
            var rm = realm.getClientByClientId("realm-management");
            if (rm != null) {
                RoleModel manageRealm = rm.getRole("manage-realm");
                if (manageRealm != null) {
                    long count = session.users().getRoleMembersStream(realm, manageRealm).count();
                    holders = (int) Math.min(Integer.MAX_VALUE, count);
                }
            }
            // approver-role holders (additive — the approver role is the
            // ONLY way a non-manage-realm admin can authorize in Tideless).
            String approverRoleAttr = realm.getAttribute("iga.approverRole");
            if (approverRoleAttr != null && !approverRoleAttr.isEmpty()) {
                for (String roleName : approverRoleAttr.split(",")) {
                    roleName = roleName.trim();
                    if (roleName.isEmpty()) continue;
                    RoleModel approver = realm.getRole(roleName);
                    if (approver != null) {
                        long count = session.users().getRoleMembersStream(realm, approver).count();
                        holders += (int) Math.min(Integer.MAX_VALUE, count);
                    }
                }
            }
            if (holders < 2) {
                return "Fewer than 2 distinct admin holders detected for realm '"
                        + realm.getName() + "' (manage-realm + iga.approverRole "
                        + "candidates: " + holders + "). Phase 6c will enforce ADOPT "
                        + "approval before admin actions — provision a second "
                        + "manage-realm admin (or configure iga.approverRole) NOW. "
                        + "Recovery path if locked out: the master-realm admin can "
                        + "always disable IGA on this realm via the master realm "
                        + "(escape hatch) — there is no other recovery.";
            }
        } catch (RuntimeException ex) {
            logger.warnf(ex, "buildAdminCoverageWarning: heuristic failed for realm %s — " +
                    "warning suppressed.", realm.getName());
        }
        return null;
    }
}
