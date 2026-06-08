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
            if (tideIdp != null && tideVendorKey != null) {
                // (a) iga.attestor=tide — must be set before the ADOPT scan so
                // the firstAdmin authorizer can seed. Write via the suppressed
                // helper for consistency (IGA is still OFF here, so it is a
                // plain realm.setAttribute under the IGA_REPLAY_ACTIVE guard).
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
                }
            }
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
        writeIgaAttributeDirect(IGA_ATTRIBUTE, Boolean.toString(next));
        logger.infof("IGA has been toggled to : %s for realm %s", next, realm.getName());

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
                // Scan failed entirely — toggle ALREADY committed in the
                // outer transaction. Surface the error in the response but
                // do NOT roll back the toggle (per locked design: scan
                // failure must not block the toggle).
                errHolder[0] = ex;
                logger.errorf(ex, "IGA toggle-on scan FAILED for realm %s — toggle " +
                        "remains enabled, no ADOPT CRs were emitted.", realm.getName());
            }

            if (capHolder[0] != null) {
                // Roll back the realm-attribute write — same outer
                // transaction, so this resets isIGAEnabled to its pre-toggle
                // value (false) before the response is sent. Bypass the
                // IGA capture (the just-written "true" would otherwise make
                // isIgaActive() route this revert through SET_REALM_ATTRIBUTE
                // CR creation instead of an actual rollback).
                writeIgaAttributeDirect(IGA_ATTRIBUTE, Boolean.toString(current));
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
                                    trackProgress ? jobId : null);
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
                    Map<String, Object> sweepErr = new LinkedHashMap<>();
                    sweepErr.put("error", sweepEx.getClass().getSimpleName());
                    sweepErr.put("message", String.valueOf(sweepEx.getMessage()));
                    body.put("autoCommit", sweepErr);
                    // The sweep failing does NOT roll back the toggle (the
                    // attribute is committed); reflect that truthfully — the
                    // sign-defaults stage failed, the job failed, but the toggle
                    // response is still a normal 200.
                    if (trackProgress) {
                        jobService.fail(jobId, "sign-defaults",
                                sweepEx.getClass().getSimpleName() + ": " + sweepEx.getMessage());
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
                    jobService.complete(jobId);
                }
            } else if (errHolder[0] != null) {
                // Scan failed entirely (not a cap rejection). The toggle stays
                // enabled but no ADOPT CRs were emitted — reflect the adopt-scan
                // stage failure truthfully.
                if (trackProgress) {
                    jobService.fail(jobId, "adopt-scan",
                            errHolder[0].getClass().getSimpleName() + ": " + errHolder[0].getMessage());
                }
                Map<String, Object> scanErr = new LinkedHashMap<>();
                scanErr.put("error", errHolder[0].getClass().getSimpleName());
                scanErr.put("message", String.valueOf(errHolder[0].getMessage()));
                body.put("scan", scanErr);
            }
        }

        // ON→OFF: cancel PENDING ADOPT CRs + clear sidecar inside
        // its own transaction (mirror of the OFF→ON pattern above). Master
        // is excluded by symmetry: IGA is never enabled on master, so an
        // ON→OFF for master is impossible in practice; the guard is
        // defensive.
        if (current && !next && !"master".equals(realm.getName())) {
            String realmId = realm.getId();
            IgaAdoptCancel.CancelResult[] offHolder = new IgaAdoptCancel.CancelResult[1];
            Throwable[] offErrHolder = new Throwable[1];
            try {
                KeycloakModelUtils.runJobInTransaction(
                        session.getKeycloakSessionFactory(),
                        cancelSession -> {
                            RealmModel cancelRealm = cancelSession.realms().getRealm(realmId);
                            if (cancelRealm == null) {
                                throw new IllegalStateException(
                                        "IGA toggle-off cancel: realm " + realmId + " not loadable in cancel session");
                            }
                            offHolder[0] = IgaAdoptCancel.cancel(cancelSession, cancelRealm);
                        });
            } catch (RuntimeException ex) {
                // Same policy as the scan: toggle attribute ALREADY committed
                // in the outer transaction. Surface the error in the
                // response but do NOT roll back — a half-cleared realm is
                // recoverable; a stuck toggle is not.
                offErrHolder[0] = ex;
                logger.errorf(ex, "IGA toggle-off cancel FAILED for realm %s — toggle remains " +
                        "disabled, sidecar/ADOPT-CR state may be partial.", realm.getName());
            }

            if (offHolder[0] != null) {
                body.put("scanOff", offHolder[0].toMap());
            } else if (offErrHolder[0] != null) {
                Map<String, Object> err = new LinkedHashMap<>();
                err.put("error", offErrHolder[0].getClass().getSimpleName());
                err.put("message", String.valueOf(offErrHolder[0].getMessage()));
                body.put("scanOff", err);
            }
            // Symmetric to the OFF→ON eviction: evict the user-cache on
            // ON→OFF too. While IGA was ON, a quarantined user's cached
            // UserAdapter held enabled=false (snapshot of IgaUserAdapter
            // returning false). After ON→OFF the IGA quarantine no longer
            // applies (IgaQuarantineCache.isUserUnsignedWithRoles short-circuits
            // when !isIgaActive), but the stale cache snapshot would still
            // report enabled=false until the entry happened to expire. Evict
            // so the next session.users() lookup re-loads through
            // IgaUserProvider → IgaUserAdapter and reflects the IGA-off state.
            evictRealmUserCache(session, realm);
            // Symmetric eviction for the client/role/group/scope realm-cache.
            // While IGA was ON, the cached ClientAdapter for a
            // client that toggled-on hit the quarantine path may hold
            // enabled=false from the IgaClientAdapter snapshot. After ON→OFF
            // the quarantine no longer applies, but the realm-cache snapshot
            // would still report enabled=false until the entry expires. Evict
            // so the next session.clients()/realm.getRole/group/scope read
            // re-loads through the IGA providers and reflects the IGA-off
            // state. Symmetric to the OFF→ON call above and the user-cache
            // eviction on this same branch.
            evictRealmCache(session, realm);

            // Restore old IGA behavior (dropped during decoupling): when IGA is disabled on a Tide realm,
            // default signature algorithm cannot remain EdDSA (no Tide signing path) -> revert to RS256.
            IdentityProviderModel tideIdp = session.identityProviders().getByAlias("tide");
            ComponentModel tideVendorKey = realm.getComponentsStream()
                    .filter(x -> "tide-vendor-key".equals(x.getProviderId()))
                    .findFirst()
                    .orElse(null);
            if (tideIdp != null && tideVendorKey != null) {
                String currentAlgorithm = realm.getDefaultSignatureAlgorithm();
                if ("EdDSA".equalsIgnoreCase(currentAlgorithm)) {
                    writeDefaultSignatureAlgorithmDirect("RS256");
                    logger.info("IGA disabled, default signature algorithm reverted to RS256");
                }
            }
        }

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
        try {
            UserCache cache = UserStorageUtil.userCache(session);
            if (cache == null) {
                logger.debugf("IGA toggle user-cache eviction: realm=%s — UserCache provider not installed (skipped)",
                        realm.getName());
                return;
            }
            cache.evict(realm);
            logger.infof("IGA toggle user-cache eviction: realm=%s — evicted (next user lookup will re-load through IgaUserProvider so the quarantine override fires)",
                    realm.getName());
        } catch (RuntimeException ex) {
            // Never let a cache-eviction failure abort the toggle — the
            // realm attribute is already committed and the response is
            // about to be sent. Subsequent reads may show stale isEnabled
            // until the entry expires, but the toggle stays consistent.
            logger.errorf(ex,
                    "IGA toggle user-cache eviction FAILED for realm %s — quarantine reads may be stale until cache entries expire.",
                    realm.getName());
        }
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
        // NOTE: the IgaOrganizationProvider extends-Infinispan refactor
        // makes FUTURE reads traverse the cache → IGA chain naturally, but it does NOT
        // invalidate entries that were ALREADY cached before this toggle flipped. A
        // CachedClient / CachedRole / CachedOrganization loaded pre-toggle still holds
        // its snapshot until natural expiry, so its IGA-wrapped accessor is never
        // re-consulted — the per-entity invalidations below remain load-bearing for
        // the toggle's "flip applies to already-loaded entities" guarantee. Do not
        // delete on the assumption that the architectural fix subsumed them.
        CacheRealmProvider cache;
        try {
            cache = session.getProvider(CacheRealmProvider.class);
        } catch (RuntimeException lookupEx) {
            logger.warnf(lookupEx,
                    "IGA toggle realm-cache eviction: realm=%s — CacheRealmProvider lookup failed (skipped); quarantine reads on cached clients/roles/groups/scopes may be stale until entries expire.",
                    realm.getName());
            return;
        }
        if (cache == null) {
            logger.debugf("IGA toggle realm-cache eviction: realm=%s — CacheRealmProvider not installed (skipped)",
                    realm.getName());
            return;
        }

        String realmId = realm.getId();
        int clients = 0, roles = 0, groups = 0, scopes = 0, orgs = 0, idps = 0;

        // Clients — the immediate client-quarantine fix surface.
        try {
            for (ClientModel client : realm.getClientsStream().toList()) {
                try {
                    cache.registerClientInvalidation(client.getId(), client.getClientId(), realmId);
                    clients++;
                } catch (RuntimeException ex) {
                    logger.debugf(ex,
                            "IGA toggle realm-cache eviction: client=%s (uuid=%s) realm=%s — registerClientInvalidation failed (continuing).",
                            client.getClientId(), client.getId(), realm.getName());
                }
            }
        } catch (RuntimeException ex) {
            logger.warnf(ex,
                    "IGA toggle realm-cache eviction: realm=%s — client iteration failed after evicting %d (continuing with roles/groups/scopes).",
                    realm.getName(), clients);
        }

        // Realm-level roles + per-client roles. IgaRoleAdapter holds the
        // role-side IGA hooks; a cached RoleAdapter snapshot would bypass them.
        try {
            for (RoleModel role : session.roles().getRealmRolesStream(realm).toList()) {
                try {
                    cache.registerRoleInvalidation(role.getId(), role.getName(), realmId);
                    roles++;
                } catch (RuntimeException ex) {
                    logger.debugf(ex,
                            "IGA toggle realm-cache eviction: realm-role=%s (id=%s) realm=%s — registerRoleInvalidation failed (continuing).",
                            role.getName(), role.getId(), realm.getName());
                }
            }
            for (ClientModel client : realm.getClientsStream().toList()) {
                try {
                    for (RoleModel role : session.roles().getClientRolesStream(client).toList()) {
                        try {
                            cache.registerRoleInvalidation(role.getId(), role.getName(), client.getId());
                            roles++;
                        } catch (RuntimeException ex) {
                            logger.debugf(ex,
                                    "IGA toggle realm-cache eviction: client-role=%s (id=%s) container=%s realm=%s — registerRoleInvalidation failed (continuing).",
                                    role.getName(), role.getId(), client.getId(), realm.getName());
                        }
                    }
                } catch (RuntimeException ex) {
                    logger.debugf(ex,
                            "IGA toggle realm-cache eviction: realm=%s client=%s — client-roles iteration failed (continuing).",
                            realm.getName(), client.getClientId());
                }
            }
        } catch (RuntimeException ex) {
            logger.warnf(ex,
                    "IGA toggle realm-cache eviction: realm=%s — role iteration failed after evicting %d (continuing with groups/scopes).",
                    realm.getName(), roles);
        }

        // Groups.
        try {
            for (GroupModel group : realm.getGroupsStream().toList()) {
                try {
                    cache.registerGroupInvalidation(group.getId());
                    groups++;
                } catch (RuntimeException ex) {
                    logger.debugf(ex,
                            "IGA toggle realm-cache eviction: group=%s (id=%s) realm=%s — registerGroupInvalidation failed (continuing).",
                            group.getName(), group.getId(), realm.getName());
                }
            }
        } catch (RuntimeException ex) {
            logger.warnf(ex,
                    "IGA toggle realm-cache eviction: realm=%s — group iteration failed after evicting %d (continuing with scopes).",
                    realm.getName(), groups);
        }

        // Client scopes.
        try {
            for (ClientScopeModel scope : realm.getClientScopesStream().toList()) {
                try {
                    cache.registerClientScopeInvalidation(scope.getId(), realmId);
                    scopes++;
                } catch (RuntimeException ex) {
                    logger.debugf(ex,
                            "IGA toggle realm-cache eviction: scope=%s (id=%s) realm=%s — registerClientScopeInvalidation failed (continuing).",
                            scope.getName(), scope.getId(), realm.getName());
                }
            }
        } catch (RuntimeException ex) {
            logger.warnf(ex,
                    "IGA toggle realm-cache eviction: realm=%s — client-scope iteration failed after evicting %d.",
                    realm.getName(), scopes);
        }

        // Organizations. KC's CacheRealmProvider has no public
        // registerOrgInvalidation primitive (the InfinispanOrganizationProvider's
        // registerOrganizationInvalidation is package-private), but the cached
        // CachedOrganization is keyed on the org id alone
        // and that key
        // is invalidated via the public CacheRealmProvider.registerInvalidation(id)
        // call — see the same primitive used in
        // IgaReplayExtension.evictCacheForAdopt's ADOPT_ORGANIZATION branch.
        //
        // Iterate via OrganizationProvider (the SPI surface KC uses everywhere
        // else); skip silently if the realm doesn't have orgs feature on
        // (provider returns empty stream) or the provider isn't installed at
        // all. Best-effort wrapping mirrors the clients/roles/groups/scopes
        // branches above.
        try {
            OrganizationProvider orgProvider = session.getProvider(OrganizationProvider.class);
            if (orgProvider != null) {
                for (OrganizationModel org : orgProvider.getAllStream().toList()) {
                    try {
                        cache.registerInvalidation(org.getId());
                        orgs++;
                    } catch (RuntimeException ex) {
                        logger.debugf(ex,
                                "IGA toggle realm-cache eviction: org=%s (id=%s) realm=%s — registerInvalidation failed (continuing).",
                                org.getName(), org.getId(), realm.getName());
                    }
                }
            }
        } catch (RuntimeException ex) {
            logger.warnf(ex,
                    "IGA toggle realm-cache eviction: realm=%s — organization iteration failed after evicting %d.",
                    realm.getName(), orgs);
        }

        // Identity providers. IdPs aren't quarantineable entities
        // (toggle-on doesn't scan IdPs, no IGA_UNSIGNED_ENTITY rows) but the
        // IdP-aware scope resolver reads iga.approverRole /
        // iga.threshold off IdentityProviderModel.getConfig() via
        // session.identityProviders().getByAlias(...). That path goes through
        // InfinispanIdentityProviderStorageProvider which caches the
        // CachedIdentityProvider snapshot under two keys: the internalId and
        // realmId + "." + alias + ".idp.alias" (both suffix constants are
        // private in KC). Without invalidating
        // those entries, an iga.approverRole / iga.threshold edit on an IdP
        // made BEFORE toggle-on could remain stale post-toggle, letting an
        // ORG_ADD_IDP / ORG_REMOVE_IDP CR resolve against pre-edit config and
        // produce the wrong gate verdict. We reconstruct the alias key here
        // (KC's suffix string is identical and the realmId-prefixed shape is
        // stable across the cache lifecycle).
        //
        // Iterate via realm.getIdentityProvidersStream() — the deprecated
        // accessor is still the simplest surface; the canonical
        // IdentityProviderStorageProvider.getAllStream() requires constructing
        // an IdentityProviderQuery which adds noise for no functional gain
        // here.
        try {
            for (IdentityProviderModel idp : realm.getIdentityProvidersStream().toList()) {
                try {
                    if (idp.getInternalId() != null) {
                        cache.registerInvalidation(idp.getInternalId());
                    }
                    if (idp.getAlias() != null) {
                        cache.registerInvalidation(realmId + "." + idp.getAlias() + ".idp.alias");
                    }
                    idps++;
                } catch (RuntimeException ex) {
                    logger.debugf(ex,
                            "IGA toggle realm-cache eviction: idp=%s (id=%s) realm=%s — registerInvalidation failed (continuing).",
                            idp.getAlias(), idp.getInternalId(), realm.getName());
                }
            }
        } catch (RuntimeException ex) {
            logger.warnf(ex,
                    "IGA toggle realm-cache eviction: realm=%s — idp iteration failed after evicting %d.",
                    realm.getName(), idps);
        }

        logger.infof("IGA toggle realm-cache eviction: realm=%s — evicted clients=%d roles=%d groups=%d scopes=%d orgs=%d idps=%d (next client/role/group/scope/org/idp read will re-load through IGA providers so the quarantine override fires)",
                realm.getName(), clients, roles, groups, scopes, orgs, idps);
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
            IgaToggleJobService jobService, String jobId) {
        IgaChangeRequestService service = new IgaChangeRequestService(
                session.getProvider(JpaConnectionProvider.class).getEntityManager(), session);
        // Pull only the baseline-config allow-list action types as candidates (governed
        // CRs are never loaded). High limit — a fresh-realm provisioning closure is well
        // under this; the per-CR MF2/default-role filter happens in isAutoCommittable.
        List<String> allowList = new ArrayList<>(IgaFirstAdminAutoCommit.BASELINE_CONFIG_ACTION_TYPES);
        List<IgaChangeRequestEntity> candidates =
                service.listPendingByActionTypeIn(realm.getId(), allowList, null, 100_000);

        UserModel admin = currentUserModel();

        IgaFirstAdminAutoCommit.BulkEngine engine = crIdIn -> {
            // Drive the bulk engine by the EXACT per-CR-eligible ids (not action
            // type): the narrowed scope means a single action type can hold both
            // eligible and ineligible CRs (system vs admin-authored ADOPT, benign
            // vs non-default composite), so an action-type drain would over-commit.
            //
            // PROGRESS: this is the slow ORK-signing stage. To surface live
            // counts we process the eligible ids in small CHUNKS and emit a
            // stageProgress(committed/total) after each chunk, so a poller sees
            // the count climb as the sweep iterates. The bulk endpoint hard cap
            // is 1000; the chunk size stays well under it. Functionally the
            // chunking is transparent — each chunk re-enters the same hardened,
            // mutex-guarded bulkAuthorize engine.
            final int total = crIdIn.size();
            final int chunkSize = 25;
            List<Map<String, Object>> out = new ArrayList<>();
            int committedSoFar = 0;
            if (jobId != null) {
                jobService.stageProgress(jobId, "sign-defaults", 0L, (long) total);
            }
            for (int from = 0; from < total; from += chunkSize) {
                int to = Math.min(from + chunkSize, total);
                List<String> chunk = crIdIn.subList(from, to);
                Map<String, Object> bulkBody = new LinkedHashMap<>();
                bulkBody.put("crIdIn", new ArrayList<>(chunk));
                bulkBody.put("limit", 1000); // bulk endpoint hard cap
                Response resp = new IgaAdminResource(session, realm, auth).bulkAuthorize(bulkBody);
                Object entity = resp.getEntity();
                if (entity instanceof Map<?, ?> respMap) {
                    Object results = respMap.get("results");
                    if (results instanceof List<?> list) {
                        for (Object o : list) {
                            if (o instanceof Map<?, ?> m) {
                                @SuppressWarnings("unchecked")
                                Map<String, Object> cast = (Map<String, Object>) m;
                                out.add(cast);
                                if ("COMMITTED".equals(String.valueOf(cast.get("status")))) {
                                    committedSoFar++;
                                }
                            }
                        }
                    }
                }
                if (jobId != null) {
                    jobService.stageProgress(jobId, "sign-defaults", (long) committedSoFar, (long) total);
                }
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
