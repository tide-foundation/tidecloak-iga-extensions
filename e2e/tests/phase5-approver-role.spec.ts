import { test, expect } from '@playwright/test';
import {
  createScratchRealm,
  deleteRealm,
  enableIga,
  createRole,
  createGroup,
  getGroupByName,
  getRole,
  setGroupIgaAttr,
  createAdminWithRoles,
  userTokenFor,
  assignGroupRealmRoleMapping,
  authorizeAs,
  commitAs,
  getChangeRequestStatus,
  findChangeRequest,
  adminToken,
} from '../lib/kc';
import { checkPrecondition, rerunCommand } from '../lib/precondition';

/**
 * Phase 5B — Tideless IGA gate: approver-role enforcement (positive + negative
 * + empty-required baseline).
 *
 * Source-of-truth (line refs verified against the resolver source):
 *
 *   IgaScopeResolver.requireApprover (iga-core/.../attestors/
 *     IgaScopeResolver.java:182-196):
 *       if (scope == null || scope.requiredApproverRoles.isEmpty()) return;
 *       boolean strict = "all".equalsIgnoreCase(realm.getAttribute(ATTR_SCOPE_MODE));
 *       Set<String> adminRoleNames = admin.getRoleMappingsStream()
 *                                         .map(RoleModel::getName)
 *                                         .collect(Collectors.toSet());
 *       boolean ok = strict
 *               ? adminRoleNames.containsAll(scope.requiredApproverRoles)
 *               : scope.requiredApproverRoles.stream().anyMatch(adminRoleNames::contains);
 *       if (!ok) {
 *           throw new ForbiddenException("Approver role required: " + scope.requiredApproverRoles
 *                   + " (mode=" + (strict ? "all" : "any") + ")");
 *       }
 *
 *   So failure shape = jakarta.ws.rs.ForbiddenException, which JAX-RS maps
 *   to HTTP 403. No custom ExceptionMapper for ForbiddenException exists in
 *   this codebase (only IgaPendingApprovalExceptionMapper), so RESTEasy's
 *   default kicks in: 403 with the WWW-Authenticate-style default body.
 *
 *   The empty-requiredApproverRoles early-return (line 183) is the
 *   "bootstrap reality" baseline: no scope-marked entity affected → no
 *   approver gate enforced beyond plain requireManageRealm (the existing
 *   IgaAdminResource.authorize:198 / commit:262 prefix that wraps every call).
 *
 * Triggered via GROUP_GRANT_ROLES so the scope HAS an attribute-bearing
 * scope entity (the group) — see IgaScopeResolver.resolve:76-80 +
 * walkGroupAncestors:333-343. We attach iga.approverRole to the GROUP and
 * grant a (separate, attribute-less) realm role to that group.
 */

const REALM_GATED = 'iga-phase5b-gated';
const REALM_BASELINE = 'iga-phase5b-baseline';
const APPROVER_ROLE = 'p5b-approver-role';
const TARGET_ROLE = 'p5b-target-role';
const TARGET_GROUP = 'p5b-target-group';

const PW = 'p5b-admin-pw';

test.describe('IGA Phase 5B: approver-role enforcement (positive + negative + empty baseline)', () => {
  test.afterAll(async ({ request }) => {
    await deleteRealm(request, REALM_GATED).catch(() => {});
    await deleteRealm(request, REALM_BASELINE).catch(() => {});
  });

  test('B.1+B.2 gated CR: admin-without-role rejected (403), admin-with-role authorizes + commits', async ({
    request,
  }) => {
    const pre = await checkPrecondition(request);
    if (pre.verdict !== 'OK') {
      throw new Error(
        `PRECONDITION: Phase 1 jar not loaded (verdict=${pre.verdict}: ${pre.detail}) — restart then re-run: ${rerunCommand()}`,
      );
    }

    await createScratchRealm(request, REALM_GATED);

    // -- pre-IGA bases: roles, group, attribute on group, two admins. -------
    // The approver role is itself just a realm role; admin-with-role holds it,
    // admin-without-role doesn't. requireApprover walks
    // admin.getRoleMappingsStream() (line 186) — realm roles only — so the
    // role MUST be created as a realm role in this realm.
    const approverRoleRes = await createRole(request, REALM_GATED, {
      name: APPROVER_ROLE,
    });
    expect(approverRoleRes.status(), `create ${APPROVER_ROLE}`).toBe(201);

    const targetRoleRes = await createRole(request, REALM_GATED, {
      name: TARGET_ROLE,
    });
    expect(targetRoleRes.status(), `create ${TARGET_ROLE}`).toBe(201);

    const groupRes = await createGroup(request, REALM_GATED, TARGET_GROUP);
    expect(groupRes.status(), `create ${TARGET_GROUP}`).toBe(201);
    const groupLookup = await getGroupByName(
      request,
      REALM_GATED,
      TARGET_GROUP,
    );
    expect(groupLookup.http).toBe(200);
    const groupId = groupLookup.body.id as string;

    // Mark the GROUP with iga.approverRole = APPROVER_ROLE. The CR for
    // assigning TARGET_ROLE to this group will then carry requiredApproverRoles
    // = {APPROVER_ROLE} (resolved via resolveGroupScopesFromRows for the GROUP
    // key in GROUP_GRANT_ROLES rows + walkGroupAncestors:333-343 reading
    // iga.approverRole off the group). The TARGET_ROLE has no iga.approverRole
    // so collectRoleScope contributes nothing.
    await setGroupIgaAttr(
      request,
      REALM_GATED,
      groupId,
      'iga.approverRole',
      APPROVER_ROLE,
    );

    // Two test admins; both must be created BEFORE enableIga so their
    // CREATE_USER + realm-management:manage-realm + realm-role grants
    // aren't themselves governed CRs.
    await createAdminWithRoles(request, REALM_GATED, 'admin-with-role', PW, [
      APPROVER_ROLE,
    ]);
    await createAdminWithRoles(request, REALM_GATED, 'admin-without-role', PW, []);

    await enableIga(request, REALM_GATED);

    // Trigger GROUP_GRANT_ROLES — assign TARGET_ROLE to TARGET_GROUP.
    const targetRoleLookup = await getRole(request, REALM_GATED, TARGET_ROLE);
    expect(targetRoleLookup.http).toBe(200);
    const mapRes = await assignGroupRealmRoleMapping(
      request,
      REALM_GATED,
      groupId,
      [targetRoleLookup.body],
    );
    expect(
      mapRes.status(),
      `group role-mapping POST expected 204 (grantRole doesn't throw), got ${mapRes.status()}`,
    ).toBe(204);

    const cr = await findChangeRequest(
      request,
      REALM_GATED,
      'GROUP_GRANT_ROLES',
      (c: any) => c.entityType === 'GROUP' && c.entityId === groupId,
    );
    expect(cr, 'GROUP_GRANT_ROLES CR must exist').toBeTruthy();
    const crId = cr!.id;

    // Sanity: the CR rep carries the resolved scope metadata exactly as the
    // resolver computes it (IgaAdminResource.toRepresentation:1444-1460
    // mirrors IgaScopeResolver.resolve / resolveThreshold / scopeMode-derive).
    const st0 = await getChangeRequestStatus(request, REALM_GATED, crId);
    expect(
      st0.requiredApproverRoles ?? [],
      `requiredApproverRoles must be [${APPROVER_ROLE}], got ${JSON.stringify(st0.requiredApproverRoles)}`,
    ).toEqual([APPROVER_ROLE]);
    // Default threshold=1 since no iga.threshold attribute set anywhere.
    expect(st0.threshold).toBe(1);
    expect(st0.scopeMode, 'scopeMode default is "any"').toBe('any');

    // ---- Negative: admin-without-role authorize → 403 ForbiddenException. -
    const withoutTok = await userTokenFor(
      request,
      REALM_GATED,
      'admin-without-role',
      PW,
    );
    const reject = await authorizeAs(request, REALM_GATED, crId, withoutTok);
    expect(
      reject.http,
      `admin-without-role authorize must be rejected (requireApprover throws ForbiddenException → JAX-RS 403); got ${reject.http} ${JSON.stringify(reject.body)}`,
    ).toBe(403);

    // CR must still be unauthorized after the rejection.
    const stAfterReject = await getChangeRequestStatus(
      request,
      REALM_GATED,
      crId,
    );
    expect(
      stAfterReject.authCount,
      `authCount must remain 0 after a rejected authorize (got ${stAfterReject.authCount})`,
    ).toBe(0);

    // Commit by the same admin-without-role must ALSO fail with 403 (commit
    // runs the same requireApprover gate — IgaAdminResource.commit:284-285).
    const commitReject = await commitAs(request, REALM_GATED, crId, withoutTok);
    expect(
      commitReject.http,
      `admin-without-role commit must 403 (commit runs requireApprover); got ${commitReject.http} ${JSON.stringify(commitReject.body)}`,
    ).toBe(403);

    // ---- Positive: admin-with-role authorizes + commits. -----------------
    const withTok = await userTokenFor(
      request,
      REALM_GATED,
      'admin-with-role',
      PW,
    );
    const authOk = await authorizeAs(request, REALM_GATED, crId, withTok);
    expect(
      authOk.http,
      `admin-with-role authorize expected 200, got ${authOk.http} ${JSON.stringify(authOk.body)}`,
    ).toBe(200);

    const commitOk = await commitAs(request, REALM_GATED, crId, withTok);
    expect(
      commitOk.http,
      `admin-with-role commit expected 200, got ${commitOk.http} ${JSON.stringify(commitOk.body)}`,
    ).toBe(200);
  });

  test('B.3 empty-requiredApproverRoles baseline: no iga.approverRole anywhere → any manage-realm admin authorizes+commits', async ({
    request,
  }) => {
    const pre = await checkPrecondition(request);
    if (pre.verdict !== 'OK') {
      throw new Error(
        `PRECONDITION: Phase 1 jar not loaded (verdict=${pre.verdict}: ${pre.detail}) — restart then re-run: ${rerunCommand()}`,
      );
    }

    await createScratchRealm(request, REALM_BASELINE);

    // Two admins pre-IGA; neither holds any "approver" role.
    await createAdminWithRoles(request, REALM_BASELINE, 'admin-a', PW, []);
    await createAdminWithRoles(request, REALM_BASELINE, 'admin-b', PW, []);
    await enableIga(request, REALM_BASELINE);

    // Drive a CREATE_ROLE CR. Empty per-scope, no iga.approverRole anywhere
    // → requireApprover early-returns (line 183). The master admin AND each
    // in-realm admin (with manage-realm) must all be able to authorize+commit
    // independent CRs.
    const masterTok = await adminToken(request);
    const aTok = await userTokenFor(request, REALM_BASELINE, 'admin-a', PW);
    const bTok = await userTokenFor(request, REALM_BASELINE, 'admin-b', PW);

    for (const [label, tok, roleName] of [
      ['master', masterTok, 'b3-role-master'],
      ['admin-a', aTok, 'b3-role-a'],
      ['admin-b', bTok, 'b3-role-b'],
    ] as const) {
      const cr = await createRole(request, REALM_BASELINE, { name: roleName });
      expect(cr.status(), `${label} CREATE_ROLE expected 202`).toBe(202);
      const body = await cr.json();
      const crId = body.changeRequestId as string;
      expect(crId, `${label} CR id`).toBeTruthy();

      const st = await getChangeRequestStatus(request, REALM_BASELINE, crId);
      expect(
        st.requiredApproverRoles ?? [],
        `${label}: empty requiredApproverRoles baseline`,
      ).toEqual([]);
      expect(st.threshold, `${label}: default threshold 1`).toBe(1);

      const a = await authorizeAs(request, REALM_BASELINE, crId, tok);
      expect(
        a.http,
        `${label} authorize expected 200, got ${a.http} ${JSON.stringify(a.body)}`,
      ).toBe(200);
      const c = await commitAs(request, REALM_BASELINE, crId, tok);
      expect(
        c.http,
        `${label} commit expected 200, got ${c.http} ${JSON.stringify(c.body)}`,
      ).toBe(200);

      const got = await getRole(request, REALM_BASELINE, roleName);
      expect(got.http, `${label}: role ${roleName} must exist after commit`).toBe(200);
    }
  });
});
