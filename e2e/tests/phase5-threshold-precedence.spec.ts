import { test, expect } from '@playwright/test';
import {
  createScratchRealm,
  deleteRealm,
  enableIga,
  igaStatus,
  createRole,
  createGroup,
  getGroupByName,
  getRole,
  setRealmIgaAttr,
  setGroupIgaAttr,
  setRoleIgaAttr,
  createAdminWithRoles,
  userTokenFor,
  assignGroupRealmRoleMapping,
  authorizeAndCommit,
  authorizeAs,
  commitAs,
  getChangeRequestStatus,
  findChangeRequest,
  locationHeader,
  safeJson,
  adminToken,
} from '../lib/kc';
import { checkPrecondition, rerunCommand } from '../lib/precondition';

/**
 * Phase 5A — Tideless IGA gate: threshold precedence.
 *
 * Source-of-truth (line refs verified against the resolver source,
 * do NOT change without re-reading):
 *
 *   IgaScopeResolver.resolveThreshold (iga-core/src/main/java/org/tidecloak/
 *     iga/attestors/IgaScopeResolver.java:211-230):
 *       int resolved = 1;
 *       if (scope != null && !scope.thresholds.isEmpty()) {
 *           resolved = scope.thresholds.stream()
 *                           .mapToInt(Integer::intValue).max().orElse(1);
 *       } else {
 *           String t = realm.getAttribute(ATTR_THRESHOLD);
 *           if (t != null) {
 *               try {
 *                   int parsed = Integer.parseInt(t.trim());
 *                   if (parsed >= 1) resolved = parsed;
 *               } catch (NumberFormatException ignored) { }
 *           }
 *       }
 *       return Math.max(1, resolved);
 *
 *   SimpleNameAttestor.getThreshold (iga-core/.../attestors/
 *     SimpleNameAttestor.java:87-91) delegates to resolveThreshold via
 *     IgaScopeResolver.resolve(session, realm, cr).
 *
 *   IgaAdminResource.commit (iga-core/.../rest/IgaAdminResource.java:288-301)
 *     enforces authCount >= threshold and returns 412 PRECONDITION_FAILED
 *     with body {error, threshold, authCount} when not met.
 *
 * Precedence ground-truthed by the source:
 *   1. If ANY affected-scope entity carries iga.threshold → MAX of those
 *      per-scope thresholds wins (realm attribute is IGNORED entirely:
 *      lines 213-214 take the per-scope branch and never read realm).
 *   2. Else if realm carries iga.threshold (a parseable int ≥1) → that value.
 *   3. Else → default 1 (the initial `int resolved = 1` survives).
 *
 * Three sub-cases on separate scratch realms so attribute state and admin
 * signatures don't bleed across.
 *
 * Realm/group/role iga.threshold attributes are set BEFORE enableIga()
 * because their writes are themselves governed once IGA is on
 * (IgaRealmAdapter.setAttribute:73-88 → SET_REALM_ATTRIBUTE, group/role
 * analogous). Test admins are also created pre-IGA so their CREATE_USER
 * and realm-management role grants stay vanilla KC.
 */

const REALM_DEFAULT = 'iga-phase5a-default';
const REALM_REALM_FB = 'iga-phase5a-realm-fb';
const REALM_PER_SCOPE = 'iga-phase5a-per-scope';

test.describe('IGA Phase 5A: threshold precedence (per-scope MAX > realm > default 1)', () => {
  test.afterAll(async ({ request }) => {
    await deleteRealm(request, REALM_DEFAULT).catch(() => {});
    await deleteRealm(request, REALM_REALM_FB).catch(() => {});
    await deleteRealm(request, REALM_PER_SCOPE).catch(() => {});
  });

  test('A.1 default 1: no iga.threshold anywhere → 1 authorize+commit succeeds', async ({
    request,
  }) => {
    const pre = await checkPrecondition(request);
    if (pre.verdict !== 'OK') {
      throw new Error(
        `PRECONDITION: Phase 1 jar not loaded (verdict=${pre.verdict}: ${pre.detail}) — restart then re-run: ${rerunCommand()}`,
      );
    }

    await createScratchRealm(request, REALM_DEFAULT);
    await enableIga(request, REALM_DEFAULT);
    expect((await igaStatus(request, REALM_DEFAULT)).enabled).toBe(true);

    // CREATE_ROLE is NOT in IgaScopeResolver.resolve()'s switch (line 65-170),
    // so it falls through to `default`, leaving scope.thresholds empty. With
    // no realm iga.threshold either, resolveThreshold() must return 1.
    const createRes = await createRole(request, REALM_DEFAULT, {
      name: 'a1-role',
    });
    expect(createRes.status(), 'governed CREATE_ROLE expected 202').toBe(202);
    const loc = locationHeader(createRes);
    const body = await safeJson(createRes);
    const crId =
      (body && body.changeRequestId) || (loc ? loc.split('/').pop() : '');
    expect(crId, 'CR id resolvable').toBeTruthy();

    const st0 = await getChangeRequestStatus(request, REALM_DEFAULT, crId);
    expect(st0.threshold, 'default threshold must be 1').toBe(1);
    expect(st0.requiredApproverRoles ?? [], 'no required roles').toEqual([]);
    expect(st0.scopeMode, 'default scopeMode is "any"').toBe('any');

    const ac = await authorizeAndCommit(request, REALM_DEFAULT, crId);
    expect(
      ac.authorize.http,
      `A.1 authorize expected 200, got ${ac.authorize.http} ${JSON.stringify(ac.authorize.body)}`,
    ).toBe(200);
    expect(
      ac.commit.http,
      `A.1 commit expected 200 (threshold=1, authCount=1), got ${ac.commit.http} ${JSON.stringify(ac.commit.body)}`,
    ).toBe(200);

    const roleAfter = await getRole(request, REALM_DEFAULT, 'a1-role');
    expect(roleAfter.http, 'a1-role must exist after commit').toBe(200);
  });

  test('A.2 realm fallback: iga.threshold=2 on realm → 1 authorize fails commit (412), 2 distinct admins succeed', async ({
    request,
  }) => {
    const pre = await checkPrecondition(request);
    if (pre.verdict !== 'OK') {
      throw new Error(
        `PRECONDITION: Phase 1 jar not loaded (verdict=${pre.verdict}: ${pre.detail}) — restart then re-run: ${rerunCommand()}`,
      );
    }

    await createScratchRealm(request, REALM_REALM_FB);
    // Pre-create a SECOND distinct admin so we can hit authCount=2 (the
    // authorize endpoint rejects duplicate sigs from the same admin with 409
    // — IgaAdminResource.authorize:222-239). Set the realm attribute and
    // create the admin BEFORE enableIga so neither write is itself governed.
    await setRealmIgaAttr(request, REALM_REALM_FB, 'iga.threshold', '2');
    const SECOND_PW = 'p5-admin-2-pw';
    await createAdminWithRoles(
      request,
      REALM_REALM_FB,
      'admin2',
      SECOND_PW,
      [],
    );
    await enableIga(request, REALM_REALM_FB);

    const createRes = await createRole(request, REALM_REALM_FB, {
      name: 'a2-role',
    });
    expect(createRes.status(), 'governed CREATE_ROLE expected 202').toBe(202);
    const body = await safeJson(createRes);
    const loc = locationHeader(createRes);
    const crId =
      (body && body.changeRequestId) || (loc ? loc.split('/').pop() : '');
    expect(crId, 'CR id resolvable').toBeTruthy();

    // Empty per-scope (CREATE_ROLE falls to `default` branch in resolve()) so
    // resolveThreshold reads the realm attribute, parses "2", returns 2.
    const st0 = await getChangeRequestStatus(request, REALM_REALM_FB, crId);
    expect(
      st0.threshold,
      `realm-fallback threshold expected 2, got ${st0.threshold}`,
    ).toBe(2);
    expect(st0.requiredApproverRoles ?? []).toEqual([]);

    const masterTok = await adminToken(request);
    const adminTok = await userTokenFor(
      request,
      REALM_REALM_FB,
      'admin2',
      SECOND_PW,
    );

    // 1st sig: master admin.
    const auth1 = await authorizeAs(request, REALM_REALM_FB, crId, masterTok);
    expect(
      auth1.http,
      `auth1 expected 200, got ${auth1.http} ${JSON.stringify(auth1.body)}`,
    ).toBe(200);

    // Commit with authCount(1) < threshold(2) MUST 412 with the exact body
    // shape IgaAdminResource.commit:294-300 returns: {error, threshold, authCount}.
    const commitEarly = await commitAs(
      request,
      REALM_REALM_FB,
      crId,
      masterTok,
    );
    expect(
      commitEarly.http,
      `commit with authCount=1<threshold=2 must be 412, got ${commitEarly.http} ${JSON.stringify(commitEarly.body)}`,
    ).toBe(412);
    expect(commitEarly.body?.threshold, 'commit-412 reports threshold').toBe(2);
    expect(commitEarly.body?.authCount, 'commit-412 reports authCount').toBe(1);

    // Role must NOT exist (replay didn't run).
    const stillMissing = await getRole(request, REALM_REALM_FB, 'a2-role');
    expect(
      stillMissing.http,
      `a2-role must NOT exist after sub-threshold commit attempt (got ${stillMissing.http})`,
    ).toBe(404);

    // 2nd sig: distinct admin.
    const auth2 = await authorizeAs(request, REALM_REALM_FB, crId, adminTok);
    expect(
      auth2.http,
      `auth2 expected 200, got ${auth2.http} ${JSON.stringify(auth2.body)}`,
    ).toBe(200);

    const stReady = await getChangeRequestStatus(request, REALM_REALM_FB, crId);
    expect(
      stReady.authCount,
      `authCount must be 2 after two distinct admins, got ${stReady.authCount}`,
    ).toBe(2);
    expect(stReady.readyToCommit, 'readyToCommit at threshold').toBe(true);

    const commitOk = await commitAs(request, REALM_REALM_FB, crId, masterTok);
    expect(
      commitOk.http,
      `commit at authCount(2)>=threshold(2) expected 200, got ${commitOk.http} ${JSON.stringify(commitOk.body)}`,
    ).toBe(200);
    const roleAfter = await getRole(request, REALM_REALM_FB, 'a2-role');
    expect(roleAfter.http, 'a2-role must exist after commit').toBe(200);
  });

  test('A.3 per-scope MAX wins: realm=3, group=2, role=4 → effective threshold = 4 (per-scope ignores realm entirely)', async ({
    request,
  }) => {
    const pre = await checkPrecondition(request);
    if (pre.verdict !== 'OK') {
      throw new Error(
        `PRECONDITION: Phase 1 jar not loaded (verdict=${pre.verdict}: ${pre.detail}) — restart then re-run: ${rerunCommand()}`,
      );
    }

    await createScratchRealm(request, REALM_PER_SCOPE);

    // SUBTLE: per-scope iga.threshold is ONLY harvested when the same entity
    // ALSO carries iga.approverRole — collectRoleScope (line 345-351) and
    // walkGroupAncestors (line 333-343) gate addThreshold() behind a non-blank
    // iga.approverRole. So Spec A.3 MUST also set iga.approverRole on the
    // group and the role; we use a single approver-role name that ALL four
    // signers hold, so requireApprover (line 182-196) passes for every signer
    // and is not what's being tested here (Spec B tests requireApprover).
    const APPROVER_ROLE = 'a3-approver';
    const apRes = await createRole(request, REALM_PER_SCOPE, {
      name: APPROVER_ROLE,
    });
    expect(apRes.status(), `create ${APPROVER_ROLE} expected 201`).toBe(201);

    // Pre-create FOUR in-realm admins, each holding APPROVER_ROLE so the
    // requireApprover gate passes. With 4 distinct signers we can hit
    // authCount=4 (same-admin duplicate sigs are rejected with 409 —
    // IgaAdminResource.authorize:222-239). Master admin would FAIL the
    // approver gate (its role mappings live in master realm, not here), so
    // it can't be one of the four.
    const PW = 'p5-admin-pw';
    await createAdminWithRoles(request, REALM_PER_SCOPE, 'a3-admin1', PW, [
      APPROVER_ROLE,
    ]);
    await createAdminWithRoles(request, REALM_PER_SCOPE, 'a3-admin2', PW, [
      APPROVER_ROLE,
    ]);
    await createAdminWithRoles(request, REALM_PER_SCOPE, 'a3-admin3', PW, [
      APPROVER_ROLE,
    ]);
    await createAdminWithRoles(request, REALM_PER_SCOPE, 'a3-admin4', PW, [
      APPROVER_ROLE,
    ]);

    // Create the realm role (the "ROLE" the GROUP_GRANT_ROLES grants) and
    // the GROUP that will receive it. Both pre-IGA.
    const roleRes = await createRole(request, REALM_PER_SCOPE, {
      name: 'a3-target-role',
    });
    expect(roleRes.status(), 'create a3-target-role expected 201').toBe(201);
    const groupRes = await createGroup(request, REALM_PER_SCOPE, 'a3-group');
    expect(groupRes.status(), 'create a3-group expected 201').toBe(201);

    const groupLookup = await getGroupByName(
      request,
      REALM_PER_SCOPE,
      'a3-group',
    );
    expect(groupLookup.http).toBe(200);
    const groupId = groupLookup.body.id as string;
    expect(groupId, 'groupId resolvable').toBeTruthy();

    // realm iga.threshold=3 is set ONLY to prove per-scope MAX overrides it.
    // resolveThreshold (lines 211-230) ignores the realm value entirely when
    // scope.thresholds is non-empty (line 213-214 takes the per-scope branch
    // and never reaches the realm-read at line 216).
    //
    // Per-scope iga.approverRole + iga.threshold pairs:
    //   group: iga.approverRole=APPROVER_ROLE + iga.threshold=2
    //   role : iga.approverRole=APPROVER_ROLE + iga.threshold=4
    // resolver collectRoleScope/walkGroupAncestors only call addThreshold
    // when the approverRole side is non-blank, so both pairs MUST be set.
    await setRealmIgaAttr(request, REALM_PER_SCOPE, 'iga.threshold', '3');
    await setGroupIgaAttr(
      request,
      REALM_PER_SCOPE,
      groupId,
      'iga.approverRole',
      APPROVER_ROLE,
    );
    await setGroupIgaAttr(
      request,
      REALM_PER_SCOPE,
      groupId,
      'iga.threshold',
      '2',
    );
    await setRoleIgaAttr(
      request,
      REALM_PER_SCOPE,
      'a3-target-role',
      'iga.approverRole',
      APPROVER_ROLE,
    );
    await setRoleIgaAttr(
      request,
      REALM_PER_SCOPE,
      'a3-target-role',
      'iga.threshold',
      '4',
    );

    await enableIga(request, REALM_PER_SCOPE);

    // Trigger GROUP_GRANT_ROLES: assign realm role a3-target-role to a3-group.
    // IgaGroupAdapter.grantRole (line 295-305) records the CR with rows
    // [{GROUP: <groupId>, ROLE: <roleId>}] — exactly the keys
    // IgaScopeResolver.resolve consumes for GROUP_GRANT_ROLES (line 76-80:
    // resolveGroupScopesFromRows(..., "GROUP") then
    // resolveRoleScopesFromRows(..., "ROLE")). Both row entities have
    // iga.approverRole set, so addThreshold runs for each — scope.thresholds
    // = {2, 4} and requiredApproverRoles = {APPROVER_ROLE} (set semantics
    // dedupes the same name).
    const roleLookup = await getRole(
      request,
      REALM_PER_SCOPE,
      'a3-target-role',
    );
    expect(roleLookup.http).toBe(200);
    const targetRoleRep = roleLookup.body;
    const mapRes = await assignGroupRealmRoleMapping(
      request,
      REALM_PER_SCOPE,
      groupId,
      [targetRoleRep],
    );
    // grantRole on IgaGroupAdapter does NOT throw IgaPendingApprovalException
    // (only the create-* paths do), so the HTTP response is KC's normal 204.
    // The CR must be discovered via findChangeRequest.
    expect(
      mapRes.status(),
      `group role-mapping POST expected 204 (no IgaPendingApprovalException for grantRole), got ${mapRes.status()}: ${await mapRes.text()}`,
    ).toBe(204);

    const cr = await findChangeRequest(
      request,
      REALM_PER_SCOPE,
      'GROUP_GRANT_ROLES',
      (c: any) => c.entityType === 'GROUP' && c.entityId === groupId,
    );
    expect(cr, 'GROUP_GRANT_ROLES CR must exist').toBeTruthy();
    const crId = cr!.id;

    const st0 = await getChangeRequestStatus(request, REALM_PER_SCOPE, crId);
    // The decisive precedence assertion: per-scope MAX (2,4)=4 wins;
    // realm=3 is ignored entirely (per-scope branch in resolveThreshold).
    expect(
      st0.threshold,
      `per-scope MAX threshold expected 4 (max of group=2 and role=4), realm=3 must be ignored — got ${st0.threshold}`,
    ).toBe(4);
    expect(
      st0.requiredApproverRoles ?? [],
      `requiredApproverRoles must be [${APPROVER_ROLE}] (deduped across group+role), got ${JSON.stringify(st0.requiredApproverRoles)}`,
    ).toEqual([APPROVER_ROLE]);

    const a1Tok = await userTokenFor(request, REALM_PER_SCOPE, 'a3-admin1', PW);
    const a2Tok = await userTokenFor(request, REALM_PER_SCOPE, 'a3-admin2', PW);
    const a3Tok = await userTokenFor(request, REALM_PER_SCOPE, 'a3-admin3', PW);
    const a4Tok = await userTokenFor(request, REALM_PER_SCOPE, 'a3-admin4', PW);

    // 3 authorizes → still below threshold(4). Each from a DISTINCT admin
    // (authorize:222-239 rejects same-admin duplicates with 409). All four
    // signers hold APPROVER_ROLE so requireApprover (line 182-196) passes
    // for every one ("any" mode, default — admin has APPROVER_ROLE ∈
    // requiredApproverRoles={APPROVER_ROLE}).
    expect((await authorizeAs(request, REALM_PER_SCOPE, crId, a1Tok)).http).toBe(200);
    expect((await authorizeAs(request, REALM_PER_SCOPE, crId, a2Tok)).http).toBe(200);
    expect((await authorizeAs(request, REALM_PER_SCOPE, crId, a3Tok)).http).toBe(200);

    // commit by an approver-role-holder with authCount=3<threshold=4 → 412.
    const subCommit = await commitAs(request, REALM_PER_SCOPE, crId, a1Tok);
    expect(
      subCommit.http,
      `commit with authCount=3<threshold=4 must be 412, got ${subCommit.http} ${JSON.stringify(subCommit.body)}`,
    ).toBe(412);
    expect(subCommit.body?.threshold).toBe(4);
    expect(subCommit.body?.authCount).toBe(3);

    // 4th authorize hits threshold; commit now succeeds.
    expect((await authorizeAs(request, REALM_PER_SCOPE, crId, a4Tok)).http).toBe(200);
    const st1 = await getChangeRequestStatus(request, REALM_PER_SCOPE, crId);
    expect(st1.authCount).toBe(4);
    expect(st1.readyToCommit).toBe(true);

    const okCommit = await commitAs(request, REALM_PER_SCOPE, crId, a1Tok);
    expect(
      okCommit.http,
      `commit at authCount(4)>=threshold(4) expected 200, got ${okCommit.http} ${JSON.stringify(okCommit.body)}`,
    ).toBe(200);
  });
});
