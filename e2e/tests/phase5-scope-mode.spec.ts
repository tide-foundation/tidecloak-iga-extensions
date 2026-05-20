import { test, expect } from '@playwright/test';
import {
  createScratchRealm,
  deleteRealm,
  enableIga,
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
  authorizeAs,
  getChangeRequestStatus,
  findChangeRequest,
} from '../lib/kc';
import { checkPrecondition, rerunCommand } from '../lib/precondition';

/**
 * Phase 5C — Tideless IGA gate: scopeMode any vs all.
 *
 * Source-of-truth (line refs verified against the resolver source):
 *
 *   IgaScopeResolver.requireApprover (iga-core/.../attestors/
 *     IgaScopeResolver.java:182-196):
 *       boolean strict = "all".equalsIgnoreCase(realm.getAttribute(ATTR_SCOPE_MODE));
 *       boolean ok = strict
 *               ? adminRoleNames.containsAll(scope.requiredApproverRoles)
 *               : scope.requiredApproverRoles.stream().anyMatch(adminRoleNames::contains);
 *
 *   So: scopeMode is REALM-LEVEL only; the realm attribute "iga.scopeMode"
 *   strictly compares to "all" (case-insensitive). ANY other value (or
 *   absent) yields strict=false → "any" semantics. The "any" branch
 *   succeeds when the admin holds ANY ONE of the required roles; "all"
 *   succeeds only when the admin holds EVERY required role.
 *
 *   IgaAdminResource.toRepresentation:1454-1456 surfaces the same derivation
 *   on the CR rep ("all" when the realm attr equals "all" case-insensitive,
 *   otherwise "any"), so getChangeRequestStatus's scopeMode field is the
 *   source-of-truth mirror.
 *
 * To get TWO distinct required roles across the CR scopes, we use
 * GROUP_GRANT_ROLES and attach iga.approverRole to BOTH the group (=roleX)
 * AND the role being granted (=roleY). IgaScopeResolver.resolve:76-80 then
 * walks both: walkGroupAncestors:333-343 contributes roleX from the group's
 * attribute, collectRoleScope:345-351 contributes roleY from the role's
 * attribute. Resulting requiredApproverRoles = {roleX, roleY}.
 *
 * Three admins: has-only-X, has-only-Y, has-both. Each authorize attempt
 * needs its OWN CR (same-admin duplicate auth is rejected with 409 —
 * IgaAdminResource.authorize:222-239), AND we need a fresh CR per attempt
 * because GROUP_GRANT_ROLES on the same (group, role) pair has at most one
 * PENDING CR at a time. To get separate CRs we use separate (group, role)
 * pairs per attempt — same attributes wired in.
 */

const REALM_ANY = 'iga-phase5c-any';
const REALM_ALL = 'iga-phase5c-all';
const ROLE_X = 'p5c-role-x';
const ROLE_Y = 'p5c-role-y';
const PW = 'p5c-admin-pw';

// Build a fresh (group, role) pair carrying the iga.approverRole attribute
// pairing required by Spec C: the group carries iga.approverRole=ROLE_X
// (an attribute-bearing scope entity for the group side) and the granted
// role carries iga.approverRole=ROLE_Y (attribute-bearing scope entity for
// the role side). Each call yields a CR with requiredApproverRoles = {X, Y}.
//
// Called PRE-IGA (the attribute writes are themselves governed otherwise).
async function makeScopePair(
  request: any,
  realm: string,
  groupName: string,
  roleName: string,
): Promise<{ groupId: string; roleRep: any }> {
  const gr = await createGroup(request, realm, groupName);
  if (gr.status() !== 201) throw new Error(`createGroup(${groupName}) failed ${gr.status()}`);
  const rr = await createRole(request, realm, { name: roleName });
  if (rr.status() !== 201) throw new Error(`createRole(${roleName}) failed ${rr.status()}`);
  const gLookup = await getGroupByName(request, realm, groupName);
  if (gLookup.http !== 200) throw new Error(`getGroupByName(${groupName}) failed ${gLookup.http}`);
  const groupId = gLookup.body.id as string;
  await setGroupIgaAttr(request, realm, groupId, 'iga.approverRole', ROLE_X);
  await setRoleIgaAttr(request, realm, roleName, 'iga.approverRole', ROLE_Y);
  const rLookup = await getRole(request, realm, roleName);
  if (rLookup.http !== 200) throw new Error(`getRole(${roleName}) failed ${rLookup.http}`);
  return { groupId, roleRep: rLookup.body };
}

async function triggerGroupGrantAndFindCr(
  request: any,
  realm: string,
  groupId: string,
  roleRep: any,
): Promise<string> {
  const mapRes = await assignGroupRealmRoleMapping(request, realm, groupId, [
    roleRep,
  ]);
  if (mapRes.status() !== 204) {
    throw new Error(
      `group role-mapping POST expected 204, got ${mapRes.status()}: ${await mapRes.text()}`,
    );
  }
  const cr = await findChangeRequest(
    request,
    realm,
    'GROUP_GRANT_ROLES',
    (c: any) => c.entityType === 'GROUP' && c.entityId === groupId,
  );
  if (!cr) throw new Error(`GROUP_GRANT_ROLES CR not found for group ${groupId}`);
  return cr.id;
}

test.describe('IGA Phase 5C: scopeMode any vs all (across multi-scope required roles)', () => {
  test.afterAll(async ({ request }) => {
    await deleteRealm(request, REALM_ANY).catch(() => {});
    await deleteRealm(request, REALM_ALL).catch(() => {});
  });

  // Build a realm with: ROLE_X + ROLE_Y as realm roles; three admins
  // has-only-X / has-only-Y / has-both; three (group, role) attribute-pairs
  // pre-wired so we can fire three distinct GROUP_GRANT_ROLES CRs (one per
  // attempt) after IGA is enabled. realm `iga.scopeMode` is set per-test
  // pre-IGA to the value under test.
  async function setupRealm(request: any, realm: string, scopeMode: 'any' | 'all') {
    await createScratchRealm(request, realm);
    // The two "required" roles (X and Y) must exist as realm roles before any
    // admin is created with them assigned. They themselves carry no IGA
    // attributes — they're just the role-NAMES iga.approverRole points to.
    const xRes = await createRole(request, realm, { name: ROLE_X });
    if (xRes.status() !== 201) throw new Error(`create ${ROLE_X} ${xRes.status()}`);
    const yRes = await createRole(request, realm, { name: ROLE_Y });
    if (yRes.status() !== 201) throw new Error(`create ${ROLE_Y} ${yRes.status()}`);

    await createAdminWithRoles(request, realm, 'has-only-x', PW, [ROLE_X]);
    await createAdminWithRoles(request, realm, 'has-only-y', PW, [ROLE_Y]);
    await createAdminWithRoles(request, realm, 'has-both', PW, [ROLE_X, ROLE_Y]);

    // Three independent (group, role) attribute pairs, each will drive its
    // own GROUP_GRANT_ROLES CR (so each test admin attempt has its own CR
    // to authorize — same-admin duplicate auth would be 409).
    const pair1 = await makeScopePair(
      request,
      realm,
      'sc-group-1',
      'sc-target-role-1',
    );
    const pair2 = await makeScopePair(
      request,
      realm,
      'sc-group-2',
      'sc-target-role-2',
    );
    const pair3 = await makeScopePair(
      request,
      realm,
      'sc-group-3',
      'sc-target-role-3',
    );

    // scopeMode realm attribute. Only "all" (case-insensitive) flips strict
    // mode; any other value (or absent) is "any". Set "all" only for the
    // strict-mode realm; for the "any" realm, leave unset to exercise the
    // default branch in requireApprover.
    if (scopeMode === 'all') {
      await setRealmIgaAttr(request, realm, 'iga.scopeMode', 'all');
    }

    await enableIga(request, realm);
    return { pair1, pair2, pair3 };
  }

  test('C.1 any (default): admin-with ANY one required role authorizes — has-only-X ✓, has-only-Y ✓, has-both ✓', async ({
    request,
  }) => {
    const pre = await checkPrecondition(request);
    if (pre.verdict !== 'OK') {
      throw new Error(
        `PRECONDITION: Phase 1 jar not loaded (verdict=${pre.verdict}: ${pre.detail}) — restart then re-run: ${rerunCommand()}`,
      );
    }
    const pairs = await setupRealm(request, REALM_ANY, 'any');

    const xTok = await userTokenFor(request, REALM_ANY, 'has-only-x', PW);
    const yTok = await userTokenFor(request, REALM_ANY, 'has-only-y', PW);
    const bothTok = await userTokenFor(request, REALM_ANY, 'has-both', PW);

    // Each attempt uses its own CR (separate group, separate role).
    const cr1 = await triggerGroupGrantAndFindCr(
      request,
      REALM_ANY,
      pairs.pair1.groupId,
      pairs.pair1.roleRep,
    );
    const cr2 = await triggerGroupGrantAndFindCr(
      request,
      REALM_ANY,
      pairs.pair2.groupId,
      pairs.pair2.roleRep,
    );
    const cr3 = await triggerGroupGrantAndFindCr(
      request,
      REALM_ANY,
      pairs.pair3.groupId,
      pairs.pair3.roleRep,
    );

    // CR-rep sanity: both ROLE_X and ROLE_Y required, scopeMode "any".
    const st = await getChangeRequestStatus(request, REALM_ANY, cr1);
    const required = new Set<string>(st.requiredApproverRoles ?? []);
    expect(
      required.has(ROLE_X) && required.has(ROLE_Y),
      `requiredApproverRoles must contain both ${ROLE_X} and ${ROLE_Y}, got ${JSON.stringify(st.requiredApproverRoles)}`,
    ).toBe(true);
    expect(st.scopeMode, 'C.1 scopeMode must default to "any"').toBe('any');

    // has-only-X authorizes CR1 — OK under "any" (holds ROLE_X ∈ {X,Y}).
    expect(
      (await authorizeAs(request, REALM_ANY, cr1, xTok)).http,
      'has-only-x must authorize under scopeMode=any',
    ).toBe(200);
    // has-only-Y authorizes CR2 — OK under "any" (holds ROLE_Y ∈ {X,Y}).
    expect(
      (await authorizeAs(request, REALM_ANY, cr2, yTok)).http,
      'has-only-y must authorize under scopeMode=any',
    ).toBe(200);
    // has-both authorizes CR3 — OK trivially.
    expect(
      (await authorizeAs(request, REALM_ANY, cr3, bothTok)).http,
      'has-both must authorize under scopeMode=any',
    ).toBe(200);
  });

  test('C.2 all (strict): admin-with EVERY required role authorizes — has-only-X ✗ (403), has-only-Y ✗ (403), has-both ✓', async ({
    request,
  }) => {
    const pre = await checkPrecondition(request);
    if (pre.verdict !== 'OK') {
      throw new Error(
        `PRECONDITION: Phase 1 jar not loaded (verdict=${pre.verdict}: ${pre.detail}) — restart then re-run: ${rerunCommand()}`,
      );
    }
    const pairs = await setupRealm(request, REALM_ALL, 'all');

    const xTok = await userTokenFor(request, REALM_ALL, 'has-only-x', PW);
    const yTok = await userTokenFor(request, REALM_ALL, 'has-only-y', PW);
    const bothTok = await userTokenFor(request, REALM_ALL, 'has-both', PW);

    const cr1 = await triggerGroupGrantAndFindCr(
      request,
      REALM_ALL,
      pairs.pair1.groupId,
      pairs.pair1.roleRep,
    );
    const cr2 = await triggerGroupGrantAndFindCr(
      request,
      REALM_ALL,
      pairs.pair2.groupId,
      pairs.pair2.roleRep,
    );
    const cr3 = await triggerGroupGrantAndFindCr(
      request,
      REALM_ALL,
      pairs.pair3.groupId,
      pairs.pair3.roleRep,
    );

    // CR-rep sanity: scopeMode is "all" because realm attribute = "all".
    const st = await getChangeRequestStatus(request, REALM_ALL, cr1);
    const required = new Set<string>(st.requiredApproverRoles ?? []);
    expect(
      required.has(ROLE_X) && required.has(ROLE_Y),
      `requiredApproverRoles must contain both ${ROLE_X} and ${ROLE_Y}, got ${JSON.stringify(st.requiredApproverRoles)}`,
    ).toBe(true);
    expect(st.scopeMode, 'C.2 scopeMode must be "all"').toBe('all');

    // has-only-X authorizing CR1 — REJECT under "all" (missing ROLE_Y).
    const r1 = await authorizeAs(request, REALM_ALL, cr1, xTok);
    expect(
      r1.http,
      `has-only-x under strict=all must be 403, got ${r1.http} ${JSON.stringify(r1.body)}`,
    ).toBe(403);

    // has-only-Y authorizing CR2 — REJECT under "all" (missing ROLE_X).
    const r2 = await authorizeAs(request, REALM_ALL, cr2, yTok);
    expect(
      r2.http,
      `has-only-y under strict=all must be 403, got ${r2.http} ${JSON.stringify(r2.body)}`,
    ).toBe(403);

    // has-both authorizing CR3 — OK (containsAll({X,Y}) = true).
    const r3 = await authorizeAs(request, REALM_ALL, cr3, bothTok);
    expect(
      r3.http,
      `has-both under strict=all must be 200, got ${r3.http} ${JSON.stringify(r3.body)}`,
    ).toBe(200);

    // The two rejected CRs must still have authCount=0 (no partial-write
    // on a requireApprover failure — record() in SimpleNameAttestor.java:46-65
    // calls requireApprover BEFORE em.persist, so the throw aborts before any
    // IgaAuthorizationEntity is written).
    const st1 = await getChangeRequestStatus(request, REALM_ALL, cr1);
    expect(st1.authCount, 'rejected CR authCount must stay 0').toBe(0);
    const st2 = await getChangeRequestStatus(request, REALM_ALL, cr2);
    expect(st2.authCount, 'rejected CR authCount must stay 0').toBe(0);
  });
});
