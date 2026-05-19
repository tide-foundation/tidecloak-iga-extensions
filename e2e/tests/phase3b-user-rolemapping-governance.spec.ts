import { test, expect, APIRequestContext } from '@playwright/test';
import {
  createScratchRealm,
  deleteRealm,
  enableIga,
  igaStatus,
  createRole,
  createGroup,
  createUser,
  getRole,
  getUserByUsername,
  getUserRealmRoleMappings,
  assignRealmRoleMapping,
  getChangeRequest,
  findChangeRequest,
  authorizeAndCommit,
  locationHeader,
  safeJson,
  UserSpec,
} from '../lib/kc';

/**
 * Phase 3b — roles are STILL fully governed, just as a SEPARATE step.
 *
 * CREATE_USER governs only the 8 KC-routed token fields and explicitly does
 * NOT govern roles (stock KC's UsersResource.createUser never applies
 * realmRoles/clientRoles — proven in phase3). This spec proves the other half:
 * a realm-role assignment to an existing user — POST
 * /admin/realms/{realm}/users/{id}/role-mappings/realm →
 * RoleMapperResource.addRealmRoleMappings → roleMapper.grantRole(role) — is
 * GOVERNED by IGA's existing inline relationship-action path as a standalone
 * `GRANT_ROLES` change request, deferred until authorize+commit, and replays
 * the role correctly. That governance code is UNCHANGED — this spec only
 * VERIFIES it.
 *
 * Observed (existing, unchanged) behaviour of the role-mapping POST under IGA:
 *  - IgaUserAdapter.grantRole (inline, IGA active, not replay) calls
 *    IgaChangeRequestService.create(... "GRANT_ROLES" ...) and returns
 *    normally WITHOUT throwing IgaPendingApprovalException. Only that
 *    exception maps to 202 (IgaPendingApprovalExceptionMapper); the inline
 *    relationship path does not throw it. KC's addRealmRoleMappings is a
 *    `void @POST`, so the HTTP response is its default 204 No Content, with
 *    NO Location header — but the role is NOT actually mapped (the inline
 *    branch substitutes a CR for the mutation) and a PENDING `GRANT_ROLES`
 *    change request now exists. We therefore locate the CR via
 *    findChangeRequest(GRANT_ROLES) rather than a 202 Location, and assert
 *    the role is absent at draft, present only after authorize+commit.
 *
 * Pure API E2E (no browser). Idempotent; the scratch realm is always deleted
 * in afterAll even on failure.
 *
 * Precondition gate (same loaded-vs-codebug distinction as phase3): a governed
 * user create on a probe realm must 202 + carry a CREATE_USER CR. If it does
 * not even 202, the jar is not loaded → restart then re-run. If it 202s but
 * something downstream is wrong, that is a code bug (do NOT restart).
 */

const REALM = 'iga-phase3b-e2e';
const PROBE_REALM = 'iga-phase3b-precond-probe';
const RERUN =
  'cd /home/sasha/project/tidecloak-iga-extensions/e2e && npx playwright test';

/** Drive a governed CREATE_USER to a committed user (the only way to get a
 *  user once IGA is on). Returns the committed user's UUID. */
async function createGovernedUserCommitted(
  request: APIRequestContext,
  realm: string,
  spec: UserSpec,
): Promise<string> {
  const create = await createUser(request, realm, spec);
  const status = create.status();
  const loc = locationHeader(create);
  const body = await safeJson(create);
  expect(
    status,
    `governed user create expected 202, got ${status} body=${JSON.stringify(
      body,
    )}`,
  ).toBe(202);
  const crId =
    (body && body.changeRequestId) || (loc ? loc.split('/').pop() : '');
  expect(crId, 'CREATE_USER CR id resolvable').toBeTruthy();
  const ac = await authorizeAndCommit(request, realm, crId);
  expect(
    ac.authorize.http,
    `CREATE_USER authorize expected 200, got ${ac.authorize.http} ${JSON.stringify(
      ac.authorize.body,
    )}`,
  ).toBe(200);
  expect(
    ac.commit.http,
    `CREATE_USER commit expected 200, got ${ac.commit.http} ${JSON.stringify(
      ac.commit.body,
    )}`,
  ).toBe(200);
  const found = await getUserByUsername(request, realm, spec.username);
  expect(found.body, `user ${spec.username} must exist after commit`).toBeTruthy();
  return found.body.id as string;
}

test.describe('IGA Phase 3b: realm role-mapping is governed separately (GRANT_ROLES)', () => {
  test.afterAll(async ({ request }) => {
    await deleteRealm(request, REALM).catch(() => {});
    await deleteRealm(request, PROBE_REALM).catch(() => {});
  });

  test('Assigning a realm role to an existing user is deferred into a GRANT_ROLES change request and replays on commit', async ({
    request,
  }) => {
    // -----------------------------------------------------------------------
    // PRECONDITION GATE — a governed user create must 202 + carry a
    // CREATE_USER CR. (Same loaded-vs-codebug distinction as phase3.)
    // -----------------------------------------------------------------------
    const pre = await (async () => {
      const evidence: Record<string, unknown> = {};
      try {
        await createScratchRealm(request, PROBE_REALM);
        await enableIga(request, PROBE_REALM);
        evidence.igaEnabled = true;
        const res = await createUser(request, PROBE_REALM, {
          username: 'probe-user',
          enabled: true,
          email: 'probe-user@example.test',
        });
        const status = res.status();
        const loc = locationHeader(res);
        const body = await safeJson(res);
        evidence.governedCreateStatus = status;
        evidence.governedCreateLocation = loc ?? null;
        if (status !== 202 || !loc) {
          const hint =
            status === 500
              ? 'governed user create returned 500 (provider jar likely not loaded)'
              : status === 201
                ? 'governed user create returned 201 (IGA capture NOT intercepting — Phase 3 path not active)'
                : `governed user create returned ${status} (expected 202 + Location)`;
          return {
            ok: false as const,
            loaded: false as const,
            detail: hint,
            evidence,
          };
        }
        const crId =
          (body && (body.changeRequestId as string)) ||
          loc.split('/').pop() ||
          '';
        const cr = await getChangeRequest(request, PROBE_REALM, crId);
        evidence.probeCrHttp = cr.http;
        evidence.probeCrActionType = cr.body?.actionType;
        if (cr.http !== 200 || cr.body?.actionType !== 'CREATE_USER') {
          return {
            ok: false as const,
            loaded: true as const,
            detail:
              `202 returned but CR not retrievable as a CREATE_USER ` +
              `(http=${cr.http}, actionType=${cr.body?.actionType}) — code ` +
              `bug, NOT a restart issue.`,
            evidence,
          };
        }
        return {
          ok: true as const,
          loaded: true as const,
          detail: 'Phase 3 loaded.',
          evidence,
        };
      } catch (e: any) {
        return {
          ok: false as const,
          loaded: false as const,
          detail: `Probe raised: ${e?.message ?? e}`,
          evidence,
        };
      } finally {
        await deleteRealm(request, PROBE_REALM).catch(() => {});
      }
    })();

    console.log(
      `\n[PRECONDITION phase3b] ok=${pre.ok} loaded=${
        (pre as { loaded?: boolean }).loaded
      }\n  ${pre.detail}\n  evidence=${JSON.stringify(pre.evidence, null, 2)}\n`,
    );
    if (!pre.ok) {
      const loaded = (pre as { loaded?: boolean }).loaded === true;
      if (loaded) {
        throw new Error(
          `PRECONDITION: Phase 3 loaded but the governed create is ` +
            `misbehaving — code bug, NOT a restart issue. ${pre.detail}`,
        );
      }
      throw new Error(
        `PRECONDITION: Phase 3 jar not loaded in the running container ` +
          `(${pre.detail}) — restart the container, then re-run: ${RERUN}`,
      );
    }

    // -----------------------------------------------------------------------
    // 1. Scratch realm + bases (IGA OFF): group g1 + realm role role1.
    //    role1 is created BEFORE IGA so creating it is not itself governed.
    // -----------------------------------------------------------------------
    await createScratchRealm(request, REALM);
    const g = await createGroup(request, REALM, 'g1');
    expect(g.status(), `base group g1 create expected 201`).toBe(201);
    const r = await createRole(request, REALM, { name: 'role1' });
    expect(r.status(), `base role role1 create expected 201`).toBe(201);

    // -----------------------------------------------------------------------
    // 2. Enable IGA + confirm active.
    // -----------------------------------------------------------------------
    await enableIga(request, REALM);
    const st1 = await igaStatus(request, REALM);
    expect(st1.http, 'iga-status http').toBe(200);
    expect(st1.enabled, 'IGA must be enabled').toBe(true);

    // -----------------------------------------------------------------------
    // 3. Get an existing user via the governed CREATE_USER path (then commit).
    //    This user carries NO roles from the create (roles are not part of
    //    CREATE_USER — proven in phase3).
    // -----------------------------------------------------------------------
    const userId = await createGovernedUserCommitted(request, REALM, {
      username: 'p3b-user',
      enabled: true,
      email: 'p3b-user@example.test',
      firstName: 'Phase',
      lastName: 'ThreeB',
    });
    expect(userId, 'committed user must have a UUID').toBeTruthy();

    // Sanity: the freshly committed user has NO role1 (roles are not part of
    // CREATE_USER).
    const rmBefore = await getUserRealmRoleMappings(request, REALM, userId);
    expect(rmBefore.http, 'user realm role-mappings http (pre-assign)').toBe(
      200,
    );
    expect(
      rmBefore.body.some((x: any) => x?.name === 'role1'),
      `user must NOT have role1 before the role-mapping assignment (got ${JSON.stringify(
        rmBefore.body.map((x: any) => x?.name),
      )})`,
    ).toBeFalsy();

    // -----------------------------------------------------------------------
    // 4. Assign realm role role1 to the existing user — POST
    //    /users/{id}/role-mappings/realm. IGA's existing inline
    //    relationship-action path governs this as a GRANT_ROLES change
    //    request: the role is NOT applied immediately and a PENDING
    //    GRANT_ROLES CR is created. (KC's void endpoint returns its default
    //    204; the inline path does not throw IgaPendingApprovalException, so
    //    there is no 202/Location — the CR is located by content.)
    // -----------------------------------------------------------------------
    const role1 = await getRole(request, REALM, 'role1');
    expect(role1.http, 'GET role1 representation').toBe(200);
    expect(role1.body?.id, 'role1 must have a UUID').toBeTruthy();

    const assign = await assignRealmRoleMapping(request, REALM, userId, [
      { id: role1.body.id, name: role1.body.name },
    ]);
    const assignStatus = assign.status();
    // The mutation must NOT have been applied synchronously: assert it is
    // deferred. KC's addRealmRoleMappings is a void @POST → default 204; the
    // decisive proof of governance is (a) no immediate role mapping and (b) a
    // PENDING GRANT_ROLES CR. Accept the KC-default 2xx for the void endpoint
    // (it does NOT mean the role was applied — the inline path swapped the
    // mutation for a CR).
    expect(
      assignStatus,
      `role-mapping POST returned ${assignStatus} ${await assign
        .text()
        .catch(() => '')} — expected the KC-default void status (2xx); the ` +
        `governance proof is the deferred CR + no immediate mapping, asserted ` +
        `next`,
    ).toBeLessThan(300);

    // The role must NOT be mapped yet — the assignment was deferred into a CR.
    const rmDraft = await getUserRealmRoleMappings(request, REALM, userId);
    expect(rmDraft.http, 'user realm role-mappings http (at draft)').toBe(200);
    expect(
      rmDraft.body.some((x: any) => x?.name === 'role1'),
      `role1 must NOT be mapped at draft — the assignment must be deferred ` +
        `into a GRANT_ROLES change request (got ${JSON.stringify(
          rmDraft.body.map((x: any) => x?.name),
        )})`,
    ).toBeFalsy();

    // A PENDING GRANT_ROLES change request for this user must now exist. This
    // is the existing IGA relationship-action governance (action type
    // "GRANT_ROLES", USER_ID/ROLE_ID rows) — verified, NOT modified.
    const grantCr = await findChangeRequest(
      request,
      REALM,
      'GRANT_ROLES',
      (cr) => cr.entityId === userId || cr.entityType === 'USER',
    );
    expect(
      grantCr,
      `a PENDING GRANT_ROLES change request must exist for the role ` +
        `assignment (entityId=${userId}). This proves the role assignment is ` +
        `deferred — roles ARE governed, just separately from CREATE_USER.`,
    ).toBeTruthy();
    expect(grantCr?.actionType, 'CR actionType').toBe('GRANT_ROLES');
    expect(grantCr?.status, 'CR status').toBe('PENDING');

    // -----------------------------------------------------------------------
    // 5. Authorize + commit the GRANT_ROLES CR → role1 now mapped on the user.
    // -----------------------------------------------------------------------
    const grantId = grantCr!.id;
    const ac = await authorizeAndCommit(request, REALM, grantId);
    expect(
      ac.authorize.http,
      `GRANT_ROLES authorize expected 200, got ${ac.authorize.http} ${JSON.stringify(
        ac.authorize.body,
      )}`,
    ).toBe(200);
    expect(
      ac.commit.http,
      `GRANT_ROLES commit expected 200, got ${ac.commit.http} ${JSON.stringify(
        ac.commit.body,
      )}`,
    ).toBe(200);

    const rmAfter = await getUserRealmRoleMappings(request, REALM, userId);
    expect(rmAfter.http, 'user realm role-mappings http (post-commit)').toBe(
      200,
    );
    expect(
      rmAfter.body.some((x: any) => x?.name === 'role1'),
      `role1 MUST be mapped on the user after the GRANT_ROLES CR is ` +
        `authorized+committed (got ${JSON.stringify(
          rmAfter.body.map((x: any) => x?.name),
        )}) — proves roles are fully governed, just as a separate step`,
    ).toBeTruthy();

    // -----------------------------------------------------------------------
    // 6. Cleanup (afterAll also deletes; do it here too and confirm).
    // -----------------------------------------------------------------------
    await deleteRealm(request, REALM);
    const gone = await igaStatus(request, REALM);
    expect(
      gone.http,
      `scratch realm must be deleted (iga-status expected 404, got ${gone.http})`,
    ).toBe(404);
  });
});
