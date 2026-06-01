import { test, expect, APIRequestContext, APIResponse } from '@playwright/test';
import { execSync } from 'child_process';
import {
  createScratchRealm,
  deleteRealm,
  enableIga,
  igaStatus,
  setRealmIgaAttr,
  setRoleIgaAttr,
  createRole,
  getRole,
  createUser,
  getUserByUsername,
  createAdminWithRoles,
  assignRealmRoleMapping,
  findChangeRequest,
  getChangeRequest,
  getChangeRequestStatus,
  authorizeAndCommit,
  authorizeAs,
  commitAs,
  userTokenFor,
  clientUuid,
  listChangeRequests,
  locationHeader,
  safeJson,
  kcFetch,
  UserSpec,
} from '../lib/kc';

/**
 * Phase 13 — TWO-MODE TideAttestor: firstAdmin bootstrap → multiAdmin transition
 * → dynamic floor(0.7 * activeAdmins) threshold.
 *
 * This is the wave-1a companion to phase12 (which proved the per-(table,owner)
 * SET-SIGNING mechanism). phase12 cannot exercise the firstAdmin/multiAdmin
 * STATE MACHINE; phase13 does, end to end against the running container +
 * Postgres, asserting on exactly what wave-1a can deliver:
 *
 *   13a firstAdmin seed + prefix + approver-bypass
 *       - A Tide realm (`iga.attestor=tide`) with a provisioned `tide-vendor-key`
 *         component lazily seeds ONE `iga_authorizer` row, mode='firstAdmin', on
 *         the first Tide-mode record() (TideAttestor.maybeSeedFirstAdminAuthorizer).
 *       - firstAdmin = ANYONE-with-manage-realm can approve: a governed CR whose
 *         scope requires an approver-role NOBODY holds is authorized+committed by
 *         a non-approver admin (IgaScopeResolver.requireApprover no-ops while the
 *         realm resolves firstAdmin). Under multiAdmin that same call would 403.
 *       - Non-policy CR attestations carry the `TIDE-FIRSTADMIN-v1:` prefix
 *         (TideAttestor.sign firstAdmin branch), distinct from phase12's
 *         `TIDE-DUMMY-v1:`.
 *
 *   13b transition flip
 *       - Committing a GRANT_ROLES CR for the realm-management `tide-realm-admin`
 *         role while firstAdmin flips `iga_authorizer.mode` -> 'multiAdmin' in the
 *         SAME txn as the attestation write (TideAttestor.combineFinal ->
 *         flipModeToMultiAdmin). Asserted by raw SQL on the MODE column.
 *
 *   13c dynamic threshold
 *       - In multiAdmin the realm-level default threshold is the dynamic
 *         floor(0.7 * activeTideRealmAdmins) (min 1) — NOT the static
 *         iga.threshold. We establish a known count N of active (committed,
 *         enabled) tide-realm-admins and OBSERVE the enforced threshold via the
 *         commit gate: a 0-authorization commit of a non-approver-gated CR returns
 *         HTTP 412 with body {threshold, authCount} where threshold ==
 *         max(1, floor(0.7*N)) (IgaAdminResource.commit:345-354 calls
 *         attestor.getThreshold -> TideAttestor.getThreshold dynamic branch).
 *
 * WAVE-2 BOUNDARY: the actual multiAdmin enclave/Midgard SIGNATURE is wave-2 and
 * NOT asserted here. We assert the reachable proxies: the MODE column, the
 * threshold MATH (via the commit-gate 412 body), the prefix, and the bypass
 * behaviour. sign() is the SHA-256 stub in wave-1a (see TideAttestor.stubSign).
 *
 * API E2E (no browser). DB facts read via `docker exec postgresP psql`, mirroring
 * phase12. Every iga_authorizer query is SCOPED to the realm's UUID so a stray
 * orphan row from a prior run on a deleted realm can never pollute an assertion.
 */

const REALM_13A = 'iga-phase13a-firstadmin';
const REALM_13BC = 'iga-phase13bc-transition'; // 13b + 13c share one realm (13b flips it, 13c reads the post-flip threshold)

const RERUN =
  'cd /home/sasha/project/tidecloak-iga-extensions/e2e && npx playwright test phase13';

const FIRSTADMIN_PREFIX = 'TIDE-FIRSTADMIN-v1:';
const DUMMY_PREFIX = 'TIDE-DUMMY-v1:';

const PG_CONTAINER = 'postgresP';
const PG_USER = 'tideadmin';
const PG_DB = 'dauthme';

// tide-vendor-key placeholder material (same approach as e2e/lib m2m specs +
// the task brief). sign() is stubbed in wave-1a, so these are never validated
// cryptographically — they only have to be NON-BLANK so the firstAdmin lazy
// seed's VRK-availability precondition passes (TideAttestor.maybeSeedFirstAdminAuthorizer).
const PLACEHOLDER_GVRK = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const PLACEHOLDER_GVRK_CERT = 'placeholder-gvrk-certificate';

const REALM_MANAGEMENT = 'realm-management';
const TIDE_REALM_ADMIN_ROLE = 'tide-realm-admin';

/** Run `docker exec postgresP psql -tAc "<sql>"` and return trimmed stdout. */
function psql(sql: string): string {
  const oneLine = sql.replace(/\s+/g, ' ').trim();
  const out = execSync(
    `docker exec ${PG_CONTAINER} psql -U ${PG_USER} -d ${PG_DB} -tAc ${JSON.stringify(oneLine)}`,
    { encoding: 'utf8' },
  );
  return out.trim();
}

function sqlLit(v: string): string {
  return v.replace(/'/g, "''");
}

/** The realm's internal UUID (= iga_authorizer.realm_id, KC realm.getId()). */
async function realmUuid(request: APIRequestContext, realm: string): Promise<string> {
  const res = await kcFetch(request, `/admin/realms/${realm}`);
  const body = await safeJson(res);
  expect(body?.id, `realm ${realm} uuid resolvable`).toBeTruthy();
  return body.id as string;
}

/** Read the SINGLE iga_authorizer row for a realm uuid: "<count>\x1F<mode>". */
function readAuthorizer(realmId: string): { count: number; mode: string | null } {
  const out = psql(
    `SELECT COUNT(*) || E'\\x1F' || COALESCE(MAX(mode),'') FROM iga_authorizer WHERE realm_id='${sqlLit(realmId)}'`,
  );
  const [count, mode] = out.split('\x1F');
  return { count: parseInt(count || '0', 10), mode: mode || null };
}

/** user_role_mapping(user, role).attestation. 'MISSING' if absent. */
function readUserRoleAtt(userId: string, roleId: string): string {
  const out = psql(
    `SELECT COUNT(*) || E'\\x1F' || COALESCE(MAX(attestation),'')
       FROM user_role_mapping
      WHERE user_id='${sqlLit(userId)}' AND role_id='${sqlLit(roleId)}'`,
  );
  const [count, att] = out.split('\x1F');
  if (!count || count === '0') return 'MISSING';
  return att ?? '';
}

/** Provision a realm-level tide-vendor-key component with non-blank gVRK material. */
async function createVendorKeyComponent(
  request: APIRequestContext,
  realm: string,
): Promise<void> {
  // Re-runnable: drop any pre-existing tide-vendor-key first.
  const existing = await kcFetch(
    request,
    `/admin/realms/${realm}/components?type=org.keycloak.keys.KeyProvider`,
  );
  const list = (await safeJson(existing)) || [];
  for (const c of Array.isArray(list) ? list : []) {
    if (c.providerId === 'tide-vendor-key') {
      await kcFetch(request, `/admin/realms/${realm}/components/${c.id}`, {
        method: 'DELETE',
      });
    }
  }
  const res = await kcFetch(request, `/admin/realms/${realm}/components`, {
    method: 'POST',
    json: {
      name: 'tide-vendor-key',
      providerId: 'tide-vendor-key',
      providerType: 'org.keycloak.keys.KeyProvider',
      parentId: realm, // realm name is accepted as parentId for realm-level components
      config: {
        priority: ['100'],
        enabled: ['true'],
        active: ['true'],
        gVRK: [PLACEHOLDER_GVRK],
        gVRKCertificate: [PLACEHOLDER_GVRK_CERT],
        clientSecret: ['{}'],
      },
    },
  });
  expect(
    res.status(),
    `createVendorKeyComponent(${realm}) expected 201, got ${res.status()}: ${await res.text()}`,
  ).toBe(201);
}

/**
 * Ensure the realm-management `tide-realm-admin` client role exists and return
 * its rep {id,name,uuid}. A vanilla scratch realm's stock `realm-management`
 * client does NOT ship this role (it is part of TideCloak's full realm template,
 * not vanilla KC), so we create it here — idempotently. The TideAttestor resolves
 * the transition trigger by the role's IDENTITY (realm-management.getRole(
 * "tide-realm-admin") -> id), so a role created with this exact name under this
 * exact client is byte-for-byte the signal combineFinal matches on. MUST be
 * called BEFORE enableIga so the create is a plain 201, not a governed CR.
 */
async function ensureTideRealmAdminRole(
  request: APIRequestContext,
  realm: string,
): Promise<{ id: string; name: string; uuid: string }> {
  const rmUuid = await clientUuid(request, realm, REALM_MANAGEMENT);
  let res = await kcFetch(
    request,
    `/admin/realms/${realm}/clients/${rmUuid}/roles/${TIDE_REALM_ADMIN_ROLE}`,
  );
  if (res.status() === 404) {
    const created = await kcFetch(
      request,
      `/admin/realms/${realm}/clients/${rmUuid}/roles`,
      { method: 'POST', json: { name: TIDE_REALM_ADMIN_ROLE } },
    );
    expect(
      created.status(),
      `create realm-management:${TIDE_REALM_ADMIN_ROLE} expected 201, got ${created.status()}: ${await created.text()}`,
    ).toBe(201);
    res = await kcFetch(
      request,
      `/admin/realms/${realm}/clients/${rmUuid}/roles/${TIDE_REALM_ADMIN_ROLE}`,
    );
  }
  expect(res.status(), `GET realm-management:${TIDE_REALM_ADMIN_ROLE}`).toBe(200);
  const role = await safeJson(res);
  expect(role?.id, 'tide-realm-admin role id resolvable').toBeTruthy();
  return { id: role.id as string, name: role.name as string, uuid: rmUuid };
}

/** Assign a CLIENT role to a user. KC's RoleMapperResource.addClientRoleMappings
 *  → user.grantRole → IgaUserAdapter.grantRole captures a GRANT_ROLES CR whose
 *  row carries ROLE_ID = the client role's id (IgaUserAdapter.java:872-873). */
function assignClientRoleMapping(
  request: APIRequestContext,
  realm: string,
  userId: string,
  clientUuidVal: string,
  roles: any[],
): Promise<APIResponse> {
  return kcFetch(
    request,
    `/admin/realms/${realm}/users/${userId}/role-mappings/clients/${clientUuidVal}`,
    { method: 'POST', json: roles },
  );
}

/** Create a governed user and commit it (CREATE_USER), returning its UUID.
 *  Mirrors phase12.createGovernedUserCommitted; works in any IGA mode because
 *  CREATE_USER has empty scope (no approver gate) and, in firstAdmin/multiAdmin
 *  with low N, threshold 1 is met by the single master signature. */
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
    `governed user create expected 202, got ${status} body=${JSON.stringify(body)}`,
  ).toBe(202);
  const crId = (body && body.changeRequestId) || (loc ? loc.split('/').pop() : '');
  expect(crId, 'CREATE_USER CR id resolvable').toBeTruthy();
  const ac = await authorizeAndCommit(request, realm, crId as string);
  expect(ac.commit.http, `CREATE_USER commit ${JSON.stringify(ac.commit.body)}`).toBe(200);
  const found = await getUserByUsername(request, realm, spec.username);
  expect(found.body, `user ${spec.username} must exist after commit`).toBeTruthy();
  return found.body.id as string;
}

/** Drive an existing user's GRANT_ROLES (client role) to commit AS THE MASTER.
 *  Returns the CR id. Used to grant tide-realm-admin (the transition trigger). */
async function grantClientRoleCommittedAsMaster(
  request: APIRequestContext,
  realm: string,
  userId: string,
  clientUuidVal: string,
  role: { id: string; name: string },
): Promise<string> {
  const assign = await assignClientRoleMapping(request, realm, userId, clientUuidVal, [role]);
  expect(
    assign.status() < 300,
    `client role-mapping POST expected 2xx (deferred), got ${assign.status()}`,
  ).toBeTruthy();
  const cr = await findChangeRequest(
    request,
    realm,
    'GRANT_ROLES',
    (c) =>
      Array.isArray((c as any).rows) &&
      (c as any).rows.some((x: any) => x.ROLE_ID === role.id),
  );
  expect(cr, `PENDING GRANT_ROLES CR for client role ${role.name}`).toBeTruthy();
  const ac = await authorizeAndCommit(request, realm, (cr as any).id);
  expect(ac.commit.http, `GRANT_ROLES(${role.name}) commit ${JSON.stringify(ac.commit.body)}`).toBe(200);
  return (cr as any).id as string;
}

test.describe('IGA Phase 13: firstAdmin/multiAdmin two-mode attestor', () => {
  test.afterAll(async ({ request }) => {
    await deleteRealm(request, REALM_13A).catch(() => {});
    await deleteRealm(request, REALM_13BC).catch(() => {});
  });

  // =========================================================================
  // 13a — firstAdmin lazy seed + TIDE-FIRSTADMIN-v1 prefix + approver-bypass.
  // =========================================================================
  test('phase13a: firstAdmin seed (mode=firstAdmin) + TIDE-FIRSTADMIN-v1 prefix + non-approver bypass', async ({
    request,
  }) => {
    // ----- bases (IGA OFF) -----
    await createScratchRealm(request, REALM_13A);
    const realmId = await realmUuid(request, REALM_13A);

    // A role gated by an approver-role NOBODY in this realm holds. Set BEFORE
    // enableIga so the attribute write itself is not governed (the "configure
    // scope bases before enabling IGA" harness rule). Under multiAdmin, granting
    // this role would require `ghost-approver`; under firstAdmin the gate no-ops.
    expect((await createRole(request, REALM_13A, { name: 'gated' })).status(), 'role gated').toBe(201);
    await setRoleIgaAttr(request, REALM_13A, 'gated', 'iga.approverRole', 'ghost-approver');

    // The NON-APPROVER admin: manage-realm ONLY, NO `ghost-approver` (extraRoles=[]).
    // Created pre-IGA so it is a plain 201 user with a usable password.
    await createAdminWithRoles(request, REALM_13A, 'p13a-nonapprover', 'pw-nonapprover-13a', []);

    // VRK material so the firstAdmin lazy seed can fire on the first record().
    await createVendorKeyComponent(request, REALM_13A);

    // Tide discriminator BEFORE enableIga (else it becomes a governed CR).
    await setRealmIgaAttr(request, REALM_13A, 'iga.attestor', 'tide');
    await enableIga(request, REALM_13A);
    expect((await igaStatus(request, REALM_13A)).enabled, 'IGA enabled (13a realm)').toBe(true);

    // Pre-seed sanity: before any Tide-mode record(), the realm has 0 authorizer
    // rows but resolveMode's no-row branch already reports firstAdmin (asserted
    // indirectly by the bypass + prefix below). The row is born lazily.
    const before = readAuthorizer(realmId);
    expect(before.count, 'no authorizer row before first record (lazy seed)').toBe(0);

    // userTokenFor self-heals the post-toggle ADOPT_USER for the non-approver
    // admin (master authorize+commit; in firstAdmin the approver gate no-ops, so
    // this is a clean 1-of-1). It returns the non-approver's own bearer token.
    // This is ALSO the first Tide-mode record() → it lazily seeds the firstAdmin
    // authorizer row (TideAttestor.maybeSeedFirstAdminAuthorizer).
    const nonApproverToken = await userTokenFor(
      request,
      REALM_13A,
      'p13a-nonapprover',
      'pw-nonapprover-13a',
    );
    expect(nonApproverToken, 'non-approver admin token').toBeTruthy();

    // ----- ASSERT 1: lazy firstAdmin seed -----
    const seeded = readAuthorizer(realmId);
    expect(
      seeded.count,
      `exactly ONE iga_authorizer row lazily seeded for realm ${realmId} (got ${seeded.count})`,
    ).toBe(1);
    expect(
      seeded.mode,
      `seeded authorizer mode must be 'firstAdmin' (got '${seeded.mode}')`,
    ).toBe('firstAdmin');

    // ----- ASSERT 2: NON-APPROVER bypass -----
    // The grant SUBJECT — a GOVERNED-committed user (created post-IGA, CREATE_USER
    // committed). A committed CREATE_USER leaves NO pending CR, so the subsequent
    // GRANT_ROLES capture is not blocked by IgaUserAdapter.checkNoPendingCr (a
    // pre-IGA user would still carry an uncommitted toggle-on ADOPT_USER and the
    // grant would 500 with IgaConflictException).
    const subjectId = await createGovernedUserCommitted(request, REALM_13A, {
      username: 'p13a-subject',
      enabled: true,
      email: 'p13a-subject@example.test',
    });

    // The non-approver admin grants `gated` (scope requires `ghost-approver`,
    // which they do NOT hold) to the subject, then authorizes+commits it THEMSELVES.
    const gated = (await getRole(request, REALM_13A, 'gated')).body;

    const assign = await assignRealmRoleMapping(request, REALM_13A, subjectId, [
      { id: gated.id, name: gated.name },
    ]);
    expect(assign.status() < 300, `grant-gated POST deferred 2xx, got ${assign.status()}`).toBeTruthy();
    const grantCr = await findChangeRequest(
      request,
      REALM_13A,
      'GRANT_ROLES',
      (c) => Array.isArray((c as any).rows) && (c as any).rows.some((x: any) => x.ROLE_ID === gated.id),
    );
    expect(grantCr, 'PENDING GRANT_ROLES CR for gated').toBeTruthy();

    // Cross-check the gate would bite under multiAdmin: the CR must actually
    // resolve `ghost-approver` as a required approver role (so the bypass below
    // is meaningful, not a vacuous empty-scope pass).
    const crStatus = await getChangeRequestStatus(request, REALM_13A, (grantCr as any).id);
    expect(
      (crStatus.requiredApproverRoles || []).includes('ghost-approver'),
      `CR scope must require 'ghost-approver' (got ${JSON.stringify(crStatus.requiredApproverRoles)}) — else the bypass is vacuous`,
    ).toBeTruthy();

    // THE BYPASS: a non-approver authorizes+commits in firstAdmin mode. Under
    // multiAdmin, authorizeAs here would be 403 (IgaScopeResolver.requireApprover).
    const auth = await authorizeAs(request, REALM_13A, (grantCr as any).id, nonApproverToken);
    expect(
      auth.http,
      `firstAdmin bypass: non-approver authorize must be 200 (got ${auth.http} ${JSON.stringify(auth.body)})`,
    ).toBe(200);
    const commit = await commitAs(request, REALM_13A, (grantCr as any).id, nonApproverToken);
    expect(
      commit.http,
      `firstAdmin bypass: non-approver commit must be 200 (got ${commit.http} ${JSON.stringify(commit.body)})`,
    ).toBe(200);

    // ----- ASSERT 3: TIDE-FIRSTADMIN-v1 prefix on the committed non-policy CR -----
    const grantAtt = readUserRoleAtt(subjectId, gated.id);
    expect(grantAtt, `gated grant must be stamped (got '${grantAtt}')`).not.toBe('MISSING');
    expect(
      grantAtt.startsWith(FIRSTADMIN_PREFIX),
      `non-policy CR attestation must carry ${FIRSTADMIN_PREFIX} (got '${grantAtt}')`,
    ).toBeTruthy();
    // ...and NOT the multiAdmin dummy prefix (mode discrimination is real).
    expect(
      grantAtt.startsWith(DUMMY_PREFIX),
      `firstAdmin attestation must NOT carry the multiAdmin ${DUMMY_PREFIX} prefix (got '${grantAtt}')`,
    ).toBeFalsy();

    // Mode is still firstAdmin (this grant was NOT tide-realm-admin → no flip).
    expect(readAuthorizer(realmId).mode, 'mode stays firstAdmin (no tide-realm-admin grant yet)').toBe(
      'firstAdmin',
    );

    console.log(
      `\n[phase13a] realm=${realmId} authorizer={count:1,mode:firstAdmin} ` +
        `bypass: non-approver authorize+commit=200 prefix='${grantAtt.slice(0, FIRSTADMIN_PREFIX.length + 6)}...'\n`,
    );
  });

  // =========================================================================
  // 13b — firstAdmin -> multiAdmin transition flip on tide-realm-admin grant.
  // 13c — dynamic floor(0.7 * N) threshold in the now-multiAdmin realm.
  // Shared realm: 13b performs the flip; 13c reads the post-flip threshold.
  // =========================================================================
  test('phase13b+c: transition flip on tide-realm-admin grant + dynamic floor(0.7*N) threshold', async ({
    request,
  }) => {
    // ----- bases (IGA OFF) -----
    await createScratchRealm(request, REALM_13BC);
    const realmId = await realmUuid(request, REALM_13BC);

    // A plain realm role to use for the 0-auth threshold probe in 13c (no
    // approver scope, so the commit reaches the THRESHOLD gate, not a 403).
    expect((await createRole(request, REALM_13BC, { name: 'probe-role' })).status(), 'role probe-role').toBe(201);

    // Provision realm-management:tide-realm-admin BEFORE enabling IGA (plain 201;
    // post-IGA it would be a governed CREATE-role CR). Resolve the rep now; its
    // id is stable across the toggle, so we reuse it after enableIga.
    const tideAdmin = await ensureTideRealmAdminRole(request, REALM_13BC);

    await createVendorKeyComponent(request, REALM_13BC);
    await setRealmIgaAttr(request, REALM_13BC, 'iga.attestor', 'tide');
    await enableIga(request, REALM_13BC);
    expect((await igaStatus(request, REALM_13BC)).enabled, 'IGA enabled (13bc realm)').toBe(true);

    // First governed user (committed) — receives the FIRST tide-realm-admin grant
    // (the transition trigger). createGovernedUserCommitted's CREATE_USER commit
    // is the first Tide-mode record() → lazily seeds the firstAdmin authorizer.
    const admin1 = await createGovernedUserCommitted(request, REALM_13BC, {
      username: 'p13-admin1',
      enabled: true,
      email: 'p13-admin1@example.test',
    });

    // Pre-flip: confirm the realm is firstAdmin (seed materialised by the
    // CREATE_USER record above).
    const preFlip = readAuthorizer(realmId);
    expect(preFlip.count, 'authorizer row seeded by first CREATE_USER record').toBe(1);
    expect(preFlip.mode, 'mode is firstAdmin before the tide-realm-admin grant').toBe('firstAdmin');

    // ---------------------------------------------------------------------
    // 13b — grant realm-management:tide-realm-admin to admin1 and commit it.
    //   In firstAdmin mode this is the bootstrap policy CR: a NON-approver
    //   master can commit it (firstAdmin bypass), and combineFinal flips the
    //   mode to multiAdmin in the SAME txn as the attestation write.
    // ---------------------------------------------------------------------
    await grantClientRoleCommittedAsMaster(request, REALM_13BC, admin1, tideAdmin.uuid, {
      id: tideAdmin.id,
      name: tideAdmin.name,
    });

    // ----- 13b ASSERT: mode flipped to multiAdmin (raw SQL on MODE column) -----
    const postFlip = readAuthorizer(realmId);
    expect(postFlip.count, 'still exactly one authorizer row after flip').toBe(1);
    expect(
      postFlip.mode,
      `TRANSITION: iga_authorizer.mode must flip firstAdmin -> multiAdmin on the ` +
        `tide-realm-admin grant (got '${postFlip.mode}')`,
    ).toBe('multiAdmin');

    // admin1's tide-realm-admin grant is committed (stamped) → counts toward N.
    const a1Att = readUserRoleAtt(admin1, tideAdmin.id);
    expect(a1Att, 'admin1 tide-realm-admin grant stamped (committed)').not.toBe('MISSING');

    console.log(
      `\n[phase13b] realm=${realmId} mode flip firstAdmin -> ${postFlip.mode} ` +
        `on tide-realm-admin grant; admin1 grant stamped='${a1Att.slice(0, 20)}...'\n`,
    );

    // ---------------------------------------------------------------------
    // 13c — dynamic floor(0.7 * N) threshold in multiAdmin mode.
    //
    // Build N up to 3 by granting tide-realm-admin to two more committed users.
    // Each subsequent grant is now in multiAdmin mode, but tide-realm-admin
    // carries no iga.approverRole (empty scope) and the running threshold is
    // floor(0.7*N_current) which stays 1 for N_current in {1,2}, so the master's
    // single signature commits each. After these, N = 3 active admins:
    //   activeTideRealmAdmin := holds realm-management tide-realm-admin
    //                            + enabled + user_role_mapping.attestation NOT NULL.
    // ---------------------------------------------------------------------
    const admin2 = await createGovernedUserCommitted(request, REALM_13BC, {
      username: 'p13-admin2',
      enabled: true,
      email: 'p13-admin2@example.test',
    });
    await grantClientRoleCommittedAsMaster(request, REALM_13BC, admin2, tideAdmin.uuid, {
      id: tideAdmin.id,
      name: tideAdmin.name,
    });

    const admin3 = await createGovernedUserCommitted(request, REALM_13BC, {
      username: 'p13-admin3',
      enabled: true,
      email: 'p13-admin3@example.test',
    });
    await grantClientRoleCommittedAsMaster(request, REALM_13BC, admin3, tideAdmin.uuid, {
      id: tideAdmin.id,
      name: tideAdmin.name,
    });

    // Confirm all three grants are committed/stamped — the exact predicate
    // countActiveTideRealmAdmins uses (UserRoleMappingEntity.attestation NOT NULL).
    const committedN = psql(
      `SELECT COUNT(*) FROM user_role_mapping
        WHERE role_id='${sqlLit(tideAdmin.id)}' AND attestation IS NOT NULL`,
    );
    const N = parseInt(committedN || '0', 10);
    expect(N, `expected 3 committed tide-realm-admin grants (got ${N})`).toBe(3);
    const expectedThreshold = Math.max(1, Math.floor(0.7 * N)); // floor(0.7*3)=2

    // OBSERVE the enforced dynamic threshold via the COMMIT GATE.
    // Create a fresh governed CR (GRANT probe-role to admin1) and, WITHOUT
    // authorizing it, attempt to commit AS THE MASTER. IgaAdminResource.commit
    // computes threshold = attestor.getThreshold(...) (the TideAttestor dynamic
    // floor(0.7*N) branch) and, since authCount(0) < threshold, returns HTTP 412
    // with body {threshold, authCount}. That body.threshold IS the dynamic value.
    //
    // NOTE on observation choice: the CR-representation `threshold` field
    // (IgaAdminResource.toRepresentation:1831) is the STATIC IgaScopeResolver
    // path and would mislead (it reports 1 here). The enforced threshold lives in
    // the commit gate (line 345), so we read it there — the authoritative source.
    const probe = await assignRealmRoleMapping(request, REALM_13BC, admin1, [
      { id: (await getRole(request, REALM_13BC, 'probe-role')).body.id, name: 'probe-role' },
    ]);
    expect(probe.status() < 300, `probe grant POST deferred 2xx, got ${probe.status()}`).toBeTruthy();
    const probeCr = await findChangeRequest(
      request,
      REALM_13BC,
      'GRANT_ROLES',
      (c) =>
        Array.isArray((c as any).rows) &&
        (c as any).rows.some((x: any) => x.ROLE_ID && (c as any).entityId === admin1) &&
        (c as any).rows.some((x: any) => x.USER_ID === admin1),
    );
    expect(probeCr, 'PENDING probe GRANT_ROLES CR').toBeTruthy();

    // Commit WITHOUT authorizing → authCount 0 → 412 exposing the dynamic threshold.
    const bareCommit = await kcFetch(
      request,
      `/admin/realms/${REALM_13BC}/iga/change-requests/${(probeCr as any).id}/commit`,
      { method: 'POST' },
    );
    const bareBody = await safeJson(bareCommit);
    expect(
      bareCommit.status(),
      `0-auth commit must be 412 PRECONDITION_FAILED in multiAdmin N=${N} ` +
        `(got ${bareCommit.status()} ${JSON.stringify(bareBody)})`,
    ).toBe(412);
    expect(
      bareBody?.authCount,
      `412 body authCount must be 0 (got ${JSON.stringify(bareBody)})`,
    ).toBe(0);
    expect(
      bareBody?.threshold,
      `DYNAMIC THRESHOLD: 412 body threshold must equal max(1, floor(0.7*${N}))=${expectedThreshold} ` +
        `(got ${JSON.stringify(bareBody)})`,
    ).toBe(expectedThreshold);

    // Cross-check the math is the NON-trivial floor (2), distinct from the min-1
    // clamp, so this genuinely exercises floor(0.7*N) and not the fallback.
    expect(expectedThreshold, 'N=3 yields a non-trivial floor of 2 (not the min-1 clamp)').toBe(2);

    // Belt-and-braces: readyToCommit in the CR representation also uses the
    // dynamic attestor.getThreshold (toRepresentation:1818), so with 0 auths it
    // must be false (authCount 0 < 2). This corroborates the 412 reading via a
    // second code path.
    const rep = await getChangeRequest(request, REALM_13BC, (probeCr as any).id);
    expect(
      rep.body?.readyToCommit,
      `readyToCommit must be false at authCount 0 < threshold ${expectedThreshold}`,
    ).toBe(false);

    console.log(
      `\n[phase13c] realm=${realmId} mode=multiAdmin N=${N} active tide-realm-admins ` +
        `=> enforced threshold floor(0.7*${N})=${expectedThreshold} ` +
        `observed via commit-gate 412 body={threshold:${bareBody?.threshold},authCount:${bareBody?.authCount}}\n`,
    );
  });
});
