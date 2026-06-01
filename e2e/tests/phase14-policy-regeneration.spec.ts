import { test, expect, APIRequestContext, APIResponse } from '@playwright/test';
import { execSync } from 'child_process';
import {
  createScratchRealm,
  deleteRealm,
  enableIga,
  igaStatus,
  setRealmIgaAttr,
  createUser,
  getUserByUsername,
  createAdminWithRoles,
  findChangeRequest,
  authorizeAndCommit,
  authorizeAs,
  commitAs,
  userTokenFor,
  clientUuid,
  locationHeader,
  safeJson,
  kcFetch,
  UserSpec,
} from '../lib/kc';

/**
 * Phase 14 — WAVE 1b: threshold-change admin-policy REGENERATION (port plan §7a).
 *
 * Wave 1a (phase13) made ENFORCEMENT dynamic: getThreshold counts active
 * tide-realm-admins live = floor(0.7 * N). Wave 1b keeps the SIGNED admin POLICY
 * artifact (iga_role_policy.policy / .policy_sig for the realm-management
 * `tide-realm-admin` role) in sync with that dynamic threshold: whenever a
 * committed CR changes the active-admin set (GRANT/REVOKE of tide-realm-admin in
 * multiAdmin mode), TideAttestor.combineFinal regenerates the policy body at the
 * new floor(0.7 * N) threshold and RE-SIGNS it (VRK path → TIDE-FIRSTADMIN-v1:),
 * in the SAME commit transaction. An IsEqualTo short-circuit skips the rewrite
 * when the threshold did not actually move (one regen per CR, no churn).
 *
 *   14a  membership ADD that MOVES the threshold regenerates + re-signs
 *        - Drive a realm to multiAdmin (phase13's transition setup) with N=1.
 *        - Upsert an initial tide-realm-admin role-policy encoding threshold 1.
 *        - Add a 2nd admin (N 1->2): floor(0.7*2)=1 == current 1 -> IsEqualTo
 *          SKIP. Assert policy_sig UNCHANGED + threshold still 1 (no-churn).
 *        - Add a 3rd admin (N 2->3): floor(0.7*3)=2 != 1 -> REGEN. Assert
 *          policy_sig CHANGED, encoded threshold 1->2, and the new policy body
 *          carries {"threshold":2,"role":"tide-realm-admin",
 *          "resource":"realm-management"}.
 *
 *   14b  membership REVOKE that MOVES the threshold regenerates again (lower)
 *        - Revoke the 3rd admin (N 3->2): floor(0.7*2)=1 != 2 -> REGEN.
 *          (The revoke CR's OWN commit gate is at the pre-revoke N=3 -> threshold
 *          2, so it needs TWO signatures; we supply master + a 2nd approver.)
 *          Assert policy_sig CHANGED AGAIN and encoded threshold 2->1.
 *
 *   14c  re-sign prefix — every regen's policy_sig carries TIDE-FIRSTADMIN-v1:
 *        (the admin policy is ALWAYS VRK-signed, bootstrap AND every regen,
 *        §7a.3/§7a.5), NEVER the multiAdmin TIDE-DUMMY-v1: enclave prefix.
 *
 * WAVE-2 BOUNDARY: the real VRK→ORK signature is wave 2. sign() is the SHA-256
 * stub here, so we assert the reachable proxies: the policy_sig STRING CHANGING
 * across a threshold move, the encoded threshold MATH, the policy body shape, and
 * the VRK prefix. Each behaviour is a distinct assertion.
 *
 * API E2E (no browser). DB facts read via `docker exec postgresP psql`, mirroring
 * phase13. Every iga_role_policy query is SCOPED to the realm's UUID.
 */

const REALM_14 = 'iga-phase14-policy-regen';

const RERUN =
  'cd /home/sasha/project/tidecloak-iga-extensions/e2e && npx playwright test phase14';

const FIRSTADMIN_PREFIX = 'TIDE-FIRSTADMIN-v1:';
const DUMMY_PREFIX = 'TIDE-DUMMY-v1:';

const PG_CONTAINER = 'postgresP';
const PG_USER = 'tideadmin';
const PG_DB = 'dauthme';

// tide-vendor-key placeholder material (sign() is stubbed in wave 1a/1b, so these
// are never validated cryptographically — they only have to be NON-BLANK so the
// firstAdmin lazy seed's VRK-availability precondition passes). vvkId is read by
// the regen for the policy body, so we set a recognisable placeholder.
const PLACEHOLDER_GVRK = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const PLACEHOLDER_GVRK_CERT = 'placeholder-gvrk-certificate';
const PLACEHOLDER_VVK_ID = 'phase14-vvk';

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

/** The realm's internal UUID (= iga_role_policy.realm_id, KC realm.getId()). */
async function realmUuid(request: APIRequestContext, realm: string): Promise<string> {
  const res = await kcFetch(request, `/admin/realms/${realm}`);
  const body = await safeJson(res);
  expect(body?.id, `realm ${realm} uuid resolvable`).toBeTruthy();
  return body.id as string;
}

/** iga_authorizer mode for a realm uuid ('' if no row). */
function readAuthorizerMode(realmId: string): string {
  return psql(
    `SELECT COALESCE(MAX(mode),'') FROM iga_authorizer WHERE realm_id='${sqlLit(realmId)}'`,
  );
}

/**
 * Read the tide-realm-admin iga_role_policy row for a realm uuid + role id:
 * { exists, policy, policySig, threshold }. Fields are joined with the unit-
 * separator \x1F so a body containing commas/quotes never breaks parsing.
 */
function readRolePolicy(
  realmId: string,
  roleId: string,
): { exists: boolean; policy: string; policySig: string; threshold: number | null } {
  const out = psql(
    `SELECT COUNT(*) || E'\\x1F'
            || COALESCE(MAX(policy),'') || E'\\x1F'
            || COALESCE(MAX(policy_sig),'') || E'\\x1F'
            || COALESCE(MAX(threshold)::text,'')
       FROM iga_role_policy
      WHERE realm_id='${sqlLit(realmId)}' AND role_id='${sqlLit(roleId)}'`,
  );
  const [count, policy, policySig, threshold] = out.split('\x1F');
  const exists = !!count && count !== '0';
  return {
    exists,
    policy: policy ?? '',
    policySig: policySig ?? '',
    threshold: threshold ? parseInt(threshold, 10) : null,
  };
}

/** Count committed (attestation NOT NULL) grants of a role across the realm. */
function committedGrantCount(roleId: string): number {
  const out = psql(
    `SELECT COUNT(*) FROM user_role_mapping
      WHERE role_id='${sqlLit(roleId)}' AND attestation IS NOT NULL`,
  );
  return parseInt(out || '0', 10);
}

/** Provision a realm-level tide-vendor-key component with non-blank gVRK + vvkId. */
async function createVendorKeyComponent(
  request: APIRequestContext,
  realm: string,
): Promise<void> {
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
      parentId: realm,
      config: {
        priority: ['100'],
        enabled: ['true'],
        active: ['true'],
        gVRK: [PLACEHOLDER_GVRK],
        gVRKCertificate: [PLACEHOLDER_GVRK_CERT],
        vvkId: [PLACEHOLDER_VVK_ID],
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
 * Ensure the realm-management `tide-realm-admin` client role exists; return its
 * rep {id,name,uuid}. (A vanilla scratch realm's realm-management client does not
 * ship this role.) MUST be called BEFORE enableIga so the create is a plain 201.
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

/** POST a client-role mapping (captured as a GRANT_ROLES CR under IGA). */
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

/** Create a governed user and commit it (CREATE_USER), returning its UUID. */
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

/** Find the PENDING GRANT/REVOKE_ROLES CR carrying (userId, roleId). */
async function findRoleCr(
  request: APIRequestContext,
  realm: string,
  action: 'GRANT_ROLES' | 'REVOKE_ROLES',
  userId: string,
  roleId: string,
): Promise<any> {
  const cr = await findChangeRequest(
    request,
    realm,
    action,
    (c) =>
      Array.isArray((c as any).rows) &&
      (c as any).rows.some(
        (x: any) => x.ROLE_ID === roleId && (x.USER_ID === userId || x.USER === userId),
      ),
  );
  expect(cr, `PENDING ${action} CR for user ${userId} role ${roleId}`).toBeTruthy();
  return cr;
}

/** Grant a client role to a user and commit AS THE MASTER (single signature). */
async function grantClientRoleAsMaster(
  request: APIRequestContext,
  realm: string,
  userId: string,
  clientUuidVal: string,
  role: { id: string; name: string },
): Promise<void> {
  const assign = await assignClientRoleMapping(request, realm, userId, clientUuidVal, [role]);
  expect(
    assign.status() < 300,
    `client role-mapping POST expected 2xx (deferred), got ${assign.status()}`,
  ).toBeTruthy();
  const cr = await findRoleCr(request, realm, 'GRANT_ROLES', userId, role.id);
  const ac = await authorizeAndCommit(request, realm, cr.id);
  expect(ac.commit.http, `GRANT_ROLES(${role.name}) commit ${JSON.stringify(ac.commit.body)}`).toBe(200);
}

test.describe('IGA Phase 14: threshold-change admin-policy regeneration (wave 1b)', () => {
  test.afterAll(async ({ request }) => {
    await deleteRealm(request, REALM_14).catch(() => {});
  });

  test('phase14: policy regenerates + re-signs on add (skip when unchanged) and on revoke (lower threshold)', async ({
    request,
  }) => {
    // ----- bases (IGA OFF) -----
    await createScratchRealm(request, REALM_14);
    const realmId = await realmUuid(request, REALM_14);

    // realm-management:tide-realm-admin (plain 201 pre-IGA); id stable across toggle.
    const tideAdmin = await ensureTideRealmAdminRole(request, REALM_14);

    // A SECOND manage-realm approver (besides the suite's master), created pre-IGA
    // with a usable password, so the 2-signature revoke in 14b can reach threshold 2.
    await createAdminWithRoles(request, REALM_14, 'p14-approverA', 'pw-approverA-14', []);

    await createVendorKeyComponent(request, REALM_14);
    await setRealmIgaAttr(request, REALM_14, 'iga.attestor', 'tide');
    await enableIga(request, REALM_14);
    expect((await igaStatus(request, REALM_14)).enabled, 'IGA enabled (14 realm)').toBe(true);

    // approverA's bearer token (also self-heals its post-toggle ADOPT_USER, and is
    // the first Tide-mode record() → lazily seeds the firstAdmin authorizer row).
    const approverAToken = await userTokenFor(request, REALM_14, 'p14-approverA', 'pw-approverA-14');
    expect(approverAToken, 'approverA token').toBeTruthy();

    // ---------------------------------------------------------------------
    // Transition: grant tide-realm-admin to admin1 (the FIRST grant) — this is
    // the firstAdmin bootstrap, NOT a wave-1b regen. It flips mode -> multiAdmin.
    // ---------------------------------------------------------------------
    const admin1 = await createGovernedUserCommitted(request, REALM_14, {
      username: 'p14-admin1',
      enabled: true,
      email: 'p14-admin1@example.test',
    });
    expect(readAuthorizerMode(realmId), 'mode firstAdmin before tide-realm-admin grant').toBe(
      'firstAdmin',
    );
    await grantClientRoleAsMaster(request, REALM_14, admin1, tideAdmin.uuid, {
      id: tideAdmin.id,
      name: tideAdmin.name,
    });
    expect(
      readAuthorizerMode(realmId),
      'mode flipped firstAdmin -> multiAdmin on the transition grant',
    ).toBe('multiAdmin');
    expect(committedGrantCount(tideAdmin.id), 'N=1 committed tide-realm-admin after transition').toBe(1);

    // ---------------------------------------------------------------------
    // Seed the admin policy artifact (threshold 1) the regen keeps in sync.
    // phase13 never created one; wave 1b needs a row to regenerate. We upsert it
    // via POST /iga/role-policies encoding threshold 1 (= floor(0.7*1)). policySig
    // is seeded with the VRK prefix so the "prefix preserved" assertion is honest.
    // ---------------------------------------------------------------------
    const seededBody = JSON.stringify({
      type: 'GenericResourceAccessThresholdRole:1',
      vvkId: PLACEHOLDER_VVK_ID,
      approvalType: 'EXPLICIT',
      executionType: 'PUBLIC',
      threshold: 1,
      role: TIDE_REALM_ADMIN_ROLE,
      resource: REALM_MANAGEMENT,
    });
    const seededSig = `${FIRSTADMIN_PREFIX}seed-threshold-1`;
    const upsert = await kcFetch(request, `/admin/realms/${REALM_14}/iga/role-policies`, {
      method: 'POST',
      json: {
        roleId: tideAdmin.id,
        policy: seededBody,
        policySig: seededSig,
        approvalType: 'EXPLICIT',
        executionType: 'PUBLIC',
        threshold: 1,
      },
    });
    expect(
      upsert.status(),
      `seed role-policy upsert expected 200, got ${upsert.status()}: ${await upsert.text()}`,
    ).toBe(200);

    const seeded = readRolePolicy(realmId, tideAdmin.id);
    expect(seeded.exists, 'seeded tide-realm-admin policy row exists').toBeTruthy();
    expect(seeded.threshold, 'seeded policy encodes threshold 1').toBe(1);
    expect(seeded.policySig, 'seeded policySig is the value we posted').toBe(seededSig);

    // ---------------------------------------------------------------------
    // 14a — ADD admin2 (N 1->2): floor(0.7*2)=1 == current 1 -> IsEqualTo SKIP.
    // The grant's OWN commit gate is at pre-grant N=1 -> threshold 1, so one
    // (master) signature commits it. Assert the policy is UNTOUCHED (no churn).
    // ---------------------------------------------------------------------
    const admin2 = await createGovernedUserCommitted(request, REALM_14, {
      username: 'p14-admin2',
      enabled: true,
      email: 'p14-admin2@example.test',
    });
    await grantClientRoleAsMaster(request, REALM_14, admin2, tideAdmin.uuid, {
      id: tideAdmin.id,
      name: tideAdmin.name,
    });
    expect(committedGrantCount(tideAdmin.id), 'N=2 committed after admin2 grant').toBe(2);

    const afterAdmin2 = readRolePolicy(realmId, tideAdmin.id);
    expect(
      afterAdmin2.threshold,
      'NO-CHURN: floor(0.7*2)=1 == seeded 1, so the policy threshold stays 1 (IsEqualTo skip)',
    ).toBe(1);
    expect(
      afterAdmin2.policySig,
      `NO-CHURN: policy_sig must be UNCHANGED when the threshold did not move ` +
        `(got '${afterAdmin2.policySig}', expected seeded '${seededSig}')`,
    ).toBe(seededSig);

    // ---------------------------------------------------------------------
    // 14a (cont.) — ADD admin3 (N 2->3): floor(0.7*3)=2 != 1 -> REGEN.
    // The grant's OWN commit gate is at pre-grant N=2 -> threshold 1, so one
    // (master) signature still commits it. Assert REGEN: sig CHANGED + thr 1->2.
    // ---------------------------------------------------------------------
    const admin3 = await createGovernedUserCommitted(request, REALM_14, {
      username: 'p14-admin3',
      enabled: true,
      email: 'p14-admin3@example.test',
    });
    await grantClientRoleAsMaster(request, REALM_14, admin3, tideAdmin.uuid, {
      id: tideAdmin.id,
      name: tideAdmin.name,
    });
    expect(committedGrantCount(tideAdmin.id), 'N=3 committed after admin3 grant').toBe(3);

    const afterAdmin3 = readRolePolicy(realmId, tideAdmin.id);
    // ASSERT A1 — encoded threshold moved 1 -> 2 (= floor(0.7*3)).
    expect(
      afterAdmin3.threshold,
      `REGEN: adding the 3rd admin moves floor(0.7*3)=2; policy threshold must be 2 (got ${afterAdmin3.threshold})`,
    ).toBe(2);
    // ASSERT A2 — policy_sig CHANGED (the artifact was re-signed).
    expect(
      afterAdmin3.policySig === seededSig,
      `REGEN: policy_sig must CHANGE on a threshold move ` +
        `(seeded='${seededSig}', after-add='${afterAdmin3.policySig}')`,
    ).toBeFalsy();
    // ASSERT A3 — the regenerated body encodes the new threshold + the role/resource scope.
    expect(
      afterAdmin3.policy.includes('"threshold":2'),
      `REGEN body must encode "threshold":2 (got '${afterAdmin3.policy}')`,
    ).toBeTruthy();
    expect(
      afterAdmin3.policy.includes(`"role":"${TIDE_REALM_ADMIN_ROLE}"`),
      `REGEN body must scope role tide-realm-admin (got '${afterAdmin3.policy}')`,
    ).toBeTruthy();
    expect(
      afterAdmin3.policy.includes(`"resource":"${REALM_MANAGEMENT}"`),
      `REGEN body must scope resource realm-management (got '${afterAdmin3.policy}')`,
    ).toBeTruthy();
    // ASSERT C (add side) — VRK prefix, never the multiAdmin enclave prefix.
    expect(
      afterAdmin3.policySig.startsWith(FIRSTADMIN_PREFIX),
      `REGEN policy_sig must carry the VRK ${FIRSTADMIN_PREFIX} prefix (got '${afterAdmin3.policySig}')`,
    ).toBeTruthy();
    expect(
      afterAdmin3.policySig.startsWith(DUMMY_PREFIX),
      `REGEN policy_sig must NOT carry the multiAdmin ${DUMMY_PREFIX} enclave prefix (got '${afterAdmin3.policySig}')`,
    ).toBeFalsy();

    console.log(
      `\n[phase14a] realm=${realmId} mode=multiAdmin ` +
        `add admin2 (N=2): NO-CHURN sig unchanged thr=1; ` +
        `add admin3 (N=3): REGEN thr 1->2 sig '${afterAdmin3.policySig.slice(0, FIRSTADMIN_PREFIX.length + 8)}...'\n`,
    );

    // ---------------------------------------------------------------------
    // 14b — REVOKE admin3 (N 3->2): floor(0.7*2)=1 != 2 -> REGEN (lower).
    // The revoke CR's OWN commit gate is at pre-revoke N=3 -> threshold 2, so it
    // needs TWO signatures: master (via authorizeAndCommit would only give one),
    // so we authorize as master AND as approverA, then commit.
    // ---------------------------------------------------------------------
    const sigBeforeRevoke = afterAdmin3.policySig;
    const unassign = await kcFetch(
      request,
      `/admin/realms/${REALM_14}/users/${admin3}/role-mappings/clients/${tideAdmin.uuid}`,
      { method: 'DELETE', json: [{ id: tideAdmin.id, name: tideAdmin.name }] },
    );
    expect(
      unassign.status() < 300,
      `revoke tide-realm-admin DELETE expected 2xx (deferred), got ${unassign.status()}`,
    ).toBeTruthy();
    const revokeCr = await findRoleCr(request, REALM_14, 'REVOKE_ROLES', admin3, tideAdmin.id);

    // Signature 1: master (default request context).
    const masterAuth = await kcFetch(
      request,
      `/admin/realms/${REALM_14}/iga/change-requests/${revokeCr.id}/authorize`,
      { method: 'POST', json: {} },
    );
    expect(masterAuth.status(), `revoke authorize #1 (master) ${await masterAuth.text()}`).toBe(200);
    // Signature 2: approverA (distinct user → distinct signature; threshold 2 met).
    const aAuth = await authorizeAs(request, REALM_14, revokeCr.id, approverAToken);
    expect(aAuth.http, `revoke authorize #2 (approverA) ${JSON.stringify(aAuth.body)}`).toBe(200);

    const revokeCommit = await commitAs(request, REALM_14, revokeCr.id, approverAToken);
    expect(
      revokeCommit.http,
      `revoke commit (2 sigs vs threshold 2) must be 200 ${JSON.stringify(revokeCommit.body)}`,
    ).toBe(200);
    expect(committedGrantCount(tideAdmin.id), 'N=2 committed after admin3 revoke').toBe(2);

    const afterRevoke = readRolePolicy(realmId, tideAdmin.id);
    // ASSERT B1 — encoded threshold dropped 2 -> 1 (= floor(0.7*2)).
    expect(
      afterRevoke.threshold,
      `REGEN-ON-REVOKE: revoking the 3rd admin moves floor(0.7*2)=1; policy threshold must be 1 (got ${afterRevoke.threshold})`,
    ).toBe(1);
    // ASSERT B2 — policy_sig CHANGED AGAIN (re-signed at the lower threshold).
    expect(
      afterRevoke.policySig === sigBeforeRevoke,
      `REGEN-ON-REVOKE: policy_sig must CHANGE again on the lower threshold ` +
        `(before-revoke='${sigBeforeRevoke}', after-revoke='${afterRevoke.policySig}')`,
    ).toBeFalsy();
    expect(
      afterRevoke.policy.includes('"threshold":1'),
      `REGEN-ON-REVOKE body must encode "threshold":1 (got '${afterRevoke.policy}')`,
    ).toBeTruthy();
    // ASSERT C (revoke side) — VRK prefix preserved.
    expect(
      afterRevoke.policySig.startsWith(FIRSTADMIN_PREFIX),
      `REGEN-ON-REVOKE policy_sig must carry the VRK ${FIRSTADMIN_PREFIX} prefix (got '${afterRevoke.policySig}')`,
    ).toBeTruthy();

    console.log(
      `\n[phase14b] realm=${realmId} revoke admin3 (N 3->2): REGEN thr 2->1 ` +
        `sig changed '${sigBeforeRevoke.slice(0, 24)}...' -> '${afterRevoke.policySig.slice(0, 24)}...' (RERUN: ${RERUN})\n`,
    );
  });
});
