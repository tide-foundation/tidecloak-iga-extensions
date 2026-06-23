import { test, expect, APIRequestContext, APIResponse } from '@playwright/test';
import { execSync } from 'child_process';
import {
  createScratchRealm,
  deleteRealm,
  enableIga,
  igaStatus,
  createRole,
  getRole,
  createClient,
  clientUuid,
  findChangeRequest,
  authorizeAndCommit,
  listChangeRequests,
  safeJson,
  kcFetch,
} from '../lib/kc';

/**
 * Phase 11 — CLIENT scope-mapping attestation (commit 4).
 *
 * SCOPE_MAPPING rows are a CLIENT's scope->role allowlist (keyed
 * CLIENT_ID + ROLE_ID). When the client has fullScopeAllowed=false this
 * allowlist bounds which roles can land in its issued token — a token-shaping
 * input. They now carry an ATTESTATION column (iga-changelog-2.3.1) and are
 * brought under the current-attested-state model:
 *
 *  PART A (live capture): an admin who adds a realm role to a CUSTOM client's
 *  scope-mapping allowlist on an IGA realm produces a SCOPE_MAPPING_ADD CR. Like
 *  the other IgaClientAdapter capture paths (ADD_PROTOCOL_MAPPER /
 *  SET_CLIENT_ATTRIBUTE), the adapter does NOT throw IgaPendingApprovalException
 *  on the scope-mapping seam — so the HTTP response is KC's normal 204 and the
 *  CR is discovered via findChangeRequest. Commit applies
 *  client.addScopeMapping + stamps SCOPE_MAPPING.attestation non-null (verified
 *  inline via psql).
 *
 *  PART B (toggle-on ADOPT + skip built-ins): an admin who added a scope-mapping
 *  on a CUSTOM client BEFORE enabling IGA gets an ADOPT_SCOPE_MAPPING CR on
 *  toggle-on for that row; bulk-authorize stamps it. Built-in clients
 *  (realm-management/account/...) ship their own scope-mappings — those get NO
 *  ADOPT CR and stay UNATTESTED (skip-built-ins invariant), classified by their
 *  owning CLIENT node.
 *
 * API E2E (no browser). SCOPE_MAPPING.attestation verified inline via
 * `docker exec postgresP psql`.
 *
 * Precondition gate: a governed client scope-mapping add (204) MUST produce a
 * PENDING SCOPE_MAPPING_ADD CR. Missing => the commit-4 jar is not loaded in the
 * running container; the test STOPS with an unambiguous PRECONDITION message.
 */

const A_REALM = 'iga-phase11-a';
const B_REALM = 'iga-phase11-b';
const PROBE_REALM = 'iga-phase11-precond-probe';

const RERUN =
  'cd /home/sasha/project/tidecloak-iga-extensions/e2e && npx playwright test phase11';

const PG_CONTAINER = 'postgresP';
const PG_USER = 'tideadmin';
const PG_DB = 'dauthme';

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

/**
 * count||attestation for a SCOPE_MAPPING row keyed (client_id, role_id).
 * Returns 'MISSING' if no row exists.
 */
function readScopeMappingAttestation(clientUuidVal: string, roleId: string): string {
  const out = psql(
    `SELECT COUNT(*) || E'\\x1F' || COALESCE(MAX(attestation),'')
       FROM scope_mapping
      WHERE client_id='${sqlLit(clientUuidVal)}' AND role_id='${sqlLit(roleId)}'`,
  );
  const [count, att] = out.split('\x1F');
  if (!count || count === '0') return 'MISSING';
  return att ?? '';
}

/** All scope_mapping rows for a realm's clients: {clientId, roleId, att}. */
function scopeMappingRowsForRealm(realmId: string): Array<{
  clientId: string;
  roleId: string;
  att: string;
}> {
  const out = psql(
    `SELECT sm.client_id || E'\\x1F' || sm.role_id || E'\\x1F' || COALESCE(sm.attestation,'')
       FROM scope_mapping sm
       JOIN client c ON c.id = sm.client_id
      WHERE c.realm_id='${sqlLit(realmId)}'`,
  );
  if (!out) return [];
  return out
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const [clientId, roleId, att] = l.split('\x1F');
      return { clientId, roleId, att: att ?? '' };
    });
}

/** Resolve a realm's UUID. */
function realmUuid(realmName: string): string {
  return psql(`SELECT id FROM realm WHERE name='${sqlLit(realmName)}'`);
}

/** POST toggle-iga, return {http, body}. */
async function toggleIgaRaw(
  request: APIRequestContext,
  realm: string,
): Promise<{ http: number; body: any }> {
  const res = await kcFetch(request, `/admin/realms/${realm}/tide-admin/toggle-iga`, {
    method: 'POST',
  });
  return { http: res.status(), body: await safeJson(res) };
}

/** POST bulk-authorize, return {http, body}. */
async function bulkAuthorize(
  request: APIRequestContext,
  realm: string,
  body: Record<string, unknown>,
): Promise<{ http: number; body: any }> {
  const res = await kcFetch(
    request,
    `/admin/realms/${realm}/iga/change-requests/bulk-authorize`,
    { method: 'POST', json: body },
  );
  return { http: res.status(), body: await safeJson(res) };
}

/** POST a realm-role scope-mapping onto a client's allowlist. */
function addClientRealmScopeMapping(
  request: APIRequestContext,
  realm: string,
  clientUuidVal: string,
  role: { id: string; name: string },
): Promise<APIResponse> {
  return kcFetch(
    request,
    `/admin/realms/${realm}/clients/${clientUuidVal}/scope-mappings/realm`,
    { method: 'POST', json: [role] },
  );
}

test.describe('IGA Phase 11: client scope-mapping attestation', () => {
  test.afterAll(async ({ request }) => {
    await deleteRealm(request, A_REALM).catch(() => {});
    await deleteRealm(request, B_REALM).catch(() => {});
    await deleteRealm(request, PROBE_REALM).catch(() => {});
  });

  // -------------------------------------------------------------------------
  // PART A — live capture: governed SCOPE_MAPPING_ADD stamps attestation.
  // -------------------------------------------------------------------------
  test('partA: governed client scope-mapping add → CR → commit stamps attestation', async ({
    request,
  }) => {
    // PRECONDITION: a realm role added to a custom client's scope-mapping on an
    // IGA realm must produce a PENDING SCOPE_MAPPING_ADD CR (commit-4 jar
    // loaded). The adapter capture path returns KC's normal 204 (no
    // IgaPendingApproval throw); the CR is discovered via findChangeRequest.
    const pre = await (async () => {
      const evidence: Record<string, unknown> = {};
      try {
        await createScratchRealm(request, PROBE_REALM);
        // role + custom client created while IGA is OFF (so they exist, ungoverned)
        await createRole(request, PROBE_REALM, { name: 'p11-probe-role' });
        const probeClientUuid = await createClient(request, PROBE_REALM, 'p11-probe-client');
        evidence.clientUuid = probeClientUuid;
        await enableIga(request, PROBE_REALM);
        const role = await getRole(request, PROBE_REALM, 'p11-probe-role');
        const roleId = role.body?.id as string;
        evidence.roleId = roleId;
        const r = await addClientRealmScopeMapping(request, PROBE_REALM, probeClientUuid, {
          id: roleId,
          name: 'p11-probe-role',
        });
        evidence.addStatus = r.status();
        if (r.status() !== 204) {
          return {
            ok: false as const,
            detail: `governed client scope-mapping add expected 204, got ${r.status()}`,
            evidence,
          };
        }
        const cr = await findChangeRequest(
          request,
          PROBE_REALM,
          'SCOPE_MAPPING_ADD',
          (c) => Array.isArray((c as any).rows) && (c as any).rows.some((x: any) => x.ROLE_ID === roleId),
        );
        evidence.crFound = !!cr;
        if (!cr) {
          return {
            ok: false as const,
            detail: 'no PENDING SCOPE_MAPPING_ADD CR found after governed add',
            evidence,
          };
        }
        return { ok: true as const, detail: 'commit-4 jar loaded.', evidence };
      } catch (e: any) {
        return { ok: false as const, detail: `probe raised: ${e?.message ?? e}`, evidence };
      } finally {
        await deleteRealm(request, PROBE_REALM).catch(() => {});
      }
    })();
    console.log(
      `\n[PRECONDITION phase11/partA] ok=${pre.ok}\n  ${pre.detail}\n  evidence=${JSON.stringify(
        pre.evidence,
        null,
        2,
      )}\n`,
    );
    if (!pre.ok) {
      throw new Error(
        `PRECONDITION: commit-4 jar not loaded (${pre.detail}) — recreate the container, then re-run: ${RERUN}`,
      );
    }

    await createScratchRealm(request, A_REALM);
    // role + custom client created pre-IGA so they exist ungoverned
    const roleCreate = await createRole(request, A_REALM, { name: 'p11a-role' });
    expect([201, 202].includes(roleCreate.status()), `pre-IGA role create ${roleCreate.status()}`).toBeTruthy();
    const aClientUuid = await createClient(request, A_REALM, 'p11a-client');
    await enableIga(request, A_REALM);
    const st = await igaStatus(request, A_REALM);
    expect(st.enabled, 'IGA enabled').toBe(true);

    const role = await getRole(request, A_REALM, 'p11a-role');
    const roleId = role.body?.id as string;
    expect(roleId, 'role id resolvable').toBeTruthy();

    // Governed client scope-mapping add → 204 (adapter capture, no throw); the
    // SCOPE_MAPPING_ADD CR is discovered via findChangeRequest.
    const add = await addClientRealmScopeMapping(request, A_REALM, aClientUuid, {
      id: roleId,
      name: 'p11a-role',
    });
    expect(add.status(), 'governed client scope-mapping add 204').toBe(204);
    const cr = await findChangeRequest(
      request,
      A_REALM,
      'SCOPE_MAPPING_ADD',
      (c) => Array.isArray((c as any).rows) && (c as any).rows.some((x: any) => x.ROLE_ID === roleId),
    );
    expect(cr, 'PENDING SCOPE_MAPPING_ADD CR found').toBeTruthy();
    const crId = (cr as any).id as string;
    expect(crId, 'CR id resolvable').toBeTruthy();

    // Before commit the SCOPE_MAPPING row must NOT exist (deferred capture).
    const before = readScopeMappingAttestation(aClientUuid, roleId);
    expect(before, 'scope-mapping row absent before commit (deferred capture)').toBe('MISSING');

    // Commit → row written + attestation stamped.
    const ac = await authorizeAndCommit(request, A_REALM, crId);
    expect(ac.commit.http, `commit ${JSON.stringify(ac.commit.body)}`).toBe(200);

    const after = readScopeMappingAttestation(aClientUuid, roleId);
    expect(after !== 'MISSING', 'scope-mapping row present after commit').toBeTruthy();
    expect(
      after.length > 0,
      `SCOPE_MAPPING.attestation must be non-null after commit, got '${after}'`,
    ).toBeTruthy();

    await deleteRealm(request, A_REALM);
  });

  // -------------------------------------------------------------------------
  // PART B — toggle-on ADOPT for a custom client scope-mapping + skip built-ins.
  // -------------------------------------------------------------------------
  test('partB: toggle-on adopts custom client scope-mapping, skips built-ins', async ({
    request,
  }) => {
    await createScratchRealm(request, B_REALM);

    // Pre-IGA: create a realm role + CUSTOM client and add the role to the
    // client's scope-mapping allowlist (ungoverned, so it is adopted on
    // toggle-on).
    const roleCreate = await createRole(request, B_REALM, { name: 'p11b-role' });
    expect(roleCreate.status(), 'pre-IGA role create 201').toBe(201);
    const bClientUuid = await createClient(request, B_REALM, 'p11b-client');
    const role = await getRole(request, B_REALM, 'p11b-role');
    const customRoleId = role.body?.id as string;
    expect(customRoleId, 'custom role id').toBeTruthy();

    const add = await addClientRealmScopeMapping(request, B_REALM, bClientUuid, {
      id: customRoleId,
      name: 'p11b-role',
    });
    expect(
      [204, 200].includes(add.status()),
      `pre-IGA client scope-mapping add status ${add.status()}`,
    ).toBeTruthy();

    const realmId = realmUuid(B_REALM);
    expect(realmId, 'realm uuid').toBeTruthy();

    // The custom client scope-mapping row exists, unattested.
    const customBefore = readScopeMappingAttestation(bClientUuid, customRoleId);
    expect(customBefore, 'custom scope-mapping row exists pre-toggle').not.toBe('MISSING');
    expect(customBefore, 'custom scope-mapping row unattested pre-toggle').toBe('');

    // Snapshot built-in clients' scope-mapping rows (the realm ships some on
    // realm-management/account/...) so we can assert they are NEVER adopted.
    const builtinRowsBefore = scopeMappingRowsForRealm(realmId).filter(
      (r) => r.clientId !== bClientUuid,
    );

    // -------------------------- TOGGLE ON -----------------------------------
    const t = await toggleIgaRaw(request, B_REALM);
    expect(t.http, `toggle expected 200, got ${t.http}`).toBe(200);
    expect(t.body?.enabled, 'IGA enabled after toggle').toBe(true);
    const scan = t.body.scan;
    expect(scan, 'scan block present on OFF→ON').toBeTruthy();

    // PRECONDITION (commit-4 field): the SCOPE_MAPPING counter must exist.
    expect(
      scan.adoptCrsCreated && scan.adoptCrsCreated.SCOPE_MAPPING !== undefined,
      `scan.adoptCrsCreated.SCOPE_MAPPING missing — commit-4 jar not loaded; ` +
        `recreate then re-run: ${RERUN}. scan=${JSON.stringify(scan)}`,
    ).toBeTruthy();

    // The custom client scope-mapping produced an ADOPT_SCOPE_MAPPING CR.
    expect(
      scan.adoptCrsCreated?.SCOPE_MAPPING,
      'SCOPE_MAPPING adopt CRs (custom scope-mapping found)',
    ).toBeGreaterThanOrEqual(1);

    // skip-built-ins held: NO ADOPT_SCOPE_MAPPING CR targets a built-in client's
    // scope-mapping row. The CR row's CLIENT_UUID is the owning client's UUID.
    const builtinClientUuids = new Set(builtinRowsBefore.map((r) => r.clientId));
    const adoptScopeMappingCrs = (await listChangeRequests(request, B_REALM)).filter(
      (cr) => cr.actionType === 'ADOPT_SCOPE_MAPPING',
    );
    for (const cr of adoptScopeMappingCrs) {
      const rows = Array.isArray((cr as any).rows) ? (cr as any).rows : [];
      for (const r of rows) {
        expect(
          builtinClientUuids.has(r.CLIENT_UUID),
          `built-in client ${r.CLIENT_UUID} must NOT have an ADOPT_SCOPE_MAPPING CR (skip-built-ins)`,
        ).toBeFalsy();
      }
    }

    // -------------------------- BULK AUTHORIZE ------------------------------
    const bulk = await bulkAuthorize(request, B_REALM, {
      actionTypeIn: ['ADOPT_SCOPE_MAPPING'],
    });
    expect(
      bulk.http,
      `bulk-authorize 200, got ${bulk.http} body=${JSON.stringify(bulk.body)}`,
    ).toBe(200);

    // The custom client scope-mapping row is now stamped.
    const customAtt = readScopeMappingAttestation(bClientUuid, customRoleId);
    expect(
      customAtt !== 'MISSING' && customAtt.length > 0,
      `custom client scope-mapping stamped, got '${customAtt}'`,
    ).toBeTruthy();

    // skip-built-ins still holds: built-in clients' scope-mapping rows remain
    // UNATTESTED (never enumerated/adopted).
    const builtinRowsAfter = scopeMappingRowsForRealm(realmId).filter(
      (r) => r.clientId !== bClientUuid,
    );
    for (const r of builtinRowsAfter) {
      expect(
        r.att === '',
        `built-in client ${r.clientId} scope-mapping must stay unattested (skip-built-ins), got '${r.att}'`,
      ).toBeTruthy();
    }

    await deleteRealm(request, B_REALM);
    const gone = await igaStatus(request, B_REALM);
    expect(gone.http, 'scratch realm deleted (iga-status 404)').toBe(404);
  });
});
