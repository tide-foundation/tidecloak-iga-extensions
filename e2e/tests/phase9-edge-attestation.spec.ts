import { test, expect, APIRequestContext, APIResponse } from '@playwright/test';
import { execSync } from 'child_process';
import {
  createScratchRealm,
  deleteRealm,
  enableIga,
  igaStatus,
  createClient,
  clientUuid,
  createClientScope,
  getClientScopeByName,
  createRole,
  getRole,
  getChangeRequest,
  authorizeAndCommit,
  listChangeRequests,
  locationHeader,
  safeJson,
  kcFetch,
} from '../lib/kc';

/**
 * Phase 9 — EDGE attestation coverage.
 *
 * Proves two commits closed the attestation-coverage gaps for admin-configured
 * token-shaping EDGE inputs:
 *
 *  COMMIT 1 (stamp-only): a GOVERNED create that has nested rows now stamps the
 *  nested rows too, not just the root entity:
 *    - CREATE_CLIENT_SCOPE with a protocol mapper  → PROTOCOL_MAPPER.attestation non-null
 *    - CREATE_ROLE (composite)                     → COMPOSITE_ROLE.attestation non-null
 *    - CREATE_CLIENT with a protocol mapper        → PROTOCOL_MAPPER.attestation non-null
 *
 *  COMMIT 2 (toggle-on ADOPT edge coverage + skip built-ins): an admin who
 *  configured a composite role + a scope→client attach + a scope→role mapping +
 *  a custom scope-owned mapper BEFORE enabling IGA gets ADOPT_* CRs for those
 *  EDGES on toggle-on; bulk-authorize stamps the edge attestations. The stock
 *  built-in scopes/mappers/edges get NO ADOPT CR (skip-built-ins invariant) —
 *  asserted via the scan's skipped.systemEdges bucket plus a DB check that a
 *  built-in scope's own protocol-mapper row stays unattested (no ADOPT emitted
 *  for it).
 *
 * API E2E (no browser). Edge attestations are verified inline via
 * `docker exec postgresP psql`.
 *
 * Precondition gate: the toggle-on scan response MUST carry skipped.systemEdges
 * (a commit-2 field) AND a governed CREATE_CLIENT_SCOPE must 202. Either
 * missing => the phase9 jar is not loaded in the running container; the test
 * STOPS with an unambiguous PRECONDITION message (restart, then re-run).
 */

const C1_REALM = 'iga-phase9-c1';
const C2_REALM = 'iga-phase9-c2';
const PROBE_REALM = 'iga-phase9-precond-probe';

const RERUN =
  'cd /home/sasha/project/tidecloak-iga-extensions/e2e && npx playwright test phase9';

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

/** count||attestation for a PROTOCOL_MAPPER row by its id. */
function readMapperAttestation(mapperId: string): string {
  const out = psql(
    `SELECT COUNT(*) || E'\\x1F' || COALESCE(MAX(attestation),'')
       FROM protocol_mapper WHERE id='${sqlLit(mapperId)}'`,
  );
  const [count, att] = out.split('\x1F');
  if (!count || count === '0') return 'MISSING';
  return att ?? '';
}

/** count||attestation for a COMPOSITE_ROLE edge (composite, child_role). */
function readCompositeAttestation(parentId: string, childId: string): string {
  const out = psql(
    `SELECT COUNT(*) || E'\\x1F' || COALESCE(MAX(attestation),'')
       FROM composite_role
      WHERE composite='${sqlLit(parentId)}' AND child_role='${sqlLit(childId)}'`,
  );
  const [count, att] = out.split('\x1F');
  if (!count || count === '0') return 'MISSING';
  return att ?? '';
}

/** count||attestation for a CLIENT_SCOPE_CLIENT edge (client_id, scope_id). */
function readScopeClientAttestation(clientUuidVal: string, scopeId: string): string {
  const out = psql(
    `SELECT COUNT(*) || E'\\x1F' || COALESCE(MAX(attestation),'')
       FROM client_scope_client
      WHERE client_id='${sqlLit(clientUuidVal)}' AND scope_id='${sqlLit(scopeId)}'`,
  );
  const [count, att] = out.split('\x1F');
  if (!count || count === '0') return 'MISSING';
  return att ?? '';
}

/** count||attestation for a CLIENT_SCOPE_ROLE_MAPPING edge (scope_id, role_id). */
function readScopeRoleAttestation(scopeId: string, roleId: string): string {
  const out = psql(
    `SELECT COUNT(*) || E'\\x1F' || COALESCE(MAX(attestation),'')
       FROM client_scope_role_mapping
      WHERE scope_id='${sqlLit(scopeId)}' AND role_id='${sqlLit(roleId)}'`,
  );
  const [count, att] = out.split('\x1F');
  if (!count || count === '0') return 'MISSING';
  return att ?? '';
}

/** All protocol_mapper rows (id) owned by a client scope, with attestation. */
function mapperRowsForScope(scopeId: string): Array<{ id: string; att: string }> {
  const out = psql(
    `SELECT id || E'\\x1F' || COALESCE(attestation,'')
       FROM protocol_mapper WHERE client_scope_id='${sqlLit(scopeId)}'`,
  );
  if (!out) return [];
  return out
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const [id, att] = l.split('\x1F');
      return { id, att: att ?? '' };
    });
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

/** Resolve a CR id from a 202 (body.changeRequestId or Location tail). */
async function crIdFrom(res: APIResponse): Promise<string> {
  const body = await safeJson(res);
  const loc = locationHeader(res);
  return (body && body.changeRequestId) || (loc ? loc.split('/').pop() : '') || '';
}

const MAPPER_SPEC = {
  name: 'p9-mapper',
  protocol: 'openid-connect',
  protocolMapper: 'oidc-usermodel-attribute-mapper',
  config: {
    'user.attribute': 'p9attr',
    'claim.name': 'p9_claim',
    'jsonType.label': 'String',
    'access.token.claim': 'true',
    'id.token.claim': 'true',
  },
};

test.describe('IGA Phase 9: edge attestation coverage', () => {
  test.afterAll(async ({ request }) => {
    await deleteRealm(request, C1_REALM).catch(() => {});
    await deleteRealm(request, C2_REALM).catch(() => {});
    await deleteRealm(request, PROBE_REALM).catch(() => {});
  });

  // -------------------------------------------------------------------------
  // COMMIT 1 — governed create stamps NESTED rows.
  // -------------------------------------------------------------------------
  test('commit1: governed create stamps nested mappers + composite edges', async ({
    request,
  }) => {
    // PRECONDITION: governed CREATE_CLIENT_SCOPE must 202 (jar loaded).
    const pre = await (async () => {
      const evidence: Record<string, unknown> = {};
      try {
        await createScratchRealm(request, PROBE_REALM);
        await enableIga(request, PROBE_REALM);
        const r = await createClientScope(request, PROBE_REALM, {
          name: 'p9-probe-scope',
          protocol: 'openid-connect',
        });
        evidence.scopeCreateStatus = r.status();
        evidence.scopeCreateLocation = locationHeader(r) ?? null;
        if (r.status() !== 202 || !locationHeader(r)) {
          return {
            ok: false as const,
            detail: `governed CREATE_CLIENT_SCOPE expected 202+Location, got ${r.status()}`,
            evidence,
          };
        }
        const crId = await crIdFrom(r);
        const cr = await getChangeRequest(request, PROBE_REALM, crId);
        evidence.crActionType = cr.body?.actionType;
        if (cr.body?.actionType !== 'CREATE_CLIENT_SCOPE') {
          return {
            ok: false as const,
            detail: `CR actionType expected CREATE_CLIENT_SCOPE, got ${cr.body?.actionType}`,
            evidence,
          };
        }
        return { ok: true as const, detail: 'phase9 jar loaded.', evidence };
      } catch (e: any) {
        return { ok: false as const, detail: `probe raised: ${e?.message ?? e}`, evidence };
      } finally {
        await deleteRealm(request, PROBE_REALM).catch(() => {});
      }
    })();
    console.log(
      `\n[PRECONDITION phase9/commit1] ok=${pre.ok}\n  ${pre.detail}\n  evidence=${JSON.stringify(
        pre.evidence,
        null,
        2,
      )}\n`,
    );
    if (!pre.ok) {
      throw new Error(
        `PRECONDITION: phase9 jar not loaded (${pre.detail}) — restart the container, then re-run: ${RERUN}`,
      );
    }

    await createScratchRealm(request, C1_REALM);
    await enableIga(request, C1_REALM);
    const st = await igaStatus(request, C1_REALM);
    expect(st.enabled, 'IGA enabled').toBe(true);

    // --- A. CREATE_CLIENT_SCOPE WITH a protocol mapper ---------------------
    const scRes = await createClientScope(request, C1_REALM, {
      name: 'p9-scope-with-mapper',
      protocol: 'openid-connect',
      protocolMappers: [MAPPER_SPEC],
    });
    expect(scRes.status(), 'governed CREATE_CLIENT_SCOPE 202').toBe(202);
    const scCrId = await crIdFrom(scRes);
    const acSc = await authorizeAndCommit(request, C1_REALM, scCrId);
    expect(acSc.commit.http, `scope commit ${JSON.stringify(acSc.commit.body)}`).toBe(200);

    // The scope now exists; find its id and its mapper id from the DB.
    const scope = await getClientScopeByName(request, C1_REALM, 'p9-scope-with-mapper');
    const scopeId = scope.body?.id as string;
    expect(scopeId, 'scope id resolvable post-commit').toBeTruthy();

    const scopeMappers = mapperRowsForScope(scopeId);
    expect(scopeMappers.length, 'scope must have its nested mapper persisted').toBeGreaterThan(0);
    for (const m of scopeMappers) {
      expect(
        m.att.length > 0,
        `nested scope mapper ${m.id} attestation must be non-null (commit 1), got '${m.att}'`,
      ).toBeTruthy();
    }

    // --- B. CREATE_ROLE composite → COMPOSITE_ROLE edge stamped ------------
    // Create a child role pre-governance is not possible (IGA on), so create
    // both as governed roles, then create the parent as a composite of child.
    const childRes = await createRole(request, C1_REALM, { name: 'p9-child' });
    expect(childRes.status(), 'governed CREATE_ROLE child 202').toBe(202);
    const acChild = await authorizeAndCommit(request, C1_REALM, await crIdFrom(childRes));
    expect(acChild.commit.http, 'child role commit').toBe(200);

    const parentRes = await createRole(request, C1_REALM, {
      name: 'p9-parent',
      composite: true,
      composites: { realm: ['p9-child'] },
    });
    expect(parentRes.status(), 'governed CREATE_ROLE composite parent 202').toBe(202);
    const acParent = await authorizeAndCommit(request, C1_REALM, await crIdFrom(parentRes));
    expect(acParent.commit.http, `parent role commit ${JSON.stringify(acParent.commit.body)}`).toBe(
      200,
    );

    const parent = await getRole(request, C1_REALM, 'p9-parent');
    const child = await getRole(request, C1_REALM, 'p9-child');
    const parentId = parent.body?.id as string;
    const childId = child.body?.id as string;
    expect(parentId && childId, 'parent+child role ids resolvable').toBeTruthy();

    const compAtt = readCompositeAttestation(parentId, childId);
    expect(compAtt !== 'MISSING', 'composite edge row present after commit').toBeTruthy();
    expect(
      compAtt.length > 0,
      `COMPOSITE_ROLE edge attestation must be non-null (commit 1), got '${compAtt}'`,
    ).toBeTruthy();

    // --- C. CREATE_CLIENT with a protocol mapper → mapper stamped ----------
    const clientCreate = await kcFetch(request, `/admin/realms/${C1_REALM}/clients`, {
      method: 'POST',
      json: {
        clientId: 'p9-client-with-mapper',
        enabled: true,
        protocolMappers: [MAPPER_SPEC],
      },
    });
    expect(clientCreate.status(), 'governed CREATE_CLIENT 202').toBe(202);
    const acClient = await authorizeAndCommit(request, C1_REALM, await crIdFrom(clientCreate));
    expect(acClient.commit.http, `client commit ${JSON.stringify(acClient.commit.body)}`).toBe(200);

    const cUuid = await clientUuid(request, C1_REALM, 'p9-client-with-mapper');
    const clientMapperRows = psql(
      `SELECT id || E'\\x1F' || COALESCE(attestation,'')
         FROM protocol_mapper WHERE client_id='${sqlLit(cUuid)}'`,
    )
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l) => {
        const [id, att] = l.split('\x1F');
        return { id, att: att ?? '' };
      });
    expect(clientMapperRows.length, 'client must have its nested mapper persisted').toBeGreaterThan(
      0,
    );
    for (const m of clientMapperRows) {
      expect(
        m.att.length > 0,
        `nested client mapper ${m.id} attestation must be non-null (commit 1), got '${m.att}'`,
      ).toBeTruthy();
    }

    await deleteRealm(request, C1_REALM);
  });

  // -------------------------------------------------------------------------
  // COMMIT 2 — toggle-on ADOPT for admin-configured edges + skip built-ins.
  // -------------------------------------------------------------------------
  test('commit2: toggle-on adopts admin edges, skips built-in edges', async ({ request }) => {
    await createScratchRealm(request, C2_REALM);

    // Build admin edges BEFORE enabling IGA (so they are ungoverned, then
    // adopted on toggle-on):
    //   - a custom client SCOPE with a custom (scope-owned) protocol mapper
    //   - that scope attached to a custom CLIENT (CLIENT_SCOPE_CLIENT edge)
    //   - a custom realm ROLE mapped to that scope (CLIENT_SCOPE_ROLE edge)
    //   - a composite role (parent p9c2-parent → child p9c2-child)  (COMPOSITE_ROLE)
    const customClientUuid = await createClient(request, C2_REALM, 'p9c2-client');

    const scCreate = await createClientScope(request, C2_REALM, {
      name: 'p9c2-scope',
      protocol: 'openid-connect',
      protocolMappers: [MAPPER_SPEC],
    });
    expect(scCreate.status(), 'pre-IGA scope create 201').toBe(201);
    const customScope = await getClientScopeByName(request, C2_REALM, 'p9c2-scope');
    const customScopeId = customScope.body?.id as string;
    expect(customScopeId, 'custom scope id').toBeTruthy();

    // scope→client attach (default-client-scope) — CLIENT_SCOPE_CLIENT edge.
    const attach = await kcFetch(
      request,
      `/admin/realms/${C2_REALM}/clients/${customClientUuid}/default-client-scopes/${customScopeId}`,
      { method: 'PUT' },
    );
    expect([204, 200].includes(attach.status()), `pre-IGA attach status ${attach.status()}`).toBeTruthy();

    // realm role + scope→role mapping — CLIENT_SCOPE_ROLE edge.
    const roleCreate = await createRole(request, C2_REALM, { name: 'p9c2-scoperole' });
    expect(roleCreate.status(), 'pre-IGA role create 201').toBe(201);
    const scoperole = await getRole(request, C2_REALM, 'p9c2-scoperole');
    const scoperoleId = scoperole.body?.id as string;
    const scopeRoleMap = await kcFetch(
      request,
      `/admin/realms/${C2_REALM}/client-scopes/${customScopeId}/scope-mappings/realm`,
      { method: 'POST', json: [{ id: scoperoleId, name: 'p9c2-scoperole' }] },
    );
    expect(
      [204, 200].includes(scopeRoleMap.status()),
      `pre-IGA scope-role map status ${scopeRoleMap.status()}`,
    ).toBeTruthy();

    // composite role — COMPOSITE_ROLE edge.
    expect((await createRole(request, C2_REALM, { name: 'p9c2-child' })).status()).toBe(201);
    expect(
      (await createRole(request, C2_REALM, { name: 'p9c2-parent', composite: true })).status(),
    ).toBe(201);
    const childRole = await getRole(request, C2_REALM, 'p9c2-child');
    const parentRole = await getRole(request, C2_REALM, 'p9c2-parent');
    const childRoleId = childRole.body?.id as string;
    const parentRoleId = parentRole.body?.id as string;
    const addComposite = await kcFetch(
      request,
      `/admin/realms/${C2_REALM}/roles-by-id/${parentRoleId}/composites`,
      { method: 'POST', json: [{ id: childRoleId, name: 'p9c2-child' }] },
    );
    expect(
      [204, 200].includes(addComposite.status()),
      `pre-IGA composite add status ${addComposite.status()}`,
    ).toBeTruthy();

    // Capture a built-in scope's own mapper id (the 'profile' scope ships
    // stock mappers) to assert it is NOT adopted (skip-built-ins).
    const profileScope = await getClientScopeByName(request, C2_REALM, 'profile');
    const profileScopeId = profileScope.body?.id as string;
    expect(profileScopeId, 'built-in profile scope present pre-IGA').toBeTruthy();
    const builtinMappersBefore = mapperRowsForScope(profileScopeId);
    expect(
      builtinMappersBefore.length,
      'built-in profile scope must ship stock mappers',
    ).toBeGreaterThan(0);

    // -------------------------- TOGGLE ON -----------------------------------
    const t = await toggleIgaRaw(request, C2_REALM);
    expect(t.http, `toggle expected 200, got ${t.http}`).toBe(200);
    expect(t.body?.enabled, 'IGA enabled after toggle').toBe(true);
    expect(t.body?.scan, 'scan block present on OFF→ON').toBeTruthy();
    const scan = t.body.scan;

    // PRECONDITION (commit-2 field): skipped.systemEdges must exist.
    expect(
      scan.skipped && scan.skipped.systemEdges !== undefined,
      `scan.skipped.systemEdges missing — phase9/commit2 jar not loaded in the running ` +
        `container; restart then re-run: ${RERUN}. scan=${JSON.stringify(scan)}`,
    ).toBeTruthy();

    // The four admin edges each produced an ADOPT_* CR.
    expect(scan.adoptCrsCreated?.COMPOSITE_ROLE, 'COMPOSITE_ROLE adopt CRs').toBeGreaterThanOrEqual(
      1,
    );
    expect(
      scan.adoptCrsCreated?.CLIENT_SCOPE_CLIENT,
      'CLIENT_SCOPE_CLIENT adopt CRs',
    ).toBeGreaterThanOrEqual(1);
    expect(
      scan.adoptCrsCreated?.CLIENT_SCOPE_ROLE,
      'CLIENT_SCOPE_ROLE adopt CRs',
    ).toBeGreaterThanOrEqual(1);
    expect(
      scan.adoptCrsCreated?.PROTOCOL_MAPPER,
      'PROTOCOL_MAPPER adopt CRs (scope-owned custom mapper found)',
    ).toBeGreaterThanOrEqual(1);

    // skip-built-ins held: built-in edges were skipped (non-zero), and the
    // built-in profile scope's stock mappers got NO ADOPT CR.
    expect(scan.skipped.systemEdges, 'systemEdges skip count > 0').toBeGreaterThan(0);
    const builtinMapperIds = new Set(builtinMappersBefore.map((m) => m.id));
    const pendingAdoptMapper = (await listChangeRequests(request, C2_REALM)).filter(
      (cr) => cr.actionType === 'ADOPT_PROTOCOL_MAPPER',
    );
    for (const cr of pendingAdoptMapper) {
      const rows = Array.isArray((cr as any).rows) ? (cr as any).rows : [];
      for (const r of rows) {
        expect(
          builtinMapperIds.has(r.ID),
          `built-in mapper ${r.ID} must NOT have an ADOPT_PROTOCOL_MAPPER CR (skip-built-ins)`,
        ).toBeFalsy();
      }
    }

    // -------------------------- BULK AUTHORIZE ------------------------------
    const bulk = await bulkAuthorize(request, C2_REALM, {
      actionTypeIn: [
        'ADOPT_COMPOSITE_ROLE',
        'ADOPT_CLIENT_SCOPE_CLIENT',
        'ADOPT_CLIENT_SCOPE_ROLE',
        'ADOPT_PROTOCOL_MAPPER',
      ],
    });
    expect(bulk.http, `bulk-authorize 200, got ${bulk.http} body=${JSON.stringify(bulk.body)}`).toBe(
      200,
    );

    // The admin edge attestations are now stamped.
    const compAtt = readCompositeAttestation(parentRoleId, childRoleId);
    expect(compAtt !== 'MISSING' && compAtt.length > 0, `composite edge stamped, got '${compAtt}'`).toBeTruthy();

    const scAtt = readScopeClientAttestation(customClientUuid, customScopeId);
    expect(scAtt !== 'MISSING' && scAtt.length > 0, `scope→client edge stamped, got '${scAtt}'`).toBeTruthy();

    const srAtt = readScopeRoleAttestation(customScopeId, scoperoleId);
    expect(srAtt !== 'MISSING' && srAtt.length > 0, `scope→role edge stamped, got '${srAtt}'`).toBeTruthy();

    const customMappers = mapperRowsForScope(customScopeId);
    expect(customMappers.length, 'custom scope mapper present').toBeGreaterThan(0);
    for (const m of customMappers) {
      expect(m.att.length > 0, `custom scope mapper ${m.id} stamped, got '${m.att}'`).toBeTruthy();
    }

    // skip-built-ins still holds post-bulk: the built-in profile scope's stock
    // mappers remain UNATTESTED (they were never enumerated/adopted).
    const builtinMappersAfter = mapperRowsForScope(profileScopeId);
    for (const m of builtinMappersAfter) {
      expect(
        m.att === '',
        `built-in profile mapper ${m.id} must stay unattested (skip-built-ins), got '${m.att}'`,
      ).toBeTruthy();
    }

    await deleteRealm(request, C2_REALM);
    const gone = await igaStatus(request, C2_REALM);
    expect(gone.http, 'scratch realm deleted (iga-status 404)').toBe(404);
  });
});
