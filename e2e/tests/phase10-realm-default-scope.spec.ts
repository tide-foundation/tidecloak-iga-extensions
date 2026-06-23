import { test, expect, APIRequestContext, APIResponse } from '@playwright/test';
import { execSync } from 'child_process';
import {
  createScratchRealm,
  deleteRealm,
  enableIga,
  igaStatus,
  createClientScope,
  getClientScopeByName,
  findChangeRequest,
  authorizeAndCommit,
  listChangeRequests,
  safeJson,
  kcFetch,
} from '../lib/kc';

/**
 * Phase 10 — REALM DEFAULT client-scope attestation (commit 3).
 *
 * DEFAULT_CLIENT_SCOPE rows are the realm-level default-default / default-
 * optional client-scope templates every new client inherits — a token-shaping
 * input. They now carry an ATTESTATION column (iga-changelog-2.3.0) and are
 * brought under the current-attested-state model:
 *
 *  PART A (live capture): an admin who sets a CUSTOM scope as a realm
 *  default-default scope on an IGA realm produces a REALM_DEFAULT_SCOPE_ADD CR.
 *  Like the other IgaRealmAdapter capture paths (SET_REALM_ATTRIBUTE /
 *  ADD_REALM_DEFAULT_GROUP), the adapter does NOT throw
 *  IgaPendingApprovalException — only the create-* provider paths do — so the
 *  HTTP response is KC's normal 204 and the CR is discovered via
 *  findChangeRequest. Commit applies realm.addDefaultClientScope + stamps
 *  DEFAULT_CLIENT_SCOPE.attestation non-null (verified inline via psql).
 *
 *  PART B (toggle-on ADOPT + skip built-ins): an admin who set a CUSTOM scope
 *  as a realm default scope BEFORE enabling IGA gets an
 *  ADOPT_DEFAULT_CLIENT_SCOPE CR on toggle-on for that custom row; bulk-
 *  authorize stamps it. The stock built-in default-scope rows (profile, email,
 *  roles, ...) get NO ADOPT CR and stay UNATTESTED (skip-built-ins invariant),
 *  classified by their owning SCOPE node.
 *
 * API E2E (no browser). DEFAULT_CLIENT_SCOPE.attestation verified inline via
 * `docker exec postgresP psql`.
 *
 * Precondition gate: a governed realm default-scope add (204) MUST produce a
 * PENDING REALM_DEFAULT_SCOPE_ADD CR. Missing => the commit-3 jar is not loaded
 * in the running container; the test STOPS with an unambiguous PRECONDITION
 * message.
 */

const A_REALM = 'iga-phase10-a';
const B_REALM = 'iga-phase10-b';
const PROBE_REALM = 'iga-phase10-precond-probe';

const RERUN =
  'cd /home/sasha/project/tidecloak-iga-extensions/e2e && npx playwright test phase10';

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
 * count||attestation for a DEFAULT_CLIENT_SCOPE row keyed (realm_id, scope_id).
 * Returns 'MISSING' if no row exists.
 */
function readDefaultScopeAttestation(realmId: string, scopeId: string): string {
  const out = psql(
    `SELECT COUNT(*) || E'\\x1F' || COALESCE(MAX(attestation),'')
       FROM default_client_scope
      WHERE realm_id='${sqlLit(realmId)}' AND scope_id='${sqlLit(scopeId)}'`,
  );
  const [count, att] = out.split('\x1F');
  if (!count || count === '0') return 'MISSING';
  return att ?? '';
}

/** All default_client_scope rows for a realm: {scopeId, att}. */
function defaultScopeRowsForRealm(realmId: string): Array<{ scopeId: string; att: string }> {
  const out = psql(
    `SELECT scope_id || E'\\x1F' || COALESCE(attestation,'')
       FROM default_client_scope WHERE realm_id='${sqlLit(realmId)}'`,
  );
  if (!out) return [];
  return out
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const [scopeId, att] = l.split('\x1F');
      return { scopeId, att: att ?? '' };
    });
}

/** Resolve a realm's UUID (default_client_scope.realm_id is the realm UUID). */
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

/** PUT a default-default-client-scope assignment on the realm. */
function addRealmDefaultDefaultScope(
  request: APIRequestContext,
  realm: string,
  scopeId: string,
): Promise<APIResponse> {
  return kcFetch(
    request,
    `/admin/realms/${realm}/default-default-client-scopes/${scopeId}`,
    { method: 'PUT' },
  );
}

test.describe('IGA Phase 10: realm default client-scope attestation', () => {
  test.afterAll(async ({ request }) => {
    await deleteRealm(request, A_REALM).catch(() => {});
    await deleteRealm(request, B_REALM).catch(() => {});
    await deleteRealm(request, PROBE_REALM).catch(() => {});
  });

  // -------------------------------------------------------------------------
  // PART A — live capture: governed REALM_DEFAULT_SCOPE_ADD stamps attestation.
  // -------------------------------------------------------------------------
  test('partA: governed realm default-scope add → CR → commit stamps attestation', async ({
    request,
  }) => {
    // PRECONDITION: a custom scope set as a realm default on an IGA realm must
    // produce a PENDING REALM_DEFAULT_SCOPE_ADD CR (commit-3 jar loaded). The
    // adapter capture path returns KC's normal 204 (no IgaPendingApproval
    // throw); the CR is discovered via findChangeRequest.
    const pre = await (async () => {
      const evidence: Record<string, unknown> = {};
      try {
        await createScratchRealm(request, PROBE_REALM);
        // create a custom scope while IGA is OFF (so it exists, ungoverned)
        const sc = await createClientScope(request, PROBE_REALM, {
          name: 'p10-probe-scope',
          protocol: 'openid-connect',
        });
        evidence.scopeCreatePreIga = sc.status();
        await enableIga(request, PROBE_REALM);
        const scope = await getClientScopeByName(request, PROBE_REALM, 'p10-probe-scope');
        const scopeId = scope.body?.id as string;
        evidence.scopeId = scopeId;
        const r = await addRealmDefaultDefaultScope(request, PROBE_REALM, scopeId);
        evidence.addStatus = r.status();
        if (r.status() !== 204) {
          return {
            ok: false as const,
            detail: `governed realm default-scope add expected 204, got ${r.status()}`,
            evidence,
          };
        }
        const cr = await findChangeRequest(
          request,
          PROBE_REALM,
          'REALM_DEFAULT_SCOPE_ADD',
          (c) => Array.isArray((c as any).rows) && (c as any).rows.some((x: any) => x.SCOPE_ID === scopeId),
        );
        evidence.crFound = !!cr;
        if (!cr) {
          return {
            ok: false as const,
            detail: 'no PENDING REALM_DEFAULT_SCOPE_ADD CR found after governed add',
            evidence,
          };
        }
        return { ok: true as const, detail: 'commit-3 jar loaded.', evidence };
      } catch (e: any) {
        return { ok: false as const, detail: `probe raised: ${e?.message ?? e}`, evidence };
      } finally {
        await deleteRealm(request, PROBE_REALM).catch(() => {});
      }
    })();
    console.log(
      `\n[PRECONDITION phase10/partA] ok=${pre.ok}\n  ${pre.detail}\n  evidence=${JSON.stringify(
        pre.evidence,
        null,
        2,
      )}\n`,
    );
    if (!pre.ok) {
      throw new Error(
        `PRECONDITION: commit-3 jar not loaded (${pre.detail}) — recreate the container, then re-run: ${RERUN}`,
      );
    }

    await createScratchRealm(request, A_REALM);
    // custom scope created pre-IGA so it exists ungoverned
    const scCreate = await createClientScope(request, A_REALM, {
      name: 'p10a-scope',
      protocol: 'openid-connect',
    });
    expect([201, 202].includes(scCreate.status()), `pre-IGA scope create ${scCreate.status()}`).toBeTruthy();
    await enableIga(request, A_REALM);
    const st = await igaStatus(request, A_REALM);
    expect(st.enabled, 'IGA enabled').toBe(true);

    const scope = await getClientScopeByName(request, A_REALM, 'p10a-scope');
    const scopeId = scope.body?.id as string;
    expect(scopeId, 'custom scope id resolvable').toBeTruthy();

    // Governed realm default-scope add → 204 (adapter capture, no throw); the
    // REALM_DEFAULT_SCOPE_ADD CR is discovered via findChangeRequest.
    const add = await addRealmDefaultDefaultScope(request, A_REALM, scopeId);
    expect(add.status(), 'governed realm default-scope add 204').toBe(204);
    const cr = await findChangeRequest(
      request,
      A_REALM,
      'REALM_DEFAULT_SCOPE_ADD',
      (c) => Array.isArray((c as any).rows) && (c as any).rows.some((x: any) => x.SCOPE_ID === scopeId),
    );
    expect(cr, 'PENDING REALM_DEFAULT_SCOPE_ADD CR found').toBeTruthy();
    const crId = (cr as any).id as string;
    expect(crId, 'CR id resolvable').toBeTruthy();

    // Before commit the DEFAULT_CLIENT_SCOPE row must NOT exist (deferred).
    const realmId = realmUuid(A_REALM);
    expect(realmId, 'realm uuid resolvable').toBeTruthy();
    const before = readDefaultScopeAttestation(realmId, scopeId);
    expect(before, 'default-scope row absent before commit (deferred capture)').toBe('MISSING');

    // Commit → row written + attestation stamped.
    const ac = await authorizeAndCommit(request, A_REALM, crId);
    expect(ac.commit.http, `commit ${JSON.stringify(ac.commit.body)}`).toBe(200);

    const after = readDefaultScopeAttestation(realmId, scopeId);
    expect(after !== 'MISSING', 'default-scope row present after commit').toBeTruthy();
    expect(
      after.length > 0,
      `DEFAULT_CLIENT_SCOPE.attestation must be non-null after commit, got '${after}'`,
    ).toBeTruthy();

    await deleteRealm(request, A_REALM);
  });

  // -------------------------------------------------------------------------
  // PART B — toggle-on ADOPT for a custom realm default-scope + skip built-ins.
  // -------------------------------------------------------------------------
  test('partB: toggle-on adopts custom realm default-scope, skips built-ins', async ({
    request,
  }) => {
    await createScratchRealm(request, B_REALM);

    // Pre-IGA: create a CUSTOM scope and set it as a realm default-default
    // scope (ungoverned, so it is adopted on toggle-on).
    const scCreate = await createClientScope(request, B_REALM, {
      name: 'p10b-scope',
      protocol: 'openid-connect',
    });
    expect(scCreate.status(), 'pre-IGA scope create 201').toBe(201);
    const customScope = await getClientScopeByName(request, B_REALM, 'p10b-scope');
    const customScopeId = customScope.body?.id as string;
    expect(customScopeId, 'custom scope id').toBeTruthy();

    const add = await addRealmDefaultDefaultScope(request, B_REALM, customScopeId);
    expect(
      [204, 200].includes(add.status()),
      `pre-IGA realm default-scope add status ${add.status()}`,
    ).toBeTruthy();

    const realmId = realmUuid(B_REALM);
    expect(realmId, 'realm uuid').toBeTruthy();

    // Snapshot the built-in default-scope rows (profile/email/roles/...) so we
    // can assert they are NEVER adopted / stamped.
    const builtinRowsBefore = defaultScopeRowsForRealm(realmId).filter(
      (r) => r.scopeId !== customScopeId,
    );
    expect(
      builtinRowsBefore.length,
      'realm must ship built-in default-scope rows',
    ).toBeGreaterThan(0);

    // -------------------------- TOGGLE ON -----------------------------------
    const t = await toggleIgaRaw(request, B_REALM);
    expect(t.http, `toggle expected 200, got ${t.http}`).toBe(200);
    expect(t.body?.enabled, 'IGA enabled after toggle').toBe(true);
    const scan = t.body.scan;
    expect(scan, 'scan block present on OFF→ON').toBeTruthy();

    // PRECONDITION (commit-3 field): the REALM_DEFAULT_SCOPE counter must exist.
    expect(
      scan.adoptCrsCreated && scan.adoptCrsCreated.REALM_DEFAULT_SCOPE !== undefined,
      `scan.adoptCrsCreated.REALM_DEFAULT_SCOPE missing — commit-3 jar not loaded; ` +
        `recreate then re-run: ${RERUN}. scan=${JSON.stringify(scan)}`,
    ).toBeTruthy();

    // The custom realm default-scope produced an ADOPT_DEFAULT_CLIENT_SCOPE CR.
    expect(
      scan.adoptCrsCreated?.REALM_DEFAULT_SCOPE,
      'REALM_DEFAULT_SCOPE adopt CRs (custom default-scope found)',
    ).toBeGreaterThanOrEqual(1);

    // skip-built-ins held: built-in edges skipped (non-zero), and NO
    // ADOPT_DEFAULT_CLIENT_SCOPE CR targets a built-in default-scope row.
    expect(scan.skipped?.systemEdges, 'systemEdges skip count > 0').toBeGreaterThan(0);
    const builtinScopeIds = new Set(builtinRowsBefore.map((r) => r.scopeId));
    const adoptDefaultScopeCrs = (await listChangeRequests(request, B_REALM)).filter(
      (cr) => cr.actionType === 'ADOPT_DEFAULT_CLIENT_SCOPE',
    );
    for (const cr of adoptDefaultScopeCrs) {
      const rows = Array.isArray((cr as any).rows) ? (cr as any).rows : [];
      for (const r of rows) {
        expect(
          builtinScopeIds.has(r.SCOPE_ID),
          `built-in default-scope ${r.SCOPE_ID} must NOT have an ADOPT_DEFAULT_CLIENT_SCOPE CR (skip-built-ins)`,
        ).toBeFalsy();
      }
    }

    // -------------------------- BULK AUTHORIZE ------------------------------
    const bulk = await bulkAuthorize(request, B_REALM, {
      actionTypeIn: ['ADOPT_DEFAULT_CLIENT_SCOPE'],
    });
    expect(
      bulk.http,
      `bulk-authorize 200, got ${bulk.http} body=${JSON.stringify(bulk.body)}`,
    ).toBe(200);

    // The custom realm default-scope row is now stamped.
    const customAtt = readDefaultScopeAttestation(realmId, customScopeId);
    expect(
      customAtt !== 'MISSING' && customAtt.length > 0,
      `custom realm default-scope stamped, got '${customAtt}'`,
    ).toBeTruthy();

    // skip-built-ins still holds: the built-in default-scope rows remain
    // UNATTESTED (never enumerated/adopted).
    const builtinRowsAfter = defaultScopeRowsForRealm(realmId).filter(
      (r) => r.scopeId !== customScopeId,
    );
    for (const r of builtinRowsAfter) {
      expect(
        r.att === '',
        `built-in default-scope ${r.scopeId} must stay unattested (skip-built-ins), got '${r.att}'`,
      ).toBeTruthy();
    }

    await deleteRealm(request, B_REALM);
    const gone = await igaStatus(request, B_REALM);
    expect(gone.http, 'scratch realm deleted (iga-status 404)').toBe(404);
  });
});
