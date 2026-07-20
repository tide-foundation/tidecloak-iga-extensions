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
  getChangeRequest,
  authorizeAndCommit,
  listChangeRequests,
  locationHeader,
  safeJson,
  kcFetch,
} from '../lib/kc';

/**
 * Phase 8 — client-scope ATTACH / DETACH capture at the provider layer.
 *
 * Root cause this proves fixed: attaching a client scope to a client used to
 * produce NO IGA change request — the CLIENT_SCOPE_CLIENT linkage row was
 * written with a NULL attestation and the attachment edge was ungoverned. The
 * capture seam was on the wrong layer (the dead IgaClientAdapter.addClientScope
 * override): with the infinispan cache ON, the admin PUT routes through
 * CacheClientAdapter → RealmCacheSession.addClientScopes →
 * IgaRealmProvider.addClientScopes, bypassing the ClientModel adapter. The fix
 * overrides addClientScopes(Set)/removeClientScope on IgaRealmProvider and
 * emits ASSIGN_SCOPE / REMOVE_SCOPE CRs there.
 *
 * This is an API E2E test (no browser). It exercises the production path
 * directly via Admin REST + verifies the persisted attestation inline through
 * `docker exec postgresP psql`.
 *
 * Asserted:
 *  - Governed attach (default-client-scopes PUT): 202 + Location (NOT a silent
 *    204), scope NOT attached at draft, authorize+commit → attached AND
 *    CLIENT_SCOPE_CLIENT.attestation non-null.
 *  - Optional-scope variant (optional-client-scopes PUT): same.
 *  - Batch: the REST route attaches one scope at a time, so the CR carries
 *    exactly ONE scope row (the addClientScopes(Set) batch is the model-path
 *    concern; the REST route can't drive a multi-scope call — noted below).
 *  - Create path NOT broken: creating a brand-new client on the IGA realm still
 *    works (its own CREATE_CLIENT CR), its default scopes attach on commit
 *    WITHOUT a spurious ASSIGN_SCOPE CR and without blocking creation.
 *  - Remove variant (DELETE default-client-scopes): REMOVE_SCOPE CR → commit →
 *    detached.
 *
 * Precondition gate (mirrors the other phase specs): a self-contained governed
 * attach probe (its own probe realm) must yield 202 + Location with an
 * ASSIGN_SCOPE CR. Anything else => the Phase 8 jar is not loaded in the
 * running container and the test STOPS with an unambiguous PRECONDITION
 * message (the user must restart the container then re-run).
 */

const REALM = 'iga-phase8-e2e';
const PROBE_REALM = 'iga-phase8-precond-probe';

const RERUN =
  'cd /home/sasha/project/tidecloak-iga-extensions/e2e && npx playwright test phase8';

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

/** SQL-escape a value for embedding in a single-quoted literal. */
function sqlLit(v: string): string {
  return v.replace(/'/g, "''");
}

/**
 * Read the attestation cell for a CLIENT_SCOPE_CLIENT(client_id, scope_id) row.
 * Returns the literal string 'MISSING' if no row exists, '' if the row exists
 * with a NULL/empty attestation, otherwise the attestation value.
 */
function readAttachAttestation(clientUuidVal: string, scopeId: string): string {
  const out = psql(
    `SELECT COUNT(*) || E'\\x1F' || COALESCE(MAX(attestation),'')
       FROM client_scope_client
      WHERE client_id='${sqlLit(clientUuidVal)}' AND scope_id='${sqlLit(scopeId)}'`,
  );
  const [count, attestation] = out.split('\x1F');
  if (!count || count === '0') return 'MISSING';
  return attestation ?? '';
}

/** Resolve a CR id from a 202 response (body.changeRequestId or Location tail). */
async function crIdFrom(res: APIResponse): Promise<string> {
  const body = await safeJson(res);
  const loc = locationHeader(res);
  return (body && body.changeRequestId) || (loc ? loc.split('/').pop() : '') || '';
}

/** Count PENDING CRs of a given actionType referencing a client UUID. */
async function countPending(
  request: APIRequestContext,
  realm: string,
  actionType: string,
  entityId?: string,
): Promise<number> {
  const list = await listChangeRequests(request, realm);
  return list.filter(
    (cr) =>
      cr.actionType === actionType &&
      (entityId === undefined || cr.entityId === entityId),
  ).length;
}

/** PUT .../{kind}-client-scopes/{scopeId}. Returns the raw response. */
function attachScope(
  request: APIRequestContext,
  realm: string,
  clientUuidVal: string,
  scopeId: string,
  kind: 'default' | 'optional',
): Promise<APIResponse> {
  return kcFetch(
    request,
    `/admin/realms/${realm}/clients/${clientUuidVal}/${kind}-client-scopes/${scopeId}`,
    { method: 'PUT' },
  );
}

/** DELETE .../{kind}-client-scopes/{scopeId}. Returns the raw response. */
function detachScope(
  request: APIRequestContext,
  realm: string,
  clientUuidVal: string,
  scopeId: string,
  kind: 'default' | 'optional',
): Promise<APIResponse> {
  return kcFetch(
    request,
    `/admin/realms/${realm}/clients/${clientUuidVal}/${kind}-client-scopes/${scopeId}`,
    { method: 'DELETE' },
  );
}

test.describe('IGA Phase 8: client-scope attach/detach governed capture', () => {
  test.afterAll(async ({ request }) => {
    await deleteRealm(request, REALM).catch(() => {});
    await deleteRealm(request, PROBE_REALM).catch(() => {});
  });

  test('Phase 8 governed attach/detach → ASSIGN_SCOPE/REMOVE_SCOPE CRs with attestation', async ({
    request,
  }) => {
    // -----------------------------------------------------------------------
    // PRECONDITION GATE — a governed attach must 202 + Location + ASSIGN_SCOPE
    // CR. (A silent 204 means the capture seam is not loaded → restart.)
    // -----------------------------------------------------------------------
    const pre = await (async () => {
      const evidence: Record<string, unknown> = {};
      try {
        await createScratchRealm(request, PROBE_REALM);
        // Create client + scope BEFORE enabling IGA so neither is governed —
        // we want to probe the ATTACH seam in isolation.
        const cUuid = await createClient(request, PROBE_REALM, 'probe-client');
        const scRes = await createClientScope(request, PROBE_REALM, {
          name: 'probe-attach-scope',
          protocol: 'openid-connect',
        });
        if (scRes.status() !== 201) {
          return {
            ok: false as const,
            loaded: false as const,
            detail: `probe scope create expected 201 (pre-IGA), got ${scRes.status()}`,
            evidence,
          };
        }
        const scope = await getClientScopeByName(
          request,
          PROBE_REALM,
          'probe-attach-scope',
        );
        const scopeId = scope.body?.id as string;
        evidence.probeScopeId = scopeId ?? null;

        await enableIga(request, PROBE_REALM);
        evidence.igaEnabled = true;

        const res = await attachScope(
          request,
          PROBE_REALM,
          cUuid,
          scopeId,
          'default',
        );
        const status = res.status();
        const loc = locationHeader(res);
        evidence.attachStatus = status;
        evidence.attachLocation = loc ?? null;

        if (status === 204 || status === 200) {
          // Attached silently with no CR → capture seam NOT intercepting →
          // genuinely not loaded → restart.
          return {
            ok: false as const,
            loaded: false as const,
            detail:
              `governed attach returned ${status} (scope attached with NO change ` +
              `request — the Phase 8 ASSIGN_SCOPE capture seam is NOT active).`,
            evidence,
          };
        }
        if (status !== 202) {
          const hint =
            status === 500
              ? 'governed attach returned 500 (provider jar likely not loaded — check server log for ClassNotFound on org.tidecloak.iga.*)'
              : `governed attach returned ${status} (expected 202 Accepted)`;
          return { ok: false as const, loaded: false as const, detail: hint, evidence };
        }
        if (!loc) {
          return {
            ok: false as const,
            loaded: false as const,
            detail:
              'governed attach returned 202 but no Location header — Phase 0 (Location on 202) not loaded.',
            evidence,
          };
        }
        const crId = await crIdFrom(res);
        const cr = await getChangeRequest(request, PROBE_REALM, crId);
        evidence.probeCrHttp = cr.http;
        evidence.probeCrActionType = cr.body?.actionType;
        if (cr.http !== 200 || cr.body?.actionType !== 'ASSIGN_SCOPE') {
          return {
            ok: false as const,
            loaded: false as const,
            detail:
              `202 returned but CR not retrievable as ASSIGN_SCOPE ` +
              `(GET CR http=${cr.http}, actionType=${cr.body?.actionType}).`,
            evidence,
          };
        }
        return {
          ok: true as const,
          loaded: true as const,
          detail: 'Phase 8 loaded.',
          evidence,
        };
      } catch (e: any) {
        return {
          ok: false as const,
          loaded: false as const,
          detail: `Probe governed attach raised: ${e?.message ?? e}`,
          evidence,
        };
      } finally {
        await deleteRealm(request, PROBE_REALM).catch(() => {});
      }
    })();

    console.log(
      `\n[PRECONDITION phase8] ok=${pre.ok} loaded=${
        (pre as { loaded?: boolean }).loaded
      }\n  ${pre.detail}\n  evidence=${JSON.stringify(pre.evidence, null, 2)}\n`,
    );
    if (!pre.ok) {
      throw new Error(
        `PRECONDITION: Phase 8 jar not loaded / capture not active in the ` +
          `running container (${pre.detail}) — restart the container, then ` +
          `re-run: ${RERUN}`,
      );
    }

    // -----------------------------------------------------------------------
    // Setup: scratch realm, a client + two scopes BEFORE enabling IGA (so the
    // client + scopes themselves are ungoverned and we isolate the attach
    // seam). Then enable IGA.
    // -----------------------------------------------------------------------
    await createScratchRealm(request, REALM);

    const existingClientUuid = await createClient(request, REALM, 'p8-client');

    for (const name of ['p8-scope-default', 'p8-scope-optional']) {
      const r = await createClientScope(request, REALM, {
        name,
        protocol: 'openid-connect',
      });
      expect(r.status(), `pre-IGA scope create ${name}`).toBe(201);
    }
    const scopeDefault = (
      await getClientScopeByName(request, REALM, 'p8-scope-default')
    ).body?.id as string;
    const scopeOptional = (
      await getClientScopeByName(request, REALM, 'p8-scope-optional')
    ).body?.id as string;
    expect(scopeDefault, 'default scope id').toBeTruthy();
    expect(scopeOptional, 'optional scope id').toBeTruthy();

    await enableIga(request, REALM);
    const st = await igaStatus(request, REALM);
    expect(st.http, 'iga-status http').toBe(200);
    expect(st.enabled, 'IGA must be enabled').toBe(true);

    // -----------------------------------------------------------------------
    // 1. GOVERNED ATTACH (default-client-scopes).
    // -----------------------------------------------------------------------
    const attach = await attachScope(
      request,
      REALM,
      existingClientUuid,
      scopeDefault,
      'default',
    );
    expect(
      attach.status(),
      `governed default attach expected 202, got ${attach.status()} ` +
        `(a 204 means the attach was silently persisted — capture missing)`,
    ).toBe(202);
    expect(
      locationHeader(attach),
      '202 attach must carry a Location header',
    ).toBeTruthy();
    const attachCrId = await crIdFrom(attach);
    expect(attachCrId, 'ASSIGN_SCOPE CR id resolvable').toBeTruthy();

    const attachCr = await getChangeRequest(request, REALM, attachCrId);
    expect(attachCr.http, 'GET ASSIGN_SCOPE CR').toBe(200);
    expect(attachCr.body?.actionType, 'CR actionType').toBe('ASSIGN_SCOPE');
    expect(attachCr.body?.status, 'CR status').toBe('PENDING');

    // BATCH assertion: the REST route attaches exactly one scope, so the CR
    // carries exactly ONE scope row. (Multi-scope batching is the
    // addClientScopes(Set) model-path concern — the REST route cannot drive a
    // multi-scope call, so we assert the 1-row CR here.)
    const attachRows = Array.isArray(attachCr.body?.rows) ? attachCr.body.rows : [];
    expect(
      attachRows.length,
      `ASSIGN_SCOPE CR must carry exactly 1 scope row (REST attaches one at a ` +
        `time); got ${JSON.stringify(attachRows)}`,
    ).toBe(1);
    expect(attachRows[0]?.SCOPE_ID, 'row SCOPE_ID').toBe(scopeDefault);
    expect(attachRows[0]?.CLIENT_UUID, 'row CLIENT_UUID').toBe(existingClientUuid);

    // NOT attached at draft time — zero CLIENT_SCOPE_CLIENT rows for this edge.
    expect(
      readAttachAttestation(existingClientUuid, scopeDefault),
      `scope must NOT be attached at draft time (no client_scope_client row)`,
    ).toBe('MISSING');

    // Authorize + commit → attached AND attestation non-null.
    const ac1 = await authorizeAndCommit(request, REALM, attachCrId);
    expect(ac1.authorize.http, 'attach authorize').toBe(200);
    expect(ac1.commit.http, `attach commit ${JSON.stringify(ac1.commit.body)}`).toBe(
      200,
    );

    const attDefault = readAttachAttestation(existingClientUuid, scopeDefault);
    expect(
      attDefault !== 'MISSING',
      `scope must be attached after commit (client_scope_client row present)`,
    ).toBeTruthy();
    expect(
      attDefault.length > 0,
      `attached default scope must have a non-null attestation, got '${attDefault}'`,
    ).toBeTruthy();

    // -----------------------------------------------------------------------
    // 2. OPTIONAL-SCOPE VARIANT.
    // -----------------------------------------------------------------------
    const attachOpt = await attachScope(
      request,
      REALM,
      existingClientUuid,
      scopeOptional,
      'optional',
    );
    expect(attachOpt.status(), 'governed optional attach expected 202').toBe(202);
    const attachOptCrId = await crIdFrom(attachOpt);
    const attachOptCr = await getChangeRequest(request, REALM, attachOptCrId);
    expect(attachOptCr.body?.actionType, 'optional CR actionType').toBe(
      'ASSIGN_SCOPE',
    );
    const optRows = Array.isArray(attachOptCr.body?.rows)
      ? attachOptCr.body.rows
      : [];
    expect(optRows.length, 'optional ASSIGN_SCOPE CR 1 row').toBe(1);
    expect(optRows[0]?.DEFAULT_SCOPE, 'optional row DEFAULT_SCOPE=false').toBe(
      false,
    );

    expect(
      readAttachAttestation(existingClientUuid, scopeOptional),
      'optional scope NOT attached at draft',
    ).toBe('MISSING');

    const ac2 = await authorizeAndCommit(request, REALM, attachOptCrId);
    expect(ac2.commit.http, 'optional attach commit').toBe(200);
    const attOpt = readAttachAttestation(existingClientUuid, scopeOptional);
    expect(attOpt !== 'MISSING', 'optional scope attached after commit').toBeTruthy();
    expect(
      attOpt.length > 0,
      `optional scope attestation must be non-null, got '${attOpt}'`,
    ).toBeTruthy();

    // -----------------------------------------------------------------------
    // 3. CREATE PATH NOT BROKEN — create a brand-new client on the IGA realm.
    //    Its default scopes auto-attach as part of creation (governed by the
    //    CREATE_CLIENT CR), with NO spurious ASSIGN_SCOPE CR and without
    //    blocking creation.
    // -----------------------------------------------------------------------
    const beforeAssignCount = await countPending(request, REALM, 'ASSIGN_SCOPE');

    const newClientCreate = await kcFetch(request, `/admin/realms/${REALM}/clients`, {
      method: 'POST',
      json: { clientId: 'p8-created-client', enabled: true },
    });
    expect(
      newClientCreate.status(),
      `client create on IGA realm expected 202 (CREATE_CLIENT CR), got ${newClientCreate.status()}`,
    ).toBe(202);
    const createCrId = await crIdFrom(newClientCreate);
    const createCr = await getChangeRequest(request, REALM, createCrId);
    expect(createCr.body?.actionType, 'create CR actionType').toBe('CREATE_CLIENT');

    // Creating the client must NOT have produced any standalone ASSIGN_SCOPE CR
    // (default scopes ride inside CREATE_CLIENT's REP_JSON).
    const afterCreateAssignCount = await countPending(
      request,
      REALM,
      'ASSIGN_SCOPE',
    );
    expect(
      afterCreateAssignCount,
      `client creation must NOT emit a standalone ASSIGN_SCOPE CR ` +
        `(default scopes are folded into CREATE_CLIENT); before=${beforeAssignCount} after=${afterCreateAssignCount}`,
    ).toBe(beforeAssignCount);

    // Commit the CREATE_CLIENT and confirm the client + its default scopes exist.
    const acCreate = await authorizeAndCommit(request, REALM, createCrId);
    expect(
      acCreate.commit.http,
      `CREATE_CLIENT commit ${JSON.stringify(acCreate.commit.body)}`,
    ).toBe(200);

    const newUuid = await clientUuid(request, REALM, 'p8-created-client');
    expect(newUuid, 'created client must exist after commit').toBeTruthy();

    const defScopeCount = psql(
      `SELECT COUNT(*) FROM client_scope_client WHERE client_id='${sqlLit(newUuid)}'`,
    );
    expect(
      Number(defScopeCount) > 0,
      `created client must have its default scopes attached (got ${defScopeCount} rows)`,
    ).toBeTruthy();

    // And still no stray ASSIGN_SCOPE CR for this client after commit.
    const strayForNew = await countPending(request, REALM, 'ASSIGN_SCOPE', newUuid);
    expect(
      strayForNew,
      `no stray ASSIGN_SCOPE CR for the freshly-created client (got ${strayForNew})`,
    ).toBe(0);

    // -----------------------------------------------------------------------
    // 4. REMOVE VARIANT — detach the default scope attached in step 1.
    // -----------------------------------------------------------------------
    const detach = await detachScope(
      request,
      REALM,
      existingClientUuid,
      scopeDefault,
      'default',
    );
    expect(
      detach.status(),
      `governed detach expected 202, got ${detach.status()} (204 = silent detach, capture missing)`,
    ).toBe(202);
    const detachCrId = await crIdFrom(detach);
    const detachCr = await getChangeRequest(request, REALM, detachCrId);
    expect(detachCr.body?.actionType, 'REMOVE_SCOPE CR actionType').toBe(
      'REMOVE_SCOPE',
    );

    // Still attached at draft time (detach deferred until commit).
    expect(
      readAttachAttestation(existingClientUuid, scopeDefault) !== 'MISSING',
      'scope still attached at REMOVE_SCOPE draft time',
    ).toBeTruthy();

    const ac3 = await authorizeAndCommit(request, REALM, detachCrId);
    expect(ac3.commit.http, `detach commit ${JSON.stringify(ac3.commit.body)}`).toBe(
      200,
    );

    expect(
      readAttachAttestation(existingClientUuid, scopeDefault),
      'scope must be detached after REMOVE_SCOPE commit (row gone)',
    ).toBe('MISSING');

    // -----------------------------------------------------------------------
    // 5. Cleanup.
    // -----------------------------------------------------------------------
    await deleteRealm(request, REALM);
    const gone = await igaStatus(request, REALM);
    expect(gone.http, 'scratch realm deleted (iga-status 404)').toBe(404);
  });
});
