import { test, expect, APIRequestContext } from '@playwright/test';
import {
  adminToken,
  createScratchRealm,
  deleteRealm,
  createUser,
  createRole,
  createGroup,
  getRole,
  getChangeRequest,
  listChangeRequests,
  safeJson,
  setRealmIgaAttr,
  kcFetch,
} from '../lib/kc';

/**
 * Phase 6e — POST /admin/realms/{realm}/iga/change-requests/bulk-authorize.
 *
 * Production path exercised:
 *   1. createScratchRealm + create N entities WITH IGA OFF
 *      (10 roles + 10 groups + 5 users in CASE A).
 *   2. Toggle-on IGA → toggle-on scan emits PENDING ADOPT_USER/ROLE/GROUP CRs.
 *   3. POST bulk-authorize with actionTypeIn=[ADOPT_USER, ADOPT_ROLE,
 *      ADOPT_GROUP, ADOPT_CLIENT, ADOPT_CLIENT_SCOPE].
 *   4. Assert HTTP 200 + per-CR results all "COMMITTED" + summary counts.
 *
 * The bulk endpoint reuses the same per-CR authorize+commit gate the per-CR
 * endpoints use (IgaAdminResource#bulkAuthorize → processOneCr →
 * IgaAttestor.record + requireApprover + combineFinal + tryReplay/dispatch).
 * Per the locked Phase 6 design:
 *   - ADOPT_* short-circuits inside IgaScopeResolver
 *     (threshold=1 + approver-role bypass).
 *   - Non-ADOPT (CREATE_x / UPDATE_x / etc.) gets the FULL threshold +
 *     approver-role + scopeMode gate. The bulk endpoint MUST NOT shortcut
 *     this — a caller missing the required role (or threshold not met)
 *     produces a per-CR rejection in the results array but the bulk endpoint
 *     itself still returns HTTP 200.
 *
 * Cases:
 *   A. Happy-path bulk-ADOPT          — drains all ADOPT_* CRs from a freshly-
 *                                       toggled realm; sidecar count == 0
 *                                       post-bulk.
 *   B. Limit enforcement               — limit>1000 → 400; default limit
 *                                       (omitted) caps at 100.
 *   C. Per-CR gate not shortcut        — CREATE_ROLE CR (governed by a realm
 *                                       iga.threshold=2) → per-CR rejection
 *                                       with THRESHOLD_NOT_MET (proves the
 *                                       gate ran). HTTP 200 on the bulk call.
 *   D. Concurrent bulk lock           — Promise.all two bulk calls → one
 *                                       returns 429, the other 200.
 *   E. Idempotent skip                — second bulk on the same realm after
 *                                       all CRs have committed →
 *                                       all already-resolved CRs from the
 *                                       prior bulk are filtered out by the
 *                                       PENDING selector, so the second
 *                                       call returns total=0
 *                                       (empty result set).
 *
 * Pure API E2E. Idempotent; scratch realms deleted in afterAll on every exit.
 *
 * Precondition gate: the bulk-authorize endpoint is the load-signal — a
 * 404/405 against a probe realm means the jar wasn't restarted into KC yet.
 */

const A_HAPPY = 'iga-phase6e-happy';
const B_LIMIT = 'iga-phase6e-limit';
const C_GATE = 'iga-phase6e-gate';
const D_LOCK = 'iga-phase6e-lock';
const E_IDEMP = 'iga-phase6e-idemp';
const PROBE = 'iga-phase6e-precond-probe';
const RERUN =
  'cd /home/sasha/project/tidecloak-iga-extensions/e2e && npx playwright test';

interface BulkResult {
  crId: string;
  status: 'COMMITTED' | 'REJECTED' | 'SKIPPED' | string;
  error?: string;
  actionType?: string;
  entityType?: string;
  entityId?: string;
  threshold?: number;
  authCount?: number;
  [k: string]: unknown;
}

interface BulkSummary {
  total: number;
  committed: number;
  rejected: number;
  skipped: number;
  durationMs: number;
  limit: number;
  defaultLimit: number;
  maxLimit: number;
  [k: string]: unknown;
}

interface BulkResponse {
  results: BulkResult[];
  summary: BulkSummary;
}

/** POST /iga/change-requests/bulk-authorize and return { http, body }. */
async function bulkAuthorize(
  request: APIRequestContext,
  realm: string,
  body: Record<string, unknown>,
): Promise<{ http: number; body: BulkResponse | any }> {
  const res = await kcFetch(
    request,
    `/admin/realms/${realm}/iga/change-requests/bulk-authorize`,
    { method: 'POST', json: body },
  );
  return { http: res.status(), body: await safeJson(res) };
}

/** POST /admin/realms/{realm}/tide-admin/toggle-iga. */
async function toggleIga(
  request: APIRequestContext,
  realm: string,
): Promise<{ http: number; body: any }> {
  const res = await kcFetch(
    request,
    `/admin/realms/${realm}/tide-admin/toggle-iga`,
    { method: 'POST' },
  );
  return { http: res.status(), body: await safeJson(res) };
}

/**
 * GET sidecar count via the existing admin list+filter path. We don't have a
 * dedicated sidecar-count endpoint, so we count remaining PENDING ADOPT_* CRs
 * post-bulk — a successful adopt-commit deletes the sidecar row AND flips the
 * CR to APPROVED, so PENDING ADOPT_* count is the operationally correct
 * "sidecar empty" assertion.
 */
async function countPendingAdopts(
  request: APIRequestContext,
  realm: string,
): Promise<number> {
  const list = await listChangeRequests(request, realm, 'PENDING');
  return list.filter((cr) =>
    String(cr.actionType).startsWith('ADOPT_'),
  ).length;
}

test.describe('IGA Phase 6e: bulk-authorize endpoint', () => {
  test.afterAll(async ({ request }) => {
    await deleteRealm(request, A_HAPPY).catch(() => {});
    await deleteRealm(request, B_LIMIT).catch(() => {});
    await deleteRealm(request, C_GATE).catch(() => {});
    await deleteRealm(request, D_LOCK).catch(() => {});
    await deleteRealm(request, E_IDEMP).catch(() => {});
    await deleteRealm(request, PROBE).catch(() => {});
  });

  test('happy path: bulk-authorize commits all ADOPT_* CRs on a freshly-toggled realm', async ({
    request,
  }) => {
    // ----- PRECONDITION GATE — the bulk endpoint itself is the load signal.
    // A 404 against a fresh realm means the jar isn't loaded; 200 (or 400 on
    // a bad body) means it is.
    const probeOk = await (async () => {
      try {
        await createScratchRealm(request, PROBE);
        // POST with an empty body — endpoint should respond 400 (loaded) or
        // 404 (not loaded). 405 also means not loaded.
        const probe = await bulkAuthorize(request, PROBE, {});
        if (probe.http === 404 || probe.http === 405) {
          return {
            ok: false,
            detail:
              `bulk-authorize probe returned HTTP ${probe.http} — Phase 6e endpoint ` +
              `not yet loaded in the running container.`,
          };
        }
        // Any other status (400 for missing actionTypeIn, 200, 429) means the
        // endpoint IS loaded.
        return { ok: true, detail: `loaded (probe HTTP ${probe.http})` };
      } catch (e: any) {
        return { ok: false, detail: `probe raised: ${e?.message ?? e}` };
      } finally {
        await deleteRealm(request, PROBE).catch(() => {});
      }
    })();
    console.log(
      `\n[PRECONDITION phase6e] ok=${probeOk.ok} ${probeOk.detail}\n`,
    );
    if (!probeOk.ok) {
      throw new Error(
        `PRECONDITION: Phase 6e jar not loaded (${probeOk.detail}) — ` +
          `restart the container, then re-run: ${RERUN}`,
      );
    }

    // ----- Setup --------------------------------------------------------------
    await createScratchRealm(request, A_HAPPY);

    const ROLE_COUNT = 10;
    const GROUP_COUNT = 10;
    const USER_COUNT = 5;
    for (let i = 0; i < ROLE_COUNT; i++) {
      const r = await createRole(request, A_HAPPY, {
        name: `p6e-a-role-${i}`,
      });
      expect(r.status(), `create role ${i}`).toBe(201);
    }
    for (let i = 0; i < GROUP_COUNT; i++) {
      const g = await createGroup(request, A_HAPPY, `p6e-a-group-${i}`);
      expect(g.status(), `create group ${i}`).toBe(201);
    }
    for (let i = 0; i < USER_COUNT; i++) {
      const u = await createUser(request, A_HAPPY, {
        username: `p6e-a-user-${i}`,
        enabled: true,
        email: `p6e-a-user-${i}@example.test`,
      });
      expect(u.status(), `create user ${i}`).toBe(201);
    }

    // Toggle IGA on — the scan emits ADOPT_* PENDING CRs.
    const onRes = await toggleIga(request, A_HAPPY);
    expect(onRes.http).toBe(200);
    expect(onRes.body?.enabled, 'IGA enabled').toBe(true);
    expect(onRes.body?.scan, 'scan block').toBeTruthy();

    const pendingBefore = await countPendingAdopts(request, A_HAPPY);
    expect(
      pendingBefore,
      `expected >= ${ROLE_COUNT + GROUP_COUNT + USER_COUNT} PENDING ADOPT_* CRs, got ${pendingBefore}`,
    ).toBeGreaterThanOrEqual(ROLE_COUNT + GROUP_COUNT + USER_COUNT);

    // ----- Bulk-authorize -----------------------------------------------------
    const bulk = await bulkAuthorize(request, A_HAPPY, {
      actionTypeIn: [
        'ADOPT_USER',
        'ADOPT_ROLE',
        'ADOPT_GROUP',
        'ADOPT_CLIENT',
        'ADOPT_CLIENT_SCOPE',
      ],
      limit: 1000,
    });
    expect(
      bulk.http,
      `bulk-authorize HTTP 200, got ${bulk.http} body=${JSON.stringify(bulk.body)}`,
    ).toBe(200);
    const resp = bulk.body as BulkResponse;
    expect(Array.isArray(resp?.results), 'results array').toBe(true);
    expect(resp.summary, 'summary block').toBeTruthy();

    // All bulk-targeted CRs should COMMIT (ADOPT_* short-circuits the
    // approver-role gate + threshold=1 via the ADOPT bypass).
    const nonCommitted = resp.results.filter((r) => r.status !== 'COMMITTED');
    expect(
      nonCommitted.length,
      `every result should be COMMITTED; non-committed=${JSON.stringify(nonCommitted)}`,
    ).toBe(0);
    expect(
      resp.summary.committed,
      `summary.committed must match results.length`,
    ).toBe(resp.results.length);
    expect(resp.summary.rejected).toBe(0);
    expect(resp.summary.skipped).toBe(0);
    expect(resp.summary.total).toBe(resp.results.length);
    expect(resp.summary.maxLimit).toBe(1000);
    expect(resp.summary.defaultLimit).toBe(100);

    // Each result row carries actionType + entityId.
    for (const r of resp.results) {
      expect(typeof r.crId).toBe('string');
      expect(String(r.actionType ?? '')).toMatch(/^ADOPT_/);
      expect(typeof r.entityId).toBe('string');
    }

    // Post-bulk: sidecar should be drained — no more PENDING ADOPT_* CRs.
    const pendingAfter = await countPendingAdopts(request, A_HAPPY);
    expect(
      pendingAfter,
      `sidecar should be empty post-bulk, got ${pendingAfter} PENDING ADOPT_* CRs`,
    ).toBe(0);

    // Sanity: pick one of the committed CRs and confirm it's APPROVED in the
    // detail endpoint (the bulk loop went through the SAME commit path).
    const firstCommit = resp.results[0];
    const detail = await getChangeRequest(
      request,
      A_HAPPY,
      String(firstCommit.crId),
    );
    expect(detail.http).toBe(200);
    expect(detail.body?.status, `CR ${firstCommit.crId} status`).toBe(
      'APPROVED',
    );
  });

  test('limit enforcement: limit>1000 → 400; default limit caps at 100', async ({
    request,
  }) => {
    await createScratchRealm(request, B_LIMIT);

    // 1) limit>1000 with no actual queue → still 400 because validation runs
    //    BEFORE any query (the cap is a body-validation reject).
    const over = await bulkAuthorize(request, B_LIMIT, {
      actionTypeIn: ['ADOPT_USER', 'ADOPT_ROLE', 'ADOPT_GROUP'],
      limit: 10000,
    });
    expect(
      over.http,
      `limit>1000 should be 400, got HTTP ${over.http} body=${JSON.stringify(over.body)}`,
    ).toBe(400);
    expect(over.body?.maxLimit).toBe(1000);

    // 2) Default-limit path. Provision >100 PENDING ADOPT_* CRs by creating
    //    150 groups + toggling IGA on; then call bulk-authorize with NO limit
    //    in the body. The summary's processed count should not exceed
    //    defaultLimit (100).
    const GROUP_COUNT = 150;
    for (let i = 0; i < GROUP_COUNT; i++) {
      const g = await createGroup(request, B_LIMIT, `p6e-b-g-${i}`);
      expect(g.status(), `create group ${i}`).toBe(201);
    }
    const on = await toggleIga(request, B_LIMIT);
    expect(on.http).toBe(200);
    expect(on.body?.enabled).toBe(true);

    const pendingBefore = await countPendingAdopts(request, B_LIMIT);
    expect(
      pendingBefore,
      `expected >${GROUP_COUNT} PENDING ADOPT_* CRs, got ${pendingBefore}`,
    ).toBeGreaterThanOrEqual(GROUP_COUNT);

    const dflt = await bulkAuthorize(request, B_LIMIT, {
      actionTypeIn: [
        'ADOPT_USER',
        'ADOPT_ROLE',
        'ADOPT_GROUP',
        'ADOPT_CLIENT',
        'ADOPT_CLIENT_SCOPE',
      ],
    });
    expect(dflt.http).toBe(200);
    const resp = dflt.body as BulkResponse;
    expect(resp.summary.limit).toBe(100);
    expect(resp.summary.defaultLimit).toBe(100);
    expect(
      resp.summary.total,
      `default-limit run must process exactly defaultLimit (100) when more CRs are available, got ${resp.summary.total}`,
    ).toBe(100);
    expect(resp.results.length).toBe(100);

    // 3) limit<=0 → 400.
    const zero = await bulkAuthorize(request, B_LIMIT, {
      actionTypeIn: ['ADOPT_GROUP'],
      limit: 0,
    });
    expect(zero.http).toBe(400);

    // 4) empty actionTypeIn → 400.
    const empty = await bulkAuthorize(request, B_LIMIT, {
      actionTypeIn: [],
      limit: 100,
    });
    expect(empty.http).toBe(400);

    // 5) missing actionTypeIn → 400.
    const missing = await bulkAuthorize(request, B_LIMIT, { limit: 100 });
    expect(missing.http).toBe(400);
  });

  test('per-CR gate not shortcut for non-ADOPT: CREATE_ROLE under realm threshold=2 → REJECTED THRESHOLD_NOT_MET (HTTP 200 overall)', async ({
    request,
  }) => {
    // Set realm iga.threshold=2 BEFORE enabling IGA so the threshold attr
    // write isn't itself governed. The Phase 5 threshold-precedence test
    // already validates this pattern.
    await createScratchRealm(request, C_GATE);
    await setRealmIgaAttr(request, C_GATE, 'iga.threshold', '2');

    // Enable IGA — the toggle-on scan emits no ADOPT_* CRs (clean realm).
    const on = await toggleIga(request, C_GATE);
    expect(on.http).toBe(200);
    expect(on.body?.enabled).toBe(true);

    // Drive a CREATE_ROLE — IGA-aware role provider captures + emits a
    // PENDING CR governed by the realm-default threshold=2. The CREATE_ROLE
    // returns 202 (governance refusal) — we just need the CR id.
    const createRes = await createRole(request, C_GATE, {
      name: 'p6e-c-target-role',
    });
    // 202 is the standard IGA-governed refusal status; the test passes as
    // long as a PENDING CREATE_ROLE CR exists for this name.
    expect(
      [201, 202].includes(createRes.status()),
      `createRole returned unexpected HTTP ${createRes.status()}: ${await createRes.text()}`,
    ).toBe(true);

    const pendingList = await listChangeRequests(request, C_GATE, 'PENDING');
    const targetCr = pendingList.find(
      (cr) => cr.actionType === 'CREATE_ROLE',
    );
    expect(
      targetCr,
      `expected a PENDING CREATE_ROLE CR for p6e-c-target-role, got ${JSON.stringify(pendingList.map((c) => ({ id: c.id, actionType: c.actionType })))}`,
    ).toBeTruthy();

    // Bulk-authorize WITH actionTypeIn=[CREATE_ROLE]. The master admin
    // contributes ONE signature (via attestor.record), threshold=2 not met,
    // → per-CR REJECTED with THRESHOLD_NOT_MET. The bulk call itself
    // returns HTTP 200 (the bulk endpoint succeeded; per-CR outcomes carry
    // the rejection in the results array).
    const bulk = await bulkAuthorize(request, C_GATE, {
      actionTypeIn: ['CREATE_ROLE'],
      limit: 100,
    });
    expect(
      bulk.http,
      `bulk-authorize HTTP 200 (per-CR rejection lives in results), got ${bulk.http} body=${JSON.stringify(bulk.body)}`,
    ).toBe(200);
    const resp = bulk.body as BulkResponse;
    expect(resp.results.length).toBeGreaterThanOrEqual(1);
    const rejected = resp.results.find(
      (r) => r.crId === (targetCr!.id as string),
    );
    expect(rejected, 'CREATE_ROLE CR present in results').toBeTruthy();
    expect(
      rejected!.status,
      `CREATE_ROLE result.status must be REJECTED (per-CR gate enforced), got ${rejected!.status}`,
    ).toBe('REJECTED');
    expect(
      rejected!.error,
      `error code must be THRESHOLD_NOT_MET (proves the gate ran), got ${rejected!.error}`,
    ).toBe('THRESHOLD_NOT_MET');
    expect(rejected!.threshold).toBe(2);
    expect(rejected!.authCount).toBe(1);
    expect(resp.summary.rejected).toBeGreaterThanOrEqual(1);
    expect(resp.summary.committed).toBe(0);

    // Sanity: the CR is still PENDING (the bulk loop recorded the master
    // admin's signature but couldn't commit; the CR survives for a later
    // second-admin signature path).
    const detail = await getChangeRequest(
      request,
      C_GATE,
      targetCr!.id as string,
    );
    expect(detail.http).toBe(200);
    expect(detail.body?.status).toBe('PENDING');
  });

  test('concurrent bulk lock: two simultaneous bulk calls → one 200, one 429', async ({
    request,
  }) => {
    await createScratchRealm(request, D_LOCK);
    // Provision a deep queue so the in-flight bulk doesn't drain
    // instantaneously before the second call lands.
    const GROUP_COUNT = 120;
    for (let i = 0; i < GROUP_COUNT; i++) {
      const g = await createGroup(request, D_LOCK, `p6e-d-g-${i}`);
      expect(g.status(), `create group ${i}`).toBe(201);
    }
    const on = await toggleIga(request, D_LOCK);
    expect(on.http).toBe(200);
    expect(on.body?.enabled).toBe(true);

    const pendingBefore = await countPendingAdopts(request, D_LOCK);
    expect(pendingBefore).toBeGreaterThanOrEqual(GROUP_COUNT);

    // Two bulks fired in parallel. The lock is now cluster-safe and
    // per-realm, backed by KC's canonical
    // ClusterProvider.executeIfNotExecuted(...) primitive (see
    // iga-core/src/main/java/org/tidecloak/iga/rest/IgaBulkLock.java →
    // server-spi-private ClusterProvider). In single-node dev mode the
    // SPI is still wired through the Infinispan local-cache impl, so the
    // taskKey ("iga-bulk:" + realmId) reliably contends here; in a
    // multi-node cluster the same key contends across nodes — that was
    // the whole reason for the swap.
    const [a, b] = await Promise.all([
      bulkAuthorize(request, D_LOCK, {
        actionTypeIn: ['ADOPT_GROUP'],
        limit: 1000,
      }),
      bulkAuthorize(request, D_LOCK, {
        actionTypeIn: ['ADOPT_GROUP'],
        limit: 1000,
      }),
    ]);
    const statuses = [a.http, b.http].sort();
    expect(
      statuses,
      `expected one 200 and one 429 from concurrent bulks, got ${JSON.stringify(statuses)} bodies=${JSON.stringify([a.body, b.body])}`,
    ).toEqual([200, 429]);

    // The 429 body should mention the realm.
    const blocked = a.http === 429 ? a.body : b.body;
    expect(blocked?.realm).toBe(D_LOCK);
    expect(String(blocked?.error ?? '')).toMatch(/already running/i);

    // The 200 call's summary.committed should be > 0 (it actually drained
    // some of the queue).
    const winner = a.http === 200 ? (a.body as BulkResponse) : (b.body as BulkResponse);
    expect(winner.summary.committed).toBeGreaterThan(0);
  });

  test('idempotent skip: second bulk after a full drain → total=0 (all already-resolved)', async ({
    request,
  }) => {
    await createScratchRealm(request, E_IDEMP);
    for (let i = 0; i < 5; i++) {
      const g = await createGroup(request, E_IDEMP, `p6e-e-g-${i}`);
      expect(g.status(), `create group ${i}`).toBe(201);
    }
    for (let i = 0; i < 3; i++) {
      const r = await createRole(request, E_IDEMP, { name: `p6e-e-r-${i}` });
      expect(r.status(), `create role ${i}`).toBe(201);
    }
    const on = await toggleIga(request, E_IDEMP);
    expect(on.http).toBe(200);
    expect(on.body?.enabled).toBe(true);

    // First bulk: drain everything.
    const first = await bulkAuthorize(request, E_IDEMP, {
      actionTypeIn: [
        'ADOPT_USER',
        'ADOPT_ROLE',
        'ADOPT_GROUP',
        'ADOPT_CLIENT',
        'ADOPT_CLIENT_SCOPE',
      ],
      limit: 1000,
    });
    expect(first.http).toBe(200);
    const r1 = first.body as BulkResponse;
    expect(r1.summary.committed).toBeGreaterThanOrEqual(5 + 3);
    expect(r1.summary.rejected).toBe(0);

    const drainedAdopts = await countPendingAdopts(request, E_IDEMP);
    expect(
      drainedAdopts,
      'sidecar drained — no PENDING ADOPT_* after first bulk',
    ).toBe(0);

    // Second bulk on the same filter → no PENDING ADOPT_* match the
    // selector, so results.length == 0 and summary.* are all 0 / committed 0.
    // This is the "idempotent skip" contract: already-resolved CRs are
    // filtered out by the PENDING selector at query time so they never even
    // reach the per-CR loop.
    const second = await bulkAuthorize(request, E_IDEMP, {
      actionTypeIn: [
        'ADOPT_USER',
        'ADOPT_ROLE',
        'ADOPT_GROUP',
        'ADOPT_CLIENT',
        'ADOPT_CLIENT_SCOPE',
      ],
      limit: 1000,
    });
    expect(second.http).toBe(200);
    const r2 = second.body as BulkResponse;
    expect(
      r2.summary.total,
      `second bulk should find 0 PENDING ADOPT_*, got ${r2.summary.total}`,
    ).toBe(0);
    expect(r2.summary.committed).toBe(0);
    expect(r2.summary.rejected).toBe(0);
    expect(r2.summary.skipped).toBe(0);
    expect(r2.results.length).toBe(0);
  });
});
