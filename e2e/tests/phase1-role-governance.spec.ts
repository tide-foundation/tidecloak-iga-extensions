import { test, expect, APIRequestContext } from '@playwright/test';
import {
  createScratchRealm,
  deleteRealm,
  enableIga,
  igaStatus,
  createRole,
  createClient,
  createClientRole,
  getRole,
  getClientRole,
  getRoleComposites,
  getClientRoleComposites,
  getChangeRequest,
  authorizeAndCommit,
  locationHeader,
  safeJson,
  RoleSpec,
} from '../lib/kc';
import { checkPrecondition, rerunCommand } from '../lib/precondition';

/**
 * Phase 1 — model-layer full capture for realm + client role creates
 * (including composites).
 *
 * This is an API E2E test (no browser). It drives the exact production path:
 * the IGA capture is enforced at the model layer, so raw Admin REST exercises
 * the same seam any caller hits.
 *
 * Order of operations mirrors the documented "configure bases BEFORE enabling
 * IGA" rule, otherwise creating the bases would itself be governed.
 */

const REALM = 'iga-phase1-e2e';

const parentSpec = (extra?: Partial<RoleSpec>): RoleSpec => ({
  name: 'r-parent',
  description: 'phase1 desc',
  attributes: { team: ['blue'] },
  composite: true,
  composites: { realm: ['r-base'], client: { acme: ['c-base'] } },
  ...extra,
});

const clientParentSpec = (): RoleSpec => ({
  name: 'c-parent',
  description: 'phase1 desc',
  attributes: { team: ['blue'] },
  composite: true,
  composites: { realm: ['r-base'], client: { acme: ['c-base'] } },
});

function compositeNames(list: any[]): string[] {
  return list.map((r) => r?.name).filter(Boolean);
}

test.describe('IGA Phase 1: realm + client role governed create/replay', () => {
  // Always clean up the scratch realm, even on failure.
  test.afterAll(async ({ request }) => {
    await deleteRealm(request, REALM).catch(() => {});
  });

  test('Phase 1 governed role create → CR → authorize+commit → full fidelity', async ({
    request,
  }) => {
    // -----------------------------------------------------------------------
    // PRECONDITION GATE — must pass before any pass/fail scenario assertions.
    // -----------------------------------------------------------------------
    const pre = await checkPrecondition(request);
    console.log(
      `\n[PRECONDITION] verdict=${pre.verdict}\n  ${pre.detail}\n  evidence=${JSON.stringify(
        pre.evidence,
        null,
        2,
      )}\n`,
    );
    if (pre.verdict !== 'OK') {
      const msg =
        `PRECONDITION: Phase 1 jar not loaded in the running container ` +
        `(verdict=${pre.verdict}: ${pre.detail}) — restart the container, ` +
        `then re-run: ${rerunCommand()}`;
      // Fail loudly and unambiguously; this is NOT a scenario failure.
      throw new Error(msg);
    }

    // -----------------------------------------------------------------------
    // 1. Scratch realm + composite bases with IGA OFF.
    // -----------------------------------------------------------------------
    await createScratchRealm(request, REALM);

    const st0 = await igaStatus(request, REALM);
    expect(
      st0.enabled,
      `IGA should start disabled on a fresh realm (got ${JSON.stringify(st0)})`,
    ).toBeFalsy();

    const rBase = await createRole(request, REALM, { name: 'r-base' });
    expect(rBase.status(), 'create base realm role r-base').toBe(201);

    const acmeUuid = await createClient(request, REALM, 'acme');
    expect(acmeUuid, 'acme client uuid').toBeTruthy();

    const cBase = await createClientRole(request, REALM, acmeUuid, {
      name: 'c-base',
    });
    expect(cBase.status(), 'create base client role acme:c-base').toBe(201);

    // -----------------------------------------------------------------------
    // 2. Enable IGA + sanity-confirm active.
    // -----------------------------------------------------------------------
    await enableIga(request, REALM);
    const st1 = await igaStatus(request, REALM);
    expect(st1.http, 'iga-status http').toBe(200);
    expect(st1.enabled, 'IGA must be enabled').toBe(true);

    // -----------------------------------------------------------------------
    // 3. Realm role governed create.
    // -----------------------------------------------------------------------
    const realmCreate = await createRole(request, REALM, parentSpec());
    const realmStatus = realmCreate.status();
    const realmLoc = locationHeader(realmCreate);
    const realmBody = await safeJson(realmCreate);
    expect(
      realmStatus,
      `realm-role governed create expected 202, got ${realmStatus} body=${JSON.stringify(realmBody)}`,
    ).toBe(202);
    expect(
      realmLoc,
      `202 must carry a Location header (got ${JSON.stringify(realmCreate.headers())})`,
    ).toBeTruthy();

    const realmCrId =
      (realmBody && realmBody.changeRequestId) ||
      (realmLoc ? realmLoc.split('/').pop() : '');
    expect(realmCrId, 'realm CR id resolvable from body/Location').toBeTruthy();

    const realmCr = await getChangeRequest(request, REALM, realmCrId);
    expect(realmCr.http, `GET ${realmLoc} expected 200`).toBe(200);
    expect(
      realmCr.body?.actionType,
      `CR actionType expected CREATE_ROLE, got ${realmCr.body?.actionType}`,
    ).toBe('CREATE_ROLE');
    expect(
      realmCr.body?.status,
      `CR status expected PENDING, got ${realmCr.body?.status}`,
    ).toBe('PENDING');

    // Not yet persisted at draft.
    const realmDraft = await getRole(request, REALM, 'r-parent');
    expect(
      realmDraft.http,
      `r-parent must NOT be persisted before commit (expected 404, got ${realmDraft.http})`,
    ).toBe(404);

    // -----------------------------------------------------------------------
    // 4. Client role governed create.
    // -----------------------------------------------------------------------
    const clientCreate = await createClientRole(
      request,
      REALM,
      acmeUuid,
      clientParentSpec(),
    );
    const clientStatus = clientCreate.status();
    const clientLoc = locationHeader(clientCreate);
    const clientBody = await safeJson(clientCreate);
    expect(
      clientStatus,
      `client-role governed create expected 202, got ${clientStatus} body=${JSON.stringify(clientBody)}`,
    ).toBe(202);
    expect(
      clientLoc,
      `202 must carry a Location header (got ${JSON.stringify(clientCreate.headers())})`,
    ).toBeTruthy();

    const clientCrId =
      (clientBody && clientBody.changeRequestId) ||
      (clientLoc ? clientLoc.split('/').pop() : '');
    expect(clientCrId, 'client CR id resolvable').toBeTruthy();

    const clientCr = await getChangeRequest(request, REALM, clientCrId);
    expect(clientCr.http, `GET ${clientLoc} expected 200`).toBe(200);
    expect(clientCr.body?.actionType, 'client CR actionType').toBe(
      'CREATE_ROLE',
    );
    expect(clientCr.body?.status, 'client CR status').toBe('PENDING');

    const clientDraft = await getClientRole(
      request,
      REALM,
      acmeUuid,
      'c-parent',
    );
    expect(
      clientDraft.http,
      `acme:c-parent must NOT be persisted before commit (expected 404, got ${clientDraft.http})`,
    ).toBe(404);

    // -----------------------------------------------------------------------
    // 5. Authorize + commit each CR (threshold 1, no approver roles → self).
    // -----------------------------------------------------------------------
    const realmAC = await authorizeAndCommit(request, REALM, realmCrId);
    expect(
      realmAC.authorize.http,
      `realm CR authorize expected 200, got ${realmAC.authorize.http} ${JSON.stringify(realmAC.authorize.body)}`,
    ).toBe(200);
    expect(
      realmAC.commit.http,
      `realm CR commit expected 200, got ${realmAC.commit.http} ${JSON.stringify(realmAC.commit.body)}`,
    ).toBe(200);

    const clientAC = await authorizeAndCommit(request, REALM, clientCrId);
    expect(
      clientAC.authorize.http,
      `client CR authorize expected 200, got ${clientAC.authorize.http} ${JSON.stringify(clientAC.authorize.body)}`,
    ).toBe(200);
    expect(
      clientAC.commit.http,
      `client CR commit expected 200, got ${clientAC.commit.http} ${JSON.stringify(clientAC.commit.body)}`,
    ).toBe(200);

    // -----------------------------------------------------------------------
    // 6. Post-commit fidelity asserts.
    // -----------------------------------------------------------------------
    // Realm role r-parent
    const rp = await getRole(request, REALM, 'r-parent');
    expect(rp.http, 'r-parent must exist after commit').toBe(200);
    expect(rp.body?.description, 'r-parent description fidelity').toBe(
      'phase1 desc',
    );
    expect(
      rp.body?.attributes?.team,
      `r-parent attribute team fidelity (got ${JSON.stringify(rp.body?.attributes)})`,
    ).toEqual(['blue']);

    const rpComp = await getRoleComposites(request, REALM, 'r-parent');
    expect(rpComp.http, 'r-parent composites http').toBe(200);
    const rpNames = compositeNames(rpComp.body);
    expect(
      rpNames,
      `r-parent composites must include realm role r-base (got ${JSON.stringify(rpNames)})`,
    ).toContain('r-base');
    expect(
      rpNames,
      `r-parent composites must include client role c-base (got ${JSON.stringify(rpNames)})`,
    ).toContain('c-base');

    // Client role acme:c-parent
    const cp = await getClientRole(request, REALM, acmeUuid, 'c-parent');
    expect(cp.http, 'acme:c-parent must exist after commit').toBe(200);
    expect(cp.body?.description, 'acme:c-parent description fidelity').toBe(
      'phase1 desc',
    );
    expect(
      cp.body?.attributes?.team,
      `acme:c-parent attribute team fidelity (got ${JSON.stringify(cp.body?.attributes)})`,
    ).toEqual(['blue']);

    const cpComp = await getClientRoleComposites(
      request,
      REALM,
      acmeUuid,
      'c-parent',
    );
    expect(cpComp.http, 'acme:c-parent composites http').toBe(200);
    const cpNames = compositeNames(cpComp.body);
    expect(
      cpNames,
      `acme:c-parent composites must include realm role r-base (got ${JSON.stringify(cpNames)})`,
    ).toContain('r-base');
    expect(
      cpNames,
      `acme:c-parent composites must include client role c-base (got ${JSON.stringify(cpNames)})`,
    ).toContain('c-base');

    // -----------------------------------------------------------------------
    // 7. Cleanup (afterAll also deletes; do it here too and confirm).
    // -----------------------------------------------------------------------
    await deleteRealm(request, REALM);
    const gone = await igaStatus(request, REALM);
    expect(
      gone.http,
      `scratch realm must be deleted (iga-status expected 404, got ${gone.http})`,
    ).toBe(404);
  });
});
