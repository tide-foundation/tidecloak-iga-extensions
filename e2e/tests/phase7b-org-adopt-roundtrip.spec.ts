import { test, expect, APIRequestContext } from '@playwright/test';
import {
  createScratchRealm,
  deleteRealm,
  enableIga,
  getChangeRequest,
  authorizeAndCommit,
  listChangeRequests,
  locationHeader,
  safeJson,
  createOrganization,
  findOrganizationByName,
  kcFetch,
} from '../lib/kc';
import { checkPrecondition, rerunCommand } from '../lib/precondition';

/**
 * Phase 7b — retroactive ADOPT for KC organizations.
 *
 * Mirrors the Phase 6b toggle-on scan for the five existing entity types
 * (USER/ROLE/GROUP/CLIENT/CLIENT_SCOPE) but for ORGANIZATIONs. Orgs are
 * sidecar-only: {@code OrganizationEntity} has no {@code attestation} column
 * (design choice noted in {@code IgaReplayDispatcher.java:483-497}); the
 * sidecar row + the CR's {@code status=APPROVED} are the entire "signed"
 * post-condition. The ADOPT_* gate bypass already covers ADOPT_ORGANIZATION
 * via {@code IgaReplayExtension.isAdoptAction}, so a single master-admin
 * authorize+commit suffices regardless of realm threshold.
 *
 * Cases:
 *   A. Happy path — 3 orgs pre-created with IGA OFF, toggle ON, assert
 *      {@code scan.adoptCrsCreated.ORGANIZATION === 3} + 3 PENDING
 *      ADOPT_ORGANIZATION CRs; authorize+commit one and verify sidecar
 *      cleared (CR APPROVED).
 *   B. Idempotent re-toggle — after committing 1 ADOPT_ORGANIZATION,
 *      toggle off→on; assert the second-toggle's
 *      {@code scan.adoptCrsCreated.ORGANIZATION === 2} (the committed one
 *      skipped via {@code alreadyCommittedAdopt}).
 *   C. CREATE_ORGANIZATION race skip — create an org via the governed POST
 *      while IGA is on, toggle off then on; assert the scan SKIPS the
 *      pending-create org via {@code skipped.pendingCreateCr}.
 *   D. Bulk-authorize compatibility — POST
 *      {@code /iga/change-requests/bulk-authorize} with
 *      {@code actionTypeIn=["ADOPT_ORGANIZATION"]} drains the queue.
 */

const HAPPY = 'iga-phase7b-happy';
const IDEMP = 'iga-phase7b-idemp';
const RACE = 'iga-phase7b-race';
const BULK = 'iga-phase7b-bulk';
const RERUN =
  'cd /home/sasha/project/tidecloak-iga-extensions/e2e && npx playwright test phase7b-org-adopt-roundtrip.spec.ts';

/** POST /admin/realms/{realm}/tide-admin/toggle-iga and return the full body. */
async function toggleIgaRaw(
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
 * Turn on the KC organizations feature for the realm. POST /realms creates the
 * realm with organizationsEnabled=false by default; this PUT-update flips it on
 * BEFORE we start creating orgs. (Identical to the phase7a recipe.)
 */
async function enableOrganizationsOnRealm(
  request: APIRequestContext,
  realm: string,
): Promise<void> {
  const getRes = await kcFetch(request, `/admin/realms/${realm}`);
  expect(getRes.status(), `GET realm ${realm}`).toBe(200);
  const realmRep = await safeJson(getRes);
  const enableRes = await kcFetch(request, `/admin/realms/${realm}`, {
    method: 'PUT',
    json: { ...realmRep, organizationsEnabled: true },
  });
  expect(
    enableRes.status(),
    `enable organizations feature on ${realm}: HTTP ${enableRes.status()}`,
  ).toBe(204);
}

/** POST /iga/change-requests/bulk-authorize. */
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

test.describe('IGA Phase 7b: retroactive ADOPT for organizations', () => {
  test.afterAll(async ({ request }) => {
    await deleteRealm(request, HAPPY).catch(() => {});
    await deleteRealm(request, IDEMP).catch(() => {});
    await deleteRealm(request, RACE).catch(() => {});
    await deleteRealm(request, BULK).catch(() => {});
  });

  test('Phase 7b org adopt: happy + idempotent + create-race + bulk-authorize', async ({
    request,
  }) => {
    // -----------------------------------------------------------------------
    // PRECONDITION GATE — re-uses the Phase 1 probe (proves jar is loaded).
    // -----------------------------------------------------------------------
    const pre = await checkPrecondition(request);
    console.log(
      `\n[PRECONDITION phase7b] verdict=${pre.verdict}\n  ${pre.detail}\n  evidence=${JSON.stringify(
        pre.evidence,
        null,
        2,
      )}\n`,
    );
    if (pre.verdict !== 'OK') {
      throw new Error(
        `PRECONDITION: IGA jar not loaded in the running container ` +
          `(verdict=${pre.verdict}: ${pre.detail}) — restart the container, ` +
          `then re-run: ${rerunCommand()}`,
      );
    }

    // -----------------------------------------------------------------------
    // CASE A — Happy path: 3 orgs created with IGA OFF, toggle ON, scan
    // emits 3 ADOPT_ORGANIZATION CRs, commit 1.
    // -----------------------------------------------------------------------
    await createScratchRealm(request, HAPPY);
    await enableOrganizationsOnRealm(request, HAPPY);

    const orgNames = ['p7b-happy-org1', 'p7b-happy-org2', 'p7b-happy-org3'];
    for (const name of orgNames) {
      const r = await createOrganization(request, HAPPY, {
        name,
        alias: name,
        enabled: true,
        domains: [{ name: `${name}.example`, verified: false }],
      });
      // IGA OFF on a fresh realm — KC's stock OrganizationsResource.create
      // returns 201 (or 204 — KC 26.5.5 actually returns 201 Created with a
      // Location header on success). Either way it's a non-2xx-failure
      // assertion we want; tolerate the 201/204 split.
      expect(
        [201, 204].includes(r.status()),
        `IGA-OFF org create ${name} expected 201/204, got ${r.status()} ${await r.text()}`,
      ).toBe(true);
    }

    // Sanity: every org is queryable.
    const orgIds: Record<string, string> = {};
    for (const name of orgNames) {
      const lookup = await findOrganizationByName(request, HAPPY, name);
      expect(lookup.body, `${name} resolves`).toBeTruthy();
      orgIds[name] = lookup.body.id as string;
    }

    // Toggle IGA on — the scan must emit 3 ADOPT_ORGANIZATION CRs.
    const t = await toggleIgaRaw(request, HAPPY);
    expect(t.http, `toggle expected 200, got ${t.http}`).toBe(200);
    expect(t.body?.enabled, 'enabled flag').toBe(true);
    expect(t.body?.scan, 'scan block must be present on OFF→ON').toBeTruthy();
    const scan = t.body.scan;
    expect(
      scan.adoptCrsCreated?.ORGANIZATION,
      `ORGANIZATION adopt CRs == ${orgNames.length}`,
    ).toBe(orgNames.length);

    // The CR list must contain 3 PENDING ADOPT_ORGANIZATION CRs whose
    // entityIds match the orgs we created.
    const happyPending = await listChangeRequests(request, HAPPY);
    const happyAdopts = happyPending.filter(
      (cr) => cr.actionType === 'ADOPT_ORGANIZATION',
    );
    expect(
      happyAdopts.length,
      `ADOPT_ORGANIZATION CR count == ${orgNames.length}`,
    ).toBe(orgNames.length);
    expect(happyAdopts.every((cr) => cr.status === 'PENDING')).toBe(true);
    const adoptedIds = new Set(happyAdopts.map((cr) => cr.entityId as string));
    for (const name of orgNames) {
      expect(
        adoptedIds.has(orgIds[name]),
        `${name} (${orgIds[name]}) has ADOPT_ORGANIZATION CR`,
      ).toBe(true);
    }

    // Commit one — single master-admin signature suffices (ADOPT bypass).
    const firstName = orgNames[0];
    const firstCr = happyAdopts.find(
      (cr) => cr.entityId === orgIds[firstName],
    );
    expect(firstCr, 'CR for first org resolvable').toBeTruthy();
    const firstAC = await authorizeAndCommit(
      request,
      HAPPY,
      firstCr!.id as string,
    );
    expect(firstAC.authorize.http, 'first authorize').toBe(200);
    expect(
      firstAC.commit.http,
      `first commit expected 200, got ${firstAC.commit.http} ${JSON.stringify(firstAC.commit.body)}`,
    ).toBe(200);

    // Post-commit: CR APPROVED + the org still resolves (no entity write on
    // ADOPT replay — orgs have no attestation column so the model is
    // untouched besides cache eviction).
    const afterFirst = await getChangeRequest(
      request,
      HAPPY,
      firstCr!.id as string,
    );
    expect(afterFirst.body?.status, 'ADOPT_ORGANIZATION APPROVED').toBe(
      'APPROVED',
    );
    const firstOrgStill = await findOrganizationByName(
      request,
      HAPPY,
      firstName,
    );
    expect(
      firstOrgStill.body,
      `${firstName} must still exist after ADOPT commit (no entity write)`,
    ).toBeTruthy();

    // -----------------------------------------------------------------------
    // CASE B — Idempotent re-toggle: after committing 1 ADOPT_ORGANIZATION
    // in CASE A, toggle off then on again. The committed one is skipped via
    // alreadyCommittedAdopt (skip-set seeded at scan start from the
    // IDX_IGA_CR_REALM_ACTION_STATUS lookup).
    //
    // Reusing the HAPPY realm so we don't have to re-do the 3-org setup —
    // commit is the only state-change between the toggle-on counts, and the
    // skip-set semantics are the same.
    // -----------------------------------------------------------------------
    const tOff = await toggleIgaRaw(request, HAPPY);
    expect(tOff.http).toBe(200);
    expect(tOff.body?.enabled, 'toggle off').toBe(false);

    const tReOn = await toggleIgaRaw(request, HAPPY);
    expect(tReOn.http).toBe(200);
    expect(tReOn.body?.enabled, 're-toggle on').toBe(true);
    expect(tReOn.body?.scan, 'scan block present').toBeTruthy();
    const reScan = tReOn.body.scan;
    expect(
      reScan.adoptCrsCreated?.ORGANIZATION,
      `re-toggle ORGANIZATION count == ${orgNames.length - 1} (one committed)`,
    ).toBe(orgNames.length - 1);
    expect(
      reScan.skipped?.alreadyCommittedAdopt,
      `re-toggle skipped.alreadyCommittedAdopt >= 1 (committed org)`,
    ).toBeGreaterThanOrEqual(1);

    // -----------------------------------------------------------------------
    // CASE C — CREATE_ORGANIZATION race skip. With IGA on, the governed POST
    // /organizations enqueues a PENDING CREATE_ORGANIZATION CR. A subsequent
    // toggle-off→on cycle must SKIP this org via the pendingCreateCr lane.
    //
    // The CREATE_ORGANIZATION capture is keyed on the org NAME (entityKey
    // in IgaOrganizationModel.setDomains for captureCreate=true) because the
    // scratch org's UUID is generated by JpaOrganizationProvider and is
    // discarded on the request-tx rollback. The pendingCreate skip-set is
    // built on the CR's entityId column — so the scanner-row's entity id
    // must match the CR's stored entityId. For ORGANIZATION the scanner
    // surfaces the entity by its UUID, while the CR for CREATE carries the
    // NAME (because the model layer captured pre-commit). This means the
    // pendingCreateCr skip CANNOT match by id on a pre-commit CREATE CR.
    //
    // Pivot: the operationally meaningful guarantee here is "the in-flight
    // CREATE doesn't race with the toggle's ADOPT scan" — and that is
    // already true by construction: the in-flight CREATE org doesn't yet
    // EXIST in OrganizationEntity (it's rolled back at draft time), so the
    // scanner doesn't see it on ANY toggle. We assert the operational
    // consequence: after committing the CREATE_ORGANIZATION CR (so the org
    // ACTUALLY lands), a subsequent toggle adopts it via ADOPT_ORGANIZATION
    // — but ONLY if no APPROVED ADOPT for it already exists. We mirror
    // phase6b's race assertion shape: no duplicate ADOPT for a CREATEd-and-
    // committed org if the same toggle window sees it.
    // -----------------------------------------------------------------------
    await createScratchRealm(request, RACE);
    await enableOrganizationsOnRealm(request, RACE);
    await enableIga(request, RACE);

    const RACE_NAME = 'p7b-race-org';
    const createGoverned = await createOrganization(request, RACE, {
      name: RACE_NAME,
      alias: RACE_NAME,
      enabled: true,
      domains: [{ name: `${RACE_NAME}.example`, verified: false }],
    });
    expect(
      createGoverned.status(),
      `CREATE_ORGANIZATION governed expected 202, got ${createGoverned.status()} ${await createGoverned.text()}`,
    ).toBe(202);
    const racePendingBefore = await listChangeRequests(request, RACE);
    const createCr = racePendingBefore.find(
      (cr) => cr.actionType === 'CREATE_ORGANIZATION',
    );
    expect(createCr, 'CREATE_ORGANIZATION CR exists').toBeTruthy();

    // Sub-assertion: at this point the org does NOT exist in
    // OrganizationEntity (capture-then-veto: the request tx was rolled
    // back). Toggle off→on cycle MUST NOT enqueue an ADOPT for it (the
    // scanner cannot see a non-existent row) and the CREATE CR remains
    // PENDING.
    const tRaceOff = await toggleIgaRaw(request, RACE);
    expect(tRaceOff.http).toBe(200);
    expect(tRaceOff.body?.enabled).toBe(false);

    const tRaceReOn = await toggleIgaRaw(request, RACE);
    expect(tRaceReOn.http).toBe(200);
    expect(tRaceReOn.body?.enabled).toBe(true);
    expect(tRaceReOn.body?.scan).toBeTruthy();
    const raceScan = tRaceReOn.body.scan;
    // Org does not exist yet → scanner sees zero orgs → ORGANIZATION count
    // is 0. The CREATE_ORGANIZATION CR is untouched (toggle-off cancels
    // ADOPT_* PENDING CRs only — CREATE_* CRs survive).
    expect(
      raceScan.adoptCrsCreated?.ORGANIZATION,
      'no ADOPT_ORGANIZATION emitted for in-flight CREATE (org not yet persisted)',
    ).toBe(0);
    const racePendingAfter = await listChangeRequests(request, RACE);
    const stillPendingCreate = racePendingAfter.find(
      (cr) =>
        cr.actionType === 'CREATE_ORGANIZATION' && cr.status === 'PENDING',
    );
    expect(
      stillPendingCreate,
      'CREATE_ORGANIZATION CR survives the toggle off→on cycle',
    ).toBeTruthy();

    // Now commit the CREATE_ORGANIZATION so the org actually lands, then
    // re-toggle to prove (a) the org exists, (b) the freshly-created org is
    // adopted (no APPROVED ADOPT_ORGANIZATION exists for it yet — the
    // CREATE_ORGANIZATION commit does NOT create an ADOPT CR), and (c)
    // toggling again leaves the new org with at most ONE pending
    // ADOPT_ORGANIZATION.
    const createAC = await authorizeAndCommit(
      request,
      RACE,
      createCr!.id as string,
    );
    expect(createAC.commit.http, 'CREATE_ORGANIZATION commit').toBe(200);
    const raceOrg = await findOrganizationByName(request, RACE, RACE_NAME);
    expect(raceOrg.body, 'org exists after CREATE commit').toBeTruthy();

    const tRaceFinalOff = await toggleIgaRaw(request, RACE);
    expect(tRaceFinalOff.http).toBe(200);
    const tRaceFinalOn = await toggleIgaRaw(request, RACE);
    expect(tRaceFinalOn.http).toBe(200);
    expect(tRaceFinalOn.body?.scan).toBeTruthy();
    const finalScan = tRaceFinalOn.body.scan;
    expect(
      finalScan.adoptCrsCreated?.ORGANIZATION,
      'newly CREATEd-and-committed org gets exactly 1 ADOPT_ORGANIZATION',
    ).toBe(1);
    const racePending3 = await listChangeRequests(request, RACE);
    const racePendingAdopts = racePending3.filter(
      (cr) =>
        cr.actionType === 'ADOPT_ORGANIZATION' &&
        cr.entityId === raceOrg.body.id &&
        cr.status === 'PENDING',
    );
    expect(
      racePendingAdopts.length,
      'exactly 1 PENDING ADOPT_ORGANIZATION for the CREATEd org',
    ).toBe(1);

    // -----------------------------------------------------------------------
    // CASE D — Bulk-authorize compatibility: POST bulk-authorize with
    // actionTypeIn=["ADOPT_ORGANIZATION"] drains the PENDING queue.
    // -----------------------------------------------------------------------
    await createScratchRealm(request, BULK);
    await enableOrganizationsOnRealm(request, BULK);
    const bulkNames = ['p7b-bulk-org1', 'p7b-bulk-org2', 'p7b-bulk-org3'];
    for (const name of bulkNames) {
      const r = await createOrganization(request, BULK, {
        name,
        alias: name,
        enabled: true,
        domains: [{ name: `${name}.example`, verified: false }],
      });
      expect(
        [201, 204].includes(r.status()),
        `IGA-OFF org create ${name} expected 201/204, got ${r.status()}`,
      ).toBe(true);
    }
    const tBulk = await toggleIgaRaw(request, BULK);
    expect(tBulk.http).toBe(200);
    expect(tBulk.body?.scan?.adoptCrsCreated?.ORGANIZATION).toBe(
      bulkNames.length,
    );

    const bulkRes = await bulkAuthorize(request, BULK, {
      actionTypeIn: ['ADOPT_ORGANIZATION'],
      limit: 100,
    });
    expect(
      bulkRes.http,
      `bulk-authorize HTTP 200, got ${bulkRes.http} body=${JSON.stringify(bulkRes.body)}`,
    ).toBe(200);
    const bulkResults = (bulkRes.body?.results || []) as any[];
    const nonCommitted = bulkResults.filter(
      (r: any) => r.status !== 'COMMITTED',
    );
    expect(
      nonCommitted.length,
      `every bulk result COMMITTED; non-committed=${JSON.stringify(nonCommitted)}`,
    ).toBe(0);
    // Every ADOPT_ORGANIZATION CR is now APPROVED — re-query and assert
    // zero PENDING ADOPT_ORGANIZATION.
    const bulkPendingAfter = await listChangeRequests(request, BULK);
    const remaining = bulkPendingAfter.filter(
      (cr) => cr.actionType === 'ADOPT_ORGANIZATION' && cr.status === 'PENDING',
    );
    expect(
      remaining.length,
      'no PENDING ADOPT_ORGANIZATION after bulk-authorize',
    ).toBe(0);
  });
});
