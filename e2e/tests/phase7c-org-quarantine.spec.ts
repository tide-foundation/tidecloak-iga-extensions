import { test, expect, APIRequestContext } from '@playwright/test';
import {
  createScratchRealm,
  deleteRealm,
  authorizeAndCommit,
  listChangeRequests,
  createOrganization,
  findOrganizationByName,
  getOrganization,
  safeJson,
  kcFetch,
} from '../lib/kc';
import { checkPrecondition, rerunCommand } from '../lib/precondition';

/**
 * Phase 7c — IGA quarantine override on IgaOrganizationModel.isEnabled.
 *
 * Phase 7b made the toggle-on scan emit a PENDING ADOPT_ORGANIZATION CR for
 * every pre-existing org and emit an IGA_UNSIGNED_ENTITY sidecar row pinning
 * the org until that CR commits. Phase 7c attaches the consequence: while
 * the sidecar exists, IgaOrganizationModel.isEnabled() returns false. That
 * single override cascades through KC's own four org-aware enforcement
 * points (Organizations.isReadOnlyOrganizationMember:290,
 * OrganizationAuthenticator.authenticate:215, IdpAddOrganizationMember-
 * Authenticator:82, RegistrationPage.validate:69 — all consult
 * org.isEnabled()) so org-scoped login, IdP-brokered org membership,
 * org-scoped registration, and managed-member writes all refuse until the
 * ADOPT commits.
 *
 * Cases (single test for atomic setup):
 *   A. Org becomes disabled on toggle — create realm + org with
 *      enabled=true and IGA OFF, toggle IGA on, assert
 *      GET /admin/realms/{r}/organizations/{orgId} returns enabled=false.
 *   B. Org regains enabled after ADOPT commits — authorize+commit the
 *      ADOPT_ORGANIZATION CR, assert GET ... returns enabled=true.
 *   C. IGA_REPLAY_ACTIVE bypass smoke (implicit in B): the commit path's
 *      replay traversal touches the org mid-replay while it's still
 *      nominally quarantined; the successful 200 commit proves the
 *      isOrganizationUnsigned primitive returns false under IGA_REPLAY_ACTIVE.
 *
 * Cascading-enforcement-point coverage (managed-member read-only, org-
 * scoped login refusal, IdP-brokered membership block, registration block)
 * is deferred to Phase 7d/7e — those require IdP federation / federated-
 * identity row setup that's out of scope for this unit-level enabled=false
 * flip. The single override demonstrated here is what every one of those
 * checkpoints consumes.
 */

const REALM = 'iga-phase7c-quarantine';
const RERUN =
  'cd /home/sasha/project/tidecloak-iga-extensions/e2e && npx playwright test phase7c-org-quarantine.spec.ts';

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
 * Turn on the KC organizations feature for the realm (POST /realms creates
 * the realm with organizationsEnabled=false by default; this PUT-update
 * flips it on BEFORE we start creating orgs). Identical to phase7a/7b.
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

test.describe('IGA Phase 7c: organization quarantine override (isEnabled)', () => {
  test.afterAll(async ({ request }) => {
    await deleteRealm(request, REALM).catch(() => {});
  });

  test('Phase 7c org quarantine: disabled on toggle, enabled after ADOPT commit', async ({
    request,
  }) => {
    // -----------------------------------------------------------------------
    // PRECONDITION GATE — proves the IGA jar is loaded.
    // -----------------------------------------------------------------------
    const pre = await checkPrecondition(request);
    console.log(
      `\n[PRECONDITION phase7c] verdict=${pre.verdict}\n  ${pre.detail}\n  evidence=${JSON.stringify(
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
    // Setup: scratch realm + organizations feature on, one org with
    // enabled=true while IGA is OFF.
    // -----------------------------------------------------------------------
    await createScratchRealm(request, REALM);
    await enableOrganizationsOnRealm(request, REALM);

    const ORG_NAME = 'p7c-quarantine-org';
    const createRes = await createOrganization(request, REALM, {
      name: ORG_NAME,
      alias: ORG_NAME,
      enabled: true,
      domains: [{ name: `${ORG_NAME}.example`, verified: false }],
    });
    expect(
      [201, 204].includes(createRes.status()),
      `IGA-OFF org create expected 201/204, got ${createRes.status()} ${await createRes.text()}`,
    ).toBe(true);

    const lookup = await findOrganizationByName(request, REALM, ORG_NAME);
    expect(lookup.body, `${ORG_NAME} resolves before toggle`).toBeTruthy();
    const orgId = lookup.body.id as string;
    expect(orgId, 'org id resolvable').toBeTruthy();

    // Sanity: pre-toggle the org is genuinely enabled.
    const preToggle = await getOrganization(request, REALM, orgId);
    expect(preToggle.http, 'GET org pre-toggle').toBe(200);
    expect(
      preToggle.body?.enabled,
      'org enabled=true before IGA toggle (IGA OFF, no quarantine override)',
    ).toBe(true);

    // -----------------------------------------------------------------------
    // CASE A — Org becomes disabled on toggle. The scan emits an
    // IGA_UNSIGNED_ENTITY sidecar row for this org; on the next admin GET,
    // IgaOrganizationModel.isEnabled returns false because
    // IgaQuarantineCache.isOrganizationUnsigned reports unsigned.
    // -----------------------------------------------------------------------
    const t = await toggleIgaRaw(request, REALM);
    expect(t.http, `toggle expected 200, got ${t.http}`).toBe(200);
    expect(t.body?.enabled, 'IGA enabled after toggle').toBe(true);
    expect(t.body?.scan, 'scan block must be present on OFF→ON').toBeTruthy();
    expect(
      t.body.scan.adoptCrsCreated?.ORGANIZATION,
      'exactly 1 ADOPT_ORGANIZATION CR emitted',
    ).toBe(1);

    const afterToggle = await getOrganization(request, REALM, orgId);
    expect(afterToggle.http, 'GET org after toggle').toBe(200);
    expect(
      afterToggle.body?.enabled,
      `org enabled flag must be FALSE after IGA toggle (quarantine override ` +
        `cascading from IgaOrganizationModel.isEnabled — sidecar row present, ` +
        `ADOPT_ORGANIZATION pending). got=${JSON.stringify(afterToggle.body?.enabled)}`,
    ).toBe(false);

    // -----------------------------------------------------------------------
    // CASE B — Org regains enabled after ADOPT commits. The
    // ADOPT_ORGANIZATION replay clears the sidecar and evicts the
    // CachedOrganization for this org id (IgaReplayExtension.evictCacheForAdopt
    // ADOPT_ORGANIZATION branch), so the next getById re-loads through the
    // IGA provider chain and the quarantine override observes the post-ADOPT
    // sidecar absence.
    // -----------------------------------------------------------------------
    const pending = await listChangeRequests(request, REALM);
    const adoptCr = pending.find(
      (cr) =>
        cr.actionType === 'ADOPT_ORGANIZATION' &&
        cr.entityId === orgId &&
        cr.status === 'PENDING',
    );
    expect(adoptCr, 'PENDING ADOPT_ORGANIZATION CR for this org').toBeTruthy();

    const ac = await authorizeAndCommit(request, REALM, adoptCr!.id as string);
    expect(ac.authorize.http, 'ADOPT authorize').toBe(200);
    expect(
      ac.commit.http,
      `ADOPT commit expected 200, got ${ac.commit.http} ${JSON.stringify(
        ac.commit.body,
      )} — CASE C (IGA_REPLAY_ACTIVE bypass smoke): the replay traversal ` +
        `must be able to touch this org mid-commit while it is still ` +
        `nominally quarantined; a non-200 here means the replay-active gate ` +
        `in isOrganizationUnsigned is not honoured.`,
    ).toBe(200);

    const afterCommit = await getOrganization(request, REALM, orgId);
    expect(afterCommit.http, 'GET org after ADOPT commit').toBe(200);
    expect(
      afterCommit.body?.enabled,
      `org enabled flag must be TRUE after ADOPT_ORGANIZATION commit ` +
        `(sidecar cleared + per-org cache evicted via registerInvalidation). ` +
        `got=${JSON.stringify(afterCommit.body?.enabled)}`,
    ).toBe(true);
  });
});
