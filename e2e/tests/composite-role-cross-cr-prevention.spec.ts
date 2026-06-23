/**
 * Regression: composite-role-across-pending-CRs is structurally prevented.
 *
 * Hazard
 * ------
 * A user creates a child role under a governed realm (PENDING CR), then tries
 * to create a parent role whose `composites` reference that not-yet-committed
 * child. If nothing defended this, the parent CR would be accepted with a
 * dangling composite ref, and depending on commit order the link would either
 * silently fail to materialize or "self-heal" inconsistently.
 *
 * Two layers of defense (verified by the prior investigation)
 * -----------------------------------------------------------
 * 1) Keycloak pre-validation at POST time: KC's REST role layer eagerly
 *    resolves every referenced composite when materializing the parent role,
 *    and fast-fails with 404 "Realm/Client Role with name <x> does not exist"
 *    when any referenced role is missing. This fires at the original POST
 *    (before IGA can wrap it as a PENDING CR), so the hazardous parent CR
 *    can't even be created. KC source:
 *      - org.keycloak.services.resources.admin.RoleContainerResource:159-231
 *        (createRole POST handler & composite pre-validation)
 *      - org.keycloak.services.resources.admin.RoleResource:120-123
 *        (addComposites — fetches each composite and 404s on miss)
 *      - org.keycloak.models.utils.RepresentationToModel.importRoles:151-192
 *        (composite import resolves names → models; null = miss)
 *
 * 2) IGA replay log-and-skip on null: even if layer (1) is ever bypassed (e.g.
 *    a future KC change weakens the pre-validation, or a non-REST caller
 *    constructs a CR row directly), the CREATE_ROLE replay resolves each
 *    composite by name and, on null, logs at WARN and skips that one link
 *    instead of aborting the whole role create. IGA source:
 *      - org.tidecloak.iga.replay.IgaReplayDispatcher.replayCreateRole:331-365
 *
 * Together these two layers guarantee:
 *   - A composite link can NEVER be established to a role that doesn't
 *     already exist in KC at POST time; the parent POST 404s outright.
 *   - The user must commit the child FIRST, then POST the parent. The
 *     reverse-order sanity test (d) confirms this is the supported workflow.
 *
 * NOTE: If this spec ever starts failing, audit whether KC weakened the
 * pre-validation (RoleContainerResource / RoleResource / RepresentationToModel)
 * and update the IGA replay's null-handling (IgaReplayDispatcher.replayCreateRole)
 * accordingly.
 *
 * Variations under test
 *   (a) realm parent + realm child, child still PENDING → parent POST 404
 *   (b) realm parent + CLIENT child, child still PENDING → parent POST 404
 *   (c) CLIENT parent + realm child, child still PENDING → parent POST 404
 *   (d) realm parent + realm child, child committed FIRST → parent POST 202,
 *       composite link established after parent commit (supported workflow)
 */
import { test, expect } from '@playwright/test';
import {
  createScratchRealm,
  deleteRealm,
  enableIga,
  igaStatus,
  createRole,
  createClient,
  createClientRole,
  getRoleComposites,
  authorizeAndCommit,
  locationHeader,
  safeJson,
  RoleSpec,
} from '../lib/kc';

function crIdFrom(res: any, body: any): string {
  return (body && body.changeRequestId) || (locationHeader(res) || '').split('/').pop() || '';
}

function compositeNames(list: any[]): string[] {
  return (list || []).map((r) => r?.name).filter(Boolean);
}

const REALM_A = 'iga-cxcr-a';
const REALM_B = 'iga-cxcr-b';
const REALM_C = 'iga-cxcr-c';
const REALM_D = 'iga-cxcr-d';

test.describe.configure({ mode: 'serial' });

test.describe('regression: composite-role-across-pending-CRs prevention', () => {
  test.afterAll(async ({ request }) => {
    for (const r of [REALM_A, REALM_B, REALM_C, REALM_D]) {
      await deleteRealm(request, r).catch(() => {});
    }
  });

  test('(a) realm parent composite → realm child (still PENDING) is rejected 404 at POST', async ({ request }) => {
    await createScratchRealm(request, REALM_A);
    await enableIga(request, REALM_A);
    expect((await igaStatus(request, REALM_A)).enabled).toBe(true);

    // Child role (governed → PENDING CR, not yet in KC)
    const childRes = await createRole(request, REALM_A, { name: 'child' });
    const childBody = await safeJson(childRes);
    expect(childRes.status(), `child create status (body=${JSON.stringify(childBody)})`).toBe(202);

    // Parent POST with composite=[child] — KC pre-validation must 404
    const parentSpec: RoleSpec = {
      name: 'parent',
      composite: true,
      composites: { realm: ['child'] },
    };
    const parentRes = await createRole(request, REALM_A, parentSpec);
    const parentBody = await safeJson(parentRes);
    expect(
      parentRes.status(),
      `parent POST must 404 (KC pre-validation); body=${JSON.stringify(parentBody)}`,
    ).toBe(404);
    expect(JSON.stringify(parentBody)).toMatch(/Realm Role with name child does not exist/i);
  });

  test('(b) realm parent composite → CLIENT child (still PENDING) is rejected 404 at POST', async ({ request }) => {
    await createScratchRealm(request, REALM_B);
    // Create the owning client BEFORE enabling IGA so the client itself is ungoverned.
    const acmeUuid = await createClient(request, REALM_B, 'acme');
    expect(acmeUuid).toBeTruthy();
    await enableIga(request, REALM_B);
    expect((await igaStatus(request, REALM_B)).enabled).toBe(true);

    // Child = CLIENT role (governed → PENDING CR, not yet in KC)
    const childRes = await createClientRole(request, REALM_B, acmeUuid, { name: 'cchild' });
    const childBody = await safeJson(childRes);
    expect(childRes.status(), `client child status (body=${JSON.stringify(childBody)})`).toBe(202);

    // Parent = REALM role with composite client:acme=[cchild] — KC must 404
    const parentSpec: RoleSpec = {
      name: 'parent',
      composite: true,
      composites: { client: { acme: ['cchild'] } },
    };
    const parentRes = await createRole(request, REALM_B, parentSpec);
    const parentBody = await safeJson(parentRes);
    expect(
      parentRes.status(),
      `parent POST must 404 (KC pre-validation); body=${JSON.stringify(parentBody)}`,
    ).toBe(404);
    expect(JSON.stringify(parentBody)).toMatch(/Client Role with name cchild does not exist/i);
  });

  test('(c) CLIENT parent composite → realm child (still PENDING) is rejected 404 at POST', async ({ request }) => {
    await createScratchRealm(request, REALM_C);
    const acmeUuid = await createClient(request, REALM_C, 'acme');
    expect(acmeUuid).toBeTruthy();
    await enableIga(request, REALM_C);
    expect((await igaStatus(request, REALM_C)).enabled).toBe(true);

    // Child = REALM role (governed → PENDING CR, not yet in KC)
    const childRes = await createRole(request, REALM_C, { name: 'rchild' });
    const childBody = await safeJson(childRes);
    expect(childRes.status(), `realm child status (body=${JSON.stringify(childBody)})`).toBe(202);

    // Parent = CLIENT role with realm composites — KC must 404
    const parentSpec: RoleSpec = {
      name: 'cparent',
      composite: true,
      composites: { realm: ['rchild'] },
    };
    const parentRes = await createClientRole(request, REALM_C, acmeUuid, parentSpec);
    const parentBody = await safeJson(parentRes);
    expect(
      parentRes.status(),
      `client-parent POST must 404 (KC pre-validation); body=${JSON.stringify(parentBody)}`,
    ).toBe(404);
    expect(JSON.stringify(parentBody)).toMatch(/Realm Role with name rchild does not exist/i);
  });

  test('(d) sanity: child committed FIRST → parent POST 202 → composite link established', async ({ request }) => {
    await createScratchRealm(request, REALM_D);
    await enableIga(request, REALM_D);
    expect((await igaStatus(request, REALM_D)).enabled).toBe(true);

    // Child first
    const childRes = await createRole(request, REALM_D, { name: 'child' });
    const childBody = await safeJson(childRes);
    expect(childRes.status()).toBe(202);
    const childCr = crIdFrom(childRes, childBody);

    // Commit child so it materializes in KC
    await authorizeAndCommit(request, REALM_D, childCr);

    // Now POST the parent — child exists in KC, so this is accepted as a CR
    const parentSpec: RoleSpec = {
      name: 'parent',
      composite: true,
      composites: { realm: ['child'] },
    };
    const parentRes = await createRole(request, REALM_D, parentSpec);
    const parentBody = await safeJson(parentRes);
    expect(parentRes.status(), `parent POST status (body=${JSON.stringify(parentBody)})`).toBe(202);
    const parentCr = crIdFrom(parentRes, parentBody);

    await authorizeAndCommit(request, REALM_D, parentCr);

    const comps = await getRoleComposites(request, REALM_D, 'parent');
    expect(compositeNames(comps.body)).toContain('child');
  });
});
