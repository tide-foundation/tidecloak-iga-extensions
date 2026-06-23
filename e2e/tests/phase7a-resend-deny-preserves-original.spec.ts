import { test, expect } from '@playwright/test';
import {
  createScratchRealm,
  deleteRealm,
  enableIga,
  igaStatus,
  getChangeRequest,
  authorizeAndCommit,
  locationHeader,
  safeJson,
  createOrganization,
  findOrganizationByName,
  getOrganization,
  inviteOrgMember,
  getOrgInvitations,
  resendOrgInvitation,
  kcFetch,
} from '../lib/kc';
import { checkPrecondition, rerunCommand } from '../lib/precondition';

/**
 * Phase 7a follow-up — resend denial preserves the original invitation.
 *
 * Bug being asserted (fixed via Tide-side patch to
 * OrganizationInvitationResource.resendInvitation):
 *
 *   Stock KC's resendInvitation does
 *     invitationManager.remove(id);          // deletes original synchronously
 *     return inviteUser(email, fn, ln);      // re-creates -> IGA seam fires
 *   so the original invitation row is removed BEFORE the IGA seam
 *   (IgaInvitationManager.create) is reached. The seam then throws
 *   IgaPendingApprovalException (HTTP 202). If the operator later DENIES the
 *   resend change request, the original row is already gone — the invitation
 *   is silently lost.
 *
 * The patch swaps the order: create the new invitation FIRST so any
 * deferred-by-IGA exception propagates out before the original is removed.
 * On the IGA-defer path, the original row therefore remains intact and a
 * denial leaves the operator's invitation in place.
 *
 * Test flow:
 *   1. Scratch realm, IGA on, organization created (commit).
 *   2. ORG_INVITE_MEMBER for a fresh email (commit) -> capture the original
 *      invitation id and createdAt.
 *   3. ORG_RESEND_INVITE on that invitation -> 202 + CR PENDING.
 *   4. Pre-deny: assert the original invitation row STILL EXISTS (this is the
 *      fix's load-bearing pre-condition; the bug was that this row was
 *      deleted before the seam fired).
 *   5. POST /iga/change-requests/{id}/deny -> 204.
 *   6. Post-deny: re-list invitations. Assert the original row still exists
 *      with the same id and the same createdAt — proves the resend did not
 *      destructively mutate it and that no replay ran.
 *
 * Pure API E2E (no browser). Idempotent (afterAll deletes the realm).
 */

const REALM = 'iga-phase7a-resend-deny';

test.describe('IGA Phase 7a: resend denial preserves the original invitation', () => {
  test.afterAll(async ({ request }) => {
    await deleteRealm(request, REALM).catch(() => {});
  });

  test('resend -> deny leaves the original invitation row intact', async ({
    request,
  }) => {
    // -------------------------------------------------------------------
    // PRECONDITION GATE — re-uses the Phase 1 probe (proves jar is loaded).
    // -------------------------------------------------------------------
    const pre = await checkPrecondition(request);
    if (pre.verdict !== 'OK') {
      throw new Error(
        `PRECONDITION: IGA jar not loaded in the running container ` +
          `(verdict=${pre.verdict}: ${pre.detail}) — restart the container, ` +
          `then re-run: ${rerunCommand()}`,
      );
    }

    // -------------------------------------------------------------------
    // 1. Scratch realm with organizations on, IGA on.
    // -------------------------------------------------------------------
    await createScratchRealm(request, REALM);
    {
      const getRealmRes = await kcFetch(request, `/admin/realms/${REALM}`);
      const realmRep = await safeJson(getRealmRes);
      const enableRes = await kcFetch(request, `/admin/realms/${REALM}`, {
        method: 'PUT',
        json: { ...realmRep, organizationsEnabled: true },
      });
      expect(
        enableRes.status(),
        `enable organizations feature on realm: HTTP ${enableRes.status()}`,
      ).toBe(204);
    }
    await enableIga(request, REALM);
    const st = await igaStatus(request, REALM);
    expect(st.enabled, 'IGA must be enabled').toBe(true);

    // -------------------------------------------------------------------
    // 2. Create + commit an organization. We need the org to exist before
    //    we can invite into it; CREATE_ORGANIZATION itself is governed
    //    under IGA so we commit it first.
    // -------------------------------------------------------------------
    const ORG_NAME = 'resend-deny-org';
    const ORG_ALIAS = 'rdorg';
    const createRes = await createOrganization(request, REALM, {
      name: ORG_NAME,
      alias: ORG_ALIAS,
      description: 'phase7a resend-deny',
      enabled: true,
      domains: [{ name: 'rd.example', verified: false }],
    });
    expect(
      createRes.status(),
      `CREATE_ORGANIZATION expected 202, got ${createRes.status()}`,
    ).toBe(202);
    const createLoc = locationHeader(createRes);
    const createBody = await safeJson(createRes);
    const createCrId =
      (createBody && createBody.changeRequestId) ||
      (createLoc ? createLoc.split('/').pop() : '');
    const createAC = await authorizeAndCommit(request, REALM, createCrId);
    expect(createAC.commit.http, 'CREATE_ORGANIZATION commit').toBe(200);
    const orgLookup = await findOrganizationByName(request, REALM, ORG_NAME);
    const orgId = orgLookup.body.id as string;
    expect(orgId, 'org id resolvable').toBeTruthy();
    // sanity: org actually exists
    {
      const got = await getOrganization(request, REALM, orgId);
      expect(got.http, 'GET org').toBe(200);
    }

    // -------------------------------------------------------------------
    // 3. ORG_INVITE_MEMBER + commit -> snapshot the original invitation.
    // -------------------------------------------------------------------
    const INVITE_EMAIL = 'resend-deny-invitee@example.test';
    const inviteRes = await inviteOrgMember(
      request,
      REALM,
      orgId,
      INVITE_EMAIL,
      'Re',
      'Send',
    );
    expect(
      inviteRes.status(),
      `ORG_INVITE_MEMBER expected 202, got ${inviteRes.status()}`,
    ).toBe(202);
    const inviteLoc = locationHeader(inviteRes);
    const inviteBody = await safeJson(inviteRes);
    const inviteCrId =
      (inviteBody && inviteBody.changeRequestId) ||
      (inviteLoc ? inviteLoc.split('/').pop() : '');
    const inviteAC = await authorizeAndCommit(request, REALM, inviteCrId);
    expect(inviteAC.commit.http, 'ORG_INVITE_MEMBER commit').toBe(200);

    let originalId: string | undefined;
    let originalSentDate: number | undefined;
    let originalExpiresAt: number | undefined;
    {
      const invs = await getOrgInvitations(request, REALM, orgId);
      expect(invs.http, 'GET invitations after commit').toBe(200);
      const inv = invs.body.find((i: any) => i?.email === INVITE_EMAIL);
      expect(inv, 'original invitation present after commit').toBeTruthy();
      originalId = inv?.id as string;
      originalSentDate = inv?.sentDate as number;
      originalExpiresAt = inv?.expiresAt as number;
      expect(originalId, 'original invitation id resolvable').toBeTruthy();
    }

    // -------------------------------------------------------------------
    // 4. ORG_RESEND_INVITE -> 202 + CR PENDING. With the fix, the
    //    create-side seam fires BEFORE the original is removed, so the
    //    original row must still be present at this point.
    // -------------------------------------------------------------------
    const resendRes = await resendOrgInvitation(
      request,
      REALM,
      orgId,
      originalId!,
    );
    expect(
      resendRes.status(),
      `ORG_RESEND_INVITE expected 202 (IGA-deferred), got ${resendRes.status()} body=${await resendRes.text()}`,
    ).toBe(202);
    const resendLoc = locationHeader(resendRes);
    const resendBodyJson = await safeJson(resendRes);
    const resendCrId =
      (resendBodyJson && resendBodyJson.changeRequestId) ||
      (resendLoc ? resendLoc.split('/').pop() : '');
    expect(resendCrId, 'resend CR id resolvable').toBeTruthy();
    {
      const cr = await getChangeRequest(request, REALM, resendCrId);
      expect(cr.http, 'GET resend CR').toBe(200);
      expect(cr.body?.actionType, 'resend actionType').toBe(
        'ORG_RESEND_INVITE',
      );
      expect(cr.body?.status, 'resend CR PENDING').toBe('PENDING');
    }

    // Load-bearing pre-deny assertion (the fix's contract): the original
    // invitation row MUST still exist. Pre-fix, KC's
    // OrganizationInvitationResource.resendInvitation called
    // invitationManager.remove(id) synchronously before the IGA seam fired,
    // so this row would already be gone.
    {
      const invs = await getOrgInvitations(request, REALM, orgId);
      expect(invs.http, 'GET invitations after resend 202').toBe(200);
      const stillThere = invs.body.find((i: any) => i?.id === originalId);
      expect(
        stillThere,
        'original invitation must still exist between resend 202 and deny ' +
          '(the create-first ordering is what the Tide-side fix introduces; ' +
          'pre-fix this row would already be deleted)',
      ).toBeTruthy();
      // Defensive: should be the only invitation for this email at this
      // point — the IGA-defer path does not persist a new one until commit.
      const sameEmail = invs.body.filter(
        (i: any) => i?.email === INVITE_EMAIL,
      );
      expect(
        sameEmail.length,
        'exactly one invitation for the email pre-deny (no new row created on the defer path)',
      ).toBe(1);
    }

    // -------------------------------------------------------------------
    // 5. Deny the resend CR. POST /iga/change-requests/{id}/deny
    //    (IgaAdminResource.deny -> 204 No Content).
    // -------------------------------------------------------------------
    const denyRes = await kcFetch(
      request,
      `/admin/realms/${REALM}/iga/change-requests/${resendCrId}/deny`,
      { method: 'POST' },
    );
    expect(
      denyRes.status(),
      `deny expected 204, got ${denyRes.status()} body=${await denyRes.text()}`,
    ).toBe(204);
    {
      const cr = await getChangeRequest(request, REALM, resendCrId);
      expect(cr.http, 'GET resend CR after deny').toBe(200);
      expect(cr.body?.status, 'resend CR DENIED').toBe('DENIED');
    }

    // -------------------------------------------------------------------
    // 6. Post-deny: original invitation still present, unchanged. This is
    //    the bug the fix closes — pre-fix this assertion would fail because
    //    the original row was deleted at request time and no replay ran.
    // -------------------------------------------------------------------
    {
      const invs = await getOrgInvitations(request, REALM, orgId);
      expect(invs.http, 'GET invitations after deny').toBe(200);
      const inv = invs.body.find((i: any) => i?.id === originalId);
      expect(
        inv,
        'original invitation must survive a denied resend (this is the bug ' +
          'the Tide-side OrganizationInvitationResource.resendInvitation patch ' +
          'fixes)',
      ).toBeTruthy();
      // Identity-preservation: the same row, not a re-created one with the
      // same id by coincidence. sentDate + expiresAt are stamped at create
      // time in JpaInvitationManager and never updated, so they're stable
      // identifiers of the row.
      expect(inv?.email, 'original email preserved').toBe(INVITE_EMAIL);
      if (originalSentDate !== undefined) {
        expect(inv?.sentDate, 'original sentDate preserved').toBe(
          originalSentDate,
        );
      }
      if (originalExpiresAt !== undefined) {
        expect(inv?.expiresAt, 'original expiresAt preserved').toBe(
          originalExpiresAt,
        );
      }
      // And — no leaked duplicate from the defer path.
      const sameEmail = invs.body.filter(
        (i: any) => i?.email === INVITE_EMAIL,
      );
      expect(
        sameEmail.length,
        'exactly one invitation for the email after deny (no replay ran)',
      ).toBe(1);
    }
  });
});
