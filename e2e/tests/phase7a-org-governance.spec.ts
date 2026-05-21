import { test, expect } from '@playwright/test';
import {
  createScratchRealm,
  deleteRealm,
  enableIga,
  igaStatus,
  createUser,
  getUserByUsername,
  getChangeRequest,
  authorizeAndCommit,
  locationHeader,
  safeJson,
  createOrganization,
  updateOrganization,
  deleteOrganization,
  getOrganization,
  findOrganizationByName,
  addOrgMemberById,
  removeOrgMember,
  getOrgMembers,
  inviteOrgMember,
  getOrgInvitations,
  resendOrgInvitation,
  createIdentityProvider,
  addOrgIdp,
  removeOrgIdp,
  getOrgIdps,
  kcFetch,
} from '../lib/kc';
import { checkPrecondition, rerunCommand } from '../lib/precondition';

/**
 * Phase 7a — wire-up + resend seam for organization governance.
 *
 * Production paths exercised (all in one realm, sequentially):
 *
 *   1. CREATE_ORGANIZATION   — POST {realm}/organizations
 *   2. UPDATE_ORGANIZATION   — PUT  {realm}/organizations/{id}
 *   3. DELETE_ORGANIZATION   — DELETE {realm}/organizations/{id}
 *   4. ADD_ORG_MEMBER        — POST {realm}/organizations/{id}/members
 *   5. REMOVE_ORG_MEMBER     — DELETE {realm}/organizations/{id}/members/{id}
 *   6. ORG_INVITE_MEMBER     — POST {realm}/organizations/{id}/members/invite-user
 *   7. ORG_ADD_IDP           — POST {realm}/organizations/{id}/identity-providers
 *   8. ORG_REMOVE_IDP        — DELETE {realm}/organizations/{id}/identity-providers/{alias}
 *   9. ORG_RESEND_INVITE     — POST {realm}/organizations/{id}/members/invitations/{id}/resend
 *
 * Each case sends the IGA-governed mutation, asserts HTTP 202 + Location, GETs
 * the PENDING CR and verifies actionType, then authorizes + commits and
 * verifies the post-commit state (org/member/invitation/idp link) via the
 * stock KC admin-REST GET endpoints. The Phase 7a wire-up fixes
 * (IgaOrganizationProvider.create signature + IgaOrganizationProviderFactory
 * order=20) make these interceptions reachable; pre-fix the same calls would
 * return KC's default 201/204 with no CR.
 *
 * Pure API E2E (no browser). Idempotent (afterAll deletes the realm).
 */

const REALM = 'iga-phase7a-org';

test.describe('IGA Phase 7a: organization governance wire-up + resend seam', () => {
  test.afterAll(async ({ request }) => {
    await deleteRealm(request, REALM).catch(() => {});
  });

  test('Phase 7a org governance: 9 action types end-to-end through replay', async ({
    request,
  }) => {
    // ---------------------------------------------------------------------
    // PRECONDITION GATE — re-uses the Phase 1 probe (proves jar is loaded).
    // A Phase 7a-specific precondition (e.g. probe POST /organizations and
    // assert 202) would only fire after the jar restart; the Phase 1 probe
    // is a strict subset (it requires the IGA capture seam to work) and
    // therefore an adequate load-signal here too.
    // ---------------------------------------------------------------------
    const pre = await checkPrecondition(request);
    console.log(
      `\n[PRECONDITION] verdict=${pre.verdict}\n  ${pre.detail}\n  evidence=${JSON.stringify(
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

    // ---------------------------------------------------------------------
    // 1. Scratch realm with organizations + admin-fine-grained features ON,
    //    pre-create a member user + IdP BEFORE enabling IGA so those bases
    //    aren't themselves governed.
    // ---------------------------------------------------------------------
    // KC's organizations feature must be enabled on the realm — POST /realms
    // creates it disabled by default. We PUT-update with organizationsEnabled.
    await createScratchRealm(request, REALM);
    {
      const getRealmRes = await kcFetch(request, `/admin/realms/${REALM}`);
      const realmRep = await safeJson(getRealmRes);
      const enableRes = await kcFetch(request, `/admin/realms/${REALM}`, {
        method: 'PUT',
        json: { ...realmRep, organizationsEnabled: true },
      });
      // KC accepts 204 No Content for the realm update.
      expect(
        enableRes.status(),
        `enable organizations feature on realm: HTTP ${enableRes.status()}`,
      ).toBe(204);
    }

    // Pre-create the member user that ADD_ORG_MEMBER will reference. Must
    // exist before IGA goes on (otherwise creating the user would itself
    // become a CREATE_USER CR — outside Phase 7a scope).
    const memberCreate = await createUser(request, REALM, {
      username: 'org-member',
      enabled: true,
      email: 'org-member@example.test',
      emailVerified: true,
      firstName: 'Org',
      lastName: 'Member',
    });
    expect(memberCreate.status(), 'pre-create member user').toBe(201);
    const memberLookup = await getUserByUsername(request, REALM, 'org-member');
    expect(memberLookup.http, 'member lookup').toBe(200);
    const memberId = memberLookup.body.id as string;
    expect(memberId, 'member id resolvable').toBeTruthy();

    // Pre-create an IdP that ORG_ADD_IDP / ORG_REMOVE_IDP will reference.
    const idpAlias = 'oidc-org-idp';
    const idpCreate = await createIdentityProvider(request, REALM, idpAlias);
    expect(idpCreate.status(), 'pre-create idp').toBe(201);

    // Flip IGA on.
    await enableIga(request, REALM);
    const st = await igaStatus(request, REALM);
    expect(st.enabled, 'IGA must be enabled').toBe(true);

    // ---------------------------------------------------------------------
    // 2. CREATE_ORGANIZATION — full rep with attributes + domains.
    // ---------------------------------------------------------------------
    const ORG_NAME = 'acme-corp';
    const ORG_ALIAS = 'acme';
    const createRes = await createOrganization(request, REALM, {
      name: ORG_NAME,
      alias: ORG_ALIAS,
      description: 'phase7a desc',
      enabled: true,
      domains: [{ name: 'acme.example', verified: false }],
      attributes: { team: ['blue'] },
    });
    expect(
      createRes.status(),
      `CREATE_ORGANIZATION governed expected 202, got ${createRes.status()} body=${await createRes.text()}`,
    ).toBe(202);
    const createLoc = locationHeader(createRes);
    expect(createLoc, 'CREATE 202 must carry Location').toBeTruthy();
    const createBody = await safeJson(createRes);
    const createCrId =
      (createBody && createBody.changeRequestId) ||
      (createLoc ? createLoc.split('/').pop() : '');
    expect(createCrId, 'CREATE CR id resolvable').toBeTruthy();

    {
      const cr = await getChangeRequest(request, REALM, createCrId);
      expect(cr.http, 'GET CREATE CR').toBe(200);
      expect(cr.body?.actionType, 'CREATE actionType').toBe(
        'CREATE_ORGANIZATION',
      );
      expect(cr.body?.status, 'CREATE CR PENDING').toBe('PENDING');
    }

    // Not yet persisted at draft time.
    {
      const orgDraft = await findOrganizationByName(request, REALM, ORG_NAME);
      expect(orgDraft.body, 'org must NOT exist before commit').toBeFalsy();
    }

    const createAC = await authorizeAndCommit(request, REALM, createCrId);
    expect(createAC.authorize.http, 'CREATE authorize').toBe(200);
    expect(
      createAC.commit.http,
      `CREATE commit expected 200, got ${createAC.commit.http} ${JSON.stringify(createAC.commit.body)}`,
    ).toBe(200);

    // Post-commit fidelity.
    const orgAfterCreate = await findOrganizationByName(
      request,
      REALM,
      ORG_NAME,
    );
    expect(orgAfterCreate.body, 'org must exist after commit').toBeTruthy();
    const orgId = orgAfterCreate.body.id as string;
    expect(orgId, 'org id resolvable').toBeTruthy();
    const orgFull = await getOrganization(request, REALM, orgId);
    expect(orgFull.http, 'GET org').toBe(200);
    expect(orgFull.body?.alias, 'alias fidelity').toBe(ORG_ALIAS);
    expect(orgFull.body?.description, 'description fidelity').toBe(
      'phase7a desc',
    );
    const domainNames = (orgFull.body?.domains || []).map((d: any) => d?.name);
    expect(domainNames, 'domain fidelity').toContain('acme.example');

    // ---------------------------------------------------------------------
    // 3. UPDATE_ORGANIZATION — add a domain, change description.
    // ---------------------------------------------------------------------
    const updatedRep = {
      ...orgFull.body,
      description: 'phase7a updated desc',
      domains: [
        { name: 'acme.example', verified: false },
        { name: 'acme-two.example', verified: false },
      ],
    };
    const updateRes = await updateOrganization(
      request,
      REALM,
      orgId,
      updatedRep,
    );
    expect(
      updateRes.status(),
      `UPDATE_ORGANIZATION governed expected 202, got ${updateRes.status()} body=${await updateRes.text()}`,
    ).toBe(202);
    const updateLoc = locationHeader(updateRes);
    expect(updateLoc, 'UPDATE 202 Location').toBeTruthy();
    const updateBody = await safeJson(updateRes);
    const updateCrId =
      (updateBody && updateBody.changeRequestId) ||
      (updateLoc ? updateLoc.split('/').pop() : '');
    {
      const cr = await getChangeRequest(request, REALM, updateCrId);
      expect(cr.http, 'GET UPDATE CR').toBe(200);
      expect(cr.body?.actionType, 'UPDATE actionType').toBe(
        'UPDATE_ORGANIZATION',
      );
    }
    const updateAC = await authorizeAndCommit(request, REALM, updateCrId);
    expect(updateAC.commit.http, 'UPDATE commit').toBe(200);
    {
      const after = await getOrganization(request, REALM, orgId);
      expect(after.body?.description, 'description after update').toBe(
        'phase7a updated desc',
      );
      const names = (after.body?.domains || []).map((d: any) => d?.name);
      expect(names, 'second domain present').toContain('acme-two.example');
    }

    // ---------------------------------------------------------------------
    // 4. ADD_ORG_MEMBER — pre-existing user becomes a member.
    // ---------------------------------------------------------------------
    const addMemRes = await addOrgMemberById(request, REALM, orgId, memberId);
    expect(
      addMemRes.status(),
      `ADD_ORG_MEMBER governed expected 202, got ${addMemRes.status()} body=${await addMemRes.text()}`,
    ).toBe(202);
    const addMemLoc = locationHeader(addMemRes);
    const addMemBody = await safeJson(addMemRes);
    const addMemCrId =
      (addMemBody && addMemBody.changeRequestId) ||
      (addMemLoc ? addMemLoc.split('/').pop() : '');
    {
      const cr = await getChangeRequest(request, REALM, addMemCrId);
      expect(cr.body?.actionType, 'ADD_ORG_MEMBER actionType').toBe(
        'ADD_ORG_MEMBER',
      );
    }
    const addMemAC = await authorizeAndCommit(request, REALM, addMemCrId);
    expect(addMemAC.commit.http, 'ADD_ORG_MEMBER commit').toBe(200);
    {
      const members = await getOrgMembers(request, REALM, orgId);
      expect(members.http, 'GET members').toBe(200);
      const ids = members.body.map((m: any) => m?.id);
      expect(ids, 'member appears after commit').toContain(memberId);
    }

    // ---------------------------------------------------------------------
    // 5. ORG_INVITE_MEMBER — invite a brand-new email.
    // ---------------------------------------------------------------------
    const INVITE_EMAIL = 'invitee@example.test';
    const inviteRes = await inviteOrgMember(
      request,
      REALM,
      orgId,
      INVITE_EMAIL,
      'Invi',
      'Tee',
    );
    expect(
      inviteRes.status(),
      `ORG_INVITE_MEMBER governed expected 202, got ${inviteRes.status()} body=${await inviteRes.text()}`,
    ).toBe(202);
    const inviteLoc = locationHeader(inviteRes);
    const inviteBody = await safeJson(inviteRes);
    const inviteCrId =
      (inviteBody && inviteBody.changeRequestId) ||
      (inviteLoc ? inviteLoc.split('/').pop() : '');
    {
      const cr = await getChangeRequest(request, REALM, inviteCrId);
      expect(cr.body?.actionType, 'INVITE actionType').toBe('ORG_INVITE_MEMBER');
    }
    // Pre-commit: no invitation persisted.
    {
      const invs = await getOrgInvitations(request, REALM, orgId);
      // KC's /invitations endpoint may be 404 if no invitations exist yet, or
      // 200 with empty list. Both acceptable; the load-bearing assertion is
      // that no email-matching invitation is present.
      const present = invs.body.some((i: any) => i?.email === INVITE_EMAIL);
      expect(present, 'invitation must NOT exist before commit').toBeFalsy();
    }
    const inviteAC = await authorizeAndCommit(request, REALM, inviteCrId);
    expect(inviteAC.commit.http, 'INVITE commit').toBe(200);
    // Post-commit: invitation exists. We don't assert the e-mail was sent
    // (no SMTP in localtest); the persisted row + invite link prove replay
    // ran KC's sendInvitation transcription.
    let invitationId: string | undefined;
    {
      const invs = await getOrgInvitations(request, REALM, orgId);
      expect(invs.http, 'GET invitations after commit').toBe(200);
      const inv = invs.body.find((i: any) => i?.email === INVITE_EMAIL);
      expect(inv, 'invitation present after commit').toBeTruthy();
      invitationId = inv?.id as string;
      expect(invitationId, 'invitation id resolvable').toBeTruthy();
    }

    // ---------------------------------------------------------------------
    // 6. ORG_RESEND_INVITE — KC's resend funnels through the same
    //    InvitationManager.create seam; IgaInvitationManager URI-sniffs the
    //    /resend suffix and emits ORG_RESEND_INVITE (not ORG_INVITE_MEMBER).
    //    Limitation: KC's resendInvitation calls invitationManager.remove(id)
    //    BEFORE the seam fires, so the prior invitation is deleted at request
    //    time. The CR's replay re-creates a fresh invitation with a new id.
    // ---------------------------------------------------------------------
    const resendRes = await resendOrgInvitation(
      request,
      REALM,
      orgId,
      invitationId!,
    );
    expect(
      resendRes.status(),
      `ORG_RESEND_INVITE governed expected 202, got ${resendRes.status()} body=${await resendRes.text()}`,
    ).toBe(202);
    const resendLoc = locationHeader(resendRes);
    const resendBody = await safeJson(resendRes);
    const resendCrId =
      (resendBody && resendBody.changeRequestId) ||
      (resendLoc ? resendLoc.split('/').pop() : '');
    {
      const cr = await getChangeRequest(request, REALM, resendCrId);
      expect(cr.body?.actionType, 'RESEND actionType').toBe(
        'ORG_RESEND_INVITE',
      );
    }
    const resendAC = await authorizeAndCommit(request, REALM, resendCrId);
    expect(resendAC.commit.http, 'RESEND commit').toBe(200);
    {
      const invs = await getOrgInvitations(request, REALM, orgId);
      expect(invs.http, 'GET invitations after resend commit').toBe(200);
      const inv = invs.body.find((i: any) => i?.email === INVITE_EMAIL);
      expect(inv, 'invitation present after resend commit').toBeTruthy();
      // New invitation id: KC's resendInvitation removed the old one before
      // our seam fired; replay re-created. We don't assert id !== prior
      // because KC's JpaInvitationManager could reuse the prior id; what we
      // DO assert is that an invitation for this email exists after resend.
    }

    // ---------------------------------------------------------------------
    // 7. ORG_ADD_IDP — link the pre-created IdP.
    // ---------------------------------------------------------------------
    const addIdpRes = await addOrgIdp(request, REALM, orgId, idpAlias);
    expect(
      addIdpRes.status(),
      `ORG_ADD_IDP governed expected 202, got ${addIdpRes.status()} body=${await addIdpRes.text()}`,
    ).toBe(202);
    const addIdpLoc = locationHeader(addIdpRes);
    const addIdpBody = await safeJson(addIdpRes);
    const addIdpCrId =
      (addIdpBody && addIdpBody.changeRequestId) ||
      (addIdpLoc ? addIdpLoc.split('/').pop() : '');
    {
      const cr = await getChangeRequest(request, REALM, addIdpCrId);
      expect(cr.body?.actionType, 'ORG_ADD_IDP actionType').toBe('ORG_ADD_IDP');
    }
    const addIdpAC = await authorizeAndCommit(request, REALM, addIdpCrId);
    expect(addIdpAC.commit.http, 'ORG_ADD_IDP commit').toBe(200);
    {
      const idps = await getOrgIdps(request, REALM, orgId);
      const aliases = idps.body.map((i: any) => i?.alias);
      expect(aliases, 'idp linked after commit').toContain(idpAlias);
    }

    // ---------------------------------------------------------------------
    // 8. ORG_REMOVE_IDP — unlink the IdP.
    // ---------------------------------------------------------------------
    const remIdpRes = await removeOrgIdp(request, REALM, orgId, idpAlias);
    expect(
      remIdpRes.status(),
      `ORG_REMOVE_IDP governed expected 202, got ${remIdpRes.status()} body=${await remIdpRes.text()}`,
    ).toBe(202);
    const remIdpLoc = locationHeader(remIdpRes);
    const remIdpBody = await safeJson(remIdpRes);
    const remIdpCrId =
      (remIdpBody && remIdpBody.changeRequestId) ||
      (remIdpLoc ? remIdpLoc.split('/').pop() : '');
    {
      const cr = await getChangeRequest(request, REALM, remIdpCrId);
      expect(cr.body?.actionType, 'ORG_REMOVE_IDP actionType').toBe(
        'ORG_REMOVE_IDP',
      );
    }
    const remIdpAC = await authorizeAndCommit(request, REALM, remIdpCrId);
    expect(remIdpAC.commit.http, 'ORG_REMOVE_IDP commit').toBe(200);
    {
      const idps = await getOrgIdps(request, REALM, orgId);
      const aliases = idps.body.map((i: any) => i?.alias);
      expect(aliases, 'idp unlinked after commit').not.toContain(idpAlias);
    }

    // ---------------------------------------------------------------------
    // 9. REMOVE_ORG_MEMBER — drop the member added in step 4.
    // ---------------------------------------------------------------------
    const remMemRes = await removeOrgMember(request, REALM, orgId, memberId);
    expect(
      remMemRes.status(),
      `REMOVE_ORG_MEMBER governed expected 202, got ${remMemRes.status()} body=${await remMemRes.text()}`,
    ).toBe(202);
    const remMemLoc = locationHeader(remMemRes);
    const remMemBody = await safeJson(remMemRes);
    const remMemCrId =
      (remMemBody && remMemBody.changeRequestId) ||
      (remMemLoc ? remMemLoc.split('/').pop() : '');
    {
      const cr = await getChangeRequest(request, REALM, remMemCrId);
      expect(cr.body?.actionType, 'REMOVE_ORG_MEMBER actionType').toBe(
        'REMOVE_ORG_MEMBER',
      );
    }
    const remMemAC = await authorizeAndCommit(request, REALM, remMemCrId);
    expect(remMemAC.commit.http, 'REMOVE_ORG_MEMBER commit').toBe(200);
    {
      const members = await getOrgMembers(request, REALM, orgId);
      const ids = members.body.map((m: any) => m?.id);
      expect(ids, 'member removed after commit').not.toContain(memberId);
    }

    // ---------------------------------------------------------------------
    // 10. DELETE_ORGANIZATION — last action so the assertion that the org
    //     no longer exists is unambiguous.
    // ---------------------------------------------------------------------
    const delRes = await deleteOrganization(request, REALM, orgId);
    expect(
      delRes.status(),
      `DELETE_ORGANIZATION governed expected 202, got ${delRes.status()} body=${await delRes.text()}`,
    ).toBe(202);
    const delLoc = locationHeader(delRes);
    const delBody = await safeJson(delRes);
    const delCrId =
      (delBody && delBody.changeRequestId) ||
      (delLoc ? delLoc.split('/').pop() : '');
    {
      const cr = await getChangeRequest(request, REALM, delCrId);
      expect(cr.body?.actionType, 'DELETE actionType').toBe(
        'DELETE_ORGANIZATION',
      );
    }
    const delAC = await authorizeAndCommit(request, REALM, delCrId);
    expect(delAC.commit.http, 'DELETE commit').toBe(200);
    {
      const after = await findOrganizationByName(request, REALM, ORG_NAME);
      expect(after.body, 'org removed after commit').toBeFalsy();
    }

    // ---------------------------------------------------------------------
    // 11. Cleanup.
    // ---------------------------------------------------------------------
    await deleteRealm(request, REALM);
  });
});
