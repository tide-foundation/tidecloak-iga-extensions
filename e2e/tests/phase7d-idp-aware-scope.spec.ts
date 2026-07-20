import { test, expect, APIRequestContext } from '@playwright/test';
import {
  createScratchRealm,
  deleteRealm,
  enableIga,
  createRole,
  createOrganization,
  findOrganizationByName,
  getOrganization,
  createIdentityProvider,
  addOrgIdp,
  removeOrgIdp,
  getOrgIdps,
  authorizeAndCommit,
  authorizeAs,
  commitAs,
  createAdminWithRoles,
  userTokenFor,
  getChangeRequestStatus,
  listChangeRequests,
  locationHeader,
  safeJson,
  kcFetch,
} from '../lib/kc';
import { checkPrecondition, rerunCommand } from '../lib/precondition';

/**
 * Phase 7d — IdP-aware scope resolver for ORG_ADD_IDP / ORG_REMOVE_IDP.
 *
 * Source-of-truth (line refs verified against the resolver source):
 *
 *   IgaScopeResolver.resolve (iga-core/.../attestors/IgaScopeResolver.java
 *     :174-188 after Phase 7d):
 *       case "ORG_ADD_IDP":
 *       case "ORG_REMOVE_IDP":
 *           resolveOrganizationScopesFromRows(session, realm, cr, scope, "ORG_ID");
 *           resolveIdpScopesFromRows(session, realm, cr, scope, "IDP_ALIAS");
 *           break;
 *
 *   collectIdpScope reads iga.approverRole / iga.threshold off
 *   IdentityProviderModel.getConfig() (server-spi:208 — `Map<String,String>`),
 *   conditional on approver-role being set (same convention as
 *   collectOrganizationScope / collectClientScope: per-entity threshold is
 *   only collected when the entity also carries an approver-role attribute).
 *
 * Scope-merge semantics (ResolvedScope is shared across both helpers):
 *   - requiredApproverRoles: UNION of org's + IdP's approver-role values
 *     (scope mode default = "any" so a single match satisfies the gate).
 *   - thresholds: MAX of all collected thresholds (resolveThresholdInternal
 *     :280-298 takes the max across scope.thresholds; the realm-level
 *     iga.threshold is only the fallback when scope.thresholds is empty).
 *
 * Cases (single atomic test):
 *   A. ADOPT_ORGANIZATION on toggle-on is unaffected by Phase 7d — commits
 *      with master admin (threshold=1, no approver-role check), proving the
 *      resolver extension short-circuits at IgaReplayExtension.isAdoptAction.
 *   B. ORG_ADD_IDP merges org + IdP scope: requiredApproverRoles=UNION,
 *      threshold=MAX(2,3)=3. admin-without-role authorize → 403; 2-of-3
 *      sigs commit → 412 PRECONDITION_FAILED; 3-of-3 sigs commit → 200.
 *   C. ORG_REMOVE_IDP mirrors B — same gate fires on the remove path; the
 *      negative admin still 403s, the positive admin commits cleanly.
 *
 * Pure API E2E. Idempotent (afterAll deletes the realm).
 */

const REALM = 'iga-phase7d';

const PW = 'p7d-admin-pw';

const ORG_APPROVER_ROLE = 'p7d-org-approver';
const IDP_APPROVER_ROLE = 'p7d-idp-approver';

const ORG_NAME = 'org-a';
const ORG_ALIAS = 'org-a';
const IDP_ALIAS = 'idp-a';

/** Turn on KC's organizations feature on the realm (default OFF post-create). */
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

/**
 * Merge keys into an IdP's `config` map via PUT
 * /admin/realms/{realm}/identity-provider/instances/{alias}. KC's
 * IdentityProviderResource.update accepts the full IdentityProviderRepresentation
 * and the resulting model.config is what IgaScopeResolver.collectIdpScope reads.
 * We GET-then-merge to preserve existing config (clientId/clientSecret/etc).
 */
async function setIdpConfig(
  request: APIRequestContext,
  realm: string,
  alias: string,
  patch: Record<string, string>,
): Promise<void> {
  const getRes = await kcFetch(
    request,
    `/admin/realms/${realm}/identity-provider/instances/${alias}`,
  );
  expect(getRes.status(), `GET IdP ${alias}`).toBe(200);
  const rep = (await safeJson(getRes)) || {};
  const merged = { ...(rep.config || {}), ...patch };
  const putRes = await kcFetch(
    request,
    `/admin/realms/${realm}/identity-provider/instances/${alias}`,
    {
      method: 'PUT',
      json: { ...rep, config: merged },
    },
  );
  expect(
    putRes.status(),
    `PUT IdP ${alias} expected 204, got HTTP ${putRes.status()}: ${await putRes.text()}`,
  ).toBe(204);
}

/**
 * Find the most recent PENDING CR of a given action type. Used to look up the
 * Phase 7b toggle-on ADOPT_ORGANIZATION CR (which doesn't return its id via
 * any API call — it's emitted as a side-effect of the toggle).
 */
async function latestPendingByAction(
  request: APIRequestContext,
  realm: string,
  actionType: string,
): Promise<string | undefined> {
  const list = await listChangeRequests(request, realm, 'PENDING');
  for (const cr of list as any[]) {
    if (cr?.actionType === actionType) return cr.id as string;
  }
  return undefined;
}

test.describe('IGA Phase 7d: IdP-aware scope resolver for ORG_ADD_IDP / ORG_REMOVE_IDP', () => {
  test.afterAll(async ({ request }) => {
    await deleteRealm(request, REALM).catch(() => {});
  });

  test('Phase 7d IdP-aware scope: ADOPT bypass + threshold MAX(org,idp) + ORG_REMOVE_IDP mirror', async ({
    request,
  }) => {
    // -----------------------------------------------------------------------
    // PRECONDITION GATE — proves the IGA jar is loaded.
    // -----------------------------------------------------------------------
    const pre = await checkPrecondition(request);
    if (pre.verdict !== 'OK') {
      throw new Error(
        `PRECONDITION: IGA jar not loaded (verdict=${pre.verdict}: ${pre.detail}) — restart then re-run: ${rerunCommand()}`,
      );
    }

    // -----------------------------------------------------------------------
    // 1. Scratch realm, orgs feature ON, pre-IGA bases:
    //      - Org-A: iga.approverRole=ORG_APPROVER_ROLE, iga.threshold=2
    //      - Idp-A: iga.approverRole=IDP_APPROVER_ROLE, iga.threshold=3
    //      - 3 admins each holding both approver roles
    //        (scopeMode default "any" → either role on the user satisfies
    //        the UNION; we put both on each admin so all 3 are valid signers).
    //      - 1 admin-without-role to assert the negative gate (403).
    //
    //    All bases created BEFORE enableIga so they don't themselves trigger
    //    governed CRs.
    // -----------------------------------------------------------------------
    await createScratchRealm(request, REALM);
    await enableOrganizationsOnRealm(request, REALM);

    const orgApproverRes = await createRole(request, REALM, {
      name: ORG_APPROVER_ROLE,
    });
    expect(orgApproverRes.status(), `create ${ORG_APPROVER_ROLE}`).toBe(201);
    const idpApproverRes = await createRole(request, REALM, {
      name: IDP_APPROVER_ROLE,
    });
    expect(idpApproverRes.status(), `create ${IDP_APPROVER_ROLE}`).toBe(201);

    // Org with iga.approverRole + iga.threshold=2.
    const orgCreate = await createOrganization(request, REALM, {
      name: ORG_NAME,
      alias: ORG_ALIAS,
      enabled: true,
      domains: [{ name: 'org-a.example', verified: false }],
      attributes: {
        'iga.approverRole': [ORG_APPROVER_ROLE],
        'iga.threshold': ['2'],
      },
    });
    expect(orgCreate.status(), 'pre-create org-a w/ attrs').toBe(201);
    const orgLookup = await findOrganizationByName(request, REALM, ORG_NAME);
    expect(orgLookup.body, 'org-a lookup').toBeTruthy();
    const orgId = orgLookup.body.id as string;

    // IdP with iga.approverRole + iga.threshold=3 (the dominant threshold).
    // Create THEN PUT-merge the iga.* config keys.
    const idpCreate = await createIdentityProvider(request, REALM, IDP_ALIAS);
    expect(idpCreate.status(), 'pre-create idp-a').toBe(201);
    await setIdpConfig(request, REALM, IDP_ALIAS, {
      'iga.approverRole': IDP_APPROVER_ROLE,
      'iga.threshold': '3',
    });

    // Three valid admins (each holds both approver roles → satisfies the
    // UNION in scopeMode=any) + one negative admin (manage-realm only).
    await createAdminWithRoles(request, REALM, 'admin-1', PW, [
      ORG_APPROVER_ROLE,
      IDP_APPROVER_ROLE,
    ]);
    await createAdminWithRoles(request, REALM, 'admin-2', PW, [
      ORG_APPROVER_ROLE,
      IDP_APPROVER_ROLE,
    ]);
    await createAdminWithRoles(request, REALM, 'admin-3', PW, [
      ORG_APPROVER_ROLE,
      IDP_APPROVER_ROLE,
    ]);
    await createAdminWithRoles(request, REALM, 'admin-without-role', PW, []);

    // -----------------------------------------------------------------------
    // 2. Flip IGA ON — fires the Phase 7b toggle-on scan; org-a gets an
    //    ADOPT_ORGANIZATION CR with the ADOPT bypass (threshold=1, no
    //    approver-role check). Commit it with the master admin to leave
    //    quarantine. This proves the Phase 7d resolver extension still
    //    short-circuits at isAdoptAction (Case A).
    // -----------------------------------------------------------------------
    await enableIga(request, REALM);

    {
      const adoptCrId = await latestPendingByAction(
        request,
        REALM,
        'ADOPT_ORGANIZATION',
      );
      expect(
        adoptCrId,
        'ADOPT_ORGANIZATION CR emitted by Phase 7b toggle-on scan',
      ).toBeTruthy();

      const st = await getChangeRequestStatus(request, REALM, adoptCrId!);
      // ADOPT bypass: rep.threshold=1 regardless of org scope (even though
      // the org carries iga.threshold=2). Proves the IGA-resolver/threshold
      // gate's ADOPT short-circuit still wins after the Phase 7d extension.
      expect(
        st.threshold,
        `ADOPT_ORGANIZATION must report threshold=1 (ADOPT bypass), got ${st.threshold}`,
      ).toBe(1);

      const adoptAC = await authorizeAndCommit(request, REALM, adoptCrId!);
      expect(
        adoptAC.commit.http,
        `ADOPT_ORGANIZATION commit expected 200 (bypass — no approver-role check), got ${adoptAC.commit.http}`,
      ).toBe(200);

      const orgAfter = await getOrganization(request, REALM, orgId);
      expect(orgAfter.body?.enabled, 'org-a enabled after ADOPT commit').toBe(
        true,
      );
    }

    // -----------------------------------------------------------------------
    // 3. ORG_ADD_IDP — resolver merges org + IdP scope contributions.
    //
    //    Expected resolved scope:
    //      requiredApproverRoles = UNION({ORG_APPROVER_ROLE},{IDP_APPROVER_ROLE})
    //      threshold             = MAX(2, 3) = 3
    //
    //    Negative gate first: admin-without-role authorize → 403.
    //    Then 2-of-3 sigs → commit 412 PRECONDITION_FAILED, 3-of-3 sigs → 200.
    // -----------------------------------------------------------------------
    const addIdpRes = await addOrgIdp(request, REALM, orgId, IDP_ALIAS);
    expect(
      addIdpRes.status(),
      `ORG_ADD_IDP governed expected 202, got ${addIdpRes.status()} body=${await addIdpRes.text()}`,
    ).toBe(202);
    const addIdpLoc = locationHeader(addIdpRes);
    const addIdpBody = await safeJson(addIdpRes);
    const addIdpCrId =
      (addIdpBody && addIdpBody.changeRequestId) ||
      (addIdpLoc ? addIdpLoc.split('/').pop() : '');
    expect(addIdpCrId, 'ORG_ADD_IDP CR id resolvable').toBeTruthy();

    // CR rep mirrors what the resolver computes (toRepresentation:1778-1788).
    {
      const st = await getChangeRequestStatus(request, REALM, addIdpCrId);
      expect(st.body?.actionType, 'ORG_ADD_IDP action').toBe('ORG_ADD_IDP');
      expect(
        st.threshold,
        `merged threshold must be MAX(org=2, idp=3)=3, got ${st.threshold}`,
      ).toBe(3);
      const required = (st.requiredApproverRoles ?? []).slice().sort();
      expect(
        required,
        `requiredApproverRoles must be UNION of org+idp approver roles, got ${JSON.stringify(required)}`,
      ).toEqual([IDP_APPROVER_ROLE, ORG_APPROVER_ROLE].sort());
      expect(st.scopeMode, 'scopeMode default "any"').toBe('any');
    }

    // Negative — admin-without-role authorize → 403 ForbiddenException.
    const withoutTok = await userTokenFor(
      request,
      REALM,
      'admin-without-role',
      PW,
    );
    {
      const reject = await authorizeAs(request, REALM, addIdpCrId, withoutTok);
      expect(
        reject.http,
        `admin-without-role authorize on ORG_ADD_IDP must 403, got ${reject.http} ${JSON.stringify(reject.body)}`,
      ).toBe(403);

      const stAfter = await getChangeRequestStatus(request, REALM, addIdpCrId);
      expect(
        stAfter.authCount,
        `authCount unchanged after rejected authorize, got ${stAfter.authCount}`,
      ).toBe(0);

      const commitReject = await commitAs(
        request,
        REALM,
        addIdpCrId,
        withoutTok,
      );
      expect(
        commitReject.http,
        `admin-without-role commit on ORG_ADD_IDP must 403, got ${commitReject.http}`,
      ).toBe(403);
    }

    // Positive — 2-of-3 sigs must NOT be enough (threshold=3 from MAX).
    const tok1 = await userTokenFor(request, REALM, 'admin-1', PW);
    const tok2 = await userTokenFor(request, REALM, 'admin-2', PW);
    const tok3 = await userTokenFor(request, REALM, 'admin-3', PW);

    {
      const a1 = await authorizeAs(request, REALM, addIdpCrId, tok1);
      expect(a1.http, 'authorize admin-1').toBe(200);
      const a2 = await authorizeAs(request, REALM, addIdpCrId, tok2);
      expect(a2.http, 'authorize admin-2').toBe(200);

      const c2 = await commitAs(request, REALM, addIdpCrId, tok2);
      expect(
        c2.http,
        `commit at 2-of-3 sigs must be 412 PRECONDITION_FAILED (threshold=3), got ${c2.http} ${JSON.stringify(c2.body)}`,
      ).toBe(412);

      const st = await getChangeRequestStatus(request, REALM, addIdpCrId);
      expect(st.authCount, 'authCount=2 after 2 authorizes').toBe(2);
      expect(st.readyToCommit, 'readyToCommit=false at 2/3').toBe(false);

      const a3 = await authorizeAs(request, REALM, addIdpCrId, tok3);
      expect(a3.http, 'authorize admin-3').toBe(200);
      const c3 = await commitAs(request, REALM, addIdpCrId, tok3);
      expect(
        c3.http,
        `commit at 3-of-3 sigs expected 200, got ${c3.http} ${JSON.stringify(c3.body)}`,
      ).toBe(200);
    }

    {
      const idps = await getOrgIdps(request, REALM, orgId);
      const linked = idps.body.find(
        (i: any) => i?.alias === IDP_ALIAS && i?.organizationId === orgId,
      );
      expect(linked, 'idp-a linked to org-a after 3-sig commit').toBeTruthy();
    }

    // -----------------------------------------------------------------------
    // 4. ORG_REMOVE_IDP — mirrors the same gate. The CR is created BEFORE
    //    the IdP is detached in DB (recordIdp throws IgaPendingApprovalException
    //    so KC's removeIdentityProvider call returns 202 with the row carrying
    //    IDP_ALIAS — the resolver can still walk the IdP's config at CR-create
    //    time AND at commit time; the IdP stays attached until commit).
    //
    //    Same expected resolved scope as ORG_ADD_IDP (threshold=3, UNION
    //    approver roles). Negative admin 403s; positive 3-of-3 commits.
    // -----------------------------------------------------------------------
    const remIdpRes = await removeOrgIdp(request, REALM, orgId, IDP_ALIAS);
    expect(
      remIdpRes.status(),
      `ORG_REMOVE_IDP governed expected 202, got ${remIdpRes.status()}`,
    ).toBe(202);
    const remIdpLoc = locationHeader(remIdpRes);
    const remIdpBody = await safeJson(remIdpRes);
    const remIdpCrId =
      (remIdpBody && remIdpBody.changeRequestId) ||
      (remIdpLoc ? remIdpLoc.split('/').pop() : '');
    expect(remIdpCrId, 'ORG_REMOVE_IDP CR id resolvable').toBeTruthy();

    {
      const st = await getChangeRequestStatus(request, REALM, remIdpCrId);
      expect(st.body?.actionType, 'ORG_REMOVE_IDP action').toBe(
        'ORG_REMOVE_IDP',
      );
      expect(
        st.threshold,
        `ORG_REMOVE_IDP merged threshold must be MAX(2,3)=3, got ${st.threshold}`,
      ).toBe(3);
      const required = (st.requiredApproverRoles ?? []).slice().sort();
      expect(required, 'ORG_REMOVE_IDP requiredApproverRoles UNION').toEqual(
        [IDP_APPROVER_ROLE, ORG_APPROVER_ROLE].sort(),
      );
    }

    // Negative — admin-without-role authorize on REMOVE → 403.
    {
      const reject = await authorizeAs(request, REALM, remIdpCrId, withoutTok);
      expect(
        reject.http,
        `admin-without-role authorize on ORG_REMOVE_IDP must 403, got ${reject.http}`,
      ).toBe(403);
    }

    // Positive — 3-of-3 sigs → commit succeeds.
    {
      const a1 = await authorizeAs(request, REALM, remIdpCrId, tok1);
      expect(a1.http, 'authorize admin-1 (remove)').toBe(200);
      const a2 = await authorizeAs(request, REALM, remIdpCrId, tok2);
      expect(a2.http, 'authorize admin-2 (remove)').toBe(200);
      const a3 = await authorizeAs(request, REALM, remIdpCrId, tok3);
      expect(a3.http, 'authorize admin-3 (remove)').toBe(200);
      const c = await commitAs(request, REALM, remIdpCrId, tok3);
      expect(
        c.http,
        `commit ORG_REMOVE_IDP at 3-of-3 expected 200, got ${c.http} ${JSON.stringify(c.body)}`,
      ).toBe(200);
    }

    // After ORG_REMOVE_IDP commit, the IdP's organizationId is cleared.
    {
      const idps = await getOrgIdps(request, REALM, orgId);
      const stillLinked = idps.body.some(
        (i: any) => i?.alias === IDP_ALIAS && i?.organizationId === orgId,
      );
      expect(stillLinked, 'idp-a unlinked from org-a after commit').toBeFalsy();
    }
  });
});
