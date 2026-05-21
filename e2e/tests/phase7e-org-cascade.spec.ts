import { test, expect, APIRequestContext } from '@playwright/test';
import {
  createScratchRealm,
  deleteRealm,
  authorizeAndCommit,
  listChangeRequests,
  createOrganization,
  findOrganizationByName,
  getOrganization,
  createUser,
  getUserByUsername,
  addOrgMemberById,
  getOrgMembers,
  safeJson,
  kcFetch,
} from '../lib/kc';
import { kcEnv } from '../lib/env';
import { checkPrecondition, rerunCommand } from '../lib/precondition';

/**
 * Phase 7e — cascading-enforcement E2E for the Phase 7c quarantine override.
 *
 * Phase 7c made {@code IgaOrganizationModel.isEnabled() → false} while an
 * unsigned {@code IGA_UNSIGNED_ENTITY} row exists for the org. Phase 7c
 * proved the flag flips (admin GET on the org returns {@code enabled=false}
 * after the toggle-on scan emits the ADOPT_ORGANIZATION sidecar, and flips
 * back after the ADOPT commits). Phase 7e proves the cascade has real teeth
 * end-to-end: a downstream consumer of {@code org.isEnabled()} observably
 * changes behaviour while quarantine is in force, and reverts once the
 * ADOPT_ORGANIZATION CR commits.
 *
 * Cascade-point coverage:
 *   ✓ (this spec) OrganizationMembershipMapper.resolveValue:159 — the OIDC
 *     org-membership mapper SKIPS organizations whose isEnabled() returns
 *     false (cross-checked at
 *     /home/sasha/project/tidecloak/services/src/main/java/org/keycloak/
 *       organization/protocol/mappers/oidc/OrganizationMembershipMapper.java
 *     :158-161):
 *
 *        for (OrganizationModel o : organizations) {
 *            if (o == null || !o.isEnabled() || user == null
 *                    || !o.isMember(user)) {
 *                continue;
 *            }
 *            ...
 *            value.put(o.getAlias(), claims);
 *        }
 *
 *     OrganizationScope.resolveOrganizations:196 is a second filter on the
 *     same isEnabled() property (the scope is consumed inside the mapper
 *     via resolveFromRequestedScopes:144); either filter suffices on its
 *     own and both observe the Phase 7c quarantine override.
 *
 *   ◇ (source-grounded, NOT exercised here) The four cascade points the
 *     Phase 7c report cited:
 *
 *     1. Organizations.isReadOnlyOrganizationMember:290 (managed members go
 *        read-only) — requires a UserGroupMembership row with
 *        MembershipType=MANAGED, which is only ever set by
 *        IdpAddOrganizationMemberAuthenticator.authenticate:63
 *        (provider.addManagedMember(...)). KC 26.5.5 exposes NO admin REST
 *        endpoint that creates a managed membership — OrganizationMember
 *        Resource.addMember:108 always calls addMember(...) (unmanaged).
 *        End-to-end exercise of this branch requires a real IdP-broker
 *        login flow (Selenium / Playwright UI driver against a federated
 *        IdP server) which is out of scope for the REST-only harness.
 *
 *     2. OrganizationAuthenticator.authenticate:215 (org-aware browser
 *        login refused) — requires the org-aware browser auth flow; needs
 *        a UI driver.
 *
 *     3. IdpAddOrganizationMemberAuthenticator:82 (IdP-brokered org
 *        membership blocked) — requires a real IdP-broker login.
 *
 *     4. RegistrationPage.validate:69 (org-scoped registration blocked) —
 *        requires parsing an InviteOrgActionToken from the request, i.e.
 *        the full UI registration flow.
 *
 *     All four read the same {@code org.isEnabled()} primitive the mapper
 *     reads, so the cascade demonstrated below is representative of the
 *     entire family: the IgaOrganizationModel.isEnabled override is what
 *     every one of those checkpoints consumes.
 *
 * Test shape (single atomic test):
 *   A. Pre-toggle setup. Create a realm with the KC organizations feature
 *      on, create one org {@code o-cascade}, one user {@code u-cascade},
 *      add the user as an (unmanaged) org member, create a confidential
 *      direct-grant client {@code c-cascade} with full scope. Confirm
 *      pre-IGA the access token issued with {@code scope=openid
 *      organization} carries the {@code organization} claim with
 *      {@code o-cascade}'s alias.
 *   B. Toggle IGA on. The Phase 7b scan emits a PENDING ADOPT_ORGANIZATION
 *      CR for o-cascade plus ADOPT_USER for u-cascade plus ADOPT_CLIENT
 *      for c-cascade. Commit ADOPT_USER and ADOPT_CLIENT (so the user/
 *      client are not quarantined and direct-grant proceeds); LEAVE
 *      ADOPT_ORGANIZATION pending. The org is now in the quarantine state
 *      Phase 7c overrides: IgaOrganizationModel.isEnabled returns false.
 *   C. Cascade observation. Get a fresh token with scope=openid
 *      organization. The OrganizationMembershipMapper.resolveValue skip
 *      condition fires on the disabled org → the {@code organization}
 *      claim is ABSENT (or empty) from the issued access_token. This is
 *      the cascading enforcement: org.isEnabled() observably changes
 *      downstream behaviour, not just the admin-REST GET payload.
 *   D. Lift. Authorize + commit ADOPT_ORGANIZATION. The replay clears the
 *      sidecar and evicts the per-org cache entry via
 *      CacheRealmProvider.registerInvalidation(orgId). A fresh token
 *      request now carries the organization claim again — the cascade
 *      reverts when the override is removed.
 */

const REALM = 'iga-phase7e-cascade';
const RERUN =
  'cd /home/sasha/project/tidecloak-iga-extensions/e2e && npx playwright test phase7e-org-cascade.spec.ts';

const ORG_NAME = 'o-cascade';
const ORG_ALIAS = 'o-cascade';
const USERNAME = 'u-cascade';
const USER_PW = 'pw-u-cascade';
const CLIENT_ID = 'c-cascade';
const CLIENT_SECRET = 'secret-c-cascade';

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
 * Turn on the KC organizations feature for the realm (POST /realms creates the
 * realm with organizationsEnabled=false by default; this PUT-update flips it on
 * BEFORE we start creating orgs). Identical to phase7a/7b/7c/7d.
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

/** PUT /admin/realms/{r}/users/{u}/reset-password — set a permanent password. */
async function setPassword(
  request: APIRequestContext,
  realm: string,
  userId: string,
  password: string,
): Promise<void> {
  const res = await kcFetch(
    request,
    `/admin/realms/${realm}/users/${userId}/reset-password`,
    {
      method: 'PUT',
      json: { type: 'password', value: password, temporary: false },
    },
  );
  expect(
    res.status(),
    `setPassword(${userId}) expected 204, got ${res.status()}`,
  ).toBe(204);
}

/** Clear required actions + emailVerified=true so direct-grant doesn't 400. */
async function finalizeUser(
  request: APIRequestContext,
  realm: string,
  userId: string,
): Promise<void> {
  const lookupRes = await kcFetch(
    request,
    `/admin/realms/${realm}/users/${userId}`,
  );
  const rep = (await safeJson(lookupRes)) || {};
  rep.requiredActions = [];
  rep.emailVerified = true;
  const putRes = await kcFetch(
    request,
    `/admin/realms/${realm}/users/${userId}`,
    { method: 'PUT', json: rep },
  );
  expect(
    putRes.status(),
    `finalizeUser(${userId}) expected 204, got ${putRes.status()}`,
  ).toBe(204);
}

/**
 * Create a confidential, full-scope, direct-grant-enabled client with the
 * stock {@code organization} client-scope assigned as an OPTIONAL default
 * scope so a {@code scope=openid organization} token request makes the
 * OrganizationMembershipMapper fire on the issued access_token. The
 * organization client-scope is auto-created by KC when the organizations
 * feature is enabled on the realm (OIDCLoginProtocolFactory.java:338-347)
 * and is wired to OrganizationMembershipMapper.create(...).
 *
 * Deliberately omits the {@code client.use.lightweight.access.token.enabled}
 * attribute so the stock org mapper actually attaches the claim to the
 * access token (lightweight tokens drop stock OIDC mappers — see the same
 * footnote in {@link phase6c-quarantine.spec.ts}).
 */
async function createConfidentialDirectGrantClient(
  request: APIRequestContext,
  realm: string,
  clientId: string,
  secret: string,
): Promise<void> {
  const res = await kcFetch(request, `/admin/realms/${realm}/clients`, {
    method: 'POST',
    json: {
      clientId,
      enabled: true,
      publicClient: false,
      fullScopeAllowed: true,
      directAccessGrantsEnabled: true,
      standardFlowEnabled: false,
      serviceAccountsEnabled: false,
      secret,
      clientAuthenticatorType: 'client-secret',
    },
  });
  expect(
    res.status(),
    `createConfidentialDirectGrantClient(${clientId}) expected 201, got ${res.status()}: ${await res.text()}`,
  ).toBe(201);
}

/**
 * Direct-grant (Resource Owner Password) against a specific confidential
 * client requesting {@code scope=openid organization} so the stock OIDC
 * OrganizationMembershipMapper fires on the issued access_token.
 */
async function directGrantWithOrgScope(
  request: APIRequestContext,
  realm: string,
  clientId: string,
  clientSecret: string,
  username: string,
  password: string,
): Promise<{ http: number; body: any }> {
  const { baseUrl } = kcEnv();
  const res = await request.post(
    `${baseUrl}/realms/${realm}/protocol/openid-connect/token`,
    {
      form: {
        grant_type: 'password',
        client_id: clientId,
        client_secret: clientSecret,
        username,
        password,
        scope: 'openid organization',
      },
    },
  );
  return { http: res.status(), body: await safeJson(res) };
}

/** Decode a JWT payload (no signature verification). */
function decodeJwtPayload(token: string): Record<string, unknown> {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Not a JWT');
  const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
  const pad = payload.length % 4 === 0 ? '' : '='.repeat(4 - (payload.length % 4));
  return JSON.parse(Buffer.from(payload + pad, 'base64').toString('utf8'));
}

/**
 * Inspect an OIDC access_token "organization" claim. The stock KC mapper
 * (OrganizationMembershipMapper.create at OrganizationMembershipMapper.java
 * :234-248) defaults to JSON_TYPE="String" + MULTIVALUED=true, so the claim
 * is a JSON array of aliases (e.g. {@code ["o-cascade"]}). If the mapper is
 * reconfigured to JSON, the claim is an object map keyed by alias. We accept
 * either shape — both observe the {@code !o.isEnabled()} filter at
 * OrganizationMembershipMapper.resolveValue:159 identically.
 *
 * Returns:
 *   "absent"   — claim is undefined/null OR an empty container
 *   "present"  — claim is a non-empty array OR non-empty object
 *   "wrong"    — claim is present but does not contain the expected alias
 *                (rare: indicates the user is a member of more orgs than
 *                expected; treat as test setup drift)
 */
function inspectOrgClaim(
  payload: Record<string, unknown>,
  expectedAlias: string,
): { state: 'absent' | 'present' | 'wrong'; raw: unknown } {
  const raw = payload.organization;
  if (raw === undefined || raw === null) return { state: 'absent', raw };
  if (Array.isArray(raw)) {
    if (raw.length === 0) return { state: 'absent', raw };
    return raw.includes(expectedAlias)
      ? { state: 'present', raw }
      : { state: 'wrong', raw };
  }
  if (typeof raw === 'object') {
    const keys = Object.keys(raw as Record<string, unknown>);
    if (keys.length === 0) return { state: 'absent', raw };
    return keys.includes(expectedAlias)
      ? { state: 'present', raw }
      : { state: 'wrong', raw };
  }
  // String claim shape (single-valued mapper); compare directly.
  if (typeof raw === 'string') {
    return raw === expectedAlias
      ? { state: 'present', raw }
      : { state: 'wrong', raw };
  }
  return { state: 'wrong', raw };
}

/** Find a PENDING CR by action + entity id. */
async function findPendingCrFor(
  request: APIRequestContext,
  realm: string,
  actionType: string,
  entityId: string,
): Promise<{ id: string } | undefined> {
  const pending = await listChangeRequests(request, realm, 'PENDING');
  const cr = pending.find(
    (c) => c.actionType === actionType && c.entityId === entityId,
  );
  return cr ? { id: cr.id } : undefined;
}

test.describe('IGA Phase 7e: org quarantine cascade (E2E)', () => {
  test.afterAll(async ({ request }) => {
    await deleteRealm(request, REALM).catch(() => {});
  });

  test('Phase 7e cascade: org-membership claim disappears while ADOPT_ORGANIZATION is pending', async ({
    request,
  }) => {
    // -----------------------------------------------------------------------
    // PRECONDITION GATE — proves the IGA jar is loaded.
    // -----------------------------------------------------------------------
    const pre = await checkPrecondition(request);
    console.log(
      `\n[PRECONDITION phase7e] verdict=${pre.verdict}\n  ${pre.detail}\n  evidence=${JSON.stringify(
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
    // CASE A — pre-IGA setup + baseline claim assertion.
    // -----------------------------------------------------------------------
    await createScratchRealm(request, REALM);
    await enableOrganizationsOnRealm(request, REALM);

    // Create org with enabled=true, IGA OFF.
    const orgCreate = await createOrganization(request, REALM, {
      name: ORG_NAME,
      alias: ORG_ALIAS,
      enabled: true,
      domains: [{ name: `${ORG_NAME}.example`, verified: false }],
    });
    expect(
      [201, 204].includes(orgCreate.status()),
      `IGA-OFF org create expected 201/204, got ${orgCreate.status()} ${await orgCreate.text()}`,
    ).toBe(true);
    const orgLookup = await findOrganizationByName(request, REALM, ORG_NAME);
    const orgId = orgLookup.body?.id as string;
    expect(orgId, 'org id resolvable pre-toggle').toBeTruthy();

    // Create user + finalize for direct grant.
    const userCreate = await createUser(request, REALM, {
      username: USERNAME,
      enabled: true,
      emailVerified: true,
      email: `${USERNAME}@example.test`,
      firstName: 'U',
      lastName: 'Cascade',
    });
    expect(
      userCreate.status(),
      `IGA-OFF user create expected 201, got ${userCreate.status()}`,
    ).toBe(201);
    const userLookup = await getUserByUsername(request, REALM, USERNAME);
    const userId = userLookup.body?.id as string;
    expect(userId, 'user id resolvable pre-toggle').toBeTruthy();
    await setPassword(request, REALM, userId, USER_PW);
    await finalizeUser(request, REALM, userId);

    // Add user as an UNMANAGED org member (the only kind admin REST creates;
    // see the deferred-cascade discussion at the top of this file).
    const addMemberRes = await addOrgMemberById(request, REALM, orgId, userId);
    expect(
      [201, 204].includes(addMemberRes.status()),
      `IGA-OFF addOrgMemberById expected 201/204, got ${addMemberRes.status()} ${await addMemberRes.text()}`,
    ).toBe(true);
    const memberCheck = await getOrgMembers(request, REALM, orgId);
    expect(
      memberCheck.body.some((m) => m?.id === userId),
      'user is a member of the org pre-toggle',
    ).toBe(true);

    // Create confidential direct-grant client with org scope auto-attached.
    await createConfidentialDirectGrantClient(
      request,
      REALM,
      CLIENT_ID,
      CLIENT_SECRET,
    );

    // Pre-IGA baseline: token with scope=openid organization carries the
    // organization claim. This proves the mapper is wired and the cascade
    // observation we use is real (not a false negative caused by missing
    // client-scope wiring).
    const preTok = await directGrantWithOrgScope(
      request,
      REALM,
      CLIENT_ID,
      CLIENT_SECRET,
      USERNAME,
      USER_PW,
    );
    expect(
      preTok.http,
      `pre-IGA direct-grant expected 200, got ${preTok.http} ${JSON.stringify(preTok.body)}`,
    ).toBe(200);
    const preAt = preTok.body?.access_token as string;
    expect(preAt, 'pre-IGA access_token issued').toBeTruthy();
    const prePayload = decodeJwtPayload(preAt);
    const preInspect = inspectOrgClaim(prePayload, ORG_ALIAS);
    expect(
      preInspect.state,
      `pre-IGA access_token MUST carry an "organization" claim containing ` +
        `alias=${ORG_ALIAS} (mapper wiring sanity — if absent, the test would ` +
        `silently pass the post-toggle absence assertion). Got state=` +
        `${preInspect.state} raw=${JSON.stringify(preInspect.raw)} ` +
        `payload.keys=${Object.keys(prePayload).join(',')}`,
    ).toBe('present');

    // -----------------------------------------------------------------------
    // CASE B — toggle IGA on, lift user + client quarantine, leave org
    // quarantine in force. Three ADOPT_* CRs are expected (USER + CLIENT +
    // ORGANIZATION); the scan response confirms each was emitted.
    // -----------------------------------------------------------------------
    const t = await toggleIgaRaw(request, REALM);
    expect(t.http, `toggle expected 200, got ${t.http}`).toBe(200);
    expect(t.body?.enabled, 'IGA enabled after toggle').toBe(true);
    expect(t.body?.scan, 'scan block must be present on OFF→ON').toBeTruthy();
    expect(
      t.body.scan.adoptCrsCreated?.ORGANIZATION,
      'exactly 1 ADOPT_ORGANIZATION CR emitted',
    ).toBe(1);
    expect(
      t.body.scan.adoptCrsCreated?.USER,
      'exactly 1 ADOPT_USER CR emitted (for u-cascade)',
    ).toBe(1);
    expect(
      t.body.scan.adoptCrsCreated?.CLIENT,
      'exactly 1 ADOPT_CLIENT CR emitted (for c-cascade)',
    ).toBe(1);

    // Commit ADOPT_USER so the user is no longer quarantined (direct-grant
    // would otherwise refuse with 400/401 — that's the Phase 6c USER hook,
    // not the Phase 7e org cascade we're trying to observe).
    const adoptUser = await findPendingCrFor(
      request,
      REALM,
      'ADOPT_USER',
      userId,
    );
    expect(adoptUser, 'PENDING ADOPT_USER CR for u-cascade').toBeTruthy();
    const acUser = await authorizeAndCommit(request, REALM, adoptUser!.id);
    expect(acUser.authorize.http, 'ADOPT_USER authorize').toBe(200);
    expect(acUser.commit.http, 'ADOPT_USER commit').toBe(200);

    // Commit ADOPT_CLIENT so the token endpoint accepts the client (the
    // Phase 6c CLIENT hook would otherwise reject c-cascade with
    // 401 "Invalid client").
    const clientLookup = await kcFetch(
      request,
      `/admin/realms/${REALM}/clients?clientId=${CLIENT_ID}`,
    );
    const clientList = await safeJson(clientLookup);
    const clientUuid = Array.isArray(clientList) && clientList[0]?.id;
    expect(clientUuid, 'c-cascade client UUID resolvable').toBeTruthy();
    const adoptClient = await findPendingCrFor(
      request,
      REALM,
      'ADOPT_CLIENT',
      clientUuid as string,
    );
    expect(adoptClient, 'PENDING ADOPT_CLIENT CR for c-cascade').toBeTruthy();
    const acClient = await authorizeAndCommit(request, REALM, adoptClient!.id);
    expect(acClient.authorize.http, 'ADOPT_CLIENT authorize').toBe(200);
    expect(acClient.commit.http, 'ADOPT_CLIENT commit').toBe(200);

    // Sanity: org STILL reports enabled=false (the Phase 7c override is in
    // force; this is the same admin-REST observation Phase 7c made).
    const orgWhileQuarantined = await getOrganization(request, REALM, orgId);
    expect(orgWhileQuarantined.http, 'GET org while quarantined').toBe(200);
    expect(
      orgWhileQuarantined.body?.enabled,
      `org.enabled must be FALSE while ADOPT_ORGANIZATION is PENDING; ` +
        `got ${JSON.stringify(orgWhileQuarantined.body?.enabled)}`,
    ).toBe(false);

    // -----------------------------------------------------------------------
    // CASE C — cascade observation. With user + client adopted, the direct-
    // grant token endpoint is otherwise unblocked. The remaining quarantine
    // is on the org: IgaOrganizationModel.isEnabled() returns false →
    // OrganizationMembershipMapper.resolveValue:159 skips the org →
    // organization claim is ABSENT (or empty) from the issued access_token.
    // -----------------------------------------------------------------------
    const quarTok = await directGrantWithOrgScope(
      request,
      REALM,
      CLIENT_ID,
      CLIENT_SECRET,
      USERNAME,
      USER_PW,
    );
    expect(
      quarTok.http,
      `direct-grant while org-quarantined expected 200 (user+client adopted), got ` +
        `${quarTok.http} ${JSON.stringify(quarTok.body)}`,
    ).toBe(200);
    const quarAt = quarTok.body?.access_token as string;
    expect(quarAt, 'access_token issued while org quarantined').toBeTruthy();
    const quarPayload = decodeJwtPayload(quarAt);

    // The cascade primitive: the org claim must NOT appear (mapper returns
    // null from resolveValue when every org in the candidate set is filtered
    // by !o.isEnabled(), and OIDCAttributeMapperHelper.mapClaim returns
    // early without writing the claim).
    const quarInspect = inspectOrgClaim(quarPayload, ORG_ALIAS);
    expect(
      quarInspect.state,
      `Phase 7e cascade observation FAILED. With ADOPT_ORGANIZATION still ` +
        `PENDING the OrganizationMembershipMapper.resolveValue skip ` +
        `condition (!o.isEnabled()) should suppress the "organization" ` +
        `claim on the issued access_token. Got state=${quarInspect.state} ` +
        `raw=${JSON.stringify(quarInspect.raw)} payload.keys=` +
        `${Object.keys(quarPayload).join(',')}. If the claim is present ` +
        `with the org alias, IgaOrganizationModel.isEnabled is not driving ` +
        `the mapper — verify the IGA org provider is wired (factory order ` +
        `>= 20) and the quarantine cache observes the sidecar.`,
    ).toBe('absent');

    // -----------------------------------------------------------------------
    // CASE D — lift the cascade. Commit ADOPT_ORGANIZATION → sidecar cleared,
    // per-org cache entry evicted (registerInvalidation(orgId)). Fresh token
    // re-acquires the organization claim.
    // -----------------------------------------------------------------------
    const adoptOrg = await findPendingCrFor(
      request,
      REALM,
      'ADOPT_ORGANIZATION',
      orgId,
    );
    expect(adoptOrg, 'PENDING ADOPT_ORGANIZATION CR for o-cascade').toBeTruthy();
    const acOrg = await authorizeAndCommit(request, REALM, adoptOrg!.id);
    expect(acOrg.authorize.http, 'ADOPT_ORGANIZATION authorize').toBe(200);
    expect(
      acOrg.commit.http,
      `ADOPT_ORGANIZATION commit expected 200, got ${acOrg.commit.http} ${JSON.stringify(
        acOrg.commit.body,
      )} (IGA_REPLAY_ACTIVE bypass must let the replay touch the still-` +
        `nominally-quarantined org mid-commit).`,
    ).toBe(200);

    // Sanity: org is enabled again.
    const orgAfter = await getOrganization(request, REALM, orgId);
    expect(orgAfter.http, 'GET org after ADOPT_ORGANIZATION commit').toBe(200);
    expect(
      orgAfter.body?.enabled,
      'org.enabled must be TRUE after ADOPT_ORGANIZATION commits',
    ).toBe(true);

    // Cascade reverts: fresh token carries the organization claim again.
    const postTok = await directGrantWithOrgScope(
      request,
      REALM,
      CLIENT_ID,
      CLIENT_SECRET,
      USERNAME,
      USER_PW,
    );
    expect(postTok.http, 'post-ADOPT direct-grant').toBe(200);
    const postAt = postTok.body?.access_token as string;
    expect(postAt, 'post-ADOPT access_token').toBeTruthy();
    const postPayload = decodeJwtPayload(postAt);
    const postInspect = inspectOrgClaim(postPayload, ORG_ALIAS);
    expect(
      postInspect.state,
      `post-ADOPT organization claim MUST be present and contain alias=` +
        `${ORG_ALIAS} (cascade lifted). Got state=${postInspect.state} ` +
        `raw=${JSON.stringify(postInspect.raw)} payload.keys=` +
        `${Object.keys(postPayload).join(',')}`,
    ).toBe('present');
  });
});
