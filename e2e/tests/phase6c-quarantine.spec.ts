import { test, expect, APIRequestContext } from '@playwright/test';
import {
  adminToken,
  createScratchRealm,
  deleteRealm,
  enableIga,
  igaStatus,
  createUser,
  getUserByUsername,
  createRole,
  getRole,
  createClient,
  clientUuid,
  createClientScope,
  getClientScopeByName,
  getChangeRequest,
  findChangeRequest,
  authorizeAndCommit,
  directGrantToken,
  locationHeader,
  safeJson,
  kcFetch,
  assignRealmRoleMapping,
} from '../lib/kc';
import { kcEnv } from '../lib/env';

/**
 * Phase 6c — quarantine hooks.
 *
 * Until an ADOPT_X CR commits, the entity is "unsigned" and KC operations
 * must be blocked:
 *   USER          → login/token fails hard (user.isEnabled() → false).
 *   USER w/ROLE   → user holding an unsigned role is also refused
 *                   (HARD refuse per locked design — NOT silent strip).
 *   CLIENT        → client-auth / client_credentials request refuses.
 *   GROUP         → group memberships and roles-through-group silently
 *                   stripped from token mapping (token still issues).
 *   CLIENT_SCOPE  → protocol mappers on the scope contribute nothing
 *                   (silent strip from token).
 *
 * The IGA_REPLAY_ACTIVE gate's correctness is implicit in EVERY case's
 * commit step succeeding: if the gate didn't fire, the replay would try
 * to touch the still-unsigned entity through a guard that refused
 * touching unsigned entities, and the commit would fail. Every test
 * below asserts the post-commit success state explicitly.
 *
 * Pure API E2E. Idempotent (scratch realms torn down in afterAll).
 *
 * Precondition gate: same shape as phase6a — a governed user create on a
 * probe realm must 202 + carry a CREATE_USER CR with REP_JSON, proving the
 * provider jar is loaded.
 */

const REALM_USER = 'iga-phase6c-user-e2e';
const REALM_ROLE = 'iga-phase6c-role-e2e';
const REALM_CLIENT = 'iga-phase6c-client-e2e';
const REALM_GROUP = 'iga-phase6c-group-e2e';
const REALM_SCOPE = 'iga-phase6c-scope-e2e';
const PROBE_REALM = 'iga-phase6c-precond-probe';
const RERUN =
  'cd /home/sasha/project/tidecloak-iga-extensions/e2e && npx playwright test';

/** Set a user password (admin reset, temporary=false). */
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
  if (res.status() !== 204) {
    throw new Error(
      `setPassword(${userId}) expected 204, got ${res.status()}: ${await res.text()}`,
    );
  }
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
  if (putRes.status() !== 204) {
    throw new Error(
      `finalizeUser(${userId}) expected 204, got ${putRes.status()}: ${await putRes.text()}`,
    );
  }
}

/** client_credentials grant against a confidential client. */
async function clientCredentialsToken(
  request: APIRequestContext,
  realm: string,
  clientId: string,
  clientSecret: string,
): Promise<{ http: number; body: any }> {
  const { baseUrl } = kcEnv();
  const res = await request.post(
    `${baseUrl}/realms/${realm}/protocol/openid-connect/token`,
    {
      form: {
        grant_type: 'client_credentials',
        client_id: clientId,
        client_secret: clientSecret,
      },
    },
  );
  return { http: res.status(), body: await safeJson(res) };
}

/** Decode the access_token JWT payload (no signature verification). */
function decodeJwtPayload(token: string): Record<string, unknown> {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Not a JWT');
  const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
  const pad = payload.length % 4 === 0 ? '' : '='.repeat(4 - (payload.length % 4));
  return JSON.parse(Buffer.from(payload + pad, 'base64').toString('utf8'));
}

/** Find an ADOPT_X CR for a specific entity (action + entityId). */
async function findAdoptCr(
  request: APIRequestContext,
  realm: string,
  actionType: string,
  entityId: string,
): Promise<string | undefined> {
  const cr = await findChangeRequest(
    request,
    realm,
    actionType,
    (c) => c.entityId === entityId,
  );
  return cr?.id;
}

/**
 * Wait for the toggle-on scan to surface a CR for the given entity. The scan
 * runs inline with the toggle request so a 200 on toggle-iga is sufficient,
 * but as a defensive measure (the scan transaction is separate from the
 * outer request tx) we retry the find a few times.
 */
async function waitForAdoptCr(
  request: APIRequestContext,
  realm: string,
  actionType: string,
  entityId: string,
  timeoutMs = 5000,
): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const id = await findAdoptCr(request, realm, actionType, entityId);
    if (id) return id;
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(
    `Timed out waiting for ${actionType} CR for ${entityId} in ${realm}`,
  );
}

test.describe('IGA Phase 6c: quarantine hooks block unsigned entities', () => {
  test.afterAll(async ({ request }) => {
    await deleteRealm(request, REALM_USER).catch(() => {});
    await deleteRealm(request, REALM_ROLE).catch(() => {});
    await deleteRealm(request, REALM_CLIENT).catch(() => {});
    await deleteRealm(request, REALM_GROUP).catch(() => {});
    await deleteRealm(request, REALM_SCOPE).catch(() => {});
    await deleteRealm(request, PROBE_REALM).catch(() => {});
  });

  test('Phase 6c quarantine: user / role / client / group / scope', async ({
    request,
  }) => {
    // -----------------------------------------------------------------------
    // PRECONDITION GATE — governed user create on probe realm must 202.
    // -----------------------------------------------------------------------
    const pre = await (async () => {
      const evidence: Record<string, unknown> = {};
      try {
        await createScratchRealm(request, PROBE_REALM);
        await enableIga(request, PROBE_REALM);
        evidence.igaEnabled = true;
        const res = await createUser(request, PROBE_REALM, {
          username: 'probe-user',
          enabled: true,
          email: 'probe-user@example.test',
        });
        const status = res.status();
        const loc = locationHeader(res);
        evidence.governedCreateStatus = status;
        evidence.governedCreateLocation = loc ?? null;
        if (status !== 202 || !loc) {
          return {
            ok: false as const,
            loaded: false as const,
            detail:
              status === 500
                ? 'governed user create returned 500 (provider jar likely not loaded)'
                : status === 201
                  ? 'governed user create returned 201 (IGA capture NOT intercepting)'
                  : `governed user create returned ${status} (expected 202 + Location)`,
            evidence,
          };
        }
        return {
          ok: true as const,
          loaded: true as const,
          detail: 'phase6c-loaded',
          evidence,
        };
      } catch (e: any) {
        return {
          ok: false as const,
          loaded: false as const,
          detail: `Probe raised: ${e?.message ?? e}`,
          evidence,
        };
      } finally {
        await deleteRealm(request, PROBE_REALM).catch(() => {});
      }
    })();
    console.log(
      `\n[PRECONDITION phase6c] ok=${pre.ok} detail=${pre.detail}\n  evidence=${JSON.stringify(
        pre.evidence,
        null,
        2,
      )}\n`,
    );
    if (!pre.ok) {
      throw new Error(
        `PRECONDITION: ${pre.detail} — restart the container, then re-run: ${RERUN}`,
      );
    }

    // ====================================================================
    // CASE 1 — USER quarantine: direct-grant login fails until ADOPT_USER
    //          commits.
    // ====================================================================
    await createScratchRealm(request, REALM_USER);

    const u1Create = await createUser(request, REALM_USER, {
      username: 'usr1',
      enabled: true,
      emailVerified: true,
      email: 'usr1@example.test',
      firstName: 'U',
      lastName: 'One',
    });
    expect(u1Create.status(), 'create u1 IGA-off').toBe(201);
    const u1Lookup = await getUserByUsername(request, REALM_USER, 'usr1');
    const u1Id = u1Lookup.body?.id as string;
    expect(u1Id).toBeTruthy();
    await setPassword(request, REALM_USER, u1Id, 'pw-u1');
    await finalizeUser(request, REALM_USER, u1Id);

    // Confirm pre-IGA: direct-grant works.
    const preTok = await directGrantToken(request, REALM_USER, 'usr1', 'pw-u1');
    expect(preTok.http, 'pre-IGA direct-grant').toBe(200);
    expect(preTok.body?.access_token).toBeTruthy();

    // Toggle IGA on (also runs the ADOPT scan).
    await enableIga(request, REALM_USER);
    expect((await igaStatus(request, REALM_USER)).enabled).toBe(true);

    // The scan should have created ADOPT_USER for u1.
    const adoptU1Id = await waitForAdoptCr(
      request,
      REALM_USER,
      'ADOPT_USER',
      u1Id,
    );

    // Direct-grant MUST now fail — user is unsigned, quarantine hard-refuses.
    const blocked = await directGrantToken(request, REALM_USER, 'usr1', 'pw-u1');
    expect(
      [400, 401].includes(blocked.http),
      `unsigned-user direct-grant should fail with 400/401, got ${blocked.http} ${JSON.stringify(blocked.body)}`,
    ).toBeTruthy();
    expect(blocked.body?.access_token, 'unsigned user must not get a token').toBeFalsy();

    // Authorize + commit ADOPT_USER for u1.
    const acU1 = await authorizeAndCommit(request, REALM_USER, adoptU1Id);
    expect(acU1.authorize.http, `authorize ADOPT_USER`).toBe(200);
    expect(acU1.commit.http, `commit ADOPT_USER`).toBe(200);
    // CR APPROVED — and the replay path was able to touch the still-unsigned
    // entity at commit time, proving the IGA_REPLAY_ACTIVE gate fires.
    const adoptU1Body = (await getChangeRequest(request, REALM_USER, adoptU1Id))
      .body;
    expect(adoptU1Body?.status).toBe('APPROVED');

    // Direct-grant now works again.
    const after = await directGrantToken(request, REALM_USER, 'usr1', 'pw-u1');
    expect(after.http, 'post-ADOPT direct-grant').toBe(200);
    expect(after.body?.access_token).toBeTruthy();

    // ====================================================================
    // CASE 2 — ROLE quarantine: user holding an unsigned role is hard-refused.
    // ====================================================================
    await createScratchRealm(request, REALM_ROLE);
    // Create role r2 + user u2 + assign r2 to u2, all IGA-off.
    const r2 = await createRole(request, REALM_ROLE, { name: 'r2' });
    expect(r2.status(), 'create r2 IGA-off').toBe(201);
    const r2Rep = (await getRole(request, REALM_ROLE, 'r2')).body;
    expect(r2Rep?.id).toBeTruthy();

    const u2Create = await createUser(request, REALM_ROLE, {
      username: 'usr2',
      enabled: true,
      emailVerified: true,
      email: 'usr2@example.test',
      firstName: 'U',
      lastName: 'Two',
    });
    expect(u2Create.status(), 'create u2 IGA-off').toBe(201);
    const u2Id = (await getUserByUsername(request, REALM_ROLE, 'usr2')).body
      ?.id as string;
    expect(u2Id).toBeTruthy();
    await setPassword(request, REALM_ROLE, u2Id, 'pw-u2');
    await finalizeUser(request, REALM_ROLE, u2Id);

    const assignR2 = await assignRealmRoleMapping(request, REALM_ROLE, u2Id, [
      r2Rep,
    ]);
    expect(assignR2.status(), 'assign r2 to u2 IGA-off').toBe(204);

    // Confirm pre-IGA: direct-grant works.
    expect(
      (await directGrantToken(request, REALM_ROLE, 'usr2', 'pw-u2')).http,
    ).toBe(200);

    await enableIga(request, REALM_ROLE);
    const adoptU2 = await waitForAdoptCr(
      request,
      REALM_ROLE,
      'ADOPT_USER',
      u2Id,
    );
    const adoptR2 = await waitForAdoptCr(
      request,
      REALM_ROLE,
      'ADOPT_ROLE',
      r2Rep.id,
    );

    // Commit ADOPT_USER, leave ADOPT_ROLE PENDING — u2 themselves are
    // attested, but they hold an unsigned role → hard refuse.
    const acU2 = await authorizeAndCommit(request, REALM_ROLE, adoptU2);
    expect(acU2.commit.http).toBe(200);

    const stillBlocked = await directGrantToken(
      request,
      REALM_ROLE,
      'usr2',
      'pw-u2',
    );
    expect(
      [400, 401].includes(stillBlocked.http),
      `u2 holds unsigned role r2 — direct-grant should still fail, got ${stillBlocked.http} ${JSON.stringify(stillBlocked.body)}`,
    ).toBeTruthy();
    expect(stillBlocked.body?.access_token).toBeFalsy();

    // Commit ADOPT_ROLE — now u2 can log in and the token carries r2.
    const acR2 = await authorizeAndCommit(request, REALM_ROLE, adoptR2);
    expect(acR2.commit.http).toBe(200);

    const u2After = await directGrantToken(request, REALM_ROLE, 'usr2', 'pw-u2');
    expect(u2After.http, 'post-ADOPT_ROLE u2 token').toBe(200);
    expect(u2After.body?.access_token).toBeTruthy();
    const u2Claims = decodeJwtPayload(u2After.body.access_token as string);
    const u2Roles = ((u2Claims as any).realm_access?.roles as string[]) || [];
    expect(
      u2Roles.includes('r2'),
      `u2 token should carry r2 — claims=${JSON.stringify(u2Claims)}`,
    ).toBe(true);

    // ====================================================================
    // CASE 3 — CLIENT quarantine: client_credentials grant fails.
    // ====================================================================
    await createScratchRealm(request, REALM_CLIENT);
    // Create a confidential client with service accounts + a known secret.
    const ccClientId = 'p6c-cc-client';
    const ccSecret = 'p6c-cc-secret';
    const ccCreate = await kcFetch(
      request,
      `/admin/realms/${REALM_CLIENT}/clients`,
      {
        method: 'POST',
        json: {
          clientId: ccClientId,
          enabled: true,
          publicClient: false,
          serviceAccountsEnabled: true,
          standardFlowEnabled: false,
          directAccessGrantsEnabled: false,
          secret: ccSecret,
          clientAuthenticatorType: 'client-secret',
        },
      },
    );
    expect(ccCreate.status(), 'create confidential client IGA-off').toBe(201);
    const ccUuid = await clientUuid(request, REALM_CLIENT, ccClientId);

    // Confirm pre-IGA: client_credentials works.
    const ccPre = await clientCredentialsToken(
      request,
      REALM_CLIENT,
      ccClientId,
      ccSecret,
    );
    expect(ccPre.http, 'pre-IGA client_credentials').toBe(200);
    expect(ccPre.body?.access_token).toBeTruthy();

    await enableIga(request, REALM_CLIENT);
    const adoptCc = await waitForAdoptCr(
      request,
      REALM_CLIENT,
      'ADOPT_CLIENT',
      ccUuid,
    );
    // client_credentials MUST now fail (client is unsigned).
    const ccBlocked = await clientCredentialsToken(
      request,
      REALM_CLIENT,
      ccClientId,
      ccSecret,
    );
    expect(
      [400, 401].includes(ccBlocked.http),
      `unsigned-client client_credentials should fail with 400/401, got ${ccBlocked.http} ${JSON.stringify(ccBlocked.body)}`,
    ).toBeTruthy();
    expect(ccBlocked.body?.access_token).toBeFalsy();

    // Commit ADOPT_CLIENT — request succeeds again.
    const acCc = await authorizeAndCommit(request, REALM_CLIENT, adoptCc);
    expect(acCc.commit.http).toBe(200);
    const ccAfter = await clientCredentialsToken(
      request,
      REALM_CLIENT,
      ccClientId,
      ccSecret,
    );
    expect(ccAfter.http, 'post-ADOPT_CLIENT client_credentials').toBe(200);
    expect(ccAfter.body?.access_token).toBeTruthy();

    // ====================================================================
    // CASE 4 — GROUP quarantine: group claim silently stripped from token.
    // ====================================================================
    await createScratchRealm(request, REALM_GROUP);
    // Create a group, a user, and a public direct-grant-enabled client with
    // a groups protocol mapper attached. Place the user in the group.
    const g3Create = await kcFetch(
      request,
      `/admin/realms/${REALM_GROUP}/groups`,
      { method: 'POST', json: { name: 'g3' } },
    );
    expect(g3Create.status(), 'create g3 IGA-off').toBe(201);
    const g3List = await kcFetch(
      request,
      `/admin/realms/${REALM_GROUP}/groups?search=g3`,
    );
    const g3Arr = await safeJson(g3List);
    const g3Id = Array.isArray(g3Arr) && g3Arr[0]?.id;
    expect(g3Id, 'g3 must have an id').toBeTruthy();

    // Create a public client with a `groups` protocol mapper.
    const grpClient = await kcFetch(
      request,
      `/admin/realms/${REALM_GROUP}/clients`,
      {
        method: 'POST',
        json: {
          clientId: 'p6c-grp-client',
          enabled: true,
          publicClient: true,
          directAccessGrantsEnabled: true,
          standardFlowEnabled: false,
          protocolMappers: [
            {
              name: 'groups',
              protocol: 'openid-connect',
              protocolMapper: 'oidc-group-membership-mapper',
              config: {
                'claim.name': 'groups',
                'full.path': 'false',
                'id.token.claim': 'true',
                'access.token.claim': 'true',
                'userinfo.token.claim': 'true',
              },
            },
          ],
        },
      },
    );
    expect(grpClient.status(), 'create grp-client IGA-off').toBe(201);

    const u3Create = await createUser(request, REALM_GROUP, {
      username: 'usr3',
      enabled: true,
      emailVerified: true,
      email: 'usr3@example.test',
      firstName: 'U',
      lastName: 'Three',
    });
    expect(u3Create.status(), 'create u3 IGA-off').toBe(201);
    const u3Id = (await getUserByUsername(request, REALM_GROUP, 'usr3')).body
      ?.id as string;
    await setPassword(request, REALM_GROUP, u3Id, 'pw-u3');
    await finalizeUser(request, REALM_GROUP, u3Id);
    // Add u3 to g3.
    const joinRes = await kcFetch(
      request,
      `/admin/realms/${REALM_GROUP}/users/${u3Id}/groups/${g3Id}`,
      { method: 'PUT' },
    );
    expect(joinRes.status(), 'add u3 to g3 IGA-off').toBe(204);

    // Pre-IGA: token via the p6c-grp-client must carry groups claim with g3.
    const grpPreTok = await request.post(
      `${kcEnv().baseUrl}/realms/${REALM_GROUP}/protocol/openid-connect/token`,
      {
        form: {
          grant_type: 'password',
          client_id: 'p6c-grp-client',
          username: 'usr3',
          password: 'pw-u3',
        },
      },
    );
    expect(grpPreTok.status(), 'pre-IGA u3 token').toBe(200);
    const grpPreBody = await grpPreTok.json();
    const grpPreClaims = decodeJwtPayload(grpPreBody.access_token);
    const grpPreClaim = (grpPreClaims as any).groups as string[] | undefined;
    expect(
      grpPreClaim && grpPreClaim.some((g) => g.includes('g3')),
      `pre-IGA token must carry g3 in groups claim — claims=${JSON.stringify(grpPreClaims)}`,
    ).toBeTruthy();

    await enableIga(request, REALM_GROUP);
    const adoptU3 = await waitForAdoptCr(
      request,
      REALM_GROUP,
      'ADOPT_USER',
      u3Id,
    );
    const adoptG3 = await waitForAdoptCr(
      request,
      REALM_GROUP,
      'ADOPT_GROUP',
      g3Id as string,
    );

    // Commit ADOPT_USER (and any default-role ADOPTs if present) so u3 can
    // log in. Leave ADOPT_GROUP PENDING.
    const acU3 = await authorizeAndCommit(request, REALM_GROUP, adoptU3);
    expect(acU3.commit.http).toBe(200);

    // The realm's default-roles role usually exists and may need an ADOPT
    // commit too; commit any ADOPT_ROLE PENDING for the default-roles role so
    // u3 isn't held back by the role-fan-out. (We commit ALL PENDING ADOPT_ROLE
    // except none — we just need u3 to log in.)
    const pendingRoles = await kcFetch(
      request,
      `/admin/realms/${REALM_GROUP}/iga/change-requests?status=PENDING`,
    );
    const pendingArr = (await safeJson(pendingRoles)) || [];
    for (const cr of pendingArr) {
      if (cr.actionType === 'ADOPT_ROLE') {
        await authorizeAndCommit(request, REALM_GROUP, cr.id);
      }
    }

    // Token issuance for u3 — group claim must be ABSENT (silent strip).
    const grpDuring = await request.post(
      `${kcEnv().baseUrl}/realms/${REALM_GROUP}/protocol/openid-connect/token`,
      {
        form: {
          grant_type: 'password',
          client_id: 'p6c-grp-client',
          username: 'usr3',
          password: 'pw-u3',
        },
      },
    );
    expect(
      grpDuring.status(),
      `u3 token must still issue (group is silent-strip) — got ${grpDuring.status()} ${await grpDuring.text().catch(() => '')}`,
    ).toBe(200);
    const grpDuringBody = await grpDuring.json();
    const grpDuringClaims = decodeJwtPayload(grpDuringBody.access_token);
    const grpDuringClaim = (grpDuringClaims as any).groups as string[] | undefined;
    const groupClaimPresent =
      Array.isArray(grpDuringClaim) &&
      grpDuringClaim.some((g) => g.includes('g3'));
    expect(
      !groupClaimPresent,
      `unsigned g3 must NOT appear in token groups claim — claims=${JSON.stringify(grpDuringClaims)}`,
    ).toBeTruthy();

    // Commit ADOPT_GROUP — group claim must return.
    const acG3 = await authorizeAndCommit(request, REALM_GROUP, adoptG3);
    expect(acG3.commit.http).toBe(200);
    const grpAfter = await request.post(
      `${kcEnv().baseUrl}/realms/${REALM_GROUP}/protocol/openid-connect/token`,
      {
        form: {
          grant_type: 'password',
          client_id: 'p6c-grp-client',
          username: 'usr3',
          password: 'pw-u3',
        },
      },
    );
    expect(grpAfter.status()).toBe(200);
    const grpAfterClaims = decodeJwtPayload(
      (await grpAfter.json()).access_token,
    );
    const grpAfterClaim = (grpAfterClaims as any).groups as string[] | undefined;
    expect(
      grpAfterClaim && grpAfterClaim.some((g) => g.includes('g3')),
      `post-ADOPT_GROUP token must carry g3 — claims=${JSON.stringify(grpAfterClaims)}`,
    ).toBeTruthy();

    // ====================================================================
    // CASE 5 — CLIENT_SCOPE quarantine: mapper claim silently stripped.
    // ====================================================================
    await createScratchRealm(request, REALM_SCOPE);
    // Create a client scope with a custom hardcoded claim mapper, IGA off.
    const csName = 'p6c-scope';
    const csClaimName = 'p6c_scope_claim';
    const csValue = 'p6c-scope-value';
    const csCreate = await createClientScope(request, REALM_SCOPE, {
      name: csName,
      protocol: 'openid-connect',
      protocolMappers: [
        {
          name: 'p6c-hardcoded',
          protocol: 'openid-connect',
          protocolMapper: 'oidc-hardcoded-claim-mapper',
          config: {
            'claim.name': csClaimName,
            'claim.value': csValue,
            'jsonType.label': 'String',
            'id.token.claim': 'true',
            'access.token.claim': 'true',
            'userinfo.token.claim': 'true',
          },
        },
      ],
    });
    expect(csCreate.status(), 'create client scope IGA-off').toBe(201);
    const csRep = (await getClientScopeByName(request, REALM_SCOPE, csName))
      .body;
    expect(csRep?.id).toBeTruthy();
    const csId = csRep.id as string;

    // Create a public direct-grant client and attach the scope as a DEFAULT.
    const scopeClientId = 'p6c-scope-client';
    const scopeClient = await kcFetch(
      request,
      `/admin/realms/${REALM_SCOPE}/clients`,
      {
        method: 'POST',
        json: {
          clientId: scopeClientId,
          enabled: true,
          publicClient: true,
          directAccessGrantsEnabled: true,
          standardFlowEnabled: false,
        },
      },
    );
    expect(scopeClient.status(), 'create scope-client IGA-off').toBe(201);
    const scopeClientUuid = await clientUuid(
      request,
      REALM_SCOPE,
      scopeClientId,
    );
    const attach = await kcFetch(
      request,
      `/admin/realms/${REALM_SCOPE}/clients/${scopeClientUuid}/default-client-scopes/${csId}`,
      { method: 'PUT' },
    );
    expect(attach.status(), 'attach scope as default').toBe(204);

    // Create a user for the token issuance.
    const u4Create = await createUser(request, REALM_SCOPE, {
      username: 'usr4',
      enabled: true,
      emailVerified: true,
      email: 'usr4@example.test',
      firstName: 'U',
      lastName: 'Four',
    });
    expect(u4Create.status()).toBe(201);
    const u4Id = (await getUserByUsername(request, REALM_SCOPE, 'usr4')).body
      ?.id as string;
    await setPassword(request, REALM_SCOPE, u4Id, 'pw-u4');
    await finalizeUser(request, REALM_SCOPE, u4Id);

    // Pre-IGA: token carries the hardcoded claim.
    const csPre = await request.post(
      `${kcEnv().baseUrl}/realms/${REALM_SCOPE}/protocol/openid-connect/token`,
      {
        form: {
          grant_type: 'password',
          client_id: scopeClientId,
          username: 'usr4',
          password: 'pw-u4',
        },
      },
    );
    expect(csPre.status()).toBe(200);
    const csPreClaims = decodeJwtPayload((await csPre.json()).access_token);
    expect(
      (csPreClaims as any)[csClaimName],
      `pre-IGA token must carry ${csClaimName} — claims=${JSON.stringify(csPreClaims)}`,
    ).toBe(csValue);

    await enableIga(request, REALM_SCOPE);
    const adoptU4 = await waitForAdoptCr(
      request,
      REALM_SCOPE,
      'ADOPT_USER',
      u4Id,
    );
    const adoptCs = await waitForAdoptCr(
      request,
      REALM_SCOPE,
      'ADOPT_CLIENT_SCOPE',
      csId,
    );
    const adoptScopeClient = await waitForAdoptCr(
      request,
      REALM_SCOPE,
      'ADOPT_CLIENT',
      scopeClientUuid,
    );

    // Commit user, client, role(s) — but LEAVE ADOPT_CLIENT_SCOPE PENDING.
    expect(
      (await authorizeAndCommit(request, REALM_SCOPE, adoptU4)).commit.http,
    ).toBe(200);
    expect(
      (await authorizeAndCommit(request, REALM_SCOPE, adoptScopeClient))
        .commit.http,
    ).toBe(200);
    const pendingRolesScope = await kcFetch(
      request,
      `/admin/realms/${REALM_SCOPE}/iga/change-requests?status=PENDING`,
    );
    const pendingScopeArr = (await safeJson(pendingRolesScope)) || [];
    for (const cr of pendingScopeArr) {
      if (cr.actionType === 'ADOPT_ROLE') {
        await authorizeAndCommit(request, REALM_SCOPE, cr.id);
      }
    }

    // Token issuance — claim must be ABSENT (scope unsigned → mappers
    // stripped).
    const csDuring = await request.post(
      `${kcEnv().baseUrl}/realms/${REALM_SCOPE}/protocol/openid-connect/token`,
      {
        form: {
          grant_type: 'password',
          client_id: scopeClientId,
          username: 'usr4',
          password: 'pw-u4',
        },
      },
    );
    expect(
      csDuring.status(),
      `u4 token must still issue while scope is unsigned (silent strip) — got ${csDuring.status()} ${await csDuring.text().catch(() => '')}`,
    ).toBe(200);
    const csDuringClaims = decodeJwtPayload(
      (await csDuring.json()).access_token,
    );
    expect(
      (csDuringClaims as any)[csClaimName],
      `unsigned client-scope must strip ${csClaimName} from token — claims=${JSON.stringify(csDuringClaims)}`,
    ).toBeFalsy();

    // Commit ADOPT_CLIENT_SCOPE — claim returns.
    expect(
      (await authorizeAndCommit(request, REALM_SCOPE, adoptCs)).commit.http,
    ).toBe(200);
    const csAfter = await request.post(
      `${kcEnv().baseUrl}/realms/${REALM_SCOPE}/protocol/openid-connect/token`,
      {
        form: {
          grant_type: 'password',
          client_id: scopeClientId,
          username: 'usr4',
          password: 'pw-u4',
        },
      },
    );
    expect(csAfter.status()).toBe(200);
    const csAfterClaims = decodeJwtPayload(
      (await csAfter.json()).access_token,
    );
    expect(
      (csAfterClaims as any)[csClaimName],
      `post-ADOPT_CLIENT_SCOPE token must carry ${csClaimName} again — claims=${JSON.stringify(csAfterClaims)}`,
    ).toBe(csValue);

    // ====================================================================
    // CASE 6 (smoke) — toggle-on session invalidation: response carries
    // scan.sessionsInvalidated.
    // ====================================================================
    // The earlier toggle-iga calls already exercised this — fetch the
    // response shape from a fresh scratch realm to assert the contract.
    const REALM_SI = 'iga-phase6c-si-e2e';
    try {
      await createScratchRealm(request, REALM_SI);
      // Create one user so the realm has at least one quarantineable entity.
      await createUser(request, REALM_SI, {
        username: 'si-u',
        enabled: true,
        emailVerified: true,
        email: 'si-u@example.test',
      });
      const toggle = await kcFetch(
        request,
        `/admin/realms/${REALM_SI}/tide-admin/toggle-iga`,
        { method: 'POST' },
      );
      expect(toggle.status()).toBe(200);
      const tj = await safeJson(toggle);
      expect(tj?.enabled).toBe(true);
      expect(
        tj?.scan && typeof tj.scan.sessionsInvalidated === 'number',
        `toggle-on response must carry scan.sessionsInvalidated — got ${JSON.stringify(tj)}`,
      ).toBeTruthy();
    } finally {
      await deleteRealm(request, REALM_SI).catch(() => {});
    }
  });
});
