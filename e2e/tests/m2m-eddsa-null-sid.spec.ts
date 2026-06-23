import { test, expect, APIRequestContext } from '@playwright/test';
import { execSync } from 'child_process';
import {
  deleteRealm,
  clientUuid,
  safeJson,
  kcFetch,
  enableIga,
  listChangeRequests,
  authorizeAndCommit,
} from '../lib/kc';
import { kcEnv } from '../lib/env';
import { checkPrecondition, rerunCommand } from '../lib/precondition';

/**
 * M2M client_credentials + EdDSA + IGA null-userSession regression.
 *
 * Source — tidecloak KC core, DefaultTokenManager:
 *   services/.../jose/jws/DefaultTokenManager.java
 *
 * The plain (non-Tide) encode path is already guarded at :159-163:
 *     String sid = accessToken != null ? accessToken.getSessionId()
 *                                       : idToken.getSessionId();
 *     UserSessionModel userSession = sid != null
 *         ? session.sessions().getUserSession(realm, sid) : null;
 * On a client_credentials grant there is NO user session, so sid is null and
 * `userSession` is null. The plain path tolerates that.
 *
 * The EdDSA Tide signing branch (encode :169-177, taken when the resolved
 * signature alg == "EdDSA" AND realm attr isIGAEnabled == true) calls
 * encodeTideSignedTokens(...). On the Midgard signing sub-path that method
 * dereferenced `userSession` UNGUARDED in THREE places, each of which NPE'd the
 * token endpoint (500) on a client_credentials grant (null userSession):
 *     1. the `TidePreviousAuthorization` / `TideAuthData` getNote derefs (~:222);
 *     2. the detached-IGA short-circuit's
 *        `userSession.removeAuthenticatedClientSessions(...)` (~:240);
 *     3. and even after guarding 1+2, the short-circuit's bare `return null`
 *        NPE'd the CALLER, TokenManager$AccessTokenResponseBuilder.build, which
 *        does `encodedTokens[0]` with no null check (TokenManager.java:1358-1361).
 *
 * The fix: (1)+(2) guard the userSession derefs the same way the plain path does
 * at :159-163 so there is no NPE; (3) the detached-IGA short-circuit now FAILS
 * CLOSED — it throws a clean OAuth-style ErrorResponseException rather than
 * returning null (which NPE'd the caller) or a plain locally-signed token.
 *
 * WHY FAIL-CLOSED (corrected design):
 *   encodeTideSignedTokens is reached ONLY when a tide-vendor-key component
 *   exists = Tide mode. In Tide mode a token MUST be Tide-signed; it must NEVER
 *   silently fall back to a plain (KC-mintable) realm-key token. With old IGA
 *   detached there is no proof/default context to threshold-sign against, and
 *   Midgard signClaims() for a client principal does not exist yet, so a Tide
 *   signature cannot be produced on this path. The only correct interim
 *   behaviour is to reject cleanly: no token. (An earlier fix returned a plain
 *   EdDSA realm-key token here — that defeated Tide mode and is reverted.)
 *
 * The sibling spec m2m-null-sid.spec.ts covers the RS256 / plain (TIDELESS,
 * no vendor key) path and asserts the contract's OTHER side: Tideless M2M
 * STILL gets a plain realm-key token (it never enters encodeTideSignedTokens).
 * This spec is the Tide (vendor-key) complement: it provisions the exact realm
 * shape (defaultSignatureAlgorithm=EdDSA + isIGAEnabled + a tide-vendor-key
 * component) needed to enter encodeTideSignedTokens, then asserts the M2M grant
 * fails closed.
 *
 * HERMETIC: no Orks / Midgard required. The tide-vendor-key component carries
 * gVRK/gVRKCertificate ONLY:
 *   - NO `eddsaPrivateKey`  → the Ragnarok local-sign branch (:207-213) is
 *     skipped, so execution reaches the Midgard sub-path and the :222 deref.
 *   - NO `vvkId`            → recreateScheduledTasks performs no network call.
 *   validateConfiguration on the factory only checks priority/enabled/active,
 *   so a syntactically-valid placeholder gVRK passes.
 *
 * POST-FIX EXPECTED BEHAVIOR (honest):
 *   The detached-IGA short-circuit (userAccessProof == null && !hasDefaultContext,
 *   ALWAYS true while old IGA is detached) now throws ErrorResponseException
 *   (OAuthErrorException.TEMPORARILY_UNAVAILABLE, HTTP 503 SERVICE_UNAVAILABLE).
 *   The token endpoint surfaces that as a clean OAuth error body. This spec
 *   asserts:
 *     (1) the grant returns HTTP 503 with error=="temporarily_unavailable"
 *         (NOT 200+token, NOT 500/NPE)  — the core assertion;
 *     (2) NO access_token / doken is issued;
 *     (3) container logs show NO NullPointerException / uncaught 500 across the
 *         grant — i.e. a clean rejection, not a crash.
 *   TODO: when Midgard signClaims() for a client principal lands (+ the new IGA
 *   artifact re-attaches a proof/default context), this rejection flips to a
 *   real Tide-signed M2M token; update assertions to expect 200 + t.uho/doken.
 */

const REALM = 'm2m-eddsa-null-sid';
const CLIENT_ID = 'm2m-eddsa-svc';
const CLIENT_SECRET = 'm2m-eddsa-null-sid-secret';
const RERUN =
  'cd /home/sasha/project/tidecloak-iga-extensions/e2e && npx playwright test m2m-eddsa-null-sid';

// A syntactically-valid placeholder for the vendor public keys. The factory's
// validateConfiguration checks only priority/enabled/active booleans, so these
// values are never cryptographically validated at component-create time. They
// exist only to make the Midgard sub-path (gVRK present, eddsaPrivateKey
// absent) the one taken.
const PLACEHOLDER_GVRK = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const PLACEHOLDER_GVRK_CERT = 'placeholder-gvrk-certificate';

/**
 * Create the scratch realm with defaultSignatureAlgorithm=EdDSA, IGA still OFF.
 *
 * defaultSignatureAlgorithm MUST be stamped at realm-CREATE time: KC's realm
 * UPDATE path (PUT /admin/realms/{realm}) is intercepted by IgaRealmAdapter
 * (its internal attribute-merge calls removeAttribute → checkNoPendingCr) and
 * 500s on an IGA-aware realm, so we cannot set it after the fact. IGA is left
 * OFF here so the m2m client + its service-account user are created as plain,
 * un-quarantined entities (201, not a governed 202). IGA is then turned on via
 * the toggle endpoint (enableIga), exactly like the RS256 m2m-null-sid spec —
 * that path runs the adopt scan and is the supported way to set the
 * `isIGAEnabled` realm attribute the EdDSA encode branch gates on.
 */
async function createEdDSARealm(
  request: APIRequestContext,
  realm: string,
): Promise<void> {
  await deleteRealm(request, realm);
  const res = await kcFetch(request, `/admin/realms`, {
    method: 'POST',
    json: {
      realm,
      enabled: true,
      defaultSignatureAlgorithm: 'EdDSA',
    },
  });
  if (res.status() !== 201) {
    throw new Error(
      `createEdDSARealm(${realm}) expected 201, got HTTP ${res.status()}: ${await res.text()}`,
    );
  }
  const get = await kcFetch(request, `/admin/realms/${realm}`);
  const body = await safeJson(get);
  if (body?.defaultSignatureAlgorithm !== 'EdDSA') {
    throw new Error(
      `createEdDSARealm(${realm}) defaultSignatureAlgorithm not EdDSA: ${body?.defaultSignatureAlgorithm}`,
    );
  }
}

/**
 * Provision a tide-vendor-key component (Midgard sub-path shape). gVRK +
 * gVRKCertificate only — no eddsaPrivateKey, no vvkId. Idempotent: deletes any
 * pre-existing instance first.
 */
async function createVendorKeyComponent(
  request: APIRequestContext,
  realm: string,
): Promise<void> {
  const realmId = realm; // KC accepts realm name as parentId for realm-level components
  // Remove any prior tide-vendor-key components so the create is re-runnable.
  const existing = await kcFetch(
    request,
    `/admin/realms/${realm}/components?type=org.keycloak.keys.KeyProvider`,
  );
  const list = (await safeJson(existing)) || [];
  for (const c of Array.isArray(list) ? list : []) {
    if (c.providerId === 'tide-vendor-key') {
      await kcFetch(request, `/admin/realms/${realm}/components/${c.id}`, {
        method: 'DELETE',
      });
    }
  }

  const res = await kcFetch(request, `/admin/realms/${realm}/components`, {
    method: 'POST',
    json: {
      name: 'tide-vendor-key',
      providerId: 'tide-vendor-key',
      providerType: 'org.keycloak.keys.KeyProvider',
      parentId: realmId,
      config: {
        priority: ['100'],
        enabled: ['true'],
        active: ['true'],
        gVRK: [PLACEHOLDER_GVRK],
        gVRKCertificate: [PLACEHOLDER_GVRK_CERT],
        // setupSignRequestSettings (DefaultTokenManager :493-501, called at :204
        // BEFORE the :222 userSession deref) does
        //   objectMapper.readTree(config.getFirst("clientSecret"))
        // which throws IllegalArgumentException("argument \"content\" is null")
        // if clientSecret is absent. Supply an empty JSON object so readTree
        // succeeds and .path("activeVrk").asText(null) yields null — letting
        // execution reach the userSession deref under test without needing real
        // VRK secret material.
        clientSecret: ['{}'],
        // deliberately NO eddsaPrivateKey (would take Ragnarok branch)
        // deliberately NO vvkId (would trigger a network scheduled task)
      },
    },
  });
  if (res.status() !== 201) {
    throw new Error(
      `createVendorKeyComponent(${realm}) expected 201, got HTTP ${res.status()}: ${await res.text()}`,
    );
  }
}

/**
 * Create a confidential service-account client with a known secret while IGA
 * is still OFF — so it is a plain 201 and its service-account user is created
 * and un-quarantined (the token endpoint's service-account lookup goes through
 * the quarantine-aware IgaUserProvider, which hides a user that was never
 * adopted; creating the client BEFORE the toggle avoids that).
 */
async function createM2mClient(
  request: APIRequestContext,
  realm: string,
): Promise<void> {
  const res = await kcFetch(request, `/admin/realms/${realm}/clients`, {
    method: 'POST',
    json: {
      clientId: CLIENT_ID,
      enabled: true,
      publicClient: false,
      serviceAccountsEnabled: true,
      standardFlowEnabled: true,
      directAccessGrantsEnabled: false,
      clientAuthenticatorType: 'client-secret',
      secret: CLIENT_SECRET,
    },
  });
  if (res.status() !== 201) {
    throw new Error(
      `createM2mClient(${CLIENT_ID}) expected 201, got ${res.status()}: ${await res.text()}`,
    );
  }
}

/**
 * After enableIga's toggle-on adopt scan quarantines the m2m client and its
 * service-account user, authorize+commit every PENDING ADOPT/CREATE CR so
 * both are committed and un-quarantined. Master is exempt from approver gates.
 * Loops because committing the client can surface the service-account user CR.
 */
async function commitAllPending(
  request: APIRequestContext,
  realm: string,
): Promise<void> {
  for (let pass = 0; pass < 4; pass++) {
    const pending = await listChangeRequests(request, realm, 'PENDING');
    if (pending.length === 0) break;
    for (const cr of pending) {
      const ac = await authorizeAndCommit(request, realm, cr.id);
      expect(
        [200, 409, 412],
        `commit ${cr.actionType} authorize=${ac.authorize.http} commit=${ac.commit.http}`,
      ).toContain(ac.commit.http);
    }
  }
}

/** POST the client_credentials grant. Returns {http, body}. */
async function clientCredentials(
  request: APIRequestContext,
  realm: string,
): Promise<{ http: number; body: any }> {
  const { baseUrl } = kcEnv();
  const res = await request.post(
    `${baseUrl}/realms/${realm}/protocol/openid-connect/token`,
    {
      form: {
        grant_type: 'client_credentials',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
      },
    },
  );
  return { http: res.status(), body: await safeJson(res) };
}


const TIDECLOAK_CONTAINER = 'tidecloakP';

/**
 * Return the tail of the tidecloak container log since `sinceMs` ago. Used to
 * prove the fail-closed rejection is CLEAN — i.e. it does NOT leave a
 * NullPointerException / uncaught 500 stack trace, which is what the pre-fix
 * null-userSession deref (and the bare `return null`) produced.
 */
function containerLogSince(sinceMs: number): string {
  const sinceSec = Math.ceil(sinceMs / 1000) + 1;
  try {
    return execSync(
      `docker logs --since ${sinceSec}s ${TIDECLOAK_CONTAINER} 2>&1`,
      { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 },
    );
  } catch (e: any) {
    return String(e?.stdout || '') + String(e?.stderr || '');
  }
}

test.describe('M2M client_credentials + EdDSA + IGA null-userSession', () => {
  test.afterAll(async ({ request }) => {
    await deleteRealm(request, REALM).catch(() => {});
  });

  test('EdDSA Tide-mode M2M fails closed cleanly (HTTP 503 temporarily_unavailable, no token, no NPE)', async ({
    request,
  }) => {
    // PRECONDITION GATE — proves the IGA jar is loaded.
    const pre = await checkPrecondition(request);
    console.log(
      `\n[PRECONDITION m2m-eddsa-null-sid] verdict=${pre.verdict}\n  ${pre.detail}\n`,
    );
    if (pre.verdict !== 'OK') {
      throw new Error(
        `PRECONDITION: IGA jar not loaded (verdict=${pre.verdict}: ${pre.detail}) — ` +
          `restart the container, then re-run: ${rerunCommand()}`,
      );
    }

    // Provision the exact realm shape that enters encodeTideSignedTokens.
    //  1. EdDSA realm, IGA OFF — m2m client + service-account user created
    //     plainly (201), un-quarantined.
    await createEdDSARealm(request, REALM);
    await createM2mClient(request, REALM);
    const uuid = await clientUuid(request, REALM, CLIENT_ID);
    expect(uuid, 'm2m client created').toBeTruthy();

    //  2. tide-vendor-key component (gVRK/gVRKCertificate only) so encode takes
    //     the Midgard sub-path that dereferences userSession at :222.
    await createVendorKeyComponent(request, REALM);

    //  3. Enable IGA via the toggle endpoint — this sets the `isIGAEnabled`
    //     realm attribute the EdDSA encode branch gates on, and runs the adopt
    //     scan which quarantines the client + its service-account user.
    await enableIga(request, REALM);

    //  4. Authorize+commit every PENDING ADOPT/CREATE so the client and its
    //     service-account user are un-quarantined and the grant reaches encode
    //     (otherwise the token endpoint 401s "service account does not exist"
    //     before the code under test runs).
    await commitAllPending(request, REALM);

    // Run the EdDSA Tide-mode M2M grant. With a null userSession this used to NPE/500
    // in DefaultTokenManager.encodeTideSignedTokens (first at the TidePreviousAuthorization
    // getNote deref, then at the short-circuit's removeAuthenticatedClientSessions),
    // and — once those were guarded — the detached-IGA `return null` NPE'd the caller
    // TokenManager$AccessTokenResponseBuilder.build (encodedTokens[0], no null check).
    //
    // The fix guards both userSession derefs (no NPE) AND makes the detached-IGA
    // short-circuit FAIL CLOSED: it throws ErrorResponseException
    // (OAuthErrorException.TEMPORARILY_UNAVAILABLE, 503), because in Tide mode a token
    // MUST be Tide-signed and must not silently fall back to a plain realm-key token.
    const t0 = Date.now();
    const cc = await clientCredentials(request, REALM);
    console.log(
      `\n[m2m-eddsa] grant HTTP=${cc.http} bodyKeys=${
        cc.body && typeof cc.body === 'object'
          ? Object.keys(cc.body).join(',')
          : typeof cc.body
      } body=${JSON.stringify(cc.body)}`,
    );

    // (1) CORE ASSERTION — clean fail-closed rejection, NOT a 200+token and NOT a
    // 500/NPE. The Tide branch cannot produce a Tide signature yet, so it rejects.
    expect(
      cc.http,
      `EdDSA Tide-mode M2M must fail closed with 503 (no plain-key fallback, no NPE). ` +
        `Got HTTP ${cc.http}, body=${JSON.stringify(cc.body)}`,
    ).toBe(503);
    expect(
      cc.body?.error,
      `OAuth error body must be temporarily_unavailable. Got ${JSON.stringify(cc.body)}`,
    ).toBe('temporarily_unavailable');

    // (2) NO token of any kind was issued.
    expect(cc.body?.access_token, 'no access_token issued (fail-closed)').toBeFalsy();
    expect(cc.body?.doken, 'no doken issued (fail-closed)').toBeFalsy();

    // (3) The rejection is CLEAN — the container log for this grant window must NOT
    // contain a NullPointerException or an uncaught 500 / ERROR stack trace. This is
    // what distinguishes the fail-closed guard from the pre-fix NPE crash.
    const log = containerLogSince(Date.now() - t0 + 2000);
    const npeHit = /NullPointerException/.test(log);
    const stackHit = /\bat org\.keycloak\.jose\.jws\.DefaultTokenManager\./.test(log);
    if (npeHit || stackHit) {
      console.log(
        `[m2m-eddsa] OFFENDING LOG TAIL:\n${log.split('\n').slice(-60).join('\n')}`,
      );
    }
    expect(npeHit, 'no NullPointerException in grant-window container log').toBe(false);
    expect(
      stackHit,
      'no DefaultTokenManager stack trace in grant-window container log (clean rejection, not a crash)',
    ).toBe(false);

    // CONTRACT — OTHER SIDE (TIDELESS = plain-key): the sibling spec
    // m2m-null-sid.spec.ts provisions a realm with NO tide-vendor-key component and
    // asserts the same client_credentials grant returns HTTP 200 with a plain
    // realm-key (RS256) token. That branch never enters encodeTideSignedTokens, so
    // it is unaffected by this fail-closed change. Together the two specs lock both
    // sides of the contract: Tideless = plain-key token; Tide = fail-closed. We
    // reference rather than duplicate it here.

    // TODO: when Midgard signClaims() for a client principal lands (+ the new IGA
    // artifact re-attaches a per-user UserClientAccessProof / per-realm default
    // context), encodeTideSignedTokens will produce a real distributed-threshold
    // EdDSA-signed M2M Tide token (with t.uho / doken). At that point this rejection
    // flips to a 200 and this spec should assert those Tide claims are PRESENT.
  });
});
