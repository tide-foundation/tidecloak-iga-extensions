import { test, expect, APIRequestContext } from '@playwright/test';
import {
  createScratchRealm,
  deleteRealm,
  enableIga,
  clientUuid,
  authorizeAndCommit,
  listChangeRequests,
  safeJson,
  kcFetch,
} from '../lib/kc';
import { kcEnv } from '../lib/env';
import { checkPrecondition, rerunCommand } from '../lib/precondition';

/**
 * M2M client_credentials null-sid regression.
 *
 * Source of the latent risk — tidecloak KC core, DefaultTokenManager.encode:
 *   services/.../jose/jws/DefaultTokenManager.java:159-163
 *     String sid = accessToken != null ? accessToken.getSessionId()
 *                                       : idToken.getSessionId();
 *     UserSessionModel userSession = sid != null
 *         ? session.sessions().getUserSession(realm, sid) : null;
 *
 * On a `client_credentials` grant there is NO user session, so the access
 * token's `sid` is null. The pre-Tide stock path computed `getUserSession`
 * unconditionally; with a null sid that bubbled a "Null keys are not
 * supported!" NPE at token encode and the endpoint 500'd. The guard above
 * short-circuits the lookup to null when sid is absent.
 *
 * IMPORTANT scope note (verified from source, not assumed):
 *   The EdDSA-specific Tide signing branch is only taken when BOTH the
 *   resolved signature alg == "EdDSA" AND the realm attribute
 *   `isIGAEnabled == true` (DefaultTokenManager.java:169). In THIS harness no
 *   scratch realm is ever given a `tide-vendor-key` component or an EdDSA
 *   `defaultSignatureAlgorithm`, so scratch-realm tokens are RS256 (KC
 *   default, Constants.DEFAULT_SIGNATURE_ALGORITHM via getSignatureAlgorithm
 *   :657-672). With alg != EdDSA the encode() short-circuits at :169-175 to
 *   the plain KC path — the sid-null guard at :159-163 still runs and is what
 *   prevents the NPE. So the risk exercised here is the KC sid-NPE on the
 *   non-Tide encode path; the EdDSA-specific M2M combination is documented as
 *   needing the Tide vendor-key provider configured (see EdDSA note below).
 *
 * What phase6c already covers vs. what this adds:
 *   phase6c CASE 3 asserts the client_credentials grant returns HTTP 200
 *   (and 401 while quarantined) — i.e. the crash-regression / status. This
 *   spec adds the part phase6c does NOT: that the absent-sid path produces a
 *   coherent, well-formed, signature-verifiable JWT — header alg+kid, NO sid
 *   claim, the expected M2M claims, AND that KC re-validates its own token
 *   end-to-end (introspection active:true), proving signature + state.
 *
 * Cases:
 *   A. IGA OFF (plain realm) — full assertions.
 *   B. IGA ON (same realm toggled) — the toggle quarantines the M2M client
 *      (PENDING ADOPT_CLIENT, phase6c plumbing); we authorize+commit it as
 *      master, then re-run the grant and re-assert. Proves the guard holds
 *      with `isIGAEnabled == true` set on the realm.
 */

const REALM = 'm2m-null-sid';
const CLIENT_ID = 'm2m-svc';
const CLIENT_SECRET = 'm2m-null-sid-secret';
const RERUN =
  'cd /home/sasha/project/tidecloak-iga-extensions/e2e && npx playwright test m2m-null-sid';

/** Decode a base64url JWS segment (header or payload) to an object. No lib. */
function decodeSegment(seg: string): Record<string, any> {
  const pad = seg.length % 4 === 0 ? '' : '='.repeat(4 - (seg.length % 4));
  const b64 = seg.replace(/-/g, '+').replace(/_/g, '/') + pad;
  return JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
}

/** Create a confidential service-account client with a known secret. */
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

/** Introspect a token via the client's own creds. Returns {http, body}. */
async function introspect(
  request: APIRequestContext,
  realm: string,
  token: string,
): Promise<{ http: number; body: any }> {
  const { baseUrl } = kcEnv();
  const res = await request.post(
    `${baseUrl}/realms/${realm}/protocol/openid-connect/token/introspect`,
    {
      form: {
        token,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
      },
    },
  );
  return { http: res.status(), body: await safeJson(res) };
}

/**
 * Assert the M2M token is well-formed, absent-sid, with the expected M2M
 * claims, and introspects active:true. `expectIga` only annotates logs.
 */
async function assertValidNullSidToken(
  request: APIRequestContext,
  realm: string,
  cc: { http: number; body: any },
  label: string,
): Promise<void> {
  expect(cc.http, `${label}: client_credentials HTTP`).toBe(200);
  const at = cc.body?.access_token;
  expect(at, `${label}: access_token present`).toBeTruthy();

  const parts = String(at).split('.');
  expect(parts.length, `${label}: JWT has 3 segments`).toBe(3);

  const header = decodeSegment(parts[0]);
  const payload = decodeSegment(parts[1]);
  console.log(
    `\n[${label}] alg=${header.alg} kid=${header.kid} typ-claim=${payload.typ} ` +
      `azp=${payload.azp} client_id=${payload.client_id} sid=${JSON.stringify(payload.sid)}`,
  );

  // Header: a real signing alg + a key id (proves a key was selected, the
  // exact thing the sid-NPE path would have aborted before reaching).
  expect(header.alg, `${label}: header.alg present`).toBeTruthy();
  expect(['RS256', 'EdDSA', 'ES256', 'PS256']).toContain(header.alg);
  expect(header.kid, `${label}: header.kid present`).toBeTruthy();

  // The crux: a client_credentials token carries NO session id.
  expect(payload.sid, `${label}: payload has NO sid (null/absent)`).toBeUndefined();

  // Coherent M2M claims.
  expect(payload.typ, `${label}: typ=Bearer`).toBe('Bearer');
  expect(payload.azp, `${label}: azp == client id`).toBe(CLIENT_ID);
  // KC stamps the service-account user as sub on client_credentials; what
  // matters for null-sid is there is no SESSION (sid), not that sub is absent.
  expect(payload.sub, `${label}: sub present (service-account user)`).toBeTruthy();

  // End-to-end signature + state validation: KC re-validates its OWN
  // absent-sid token. active:true proves decode + signature + state all pass.
  const intro = await introspect(request, realm, String(at));
  expect(intro.http, `${label}: introspect HTTP`).toBe(200);
  expect(intro.body?.active, `${label}: introspection active:true`).toBe(true);
  expect(intro.body?.client_id, `${label}: introspect client_id`).toBe(CLIENT_ID);
  expect(intro.body?.sid, `${label}: introspect carries no sid`).toBeUndefined();
}

test.describe('M2M client_credentials null-sid token issuance', () => {
  test.afterAll(async ({ request }) => {
    await deleteRealm(request, REALM).catch(() => {});
  });

  test('client_credentials issues a valid, introspectable, sid-less token (IGA off + on)', async ({
    request,
  }) => {
    // PRECONDITION GATE — proves the IGA jar is loaded.
    const pre = await checkPrecondition(request);
    console.log(
      `\n[PRECONDITION m2m-null-sid] verdict=${pre.verdict}\n  ${pre.detail}\n`,
    );
    if (pre.verdict !== 'OK') {
      throw new Error(
        `PRECONDITION: IGA jar not loaded (verdict=${pre.verdict}: ${pre.detail}) — ` +
          `restart the container, then re-run: ${rerunCommand()}`,
      );
    }

    // -----------------------------------------------------------------------
    // CASE A — IGA OFF (plain realm).
    // -----------------------------------------------------------------------
    await createScratchRealm(request, REALM);
    await createM2mClient(request, REALM);

    const ccOff = await clientCredentials(request, REALM);
    await assertValidNullSidToken(request, REALM, ccOff, 'IGA-OFF');

    // -----------------------------------------------------------------------
    // CASE B — IGA ON (same realm toggled). The toggle-on adopt scan emits a
    // PENDING ADOPT_CLIENT for the m2m client AND a PENDING ADOPT_USER for its
    // service-account user — BOTH quarantine the client_credentials path
    // (phase6c CASE 3): the token endpoint 401s while the client is unsigned,
    // and even once the client commits, introspection's state validation
    // returns active:false while the backing service-account USER is still
    // quarantined. Master is exempt from approver gates, so authorize+commit
    // every PENDING ADOPT_CLIENT/ADOPT_USER, then re-assert the grant. This
    // proves the sid-null guard holds with isIGAEnabled==true set on the realm
    // (the EdDSA branch's gating condition), not just IGA off.
    // -----------------------------------------------------------------------
    await enableIga(request, REALM);

    // sanity: the client got an ADOPT_CLIENT pinned to its UUID.
    const uuid = await clientUuid(request, REALM, CLIENT_ID);
    const pending = await listChangeRequests(request, REALM, 'PENDING');
    expect(
      pending.some(
        (cr) => cr.actionType === 'ADOPT_CLIENT' && cr.entityId === uuid,
      ),
      'IGA-ON: toggle emitted ADOPT_CLIENT for the m2m client',
    ).toBe(true);

    // Commit every ADOPT for the client + its service-account user.
    const toAdopt = pending.filter(
      (cr) => cr.actionType === 'ADOPT_CLIENT' || cr.actionType === 'ADOPT_USER',
    );
    for (const cr of toAdopt) {
      const ac = await authorizeAndCommit(request, REALM, cr.id);
      expect(
        [200, 409],
        `IGA-ON: ${cr.actionType} authorize HTTP ${ac.authorize.http}`,
      ).toContain(ac.authorize.http);
      expect(
        [200, 412],
        `IGA-ON: ${cr.actionType} commit HTTP ${ac.commit.http}`,
      ).toContain(ac.commit.http);
    }

    const ccOn = await clientCredentials(request, REALM);
    await assertValidNullSidToken(request, REALM, ccOn, 'IGA-ON');
  });
});

/*
 * EdDSA-specific coverage — NOTE (not faked):
 * To genuinely exercise the "EdDSA M2M null-sid" combination the realm must
 * (a) have `defaultSignatureAlgorithm: "EdDSA"` (or the client's
 * access.token.signed.response.alg = EdDSA) AND (b) have IGA enabled AND
 * (c) carry a `tide-vendor-key` component with gVRK/gVRKCertificate (or an
 * `eddsaPrivateKey` for the Ragnarok local-sign path). Only then does
 * DefaultTokenManager.encode take the encodeTideSignedTokens branch
 * (:177). Without the Tide vendor-key provisioned (the licensed/enrolled
 * realm path — not configurable from the admin REST surface this harness
 * uses), that branch is unreachable, so this spec covers the default RS256
 * encode path solidly and DOES NOT fabricate an EdDSA realm. Provisioning a
 * tide-vendor-key + live ORK network would be required to extend coverage
 * to the EdDSA M2M path.
 */
