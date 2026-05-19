import { test, expect, APIRequestContext } from '@playwright/test';
import {
  createScratchRealm,
  deleteRealm,
  enableIga,
  igaStatus,
  createClientScope,
  getClientScopeByName,
  getClientScopeById,
  getClientScopeProtocolMappers,
  getChangeRequest,
  authorizeAndCommit,
  locationHeader,
  safeJson,
  ClientScopeSpec,
} from '../lib/kc';

/**
 * Phase 2 — model-layer full capture for client-scope creates (including
 * protocol mappers WITH full config AND attributes).
 *
 * This is an API E2E test (no browser). It drives the exact production path:
 * the IGA capture is enforced at the model layer
 * (IgaClientScopeAdapter#getId terminal seam during
 * RepresentationToModel.createClientScope), so raw Admin REST exercises the
 * same seam any caller hits.
 *
 * Order of operations mirrors the documented "configure bases BEFORE enabling
 * IGA" rule. A client scope has no external bases to pre-create, so the only
 * pre-IGA setup is the scratch realm itself.
 *
 * Precondition gate is parallel to Phase 1: a self-contained governed
 * client-scope create probe (its own probe realm) must yield 202 + Location
 * with the CR carrying the protocol mapper config / attributes in REP_JSON.
 * Anything else => the Phase 2 jar is not loaded in the running container and
 * the test STOPS with an unambiguous PRECONDITION message (NOT a scenario
 * failure; the user must restart the container then re-run).
 */

const REALM = 'iga-phase2-e2e';
const PROBE_REALM = 'iga-phase2-precond-probe';

const RERUN =
  'cd /home/sasha/project/tidecloak-iga-extensions/e2e && npx playwright test';

const scopeSpec = (): ClientScopeSpec => ({
  name: 'p2-scope',
  description: 'phase2 scope desc',
  // Non-default protocol (default scopes are openid-connect; use saml to
  // prove protocol fidelity through capture+replay).
  protocol: 'saml',
  attributes: {
    'display.on.consent.screen': 'true',
    'consent.screen.text': 'phase2-consent',
  },
  protocolMappers: [
    {
      name: 'p2-mapper',
      protocol: 'saml',
      protocolMapper: 'saml-user-attribute-mapper',
      // Non-default config — must survive capture + replay verbatim.
      config: {
        'attribute.nameformat': 'Basic',
        'user.attribute': 'p2CustomAttr',
        'attribute.name': 'p2-attr-name',
        'friendly.name': 'p2-friendly',
      },
    },
  ],
});

function mapperByName(list: any[], name: string): any | undefined {
  return list.find((m) => m?.name === name);
}

test.describe('IGA Phase 2: client-scope governed create/replay', () => {
  // Always clean up both realms, even on failure.
  test.afterAll(async ({ request }) => {
    await deleteRealm(request, REALM).catch(() => {});
    await deleteRealm(request, PROBE_REALM).catch(() => {});
  });

  test('Phase 2 governed client-scope create → CR → authorize+commit → full fidelity', async ({
    request,
  }) => {
    // -----------------------------------------------------------------------
    // PRECONDITION GATE — a governed client-scope create must 202 + carry the
    // full rep (protocol mapper config + attributes) in the CR. Mirrors the
    // Phase 1 precondition idea but probes the Phase 2 (client-scope) seam.
    // -----------------------------------------------------------------------
    const pre = await (async () => {
      const evidence: Record<string, unknown> = {};
      try {
        await createScratchRealm(request, PROBE_REALM);
        await enableIga(request, PROBE_REALM);
        evidence.igaEnabled = true;

        const res = await createClientScope(request, PROBE_REALM, {
          name: 'probe-scope',
          description: 'precond probe',
          protocol: 'saml',
          attributes: { 'consent.screen.text': 'probe' },
          protocolMappers: [
            {
              name: 'probe-mapper',
              protocol: 'saml',
              protocolMapper: 'saml-user-attribute-mapper',
              config: {
                'user.attribute': 'probeAttr',
                'attribute.name': 'probe-attr-name',
              },
            },
          ],
        });
        const status = res.status();
        const loc = locationHeader(res);
        const body = await safeJson(res);
        evidence.governedCreateStatus = status;
        evidence.governedCreateLocation = loc ?? null;
        evidence.governedCreateBody = body;

        if (status !== 202) {
          const hint =
            status === 500
              ? 'governed scope create returned 500 (provider jar likely not loaded — check server log for a ZipException/ClassNotFound on org.tidecloak.iga.*)'
              : status === 201
                ? 'governed scope create returned 201 (scope persisted immediately — IGA capture is NOT intercepting; Phase 2 capture path not active)'
                : `governed scope create returned ${status} (expected 202 Accepted)`;
          return { ok: false as const, detail: hint, evidence };
        }
        if (!loc) {
          return {
            ok: false as const,
            detail:
              'governed scope create returned 202 but no Location header — Phase 0/2 (Location on 202) not loaded.',
            evidence,
          };
        }
        const crId =
          (body && (body.changeRequestId as string)) ||
          loc.split('/').pop() ||
          '';
        const cr = await getChangeRequest(request, PROBE_REALM, crId);
        evidence.probeCrHttp = cr.http;
        evidence.probeCrActionType = cr.body?.actionType;
        evidence.probeCrStatus = cr.body?.status;
        if (cr.http !== 200 || cr.body?.actionType !== 'CREATE_CLIENT_SCOPE') {
          return {
            ok: false as const,
            detail:
              `202 returned but CR not retrievable as a CREATE_CLIENT_SCOPE ` +
              `(GET CR http=${cr.http}, actionType=${cr.body?.actionType}).`,
            evidence,
          };
        }
        const rowsJson = JSON.stringify(cr.body?.rows ?? cr.body ?? {});
        // The captured REP_JSON must carry the protocol mapper + its
        // non-default config AND the custom attribute — this is exactly the
        // pre-Phase-2 lossy behaviour we are guarding against.
        const carriesFullRep =
          rowsJson.includes('probe-mapper') &&
          rowsJson.includes('probeAttr') &&
          rowsJson.includes('probe-attr-name');
        evidence.probeCrCarriesFullRep = carriesFullRep;
        if (!carriesFullRep) {
          return {
            ok: false as const,
            detail:
              'CREATE_CLIENT_SCOPE CR captured but protocol-mapper config / ' +
              'attributes dropped from REP_JSON — pre-Phase-2 behaviour; ' +
              'Phase 2 full-rep capture not loaded.',
            evidence,
          };
        }
        return { ok: true as const, detail: 'Phase 2 loaded.', evidence };
      } catch (e: any) {
        return {
          ok: false as const,
          detail: `Probe governed client-scope create raised: ${e?.message ?? e}`,
          evidence,
        };
      } finally {
        await deleteRealm(request, PROBE_REALM).catch(() => {});
      }
    })();

    console.log(
      `\n[PRECONDITION phase2] ok=${pre.ok}\n  ${pre.detail}\n  evidence=${JSON.stringify(
        pre.evidence,
        null,
        2,
      )}\n`,
    );
    if (!pre.ok) {
      throw new Error(
        `PRECONDITION: Phase 2 jar not loaded in the running container ` +
          `(${pre.detail}) — restart the container, then re-run: ${RERUN}`,
      );
    }

    // -----------------------------------------------------------------------
    // 1. Scratch realm (no external bases needed for a client scope).
    // -----------------------------------------------------------------------
    await createScratchRealm(request, REALM);

    const st0 = await igaStatus(request, REALM);
    expect(
      st0.enabled,
      `IGA should start disabled on a fresh realm (got ${JSON.stringify(st0)})`,
    ).toBeFalsy();

    // -----------------------------------------------------------------------
    // 2. Enable IGA + sanity-confirm active.
    // -----------------------------------------------------------------------
    await enableIga(request, REALM);
    const st1 = await igaStatus(request, REALM);
    expect(st1.http, 'iga-status http').toBe(200);
    expect(st1.enabled, 'IGA must be enabled').toBe(true);

    // -----------------------------------------------------------------------
    // 3. Governed client-scope create (non-default protocol + custom
    //    attribute + a protocol mapper with non-default config).
    // -----------------------------------------------------------------------
    const spec = scopeSpec();
    const create = await createClientScope(request, REALM, spec);
    const status = create.status();
    const loc = locationHeader(create);
    const body = await safeJson(create);
    expect(
      status,
      `client-scope governed create expected 202, got ${status} body=${JSON.stringify(body)}`,
    ).toBe(202);
    expect(
      loc,
      `202 must carry a Location header (got ${JSON.stringify(create.headers())})`,
    ).toBeTruthy();

    const crId =
      (body && body.changeRequestId) || (loc ? loc.split('/').pop() : '');
    expect(crId, 'CR id resolvable from body/Location').toBeTruthy();

    const cr = await getChangeRequest(request, REALM, crId);
    expect(cr.http, `GET ${loc} expected 200`).toBe(200);
    expect(
      cr.body?.actionType,
      `CR actionType expected CREATE_CLIENT_SCOPE, got ${cr.body?.actionType}`,
    ).toBe('CREATE_CLIENT_SCOPE');
    expect(
      cr.body?.status,
      `CR status expected PENDING, got ${cr.body?.status}`,
    ).toBe('PENDING');

    // Not yet persisted at draft (zero rows persisted before commit).
    const draft = await getClientScopeByName(request, REALM, spec.name);
    expect(
      draft.body,
      `scope ${spec.name} must NOT exist before commit (got ${JSON.stringify(draft.body)})`,
    ).toBeFalsy();

    // -----------------------------------------------------------------------
    // 4. Authorize + commit (threshold 1, no approver roles → self).
    // -----------------------------------------------------------------------
    const ac = await authorizeAndCommit(request, REALM, crId);
    expect(
      ac.authorize.http,
      `CR authorize expected 200, got ${ac.authorize.http} ${JSON.stringify(ac.authorize.body)}`,
    ).toBe(200);
    expect(
      ac.commit.http,
      `CR commit expected 200, got ${ac.commit.http} ${JSON.stringify(ac.commit.body)}`,
    ).toBe(200);

    // -----------------------------------------------------------------------
    // 5. Post-commit fidelity asserts: scope exists with protocol, the custom
    //    attribute, AND the protocol mapper WITH its full non-default config.
    // -----------------------------------------------------------------------
    const found = await getClientScopeByName(request, REALM, spec.name);
    expect(
      found.body,
      `scope ${spec.name} must exist after commit`,
    ).toBeTruthy();
    const scopeId = found.body.id as string;
    expect(scopeId, 'committed scope must have a UUID').toBeTruthy();

    const full = await getClientScopeById(request, REALM, scopeId);
    expect(full.http, 'GET scope by id after commit').toBe(200);
    expect(full.body?.protocol, 'scope protocol fidelity').toBe('saml');
    expect(
      full.body?.description,
      'scope description fidelity',
    ).toBe('phase2 scope desc');
    expect(
      full.body?.attributes?.['consent.screen.text'],
      `scope custom attribute fidelity (got ${JSON.stringify(full.body?.attributes)})`,
    ).toBe('phase2-consent');
    expect(
      full.body?.attributes?.['display.on.consent.screen'],
      `scope custom attribute fidelity (got ${JSON.stringify(full.body?.attributes)})`,
    ).toBe('true');

    const pm = await getClientScopeProtocolMappers(request, REALM, scopeId);
    expect(pm.http, 'scope protocol-mappers http').toBe(200);
    const mapper = mapperByName(pm.body, 'p2-mapper');
    expect(
      mapper,
      `scope must carry protocol mapper p2-mapper after commit (got ${JSON.stringify(
        pm.body.map((m: any) => m?.name),
      )})`,
    ).toBeTruthy();
    expect(mapper.protocol, 'mapper protocol fidelity').toBe('saml');
    expect(mapper.protocolMapper, 'mapper type fidelity').toBe(
      'saml-user-attribute-mapper',
    );
    // The full non-default config must have round-tripped verbatim.
    expect(
      mapper.config?.['user.attribute'],
      `mapper config user.attribute fidelity (got ${JSON.stringify(mapper.config)})`,
    ).toBe('p2CustomAttr');
    expect(
      mapper.config?.['attribute.name'],
      `mapper config attribute.name fidelity (got ${JSON.stringify(mapper.config)})`,
    ).toBe('p2-attr-name');
    expect(
      mapper.config?.['attribute.nameformat'],
      `mapper config attribute.nameformat fidelity (got ${JSON.stringify(mapper.config)})`,
    ).toBe('Basic');
    expect(
      mapper.config?.['friendly.name'],
      `mapper config friendly.name fidelity (got ${JSON.stringify(mapper.config)})`,
    ).toBe('p2-friendly');

    // -----------------------------------------------------------------------
    // 6. Cleanup (afterAll also deletes; do it here too and confirm).
    // -----------------------------------------------------------------------
    await deleteRealm(request, REALM);
    const gone = await igaStatus(request, REALM);
    expect(
      gone.http,
      `scratch realm must be deleted (iga-status expected 404, got ${gone.http})`,
    ).toBe(404);
  });
});
