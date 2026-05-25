import { test, expect, APIRequestContext, APIResponse } from '@playwright/test';
import { execSync } from 'child_process';
import {
  createScratchRealm,
  deleteRealm,
  enableIga,
  igaStatus,
  clientUuid,
  createClientScope,
  getClientScopeByName,
  createRole,
  getRole,
  getChangeRequest,
  authorizeAndCommit,
  locationHeader,
  safeJson,
  kcFetch,
} from '../lib/kc';

/**
 * Phase 9 — EDGE attestation coverage (COMMIT 1 only).
 *
 * Proves commit 1 closed the attestation-coverage gap for nested rows on a
 * GOVERNED create:
 *
 *  COMMIT 1 (stamp-only): a GOVERNED create that has nested rows now stamps the
 *  nested rows too, not just the root entity:
 *    - CREATE_CLIENT_SCOPE with a protocol mapper  → PROTOCOL_MAPPER.attestation non-null
 *    - CREATE_ROLE (composite)                     → COMPOSITE_ROLE.attestation non-null
 *    - CREATE_CLIENT with a protocol mapper        → PROTOCOL_MAPPER.attestation non-null
 *
 * COMMIT 2 (toggle-on ADOPT edge coverage) was reverted — it poisoned the
 * toggle-on scan transaction (edge CRs overflowed IGA_CHANGE_REQUEST.ENTITY_ID
 * varchar(36)). Its `commit2:` test has been dropped pending a redo; the parked
 * work lives at reflog SHA 58a827f.
 *
 * API E2E (no browser). Edge attestations are verified inline via
 * `docker exec postgresP psql`.
 *
 * Precondition gate: a governed CREATE_CLIENT_SCOPE must 202+Location. If it
 * does not, the phase9 jar (commit 1) is not loaded in the running container;
 * the test STOPS with an unambiguous PRECONDITION message (restart, re-run).
 */

const C1_REALM = 'iga-phase9-c1';
const PROBE_REALM = 'iga-phase9-precond-probe';

const RERUN =
  'cd /home/sasha/project/tidecloak-iga-extensions/e2e && npx playwright test phase9';

const PG_CONTAINER = 'postgresP';
const PG_USER = 'tideadmin';
const PG_DB = 'dauthme';

/** Run `docker exec postgresP psql -tAc "<sql>"` and return trimmed stdout. */
function psql(sql: string): string {
  const oneLine = sql.replace(/\s+/g, ' ').trim();
  const out = execSync(
    `docker exec ${PG_CONTAINER} psql -U ${PG_USER} -d ${PG_DB} -tAc ${JSON.stringify(oneLine)}`,
    { encoding: 'utf8' },
  );
  return out.trim();
}

function sqlLit(v: string): string {
  return v.replace(/'/g, "''");
}

/** count||attestation for a COMPOSITE_ROLE edge (composite, child_role). */
function readCompositeAttestation(parentId: string, childId: string): string {
  const out = psql(
    `SELECT COUNT(*) || E'\\x1F' || COALESCE(MAX(attestation),'')
       FROM composite_role
      WHERE composite='${sqlLit(parentId)}' AND child_role='${sqlLit(childId)}'`,
  );
  const [count, att] = out.split('\x1F');
  if (!count || count === '0') return 'MISSING';
  return att ?? '';
}

/** All protocol_mapper rows (id) owned by a client scope, with attestation. */
function mapperRowsForScope(scopeId: string): Array<{ id: string; att: string }> {
  const out = psql(
    `SELECT id || E'\\x1F' || COALESCE(attestation,'')
       FROM protocol_mapper WHERE client_scope_id='${sqlLit(scopeId)}'`,
  );
  if (!out) return [];
  return out
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const [id, att] = l.split('\x1F');
      return { id, att: att ?? '' };
    });
}

/** Resolve a CR id from a 202 (body.changeRequestId or Location tail). */
async function crIdFrom(res: APIResponse): Promise<string> {
  const body = await safeJson(res);
  const loc = locationHeader(res);
  return (body && body.changeRequestId) || (loc ? loc.split('/').pop() : '') || '';
}

const MAPPER_SPEC = {
  name: 'p9-mapper',
  protocol: 'openid-connect',
  protocolMapper: 'oidc-usermodel-attribute-mapper',
  config: {
    'user.attribute': 'p9attr',
    'claim.name': 'p9_claim',
    'jsonType.label': 'String',
    'access.token.claim': 'true',
    'id.token.claim': 'true',
  },
};

test.describe('IGA Phase 9: edge attestation coverage', () => {
  test.afterAll(async ({ request }) => {
    await deleteRealm(request, C1_REALM).catch(() => {});
    await deleteRealm(request, PROBE_REALM).catch(() => {});
  });

  // -------------------------------------------------------------------------
  // COMMIT 1 — governed create stamps NESTED rows.
  // -------------------------------------------------------------------------
  test('commit1: governed create stamps nested mappers + composite edges', async ({
    request,
  }) => {
    // PRECONDITION: governed CREATE_CLIENT_SCOPE must 202 (jar loaded).
    const pre = await (async () => {
      const evidence: Record<string, unknown> = {};
      try {
        await createScratchRealm(request, PROBE_REALM);
        await enableIga(request, PROBE_REALM);
        const r = await createClientScope(request, PROBE_REALM, {
          name: 'p9-probe-scope',
          protocol: 'openid-connect',
        });
        evidence.scopeCreateStatus = r.status();
        evidence.scopeCreateLocation = locationHeader(r) ?? null;
        if (r.status() !== 202 || !locationHeader(r)) {
          return {
            ok: false as const,
            detail: `governed CREATE_CLIENT_SCOPE expected 202+Location, got ${r.status()}`,
            evidence,
          };
        }
        const crId = await crIdFrom(r);
        const cr = await getChangeRequest(request, PROBE_REALM, crId);
        evidence.crActionType = cr.body?.actionType;
        if (cr.body?.actionType !== 'CREATE_CLIENT_SCOPE') {
          return {
            ok: false as const,
            detail: `CR actionType expected CREATE_CLIENT_SCOPE, got ${cr.body?.actionType}`,
            evidence,
          };
        }
        return { ok: true as const, detail: 'phase9 jar loaded.', evidence };
      } catch (e: any) {
        return { ok: false as const, detail: `probe raised: ${e?.message ?? e}`, evidence };
      } finally {
        await deleteRealm(request, PROBE_REALM).catch(() => {});
      }
    })();
    console.log(
      `\n[PRECONDITION phase9/commit1] ok=${pre.ok}\n  ${pre.detail}\n  evidence=${JSON.stringify(
        pre.evidence,
        null,
        2,
      )}\n`,
    );
    if (!pre.ok) {
      throw new Error(
        `PRECONDITION: phase9 jar not loaded (${pre.detail}) — restart the container, then re-run: ${RERUN}`,
      );
    }

    await createScratchRealm(request, C1_REALM);
    await enableIga(request, C1_REALM);
    const st = await igaStatus(request, C1_REALM);
    expect(st.enabled, 'IGA enabled').toBe(true);

    // --- A. CREATE_CLIENT_SCOPE WITH a protocol mapper ---------------------
    const scRes = await createClientScope(request, C1_REALM, {
      name: 'p9-scope-with-mapper',
      protocol: 'openid-connect',
      protocolMappers: [MAPPER_SPEC],
    });
    expect(scRes.status(), 'governed CREATE_CLIENT_SCOPE 202').toBe(202);
    const scCrId = await crIdFrom(scRes);
    const acSc = await authorizeAndCommit(request, C1_REALM, scCrId);
    expect(acSc.commit.http, `scope commit ${JSON.stringify(acSc.commit.body)}`).toBe(200);

    // The scope now exists; find its id and its mapper id from the DB.
    const scope = await getClientScopeByName(request, C1_REALM, 'p9-scope-with-mapper');
    const scopeId = scope.body?.id as string;
    expect(scopeId, 'scope id resolvable post-commit').toBeTruthy();

    const scopeMappers = mapperRowsForScope(scopeId);
    expect(scopeMappers.length, 'scope must have its nested mapper persisted').toBeGreaterThan(0);
    for (const m of scopeMappers) {
      expect(
        m.att.length > 0,
        `nested scope mapper ${m.id} attestation must be non-null (commit 1), got '${m.att}'`,
      ).toBeTruthy();
    }

    // --- B. CREATE_ROLE composite → COMPOSITE_ROLE edge stamped ------------
    // Create a child role pre-governance is not possible (IGA on), so create
    // both as governed roles, then create the parent as a composite of child.
    const childRes = await createRole(request, C1_REALM, { name: 'p9-child' });
    expect(childRes.status(), 'governed CREATE_ROLE child 202').toBe(202);
    const acChild = await authorizeAndCommit(request, C1_REALM, await crIdFrom(childRes));
    expect(acChild.commit.http, 'child role commit').toBe(200);

    const parentRes = await createRole(request, C1_REALM, {
      name: 'p9-parent',
      composite: true,
      composites: { realm: ['p9-child'] },
    });
    expect(parentRes.status(), 'governed CREATE_ROLE composite parent 202').toBe(202);
    const acParent = await authorizeAndCommit(request, C1_REALM, await crIdFrom(parentRes));
    expect(acParent.commit.http, `parent role commit ${JSON.stringify(acParent.commit.body)}`).toBe(
      200,
    );

    const parent = await getRole(request, C1_REALM, 'p9-parent');
    const child = await getRole(request, C1_REALM, 'p9-child');
    const parentId = parent.body?.id as string;
    const childId = child.body?.id as string;
    expect(parentId && childId, 'parent+child role ids resolvable').toBeTruthy();

    const compAtt = readCompositeAttestation(parentId, childId);
    expect(compAtt !== 'MISSING', 'composite edge row present after commit').toBeTruthy();
    expect(
      compAtt.length > 0,
      `COMPOSITE_ROLE edge attestation must be non-null (commit 1), got '${compAtt}'`,
    ).toBeTruthy();

    // --- C. CREATE_CLIENT with a protocol mapper → mapper stamped ----------
    const clientCreate = await kcFetch(request, `/admin/realms/${C1_REALM}/clients`, {
      method: 'POST',
      json: {
        clientId: 'p9-client-with-mapper',
        enabled: true,
        protocolMappers: [MAPPER_SPEC],
      },
    });
    expect(clientCreate.status(), 'governed CREATE_CLIENT 202').toBe(202);
    const acClient = await authorizeAndCommit(request, C1_REALM, await crIdFrom(clientCreate));
    expect(acClient.commit.http, `client commit ${JSON.stringify(acClient.commit.body)}`).toBe(200);

    const cUuid = await clientUuid(request, C1_REALM, 'p9-client-with-mapper');
    const clientMapperRows = psql(
      `SELECT id || E'\\x1F' || COALESCE(attestation,'')
         FROM protocol_mapper WHERE client_id='${sqlLit(cUuid)}'`,
    )
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l) => {
        const [id, att] = l.split('\x1F');
        return { id, att: att ?? '' };
      });
    expect(clientMapperRows.length, 'client must have its nested mapper persisted').toBeGreaterThan(
      0,
    );
    for (const m of clientMapperRows) {
      expect(
        m.att.length > 0,
        `nested client mapper ${m.id} attestation must be non-null (commit 1), got '${m.att}'`,
      ).toBeTruthy();
    }

    await deleteRealm(request, C1_REALM);
  });
});
