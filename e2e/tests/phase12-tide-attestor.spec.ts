import { test, expect, APIRequestContext, APIResponse } from '@playwright/test';
import { execSync } from 'child_process';
import {
  createScratchRealm,
  deleteRealm,
  enableIga,
  igaStatus,
  setRealmIgaAttr,
  createRole,
  getRole,
  createClientScope,
  getClientScopeByName,
  createUser,
  getUserByUsername,
  assignRealmRoleMapping,
  findChangeRequest,
  authorizeAndCommit,
  locationHeader,
  safeJson,
  kcFetch,
  UserSpec,
} from '../lib/kc';

/**
 * Phase 12 — DUMMY TideAttestor: per-(table, owner) SET-SIGNING.
 *
 * On a realm with `iga.attestor=tide` (set BEFORE enabling IGA so it is not
 * itself governed), LINKAGE rows are signed as a per-(table, owner) SET: all
 * rows in a table sharing the same owner key carry ONE identical aggregate
 * signature, and adding/removing a row RE-SIGNS the whole owner set (a new sig
 * fanned out to every surviving row). NODE entities (user_entity) keep a
 * per-entity signature over their own state.
 *
 * This spec proves, end to end against the running container + Postgres:
 *  1. user_role_mapping: granting R1 then R2 to user U makes BOTH rows carry the
 *     SAME sig; granting R3 makes all THREE share a NEW identical sig (re-sign +
 *     fan-out). The dummy sig has the `TIDE-DUMMY-v1:` prefix and is
 *     deterministic.
 *  2. client_scope_role_mapping: two realm roles mapped onto one client-scope
 *     share one identical set sig.
 *  3. The user_entity NODE row carries its OWN per-entity sig (NOT the set sig).
 *  4. REGRESSION GUARD: on a SEPARATE realm using the default `simple` attestor,
 *     two role grants produce two DISTINCT per-row attestations — today's
 *     behaviour, preserved by the dispatcher's set-signed gating.
 *
 * API E2E (no browser). Attestations verified inline via
 * `docker exec postgresP psql`.
 */

const TIDE_REALM = 'iga-phase12-tide';
const SIMPLE_REALM = 'iga-phase12-simple';
const PROBE_REALM = 'iga-phase12-precond-probe';

const RERUN =
  'cd /home/sasha/project/tidecloak-iga-extensions/e2e && npx playwright test phase12';

const DUMMY_PREFIX = 'TIDE-DUMMY-v1:';

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

/** Single user_role_mapping row's attestation (user_id, role_id). 'MISSING' if absent. */
function readUserRoleAtt(userId: string, roleId: string): string {
  const out = psql(
    `SELECT COUNT(*) || E'\\x1F' || COALESCE(MAX(attestation),'')
       FROM user_role_mapping
      WHERE user_id='${sqlLit(userId)}' AND role_id='${sqlLit(roleId)}'`,
  );
  const [count, att] = out.split('\x1F');
  if (!count || count === '0') return 'MISSING';
  return att ?? '';
}

/** user_entity NODE row's attestation. 'MISSING' if absent. */
function readUserEntityAtt(userId: string): string {
  const out = psql(
    `SELECT COUNT(*) || E'\\x1F' || COALESCE(MAX(attestation),'')
       FROM user_entity
      WHERE id='${sqlLit(userId)}'`,
  );
  const [count, att] = out.split('\x1F');
  if (!count || count === '0') return 'MISSING';
  return att ?? '';
}

/** client_scope_role_mapping row's attestation (scope_id, role_id). 'MISSING' if absent. */
function readScopeRoleAtt(scopeId: string, roleId: string): string {
  const out = psql(
    `SELECT COUNT(*) || E'\\x1F' || COALESCE(MAX(attestation),'')
       FROM client_scope_role_mapping
      WHERE scope_id='${sqlLit(scopeId)}' AND role_id='${sqlLit(roleId)}'`,
  );
  const [count, att] = out.split('\x1F');
  if (!count || count === '0') return 'MISSING';
  return att ?? '';
}

/** POST a realm-role scope-mapping onto a client-scope's allowlist → SCOPE_ADD_ROLE CR. */
function addScopeRealmRoleMapping(
  request: APIRequestContext,
  realm: string,
  scopeId: string,
  role: { id: string; name: string },
): Promise<APIResponse> {
  return kcFetch(
    request,
    `/admin/realms/${realm}/client-scopes/${scopeId}/scope-mappings/realm`,
    { method: 'POST', json: [role] },
  );
}

/** Drive a governed CREATE_USER to a committed user; return its UUID. */
async function createGovernedUserCommitted(
  request: APIRequestContext,
  realm: string,
  spec: UserSpec,
): Promise<string> {
  const create = await createUser(request, realm, spec);
  const status = create.status();
  const loc = locationHeader(create);
  const body = await safeJson(create);
  expect(
    status,
    `governed user create expected 202, got ${status} body=${JSON.stringify(body)}`,
  ).toBe(202);
  const crId = (body && body.changeRequestId) || (loc ? loc.split('/').pop() : '');
  expect(crId, 'CREATE_USER CR id resolvable').toBeTruthy();
  const ac = await authorizeAndCommit(request, realm, crId);
  expect(ac.commit.http, `CREATE_USER commit ${JSON.stringify(ac.commit.body)}`).toBe(200);
  const found = await getUserByUsername(request, realm, spec.username);
  expect(found.body, `user ${spec.username} must exist after commit`).toBeTruthy();
  return found.body.id as string;
}

/** Grant a realm role to a user via a GRANT_ROLES CR, then commit it. */
async function grantRoleCommitted(
  request: APIRequestContext,
  realm: string,
  userId: string,
  role: { id: string; name: string },
): Promise<void> {
  const assign = await assignRealmRoleMapping(request, realm, userId, [role]);
  expect(
    assign.status() < 300,
    `role-mapping POST expected 2xx (deferred), got ${assign.status()}`,
  ).toBeTruthy();
  const cr = await findChangeRequest(
    request,
    realm,
    'GRANT_ROLES',
    (c) =>
      Array.isArray((c as any).rows) &&
      (c as any).rows.some((x: any) => x.ROLE_ID === role.id),
  );
  expect(cr, `PENDING GRANT_ROLES CR for role ${role.name}`).toBeTruthy();
  const ac = await authorizeAndCommit(request, realm, (cr as any).id);
  expect(ac.commit.http, `GRANT_ROLES commit ${JSON.stringify(ac.commit.body)}`).toBe(200);
}

test.describe('IGA Phase 12: dummy TideAttestor set-signing', () => {
  test.afterAll(async ({ request }) => {
    await deleteRealm(request, TIDE_REALM).catch(() => {});
    await deleteRealm(request, SIMPLE_REALM).catch(() => {});
    await deleteRealm(request, PROBE_REALM).catch(() => {});
  });

  test('tide attestor: per-(table,owner) set-signing, re-sign-on-change, node per-entity sig', async ({
    request,
  }) => {
    // -----------------------------------------------------------------------
    // PRECONDITION GATE — on a tide realm, a governed CREATE_USER must 202 and
    // commit, and its user_entity row must carry a TIDE-DUMMY-v1: sig. If the
    // 202 path is missing the jar is not loaded → restart then re-run. If it
    // 202s but the sig is wrong that is a code bug (do NOT restart).
    // -----------------------------------------------------------------------
    const pre = await (async () => {
      const evidence: Record<string, unknown> = {};
      try {
        await createScratchRealm(request, PROBE_REALM);
        // attestor MUST be set before IGA is enabled (else it becomes a CR).
        await setRealmIgaAttr(request, PROBE_REALM, 'iga.attestor', 'tide');
        await enableIga(request, PROBE_REALM);
        const uid = await createGovernedUserCommitted(request, PROBE_REALM, {
          username: 'p12-probe-user',
          enabled: true,
          email: 'p12-probe-user@example.test',
        });
        const att = readUserEntityAtt(uid);
        evidence.userEntityAtt = att;
        if (att === 'MISSING' || !att.startsWith(DUMMY_PREFIX)) {
          return {
            ok: false as const,
            loaded: att !== 'MISSING',
            detail:
              att === 'MISSING'
                ? 'user_entity has no attestation after governed CREATE_USER commit (tide jar likely not loaded)'
                : `user_entity attestation lacks ${DUMMY_PREFIX} prefix (got '${att}') — code bug`,
            evidence,
          };
        }
        return { ok: true as const, loaded: true, detail: 'tide attestor loaded.', evidence };
      } catch (e: any) {
        return { ok: false as const, loaded: false, detail: `probe raised: ${e?.message ?? e}`, evidence };
      } finally {
        await deleteRealm(request, PROBE_REALM).catch(() => {});
      }
    })();
    console.log(
      `\n[PRECONDITION phase12] ok=${pre.ok} loaded=${pre.loaded}\n  ${pre.detail}\n  evidence=${JSON.stringify(
        pre.evidence,
        null,
        2,
      )}\n`,
    );
    if (!pre.ok) {
      if (pre.loaded) {
        throw new Error(`PRECONDITION: tide jar loaded but misbehaving — code bug. ${pre.detail}`);
      }
      throw new Error(
        `PRECONDITION: tide attestor not loaded in the running container (${pre.detail}) — restart, then re-run: ${RERUN}`,
      );
    }

    // -----------------------------------------------------------------------
    // 1. tide realm + bases (IGA OFF): 3 realm roles + 1 client-scope + 2
    //    scope roles. attestor=tide set BEFORE enableIga.
    // -----------------------------------------------------------------------
    await createScratchRealm(request, TIDE_REALM);
    for (const n of ['r1', 'r2', 'r3', 'sr1', 'sr2']) {
      expect((await createRole(request, TIDE_REALM, { name: n })).status(), `role ${n}`).toBe(201);
    }
    expect(
      (await createClientScope(request, TIDE_REALM, { name: 'p12-scope', protocol: 'openid-connect' })).status(),
      'client-scope create',
    ).toBe(201);

    await setRealmIgaAttr(request, TIDE_REALM, 'iga.attestor', 'tide');
    await enableIga(request, TIDE_REALM);
    const st = await igaStatus(request, TIDE_REALM);
    expect(st.enabled, 'IGA enabled on tide realm').toBe(true);

    const r1 = (await getRole(request, TIDE_REALM, 'r1')).body;
    const r2 = (await getRole(request, TIDE_REALM, 'r2')).body;
    const r3 = (await getRole(request, TIDE_REALM, 'r3')).body;
    const sr1 = (await getRole(request, TIDE_REALM, 'sr1')).body;
    const sr2 = (await getRole(request, TIDE_REALM, 'sr2')).body;

    // Governed CREATE_USER → user_entity gets its OWN node sig.
    const userId = await createGovernedUserCommitted(request, TIDE_REALM, {
      username: 'p12-user',
      enabled: true,
      email: 'p12-user@example.test',
    });
    const nodeSig = readUserEntityAtt(userId);
    expect(nodeSig.startsWith(DUMMY_PREFIX), `user_entity node sig has prefix, got '${nodeSig}'`).toBeTruthy();

    // -----------------------------------------------------------------------
    // 2. user_role_mapping set-signing across grants.
    // -----------------------------------------------------------------------
    // Grant R1 → 1-row set.
    await grantRoleCommitted(request, TIDE_REALM, userId, { id: r1.id, name: r1.name });
    const sigR1only = readUserRoleAtt(userId, r1.id);
    expect(sigR1only.startsWith(DUMMY_PREFIX), `R1 row sig prefix, got '${sigR1only}'`).toBeTruthy();

    // Grant R2 → BOTH rows must share ONE identical 2-row set sig.
    await grantRoleCommitted(request, TIDE_REALM, userId, { id: r2.id, name: r2.name });
    const sig2_r1 = readUserRoleAtt(userId, r1.id);
    const sig2_r2 = readUserRoleAtt(userId, r2.id);
    expect(sig2_r1.startsWith(DUMMY_PREFIX), `2-set R1 sig prefix, got '${sig2_r1}'`).toBeTruthy();
    expect(
      sig2_r1,
      `set-signing: after granting R2, R1 and R2 rows must carry the SAME set sig (R1='${sig2_r1}' R2='${sig2_r2}')`,
    ).toBe(sig2_r2);
    // The 2-row set sig must DIFFER from the 1-row set sig (re-signed on change).
    expect(
      sig2_r1,
      `re-sign-on-change: the 2-row set sig must differ from the 1-row sig ('${sig2_r1}' vs '${sigR1only}')`,
    ).not.toBe(sigR1only);

    // Grant R3 → all THREE rows must share a NEW identical 3-row set sig.
    await grantRoleCommitted(request, TIDE_REALM, userId, { id: r3.id, name: r3.name });
    const sig3_r1 = readUserRoleAtt(userId, r1.id);
    const sig3_r2 = readUserRoleAtt(userId, r2.id);
    const sig3_r3 = readUserRoleAtt(userId, r3.id);
    expect(sig3_r1, 'all 3 rows share sig (r1==r2)').toBe(sig3_r2);
    expect(sig3_r2, 'all 3 rows share sig (r2==r3)').toBe(sig3_r3);
    expect(
      sig3_r1,
      `re-sign-on-change: the 3-row set sig must differ from the 2-row sig ('${sig3_r1}' vs '${sig2_r1}')`,
    ).not.toBe(sig2_r1);

    // -----------------------------------------------------------------------
    // 3. The NODE user_entity sig is its OWN per-entity sig — NOT the set sig.
    // -----------------------------------------------------------------------
    expect(
      nodeSig,
      `node per-entity invariant: user_entity sig ('${nodeSig}') must NOT equal the user_role_mapping set sig ('${sig3_r1}')`,
    ).not.toBe(sig3_r1);
    // The node sig is unchanged by the role-set churn.
    expect(readUserEntityAtt(userId), 'node sig stable across role grants').toBe(nodeSig);

    // -----------------------------------------------------------------------
    // 4. SECOND TABLE — client_scope_role_mapping: two roles on one scope share
    //    one identical set sig.
    // -----------------------------------------------------------------------
    const scope = await getClientScopeByName(request, TIDE_REALM, 'p12-scope');
    const scopeId = scope.body?.id as string;
    expect(scopeId, 'scope id resolvable').toBeTruthy();

    for (const sr of [sr1, sr2]) {
      const add = await addScopeRealmRoleMapping(request, TIDE_REALM, scopeId, { id: sr.id, name: sr.name });
      expect(add.status() < 300, `scope-role add deferred 2xx, got ${add.status()}`).toBeTruthy();
      const cr = await findChangeRequest(
        request,
        TIDE_REALM,
        'SCOPE_ADD_ROLE',
        (c) => Array.isArray((c as any).rows) && (c as any).rows.some((x: any) => x.ROLE_ID === sr.id),
      );
      expect(cr, `PENDING SCOPE_ADD_ROLE CR for ${sr.name}`).toBeTruthy();
      const ac = await authorizeAndCommit(request, TIDE_REALM, (cr as any).id);
      expect(ac.commit.http, `SCOPE_ADD_ROLE commit ${JSON.stringify(ac.commit.body)}`).toBe(200);
    }
    const scopeSig1 = readScopeRoleAtt(scopeId, sr1.id);
    const scopeSig2 = readScopeRoleAtt(scopeId, sr2.id);
    expect(scopeSig1.startsWith(DUMMY_PREFIX), `scope-role sig prefix, got '${scopeSig1}'`).toBeTruthy();
    expect(
      scopeSig1,
      `set-signing (client_scope_role_mapping): both roles on the scope share ONE set sig (sr1='${scopeSig1}' sr2='${scopeSig2}')`,
    ).toBe(scopeSig2);

    // -----------------------------------------------------------------------
    // 5. Determinism: same set → same sig (re-reading the DB is stable; the
    //    dummy sign() is sha256 over the canonical set, so identical members
    //    yield identical bytes).
    // -----------------------------------------------------------------------
    expect(readUserRoleAtt(userId, r1.id), 'sig deterministic on re-read').toBe(sig3_r1);

    await deleteRealm(request, TIDE_REALM);
  });

  // -------------------------------------------------------------------------
  // REGRESSION GUARD — simple attestor keeps today's per-row distinct sigs.
  // -------------------------------------------------------------------------
  test('regression: simple attestor produces DISTINCT per-row attestations (today behaviour preserved)', async ({
    request,
  }) => {
    await createScratchRealm(request, SIMPLE_REALM);
    expect((await createRole(request, SIMPLE_REALM, { name: 's1' })).status()).toBe(201);
    expect((await createRole(request, SIMPLE_REALM, { name: 's2' })).status()).toBe(201);

    // NO iga.attestor attr → default `simple` attestor.
    await enableIga(request, SIMPLE_REALM);
    const st = await igaStatus(request, SIMPLE_REALM);
    expect(st.enabled, 'IGA enabled on simple realm').toBe(true);

    const s1 = (await getRole(request, SIMPLE_REALM, 's1')).body;
    const s2 = (await getRole(request, SIMPLE_REALM, 's2')).body;

    const userId = await createGovernedUserCommitted(request, SIMPLE_REALM, {
      username: 'p12-simple-user',
      enabled: true,
      email: 'p12-simple-user@example.test',
    });

    await grantRoleCommitted(request, SIMPLE_REALM, userId, { id: s1.id, name: s1.name });
    await grantRoleCommitted(request, SIMPLE_REALM, userId, { id: s2.id, name: s2.name });

    const a1 = readUserRoleAtt(userId, s1.id);
    const a2 = readUserRoleAtt(userId, s2.id);
    expect(a1 !== 'MISSING' && a1.length > 0, `s1 row attested, got '${a1}'`).toBeTruthy();
    expect(a2 !== 'MISSING' && a2.length > 0, `s2 row attested, got '${a2}'`).toBeTruthy();
    // simple attestor stamps each row independently → DISTINCT per-row sigs.
    // (The simple sig is a JSON array of {by,at}; the per-grant timestamp makes
    // the two rows differ, and crucially they are NOT fanned out / shared.)
    expect(
      a1,
      `regression: simple attestor must keep DISTINCT per-row attestations (s1='${a1}' s2='${a2}') — NO set fan-out`,
    ).not.toBe(a2);
    // And neither carries the tide dummy prefix.
    expect(a1.startsWith(DUMMY_PREFIX), 'simple sig is NOT a tide dummy sig').toBeFalsy();

    await deleteRealm(request, SIMPLE_REALM);
    const gone = await igaStatus(request, SIMPLE_REALM);
    expect(gone.http, 'simple realm deleted (iga-status 404)').toBe(404);
  });
});
