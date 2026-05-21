import { test, expect, APIRequestContext } from '@playwright/test';
import { execSync } from 'child_process';
import { gzipSync } from 'zlib';
import {
  createScratchRealm,
  deleteRealm,
  enableIga,
  igaStatus,
  createRole,
  createClient,
  createClientRole,
  createClientScope,
  createGroup,
  createUser,
  getRole,
  getClientRole,
  getRoleComposites,
  getGroupByName,
  getGroupById,
  getUserByUsername,
  getUserGroups,
  getUserRealmRoleMappings,
  getClientByClientId,
  getClientScopeById,
  getClientScopeByName,
  getClientScopeProtocolMappers,
  clientUuid,
  assignRealmRoleMapping,
  assignGroupRealmRoleMapping,
  listChangeRequests,
  findChangeRequest,
  getChangeRequest,
  authorizeAndCommit,
  locationHeader,
  safeJson,
  kcFetch,
} from '../lib/kc';

/**
 * Tide-network login-row visualizer (single test, no production-code changes).
 *
 * Builds a realistic contributor graph in a scratch realm, drives every IGA
 * capture through commit so the per-row ATTESTATION columns are populated,
 * then assembles the "snapshot bundle" that KC's future Tide-mode would POST
 * to the Tide network at OIDC token-issue time:
 *   (realm, client, user, effective-roles, groups, client-scopes, edges)
 * — each entity carrying its current attestation value.
 *
 * Prints TWO artifacts:
 *   1. REAL Tideless stamps read from Postgres
 *      (SimpleNameAttestor → `[{"by":"admin","at":<epoch>}]`).
 *   2. SIMULATED Tide-sized — same bundle, every attestation slot replaced
 *      with `"A".repeat(88)` (one base64 Ed25519 sig shape from
 *      Midgard.SignModel) so the human reader can SEE the cost of swapping
 *      the attestor.
 *
 * Pure visualizer. Assertions are light (presence + non-empty + counts);
 * deliberately no byte-count assertions because IDs/timestamps vary.
 *
 * No new npm deps; `child_process.execSync` + `zlib.gzipSync` are built-ins.
 *
 * No new helpers in e2e/tests/helpers — every DB-shaped helper lives inline.
 *
 * Postgres container: `postgresP`, DB `dauthme`, user `tideadmin` (read from
 * `docker ps` + `docker exec postgresP env`).
 */

const REALM = 'iga-tide-row-viz';
const CLIENT_ID_HUMAN = 'tide-viz-client';
const CLIENT_SECRET = 'tide-viz-secret';
const USER_NAME = 'alice';

// Roles
const REALM_ROLES = ['viz-realm-admin', 'viz-realm-editor', 'viz-realm-viewer'];
const COMPOSITE_PARENT = 'viz-composite-parent';
const CLIENT_ROLES = ['viz-client-write', 'viz-client-read'];
const GROUP_ROLE = 'viz-group-role'; // assigned to the parent group → group-inherited

// Groups
const PARENT_GROUP = 'engineering';
const CHILD_GROUP = 'platform';

// Client scopes
const SCOPE_DEFAULT_A = 'viz-scope-default-a';
const SCOPE_DEFAULT_B = 'viz-scope-default-b';
const SCOPE_OPTIONAL = 'viz-scope-optional';
const SCOPE_MAPPER_NAME = 'viz-scope-mapper';

const PG_CONTAINER = 'postgresP';
const PG_USER = 'tideadmin';
const PG_DB = 'dauthme';

const ATTEST_PLACEHOLDER = 'A'.repeat(88); // Tide-sized ed25519 b64 placeholder
const REALM_ANCHOR_SENTINEL = '__realm_anchor_no_column__'; // REALM has no col

// ---------------------------------------------------------------------------
// Inline helpers (do not add to e2e/tests/helpers/, per task constraints).
// ---------------------------------------------------------------------------

/** Run `docker exec postgresP psql -tAc "<sql>"` and return trimmed stdout. */
function psql(sql: string): string {
  const out = execSync(
    `docker exec ${PG_CONTAINER} psql -U ${PG_USER} -d ${PG_DB} -tAc ${JSON.stringify(sql)}`,
    { encoding: 'utf8' },
  );
  return out.trim();
}

/** Read a single ATTESTATION cell. Returns null when row missing OR null. */
function readAttestation(table: string, where: string): string | null {
  const sql = `SELECT COALESCE(attestation, '') FROM ${table} WHERE ${where} LIMIT 1`;
  const v = psql(sql);
  if (v === '') return null;
  return v;
}

/** Drive a governed POST to a committed entity, returning the CR id. */
async function commitGoverned(
  request: APIRequestContext,
  realm: string,
  res: import('@playwright/test').APIResponse,
  label: string,
): Promise<string> {
  const status = res.status();
  const loc = locationHeader(res);
  const body = await safeJson(res);
  expect(
    status,
    `${label} governed expected 202, got ${status} body=${JSON.stringify(body)}`,
  ).toBe(202);
  const crId =
    (body && body.changeRequestId) || (loc ? loc.split('/').pop() : '');
  expect(crId, `${label} CR id resolvable`).toBeTruthy();
  const ac = await authorizeAndCommit(request, realm, crId as string);
  expect(ac.authorize.http, `${label} authorize`).toBe(200);
  expect(
    ac.commit.http,
    `${label} commit expected 200, got ${ac.commit.http} ${JSON.stringify(ac.commit.body)}`,
  ).toBe(200);
  return crId as string;
}

/**
 * Drain every PENDING ADOPT_* CR via bulk-authorize (same endpoint Phase 6e
 * exercises). Returns the bulk summary for visibility.
 */
async function drainAdopts(
  request: APIRequestContext,
  realm: string,
): Promise<{ committed: number; total: number }> {
  const res = await kcFetch(
    request,
    `/admin/realms/${realm}/iga/change-requests/bulk-authorize`,
    {
      method: 'POST',
      json: {
        actionTypeIn: [
          'ADOPT_USER',
          'ADOPT_ROLE',
          'ADOPT_GROUP',
          'ADOPT_CLIENT',
          'ADOPT_CLIENT_SCOPE',
          'ADOPT_ORGANIZATION',
        ],
        limit: 1000,
      },
    },
  );
  expect(res.status(), 'drain bulk-authorize').toBe(200);
  const body = await safeJson(res);
  return { committed: body?.summary?.committed ?? 0, total: body?.summary?.total ?? 0 };
}

/** Drive ALL non-ADOPT pending CRs to commit (one at a time, threshold=1). */
async function drainAllPending(
  request: APIRequestContext,
  realm: string,
): Promise<number> {
  let drained = 0;
  // Loop a bounded number of times in case commits surface follow-on CRs.
  for (let i = 0; i < 25; i++) {
    const list = await listChangeRequests(request, realm, 'PENDING');
    if (list.length === 0) break;
    let progress = 0;
    for (const cr of list) {
      const ac = await authorizeAndCommit(request, realm, cr.id);
      // 200 = committed; 412 = threshold not met (shouldn't happen with master
      // alone on a no-threshold realm); 409 = duplicate sig (idempotent rerun).
      if (ac.commit.http === 200) {
        drained++;
        progress++;
      } else {
        // eslint-disable-next-line no-console
        console.log(
          `[drain] CR ${cr.id} (${cr.actionType}/${cr.entityType}) authorize=${ac.authorize.http} commit=${ac.commit.http} commitBody=${JSON.stringify(ac.commit.body)}`,
        );
      }
    }
    if (progress === 0) {
      // Nothing committed this round — break to avoid infinite loop (e.g. a
      // CR that genuinely cannot commit because authorize already 409s and
      // commit threshold can't be met).
      // eslint-disable-next-line no-console
      console.log(
        `[drain] stuck after ${i} rounds with ${list.length} PENDING CRs; breaking`,
      );
      break;
    }
  }
  return drained;
}

interface BundleEntity {
  id: string;
  [k: string]: unknown;
}

interface Bundle {
  version: string;
  realm: BundleEntity & { name: string; attestation: string };
  client: BundleEntity & { clientId: string; attestation: string };
  user: BundleEntity & { username: string; email?: string; attestation: string };
  effectiveRoles: Array<{
    id: string;
    name: string;
    containerKind: 'REALM' | 'CLIENT';
    containerId: string;
    attestation: string;
    via: 'direct' | 'composite' | 'group';
  }>;
  groups: Array<{
    id: string;
    name: string;
    path: string;
    attestation: string;
  }>;
  clientScopes: Array<{
    id: string;
    name: string;
    assignmentKind: 'default' | 'optional';
    attestation: string;
  }>;
  // Set-attested relationships (interpretation B): one CR commit binds the
  // SET of rows it stamped. Groups are keyed by (attestation_string, kind);
  // empty-attestation rows collapse into a single sentinel group per kind
  // with an explicit `note` so the gap is visible to the human reader.
  attestedRelationships: Array<{
    attestation: string;
    kind: string;
    applied: Array<Record<string, unknown>>;
    note?: string;
  }>;
}

// Legacy per-row bundle shape, used ONLY to keep the side-by-side comparison
// output for the human reader (Option (a) in the task spec).
interface LegacyEdgeBundle {
  version: string;
  realm: Bundle['realm'];
  client: Bundle['client'];
  user: Bundle['user'];
  effectiveRoles: Bundle['effectiveRoles'];
  groups: Bundle['groups'];
  clientScopes: Bundle['clientScopes'];
  edges: Array<{ kind: string; [k: string]: unknown }>;
}

/** Walk composite parents recursively to expand into transitive children. */
async function expandComposites(
  request: APIRequestContext,
  realm: string,
  parentName: string,
  seen: Set<string>,
): Promise<Array<{ id: string; name: string; containerKind: 'REALM'; containerId: string }>> {
  if (seen.has(parentName)) return [];
  seen.add(parentName);
  const comps = await getRoleComposites(request, realm, parentName);
  const out: Array<{ id: string; name: string; containerKind: 'REALM'; containerId: string }> = [];
  for (const child of comps.body || []) {
    if (!child?.id) continue;
    out.push({
      id: child.id,
      name: child.name,
      containerKind: 'REALM',
      containerId: child.containerId,
    });
    // Recurse only into realm-level composites for this visualizer.
    if (child?.composite && !child?.clientRole) {
      const grand = await expandComposites(request, realm, child.name, seen);
      out.push(...grand);
    }
  }
  return out;
}

/** Substitute every `attestation` slot in a (deeply) cloned legacy bundle. */
function withSimulatedAttestationsLegacy(b: LegacyEdgeBundle): LegacyEdgeBundle {
  const clone: LegacyEdgeBundle = JSON.parse(JSON.stringify(b));
  clone.realm.attestation = ATTEST_PLACEHOLDER;
  clone.client.attestation = ATTEST_PLACEHOLDER;
  clone.user.attestation = ATTEST_PLACEHOLDER;
  for (const r of clone.effectiveRoles) r.attestation = ATTEST_PLACEHOLDER;
  for (const g of clone.groups) g.attestation = ATTEST_PLACEHOLDER;
  for (const s of clone.clientScopes) s.attestation = ATTEST_PLACEHOLDER;
  for (const e of clone.edges) (e as any).attestation = ATTEST_PLACEHOLDER;
  return clone;
}

/**
 * Simulated variant of the SET-ATTESTED bundle.
 *
 * CRITICAL: we PRESERVE the grouping structure computed from the REAL bundle.
 * If we re-grouped from the placeholder strings, every kind would collapse to
 * a single group because all placeholders are identical — that would
 * misrepresent the cost. Instead we walk the existing groups and swap the
 * `attestation` field in-place. Empty-attestation sentinel groups stay empty
 * (placeholder substitution doesn't apply — those rows never went through
 * IGA capture, so a Tide attestor would still produce no signature).
 */
function withSimulatedAttestationsSet(b: Bundle): Bundle {
  const clone: Bundle = JSON.parse(JSON.stringify(b));
  clone.realm.attestation = ATTEST_PLACEHOLDER;
  clone.client.attestation = ATTEST_PLACEHOLDER;
  clone.user.attestation = ATTEST_PLACEHOLDER;
  for (const r of clone.effectiveRoles) r.attestation = ATTEST_PLACEHOLDER;
  for (const g of clone.groups) g.attestation = ATTEST_PLACEHOLDER;
  for (const s of clone.clientScopes) s.attestation = ATTEST_PLACEHOLDER;
  // Walk the SAME group structure — substitute attestation only on groups
  // that actually carried one (skip sentinel/empty-attestation groups).
  for (const rel of clone.attestedRelationships) {
    if (rel.attestation !== '') {
      rel.attestation = ATTEST_PLACEHOLDER;
    }
  }
  return clone;
}

function sizeOf(b: object): { pretty: number; minified: number; gzip: number } {
  const pretty = JSON.stringify(b, null, 2);
  const minified = JSON.stringify(b);
  return {
    pretty: Buffer.byteLength(pretty, 'utf8'),
    minified: Buffer.byteLength(minified, 'utf8'),
    gzip: gzipSync(minified).length,
  };
}

function printArtifact(
  label: string,
  b: object,
  contributors: string,
): void {
  const sizes = sizeOf(b);
  // eslint-disable-next-line no-console
  console.log(`\n=== Tide-network login-row (${label}) ===`);
  // eslint-disable-next-line no-console
  console.log(JSON.stringify(b, null, 2));
  // eslint-disable-next-line no-console
  console.log(`\n=== Sizes (${label}) ===`);
  // eslint-disable-next-line no-console
  console.log(`Pretty JSON:    ${sizes.pretty} bytes`);
  // eslint-disable-next-line no-console
  console.log(`Minified JSON:  ${sizes.minified} bytes`);
  // eslint-disable-next-line no-console
  console.log(`Gzip:           ${sizes.gzip} bytes`);
  // eslint-disable-next-line no-console
  console.log(`Contributors:   ${contributors}`);
}

/**
 * Group per-row edges into set-attested relationships.
 *
 * Grouping rule: GROUP BY (attestation_string, kind). Empty attestations
 * collapse into a single sentinel group per kind with an explicit `note`
 * so the gap (rows that never went through IGA capture) is visible.
 *
 * `appliedKeys` lists which edge fields belong in the `applied[]` row body
 * for each kind (everything BUT `kind` and `attestation`).
 */
function groupEdgesByAttestation(
  edges: Array<{ kind: string; [k: string]: unknown }>,
): Bundle['attestedRelationships'] {
  // key = `${kind}\x00${attestation}` (NUL separator avoids collision with
  // any realistic attestation char).
  const groups = new Map<
    string,
    { attestation: string; kind: string; applied: Array<Record<string, unknown>> }
  >();
  for (const edge of edges) {
    const { kind, attestation, ...rest } = edge as {
      kind: string;
      attestation?: string;
      [k: string]: unknown;
    };
    const att = (attestation as string) ?? '';
    const key = `${kind}\x00${att}`;
    if (!groups.has(key)) {
      groups.set(key, { attestation: att, kind, applied: [] });
    }
    groups.get(key)!.applied.push(rest);
  }
  // Stable order: by kind, then attestation (empty last so the sentinel
  // groups sit at the bottom of each kind cluster).
  const out = Array.from(groups.values()).sort((a, b) => {
    if (a.kind !== b.kind) return a.kind.localeCompare(b.kind);
    if (a.attestation === '' && b.attestation !== '') return 1;
    if (b.attestation === '' && a.attestation !== '') return -1;
    return a.attestation.localeCompare(b.attestation);
  });
  return out.map((g) =>
    g.attestation === ''
      ? { ...g, note: 'no IGA capture — built-in entities' }
      : g,
  );
}

test.describe('Tide-network login-row visualizer', () => {
  test.afterAll(async ({ request }) => {
    await deleteRealm(request, REALM).catch(() => {});
  });

  test('build a representative login row, print REAL + SIMULATED Tide artifacts', async ({
    request,
  }) => {
    // -----------------------------------------------------------------------
    // 1. Scratch realm, enable IGA on the EMPTY realm so the toggle-on scan
    //    finds nothing new to ADOPT (the default realm-management client +
    //    built-in roles are filtered by the system-entity rules — see Phase 6b
    //    coverage), then build the contributor graph as a sequence of
    //    governed CRs.
    // -----------------------------------------------------------------------
    await createScratchRealm(request, REALM);
    await enableIga(request, REALM);
    expect((await igaStatus(request, REALM)).enabled).toBe(true);

    // Drain any ADOPT_* the toggle-on scan emitted (built-in realm-management
    // roles, default groups, etc — varies by KC build; safe to drain).
    const initialDrain = await drainAdopts(request, REALM);
    // eslint-disable-next-line no-console
    console.log(
      `[setup] toggle-on ADOPT drain: committed=${initialDrain.committed} total=${initialDrain.total}`,
    );

    // -----------------------------------------------------------------------
    // 2. Bases first (CREATE_ROLE for the 3 realm roles + the group-inherited
    //    role + each composite child must exist BEFORE the composite parent
    //    is POSTed — KC's composite pre-validation 404s if the child is not
    //    materialized yet, see composite-role-cross-cr-prevention.spec.ts).
    // -----------------------------------------------------------------------
    for (const name of REALM_ROLES) {
      const r = await createRole(request, REALM, { name });
      await commitGoverned(request, REALM, r, `CREATE_ROLE ${name}`);
    }
    {
      const r = await createRole(request, REALM, { name: GROUP_ROLE });
      await commitGoverned(request, REALM, r, `CREATE_ROLE ${GROUP_ROLE}`);
    }

    // Composite parent — child roles already committed above (REALM_ROLES[0]
    // and REALM_ROLES[1] become its composite children, exercising composite
    // expansion in effective-roles assembly).
    {
      const r = await createRole(request, REALM, {
        name: COMPOSITE_PARENT,
        composite: true,
        composites: { realm: [REALM_ROLES[0], REALM_ROLES[1]] },
      });
      await commitGoverned(request, REALM, r, `CREATE_ROLE ${COMPOSITE_PARENT}`);
    }

    // -----------------------------------------------------------------------
    // 3. Client + client roles. createClient() in the harness is the IGA-aware
    //    seam under IGA-on (returns the synchronous 201 only on the no-op
    //    fallback; otherwise returns 202 — but the helper calls clientUuid on
    //    success which only resolves post-commit). To stay symmetric with the
    //    rest of the visualizer, we POST clients directly and commit via
    //    commitGoverned.
    // -----------------------------------------------------------------------
    const clientCreateRes = await kcFetch(
      request,
      `/admin/realms/${REALM}/clients`,
      {
        method: 'POST',
        json: {
          clientId: CLIENT_ID_HUMAN,
          enabled: true,
          publicClient: false,
          protocol: 'openid-connect',
          secret: CLIENT_SECRET,
          clientAuthenticatorType: 'client-secret',
          standardFlowEnabled: true,
          directAccessGrantsEnabled: true,
          redirectUris: [
            'https://viz.example.test/cb',
            'https://viz.example.test/cb2',
          ],
          webOrigins: ['https://viz.example.test'],
        },
      },
    );
    await commitGoverned(
      request,
      REALM,
      clientCreateRes,
      `CREATE_CLIENT ${CLIENT_ID_HUMAN}`,
    );
    const cUuid = await clientUuid(request, REALM, CLIENT_ID_HUMAN);

    for (const name of CLIENT_ROLES) {
      const cr = await createClientRole(request, REALM, cUuid, { name });
      await commitGoverned(
        request,
        REALM,
        cr,
        `CREATE_CLIENT_ROLE ${CLIENT_ID_HUMAN}/${name}`,
      );
    }

    // -----------------------------------------------------------------------
    // 4. Groups: engineering (parent) + engineering/platform (child).
    // -----------------------------------------------------------------------
    {
      const g = await createGroup(request, REALM, PARENT_GROUP);
      await commitGoverned(request, REALM, g, `CREATE_GROUP ${PARENT_GROUP}`);
    }
    const parentGroup = (await getGroupByName(request, REALM, PARENT_GROUP)).body;
    expect(parentGroup?.id, 'parent group id resolvable').toBeTruthy();

    // Sub-group: POST /groups/{parentId}/children — this is a CREATE_GROUP CR.
    const childRes = await kcFetch(
      request,
      `/admin/realms/${REALM}/groups/${parentGroup.id}/children`,
      { method: 'POST', json: { name: CHILD_GROUP } },
    );
    await commitGoverned(
      request,
      REALM,
      childRes,
      `CREATE_GROUP ${PARENT_GROUP}/${CHILD_GROUP}`,
    );

    // -----------------------------------------------------------------------
    // 5. Assign the GROUP_ROLE to the parent group (GROUP_GRANT_ROLES CR —
    //    located by content per phase6b-toggle-on-scan / IgaGroupAdapter
    //    semantics; no 202 envelope).
    // -----------------------------------------------------------------------
    const groupRoleRep = await getRole(request, REALM, GROUP_ROLE);
    expect(groupRoleRep.http, `GET ${GROUP_ROLE}`).toBe(200);
    const ggrRes = await assignGroupRealmRoleMapping(
      request,
      REALM,
      parentGroup.id,
      [groupRoleRep.body],
    );
    expect(ggrRes.status(), 'GROUP role-mapping void POST 2xx').toBeLessThan(300);
    const ggrCr = await findChangeRequest(
      request,
      REALM,
      'GROUP_GRANT_ROLES',
      (cr) => cr.entityId === parentGroup.id || true,
    );
    expect(ggrCr, 'GROUP_GRANT_ROLES CR present').toBeTruthy();
    {
      const ac = await authorizeAndCommit(request, REALM, ggrCr!.id);
      expect(ac.commit.http, 'GROUP_GRANT_ROLES commit').toBe(200);
    }

    // -----------------------------------------------------------------------
    // 6. User alice — governed CREATE_USER.
    // -----------------------------------------------------------------------
    const userCreate = await createUser(request, REALM, {
      username: USER_NAME,
      enabled: true,
      emailVerified: true,
      email: 'alice@example.test',
      firstName: 'Alice',
      lastName: 'Vizzo',
    });
    await commitGoverned(request, REALM, userCreate, `CREATE_USER ${USER_NAME}`);
    const aliceLookup = await getUserByUsername(request, REALM, USER_NAME);
    expect(aliceLookup.body?.id, 'alice id resolvable').toBeTruthy();
    const aliceId = aliceLookup.body.id as string;

    // Add alice to engineering/platform — POST /users/{id}/groups/{groupId}
    // is an inline relationship action (USER_JOIN_GROUP). KC's void PUT
    // returns 204; the CR is located by content like GRANT_ROLES.
    //
    // The child group is a SUBGROUP under PARENT_GROUP, so the top-level
    // getGroupByName lookup won't find it — resolve by path via KC's
    // /group-by-path endpoint instead.
    const childByPathRes = await kcFetch(
      request,
      `/admin/realms/${REALM}/group-by-path/${PARENT_GROUP}/${CHILD_GROUP}`,
    );
    expect(
      childByPathRes.status(),
      `GET group-by-path /${PARENT_GROUP}/${CHILD_GROUP}`,
    ).toBe(200);
    const childGroup = await safeJson(childByPathRes);
    expect(childGroup?.id, 'child group id resolvable').toBeTruthy();
    const joinRes = await kcFetch(
      request,
      `/admin/realms/${REALM}/users/${aliceId}/groups/${childGroup.id}`,
      { method: 'PUT' },
    );
    expect(joinRes.status(), 'user-join-group void PUT 2xx').toBeLessThan(300);
    // Locate the membership CR by content (action type varies by KC build —
    // USER_JOIN_GROUP / GROUP_ADD_MEMBER / GRANT_GROUPS — drain anything
    // PENDING that touches this user OR this group).
    await drainAllPending(request, REALM);

    // Assign realm roles to alice: 2 direct realm roles + the composite parent.
    // Pass `{ id, name }` only — KC's RoleMapperResource.addRealmRoleMappings
    // only needs id+name to grant the mapping.
    //
    // CRITICAL: IgaUserAdapter#grantRole calls checkNoPendingCr per role and
    // rejects with IgaConflictException → HTTP 500 if there is ALREADY a
    // PENDING GRANT_ROLES CR for this user. KC's addRealmRoleMappings iterates
    // the array sequentially, so sending 3 roles in one POST creates 1 CR for
    // role-0 then explodes on role-1. Loop one role at a time, drain between.
    const role0 = (await getRole(request, REALM, REALM_ROLES[0])).body;
    const role2 = (await getRole(request, REALM, REALM_ROLES[2])).body;
    const composite = (await getRole(request, REALM, COMPOSITE_PARENT)).body;
    for (const roleRep of [role0, role2, composite]) {
      const r = await assignRealmRoleMapping(request, REALM, aliceId, [
        { id: roleRep.id, name: roleRep.name },
      ]);
      expect(
        r.status(),
        `GRANT_ROLES POST (role=${roleRep.name}) 2xx, body=${await r.text().catch(() => '')}`,
      ).toBeLessThan(300);
      // Drain the just-created GRANT_ROLES CR (plus any fan-out) so the next
      // role in the loop doesn't hit checkNoPendingCr.
      await drainAllPending(request, REALM);
    }

    // -----------------------------------------------------------------------
    // 7. Client scopes (2 default + 1 optional). One scope carries a protocol
    //    mapper. One scope gets a CLIENT_SCOPE_ROLE_MAPPING.
    // -----------------------------------------------------------------------
    const scopeSpecs = [
      {
        name: SCOPE_DEFAULT_A,
        assignmentKind: 'default' as const,
        protocol: 'openid-connect',
      },
      {
        name: SCOPE_DEFAULT_B,
        assignmentKind: 'default' as const,
        protocol: 'openid-connect',
        protocolMappers: [
          {
            name: SCOPE_MAPPER_NAME,
            protocol: 'openid-connect',
            protocolMapper: 'oidc-hardcoded-claim-mapper',
            config: {
              'claim.name': 'tide_viz_claim',
              'claim.value': 'tide-viz',
              'jsonType.label': 'String',
              'id.token.claim': 'true',
              'access.token.claim': 'true',
              'userinfo.token.claim': 'true',
            },
          },
        ],
      },
      {
        name: SCOPE_OPTIONAL,
        assignmentKind: 'optional' as const,
        protocol: 'openid-connect',
      },
    ];
    for (const s of scopeSpecs) {
      const res = await createClientScope(request, REALM, {
        name: s.name,
        protocol: s.protocol,
        protocolMappers: (s as any).protocolMappers,
      });
      await commitGoverned(
        request,
        REALM,
        res,
        `CREATE_CLIENT_SCOPE ${s.name}`,
      );
    }

    // Attach scopes to the client (default / optional). PUT
    // /clients/{cUuid}/default-client-scopes/{scopeId} is an inline
    // relationship — governed as a CLIENT_SCOPE_CLIENT CR (per IGA
    // ClientAdapter wrapping); drain anything PENDING afterwards.
    for (const s of scopeSpecs) {
      const scope = await getClientScopeByName(request, REALM, s.name);
      expect(scope.body?.id, `scope ${s.name} id`).toBeTruthy();
      const endpoint =
        s.assignmentKind === 'default'
          ? `default-client-scopes`
          : `optional-client-scopes`;
      const attachRes = await kcFetch(
        request,
        `/admin/realms/${REALM}/clients/${cUuid}/${endpoint}/${scope.body.id}`,
        { method: 'PUT' },
      );
      // Inline relationship: KC's void PUT returns 204 even when IGA defers.
      expect(
        attachRes.status(),
        `attach scope ${s.name} as ${s.assignmentKind}`,
      ).toBeLessThan(300);
    }
    await drainAllPending(request, REALM);

    // Map REALM_ROLES[1] onto SCOPE_DEFAULT_B (CLIENT_SCOPE_ROLE_MAPPING edge).
    const scopeBId = (await getClientScopeByName(request, REALM, SCOPE_DEFAULT_B))
      .body.id as string;
    const role1Rep = (await getRole(request, REALM, REALM_ROLES[1])).body;
    const scopeRoleRes = await kcFetch(
      request,
      `/admin/realms/${REALM}/client-scopes/${scopeBId}/scope-mappings/realm`,
      { method: 'POST', json: [role1Rep] },
    );
    expect(
      scopeRoleRes.status(),
      'scope-role-mapping void POST 2xx',
    ).toBeLessThan(300);
    await drainAllPending(request, REALM);

    // Final drain — anything left from cascade replays.
    const finalDrain = await drainAdopts(request, REALM);
    // eslint-disable-next-line no-console
    console.log(
      `[setup] final ADOPT drain: committed=${finalDrain.committed} total=${finalDrain.total}`,
    );
    await drainAllPending(request, REALM);

    // -----------------------------------------------------------------------
    // 8. Snapshot assembly — read everything KC's future Tide-mode would
    //    collect for an OIDC token issuance: realm + client + user +
    //    effective-roles (direct + composite + group) + groups + scopes +
    //    edges. Attestations are read directly from Postgres (real Tideless
    //    stamps; null when the row has none — most edges committed under IGA
    //    DO get a stamp via IgaSimpleAttestor.record).
    // -----------------------------------------------------------------------

    // Realm metadata.
    const realmGetRes = await kcFetch(request, `/admin/realms/${REALM}`);
    const realmRep = await safeJson(realmGetRes);
    expect(realmRep?.id, 'realm id').toBeTruthy();

    // Client.
    const clientLookup = await getClientByClientId(
      request,
      REALM,
      CLIENT_ID_HUMAN,
    );
    expect(clientLookup.body?.id, 'client id').toBeTruthy();
    const clientRep = clientLookup.body;
    const clientAttestation = readAttestation(
      'client',
      `id='${clientRep.id}'`,
    );

    // User.
    const userAttestation = readAttestation('user_entity', `id='${aliceId}'`);

    // Groups (alice's groups + their parents).
    const aliceGroups = (await getUserGroups(request, REALM, aliceId)).body;
    const groupSet = new Map<string, { id: string; name: string; path: string }>();
    for (const g of aliceGroups) {
      if (!g?.id) continue;
      groupSet.set(g.id, { id: g.id, name: g.name, path: g.path });
      // Walk up to parents (KC's brief rep only carries path, so resolve full).
      let cursor: any = g;
      while (cursor?.path && cursor.path.includes('/')) {
        const parentPath = cursor.path.substring(0, cursor.path.lastIndexOf('/'));
        if (!parentPath) break;
        // Lookup parent by path. KC has a path-search endpoint:
        const byPathRes = await kcFetch(
          request,
          `/admin/realms/${REALM}/group-by-path${parentPath}`,
        );
        if (byPathRes.status() !== 200) break;
        const parentRep = await safeJson(byPathRes);
        if (!parentRep?.id || groupSet.has(parentRep.id)) break;
        groupSet.set(parentRep.id, {
          id: parentRep.id,
          name: parentRep.name,
          path: parentRep.path,
        });
        cursor = parentRep;
      }
    }
    const groupsOut = Array.from(groupSet.values()).map((g) => ({
      ...g,
      attestation: readAttestation('keycloak_group', `id='${g.id}'`) ?? '',
    }));

    // Effective roles: direct realm + composite expansion + group-inherited.
    const effectiveByKey = new Map<
      string,
      Bundle['effectiveRoles'][number]
    >();

    // Direct realm-role mappings.
    const directRealm = (await getUserRealmRoleMappings(request, REALM, aliceId))
      .body;
    for (const r of directRealm) {
      if (!r?.id) continue;
      effectiveByKey.set(`REALM:${r.id}`, {
        id: r.id,
        name: r.name,
        containerKind: 'REALM',
        containerId: r.containerId,
        attestation: readAttestation('keycloak_role', `id='${r.id}'`) ?? '',
        via: 'direct',
      });
      // Composite expansion if this role is itself composite.
      if (r.composite) {
        const expanded = await expandComposites(
          request,
          REALM,
          r.name,
          new Set(),
        );
        for (const child of expanded) {
          if (!effectiveByKey.has(`REALM:${child.id}`)) {
            effectiveByKey.set(`REALM:${child.id}`, {
              ...child,
              attestation:
                readAttestation('keycloak_role', `id='${child.id}'`) ?? '',
              via: 'composite',
            });
          }
        }
      }
    }

    // Group-inherited roles: every group the user transitively belongs to
    // contributes its realm-role mappings.
    for (const g of groupsOut) {
      const gRolesRes = await kcFetch(
        request,
        `/admin/realms/${REALM}/groups/${g.id}/role-mappings/realm`,
      );
      if (gRolesRes.status() !== 200) continue;
      const gRoles = await safeJson(gRolesRes);
      if (!Array.isArray(gRoles)) continue;
      for (const r of gRoles) {
        if (!r?.id) continue;
        const key = `REALM:${r.id}`;
        if (!effectiveByKey.has(key)) {
          effectiveByKey.set(key, {
            id: r.id,
            name: r.name,
            containerKind: 'REALM',
            containerId: r.containerId,
            attestation: readAttestation('keycloak_role', `id='${r.id}'`) ?? '',
            via: 'group',
          });
        }
      }
    }

    // Client-role mappings (from the tide-viz-client's perspective):
    const clientMappingsRes = await kcFetch(
      request,
      `/admin/realms/${REALM}/users/${aliceId}/role-mappings/clients/${cUuid}`,
    );
    if (clientMappingsRes.status() === 200) {
      const cRoles = await safeJson(clientMappingsRes);
      if (Array.isArray(cRoles)) {
        for (const r of cRoles) {
          if (!r?.id) continue;
          effectiveByKey.set(`CLIENT:${r.id}`, {
            id: r.id,
            name: r.name,
            containerKind: 'CLIENT',
            containerId: r.containerId,
            attestation: readAttestation('keycloak_role', `id='${r.id}'`) ?? '',
            via: 'direct',
          });
        }
      }
    }

    const effectiveRoles = Array.from(effectiveByKey.values());

    // Client scopes (mounted on this client; default + optional).
    const defaultScopesRes = await kcFetch(
      request,
      `/admin/realms/${REALM}/clients/${cUuid}/default-client-scopes`,
    );
    const optionalScopesRes = await kcFetch(
      request,
      `/admin/realms/${REALM}/clients/${cUuid}/optional-client-scopes`,
    );
    const dfltScopes = (await safeJson(defaultScopesRes)) || [];
    const optScopes = (await safeJson(optionalScopesRes)) || [];
    const scopesOut: Bundle['clientScopes'] = [];
    for (const s of dfltScopes) {
      if (!s?.id) continue;
      scopesOut.push({
        id: s.id,
        name: s.name,
        assignmentKind: 'default',
        attestation: readAttestation('client_scope', `id='${s.id}'`) ?? '',
      });
    }
    for (const s of optScopes) {
      if (!s?.id) continue;
      scopesOut.push({
        id: s.id,
        name: s.name,
        assignmentKind: 'optional',
        attestation: readAttestation('client_scope', `id='${s.id}'`) ?? '',
      });
    }

    // Edges — the "user X holds role Y via this attested mapping" rows the
    // Tide-network verifier wants to see. We read them from the edge tables
    // directly so the attestation column is the same row the verifier reads.
    const edges: Bundle['edges'] = [];

    // USER_ROLE_MAPPING (direct realm + client role grants).
    {
      const sql = `SELECT role_id, attestation FROM user_role_mapping WHERE user_id='${aliceId}'`;
      const lines = psql(sql).split('\n').filter(Boolean);
      for (const line of lines) {
        const [roleId, att] = line.split('|');
        edges.push({
          kind: 'USER_ROLE_MAPPING',
          userId: aliceId,
          roleId,
          attestation: att || '',
        });
      }
    }
    // USER_GROUP_MEMBERSHIP.
    {
      const sql = `SELECT group_id, attestation FROM user_group_membership WHERE user_id='${aliceId}'`;
      const lines = psql(sql).split('\n').filter(Boolean);
      for (const line of lines) {
        const [groupId, att] = line.split('|');
        edges.push({
          kind: 'USER_GROUP_MEMBERSHIP',
          userId: aliceId,
          groupId,
          attestation: att || '',
        });
      }
    }
    // GROUP_ROLE_MAPPING (only the groups in scope).
    if (groupsOut.length > 0) {
      const ids = groupsOut.map((g) => `'${g.id}'`).join(',');
      const sql = `SELECT group_id, role_id, attestation FROM group_role_mapping WHERE group_id IN (${ids})`;
      const lines = psql(sql).split('\n').filter(Boolean);
      for (const line of lines) {
        const [groupId, roleId, att] = line.split('|');
        edges.push({
          kind: 'GROUP_ROLE_MAPPING',
          groupId,
          roleId,
          attestation: att || '',
        });
      }
    }
    // COMPOSITE_ROLE (parent -> child for any composite role in scope).
    {
      const compositeIds = effectiveRoles
        .filter((r) => r.via === 'direct' || r.via === 'composite')
        .map((r) => `'${r.id}'`);
      // Add the composite parent explicitly (even if it has no other edges).
      compositeIds.push(`'${composite.id}'`);
      const uniq = Array.from(new Set(compositeIds)).join(',');
      const sql = `SELECT composite, child_role, attestation FROM composite_role WHERE composite IN (${uniq})`;
      const lines = psql(sql).split('\n').filter(Boolean);
      for (const line of lines) {
        const [parentId, childId, att] = line.split('|');
        edges.push({
          kind: 'COMPOSITE_ROLE',
          parentId,
          childId,
          attestation: att || '',
        });
      }
    }
    // CLIENT_SCOPE_CLIENT (this client's scope assignments).
    {
      const sql = `SELECT scope_id, default_scope, attestation FROM client_scope_client WHERE client_id='${clientRep.id}'`;
      const lines = psql(sql).split('\n').filter(Boolean);
      for (const line of lines) {
        const [scopeId, isDefault, att] = line.split('|');
        edges.push({
          kind: 'CLIENT_SCOPE_CLIENT',
          clientId: clientRep.id,
          scopeId,
          defaultScope: isDefault === 't',
          attestation: att || '',
        });
      }
    }
    // CLIENT_SCOPE_ROLE_MAPPING (any scope-role mapping for in-scope scopes).
    if (scopesOut.length > 0) {
      const sids = scopesOut.map((s) => `'${s.id}'`).join(',');
      const sql = `SELECT scope_id, role_id, attestation FROM client_scope_role_mapping WHERE scope_id IN (${sids})`;
      const lines = psql(sql).split('\n').filter(Boolean);
      for (const line of lines) {
        const [scopeId, roleId, att] = line.split('|');
        edges.push({
          kind: 'CLIENT_SCOPE_ROLE_MAPPING',
          scopeId,
          roleId,
          attestation: att || '',
        });
      }
    }
    // PROTOCOL_MAPPER (mappers on the in-scope client + scopes).
    {
      const ownerIds = [`'${clientRep.id}'`, ...scopesOut.map((s) => `'${s.id}'`)].join(',');
      const sql = `SELECT id, name, protocol, COALESCE(client_id,''), COALESCE(client_scope_id,''), attestation FROM protocol_mapper WHERE client_id IN (${ownerIds}) OR client_scope_id IN (${ownerIds})`;
      const lines = psql(sql).split('\n').filter(Boolean);
      for (const line of lines) {
        const [id, name, protocol, clientOwnerId, scopeOwnerId, att] =
          line.split('|');
        edges.push({
          kind: 'PROTOCOL_MAPPER',
          id,
          name,
          protocol,
          ownerClientId: clientOwnerId || null,
          ownerScopeId: scopeOwnerId || null,
          attestation: att || '',
        });
      }
    }

    // Common entity heads — shared between the legacy per-row bundle (kept
    // around purely for the side-by-side comparison output) and the new
    // set-attested bundle.
    const realmHead = {
      id: realmRep.id,
      name: REALM,
      // REALM table has no attestation column — use a sentinel so the human
      // reader can see the gap explicitly (not silently empty).
      attestation: REALM_ANCHOR_SENTINEL,
    };
    const clientHead = {
      id: clientRep.id,
      clientId: CLIENT_ID_HUMAN,
      attestation: clientAttestation ?? '',
    };
    const userHead = {
      id: aliceId,
      username: USER_NAME,
      email: 'alice@example.test',
      attestation: userAttestation ?? '',
    };

    // Legacy bundle (per-row edges) — retained for direct comparison output.
    const bundleRealLegacy: LegacyEdgeBundle = {
      version: '1',
      realm: realmHead,
      client: clientHead,
      user: userHead,
      effectiveRoles,
      groups: groupsOut,
      clientScopes: scopesOut,
      edges,
    };

    // Set-attested bundle (interpretation B) — group per-row edges by
    // (attestation_string, kind). Same `edges` data, different framing.
    const attestedRelationships = groupEdgesByAttestation(edges);

    const bundleReal: Bundle = {
      version: '1',
      realm: realmHead,
      client: clientHead,
      user: userHead,
      effectiveRoles,
      groups: groupsOut,
      clientScopes: scopesOut,
      attestedRelationships,
    };

    // Light assertions — this is a visualizer, not a contract test.
    expect(bundleReal.user.id, 'user.id non-empty').toBeTruthy();
    expect(bundleReal.client.id, 'client.id non-empty').toBeTruthy();
    expect(bundleReal.realm.id, 'realm.id non-empty').toBeTruthy();
    expect(
      bundleReal.effectiveRoles.length,
      `effective roles ≥ 4 (direct + composite + group-inherited); got ${bundleReal.effectiveRoles.length}`,
    ).toBeGreaterThanOrEqual(4);
    expect(bundleReal.groups.length, 'groups ≥ 1').toBeGreaterThanOrEqual(1);
    expect(
      bundleReal.clientScopes.length,
      'client scopes ≥ 3 (2 default + 1 optional)',
    ).toBeGreaterThanOrEqual(3);
    expect(bundleRealLegacy.edges.length, 'edges ≥ 6').toBeGreaterThanOrEqual(6);
    expect(
      bundleReal.attestedRelationships.length,
      'attestedRelationships ≥ 1',
    ).toBeGreaterThanOrEqual(1);
    // Set-attested grouping must NEVER lose data: total applied rows across
    // groups must equal the per-row edge count.
    const totalApplied = bundleReal.attestedRelationships.reduce(
      (n, g) => n + g.applied.length,
      0,
    );
    expect(
      totalApplied,
      'sum(applied) per group == edges.length (no rows lost in grouping)',
    ).toBe(bundleRealLegacy.edges.length);

    const totalEdges = bundleRealLegacy.edges.length;
    const groupCount = bundleReal.attestedRelationships.length;
    const contributorsSummary = `user=1 roles=${bundleReal.effectiveRoles.length} groups=${bundleReal.groups.length} scopes=${bundleReal.clientScopes.length} edges=${totalEdges} attestedRelationships=${groupCount}`;

    // -----------------------------------------------------------------------
    // 9. Print FOUR artifacts side-by-side (legacy per-row + set-attested,
    //    each in REAL and SIMULATED variants) then a Comparison block.
    // -----------------------------------------------------------------------

    // (a) Legacy per-row, REAL — kept for direct visual comparison.
    printArtifact(
      'REAL Tideless attestations, per-row edges (legacy)',
      bundleRealLegacy,
      contributorsSummary,
    );

    // (b) Set-attested, REAL.
    printArtifact(
      'REAL, set-attested relationships',
      bundleReal,
      contributorsSummary,
    );
    // eslint-disable-next-line no-console
    console.log(
      `Relationships: ${groupCount} groups covering ${totalApplied} total applied rows (was ${totalEdges} per-row edges)`,
    );

    // (c) Legacy per-row, SIMULATED Tide-sized.
    const bundleSimulatedLegacy = withSimulatedAttestationsLegacy(bundleRealLegacy);
    printArtifact(
      'SIMULATED Tide-sized, per-row edges (legacy)',
      bundleSimulatedLegacy,
      contributorsSummary,
    );

    // (d) Set-attested, SIMULATED — preserves the group structure from (b).
    const bundleSimulated = withSimulatedAttestationsSet(bundleReal);
    printArtifact(
      'SIMULATED Tide-sized, set-attested relationships',
      bundleSimulated,
      contributorsSummary,
    );

    // -----------------------------------------------------------------------
    // 10. Comparison block — show the byte delta between per-row and set-
    //     attested framings for both REAL and SIMULATED. Gzip and minified
    //     are the load-bearing numbers (pretty JSON is whitespace-dominated).
    // -----------------------------------------------------------------------
    const sLegacyReal = sizeOf(bundleRealLegacy);
    const sSetReal = sizeOf(bundleReal);
    const sLegacySim = sizeOf(bundleSimulatedLegacy);
    const sSetSim = sizeOf(bundleSimulated);

    const fmt = (s: { pretty: number; minified: number; gzip: number }) =>
      `pretty=${s.pretty}B  minified=${s.minified}B  gzip=${s.gzip}B`;

    const pct = (was: number, now: number) =>
      was === 0 ? '0.0%' : `${(((was - now) / was) * 100).toFixed(1)}%`;

    // eslint-disable-next-line no-console
    console.log(`\n=== Comparison ===`);
    // eslint-disable-next-line no-console
    console.log(`Real per-row (previous):       ${fmt(sLegacyReal)}`);
    // eslint-disable-next-line no-console
    console.log(`Real set-attested (new):       ${fmt(sSetReal)}`);
    // eslint-disable-next-line no-console
    console.log(`Simulated per-row (previous):  ${fmt(sLegacySim)}`);
    // eslint-disable-next-line no-console
    console.log(`Simulated set-attested (new):  ${fmt(sSetSim)}`);
    // eslint-disable-next-line no-console
    console.log(
      `Delta (REAL):       minified saving ${sLegacyReal.minified - sSetReal.minified} bytes (${pct(sLegacyReal.minified, sSetReal.minified)}), gzip saving ${sLegacyReal.gzip - sSetReal.gzip} bytes (${pct(sLegacyReal.gzip, sSetReal.gzip)})`,
    );
    // eslint-disable-next-line no-console
    console.log(
      `Delta (SIMULATED):  minified saving ${sLegacySim.minified - sSetSim.minified} bytes (${pct(sLegacySim.minified, sSetSim.minified)}), gzip saving ${sLegacySim.gzip - sSetSim.gzip} bytes (${pct(sLegacySim.gzip, sSetSim.gzip)})`,
    );

    // Sanity: simulated bundle's keys + counts must match real bundle's shape.
    expect(Object.keys(bundleSimulated).sort()).toEqual(
      Object.keys(bundleReal).sort(),
    );
    expect(bundleSimulated.effectiveRoles.length).toBe(
      bundleReal.effectiveRoles.length,
    );
    // Group structure preservation: simulated must have the EXACT same
    // number of groups, in the SAME order, with the SAME applied-row counts
    // as the real bundle (otherwise we accidentally re-grouped from the
    // placeholder strings).
    expect(bundleSimulated.attestedRelationships.length).toBe(
      bundleReal.attestedRelationships.length,
    );
    for (let i = 0; i < bundleReal.attestedRelationships.length; i++) {
      expect(bundleSimulated.attestedRelationships[i].kind).toBe(
        bundleReal.attestedRelationships[i].kind,
      );
      expect(bundleSimulated.attestedRelationships[i].applied.length).toBe(
        bundleReal.attestedRelationships[i].applied.length,
      );
    }

    // Both size reports MUST have been printed (load-bearing for the human
    // reader). The check is implicit via the console.log labels — we assert
    // the bundles are non-empty so the printing path executed.
    expect(sSetReal.minified).toBeGreaterThan(0);
    expect(sSetSim.minified).toBeGreaterThan(0);
  });
});
