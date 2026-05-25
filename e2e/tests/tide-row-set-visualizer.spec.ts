import { test, expect, APIRequestContext } from '@playwright/test';
import { execSync } from 'child_process';
import { gzipSync } from 'zlib';
import { createHash } from 'crypto';
import {
  createScratchRealm,
  deleteRealm,
  enableIga,
  igaStatus,
  setRealmIgaAttr,
  createRole,
  createClientRole,
  createClientScope,
  createGroup,
  createUser,
  getRole,
  getGroupByName,
  getUserByUsername,
  getClientByClientId,
  getClientScopeByName,
  clientUuid,
  assignRealmRoleMapping,
  assignGroupRealmRoleMapping,
  listChangeRequests,
  findChangeRequest,
  authorizeAndCommit,
  locationHeader,
  safeJson,
  kcFetch,
} from '../lib/kc';

/**
 * Tide SET-SIGNED wire-bundle visualizer (DUMMY TideAttestor, id `tide`).
 *
 * This is the SET-SIGNING counterpart to tide-row-visualizer.spec.ts (v4). Where
 * v4 enumerates the current attested PER-ROW state under the Tideless `simple`
 * attestor, THIS spec builds a realm on the `tide` attestor — which signs per-
 * (table, owner) SETS — and reshapes the result into the bundle that goes to the
 * ORKs:
 *
 *   {
 *     context: { realm_id, client_id, user_id },
 *     node_attestations: [ { entity_type, entity_id, signature }, ... ],
 *     set_attestations:  [ { table, owner_key, owner_id, members[], canonical,
 *                            signature }, ... ]
 *   }
 *
 * The DEFINING property of set-signing: every linkage row sharing a (table,
 * owner) carries ONE identical aggregate signature. So a graph that has N
 * contributing linkage rows across an owner collapses to ONE set entry. The
 * `signature` of a linkage SET is `TIDE-DUMMY-v1:base64(sha256(canonical))`,
 * where for a single-owner set the canonical is EXACTLY:
 *
 *     table=<t>\nowner=<o>\nmembers=<sorted,comma-joined member ids>\n
 *
 * (see iga-core TideAttestor.java#canonicalizeLinkageSet + TideSetResolver.java).
 * NODE entities (user_entity, keycloak_role, client, client_scope,
 * keycloak_group) stay PER-ENTITY: their signature is over their own state, read
 * straight off the row.
 *
 * We REBUILD the linkage canonical string in-test from the post-change member
 * set and assert that sha256→base64 of it equals the stored signature's payload
 * — i.e. the dummy sig is re-derivable from what we send. We also assert the
 * core set-sharing property (all members of a set carry one identical sig) and
 * that distinct-sig count < contributing-row count (the collapse).
 */

const REALM = 'iga-tide-set-viz';
const CLIENT_ID_HUMAN = 'tide-set-client';
const CLIENT_SECRET = 'tide-set-secret';
const USER_NAME = 'alice';

// Roles
const REALM_ROLES = ['vset-realm-admin', 'vset-realm-editor', 'vset-realm-viewer'];
const COMPOSITE_PARENT = 'vset-composite-parent';
const CLIENT_ROLES = ['vset-client-write', 'vset-client-read'];
const GROUP_ROLE = 'vset-group-role';

// Groups
const PARENT_GROUP = 'engineering';
const CHILD_GROUP = 'platform';

// Client scopes
const SCOPE_DEFAULT_A = 'vset-scope-default-a';
const SCOPE_DEFAULT_B = 'vset-scope-default-b';
const SCOPE_OPTIONAL = 'vset-scope-optional';
const SCOPE_MAPPER_NAME = 'vset-scope-mapper';

const PG_CONTAINER = 'postgresP';
const PG_USER = 'tideadmin';
const PG_DB = 'dauthme';

const DUMMY_PREFIX = 'TIDE-DUMMY-v1:';

// ---------------------------------------------------------------------------
// Inline helpers (do not add to e2e/tests/helpers/, per task constraints).
// ---------------------------------------------------------------------------

/** Run `docker exec postgresP psql -tAc "<sql>"` and return trimmed stdout. */
function psql(sql: string): string {
  const oneLine = sql.replace(/\s+/g, ' ').trim();
  const out = execSync(
    `docker exec ${PG_CONTAINER} psql -U ${PG_USER} -d ${PG_DB} -tAc ${JSON.stringify(oneLine)}`,
    { encoding: 'utf8' },
  );
  return out.trim();
}

/** SQL-escape a value for embedding in a single-quoted literal. */
function sql(v: string): string {
  return v.replace(/'/g, "''");
}

/**
 * Read a single ATTESTATION cell from a table keyed by `where`. Returns "" when
 * the row is missing OR its attestation is null.
 */
function readAttestation(table: string, where: string): string {
  return psql(`SELECT COALESCE(attestation, '') FROM ${table} WHERE ${where} LIMIT 1`);
}

/**
 * Recompute the DUMMY sig the way TideAttestor.sign() does:
 *   "TIDE-DUMMY-v1:" + base64(sha256(canonicalBytes))
 * This is the single crypto swap-point; reproducing it here lets us assert the
 * stored sig is re-derivable from the canonical string we reconstruct.
 */
function dummySign(canonical: string): string {
  const digest = createHash('sha256').update(Buffer.from(canonical, 'utf8')).digest('base64');
  return DUMMY_PREFIX + digest;
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
  const crId = (body && body.changeRequestId) || (loc ? loc.split('/').pop() : '');
  expect(crId, `${label} CR id resolvable`).toBeTruthy();
  const ac = await authorizeAndCommit(request, realm, crId as string);
  expect(ac.authorize.http, `${label} authorize`).toBe(200);
  expect(
    ac.commit.http,
    `${label} commit expected 200, got ${ac.commit.http} ${JSON.stringify(ac.commit.body)}`,
  ).toBe(200);
  return crId as string;
}

/** Drain every PENDING ADOPT_* CR via bulk-authorize. */
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
  for (let i = 0; i < 25; i++) {
    const list = await listChangeRequests(request, realm, 'PENDING');
    if (list.length === 0) break;
    let progress = 0;
    for (const cr of list) {
      const ac = await authorizeAndCommit(request, realm, cr.id);
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
      // eslint-disable-next-line no-console
      console.log(`[drain] stuck after ${i} rounds with ${list.length} PENDING CRs; breaking`);
      break;
    }
  }
  return drained;
}

// ---------------------------------------------------------------------------
// Set-signed wire-bundle model
// ---------------------------------------------------------------------------

interface NodeAttestation {
  entity_type: string; // user_entity | keycloak_role | client | client_scope | keycloak_group
  entity_id: string;
  signature: string;
}

interface SetAttestation {
  table: string; // physical linkage table (matches TideSetResolver.Linkage.table())
  owner_key: string; // the group-by concept (user/group/parent/client/scope/realm)
  owner_id: string; // the owner value
  members: string[]; // sorted member ids — the set the sig commits to
  canonical: string; // the EXACT string TideAttestor signs: table=…\nowner=…\nmembers=…\n
  signature: string; // shared set sig read from every member row (asserted identical)
}

interface WireBundle {
  context: { realm_id: string; client_id: string; user_id: string };
  node_attestations: NodeAttestation[];
  set_attestations: SetAttestation[];
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

/**
 * Linkage descriptor mirror of TideSetResolver, expressed in PHYSICAL table /
 * column terms (what we read from Postgres). `owner_key` is the human concept
 * used in the bundle; `ownerCol`/`memberCol` are the physical columns we group
 * by and list. We reconstruct the canonical from the post-change member set
 * exactly as TideAttestor.canonicalizeLinkageSet does for a single owner.
 */
interface LinkageDesc {
  table: string;
  ownerCol: string;
  memberCol: string;
  ownerKey: string;
}

test.describe('Tide set-signed wire-bundle visualizer', () => {
  test.afterAll(async ({ request }) => {
    await deleteRealm(request, REALM).catch(() => {});
  });

  test('build a graph on the tide attestor, print the set-signed wire bundle (REAL dummy sigs)', async ({
    request,
  }) => {
    // -----------------------------------------------------------------------
    // 1. Scratch realm, set iga.attestor=tide BEFORE enableIga (so the attestor
    //    choice is not itself governed), then enable IGA on the empty realm.
    // -----------------------------------------------------------------------
    await createScratchRealm(request, REALM);
    await setRealmIgaAttr(request, REALM, 'iga.attestor', 'tide');
    await enableIga(request, REALM);
    expect((await igaStatus(request, REALM)).enabled).toBe(true);

    const initialDrain = await drainAdopts(request, REALM);
    // eslint-disable-next-line no-console
    console.log(
      `[setup] toggle-on ADOPT drain: committed=${initialDrain.committed} total=${initialDrain.total}`,
    );

    // -----------------------------------------------------------------------
    // 2. Roles: 3 realm roles + group-inherited role + composite parent (2
    //    children). Children must exist before the composite parent is POSTed.
    // -----------------------------------------------------------------------
    for (const name of REALM_ROLES) {
      const r = await createRole(request, REALM, { name });
      await commitGoverned(request, REALM, r, `CREATE_ROLE ${name}`);
    }
    {
      const r = await createRole(request, REALM, { name: GROUP_ROLE });
      await commitGoverned(request, REALM, r, `CREATE_ROLE ${GROUP_ROLE}`);
    }
    {
      // Create the parent as a PLAIN role first; add its children as a separate
      // governed ADD_COMPOSITE CR below (so the composite_role rows get the
      // per-(table,owner) SET sig, not the node CREATE_ROLE stamp).
      const r = await createRole(request, REALM, { name: COMPOSITE_PARENT });
      await commitGoverned(request, REALM, r, `CREATE_ROLE ${COMPOSITE_PARENT}`);
    }
    // ADD_COMPOSITE: attach two realm-role children to the composite parent.
    {
      const child0 = (await getRole(request, REALM, REALM_ROLES[0])).body;
      const child1 = (await getRole(request, REALM, REALM_ROLES[1])).body;
      const addCompRes = await kcFetch(
        request,
        `/admin/realms/${REALM}/roles/${encodeURIComponent(COMPOSITE_PARENT)}/composites`,
        { method: 'POST', json: [child0, child1] },
      );
      expect(addCompRes.status(), 'ADD_COMPOSITE deferred 2xx').toBeLessThan(300);
      await drainAllPending(request, REALM);
    }

    // -----------------------------------------------------------------------
    // 3. Confidential client + client roles.
    // -----------------------------------------------------------------------
    const clientCreateRes = await kcFetch(request, `/admin/realms/${REALM}/clients`, {
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
        redirectUris: ['https://vset.example.test/cb'],
        webOrigins: ['https://vset.example.test'],
      },
    });
    await commitGoverned(request, REALM, clientCreateRes, `CREATE_CLIENT ${CLIENT_ID_HUMAN}`);
    const cUuid = await clientUuid(request, REALM, CLIENT_ID_HUMAN);

    for (const name of CLIENT_ROLES) {
      const cr = await createClientRole(request, REALM, cUuid, { name });
      await commitGoverned(request, REALM, cr, `CREATE_CLIENT_ROLE ${CLIENT_ID_HUMAN}/${name}`);
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

    const childRes = await kcFetch(
      request,
      `/admin/realms/${REALM}/groups/${parentGroup.id}/children`,
      { method: 'POST', json: { name: CHILD_GROUP } },
    );
    await commitGoverned(request, REALM, childRes, `CREATE_GROUP ${PARENT_GROUP}/${CHILD_GROUP}`);

    // -----------------------------------------------------------------------
    // 5. GROUP_GRANT_ROLES — assign GROUP_ROLE to the parent group.
    // -----------------------------------------------------------------------
    const groupRoleRep = await getRole(request, REALM, GROUP_ROLE);
    expect(groupRoleRep.http, `GET ${GROUP_ROLE}`).toBe(200);
    const ggrRes = await assignGroupRealmRoleMapping(request, REALM, parentGroup.id, [
      groupRoleRep.body,
    ]);
    expect(ggrRes.status(), 'GROUP role-mapping void POST 2xx').toBeLessThan(300);
    const ggrCr = await findChangeRequest(request, REALM, 'GROUP_GRANT_ROLES', () => true);
    expect(ggrCr, 'GROUP_GRANT_ROLES CR present').toBeTruthy();
    {
      const ac = await authorizeAndCommit(request, REALM, ggrCr!.id);
      expect(ac.commit.http, 'GROUP_GRANT_ROLES commit').toBe(200);
    }

    // -----------------------------------------------------------------------
    // 6. User alice — governed CREATE_USER → user_entity NODE sig.
    // -----------------------------------------------------------------------
    const userCreate = await createUser(request, REALM, {
      username: USER_NAME,
      enabled: true,
      emailVerified: true,
      email: 'alice@example.test',
      firstName: 'Alice',
      lastName: 'Setto',
    });
    await commitGoverned(request, REALM, userCreate, `CREATE_USER ${USER_NAME}`);
    const aliceLookup = await getUserByUsername(request, REALM, USER_NAME);
    expect(aliceLookup.body?.id, 'alice id resolvable').toBeTruthy();
    const aliceId = aliceLookup.body.id as string;

    // alice → engineering/platform — JOIN_GROUPS.
    const childByPathRes = await kcFetch(
      request,
      `/admin/realms/${REALM}/group-by-path/${PARENT_GROUP}/${CHILD_GROUP}`,
    );
    expect(childByPathRes.status(), `GET group-by-path`).toBe(200);
    const childGroup = await safeJson(childByPathRes);
    expect(childGroup?.id, 'child group id resolvable').toBeTruthy();
    const joinRes = await kcFetch(
      request,
      `/admin/realms/${REALM}/users/${aliceId}/groups/${childGroup.id}`,
      { method: 'PUT' },
    );
    expect(joinRes.status(), 'user-join-group void PUT 2xx').toBeLessThan(300);
    await drainAllPending(request, REALM);

    // Direct role grants: realm roles[0], roles[2] + composite parent.
    const role0 = (await getRole(request, REALM, REALM_ROLES[0])).body;
    const role2 = (await getRole(request, REALM, REALM_ROLES[2])).body;
    const composite = (await getRole(request, REALM, COMPOSITE_PARENT)).body;
    for (const roleRep of [role0, role2, composite]) {
      const r = await assignRealmRoleMapping(request, REALM, aliceId, [
        { id: roleRep.id, name: roleRep.name },
      ]);
      expect(r.status(), `GRANT_ROLES POST (role=${roleRep.name}) 2xx`).toBeLessThan(300);
      await drainAllPending(request, REALM);
    }

    // -----------------------------------------------------------------------
    // 7. Client scopes (2 default + 1 optional). One scope carries a protocol
    //    mapper. One scope gets a SCOPE_ADD_ROLE.
    // -----------------------------------------------------------------------
    const scopeSpecs = [
      { name: SCOPE_DEFAULT_A, assignmentKind: 'default' as const, protocol: 'openid-connect' },
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
              'claim.name': 'tide_set_claim',
              'claim.value': 'tide-set',
              'jsonType.label': 'String',
              'id.token.claim': 'true',
              'access.token.claim': 'true',
              'userinfo.token.claim': 'true',
            },
          },
        ],
      },
      { name: SCOPE_OPTIONAL, assignmentKind: 'optional' as const, protocol: 'openid-connect' },
    ];
    for (const s of scopeSpecs) {
      const res = await createClientScope(request, REALM, {
        name: s.name,
        protocol: s.protocol,
        protocolMappers: (s as any).protocolMappers,
      });
      await commitGoverned(request, REALM, res, `CREATE_CLIENT_SCOPE ${s.name}`);
    }

    // Attach scopes to the client (default/optional). The attach PUT itself is
    // not IGA-captured, but it builds the client_scope_client rows we group.
    for (const s of scopeSpecs) {
      const scope = await getClientScopeByName(request, REALM, s.name);
      expect(scope.body?.id, `scope ${s.name} id`).toBeTruthy();
      const endpoint =
        s.assignmentKind === 'default' ? `default-client-scopes` : `optional-client-scopes`;
      const attachRes = await kcFetch(
        request,
        `/admin/realms/${REALM}/clients/${cUuid}/${endpoint}/${scope.body.id}`,
        { method: 'PUT' },
      );
      expect(attachRes.status(), `attach scope ${s.name}`).toBeLessThan(300);
    }
    await drainAllPending(request, REALM);

    // Map two realm roles onto SCOPE_DEFAULT_B (two SCOPE_ADD_ROLE CRs → ONE set
    // sig over the scope's two members).
    const scopeBId = (await getClientScopeByName(request, REALM, SCOPE_DEFAULT_B)).body.id as string;
    for (const rn of [REALM_ROLES[1], REALM_ROLES[2]]) {
      const roleRep = (await getRole(request, REALM, rn)).body;
      const scopeRoleRes = await kcFetch(
        request,
        `/admin/realms/${REALM}/client-scopes/${scopeBId}/scope-mappings/realm`,
        { method: 'POST', json: [roleRep] },
      );
      expect(scopeRoleRes.status(), `scope-role-mapping (${rn}) 2xx`).toBeLessThan(300);
      await drainAllPending(request, REALM);
    }

    // Client scope-mapping (scope_mapping): allowlist two realm roles on the
    // client → ONE set sig over the client's two members.
    for (const rn of [REALM_ROLES[0], REALM_ROLES[1]]) {
      const roleRep = (await getRole(request, REALM, rn)).body;
      const smRes = await kcFetch(
        request,
        `/admin/realms/${REALM}/clients/${cUuid}/scope-mappings/realm`,
        { method: 'POST', json: [roleRep] },
      );
      expect(smRes.status(), `scope_mapping (${rn}) 2xx`).toBeLessThan(300);
      await drainAllPending(request, REALM);
    }

    const finalDrain = await drainAdopts(request, REALM);
    // eslint-disable-next-line no-console
    console.log(
      `[setup] final ADOPT drain: committed=${finalDrain.committed} total=${finalDrain.total}`,
    );
    await drainAllPending(request, REALM);

    // -----------------------------------------------------------------------
    // 8. Realm + client UUIDs for context.
    // -----------------------------------------------------------------------
    const realmGetRes = await kcFetch(request, `/admin/realms/${REALM}`);
    const realmRep = await safeJson(realmGetRes);
    expect(realmRep?.id, 'realm id').toBeTruthy();
    const realmUuid = realmRep.id as string;
    const clientLookup = await getClientByClientId(request, REALM, CLIENT_ID_HUMAN);
    const clientUuidVal = clientLookup.body.id as string;

    // =======================================================================
    // 9. Build the NODE attestations — per-entity sigs read off each row.
    // =======================================================================
    const node_attestations: NodeAttestation[] = [];
    const seenNode = new Set<string>(); // `${type}:${id}`

    function pushNode(entityType: string, table: string, id: string) {
      const k = `${entityType}:${id}`;
      if (seenNode.has(k)) return;
      seenNode.add(k);
      const sig = readAttestation(table, `id='${sql(id)}'`);
      node_attestations.push({ entity_type: entityType, entity_id: id, signature: sig });
    }

    // alice (user_entity) — the canonical NODE row.
    pushNode('user_entity', 'user_entity', aliceId);
    // client + client scopes + groups on the path are NODE entities too.
    pushNode('client', 'client', clientUuidVal);
    for (const sName of [SCOPE_DEFAULT_A, SCOPE_DEFAULT_B, SCOPE_OPTIONAL]) {
      const sid = (await getClientScopeByName(request, REALM, sName)).body.id as string;
      pushNode('client_scope', 'client_scope', sid);
    }
    // Group path: platform + ancestor engineering.
    const groupPathIds: string[] = [];
    {
      let gid: string | null = childGroup.id as string;
      const guard = new Set<string>();
      while (gid && !guard.has(gid)) {
        guard.add(gid);
        groupPathIds.push(gid);
        const parent = psql(
          `SELECT COALESCE(parent_group, '') FROM keycloak_group WHERE id='${sql(gid)}' LIMIT 1`,
        );
        gid = parent ? parent : null;
      }
    }
    for (const gid of groupPathIds) pushNode('keycloak_group', 'keycloak_group', gid);

    // Every contributing role becomes a NODE entity. Gather the effective role
    // id set: alice's direct grants + composite children + group-inherited.
    const effectiveRoleIds = new Set<string>();
    const directRoleIds = psql(
      `SELECT role_id FROM user_role_mapping WHERE user_id='${sql(aliceId)}' ORDER BY role_id ASC`,
    )
      .split('\n')
      .filter(Boolean);
    for (const rid of directRoleIds) effectiveRoleIds.add(rid);
    for (const rid of [...directRoleIds]) {
      const children = psql(
        `SELECT child_role FROM composite_role WHERE composite='${sql(rid)}' ORDER BY child_role ASC`,
      )
        .split('\n')
        .filter(Boolean);
      for (const c of children) effectiveRoleIds.add(c);
    }
    for (const gid of groupPathIds) {
      const grm = psql(
        `SELECT role_id FROM group_role_mapping WHERE group_id='${sql(gid)}' ORDER BY role_id ASC`,
      )
        .split('\n')
        .filter(Boolean);
      for (const rid of grm) effectiveRoleIds.add(rid);
    }
    for (const rid of effectiveRoleIds) pushNode('keycloak_role', 'keycloak_role', rid);

    // =======================================================================
    // 10. Build the SET attestations — group linkage rows by (table, owner)
    //     using the SAME owner mapping as TideSetResolver, read the shared sig
    //     off every member row (assert identical), and reconstruct the canonical
    //     string TideAttestor signs.
    // =======================================================================
    const set_attestations: SetAttestation[] = [];
    let totalContributingRows = 0; // every linkage row that contributes a sig

    /**
     * Read all (owner_id, member_id, attestation) rows for a linkage table for a
     * given set of owners, group by owner, assert one shared sig per owner, and
     * emit a set entry per owner with the reconstructed canonical.
     *
     * `tableCanon` is the physical table name TideAttestor writes into the
     * canonical (`table=<tableCanon>`).
     */
    function emitSets(desc: LinkageDesc, ownerIds: string[]) {
      const uniqueOwners = [...new Set(ownerIds)].filter(Boolean);
      for (const ownerId of uniqueOwners) {
        const rows = psql(
          `SELECT ${desc.memberCol} || E'\\x1F' || COALESCE(attestation,'')
             FROM ${desc.table}
            WHERE ${desc.ownerCol}='${sql(ownerId)}'
            ORDER BY ${desc.memberCol} ASC`,
        )
          .split('\n')
          .filter(Boolean)
          .map((l) => {
            const [member, att] = l.split('\x1F');
            return { member, att: att ?? '' };
          });
        if (rows.length === 0) continue;
        totalContributingRows += rows.length;

        // Core set-signing property: every member row carries ONE identical sig.
        const sigs = new Set(rows.map((r) => r.att));
        expect(
          sigs.size,
          `set-sharing: ${desc.table} owner=${ownerId} members must share ONE sig, saw ${[...sigs].join(' | ')}`,
        ).toBe(1);
        const signature = rows[0].att;
        expect(
          signature.startsWith(DUMMY_PREFIX),
          `${desc.table} owner=${ownerId} sig has dummy prefix, got '${signature}'`,
        ).toBeTruthy();

        // Members sorted = the TreeSet order TideAttestor canonicalizes with.
        const members = rows.map((r) => r.member).sort();
        // Reconstruct the EXACT canonical for a single-owner set:
        //   table=<t>\nowner=<o>\nmembers=<m1,m2,...>\n
        const canonical = `table=${desc.table}\nowner=${ownerId}\nmembers=${members.join(',')}\n`;

        set_attestations.push({
          table: desc.table,
          owner_key: desc.ownerKey,
          owner_id: ownerId,
          members,
          canonical,
          signature,
        });
      }
    }

    // user_role_mapping — owner = user (alice).
    emitSets(
      { table: 'user_role_mapping', ownerCol: 'user_id', memberCol: 'role_id', ownerKey: 'user' },
      [aliceId],
    );
    // user_group_membership — owner = user (alice).
    emitSets(
      {
        table: 'user_group_membership',
        ownerCol: 'user_id',
        memberCol: 'group_id',
        ownerKey: 'user',
      },
      [aliceId],
    );
    // group_role_mapping — owner = group (each group on the path).
    emitSets(
      {
        table: 'group_role_mapping',
        ownerCol: 'group_id',
        memberCol: 'role_id',
        ownerKey: 'group',
      },
      groupPathIds,
    );
    // composite_role — owner = parent role (every composite among effective roles).
    emitSets(
      {
        table: 'composite_role',
        ownerCol: 'composite',
        memberCol: 'child_role',
        ownerKey: 'parent_role',
      },
      [...effectiveRoleIds],
    );
    // client_scope_role_mapping — owner = client_scope (scope B).
    emitSets(
      {
        table: 'client_scope_role_mapping',
        ownerCol: 'scope_id',
        memberCol: 'role_id',
        ownerKey: 'client_scope',
      },
      [scopeBId],
    );
    // scope_mapping — owner = client (the confidential client).
    emitSets(
      {
        table: 'scope_mapping',
        ownerCol: 'client_id',
        memberCol: 'role_id',
        ownerKey: 'client',
      },
      [clientUuidVal],
    );

    // =======================================================================
    // 11. Assemble the wire bundle.
    // =======================================================================
    const bundle: WireBundle = {
      context: { realm_id: realmUuid, client_id: clientUuidVal, user_id: aliceId },
      node_attestations,
      set_attestations,
    };

    // -----------------------------------------------------------------------
    // 12. Light assertions.
    // -----------------------------------------------------------------------
    expect(bundle.context.user_id, 'context.user_id').toBeTruthy();
    expect(bundle.node_attestations.length, 'node_attestations non-empty').toBeGreaterThan(0);
    expect(bundle.set_attestations.length, 'set_attestations non-empty').toBeGreaterThan(0);

    // Distinct signatures across the whole bundle.
    const nodeSigs = node_attestations.map((n) => n.signature).filter((s) => s.length > 0);
    const setSigs = set_attestations.map((s) => s.signature);
    const distinctNode = new Set(nodeSigs);
    const distinctSet = new Set(setSigs);
    const distinctAll = new Set([...nodeSigs, ...setSigs]);

    // Total contributing rows: node rows (1 per node) + linkage rows summed.
    const nodeRowCount = nodeSigs.length;
    const totalRows = nodeRowCount + totalContributingRows;

    // The collapse: distinct sig count strictly less than contributing row count.
    expect(
      distinctAll.size,
      `collapse: distinct sigs (${distinctAll.size}) must be < contributing rows (${totalRows})`,
    ).toBeLessThan(totalRows);

    // alice's user_entity NODE sig must differ from her user_role_mapping set sig.
    const aliceNodeSig = node_attestations.find(
      (n) => n.entity_type === 'user_entity' && n.entity_id === aliceId,
    )?.signature as string;
    const aliceRoleSet = set_attestations.find(
      (s) => s.table === 'user_role_mapping' && s.owner_id === aliceId,
    );
    expect(aliceNodeSig?.startsWith(DUMMY_PREFIX), 'alice node sig dummy').toBeTruthy();
    expect(aliceRoleSet, 'alice role set present').toBeTruthy();
    expect(
      aliceNodeSig,
      `node vs set: user_entity sig must differ from user_role_mapping set sig`,
    ).not.toBe(aliceRoleSet!.signature);

    // Re-derivability: for EVERY set, sha256→base64 of the reconstructed
    // canonical must equal the stored sig. This proves the wire sig is
    // reproducible from what we send.
    for (const s of set_attestations) {
      expect(
        dummySign(s.canonical),
        `re-derive: recomputed sig over canonical must equal stored sig for ${s.table} owner=${s.owner_id}\n  canonical=${JSON.stringify(s.canonical)}`,
      ).toBe(s.signature);
    }

    // -----------------------------------------------------------------------
    // 13. Print artifacts.
    // -----------------------------------------------------------------------
    /* eslint-disable no-console */
    console.log(`\n=== Set-signed wire bundle (tide attestor, REAL dummy sigs) ===`);
    console.log(JSON.stringify(bundle, null, 2));

    console.log(`\n=== Distinct signatures ===`);
    console.log(
      `${distinctNode.size} node sigs + ${distinctSet.size} set sigs = ${distinctAll.size} total distinct, ` +
        `over ${totalRows} contributing rows (${nodeRowCount} node rows + ${totalContributingRows} linkage rows)`,
    );
    console.log(
      `Collapse: ${distinctAll.size} distinct sigs over ${totalRows} rows ` +
        `(${set_attestations.length} linkage sets, each one shared sig over its members)`,
    );

    const s = sizeOf(bundle);
    console.log(`\n=== Sizes ===`);
    console.log(`Pretty JSON:    ${s.pretty} bytes`);
    console.log(`Minified JSON:  ${s.minified} bytes`);
    console.log(`Gzip:           ${s.gzip} bytes`);

    console.log(`\n=== Canonical / signature re-derivation proof (sample sets) ===`);
    const proofSets = set_attestations.slice(0, 2);
    for (const ps of proofSets) {
      const recomputed = dummySign(ps.canonical);
      console.log(
        `[${ps.table} owner_key=${ps.owner_key} owner=${ps.owner_id}] members=${ps.members.length}`,
      );
      console.log(`  canonical = ${JSON.stringify(ps.canonical)}`);
      console.log(`  stored    = ${ps.signature}`);
      console.log(
        `  sha256→b64= ${recomputed}   ${recomputed === ps.signature ? '✓ MATCHES (re-derivable)' : '✗ MISMATCH'}`,
      );
    }
    /* eslint-enable no-console */
  });
});
