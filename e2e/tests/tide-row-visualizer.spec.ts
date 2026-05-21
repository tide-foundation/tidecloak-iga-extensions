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
import { kcEnv } from '../lib/env';

/**
 * Tide-network login-row visualizer — bundle v2.
 *
 * A Tide-network verifier signs/verifies BYTES. The bundle therefore MUST
 * carry the exact bytes that were signed at commit time — nothing
 * reconstructed from the live entity state afterwards. Otherwise signatures
 * would not verify.
 *
 * Bundle shape:
 *   {
 *     version: "2",
 *     context: { realm_id, client_id, user_id },   // routing header, NOT signed
 *     attested_operations: [
 *       {
 *         cr_id:         "<uuid>",
 *         action_type:   "CREATE_USER" | "GRANT_ROLES" | ...,
 *         entity_type:   "USER" | "ROLE" | ...,
 *         entity_id:     "<uuid or composite-id>",
 *         signed_payload: <verbatim from iga_change_request.rows_json>,
 *         attestation:    "<finalAttestation string from the entity row>"
 *       },
 *       ...
 *     ]
 *   }
 *
 * - `context` is the bundle's routing header — NOT part of any signed
 *   payload. The signed bytes live inside each attested_operations[i].
 * - `signed_payload` is the CR's stored data as a verbatim string. We do NOT
 *   JSON.parse + re-emit it — that would change the bytes-on-wire (Postgres
 *   column ordering, escaping, whitespace, etc). Embedded as a JSON string
 *   literal so size measurements match what would actually go on the wire.
 * - Built-in KC entities (the stock client scopes, their built-in mappers,
 *   default-roles-<realm>) have NO CR. They're included as sentinel
 *   `attested_operations` entries with cr_id:null, signed_payload:null,
 *   attestation:"", note:"built-in — no IGA capture" so the Tide-side
 *   reader knows they contribute to token issuance but are not (yet)
 *   IGA-attested. Treat as "well-known unsigned" pending a Tide-side
 *   design decision.
 *
 * Two variants are emitted:
 *   1. REAL Tideless — actual SimpleNameAttestor stamps read from Postgres.
 *   2. SIMULATED Tide-sized — every non-empty attestation replaced with
 *      "A".repeat(88) (one base64 Ed25519 sig shape). `signed_payload`
 *      is UNCHANGED — Tide attestor doesn't change the signed bytes.
 *
 * AFTER the bundle, a debug block prints the issued access + id token claims
 * — for the human reader to cross-check what the runtime produced. The
 * debug block is NOT part of the bundle.
 */

const REALM = 'iga-tide-row-viz';
const CLIENT_ID_HUMAN = 'tide-viz-client';
const CLIENT_SECRET = 'tide-viz-secret';
const USER_NAME = 'alice';
const USER_PASSWORD = 'tide-viz-alice-pw';

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

// Map an IGA entity_type to the Postgres table that owns the attestation
// column for that entity. Relationship CRs (GRANT_ROLES, JOIN_GROUPS,
// ADD_COMPOSITE, ASSIGN_SCOPE, SCOPE_ADD_ROLE, GROUP_GRANT_ROLES) carry the
// principal entity_type (e.g. GRANT_ROLES.entityType=USER) and the
// finalAttestation is then propagated to the relationship row(s) at replay
// time. For visualizer purposes we report the attestation off the principal
// entity's row — same string IgaSimpleAttestor.record stamps both places.
const ENTITY_TABLE: Record<string, string> = {
  USER: 'user_entity',
  ROLE: 'keycloak_role',
  CLIENT: 'client',
  CLIENT_SCOPE: 'client_scope',
  GROUP: 'keycloak_group',
  PROTOCOL_MAPPER: 'protocol_mapper',
};

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

/** Read a single ATTESTATION cell. Returns "" when row missing OR null. */
function readAttestation(table: string, where: string): string {
  const sql = `SELECT COALESCE(attestation, '') FROM ${table} WHERE ${where} LIMIT 1`;
  return psql(sql);
}

/**
 * Resolve a realm's UUID from its name (lookup KC's `realm` table). Needed
 * because the IGA CRs key off `realm_id` (UUID), not the realm name.
 */
function realmIdByName(name: string): string {
  return psql(`SELECT id FROM realm WHERE name='${name}' LIMIT 1`);
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
      console.log(
        `[drain] stuck after ${i} rounds with ${list.length} PENDING CRs; breaking`,
      );
      break;
    }
  }
  return drained;
}

/**
 * Fetch every COMMITTED CR for a realm, ordered by created_at. Returns
 * structured rows including the verbatim rows_json (signed_payload).
 *
 * `rows_json` is emitted as single-line base64 (`translate(..., '\n','')`)
 * so embedded newlines + the ASCII Unit-Separator (`\x1F`) column delimiter
 * survive `psql -tA` round-tripping. Decoded byte-for-byte on the JS side
 * — no JSON.parse + re-stringify (that would change canonical bytes).
 */
function fetchCommittedCRs(realmId: string): Array<{
  id: string;
  action_type: string;
  entity_type: string;
  entity_id: string;
  rows_json: string;
  created_at: string;
}> {
  // Committed CRs are flagged status='APPROVED' (see
  // IgaReplayDispatcher#commitChangeRequest: managed.setStatus("APPROVED")).
  // The Tideless gate doesn't have a distinct "COMMITTED" terminal state —
  // APPROVED == replay applied + entity rows + attestations populated.
  const sql = [
    "SELECT id || E'\\x1F'",
    "    || action_type || E'\\x1F'",
    "    || entity_type || E'\\x1F'",
    "    || entity_id || E'\\x1F'",
    "    || translate(encode(convert_to(rows_json, 'UTF8'), 'base64'), E'\\n', '') || E'\\x1F'",
    "    || created_at::text",
    `  FROM iga_change_request`,
    `  WHERE realm_id = '${realmId}' AND status = 'APPROVED'`,
    `  ORDER BY created_at ASC, id ASC`,
  ].join(' ');
  const raw = psql(sql);
  if (!raw) return [];
  const out: Array<{
    id: string;
    action_type: string;
    entity_type: string;
    entity_id: string;
    rows_json: string;
    created_at: string;
  }> = [];
  for (const line of raw.split('\n')) {
    if (!line) continue;
    const parts = line.split('\x1F');
    if (parts.length !== 6) {
      // eslint-disable-next-line no-console
      console.log(
        `[fetchCommittedCRs] skipping malformed row (parts=${parts.length}): ${line.slice(0, 80)}...`,
      );
      continue;
    }
    const [id, action_type, entity_type, entity_id, rows_b64, created_at] =
      parts;
    const rows_json = Buffer.from(rows_b64, 'base64').toString('utf8');
    out.push({ id, action_type, entity_type, entity_id, rows_json, created_at });
  }
  return out;
}

interface AttestedOperation {
  cr_id: string | null;
  action_type: string;
  entity_type: string;
  entity_id: string;
  // `signed_payload` is the verbatim CR rows_json string. Embedded as a
  // JSON string literal so it preserves byte-for-byte canonical fidelity.
  // null for built-in (no-CR) entries.
  signed_payload: string | null;
  attestation: string;
  note?: string;
}

interface BundleV2 {
  version: '2';
  context: {
    realm_id: string;
    client_id: string;
    user_id: string;
  };
  attested_operations: AttestedOperation[];
}

/**
 * Substitute every non-empty `attestation` slot with the 88-char placeholder.
 * `signed_payload` is left UNCHANGED (Tide attestor doesn't change the bytes
 * the verifier signs — it only changes the trailing signature byte string).
 */
function withSimulatedAttestations(b: BundleV2): BundleV2 {
  const clone: BundleV2 = JSON.parse(JSON.stringify(b));
  for (const op of clone.attested_operations) {
    if (op.attestation && op.attestation.length > 0) {
      op.attestation = ATTEST_PLACEHOLDER;
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

/**
 * Sum the byte length of every signed_payload string in the bundle.
 * Built-in (no-CR) entries contribute 0 because their payload is null.
 */
function sumSignedPayloadBytes(b: BundleV2): number {
  let total = 0;
  for (const op of b.attested_operations) {
    if (typeof op.signed_payload === 'string') {
      total += Buffer.byteLength(op.signed_payload, 'utf8');
    }
  }
  return total;
}

/**
 * Sum the byte length of every attestation string. Used to make the
 * Tideless-vs-Tide-sized comparison concrete.
 */
function sumAttestationBytes(b: BundleV2): number {
  let total = 0;
  for (const op of b.attested_operations) {
    total += Buffer.byteLength(op.attestation, 'utf8');
  }
  return total;
}

/** Count operations partitioned by IGA-captured vs built-in sentinel. */
function partitionOps(b: BundleV2): { withCR: number; builtIn: number } {
  let withCR = 0;
  let builtIn = 0;
  for (const op of b.attested_operations) {
    if (op.cr_id !== null) withCR++;
    else builtIn++;
  }
  return { withCR, builtIn };
}

/**
 * Decode the payload of a compact-serialised JWT (header.payload.signature).
 * Used ONLY for the debug block — NOT part of the bundle.
 */
function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const parts = jwt.split('.');
  if (parts.length < 2) {
    throw new Error(`decodeJwtPayload: not a JWT (parts=${parts.length})`);
  }
  const json = Buffer.from(parts[1], 'base64url').toString('utf8');
  return JSON.parse(json) as Record<string, unknown>;
}

test.describe('Tide-network login-row visualizer', () => {
  test.afterAll(async ({ request }) => {
    await deleteRealm(request, REALM).catch(() => {});
  });

  test('build a representative login row, print v2 bundle (REAL + SIMULATED) + debug token claims', async ({
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

    const initialDrain = await drainAdopts(request, REALM);
    // eslint-disable-next-line no-console
    console.log(
      `[setup] toggle-on ADOPT drain: committed=${initialDrain.committed} total=${initialDrain.total}`,
    );

    // -----------------------------------------------------------------------
    // 2. Bases first (CREATE_ROLE for the 3 realm roles + the group-inherited
    //    role + each composite child must exist BEFORE the composite parent
    //    is POSTed).
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
      const r = await createRole(request, REALM, {
        name: COMPOSITE_PARENT,
        composite: true,
        composites: { realm: [REALM_ROLES[0], REALM_ROLES[1]] },
      });
      await commitGoverned(request, REALM, r, `CREATE_ROLE ${COMPOSITE_PARENT}`);
    }

    // -----------------------------------------------------------------------
    // 3. Client + client roles.
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
    // 5. GROUP_GRANT_ROLES — assign the GROUP_ROLE to the parent group.
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

    // Add alice to engineering/platform — JOIN_GROUPS CR.
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
    await drainAllPending(request, REALM);

    // Direct role grants: realm roles + composite parent.
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
      await drainAllPending(request, REALM);
    }

    // -----------------------------------------------------------------------
    // 7. Client scopes (2 default + 1 optional). One scope carries a protocol
    //    mapper. One scope gets a SCOPE_ADD_ROLE.
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

    // Attach scopes to the client — ASSIGN_SCOPE CRs (governed by IGA
    // ClientAdapter wrapping).
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
      expect(
        attachRes.status(),
        `attach scope ${s.name} as ${s.assignmentKind}`,
      ).toBeLessThan(300);
    }
    await drainAllPending(request, REALM);

    // Map REALM_ROLES[1] onto SCOPE_DEFAULT_B (SCOPE_ADD_ROLE CR).
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
    // 7b. Set alice's password + issue real access + id tokens for the debug
    //     block (NOT part of the bundle).
    // -----------------------------------------------------------------------
    const pwRes = await kcFetch(
      request,
      `/admin/realms/${REALM}/users/${aliceId}/reset-password`,
      {
        method: 'PUT',
        json: { type: 'password', value: USER_PASSWORD, temporary: false },
      },
    );
    expect(
      pwRes.status(),
      `reset alice password expected 204, got ${pwRes.status()}`,
    ).toBe(204);

    const secretRes = await kcFetch(
      request,
      `/admin/realms/${REALM}/clients/${cUuid}/client-secret`,
    );
    expect(secretRes.status(), 'client-secret GET').toBe(200);
    const secretBody = await safeJson(secretRes);
    const tideVizSecret = (secretBody?.value as string) || CLIENT_SECRET;
    expect(tideVizSecret, 'tide-viz-client secret').toBeTruthy();

    const { baseUrl } = kcEnv();
    const tokenRes = await request.post(
      `${baseUrl}/realms/${REALM}/protocol/openid-connect/token`,
      {
        form: {
          grant_type: 'password',
          client_id: CLIENT_ID_HUMAN,
          client_secret: tideVizSecret,
          username: USER_NAME,
          password: USER_PASSWORD,
          scope: 'openid',
        },
      },
    );
    expect(
      tokenRes.status(),
      `tide-viz-client password grant expected 200, got ${tokenRes.status()} ${await tokenRes.text().catch(() => '')}`,
    ).toBe(200);
    const tokenBody = (await safeJson(tokenRes)) as {
      access_token: string;
      id_token?: string;
    };
    expect(tokenBody.access_token, 'access_token present').toBeTruthy();
    expect(tokenBody.id_token, 'id_token present (scope=openid)').toBeTruthy();

    const accessClaims = decodeJwtPayload(tokenBody.access_token);
    const idClaims = decodeJwtPayload(tokenBody.id_token as string);

    // -----------------------------------------------------------------------
    // 8. Realm + client UUIDs (for the bundle's `context` routing header).
    // -----------------------------------------------------------------------
    const realmGetRes = await kcFetch(request, `/admin/realms/${REALM}`);
    const realmRep = await safeJson(realmGetRes);
    expect(realmRep?.id, 'realm id').toBeTruthy();
    const realmUuid = realmRep.id as string;

    const clientLookup = await getClientByClientId(
      request,
      REALM,
      CLIENT_ID_HUMAN,
    );
    expect(clientLookup.body?.id, 'client id').toBeTruthy();
    const clientUuidVal = clientLookup.body.id as string;

    // -----------------------------------------------------------------------
    // 9. Bundle v2 assembly — pull every COMMITTED CR for this realm
    //    verbatim from Postgres. Each CR contributes one attested_operation
    //    with signed_payload = rows_json (verbatim string, byte-preserved).
    // -----------------------------------------------------------------------
    const realmUuidDb = realmIdByName(REALM);
    expect(realmUuidDb, 'realm UUID from DB').toBe(realmUuid);

    const committed = fetchCommittedCRs(realmUuidDb);
    expect(committed.length, 'at least one COMMITTED CR').toBeGreaterThan(0);

    const attestedOps: AttestedOperation[] = committed.map((cr) => {
      const table = ENTITY_TABLE[cr.entity_type];
      let attestation = '';
      if (table) {
        attestation = readAttestation(table, `id='${cr.entity_id}'`);
      }
      // SCOPE_ADD_ROLE is governed under entity_type=CLIENT with
      // entity_id=<scope_id>, which doesn't exist in the `client` table.
      // The attestation actually lives on the client_scope_role_mapping
      // edge row stamped at replay. Look it up by (scope_id, role_id)
      // parsed from the verbatim rows_json.
      if (attestation === '' && cr.action_type === 'SCOPE_ADD_ROLE') {
        const m = /"SCOPE_ID":"([^"]+)"[^}]*"ROLE_ID":"([^"]+)"/.exec(
          cr.rows_json,
        );
        if (m) {
          attestation = readAttestation(
            'client_scope_role_mapping',
            `scope_id='${m[1]}' AND role_id='${m[2]}'`,
          );
        }
      }
      // signed_payload must be the verbatim rows_json string. We DO NOT
      // JSON.parse + re-emit it.
      return {
        cr_id: cr.id,
        action_type: cr.action_type,
        entity_type: cr.entity_type,
        entity_id: cr.entity_id,
        signed_payload: cr.rows_json,
        attestation,
      };
    });

    // -----------------------------------------------------------------------
    // 9b. Built-in (no-CR) sentinel entries.
    //
    // The realm carries built-in entities the Tide network needs to know
    // about because they contribute to token issuance — but they were never
    // IGA-captured (no CR exists, no attestation was stamped). The verifier
    // will treat these as "well-known unsigned" until a Tide-side design
    // decision changes that. We emit them as sentinel attested_operations
    // with cr_id:null and signed_payload:null so the gap is visible.
    //
    // Conservatively included:
    //   - The realm's `default-roles-<realm>` composite role (assigned to
    //     every user implicitly via the realm's defaultRole reference).
    //   - The 11 built-in OIDC client scopes that are attached as default
    //     scopes to every new client (profile, email, address, phone,
    //     offline_access, microprofile-jwt, roles, web-origins, acr,
    //     basic, organization — varies by KC build).
    //   - The protocol-mappers KC pre-installs on those built-in scopes.
    //
    // We discover them by querying the DB for entities in this realm whose
    // id was NOT mentioned in any committed CR's entity_id.
    // -----------------------------------------------------------------------
    // Entity-id coverage for built-in sentinel detection. We MUST include
    // not just each CR's entity_id, but every entity id mentioned inside
    // any CR's rows_json — because some CRs capture multiple entities
    // inline (e.g. CREATE_CLIENT_SCOPE.REP_JSON nests a protocolMappers[]
    // array with mapper ids; those mappers ARE attested via the parent
    // CR's signed payload, NOT built-ins).
    const crEntityIds = new Set<string>(committed.map((c) => c.entity_id));
    // Match UUIDs anywhere in the raw rows_json — works for both the outer
    // "ID":"..." columns and the inner escaped REP_JSON ("id":"...","
    // becomes "\"id\":\"...\"" after JSON-stringification). A raw UUID-
    // shaped scan is cheaper than properly un-escaping every nested level.
    const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g;
    for (const cr of committed) {
      for (const m of cr.rows_json.matchAll(UUID_RE)) {
        crEntityIds.add(m[0]);
      }
    }

    // Built-in client scopes attached to the realm (the realm spawns the
    // standard set when created; they are realm-scoped, not client-scoped).
    const builtinScopeRows = psql(
      `SELECT id, name FROM client_scope WHERE realm_id='${realmUuid}'`,
    )
      .split('\n')
      .filter(Boolean);
    for (const line of builtinScopeRows) {
      const [id, name] = line.split('|');
      if (crEntityIds.has(id)) continue; // CR already covered this scope
      attestedOps.push({
        cr_id: null,
        action_type: 'BUILTIN_CLIENT_SCOPE',
        entity_type: 'CLIENT_SCOPE',
        entity_id: id,
        signed_payload: null,
        attestation: '',
        note: `built-in — no IGA capture (name=${name})`,
      });
    }

    // Built-in default-roles-<realm> composite role.
    const defaultRolesRow = psql(
      `SELECT id, name FROM keycloak_role WHERE realm_id='${realmUuid}' AND name LIKE 'default-roles-%' LIMIT 1`,
    );
    if (defaultRolesRow) {
      const [id, name] = defaultRolesRow.split('|');
      if (!crEntityIds.has(id)) {
        attestedOps.push({
          cr_id: null,
          action_type: 'BUILTIN_REALM_DEFAULT_ROLE',
          entity_type: 'ROLE',
          entity_id: id,
          signed_payload: null,
          attestation: '',
          note: `built-in — no IGA capture (name=${name})`,
        });
      }
    }

    // Built-in protocol-mappers on the built-in scopes attached to our
    // client (each built-in scope ships a handful of mappers — they
    // contribute claims at token issuance, so the verifier needs to know).
    const ourClientScopeIds = psql(
      `SELECT scope_id FROM client_scope_client WHERE client_id='${clientUuidVal}'`,
    )
      .split('\n')
      .filter(Boolean);
    if (ourClientScopeIds.length > 0) {
      const ids = ourClientScopeIds.map((s) => `'${s}'`).join(',');
      const mapperRows = psql(
        `SELECT id, name FROM protocol_mapper WHERE client_scope_id IN (${ids}) OR client_id='${clientUuidVal}'`,
      )
        .split('\n')
        .filter(Boolean);
      for (const line of mapperRows) {
        const [id, name] = line.split('|');
        if (crEntityIds.has(id)) continue;
        attestedOps.push({
          cr_id: null,
          action_type: 'BUILTIN_PROTOCOL_MAPPER',
          entity_type: 'PROTOCOL_MAPPER',
          entity_id: id,
          signed_payload: null,
          attestation: '',
          note: `built-in — no IGA capture (name=${name})`,
        });
      }
    }

    // -----------------------------------------------------------------------
    // 10. Final bundle (REAL + SIMULATED).
    // -----------------------------------------------------------------------
    const bundleReal: BundleV2 = {
      version: '2',
      // context is the bundle's routing header, NOT part of any signed payload
      context: {
        realm_id: realmUuid,
        client_id: clientUuidVal,
        user_id: aliceId,
      },
      attested_operations: attestedOps,
    };
    const bundleSimulated = withSimulatedAttestations(bundleReal);

    // Light assertions — visualizer, not a contract test.
    expect(bundleReal.context.user_id, 'context.user_id non-empty').toBeTruthy();
    expect(bundleReal.context.client_id, 'context.client_id non-empty').toBeTruthy();
    expect(bundleReal.context.realm_id, 'context.realm_id non-empty').toBeTruthy();
    expect(
      bundleReal.attested_operations.length,
      'attested_operations ≥ 10 (CRs + built-in sentinels)',
    ).toBeGreaterThanOrEqual(10);
    // Every CR-backed op must have a non-null signed_payload that is a
    // non-empty string (rows_json is NOT NULL in schema).
    for (const op of bundleReal.attested_operations) {
      if (op.cr_id !== null) {
        expect(
          typeof op.signed_payload,
          `cr_id=${op.cr_id} signed_payload type`,
        ).toBe('string');
        expect(
          (op.signed_payload as string).length,
          `cr_id=${op.cr_id} signed_payload non-empty`,
        ).toBeGreaterThan(0);
      } else {
        expect(
          op.signed_payload,
          `built-in sentinel ${op.entity_id} signed_payload null`,
        ).toBeNull();
      }
    }

    // -----------------------------------------------------------------------
    // 11. Print artifacts.
    // -----------------------------------------------------------------------
    const sReal = sizeOf(bundleReal);
    const sSim = sizeOf(bundleSimulated);
    const partition = partitionOps(bundleReal);
    const sumSignedReal = sumSignedPayloadBytes(bundleReal);
    const sumAttestReal = sumAttestationBytes(bundleReal);
    const sumAttestSim = sumAttestationBytes(bundleSimulated);

    // eslint-disable-next-line no-console
    console.log(
      `\n=== Bundle v2: per-CR signed payloads + final attestations (REAL Tideless) ===`,
    );
    // eslint-disable-next-line no-console
    console.log(JSON.stringify(bundleReal, null, 2));
    // eslint-disable-next-line no-console
    console.log(`\n=== Sizes (REAL Tideless) ===`);
    // eslint-disable-next-line no-console
    console.log(`Pretty JSON:    ${sReal.pretty} bytes`);
    // eslint-disable-next-line no-console
    console.log(`Minified JSON:  ${sReal.minified} bytes`);
    // eslint-disable-next-line no-console
    console.log(`Gzip:           ${sReal.gzip} bytes`);
    // eslint-disable-next-line no-console
    console.log(
      `Operations: ${bundleReal.attested_operations.length} total (${partition.withCR} with IGA CR + signed_payload, ${partition.builtIn} built-in/no-CR sentinels)`,
    );
    // eslint-disable-next-line no-console
    console.log(`Sum of signed_payload bytes: ${sumSignedReal}`);
    // eslint-disable-next-line no-console
    console.log(`Sum of attestation bytes:    ${sumAttestReal}`);

    // eslint-disable-next-line no-console
    console.log(
      `\n=== Bundle v2: per-CR signed payloads + final attestations (SIMULATED Tide-sized) ===`,
    );
    // eslint-disable-next-line no-console
    console.log(JSON.stringify(bundleSimulated, null, 2));
    // eslint-disable-next-line no-console
    console.log(`\n=== Sizes (SIMULATED Tide-sized) ===`);
    // eslint-disable-next-line no-console
    console.log(`Pretty JSON:    ${sSim.pretty} bytes`);
    // eslint-disable-next-line no-console
    console.log(`Minified JSON:  ${sSim.minified} bytes`);
    // eslint-disable-next-line no-console
    console.log(`Gzip:           ${sSim.gzip} bytes`);
    // eslint-disable-next-line no-console
    console.log(
      `Sum of attestation bytes: ${sumAttestSim} (88-char placeholder per IGA-attested op)`,
    );

    // -----------------------------------------------------------------------
    // 12. Debug block — issued token claims. NOT part of the bundle.
    // -----------------------------------------------------------------------
    // eslint-disable-next-line no-console
    console.log(`\n=== Debug: issued token claims (NOT part of bundle) ===`);
    const debugExtract = {
      access: {
        iss: (accessClaims as any).iss,
        aud: (accessClaims as any).aud,
        sub: (accessClaims as any).sub,
        preferred_username: (accessClaims as any).preferred_username,
        email: (accessClaims as any).email,
        realm_access: (accessClaims as any).realm_access,
        resource_access: (accessClaims as any).resource_access,
        scope: (accessClaims as any).scope,
        tide_viz_claim: (accessClaims as any).tide_viz_claim,
      },
      id: {
        iss: (idClaims as any).iss,
        aud: (idClaims as any).aud,
        sub: (idClaims as any).sub,
        preferred_username: (idClaims as any).preferred_username,
        email: (idClaims as any).email,
        tide_viz_claim: (idClaims as any).tide_viz_claim,
      },
    };
    // eslint-disable-next-line no-console
    console.log(JSON.stringify(debugExtract, null, 2));

    // Sanity assertions on debug content (these confirm the run produced
    // semantically correct output, not bundle correctness).
    expect(
      (accessClaims as any).preferred_username,
      'access.preferred_username == alice',
    ).toBe(USER_NAME);
    expect((idClaims as any).sub, 'id.sub present').toBeTruthy();

    // Sanity: simulated bundle keeps shape + counts identical to real.
    expect(Object.keys(bundleSimulated).sort()).toEqual(
      Object.keys(bundleReal).sort(),
    );
    expect(bundleSimulated.attested_operations.length).toBe(
      bundleReal.attested_operations.length,
    );
    // signed_payload bytes are IDENTICAL between REAL and SIMULATED (the
    // Tide attestor doesn't change what we sign over — only the signature).
    expect(sumSignedPayloadBytes(bundleSimulated)).toBe(sumSignedReal);
  });
});
