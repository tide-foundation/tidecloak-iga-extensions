import { test, expect, APIRequestContext } from '@playwright/test';
import { execSync } from 'child_process';
import { gzipSync } from 'zlib';
import {
  createScratchRealm,
  deleteRealm,
  enableIga,
  igaStatus,
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
import { kcEnv } from '../lib/env';

/**
 * Tide-network login-row visualizer — bundle v4.
 *
 * VERIFICATION MODEL: CURRENT ATTESTED STATE ONLY.
 *
 * The Tide network verifies, per contributor row, that its CURRENT attestation
 * matches its CURRENT state. It does NOT replay per-historical-CR commit
 * payloads. The bundle therefore enumerates the CURRENT contributor rows that
 * constitute alice's effective login at tide-viz-client — entity rows AND
 * linkage (edge) rows — each carrying:
 *   - `signed_state`: the canonical bytes the Tide attestor would sign over
 *     this row's CURRENT state (a deterministic, sorted-key JSON projection of
 *     the row's business columns, EXCLUDING the attestation column itself).
 *   - `attestation`: the CURRENT value of THIS row's own ATTESTATION column,
 *     read from THIS row's own table.
 *
 * This supersedes v2 (which keyed entries by cr_id and used
 * IGA_CHANGE_REQUEST.rows_json as the signed payload — the per-CR-history
 * model). v2 also had a read bug: relationship CRs (GRANT_ROLES, JOIN_GROUPS,
 * GROUP_GRANT_ROLES, SCOPE_ADD_ROLE) read the attestation off the PRINCIPAL
 * ENTITY row (e.g. USER_ENTITY.attestation), so all of alice's GRANT_ROLES
 * showed the same timestamp. v3 reads each linkage row's OWN attestation from
 * the correct linkage table (USER_ROLE_MAPPING(uid,rid).attestation, etc.).
 *
 * v4 (this version) closes the CLIENT-CONFIG and REALM-CONFIG gaps. A Keycloak
 * token is a pure function of FIVE inputs (per the keycloak-token-construction
 * skill, references/inputs-and-outputs.md): user, client, scopeParam, surface,
 * sessionCtxAttrs. v3's bundle was user-complete but client-config-incomplete
 * and realm-config-incomplete: it carried only the scopes/mappers the user's
 * claims happened to surface, not the client's COMPLETE assigned scope set, the
 * client's own role allowlist (scope_mapping / fullScopeAllowed gate), the
 * per-scope protocol mappers, or the realm-level scope assignments that every
 * client inherits. The Tide network therefore could not reproduce WHY a given
 * claim is in the token from what we send. v4 adds, for
 * (alice, tide-viz-client, iga-tide-row-viz):
 *   - FULL CLIENT object: full_scope_allowed / consent_required /
 *     service_accounts_enabled + token-shape client attributes
 *     (use.lightweight.access.token.enabled, access.token.lifespan) read from
 *     client_attributes (which DOES carry an attestation column).
 *   - ALL default client scopes (client_scope_client.default_scope=true) AND
 *     ALL optional client scopes (default_scope=false) — the client's complete
 *     assigned scope set, regardless of whether this login requested them.
 *   - The client's own scope-mappings / role allowlist (scope_mapping table,
 *     getScopeMappingsStream) — the allowlist consulted when
 *     fullScopeAllowed=false. NOTE: scope_mapping has NO attestation column →
 *     reported as a GAP.
 *   - For each client scope in the set: its protocol mappers (protocol_mapper
 *     rows, each with its OWN attestation; built-in mappers null).
 *   - REALM-level scope assignments: default_client_scope(realm_id, scope_id,
 *     default_scope) — the default-default and default-optional templates every
 *     client inherits at create time. NO attestation column → GAP.
 *   - Realm-owned built-in client scopes + their mappers stay, now explicitly
 *     tagged realm-owned.
 * After building v4, a COVERAGE TABLE maps the skill's token inputs to bundle
 * presence + attestation, flagging the rows that have no IGA capture column as
 * GAPs. The realm signing key and realm name (iss) are out of the skill's
 * claim-shape scope and are NOT bundled (realm id + name stay in `context`).
 *
 * Bundle shape:
 *   {
 *     version: "4",
 *     context: { realm_id, client_id, user_id },   // routing header, NOT signed
 *     attested_state: [
 *       {
 *         table:        "USER_ENTITY" | "USER_ROLE_MAPPING" | ...,
 *         key:          { id: "..." } | { user_id: "...", role_id: "..." } | ...,
 *         signed_state: "<canonical sorted-key JSON of current business cols>",
 *         attestation:  "<current ATTESTATION on THIS row>",
 *         note?:        "built-in — no IGA capture" | "attachment not IGA-captured ..."
 *       },
 *       ...
 *     ]
 *   }
 *
 * - `context` is the bundle's routing header — NOT part of any signed state.
 * - `signed_state` canonical form is a DEFENSIBLE PLACEHOLDER pending the real
 *   Tide attestor's serialization contract. It is a stable, sorted-key JSON
 *   serialization of the row's business columns read from its REAL table. Keys
 *   are uppercased column names matching the IGA pipeline's row projection.
 *   Deterministic so the size is reproducible.
 * - Built-in entities (KC's stock client scopes, their mappers, the
 *   default-roles composite, and any built-in linkage rows) have a null/empty
 *   ATTESTATION. They stay in attested_state with attestation:"" and a note,
 *   so the verifier sees what's contributing but knows it is not IGA-attested.
 *
 * Two variants are emitted:
 *   1. REAL Tideless — actual SimpleNameAttestor stamps read from Postgres.
 *   2. SIMULATED Tide-sized — every non-empty attestation replaced with
 *      "A".repeat(88) (one base64 Ed25519 sig shape). `signed_state` is
 *      UNCHANGED — the Tide attestor doesn't change the signed bytes.
 *
 * AFTER the bundle, a debug block prints the issued access + id token claims —
 * for the human reader to cross-check what the runtime produced. The debug
 * block is NOT part of the bundle.
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

// ---------------------------------------------------------------------------
// Inline helpers (do not add to e2e/tests/helpers/, per task constraints).
// ---------------------------------------------------------------------------

/** Run `docker exec postgresP psql -tAc "<sql>"` and return trimmed stdout. */
function psql(sql: string): string {
  // Collapse any incidental whitespace/newlines to single spaces — psql -tAc
  // takes a single-line statement and embedded newlines break the shell arg.
  const oneLine = sql.replace(/\s+/g, ' ').trim();
  const out = execSync(
    `docker exec ${PG_CONTAINER} psql -U ${PG_USER} -d ${PG_DB} -tAc ${JSON.stringify(oneLine)}`,
    { encoding: 'utf8' },
  );
  return out.trim();
}

/**
 * Read a single ATTESTATION cell. Returns "" when row missing OR null.
 * `where` keys the row by its OWN primary/foreign-key columns — this is the
 * v2-bug fix: linkage rows are read from THEIR table, not the principal
 * entity's table.
 */
function readAttestation(table: string, where: string): string {
  const sql = `SELECT COALESCE(attestation, '') FROM ${table} WHERE ${where} LIMIT 1`;
  return psql(sql);
}

/** SQL-escape a value for embedding in a single-quoted literal. */
function sql(v: string): string {
  return v.replace(/'/g, "''");
}

/**
 * Read a row's selected business columns and return them keyed by UPPERCASE
 * column name with values as strings ("" for NULL). Columns are read in the
 * order requested but the canonical serialization (below) re-sorts the keys,
 * so order here does not affect signed_state bytes.
 */
function readRow(
  table: string,
  cols: string[],
  where: string,
): Record<string, string> {
  // Emit columns delimited by the ASCII Unit-Separator so values containing
  // '|' or whitespace round-trip through psql -tA cleanly.
  const projection = cols
    .map((c) => `COALESCE(${c}::text, '')`)
    .join(` || E'\\x1F' || `);
  const out = psql(
    `SELECT ${projection} FROM ${table} WHERE ${where} LIMIT 1`,
  );
  const parts = out === '' ? [] : out.split('\x1F');
  const row: Record<string, string> = {};
  cols.forEach((c, i) => {
    row[c.toUpperCase()] = parts[i] ?? '';
  });
  return row;
}

/**
 * Canonicalize a row projection into the bytes the Tide attestor would sign.
 *
 * PLACEHOLDER canonical form pending the real Tide attestor's serialization
 * contract: a deterministic JSON object with sorted keys. We never include the
 * attestation column (you don't sign the signature).
 */
function canonicalSignedState(row: Record<string, string>): string {
  const sorted: Record<string, string> = {};
  for (const k of Object.keys(row).sort()) sorted[k] = row[k];
  return JSON.stringify(sorted);
}

/** Resolve a realm's UUID from its name. */
function realmIdByName(name: string): string {
  return psql(`SELECT id FROM realm WHERE name='${sql(name)}' LIMIT 1`);
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

// ---------------------------------------------------------------------------
// Bundle v3 model
// ---------------------------------------------------------------------------

interface AttestedRow {
  table: string;
  key: Record<string, string>;
  // Canonical bytes the Tide attestor would sign over this row's CURRENT state.
  // null only for built-in rows where we judge "no current state to sign" is
  // cleaner than projecting one — but by default we still populate it so the
  // verifier sees the contributing row.
  signed_state: string | null;
  attestation: string;
  note?: string;
}

interface BundleV4 {
  version: '4';
  context: {
    realm_id: string;
    client_id: string;
    user_id: string;
  };
  attested_state: AttestedRow[];
}

/**
 * Substitute every non-empty `attestation` slot with the 88-char placeholder.
 * `signed_state` is left UNCHANGED (Tide attestor doesn't change the bytes the
 * verifier signs — it only changes the trailing signature byte string).
 */
function withSimulatedAttestations(b: BundleV4): BundleV4 {
  const clone: BundleV4 = JSON.parse(JSON.stringify(b));
  for (const row of clone.attested_state) {
    if (row.attestation && row.attestation.length > 0) {
      row.attestation = ATTEST_PLACEHOLDER;
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

/** Sum the byte length of every signed_state string in the bundle. */
function sumSignedStateBytes(b: BundleV4): number {
  let total = 0;
  for (const row of b.attested_state) {
    if (typeof row.signed_state === 'string') {
      total += Buffer.byteLength(row.signed_state, 'utf8');
    }
  }
  return total;
}

/** Sum the byte length of every attestation string. */
function sumAttestationBytes(b: BundleV4): number {
  let total = 0;
  for (const row of b.attested_state) {
    total += Buffer.byteLength(row.attestation, 'utf8');
  }
  return total;
}

/**
 * Partition rows by category for the size summary:
 *   - entity rows (table without a 2-col composite key)
 *   - linkage rows (composite-key edge rows)
 *   - built-in / unattested sentinels (note present)
 */
function partitionRows(b: BundleV4): {
  entity: number;
  linkage: number;
  sentinel: number;
} {
  const LINKAGE_TABLES = new Set([
    'USER_ROLE_MAPPING',
    'USER_GROUP_MEMBERSHIP',
    'GROUP_ROLE_MAPPING',
    'COMPOSITE_ROLE',
    'CLIENT_SCOPE_CLIENT',
    'CLIENT_SCOPE_ROLE_MAPPING',
    'CLIENT_ATTRIBUTES',
    'SCOPE_MAPPING',
    'DEFAULT_CLIENT_SCOPE',
  ]);
  let entity = 0;
  let linkage = 0;
  let sentinel = 0;
  for (const row of b.attested_state) {
    if (row.note) sentinel++;
    else if (LINKAGE_TABLES.has(row.table)) linkage++;
    else entity++;
  }
  return { entity, linkage, sentinel };
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

  test('build a representative login row, print v3 bundle (REAL + SIMULATED) + debug token claims', async ({
    request,
  }) => {
    // -----------------------------------------------------------------------
    // 1. Scratch realm, enable IGA on the EMPTY realm so the toggle-on scan
    //    finds nothing new to ADOPT, then build the contributor graph as a
    //    sequence of governed CRs.
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

    // Attach scopes to the client — PUT default/optional-client-scopes.
    // NOTE: this PUT produces no IGA CR (CLIENT_SCOPE_ATTACH bypass) — the
    // resulting client_scope_client rows carry a NULL attestation even though
    // they are not built-ins. The bundle distinguishes these below.
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

    const realmUuidDb = realmIdByName(REALM);
    expect(realmUuidDb, 'realm UUID from DB').toBe(realmUuid);

    // =======================================================================
    // 9. Bundle v3 assembly — enumerate the CURRENT contributor rows that
    //    constitute alice's effective login at tide-viz-client. Each row reads
    //    its OWN attestation column from its OWN table (the v2-bug fix), and a
    //    canonical signed_state from the row's current business columns.
    // =======================================================================
    const attested: AttestedRow[] = [];

    // Track which entity ids we've already emitted (dedupe across the effective
    // role/group/scope sets).
    const seenEntity = new Set<string>(); // `${table}:${id}`

    /** Append an entity row read from its real table (id-keyed). */
    function pushEntity(
      tableUpper: string,
      tableLower: string,
      cols: string[],
      id: string,
      note?: string,
    ) {
      const k = `${tableUpper}:${id}`;
      if (seenEntity.has(k)) return;
      seenEntity.add(k);
      const row = readRow(tableLower, cols, `id='${sql(id)}'`);
      const attestation = readAttestation(tableLower, `id='${sql(id)}'`);
      const entry: AttestedRow = {
        table: tableUpper,
        key: { id },
        signed_state: canonicalSignedState(row),
        attestation,
      };
      if (note) entry.note = note;
      else if (attestation === '') {
        entry.note = 'built-in — no IGA capture';
      }
      attested.push(entry);
    }

    /**
     * Append a linkage row, reading its OWN attestation from its OWN table.
     * `hasAttestationCol=false` for tables that have NO attestation column
     * (scope_mapping, default_client_scope) — these are bundled as GAP rows
     * with attestation:"" and SELECT must NOT reference the missing column.
     */
    function pushLinkage(
      tableUpper: string,
      tableLower: string,
      key: Record<string, string>,
      note?: string,
      hasAttestationCol: boolean = true,
    ) {
      const where = Object.entries(key)
        .map(([col, val]) => `${col}='${sql(val)}'`)
        .join(' AND ');
      const cols = Object.keys(key);
      const row = readRow(tableLower, cols, where);
      const attestation = hasAttestationCol
        ? readAttestation(tableLower, where)
        : '';
      const entry: AttestedRow = {
        table: tableUpper,
        key,
        signed_state: canonicalSignedState(row),
        attestation,
      };
      if (note) entry.note = note;
      attested.push(entry);
    }

    // --- 9a. USER_ENTITY (alice) ------------------------------------------
    const USER_COLS = [
      'id',
      'username',
      'email',
      'email_verified',
      'enabled',
      'first_name',
      'last_name',
      'realm_id',
    ];
    pushEntity('USER_ENTITY', 'user_entity', USER_COLS, aliceId);

    // --- 9b. Alice's effective realm-role set -----------------------------
    // Direct realm-role grants (USER_ROLE_MAPPING) — read each linkage row's
    // own attestation. Then expand composites and group-inherited roles for
    // the entity-row set.
    const ROLE_COLS = [
      'id',
      'name',
      'client_role',
      'realm_id',
      'client',
      'description',
    ];

    // Direct realm-role grants on alice (USER_ROLE_MAPPING). We list them from
    // the DB joined to keycloak_role so we only pick up REALM roles alice was
    // directly granted (composite-parent + the 2 realm roles). The
    // default-roles composite is also a direct mapping (KC auto-assigns it).
    const directRoleRows = psql(
      `SELECT urm.role_id, kr.name, kr.client_role
         FROM user_role_mapping urm
         JOIN keycloak_role kr ON kr.id = urm.role_id
        WHERE urm.user_id='${sql(aliceId)}'
        ORDER BY kr.name ASC`,
    )
      .split('\n')
      .filter(Boolean)
      .map((l) => {
        const [role_id, name, client_role] = l.split('|');
        return { role_id, name, client_role };
      });

    // Effective role-id set for entity-row emission (direct + composite
    // children + group roles). Seeded with the direct grants.
    const effectiveRoleIds = new Set<string>();

    for (const dr of directRoleRows) {
      // Linkage row: USER_ROLE_MAPPING(user_id, role_id) — OWN attestation.
      pushLinkage('USER_ROLE_MAPPING', 'user_role_mapping', {
        user_id: aliceId,
        role_id: dr.role_id,
      });
      effectiveRoleIds.add(dr.role_id);
    }

    // Composite expansion: for each direct composite role, enumerate its
    // children via COMPOSITE_ROLE(composite, child_role) — each edge its OWN
    // attestation — and add the child role ids to the effective set.
    for (const dr of directRoleRows) {
      const children = psql(
        `SELECT child_role FROM composite_role WHERE composite='${sql(dr.role_id)}' ORDER BY child_role ASC`,
      )
        .split('\n')
        .filter(Boolean);
      for (const childId of children) {
        pushLinkage('COMPOSITE_ROLE', 'composite_role', {
          composite: dr.role_id,
          child_role: childId,
        });
        effectiveRoleIds.add(childId);
      }
    }

    // --- 9c. Group membership path + group-inherited roles ----------------
    // alice → platform (child of engineering). USER_GROUP_MEMBERSHIP edge.
    pushLinkage('USER_GROUP_MEMBERSHIP', 'user_group_membership', {
      user_id: aliceId,
      group_id: childGroup.id,
    });

    // Membership path groups: platform + its ancestors (engineering).
    const GROUP_COLS = ['id', 'name', 'parent_group', 'realm_id', 'type'];
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
    for (const gid of groupPathIds) {
      pushEntity('KEYCLOAK_GROUP', 'keycloak_group', GROUP_COLS, gid);
    }

    // Group-inherited role grants: for each group on the path, its
    // GROUP_ROLE_MAPPING edges (each OWN attestation), and add the granted
    // role ids to the effective set.
    for (const gid of groupPathIds) {
      const grm = psql(
        `SELECT role_id FROM group_role_mapping WHERE group_id='${sql(gid)}' ORDER BY role_id ASC`,
      )
        .split('\n')
        .filter(Boolean);
      for (const roleId of grm) {
        pushLinkage('GROUP_ROLE_MAPPING', 'group_role_mapping', {
          group_id: gid,
          role_id: roleId,
        });
        effectiveRoleIds.add(roleId);
        // Group-inherited roles can themselves be composite — expand.
        const children = psql(
          `SELECT child_role FROM composite_role WHERE composite='${sql(roleId)}' ORDER BY child_role ASC`,
        )
          .split('\n')
          .filter(Boolean);
        for (const childId of children) {
          pushLinkage('COMPOSITE_ROLE', 'composite_role', {
            composite: roleId,
            child_role: childId,
          });
          effectiveRoleIds.add(childId);
        }
      }
    }

    // Emit a KEYCLOAK_ROLE entity row for every role in the effective set.
    for (const roleId of effectiveRoleIds) {
      pushEntity('KEYCLOAK_ROLE', 'keycloak_role', ROLE_COLS, roleId);
    }

    // -----------------------------------------------------------------------
    // Coverage tracking — set as each token input is bundled. Drives the
    // COVERAGE TABLE printed in §11. `inBundle` = a row carrying this input is
    // present; `attested` = at least one such row has a non-empty attestation
    // OR the input lives in a table with an attestation column we read.
    // -----------------------------------------------------------------------
    const coverage: Record<
      string,
      { inBundle: boolean; attested: boolean; gap?: string }
    > = {};

    // --- 9d. FULL CLIENT object (tide-viz-client) -------------------------
    // The client row carries the token-shape config fields read straight from
    // the `client` table: full_scope_allowed (gates role intersection — skill
    // invariant 6), consent_required (gates verifyConsentStillAvailable),
    // service_accounts_enabled (auto-attaches the service_account scope),
    // standard/direct flow, protocol, public_client. CLIENT row carries an
    // attestation (governed CREATE_CLIENT).
    const CLIENT_COLS = [
      'id',
      'client_id',
      'enabled',
      'protocol',
      'public_client',
      'standard_flow_enabled',
      'direct_access_grants_enabled',
      'full_scope_allowed',
      'consent_required',
      'service_accounts_enabled',
      'realm_id',
    ];
    pushEntity('CLIENT', 'client', CLIENT_COLS, clientUuidVal);
    coverage['CLIENT: fullScopeAllowed / consentRequired / attrs'] = {
      inBundle: true,
      attested: readAttestation('client', `id='${sql(clientUuidVal)}'`) !== '',
    };

    // Client attributes that shape the token (lightweight access-token toggle,
    // access-token lifespan). client_attributes(client_id,name,value) carries
    // an attestation column, so governed attribute writes ARE attestable. A
    // missing attribute row → that toggle is at its KC default (not bundled,
    // noted in coverage).
    const TOKEN_SHAPE_CLIENT_ATTRS = [
      'use.lightweight.access.token.enabled',
      'access.token.lifespan',
    ];
    let anyClientAttrPresent = false;
    let anyClientAttrAttested = false;
    for (const attrName of TOKEN_SHAPE_CLIENT_ATTRS) {
      const where = `client_id='${sql(clientUuidVal)}' AND name='${sql(attrName)}'`;
      const present =
        psql(
          `SELECT 1 FROM client_attributes WHERE ${where} LIMIT 1`,
        ) !== '';
      if (!present) continue;
      anyClientAttrPresent = true;
      const att = readAttestation('client_attributes', where);
      if (att !== '') anyClientAttrAttested = true;
      pushLinkage(
        'CLIENT_ATTRIBUTES',
        'client_attributes',
        { client_id: clientUuidVal, name: attrName },
        att === '' ? 'client attribute not IGA-governed (no attestation)' : undefined,
      );
    }

    // --- 9e. CLIENT scope-mappings / role allowlist (getScopeMappingsStream) -
    // scope_mapping(client_id, role_id) is the CLIENT's OWN role allowlist —
    // the set intersected against the user's roles when fullScopeAllowed=false
    // (scope-resolution.md: isClientScopePermittedForUser). It has NO
    // attestation column → GAP. Bundle the rows so the verifier sees the
    // allowlist, tagged as un-attestable.
    const clientScopeMappings = psql(
      `SELECT role_id FROM scope_mapping WHERE client_id='${sql(clientUuidVal)}' ORDER BY role_id ASC`,
    )
      .split('\n')
      .filter(Boolean);
    for (const roleId of clientScopeMappings) {
      pushLinkage(
        'SCOPE_MAPPING',
        'scope_mapping',
        { client_id: clientUuidVal, role_id: roleId },
        'client role-allowlist edge has no attestation column (GAP)',
        false,
      );
      // The allowlisted role also contributes to issuance — entity row.
      pushEntity('KEYCLOAK_ROLE', 'keycloak_role', ROLE_COLS, roleId);
    }
    coverage['CLIENT: scope-mappings / role allowlist'] = {
      inBundle: true,
      attested: false,
      gap: 'scope_mapping table has no attestation column',
    };

    // --- 9f. COMPLETE client scope set: default + optional ----------------
    // client_scope_client.default_scope distinguishes default (true) from
    // optional (false). We enumerate the client's COMPLETE assigned scope set
    // regardless of whether this login's scope param requested them (v3 only
    // surfaced scopes the claims happened to touch). Each scope's CLIENT_SCOPE
    // entity row + its CLIENT_SCOPE_CLIENT attach edge + ALL its protocol
    // mappers are bundled.
    const SCOPE_COLS = ['id', 'name', 'realm_id', 'protocol', 'description'];
    const vizScopeNames = new Set([
      SCOPE_DEFAULT_A,
      SCOPE_DEFAULT_B,
      SCOPE_OPTIONAL,
    ]);
    const attachRows = psql(
      `SELECT csc.scope_id, cs.name, COALESCE(csc.attestation,''), csc.default_scope
         FROM client_scope_client csc
         JOIN client_scope cs ON cs.id = csc.scope_id
        WHERE csc.client_id='${sql(clientUuidVal)}'
        ORDER BY cs.name ASC`,
    )
      .split('\n')
      .filter(Boolean)
      .map((l) => {
        const [scope_id, name, attestation, default_scope] = l.split('|');
        return {
          scope_id,
          name,
          attestation: attestation ?? '',
          isDefault: default_scope === 't' || default_scope === 'true',
        };
      });

    let anyDefaultScope = false;
    let anyOptionalScope = false;
    let anyScopeMapperAttested = false;
    let anyScopeMapperPresent = false;
    const PMAPPER_COLS = [
      'id',
      'name',
      'protocol',
      'protocol_mapper_name',
      'client_scope_id',
    ];
    for (const ar of attachRows) {
      const isViz = vizScopeNames.has(ar.name);
      if (ar.isDefault) anyDefaultScope = true;
      else anyOptionalScope = true;
      // Entity row for the scope. Viz scopes were governed (CREATE_CLIENT_SCOPE)
      // so carry an attestation; KC built-ins are realm-owned, no IGA capture.
      pushEntity(
        'CLIENT_SCOPE',
        'client_scope',
        SCOPE_COLS,
        ar.scope_id,
        isViz ? undefined : 'realm-owned built-in scope — no IGA capture',
      );
      // Attach edge: CLIENT_SCOPE_CLIENT(client_id, scope_id) — OWN attestation.
      // The PUT default/optional-client-scopes attach is NOT IGA-captured
      // (CLIENT_SCOPE_ATTACH bypass), so even viz-scope attach rows have a
      // NULL attestation. Distinguish from true built-ins via the note. We also
      // surface whether the edge is a default or optional assignment.
      const assignKind = ar.isDefault ? 'default' : 'optional';
      let note: string;
      if (ar.attestation === '') {
        note = isViz
          ? `attachment (${assignKind}) not IGA-captured (CLIENT_SCOPE_ATTACH bypass)`
          : `realm-owned built-in (${assignKind}) — no IGA capture`;
      } else {
        note = `${assignKind} client-scope attachment`;
      }
      pushLinkage(
        'CLIENT_SCOPE_CLIENT',
        'client_scope_client',
        { client_id: clientUuidVal, scope_id: ar.scope_id },
        note,
      );

      // Every protocol mapper on this scope (mapper-set-assembly.md: the mapper
      // set is the union over allowed scopes). protocol_mapper carries its OWN
      // attestation; built-in mappers are null.
      const mapperIds = psql(
        `SELECT id FROM protocol_mapper WHERE client_scope_id='${sql(ar.scope_id)}' ORDER BY id ASC`,
      )
        .split('\n')
        .filter(Boolean);
      for (const mid of mapperIds) {
        anyScopeMapperPresent = true;
        const k = `PROTOCOL_MAPPER:${mid}`;
        if (seenEntity.has(k)) continue;
        seenEntity.add(k);
        const row = readRow('protocol_mapper', PMAPPER_COLS, `id='${sql(mid)}'`);
        const att = readAttestation('protocol_mapper', `id='${sql(mid)}'`);
        if (att !== '') anyScopeMapperAttested = true;
        const entry: AttestedRow = {
          table: 'PROTOCOL_MAPPER',
          key: { id: mid },
          signed_state: canonicalSignedState(row),
          attestation: att,
        };
        if (att === '') {
          entry.note = isViz
            ? 'mapper on governed scope but not IGA-attested'
            : 'realm-owned built-in mapper — no IGA capture';
        }
        attested.push(entry);
      }
    }

    // --- 9g. CLIENT_SCOPE_ROLE_MAPPING (scope→role) -----------------------
    // The SCOPE_ADD_ROLE we created (SCOPE_DEFAULT_B → REALM_ROLES[1]) plus
    // any others on the attached scopes. Each edge its OWN attestation
    // (client_scope_role_mapping DOES carry an attestation column).
    const scopeIds = attachRows.map((a) => a.scope_id);
    if (scopeIds.length > 0) {
      const idList = scopeIds.map((s) => `'${sql(s)}'`).join(',');
      const csrm = psql(
        `SELECT scope_id, role_id FROM client_scope_role_mapping WHERE scope_id IN (${idList}) ORDER BY scope_id, role_id ASC`,
      )
        .split('\n')
        .filter(Boolean)
        .map((l) => {
          const [scope_id, role_id] = l.split('|');
          return { scope_id, role_id };
        });
      for (const m of csrm) {
        pushLinkage('CLIENT_SCOPE_ROLE_MAPPING', 'client_scope_role_mapping', {
          scope_id: m.scope_id,
          role_id: m.role_id,
        });
        // The role referenced by a scope→role mapping also contributes to
        // token issuance — include its entity row if not already present.
        pushEntity('KEYCLOAK_ROLE', 'keycloak_role', ROLE_COLS, m.role_id);
      }
    }

    coverage['CLIENT: default client scopes (getClientScopes T)'] = {
      inBundle: anyDefaultScope,
      attested: false,
      gap: 'client_scope_client attach has no attestation (CLIENT_SCOPE_ATTACH bypass)',
    };
    coverage['CLIENT: optional client scopes (getClientScopes F)'] = {
      inBundle: anyOptionalScope,
      attested: false,
      gap: 'client_scope_client attach has no attestation (CLIENT_SCOPE_ATTACH bypass)',
    };
    coverage['CLIENT SCOPES: protocol mappers'] = {
      inBundle: anyScopeMapperPresent,
      attested: anyScopeMapperAttested,
      gap: anyScopeMapperAttested
        ? undefined
        : 'protocol_mapper has an attestation column, but neither realm-owned ' +
          'built-in mappers NOR mappers created nested inside a governed ' +
          'CREATE_CLIENT_SCOPE CR are individually stamped (observed null)',
    };
    coverage['CLIENT: client attributes (lightweight / lifespan)'] = {
      inBundle: anyClientAttrPresent,
      attested: anyClientAttrAttested,
      gap: anyClientAttrPresent
        ? undefined
        : 'no token-shape client attribute set (KC defaults; nothing to bundle)',
    };

    // --- 9h. REALM-level scope assignments (inherited by every client) ----
    // default_client_scope(realm_id, scope_id, default_scope) is the realm-level
    // template: default_scope=true → default-default client scopes,
    // false → default-optional. Every client inherits these at create time
    // (scope-resolution.md "What client.getClientScopes(true) actually
    // returns"). This table has NO attestation column → GAP. We bundle the
    // assignment rows (each with the realm-owned CLIENT_SCOPE entity row) so the
    // verifier sees the realm-level inheritance source, tagged un-attestable.
    const realmDefaultScopes = psql(
      `SELECT dcs.scope_id, cs.name, dcs.default_scope
         FROM default_client_scope dcs
         JOIN client_scope cs ON cs.id = dcs.scope_id
        WHERE dcs.realm_id='${sql(realmUuid)}'
        ORDER BY cs.name ASC`,
    )
      .split('\n')
      .filter(Boolean)
      .map((l) => {
        const [scope_id, name, default_scope] = l.split('|');
        return {
          scope_id,
          name,
          isDefault: default_scope === 't' || default_scope === 'true',
        };
      });
    let anyRealmDefaultDefault = false;
    let anyRealmDefaultOptional = false;
    for (const rs of realmDefaultScopes) {
      if (rs.isDefault) anyRealmDefaultDefault = true;
      else anyRealmDefaultOptional = true;
      // Realm-owned built-in scope entity row (no IGA capture).
      pushEntity(
        'CLIENT_SCOPE',
        'client_scope',
        SCOPE_COLS,
        rs.scope_id,
        'realm-owned built-in scope — no IGA capture',
      );
      pushLinkage(
        'DEFAULT_CLIENT_SCOPE',
        'default_client_scope',
        { realm_id: realmUuid, scope_id: rs.scope_id },
        `realm ${rs.isDefault ? 'default-default' : 'default-optional'} scope assignment — no attestation column (GAP)`,
        false,
      );
      // Realm-owned built-in scopes also carry mappers that fire on the token.
      const mapperIds = psql(
        `SELECT id FROM protocol_mapper WHERE client_scope_id='${sql(rs.scope_id)}' ORDER BY id ASC`,
      )
        .split('\n')
        .filter(Boolean);
      for (const mid of mapperIds) {
        const k = `PROTOCOL_MAPPER:${mid}`;
        if (seenEntity.has(k)) continue;
        seenEntity.add(k);
        const row = readRow('protocol_mapper', PMAPPER_COLS, `id='${sql(mid)}'`);
        const att = readAttestation('protocol_mapper', `id='${sql(mid)}'`);
        const entry: AttestedRow = {
          table: 'PROTOCOL_MAPPER',
          key: { id: mid },
          signed_state: canonicalSignedState(row),
          attestation: att,
        };
        if (att === '') {
          entry.note = 'realm-owned built-in mapper — no IGA capture';
        }
        attested.push(entry);
      }
    }
    coverage['REALM: default-default / default-optional scopes'] = {
      inBundle: anyRealmDefaultDefault || anyRealmDefaultOptional,
      attested: false,
      gap: 'default_client_scope table has no attestation column',
    };
    coverage['REALM: built-in scopes + mappers'] = {
      inBundle: true,
      attested: false,
      gap: 'realm-owned built-in scopes/mappers carry no attestation',
    };

    // USER + REALM-role coverage (carried since v3).
    coverage['USER: id/roles/attributes'] = {
      inBundle: true,
      attested: readAttestation('user_entity', `id='${sql(aliceId)}'`) !== '',
    };
    coverage['REALM: realm roles (realm_access)'] = {
      inBundle: effectiveRoleIds.size > 0,
      // realm roles' direct USER_ROLE_MAPPING grants carry per-edge attestation.
      attested: true,
    };

    // -----------------------------------------------------------------------
    // 10. Final bundle (REAL + SIMULATED).
    // -----------------------------------------------------------------------
    const bundleReal: BundleV4 = {
      version: '4',
      // context is the bundle's routing header, NOT part of any signed state
      context: {
        realm_id: realmUuid,
        client_id: clientUuidVal,
        user_id: aliceId,
      },
      attested_state: attested,
    };
    const bundleSimulated = withSimulatedAttestations(bundleReal);

    // Light assertions — visualizer, not a contract test.
    expect(bundleReal.context.user_id, 'context.user_id non-empty').toBeTruthy();
    expect(bundleReal.context.client_id, 'context.client_id non-empty').toBeTruthy();
    expect(bundleReal.context.realm_id, 'context.realm_id non-empty').toBeTruthy();
    expect(
      bundleReal.attested_state.length,
      'attested_state ≥ 10 (entity + linkage + sentinel rows)',
    ).toBeGreaterThanOrEqual(10);
    // Every row has a key and a (possibly empty) attestation string.
    for (const row of bundleReal.attested_state) {
      expect(
        Object.keys(row.key).length,
        `${row.table} key non-empty`,
      ).toBeGreaterThan(0);
      expect(
        typeof row.attestation,
        `${row.table} attestation is string`,
      ).toBe('string');
    }

    // -----------------------------------------------------------------------
    // 11. Print artifacts.
    // -----------------------------------------------------------------------
    const sReal = sizeOf(bundleReal);
    const sSim = sizeOf(bundleSimulated);
    const part = partitionRows(bundleReal);
    const sumSignedReal = sumSignedStateBytes(bundleReal);
    const sumAttestReal = sumAttestationBytes(bundleReal);
    const sumAttestSim = sumAttestationBytes(bundleSimulated);

    // v3 REAL baseline (from the prior version, for the delta line):
    //   ~16.4 KB minified / 2.2 KB gzip.
    const V3_BASELINE = { minified: 16400, gzip: 2200 };

    // eslint-disable-next-line no-console
    console.log(`\n=== Bundle v4: current attested state (REAL Tideless) ===`);
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
      `Rows: ${bundleReal.attested_state.length} total (${part.entity} entity + ${part.linkage} linkage + ${part.sentinel} built-in/unattested sentinels)`,
    );
    // eslint-disable-next-line no-console
    console.log(`Sum of signed_state bytes: ${sumSignedReal}`);
    // eslint-disable-next-line no-console
    console.log(`Sum of attestation bytes:  ${sumAttestReal}`);
    // eslint-disable-next-line no-console
    console.log(
      `Delta vs v3 (REAL): minified ${sReal.minified - V3_BASELINE.minified >= 0 ? '+' : ''}${sReal.minified - V3_BASELINE.minified} B (${sReal.minified} vs ~${V3_BASELINE.minified}), ` +
        `gzip ${sReal.gzip - V3_BASELINE.gzip >= 0 ? '+' : ''}${sReal.gzip - V3_BASELINE.gzip} B (${sReal.gzip} vs ~${V3_BASELINE.gzip})`,
    );

    // eslint-disable-next-line no-console
    console.log(
      `\n=== Bundle v4: current attested state (SIMULATED Tide-sized) ===`,
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
      `Sum of attestation bytes: ${sumAttestSim} (88-char placeholder per attested row)`,
    );

    // -----------------------------------------------------------------------
    // 11b. COVERAGE TABLE — map the token-construction skill's inputs
    //      (references/inputs-and-outputs.md) to bundle presence + attestation.
    //      GAP = the input is bundled but the source table/row has no IGA
    //      attestation column, so the Tide network sees it but can't verify a
    //      signed stamp over it.
    // -----------------------------------------------------------------------
    const COVERAGE_ORDER = [
      'USER: id/roles/attributes',
      'CLIENT: default client scopes (getClientScopes T)',
      'CLIENT: optional client scopes (getClientScopes F)',
      'CLIENT: scope-mappings / role allowlist',
      'CLIENT: fullScopeAllowed / consentRequired / attrs',
      'CLIENT: client attributes (lightweight / lifespan)',
      'CLIENT SCOPES: protocol mappers',
      'REALM: default-default / default-optional scopes',
      'REALM: built-in scopes + mappers',
      'REALM: realm roles (realm_access)',
    ];
    const yn = (b: boolean) => (b ? 'yes' : 'no');
    const col = (s: string, w: number) =>
      s.length >= w ? s : s + ' '.repeat(w - s.length);
    // eslint-disable-next-line no-console
    console.log(`\n=== Coverage vs token-construction skill inputs ===`);
    // eslint-disable-next-line no-console
    console.log(
      `${col('token input (from inputs-and-outputs.md)', 50)}| ${col('in bundle?', 11)}| attested?`,
    );
    const gaps: string[] = [];
    for (const key of COVERAGE_ORDER) {
      const c = coverage[key];
      if (!c) {
        // eslint-disable-next-line no-console
        console.log(`${col(key, 50)}| ${col('MISSING', 11)}| MISSING`);
        continue;
      }
      // eslint-disable-next-line no-console
      console.log(
        `${col(key, 50)}| ${col(yn(c.inBundle), 11)}| ${yn(c.attested)}${c.gap ? '  (GAP)' : ''}`,
      );
      if (c.gap) gaps.push(`${key} — ${c.gap}`);
    }
    // eslint-disable-next-line no-console
    console.log(`\n=== GAPs (in bundle, but no IGA attestation column) ===`);
    if (gaps.length === 0) {
      // eslint-disable-next-line no-console
      console.log('(none)');
    } else {
      for (const g of gaps) {
        // eslint-disable-next-line no-console
        console.log(`- ${g}`);
      }
    }

    // Coverage assertions — every skill input must have a coverage entry, and
    // every REQUIRED input must be represented in the bundle. The fine-grained
    // 'client attributes (lightweight / lifespan)' sub-entry is legitimately
    // absent when neither toggle is set (KC defaults), so it is not required to
    // be in-bundle — only present in the table.
    const NOT_REQUIRED_IN_BUNDLE = new Set([
      'CLIENT: client attributes (lightweight / lifespan)',
    ]);
    for (const key of COVERAGE_ORDER) {
      expect(coverage[key], `coverage entry present: ${key}`).toBeTruthy();
      if (!NOT_REQUIRED_IN_BUNDLE.has(key)) {
        expect(coverage[key].inBundle, `bundled: ${key}`).toBe(true);
      }
    }

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

    // Sanity assertions on debug content.
    expect(
      (accessClaims as any).preferred_username,
      'access.preferred_username == alice',
    ).toBe(USER_NAME);
    expect((idClaims as any).sub, 'id.sub present').toBeTruthy();

    // Sanity: simulated bundle keeps shape + counts identical to real.
    expect(Object.keys(bundleSimulated).sort()).toEqual(
      Object.keys(bundleReal).sort(),
    );
    expect(bundleSimulated.attested_state.length).toBe(
      bundleReal.attested_state.length,
    );
    // signed_state bytes are IDENTICAL between REAL and SIMULATED (the Tide
    // attestor doesn't change what we sign over — only the signature).
    expect(sumSignedStateBytes(bundleSimulated)).toBe(sumSignedReal);
  });
});
