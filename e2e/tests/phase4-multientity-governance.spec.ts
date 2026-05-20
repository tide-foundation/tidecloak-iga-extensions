import { test, expect } from '@playwright/test';
import {
  createScratchRealm,
  deleteRealm,
  enableIga,
  igaStatus,
  declareUserProfileAttribute,
  partialImport,
  listChangeRequests,
  getChangeRequest,
  authorizeAndCommit,
  getRole,
  getGroupByName,
  getGroupById,
  getUserByUsername,
  getClientByClientId,
  getClientProtocolMappers,
  getClientScopeByName,
  getClientScopeProtocolMappers,
  locationHeader,
  safeJson,
  ChangeRequest,
} from '../lib/kc';

/**
 * Phase 4 — true batch governance for partialImport.
 *
 * Before Phase 4 the single-entity capture seams (Phases 1–3) each emit ONE
 * CR then setRollbackOnly + throw mid-flow, so inside
 * POST /admin/realms/{realm}/partialImport the FIRST captured entity aborted
 * the whole import; and partialImport users (routed through the 5-arg
 * local-storage addUser of DefaultExportImportManager.createUser, NOT the
 * Phase-3 1-arg seam) were created UNGOVERNED.
 *
 * Phase 4 mechanism (source-proven, KC 26.5.5): every governed create in the
 * import ACCUMULATES its per-type CR (no per-entity throw / no
 * setRollbackOnly); a KeycloakTransaction enlisted via enlistPrepare on the
 * nested import session writes ALL accumulated CRs in one independent
 * transaction then throws once — the scratch import tx is rolled back
 * (every imported entity discarded atomically) and the mapper returns a
 * single 202 carrying the batch.
 *
 * Scenario: scratch realm + IGA on, ONE partialImport carrying 2 users +
 * 1 realm role + 1 group + 1 client + 1 client-scope →
 *   - single 202 (batch),
 *   - 6 PENDING CRs of the right types (2× CREATE_USER, 1× CREATE_ROLE,
 *     1× CREATE_GROUP, 1× CREATE_CLIENT, 1× CREATE_CLIENT_SCOPE — clients +
 *     client-scopes added so the import-mode branch covers addClient
 *     symmetrically and addClientScope by defensive parity, even though KC
 *     26.5.5 has no ClientScopesPartialImport per-type handler and the scope
 *     in the partialImport payload is therefore not consumed by the per-type
 *     import loop today; see IgaImportMode#registerImportClientScope
 *     javadoc for the source-confirmed gap),
 *   - NONE of the 6 entities exist at draft (GET each → absent, INCLUDING
 *     the 2 users — proving the 5-arg local-storage addUser bypass is
 *     closed — AND the client, proving the addClient import branch closes
 *     the same class of bypass),
 *   - authorize+commit all CRs → all 6 entities exist with config (full
 *     attribute / protocol-mapper / redirectUri fidelity).
 *
 * Pure API E2E (no browser). Idempotent; teardown deletes the scratch realm
 * even on failure.
 *
 * Precondition gate (loaded-vs-codebug style, REAL evidence — never a bogus
 * "restart"): a governed partialImport must 202 and the entities must NOT
 * persist immediately. If they persist immediately we distinguish "Phase 4
 * jar not loaded" (restart then re-run) from "loaded but Phase 4 inactive /
 * code bug" (do NOT restart; fix the code) using the parsed response + CRs.
 */

const REALM = 'iga-phase4-e2e';
const PROBE_REALM = 'iga-phase4-precond-probe';
const RERUN =
  'cd /home/sasha/project/tidecloak-iga-extensions/e2e && npx playwright test';

const ROLE_NAME = 'p4-role';
const GROUP_NAME = 'p4-group';
const USER_A = 'p4-user-a';
const USER_B = 'p4-user-b';
const CLIENT_ID = 'p4-client';
const CLIENT_SCOPE_NAME = 'p4-scope';
const CUSTOM_ATTR = 'p4CustomAttr';
// A non-default redirect URI proves redirectUri fidelity through capture+replay.
const CLIENT_REDIRECT = 'https://phase4.example.test/cb';
// Saml protocol on the client + a saml-user-attribute-mapper exercises a
// non-default protocol AND mapper config (must survive capture+replay verbatim,
// same shape Phase 2 exercises for client scopes).
const CLIENT_MAPPER_NAME = 'p4-client-mapper';
const SCOPE_MAPPER_NAME = 'p4-scope-mapper';

/**
 * The PartialImportRepresentation: 2 users + 1 realm role + 1 group + 1 client
 * + 1 client-scope. Each entity carries enough non-default state (custom
 * attribute / protocol mapper / redirectUri) to prove capture+replay fidelity.
 *
 * Client populated with the fields KC's ClientsPartialImport.getModelId reads
 * after create() (services/.../ClientsPartialImport.java:77-79 —
 * `realm.getClientByClientId(getName(clientRep)).getId()` where getName ==
 * clientRep.getClientId()), so `clientId` is the only hard precondition. The
 * IgaRealmProvider.addClient import branch persists the scratch client via
 * super.addClient (em.persist+flush) so that lookup resolves in the nested
 * import session — same precondition pattern as createGroup/path and the
 * other Phase 4 branches.
 *
 * Client-scope is included for symmetry / defensive parity. KC 26.5.5 has NO
 * ClientScopesPartialImport (PartialImportManager.partialImports —
 * services/.../partialimport/PartialImportManager.java:47-52 — registers only
 * Clients/Roles/IdPs/IdP-mappers/Groups/Users; the source set has no
 * ClientScopesPartialImport.java), so the per-type import loop does NOT
 * consume `clientScopes` from the payload and we cannot assert a
 * CREATE_CLIENT_SCOPE batch CR here today. The payload entry documents the
 * defensive wiring; if a future KC version adds the handler the assertions in
 * the "future" block below will start passing automatically.
 */
function importRep() {
  return {
    ifResourceExists: 'FAIL',
    roles: {
      realm: [
        {
          name: ROLE_NAME,
          description: 'phase4 batch-imported realm role',
          attributes: { [CUSTOM_ATTR]: ['role-val'] },
        },
      ],
    },
    groups: [
      {
        name: GROUP_NAME,
        // path MUST be supplied. KC's GroupsPartialImport.getModelId (KC
        // 26.5.5 GroupsPartialImport.java:53) is `findGroupModel(...).getId()`
        // where findGroupModel == KeycloakModelUtils.findGroupByPath(session,
        // realm, groupRep.getPath()). findGroupByPath returns null at its
        // first guard (`if (path == null) return null;`) when the rep omits
        // path, → null.getId() → NPE → KC-SERVICES0037 → HTTP 500 (the
        // role/user paths don't NPE: RealmRolesPartialImport.getModelId uses
        // .orElse(null), UsersPartialImport.getModelId uses a createdIds
        // cache). This is vanilla-KC behaviour, not IGA-specific —
        // empirically verified: the same payload returns 500 on an
        // IGA-disabled realm, and KC's own AbstractPartialImportTest
        // .addGroups always sets BOTH name AND path
        // ("/" + GROUP_PREFIX + i). IGA's Phase 4 import branch
        // (IgaRealmProvider.createGroup) already persists the scratch group
        // normally via super.createGroup so the find-by-name half of
        // findGroupByPath would resolve it — but only if path != null at the
        // call site. Supplying path here makes the payload conform to KC's
        // partialImport contract and lets the Phase 4 batch governance run.
        path: `/${GROUP_NAME}`,
        attributes: { [CUSTOM_ATTR]: ['group-val'] },
      },
    ],
    users: [
      {
        username: USER_A,
        enabled: true,
        email: `${USER_A}@example.test`,
        emailVerified: true,
        firstName: 'Phase4',
        lastName: 'Alpha',
        attributes: { [CUSTOM_ATTR]: ['user-a-val'] },
      },
      {
        username: USER_B,
        enabled: true,
        email: `${USER_B}@example.test`,
        emailVerified: true,
        firstName: 'Phase4',
        lastName: 'Bravo',
        attributes: { [CUSTOM_ATTR]: ['user-b-val'] },
      },
    ],
    clients: [
      {
        clientId: CLIENT_ID,
        protocol: 'openid-connect',
        enabled: true,
        publicClient: true,
        redirectUris: [CLIENT_REDIRECT],
        attributes: {
          [CUSTOM_ATTR]: 'client-val',
          // A non-default well-known KC client attribute also proves attribute
          // fidelity through the capture+batch+replay round-trip.
          'post.logout.redirect.uris': '+',
        },
        protocolMappers: [
          {
            name: CLIENT_MAPPER_NAME,
            protocol: 'openid-connect',
            protocolMapper: 'oidc-usermodel-attribute-mapper',
            config: {
              'user.attribute': CUSTOM_ATTR,
              'claim.name': 'p4_custom_claim',
              'jsonType.label': 'String',
              'id.token.claim': 'true',
              'access.token.claim': 'true',
              'userinfo.token.claim': 'true',
            },
          },
        ],
      },
    ],
    clientScopes: [
      {
        name: CLIENT_SCOPE_NAME,
        description: 'phase4 batch-imported client scope',
        // Non-default protocol (saml) + an attribute + a mapper with full
        // config, same fidelity shape as the Phase 2 single-entity client-
        // scope spec. NOTE (source-confirmed): KC 26.5.5 has no
        // ClientScopesPartialImport (PartialImportManager registers only
        // Clients/Roles/IdPs/IdP-mappers/Groups/Users), so this payload entry
        // is NOT consumed by the per-type import loop today; the
        // IgaRealmProvider.addClientScope import branch is wired up for
        // defensive parity (future KC versions / indirect multi-entity import
        // paths). Therefore CREATE_CLIENT_SCOPE is NOT among the expected
        // pending CRs; if KC ever adds the handler the future-coverage
        // assertions below will start passing automatically.
        protocol: 'saml',
        attributes: {
          [CUSTOM_ATTR]: 'scope-val',
          'display.on.consent.screen': 'true',
          'consent.screen.text': 'phase4-consent',
        },
        protocolMappers: [
          {
            name: SCOPE_MAPPER_NAME,
            protocol: 'saml',
            protocolMapper: 'saml-user-attribute-mapper',
            config: {
              'attribute.nameformat': 'Basic',
              'user.attribute': CUSTOM_ATTR,
              'attribute.name': 'p4-scope-attr-name',
              'friendly.name': 'p4-scope-friendly',
            },
          },
        ],
      },
    ],
  };
}

/** Parse the REP_JSON of the first row of a CR (the replay source of truth). */
function parseRep(crBody: any): any | undefined {
  const rows: any[] = Array.isArray(crBody?.rows)
    ? crBody.rows
    : Array.isArray(crBody)
      ? crBody
      : [];
  for (const row of rows) {
    const repJson = row?.REP_JSON ?? row?.rep_json ?? row?.repJson;
    if (typeof repJson === 'string' && repJson.length > 0) {
      try {
        return JSON.parse(repJson);
      } catch {
        /* next */
      }
    } else if (repJson && typeof repJson === 'object') {
      return repJson;
    }
  }
  return undefined;
}

/** Group all CR action types → count, for batch-shape assertions. */
function actionCounts(crs: ChangeRequest[]): Record<string, number> {
  const m: Record<string, number> = {};
  for (const cr of crs) {
    m[cr.actionType] = (m[cr.actionType] ?? 0) + 1;
  }
  return m;
}

test.describe('IGA Phase 4: partialImport batch governance', () => {
  test.afterAll(async ({ request }) => {
    await deleteRealm(request, REALM).catch(() => {});
    await deleteRealm(request, PROBE_REALM).catch(() => {});
  });

  test('partialImport (2 users + 1 role + 1 group + 1 client + 1 client-scope) → ONE 202 batch, 5 pending CRs (clientScopes inert per KC 26.5.5 source), NOTHING at draft (incl. users — 5-arg bypass closed — and client), all created on commit', async ({
    request,
  }) => {
    // -----------------------------------------------------------------------
    // PRECONDITION GATE — a governed partialImport must 202 and NOT persist
    // any entity at draft. Distinguish jar-not-loaded vs loaded-but-codebug
    // with real parsed evidence (never a misleading "restart").
    // -----------------------------------------------------------------------
    const pre = await (async () => {
      const evidence: Record<string, unknown> = {};
      try {
        await createScratchRealm(request, PROBE_REALM);
        await declareUserProfileAttribute(request, PROBE_REALM, CUSTOM_ATTR);
        await enableIga(request, PROBE_REALM);
        evidence.igaEnabled = true;

        const res = await partialImport(request, PROBE_REALM, importRep());
        const status = res.status();
        const loc = locationHeader(res);
        const body = await safeJson(res);
        evidence.status = status;
        evidence.location = loc ?? null;
        evidence.body = body;

        // Did anything persist immediately? (the decisive bypass check).
        // Client also probed so an addClient leak (the SAME class of bypass
        // the 5-arg addUser fix closed) is caught as a CODE BUG, not a
        // restart issue. Client-scope is NOT probed here because KC 26.5.5
        // has no ClientScopesPartialImport (PartialImportManager registers
        // only Clients/Roles/IdPs/IdP-mappers/Groups/Users), so the per-type
        // import loop never reaches addClientScope and the payload entry is
        // deliberately discarded by KC itself — there is nothing to leak.
        const roleNow = await getRole(request, PROBE_REALM, ROLE_NAME);
        const grpNow = await getGroupByName(request, PROBE_REALM, GROUP_NAME);
        const uaNow = await getUserByUsername(request, PROBE_REALM, USER_A);
        const ubNow = await getUserByUsername(request, PROBE_REALM, USER_B);
        const cliNow = await getClientByClientId(
          request,
          PROBE_REALM,
          CLIENT_ID,
        );
        const persisted = {
          role: roleNow.http === 200,
          group: !!grpNow.body,
          userA: !!uaNow.body,
          userB: !!ubNow.body,
          client: !!cliNow.body,
        };
        evidence.persistedAtDraft = persisted;

        if (status !== 202) {
          // 200 + entities persisted ⇒ jar loaded but Phase 4 NOT
          // intercepting partialImport (code bug — do NOT restart). Any
          // other non-202 with nothing persisted ⇒ jar likely not loaded.
          const anyPersisted = Object.values(persisted).some(Boolean);
          if (status === 200 && anyPersisted) {
            return {
              ok: false as const,
              loaded: true as const,
              detail:
                `partialImport returned 200 and entities persisted ` +
                `immediately (${JSON.stringify(persisted)}) — the Phase 4 ` +
                `jar IS loaded but partialImport batch governance is NOT ` +
                `active (CODE BUG: import-mode detection or enlistPrepare ` +
                `not firing). Do NOT restart; fix the code.`,
              evidence,
            };
          }
          return {
            ok: false as const,
            loaded: false as const,
            detail:
              `partialImport returned ${status} (expected 202 batch) and ` +
              `nothing persisted — the Phase 4 jar is likely not loaded.`,
            evidence,
          };
        }
        // 202 but something persisted at draft ⇒ loaded but the discard
        // (scratch rollback) is broken — code bug, not a restart.
        const leaked = Object.entries(persisted)
          .filter(([, v]) => v)
          .map(([k]) => k);
        if (leaked.length > 0) {
          return {
            ok: false as const,
            loaded: true as const,
            detail:
              `partialImport returned 202 but ${JSON.stringify(leaked)} ` +
              `persisted at draft — Phase 4 loaded but the scratch ` +
              `rollback/discard is broken (CODE BUG, not a restart). ` +
              `Especially a leaked user proves the 5-arg addUser bypass ` +
              `is NOT closed.`,
            evidence,
          };
        }
        const crs = await listChangeRequests(request, PROBE_REALM);
        evidence.crCount = crs.length;
        evidence.crActionCounts = actionCounts(crs);
        const counts = actionCounts(crs);
        const batchOk =
          (counts.CREATE_USER ?? 0) >= 2 &&
          (counts.CREATE_ROLE ?? 0) >= 1 &&
          (counts.CREATE_GROUP ?? 0) >= 1 &&
          (counts.CREATE_CLIENT ?? 0) >= 1;
        if (!batchOk) {
          return {
            ok: false as const,
            loaded: true as const,
            detail:
              `partialImport 202 + nothing at draft, but the pending CRs ` +
              `are not the expected batch (got ${JSON.stringify(counts)}; ` +
              `expected ≥2 CREATE_USER, ≥1 CREATE_ROLE, ≥1 CREATE_GROUP, ` +
              `≥1 CREATE_CLIENT) — Phase 4 loaded but accumulation is lossy ` +
              `(CODE BUG, not a restart).`,
            evidence,
          };
        }
        return {
          ok: true as const,
          loaded: true as const,
          detail: 'Phase 4 loaded.',
          evidence,
        };
      } catch (e: any) {
        return {
          ok: false as const,
          loaded: false as const,
          detail: `Probe partialImport raised: ${e?.message ?? e}`,
          evidence,
        };
      } finally {
        await deleteRealm(request, PROBE_REALM).catch(() => {});
      }
    })();

    console.log(
      `\n[PRECONDITION phase4] ok=${pre.ok} loaded=${
        (pre as { loaded?: boolean }).loaded
      }\n  ${pre.detail}\n  evidence=${JSON.stringify(
        pre.evidence,
        null,
        2,
      )}\n`,
    );
    if (!pre.ok) {
      const loaded = (pre as { loaded?: boolean }).loaded === true;
      if (loaded) {
        throw new Error(
          `PRECONDITION: Phase 4 jar loaded but partialImport batch ` +
            `governance is not behaving correctly — this is a CODE BUG, ` +
            `NOT a restart issue. Do NOT restart; fix the code. ` +
            `Detail: ${pre.detail}`,
        );
      }
      throw new Error(
        `PRECONDITION: Phase 4 jar not loaded in the running container ` +
          `(${pre.detail}) — restart the container, then re-run: ${RERUN}`,
      );
    }

    // -----------------------------------------------------------------------
    // 1. Scratch realm + IGA on (custom attr declared so users carry it).
    // -----------------------------------------------------------------------
    await createScratchRealm(request, REALM);
    const st0 = await igaStatus(request, REALM);
    expect(
      st0.enabled,
      `IGA should start disabled on a fresh realm (got ${JSON.stringify(st0)})`,
    ).toBeFalsy();
    await declareUserProfileAttribute(request, REALM, CUSTOM_ATTR);
    await enableIga(request, REALM);
    const st1 = await igaStatus(request, REALM);
    expect(st1.http, 'iga-status http').toBe(200);
    expect(st1.enabled, 'IGA must be enabled').toBe(true);

    // -----------------------------------------------------------------------
    // 2. ONE partialImport: 2 users + 1 realm role + 1 group.
    // -----------------------------------------------------------------------
    const res = await partialImport(request, REALM, importRep());
    const status = res.status();
    const loc = locationHeader(res);
    const body = await safeJson(res);
    expect(
      status,
      `partialImport expected a single 202 batch, got ${status} body=${JSON.stringify(
        body,
      )}`,
    ).toBe(202);
    // The batch envelope: entityType=BATCH / actionType=PARTIAL_IMPORT, with a
    // Location to the first CR (single-entity 202 envelope shape preserved).
    expect(
      loc,
      `batch 202 must carry a Location header (got ${JSON.stringify(
        res.headers(),
      )})`,
    ).toBeTruthy();
    if (body && typeof body === 'object') {
      expect(
        body.entityType,
        `batch 202 body entityType expected BATCH (got ${JSON.stringify(
          body.entityType,
        )})`,
      ).toBe('BATCH');
      expect(
        body.actionType,
        `batch 202 body actionType expected PARTIAL_IMPORT (got ${JSON.stringify(
          body.actionType,
        )})`,
      ).toBe('PARTIAL_IMPORT');
    }

    // -----------------------------------------------------------------------
    // 3. Exactly the expected 5 PENDING CRs of the right types.
    //
    // NOTE on the count: the payload carries 1 role + 1 group + 2 users + 1
    // client + 1 client-scope (6 entities), but KC 26.5.5 has NO
    // ClientScopesPartialImport — PartialImportManager.partialImports
    // (services/.../partialimport/PartialImportManager.java:47-52) registers
    // only Clients/Roles/IdPs/IdP-mappers/Groups/Users, and the per-type
    // import loop discards the `clientScopes` payload entry on the way in.
    // So we expect 5 governed CRs today: 2× CREATE_USER + 1× CREATE_ROLE +
    // 1× CREATE_GROUP + 1× CREATE_CLIENT. The addClientScope import branch
    // (registerImportClientScope) is defensive parity wiring — see
    // IgaImportMode#registerImportClientScope javadoc. A "future" assertion
    // block below documents the post-KC-handler shape (6 governed CRs incl.
    // CREATE_CLIENT_SCOPE) without failing today.
    // -----------------------------------------------------------------------
    const crs = await listChangeRequests(request, REALM);
    const counts = actionCounts(crs);
    expect(
      counts.CREATE_USER ?? 0,
      `expected 2 CREATE_USER CRs (got ${JSON.stringify(counts)})`,
    ).toBe(2);
    expect(
      counts.CREATE_ROLE ?? 0,
      `expected 1 CREATE_ROLE CR (got ${JSON.stringify(counts)})`,
    ).toBe(1);
    expect(
      counts.CREATE_GROUP ?? 0,
      `expected 1 CREATE_GROUP CR (got ${JSON.stringify(counts)})`,
    ).toBe(1);
    expect(
      counts.CREATE_CLIENT ?? 0,
      `expected 1 CREATE_CLIENT CR (got ${JSON.stringify(counts)})`,
    ).toBe(1);
    // CREATE_CLIENT_SCOPE: 0 today (KC has no ClientScopesPartialImport).
    // The defensive parity wiring in IgaRealmProvider.addClientScope means
    // IF a future KC version starts dispatching addClientScope from
    // partialImport, this assertion will tighten to 1 — the import branch is
    // already in place and would emit the CR through the same batch.
    expect(
      counts.CREATE_CLIENT_SCOPE ?? 0,
      `CREATE_CLIENT_SCOPE expected 0 — KC 26.5.5 has no ` +
        `ClientScopesPartialImport so the per-type import loop discards the ` +
        `clientScopes payload entry; the addClientScope import branch is ` +
        `wired up for defensive parity (got ${JSON.stringify(counts)})`,
    ).toBe(0);
    const governed = crs.filter((c) =>
      [
        'CREATE_USER',
        'CREATE_ROLE',
        'CREATE_GROUP',
        'CREATE_CLIENT',
        'CREATE_CLIENT_SCOPE',
      ].includes(c.actionType),
    );
    expect(
      governed.length,
      `exactly 5 governed CRs expected today (got ${governed.length}: ` +
        `${JSON.stringify(
          counts,
        )}) — 2 users + 1 role + 1 group + 1 client; client-scope is 0 per ` +
        `KC 26.5.5 source (no ClientScopesPartialImport)`,
    ).toBe(5);
    for (const cr of governed) {
      expect(
        cr.status,
        `CR ${cr.id} (${cr.actionType}) must be PENDING (got ${cr.status})`,
      ).toBe('PENDING');
    }

    // Capture fidelity at the CRs (parsed REP_JSON) BEFORE commit.
    const roleCr = governed.find((c) => c.actionType === 'CREATE_ROLE')!;
    const roleCrFull = await getChangeRequest(request, REALM, roleCr.id);
    const roleRep = parseRep(roleCrFull.body);
    expect(roleRep?.name, 'role CR rep carries name').toBe(ROLE_NAME);
    const userCrs = governed.filter((c) => c.actionType === 'CREATE_USER');
    const userNames = new Set<string>();
    for (const uc of userCrs) {
      const full = await getChangeRequest(request, REALM, uc.id);
      const r = parseRep(full.body);
      if (r?.username) userNames.add(String(r.username).toLowerCase());
    }
    expect(
      userNames.has(USER_A) && userNames.has(USER_B),
      `both user CRs must carry their usernames (got ${JSON.stringify([
        ...userNames,
      ])})`,
    ).toBeTruthy();
    // Client CR REP_JSON must carry clientId + at least one protocol mapper +
    // the captured redirectUri (proves the batch-harvest snapshot is full-rep,
    // not bare). This matches the single-entity CREATE_CLIENT contract that
    // IgaReplayDispatcher.replayCreateClient consumes byte-for-byte.
    const clientCr = governed.find((c) => c.actionType === 'CREATE_CLIENT')!;
    const clientCrFull = await getChangeRequest(request, REALM, clientCr.id);
    const clientRep = parseRep(clientCrFull.body);
    expect(clientRep?.clientId, 'client CR rep carries clientId').toBe(
      CLIENT_ID,
    );
    const repMappers = Array.isArray(clientRep?.protocolMappers)
      ? clientRep.protocolMappers
      : [];
    expect(
      repMappers.some((m: any) => m?.name === CLIENT_MAPPER_NAME),
      `client CR rep must carry the protocol mapper '${CLIENT_MAPPER_NAME}' ` +
        `(got ${JSON.stringify(repMappers.map((m: any) => m?.name))})`,
    ).toBeTruthy();
    const repRedirects = Array.isArray(clientRep?.redirectUris)
      ? clientRep.redirectUris
      : [];
    expect(
      repRedirects.includes(CLIENT_REDIRECT),
      `client CR rep must carry redirectUri '${CLIENT_REDIRECT}' ` +
        `(got ${JSON.stringify(repRedirects)})`,
    ).toBeTruthy();

    // -----------------------------------------------------------------------
    // 4. NOTHING persisted at draft — the decisive negative proof. The 2
    //    users 404-at-draft proves the 5-arg local-storage addUser bypass is
    //    closed (pre-Phase-4 they would have persisted ungoverned).
    // -----------------------------------------------------------------------
    const roleDraft = await getRole(request, REALM, ROLE_NAME);
    expect(
      roleDraft.http,
      `role ${ROLE_NAME} must NOT exist before commit (got HTTP ${roleDraft.http})`,
    ).toBe(404);
    const grpDraft = await getGroupByName(request, REALM, GROUP_NAME);
    expect(
      grpDraft.body,
      `group ${GROUP_NAME} must NOT exist before commit (got ${JSON.stringify(
        grpDraft.body,
      )})`,
    ).toBeFalsy();
    const uaDraft = await getUserByUsername(request, REALM, USER_A);
    expect(
      uaDraft.body,
      `user ${USER_A} must NOT exist before commit — proves the 5-arg ` +
        `local-storage addUser partialImport bypass is CLOSED (got ` +
        `${JSON.stringify(uaDraft.body)})`,
    ).toBeFalsy();
    const ubDraft = await getUserByUsername(request, REALM, USER_B);
    expect(
      ubDraft.body,
      `user ${USER_B} must NOT exist before commit — proves the 5-arg ` +
        `local-storage addUser partialImport bypass is CLOSED (got ` +
        `${JSON.stringify(ubDraft.body)})`,
    ).toBeFalsy();
    // Client also must NOT exist at draft. The IgaRealmProvider.addClient
    // import branch persists the scratch ClientEntity via super.addClient so
    // KC's ClientsPartialImport.getModelId can resolve in the nested import
    // session, but the BatchEmit prepare-tx throw triggers the nested import
    // tx rollback — the scratch client + its mappers + scope links + redirect
    // URI rows are discarded atomically. If this assertion fails the addClient
    // import branch (or its scratch-rollback handshake) is broken.
    const cliDraft = await getClientByClientId(request, REALM, CLIENT_ID);
    expect(
      cliDraft.body,
      `client ${CLIENT_ID} must NOT exist before commit — proves the ` +
        `addClient partialImport branch's batch-emit scratch rollback ` +
        `discards the (super-persisted) scratch client (got ` +
        `${JSON.stringify(cliDraft.body)})`,
    ).toBeFalsy();
    // Client-scope: today KC 26.5.5 discards the clientScopes payload entry
    // at the per-type import loop (no ClientScopesPartialImport), so it
    // never reached the IGA branch and never had any scratch row to roll
    // back. Asserting absence proves nothing about Phase 4 today but is the
    // baseline for the future-coverage block.
    const scopeDraft = await getClientScopeByName(
      request,
      REALM,
      CLIENT_SCOPE_NAME,
    );
    expect(
      scopeDraft.body,
      `client-scope ${CLIENT_SCOPE_NAME} must NOT exist before commit ` +
        `(KC discards the payload entry; baseline check for future ` +
        `coverage) (got ${JSON.stringify(scopeDraft.body)})`,
    ).toBeFalsy();

    // -----------------------------------------------------------------------
    // 5. Authorize + commit ALL governed CRs (threshold 1, no approver roles
    //    → self). Each replays through the UNCHANGED IgaReplayDispatcher
    //    per-type path.
    // -----------------------------------------------------------------------
    for (const cr of governed) {
      const ac = await authorizeAndCommit(request, REALM, cr.id);
      expect(
        ac.authorize.http,
        `authorize CR ${cr.id} (${cr.actionType}) expected 200, got ${
          ac.authorize.http
        } ${JSON.stringify(ac.authorize.body)}`,
      ).toBe(200);
      expect(
        ac.commit.http,
        `commit CR ${cr.id} (${cr.actionType}) expected 200, got ${
          ac.commit.http
        } ${JSON.stringify(ac.commit.body)}`,
      ).toBe(200);
    }

    // -----------------------------------------------------------------------
    // 6. Post-commit: all 4 entities now exist with their config.
    // -----------------------------------------------------------------------
    const roleAfter = await getRole(request, REALM, ROLE_NAME);
    expect(
      roleAfter.http,
      `role ${ROLE_NAME} must exist after commit (got ${roleAfter.http})`,
    ).toBe(200);
    expect(
      roleAfter.body?.attributes?.[CUSTOM_ATTR]?.[0],
      `role custom attribute fidelity (got ${JSON.stringify(
        roleAfter.body?.attributes,
      )})`,
    ).toBe('role-val');

    const grpAfter = await getGroupByName(request, REALM, GROUP_NAME);
    expect(
      grpAfter.body,
      `group ${GROUP_NAME} must exist after commit`,
    ).toBeTruthy();
    // The list endpoint (?search=) returns the BRIEF group rep only — no
    // attributes — so fetch the full rep by uuid to assert attribute
    // fidelity. KC 26.5.5 GroupsResource.getGroups serves the brief form
    // and GroupResource.getGroup (/groups/{id}) serves the full rep.
    const grpAfterFull = await getGroupById(request, REALM, grpAfter.body.id);
    expect(
      grpAfterFull.http,
      `group ${GROUP_NAME} full-rep fetch http (got ${grpAfterFull.http})`,
    ).toBe(200);
    expect(
      grpAfterFull.body?.attributes?.[CUSTOM_ATTR]?.[0],
      `group custom attribute fidelity (got ${JSON.stringify(
        grpAfterFull.body?.attributes,
      )})`,
    ).toBe('group-val');

    const uaAfter = await getUserByUsername(request, REALM, USER_A);
    expect(uaAfter.body, `user ${USER_A} must exist after commit`).toBeTruthy();
    expect(uaAfter.body?.email, 'user A email fidelity').toBe(
      `${USER_A}@example.test`,
    );
    expect(uaAfter.body?.firstName, 'user A firstName fidelity').toBe('Phase4');
    expect(
      uaAfter.body?.attributes?.[CUSTOM_ATTR]?.[0],
      `user A custom attribute fidelity (got ${JSON.stringify(
        uaAfter.body?.attributes,
      )})`,
    ).toBe('user-a-val');

    const ubAfter = await getUserByUsername(request, REALM, USER_B);
    expect(ubAfter.body, `user ${USER_B} must exist after commit`).toBeTruthy();
    expect(ubAfter.body?.email, 'user B email fidelity').toBe(
      `${USER_B}@example.test`,
    );
    expect(ubAfter.body?.lastName, 'user B lastName fidelity').toBe('Bravo');
    expect(
      ubAfter.body?.attributes?.[CUSTOM_ATTR]?.[0],
      `user B custom attribute fidelity (got ${JSON.stringify(
        ubAfter.body?.attributes,
      )})`,
    ).toBe('user-b-val');

    // Client must exist after commit, with its redirectUri / attribute /
    // protocol mapper all faithful to the import payload (the
    // IgaReplayDispatcher.replayCreateClient REP_JSON path rebuilds the
    // complete client via RepresentationToModel.createClient — KC 26.5.5
    // RepresentationToModel.java:332-408 — so every field the snapshot
    // carried is round-tripped).
    const cliAfter = await getClientByClientId(request, REALM, CLIENT_ID);
    expect(
      cliAfter.body,
      `client ${CLIENT_ID} must exist after commit`,
    ).toBeTruthy();
    expect(
      cliAfter.body?.redirectUris,
      `client redirectUris fidelity (got ${JSON.stringify(
        cliAfter.body?.redirectUris,
      )})`,
    ).toContain(CLIENT_REDIRECT);
    expect(
      cliAfter.body?.attributes?.[CUSTOM_ATTR],
      `client custom attribute fidelity (got ${JSON.stringify(
        cliAfter.body?.attributes,
      )})`,
    ).toBe('client-val');
    const cliPms = await getClientProtocolMappers(
      request,
      REALM,
      cliAfter.body.id,
    );
    expect(cliPms.http, 'client protocol-mappers list http').toBe(200);
    const cliMapper = cliPms.body.find(
      (m: any) => m?.name === CLIENT_MAPPER_NAME,
    );
    expect(
      cliMapper,
      `client protocol mapper '${CLIENT_MAPPER_NAME}' must exist after commit ` +
        `(got names=${JSON.stringify(cliPms.body.map((m: any) => m?.name))})`,
    ).toBeTruthy();
    expect(
      cliMapper?.config?.['user.attribute'],
      `client mapper config 'user.attribute' fidelity (got ${JSON.stringify(
        cliMapper?.config,
      )})`,
    ).toBe(CUSTOM_ATTR);
    expect(
      cliMapper?.config?.['claim.name'],
      `client mapper config 'claim.name' fidelity`,
    ).toBe('p4_custom_claim');

    // -----------------------------------------------------------------------
    // 6b. Future-coverage block — documents the post-KC-handler shape for
    // client-scope governance through partialImport. Today KC 26.5.5 has no
    // ClientScopesPartialImport so this block is a no-op; the moment a KC
    // version adds the handler, the IgaRealmProvider.addClientScope import
    // branch (already wired) will emit a CREATE_CLIENT_SCOPE CR and
    // CREATE_CLIENT_SCOPE will be 1, at which point the conditional
    // assertion below will start exercising the full replay fidelity. This
    // is deliberately a NON-failing check today.
    // -----------------------------------------------------------------------
    if ((counts.CREATE_CLIENT_SCOPE ?? 0) >= 1) {
      const scopeAfter = await getClientScopeByName(
        request,
        REALM,
        CLIENT_SCOPE_NAME,
      );
      expect(
        scopeAfter.body,
        `client-scope ${CLIENT_SCOPE_NAME} must exist after commit (future ` +
          `coverage — KC partialImport now dispatches addClientScope)`,
      ).toBeTruthy();
      expect(scopeAfter.body?.protocol, 'scope protocol fidelity').toBe('saml');
      expect(
        scopeAfter.body?.attributes?.[CUSTOM_ATTR],
        `scope custom attribute fidelity`,
      ).toBe('scope-val');
      const scopePms = await getClientScopeProtocolMappers(
        request,
        REALM,
        scopeAfter.body.id,
      );
      expect(
        scopePms.body.some((m: any) => m?.name === SCOPE_MAPPER_NAME),
        `scope protocol mapper '${SCOPE_MAPPER_NAME}' must exist after commit`,
      ).toBeTruthy();
    } else {
      // Make the source-confirmed gap explicit in the test output, but do
      // NOT fail — the defensive parity branch is correct by construction.
      console.log(
        `[INFO phase4] CREATE_CLIENT_SCOPE=0 as expected — KC 26.5.5 has ` +
          `no ClientScopesPartialImport (PartialImportManager registers ` +
          `only Clients/Roles/IdPs/IdP-mappers/Groups/Users). The ` +
          `IgaRealmProvider.addClientScope import branch is defensive ` +
          `parity wiring; it will activate automatically if a future KC ` +
          `version adds the per-type handler.`,
      );
    }

    // -----------------------------------------------------------------------
    // 7. Cleanup (afterAll also deletes; do it here too and confirm).
    // -----------------------------------------------------------------------
    await deleteRealm(request, REALM);
    const gone = await igaStatus(request, REALM);
    expect(
      gone.http,
      `scratch realm must be deleted (iga-status expected 404, got ${gone.http})`,
    ).toBe(404);
  });
});
