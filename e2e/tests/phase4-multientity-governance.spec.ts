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
  getUserByUsername,
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
 * 1 realm role + 1 group →
 *   - single 202 (batch),
 *   - 4 PENDING CRs of the right types (2× CREATE_USER, 1× CREATE_ROLE,
 *     1× CREATE_GROUP),
 *   - NONE of the 4 entities exist at draft (GET each → absent, INCLUDING
 *     the 2 users — proving the 5-arg local-storage addUser bypass is
 *     closed),
 *   - authorize+commit all CRs → all 4 entities exist with config.
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
const CUSTOM_ATTR = 'p4CustomAttr';

/** The PartialImportRepresentation: 2 users + 1 realm role + 1 group. */
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

  test('partialImport (2 users + 1 role + 1 group) → ONE 202 batch, 4 pending CRs, NOTHING at draft (incl. users — 5-arg bypass closed), all created on commit', async ({
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

        // Did anything persist immediately? (the decisive bypass check)
        const roleNow = await getRole(request, PROBE_REALM, ROLE_NAME);
        const grpNow = await getGroupByName(request, PROBE_REALM, GROUP_NAME);
        const uaNow = await getUserByUsername(request, PROBE_REALM, USER_A);
        const ubNow = await getUserByUsername(request, PROBE_REALM, USER_B);
        const persisted = {
          role: roleNow.http === 200,
          group: !!grpNow.body,
          userA: !!uaNow.body,
          userB: !!ubNow.body,
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
          (counts.CREATE_GROUP ?? 0) >= 1;
        if (!batchOk) {
          return {
            ok: false as const,
            loaded: true as const,
            detail:
              `partialImport 202 + nothing at draft, but the pending CRs ` +
              `are not the expected batch (got ${JSON.stringify(counts)}; ` +
              `expected ≥2 CREATE_USER, ≥1 CREATE_ROLE, ≥1 CREATE_GROUP) — ` +
              `Phase 4 loaded but accumulation is lossy (CODE BUG, not a ` +
              `restart).`,
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
    // 3. Exactly the expected 4 PENDING CRs of the right types.
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
    const governed = crs.filter((c) =>
      ['CREATE_USER', 'CREATE_ROLE', 'CREATE_GROUP'].includes(c.actionType),
    );
    expect(
      governed.length,
      `exactly 4 governed CRs expected (got ${governed.length}: ${JSON.stringify(
        counts,
      )})`,
    ).toBe(4);
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
    expect(
      grpAfter.body?.attributes?.[CUSTOM_ATTR]?.[0],
      `group custom attribute fidelity (got ${JSON.stringify(
        grpAfter.body?.attributes,
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
