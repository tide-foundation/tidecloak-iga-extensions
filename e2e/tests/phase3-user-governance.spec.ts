import { test, expect } from '@playwright/test';
import {
  createScratchRealm,
  deleteRealm,
  enableIga,
  igaStatus,
  createRole,
  createGroup,
  createUser,
  getUserByUsername,
  getUserGroups,
  getUserRealmRoleMappings,
  directGrantToken,
  getChangeRequest,
  authorizeAndCommit,
  locationHeader,
  safeJson,
  UserSpec,
} from '../lib/kc';

/**
 * Phase 3 — model-layer full capture for user creates (the hardest type:
 * group memberships, realm-role mappings, required actions and federated
 * identities are NOT serialized by ModelToRepresentation and there is no
 * single unconditional terminal model call).
 *
 * Credentials are NOT governed (product decision): a user's password is never
 * captured, deferred or replayed. The created user sets their own password
 * themselves (an `UPDATE_PASSWORD` required action / set-password email /
 * self-service) AFTER the governed create is approved. So the governed-create
 * payload deliberately sends NO password, the captured CR must NOT carry a
 * `credentials` field, and post-commit the user must have NO usable password.
 *
 * Pure API E2E (no browser). It drives the exact production path: the IGA
 * capture is enforced at the model layer (IgaUserAdapter#getId terminal seam
 * during UsersResource.createUser, plus IgaUserProvider.addFederatedIdentity),
 * so raw Admin REST exercises the same seam any caller hits.
 *
 * Order of operations follows the documented "configure bases BEFORE enabling
 * IGA" rule: the group `g1` and realm role `role1` the governed user will join
 * / be granted are created with IGA OFF, then IGA is enabled.
 *
 * Precondition gate (improved distinction, Phase 2 lesson):
 *  - parse the captured REP_JSON (the JSON string replay consumes) and assert
 *    against the *parsed* rep — never a substring search on a stringified CR
 *    (double-escaping yields false negatives);
 *  - distinguish "jar loaded but capture is a CODE BUG" (do NOT tell the user
 *    to restart) from "jar genuinely not loaded" (restart then re-run);
 *  - assert the captured rep carries identity/attribute/required-action/group/
 *    realm-role AND that `credentials` is absent or empty.
 */

const REALM = 'iga-phase3-e2e';
const PROBE_REALM = 'iga-phase3-precond-probe';
const RERUN =
  'cd /home/sasha/project/tidecloak-iga-extensions/e2e && npx playwright test';

// Any password value; it MUST NOT yield a token (the password is not governed,
// so the user never gets one through the governed-create path).
const ANY_PW = 'Phase3-Any-Pw!';

const userSpec = (): UserSpec => ({
  username: 'p3-user',
  enabled: true,
  email: 'p3-user@example.test',
  emailVerified: true,
  firstName: 'Phase',
  lastName: 'Three',
  attributes: { p3CustomAttr: ['p3-attr-value'] },
  // UPDATE_PASSWORD is a REQUIRED ACTION (the real model: the approved user
  // must set their own password) — NOT a credential. No `credentials` sent.
  requiredActions: ['UPDATE_PASSWORD'],
  groups: ['/g1'],
  realmRoles: ['role1'],
});

/**
 * Parse the captured user representation out of a change-request body. The CR
 * carries rows; each row's `REP_JSON` is itself a JSON *string* (the serialized
 * UserRepresentation replay consumes). Parse that string and read the parsed
 * object — NOT a substring search on a stringified CR.
 */
function parseCapturedUserRep(crBody: any): any | undefined {
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
        /* try next row */
      }
    } else if (repJson && typeof repJson === 'object') {
      return repJson;
    }
  }
  return undefined;
}

/** True iff the parsed rep carries no usable `credentials` (absent or empty). */
function credentialsAbsent(rep: any): boolean {
  const c = rep?.credentials;
  return c == null || (Array.isArray(c) && c.length === 0);
}

test.describe('IGA Phase 3: user governed create/replay', () => {
  test.afterAll(async ({ request }) => {
    await deleteRealm(request, REALM).catch(() => {});
    await deleteRealm(request, PROBE_REALM).catch(() => {});
  });

  test('Phase 3 governed user create → CR → authorize+commit → full identity/roles/groups/required-actions fidelity, NO credentials, password not set', async ({
    request,
  }) => {
    // -----------------------------------------------------------------------
    // PRECONDITION GATE — a governed user create must 202 + carry the full
    // identity rep (groups + realmRoles + requiredActions, NO credentials) in
    // the CR.
    // -----------------------------------------------------------------------
    const pre = await (async () => {
      const evidence: Record<string, unknown> = {};
      try {
        await createScratchRealm(request, PROBE_REALM);
        // Bases BEFORE enabling IGA (probe its own realm).
        const gp = await createGroup(request, PROBE_REALM, 'pg1');
        evidence.probeGroupCreate = gp.status();
        const rp = await createRole(request, PROBE_REALM, { name: 'prole1' });
        evidence.probeRoleCreate = rp.status();
        await enableIga(request, PROBE_REALM);
        evidence.igaEnabled = true;

        const res = await createUser(request, PROBE_REALM, {
          username: 'probe-user',
          enabled: true,
          email: 'probe-user@example.test',
          emailVerified: true,
          firstName: 'Probe',
          lastName: 'User',
          attributes: { probeAttr: ['probe-val'] },
          requiredActions: ['UPDATE_PASSWORD'],
          groups: ['/pg1'],
          realmRoles: ['prole1'],
          // Deliberately NO credentials — passwords are not governed.
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
              ? 'governed user create returned 500 (provider jar likely not loaded — check server log for a ZipException/ClassNotFound on org.tidecloak.iga.*)'
              : status === 201
                ? 'governed user create returned 201 (user persisted immediately — IGA capture is NOT intercepting; Phase 3 capture path not active)'
                : `governed user create returned ${status} (expected 202 Accepted)`;
          return {
            ok: false as const,
            loaded: false as const,
            detail: hint,
            evidence,
          };
        }
        if (!loc) {
          return {
            ok: false as const,
            loaded: false as const,
            detail:
              'governed user create returned 202 but no Location header — Phase 0/3 (Location on 202) not loaded.',
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
        if (cr.http !== 200 || cr.body?.actionType !== 'CREATE_USER') {
          return {
            ok: false as const,
            loaded: false as const,
            detail:
              `202 returned but CR not retrievable as a CREATE_USER ` +
              `(GET CR http=${cr.http}, actionType=${cr.body?.actionType}).`,
            evidence,
          };
        }
        const rep = parseCapturedUserRep(cr.body);
        const rowsJson = JSON.stringify(cr.body?.rows ?? cr.body ?? {});
        const carriesUsername =
          (rep?.username || '').toLowerCase() === 'probe-user';
        const carriesEmail = rep?.email === 'probe-user@example.test';
        const carriesAttr =
          Array.isArray(rep?.attributes?.probeAttr) &&
          rep.attributes.probeAttr.includes('probe-val');
        const carriesReqAction =
          Array.isArray(rep?.requiredActions) &&
          rep.requiredActions.includes('UPDATE_PASSWORD');
        const carriesGroup =
          Array.isArray(rep?.groups) && rep.groups.includes('/pg1');
        const carriesRealmRole =
          Array.isArray(rep?.realmRoles) && rep.realmRoles.includes('prole1');
        const noCreds = credentialsAbsent(rep);
        const carriesFullRep =
          carriesUsername &&
          carriesEmail &&
          carriesAttr &&
          carriesReqAction &&
          carriesGroup &&
          carriesRealmRole &&
          noCreds;
        const captured = {
          username: carriesUsername,
          email: carriesEmail,
          attributes: carriesAttr,
          requiredActions: carriesReqAction,
          groups: carriesGroup,
          realmRoles: carriesRealmRole,
          credentialsAbsent: noCreds,
        };
        evidence.probeCaptured = captured;
        if (!carriesFullRep) {
          // 202 + Location + CR exists + actionType === CREATE_USER ⇒ the
          // Phase 3 jar IS loaded and capture IS intercepting — a lossy rep
          // (or a rep that still carries credentials) is a CODE BUG in
          // IgaUserAdapter, NOT a restart situation.
          return {
            ok: false as const,
            loaded: true as const,
            detail:
              'Phase 3 loaded but user capture is producing a lossy rep, or ' +
              'is still carrying `credentials` (passwords must NOT be ' +
              'governed) — this is a CODE BUG in IgaUserAdapter capture, NOT ' +
              'a restart issue (the governed create DID 202 with a ' +
              `CREATE_USER CR). captured=${JSON.stringify(captured)} ` +
              `rep=${rowsJson.slice(0, 700)}`,
            evidence,
          };
        }
        return {
          ok: true as const,
          loaded: true as const,
          detail: 'Phase 3 loaded.',
          evidence,
        };
      } catch (e: any) {
        return {
          ok: false as const,
          loaded: false as const,
          detail: `Probe governed user create raised: ${e?.message ?? e}`,
          evidence,
        };
      } finally {
        await deleteRealm(request, PROBE_REALM).catch(() => {});
      }
    })();

    console.log(
      `\n[PRECONDITION phase3] ok=${pre.ok} loaded=${
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
          `PRECONDITION: Phase 3 loaded but user capture is producing a ` +
            `lossy rep or still carrying credentials — this is a code bug in ` +
            `IgaUserAdapter, NOT a restart issue. Do NOT restart; fix the ` +
            `capture. Detail: ${pre.detail}`,
        );
      }
      throw new Error(
        `PRECONDITION: Phase 3 jar not loaded in the running container ` +
          `(${pre.detail}) — restart the container, then re-run: ${RERUN}`,
      );
    }

    // -----------------------------------------------------------------------
    // 1. Scratch realm + bases (IGA OFF): group g1 + realm role role1.
    // -----------------------------------------------------------------------
    await createScratchRealm(request, REALM);

    const st0 = await igaStatus(request, REALM);
    expect(
      st0.enabled,
      `IGA should start disabled on a fresh realm (got ${JSON.stringify(st0)})`,
    ).toBeFalsy();

    const gRes = await createGroup(request, REALM, 'g1');
    expect(
      gRes.status(),
      `base group g1 create expected 201, got ${gRes.status()}`,
    ).toBe(201);
    const rRes = await createRole(request, REALM, { name: 'role1' });
    expect(
      rRes.status(),
      `base role role1 create expected 201, got ${rRes.status()}`,
    ).toBe(201);

    // -----------------------------------------------------------------------
    // 2. Enable IGA + sanity-confirm active.
    // -----------------------------------------------------------------------
    await enableIga(request, REALM);
    const st1 = await igaStatus(request, REALM);
    expect(st1.http, 'iga-status http').toBe(200);
    expect(st1.enabled, 'IGA must be enabled').toBe(true);

    // -----------------------------------------------------------------------
    // 3. Governed user create: email, names, custom attribute, the
    //    UPDATE_PASSWORD required action, membership of g1, realm role role1.
    //    NO password is sent (passwords are not governed).
    // -----------------------------------------------------------------------
    const spec = userSpec();
    const create = await createUser(request, REALM, spec);
    const status = create.status();
    const loc = locationHeader(create);
    const body = await safeJson(create);
    expect(
      status,
      `user governed create expected 202, got ${status} body=${JSON.stringify(body)}`,
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
      `CR actionType expected CREATE_USER, got ${cr.body?.actionType}`,
    ).toBe('CREATE_USER');
    expect(
      cr.body?.status,
      `CR status expected PENDING, got ${cr.body?.status}`,
    ).toBe('PENDING');

    // Capture fidelity at the CR (parsed REP_JSON — the replay source of
    // truth) BEFORE commit: identity/attribute/required-action/group/role
    // present AND `credentials` absent/empty.
    const rep = parseCapturedUserRep(cr.body);
    expect(
      (rep?.username || '').toLowerCase(),
      `captured rep must carry username p3-user (got ${JSON.stringify(
        rep?.username,
      )})`,
    ).toBe('p3-user');
    expect(rep?.email, 'captured rep must carry email').toBe(
      'p3-user@example.test',
    );
    expect(rep?.firstName, 'captured rep must carry firstName').toBe('Phase');
    expect(rep?.lastName, 'captured rep must carry lastName').toBe('Three');
    expect(
      Array.isArray(rep?.attributes?.p3CustomAttr) &&
        rep.attributes.p3CustomAttr.includes('p3-attr-value'),
      `captured rep must carry custom attribute (got ${JSON.stringify(
        rep?.attributes,
      )})`,
    ).toBeTruthy();
    expect(
      Array.isArray(rep?.groups) && rep.groups.includes('/g1'),
      `captured rep must carry group path /g1 (got ${JSON.stringify(rep?.groups)})`,
    ).toBeTruthy();
    expect(
      Array.isArray(rep?.realmRoles) && rep.realmRoles.includes('role1'),
      `captured rep must carry realmRole role1 (got ${JSON.stringify(
        rep?.realmRoles,
      )})`,
    ).toBeTruthy();
    expect(
      Array.isArray(rep?.requiredActions) &&
        rep.requiredActions.includes('UPDATE_PASSWORD'),
      `captured rep must carry requiredAction UPDATE_PASSWORD (got ${JSON.stringify(
        rep?.requiredActions,
      )})`,
    ).toBeTruthy();
    // Credentials must NOT ride along: the password is not governed.
    expect(
      credentialsAbsent(rep),
      `captured REP_JSON must NOT carry a credentials field (passwords are ` +
        `not governed) — got ${JSON.stringify(rep?.credentials)}`,
    ).toBeTruthy();

    // Not persisted at draft: user must 404 (absent) before commit.
    const draft = await getUserByUsername(request, REALM, spec.username);
    expect(
      draft.body,
      `user ${spec.username} must NOT exist before commit (got ${JSON.stringify(
        draft.body,
      )})`,
    ).toBeFalsy();

    // -----------------------------------------------------------------------
    // 4. Authorize + commit (threshold 1, no approver roles → self).
    // -----------------------------------------------------------------------
    const ac = await authorizeAndCommit(request, REALM, crId);
    expect(
      ac.authorize.http,
      `CR authorize expected 200, got ${ac.authorize.http} ${JSON.stringify(
        ac.authorize.body,
      )}`,
    ).toBe(200);
    expect(
      ac.commit.http,
      `CR commit expected 200, got ${ac.commit.http} ${JSON.stringify(
        ac.commit.body,
      )}`,
    ).toBe(200);

    // -----------------------------------------------------------------------
    // 5. Post-commit fidelity: the user exists with email/names/attribute,
    //    has the UPDATE_PASSWORD required action, is in g1, has role1 — and
    //    has NO usable password (passwords are not governed).
    // -----------------------------------------------------------------------
    const found = await getUserByUsername(request, REALM, spec.username);
    expect(found.body, `user ${spec.username} must exist after commit`).toBeTruthy();
    const userId = found.body.id as string;
    expect(userId, 'committed user must have a UUID').toBeTruthy();
    expect(found.body.email, 'user email fidelity').toBe(
      'p3-user@example.test',
    );
    expect(found.body.firstName, 'user firstName fidelity').toBe('Phase');
    expect(found.body.lastName, 'user lastName fidelity').toBe('Three');
    expect(found.body.emailVerified, 'user emailVerified fidelity').toBe(true);
    expect(
      found.body.attributes?.p3CustomAttr?.[0],
      `user custom attribute fidelity (got ${JSON.stringify(
        found.body.attributes,
      )})`,
    ).toBe('p3-attr-value');
    expect(
      Array.isArray(found.body.requiredActions) &&
        found.body.requiredActions.includes('UPDATE_PASSWORD'),
      `user UPDATE_PASSWORD required-action fidelity (got ${JSON.stringify(
        found.body.requiredActions,
      )}) — the approved user must be told to set their own password`,
    ).toBeTruthy();

    const grp = await getUserGroups(request, REALM, userId);
    expect(grp.http, 'user groups http').toBe(200);
    expect(
      grp.body.some((g: any) => g?.name === 'g1'),
      `user must be a member of g1 after commit (got ${JSON.stringify(
        grp.body.map((g: any) => g?.name),
      )})`,
    ).toBeTruthy();

    const rm = await getUserRealmRoleMappings(request, REALM, userId);
    expect(rm.http, 'user realm role-mappings http').toBe(200);
    expect(
      rm.body.some((r: any) => r?.name === 'role1'),
      `user must have realm role role1 after commit (got ${JSON.stringify(
        rm.body.map((r: any) => r?.name),
      )})`,
    ).toBeTruthy();

    // The decisive negative proof: the password was NOT governed, captured or
    // replayed, so a direct-grant token request for username + ANY password
    // MUST NOT succeed (the user has no usable password until they set one
    // themselves via UPDATE_PASSWORD). Expect a non-200 (typically 401).
    const tok = await directGrantToken(request, REALM, spec.username, ANY_PW);
    expect(
      tok.http,
      `direct-grant token for ${spec.username} must NOT succeed post-commit ` +
        `(got HTTP ${tok.http} ${JSON.stringify(tok.body)}) — proves the ` +
        `password was correctly NOT set/replayed (credentials not governed)`,
    ).not.toBe(200);
    expect(
      tok.body?.access_token,
      'direct-grant must NOT return an access_token (no usable password)',
    ).toBeFalsy();

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
