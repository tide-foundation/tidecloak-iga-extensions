import { test, expect } from '@playwright/test';
import {
  createScratchRealm,
  deleteRealm,
  enableIga,
  igaStatus,
  createRole,
  createGroup,
  getGroupByName,
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
 * credentials, group memberships, realm-role mappings, required actions and
 * federated identities are NOT serialized by ModelToRepresentation and there
 * is no single unconditional terminal model call).
 *
 * Pure API E2E (no browser). It drives the exact production path: the IGA
 * capture is enforced at the model layer (IgaUserAdapter#getId terminal seam
 * during UsersResource.createUser, plus the credential-manager wrapper and
 * IgaUserProvider.addFederatedIdentity), so raw Admin REST exercises the same
 * seam any caller hits.
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
 *    to restart) from "jar genuinely not loaded" (restart then re-run).
 */

const REALM = 'iga-phase3-e2e';
const PROBE_REALM = 'iga-phase3-precond-probe';
const RERUN =
  'cd /home/sasha/project/tidecloak-iga-extensions/e2e && npx playwright test';

const PW = 'Phase3-Pw-Str0ng!';

const userSpec = (): UserSpec => ({
  username: 'p3-user',
  enabled: true,
  email: 'p3-user@example.test',
  emailVerified: true,
  firstName: 'Phase',
  lastName: 'Three',
  attributes: { p3CustomAttr: ['p3-attr-value'] },
  requiredActions: ['VERIFY_EMAIL'],
  groups: ['/g1'],
  realmRoles: ['role1'],
  credentials: [{ type: 'password', value: PW, temporary: false }],
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

test.describe('IGA Phase 3: user governed create/replay', () => {
  test.afterAll(async ({ request }) => {
    await deleteRealm(request, REALM).catch(() => {});
    await deleteRealm(request, PROBE_REALM).catch(() => {});
  });

  test('Phase 3 governed user create → CR → authorize+commit → full fidelity + password works', async ({
    request,
  }) => {
    // -----------------------------------------------------------------------
    // PRECONDITION GATE — a governed user create must 202 + carry the full rep
    // (credentials + groups + realmRoles + requiredActions) in the CR.
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
          requiredActions: ['VERIFY_EMAIL'],
          groups: ['/pg1'],
          realmRoles: ['prole1'],
          credentials: [
            { type: 'password', value: 'Probe-Pw-1!', temporary: false },
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
        const creds: any[] = Array.isArray(rep?.credentials)
          ? rep.credentials
          : [];
        const carriesUsername =
          (rep?.username || '').toLowerCase() === 'probe-user';
        const carriesEmail = rep?.email === 'probe-user@example.test';
        const carriesAttr =
          Array.isArray(rep?.attributes?.probeAttr) &&
          rep.attributes.probeAttr.includes('probe-val');
        const carriesReqAction =
          Array.isArray(rep?.requiredActions) &&
          rep.requiredActions.includes('VERIFY_EMAIL');
        const carriesGroup =
          Array.isArray(rep?.groups) && rep.groups.includes('/pg1');
        const carriesRealmRole =
          Array.isArray(rep?.realmRoles) && rep.realmRoles.includes('prole1');
        const carriesCred =
          creds.length >= 1 &&
          creds.some(
            (c: any) =>
              c?.type === 'password' &&
              (c?.value === 'Probe-Pw-1!' ||
                !!c?.secretData ||
                !!c?.credentialData),
          );
        const carriesFullRep =
          carriesUsername &&
          carriesEmail &&
          carriesAttr &&
          carriesReqAction &&
          carriesGroup &&
          carriesRealmRole &&
          carriesCred;
        const captured = {
          username: carriesUsername,
          email: carriesEmail,
          attributes: carriesAttr,
          requiredActions: carriesReqAction,
          groups: carriesGroup,
          realmRoles: carriesRealmRole,
          credentials: carriesCred,
        };
        evidence.probeCaptured = captured;
        if (!carriesFullRep) {
          // 202 + Location + CR exists + actionType === CREATE_USER ⇒ the
          // Phase 3 jar IS loaded and capture IS intercepting — an empty/lossy
          // rep is a CODE BUG in IgaUserAdapter, NOT a restart situation.
          return {
            ok: false as const,
            loaded: true as const,
            detail:
              'Phase 3 loaded but user capture is producing an EMPTY/lossy ' +
              'rep — this is a CODE BUG in IgaUserAdapter capture, NOT a ' +
              'restart issue (the governed create DID 202 with a CREATE_USER ' +
              `CR). captured=${JSON.stringify(captured)} ` +
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
          `PRECONDITION: Phase 3 loaded but user capture is producing an ` +
            `EMPTY rep — this is a code bug in IgaUserAdapter, NOT a restart ` +
            `issue. Do NOT restart; fix the capture. Detail: ${pre.detail}`,
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
    // 3. Governed user create: email, names, custom attribute, a required
    //    action, membership of g1, realm role role1, AND a password.
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
    // truth) BEFORE commit: credentials>=1 etc.
    const rep = parseCapturedUserRep(cr.body);
    const creds: any[] = Array.isArray(rep?.credentials)
      ? rep.credentials
      : [];
    expect(
      creds.length,
      `captured REP_JSON must carry >=1 credential (got ${JSON.stringify(
        rep?.credentials,
      )})`,
    ).toBeGreaterThanOrEqual(1);
    expect(
      creds.some(
        (c: any) =>
          c?.type === 'password' &&
          (c?.value === PW || !!c?.secretData || !!c?.credentialData),
      ),
      `captured password credential must carry the value or hashed data ` +
        `(got ${JSON.stringify(creds)})`,
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
        rep.requiredActions.includes('VERIFY_EMAIL'),
      `captured rep must carry requiredAction VERIFY_EMAIL (got ${JSON.stringify(
        rep?.requiredActions,
      )})`,
    ).toBeTruthy();

    // Not persisted at draft: user must 404 (absent) before commit.
    const draft = await getUserByUsername(request, REALM, spec.username);
    expect(
      draft.body,
      `user ${spec.username} must NOT exist before commit (got ${JSON.stringify(
        draft.body,
      )})`,
    ).toBeFalsy();
    // And the password must NOT work before commit.
    const preTok = await directGrantToken(
      request,
      REALM,
      spec.username,
      PW,
    );
    expect(
      preTok.http,
      `direct-grant before commit must fail (got ${preTok.http})`,
    ).not.toBe(200);

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
    // 5. Post-commit fidelity: the user exists with email/names/attribute/
    //    required-action, is in g1, has role1, AND the password actually
    //    works (decisive credential proof via a direct-grant token request).
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
        found.body.requiredActions.includes('VERIFY_EMAIL'),
      `user requiredAction fidelity (got ${JSON.stringify(
        found.body.requiredActions,
      )})`,
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

    // The decisive credential proof: a direct-grant token request for
    // username+password against the realm succeeds → the password credential
    // was captured & replayed faithfully (the password actually works).
    const tok = await directGrantToken(request, REALM, spec.username, PW);
    expect(
      tok.http,
      `direct-grant token for ${spec.username} must succeed post-commit ` +
        `(got HTTP ${tok.http} ${JSON.stringify(tok.body)}) — this is the ` +
        `decisive proof the password credential round-tripped`,
    ).toBe(200);
    expect(
      tok.body?.access_token,
      'direct-grant must return an access_token',
    ).toBeTruthy();

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
