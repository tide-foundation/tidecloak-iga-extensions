import { APIRequestContext } from '@playwright/test';
import {
  adminToken,
  createScratchRealm,
  deleteRealm,
  enableIga,
  createRole,
  createClient,
  createClientRole,
  getChangeRequest,
  locationHeader,
  safeJson,
  kcFetch,
} from './kc';

/**
 * Precondition gate.
 *
 * Verifies the RUNNING container is actually serving a working Phase 1 IGA
 * build before any pass/fail scenario runs. The container may not have been
 * restarted since the Phase 1 jar was built/deployed, OR (observed in this
 * environment) the deployed provider jar can be corrupt and fail to load —
 * in which case governed creates fall through to a 500 instead of a 202.
 *
 * Detection (in order), each producing a distinct verdict:
 *   1. Reachability + admin token            -> UNREACHABLE
 *   2. Scratch IGA-enabled realm w/ bases     -> IGA_NOT_ENABLED
 *   3. Governed composite realm-role create:
 *        - HTTP 202 + Location + CR carries
 *          composites in REP_JSON/replay      -> OK (Phase 1 loaded)
 *        - anything else (500, 201, missing
 *          Location, dropped composites)       -> PHASE1_NOT_LOADED
 *
 * On any non-OK verdict the probe realm is cleaned up and a precise message is
 * returned. The caller (spec) must STOP — these are NOT scenario failures.
 */

export type Verdict =
  | 'OK'
  | 'UNREACHABLE'
  | 'IGA_NOT_ENABLED'
  | 'PHASE1_NOT_LOADED';

export interface PreconditionResult {
  verdict: Verdict;
  detail: string;
  evidence: Record<string, unknown>;
}

const PROBE_REALM = 'iga-precond-probe';

export async function checkPrecondition(
  request: APIRequestContext,
): Promise<PreconditionResult> {
  const evidence: Record<string, unknown> = {};

  // 1. Reachability + admin token.
  try {
    const tok = await adminToken(request);
    evidence.adminToken = tok ? 'OK' : 'EMPTY';
    if (!tok) {
      return {
        verdict: 'UNREACHABLE',
        detail: 'Admin token endpoint returned no access_token.',
        evidence,
      };
    }
  } catch (e: any) {
    return {
      verdict: 'UNREACHABLE',
      detail: `Could not reach Keycloak / obtain admin token: ${e?.message ?? e}`,
      evidence,
    };
  }

  // 2. Scratch realm + composite bases (IGA OFF) + enable IGA.
  try {
    await createScratchRealm(request, PROBE_REALM);
    evidence.scratchRealm = 'created';

    const rb = await createRole(request, PROBE_REALM, { name: 'r-base' });
    evidence.rBaseCreate = rb.status();
    const acmeUuid = await createClient(request, PROBE_REALM, 'acme');
    const cb = await createClientRole(request, PROBE_REALM, acmeUuid, {
      name: 'c-base',
    });
    evidence.cBaseCreate = cb.status();

    await enableIga(request, PROBE_REALM);
    evidence.igaEnabled = true;
  } catch (e: any) {
    await deleteRealm(request, PROBE_REALM).catch(() => {});
    return {
      verdict: 'IGA_NOT_ENABLED',
      detail:
        `Could not stand up an IGA-enabled probe realm (base setup / toggle ` +
        `failed): ${e?.message ?? e}`,
      evidence,
    };
  }

  // 3. Governed composite realm-role create — the decisive probe.
  try {
    const res = await createRole(request, PROBE_REALM, {
      name: 'probe-parent',
      description: 'precond probe',
      attributes: { team: ['blue'] },
      composite: true,
      composites: { realm: ['r-base'], client: { acme: ['c-base'] } },
    });
    const status = res.status();
    const loc = locationHeader(res);
    const body = await safeJson(res);
    evidence.governedCreateStatus = status;
    evidence.governedCreateLocation = loc ?? null;
    evidence.governedCreateBody = body;

    if (status !== 202) {
      // 500 => provider jar not loaded / broken; 201 => IGA capture inactive
      // (bare create slipped through). Either way Phase 1 is NOT serving.
      const hint =
        status === 500
          ? 'governed create returned 500 (provider jar likely not loaded — check server log for a ZipException/ClassNotFound on org.tidecloak.iga.*)'
          : status === 201
            ? 'governed create returned 201 (role persisted immediately — IGA capture is NOT intercepting; Phase 1 capture path not active)'
            : `governed create returned ${status} (expected 202 Accepted)`;
      await deleteRealm(request, PROBE_REALM).catch(() => {});
      return {
        verdict: 'PHASE1_NOT_LOADED',
        detail: `Phase 1 governed-create did not 202: ${hint}.`,
        evidence,
      };
    }

    if (!loc) {
      await deleteRealm(request, PROBE_REALM).catch(() => {});
      return {
        verdict: 'PHASE1_NOT_LOADED',
        detail:
          'governed create returned 202 but no Location header — Phase 1 ' +
          '(Location on 202) not loaded.',
        evidence,
      };
    }

    // Pull the CR and confirm composites survived into the captured rep.
    const crId =
      (body && (body.changeRequestId as string)) ||
      loc.split('/').pop() ||
      '';
    const cr = await getChangeRequest(request, PROBE_REALM, crId);
    evidence.probeCrHttp = cr.http;
    evidence.probeCrActionType = cr.body?.actionType;
    evidence.probeCrStatus = cr.body?.status;

    const rowsJson = JSON.stringify(cr.body?.rows ?? cr.body ?? {});
    const hasComposites =
      rowsJson.includes('"composites"') ||
      rowsJson.includes('r-base') ||
      rowsJson.includes('c-base');
    evidence.probeCrComposites = hasComposites;

    if (cr.http !== 200 || cr.body?.actionType !== 'CREATE_ROLE') {
      await deleteRealm(request, PROBE_REALM).catch(() => {});
      return {
        verdict: 'PHASE1_NOT_LOADED',
        detail:
          `202 returned but CR not retrievable as a CREATE_ROLE ` +
          `(GET CR http=${cr.http}, actionType=${cr.body?.actionType}).`,
        evidence,
      };
    }

    if (!hasComposites) {
      await deleteRealm(request, PROBE_REALM).catch(() => {});
      return {
        verdict: 'PHASE1_NOT_LOADED',
        detail:
          'CREATE_ROLE CR captured but composites/REP_JSON dropped — this is ' +
          'the pre-Phase-1 behaviour; Phase 1 full-rep capture not loaded.',
        evidence,
      };
    }
  } catch (e: any) {
    await deleteRealm(request, PROBE_REALM).catch(() => {});
    return {
      verdict: 'PHASE1_NOT_LOADED',
      detail: `Probe governed-create raised: ${e?.message ?? e}`,
      evidence,
    };
  }

  await deleteRealm(request, PROBE_REALM).catch(() => {});
  return {
    verdict: 'OK',
    detail:
      'Phase 1 loaded: governed composite create -> 202 + Location, CR is a ' +
      'PENDING CREATE_ROLE carrying composites.',
    evidence,
  };
}

/** Build the exact re-run command to print on a precondition fail. */
export function rerunCommand(): string {
  return 'cd /home/sasha/project/tidecloak-iga-extensions/e2e && npx playwright test';
}
