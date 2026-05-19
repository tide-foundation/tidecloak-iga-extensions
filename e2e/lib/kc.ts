import { APIRequestContext, APIResponse, expect } from '@playwright/test';
import { kcEnv } from './env';

/**
 * Reusable Keycloak / IGA admin-REST helpers.
 *
 * Every helper here is generic and intended to be shared by Phase 1..N specs.
 * Nothing here is Phase-1-specific. All calls go through Playwright's
 * APIRequestContext so the harness is a pure API test (no browser).
 */

let tokenCache: { value: string; exp: number } | undefined;

/** Master-realm admin token via the admin-cli password grant. Cached ~50s. */
export async function adminToken(request: APIRequestContext): Promise<string> {
  const now = Date.now();
  if (tokenCache && tokenCache.exp > now + 5_000) return tokenCache.value;

  const { baseUrl, adminUser, adminPassword } = kcEnv();
  const res = await request.post(
    `${baseUrl}/realms/master/protocol/openid-connect/token`,
    {
      form: {
        grant_type: 'password',
        client_id: 'admin-cli',
        username: adminUser,
        password: adminPassword,
      },
    },
  );
  if (!res.ok()) {
    throw new Error(
      `Failed to obtain admin token: HTTP ${res.status()} ${res.statusText()}`,
    );
  }
  const body = (await res.json()) as {
    access_token: string;
    expires_in: number;
  };
  tokenCache = {
    value: body.access_token,
    exp: now + (body.expires_in ?? 60) * 1000,
  };
  return tokenCache.value;
}

export interface KcFetchOpts {
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
  /** JSON body (object) — serialized and sent as application/json. */
  json?: unknown;
  /** Form body for token-style endpoints. */
  form?: Record<string, string>;
  /** Extra headers. */
  headers?: Record<string, string>;
}

/**
 * Authenticated admin-REST call. `path` is relative to baseUrl (it should
 * start with `/`). Returns the raw APIResponse so callers can assert on
 * status AND headers (e.g. Location on a 202).
 */
export async function kcFetch(
  request: APIRequestContext,
  path: string,
  opts: KcFetchOpts = {},
): Promise<APIResponse> {
  const { baseUrl } = kcEnv();
  const token = await adminToken(request);
  const method = opts.method || 'GET';
  const url = `${baseUrl}${path}`;
  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`,
    ...(opts.headers || {}),
  };
  const init: Parameters<APIRequestContext['fetch']>[1] = { method, headers };
  if (opts.json !== undefined) {
    init.data = JSON.stringify(opts.json);
    headers['Content-Type'] = 'application/json';
  } else if (opts.form !== undefined) {
    init.form = opts.form;
  }
  return request.fetch(url, init);
}

/** Best-effort JSON parse (some endpoints return empty/no body). */
export async function safeJson(res: APIResponse): Promise<any> {
  const text = await res.text();
  if (!text) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

// ---------------------------------------------------------------------------
// Realm lifecycle
// ---------------------------------------------------------------------------

/** Delete a realm if it exists (idempotent). */
export async function deleteRealm(
  request: APIRequestContext,
  realm: string,
): Promise<void> {
  const res = await kcFetch(request, `/admin/realms/${realm}`, {
    method: 'DELETE',
  });
  // 204 deleted, 404 already gone — both acceptable.
  if (res.status() !== 204 && res.status() !== 404) {
    throw new Error(
      `deleteRealm(${realm}) unexpected HTTP ${res.status()}: ${await res.text()}`,
    );
  }
}

/** Delete-if-exists then create a fresh realm. Re-runnable. */
export async function createScratchRealm(
  request: APIRequestContext,
  realm: string,
): Promise<void> {
  await deleteRealm(request, realm);
  const res = await kcFetch(request, `/admin/realms`, {
    method: 'POST',
    json: { realm, enabled: true },
  });
  if (res.status() !== 201) {
    throw new Error(
      `createScratchRealm(${realm}) expected 201, got HTTP ${res.status()}: ${await res.text()}`,
    );
  }
}

export async function realmExists(
  request: APIRequestContext,
  realm: string,
): Promise<boolean> {
  const res = await kcFetch(request, `/admin/realms/${realm}`);
  return res.status() === 200;
}

// ---------------------------------------------------------------------------
// IGA enablement
// ---------------------------------------------------------------------------

/**
 * Enable IGA on a realm via tide-admin/toggle-iga, then confirm via
 * tide-admin/iga-status. toggle-iga is a flip, so we only POST it when status
 * reports disabled — making this idempotent.
 */
export async function enableIga(
  request: APIRequestContext,
  realm: string,
): Promise<void> {
  const statusRes = await kcFetch(
    request,
    `/admin/realms/${realm}/tide-admin/iga-status`,
  );
  let enabled = false;
  if (statusRes.status() === 200) {
    enabled = !!(await safeJson(statusRes))?.enabled;
  }
  if (!enabled) {
    const toggle = await kcFetch(
      request,
      `/admin/realms/${realm}/tide-admin/toggle-iga`,
      { method: 'POST' },
    );
    if (toggle.status() !== 200) {
      throw new Error(
        `enableIga(${realm}) toggle expected 200, got HTTP ${toggle.status()}: ${await toggle.text()}`,
      );
    }
    const after = await safeJson(toggle);
    if (after?.enabled !== true) {
      throw new Error(
        `enableIga(${realm}) toggle did not report enabled=true: ${JSON.stringify(after)}`,
      );
    }
  }
  // Final sanity confirm.
  const confirm = await kcFetch(
    request,
    `/admin/realms/${realm}/tide-admin/iga-status`,
  );
  const cj = await safeJson(confirm);
  if (confirm.status() !== 200 || cj?.enabled !== true) {
    throw new Error(
      `enableIga(${realm}) status not enabled after toggle: HTTP ${confirm.status()} ${JSON.stringify(cj)}`,
    );
  }
}

export async function igaStatus(
  request: APIRequestContext,
  realm: string,
): Promise<{ http: number; enabled: boolean | undefined }> {
  const res = await kcFetch(
    request,
    `/admin/realms/${realm}/tide-admin/iga-status`,
  );
  const j = await safeJson(res);
  return { http: res.status(), enabled: j?.enabled };
}

// ---------------------------------------------------------------------------
// Roles / clients
// ---------------------------------------------------------------------------

export interface RoleSpec {
  name: string;
  description?: string;
  attributes?: Record<string, string[]>;
  composite?: boolean;
  composites?: {
    realm?: string[];
    client?: Record<string, string[]>;
  };
}

/** Create a realm role. Returns the raw response (caller asserts status). */
export function createRole(
  request: APIRequestContext,
  realm: string,
  role: RoleSpec,
): Promise<APIResponse> {
  return kcFetch(request, `/admin/realms/${realm}/roles`, {
    method: 'POST',
    json: role,
  });
}

/** Create a client role under the given client UUID. */
export function createClientRole(
  request: APIRequestContext,
  realm: string,
  clientUuid: string,
  role: RoleSpec,
): Promise<APIResponse> {
  return kcFetch(
    request,
    `/admin/realms/${realm}/clients/${clientUuid}/roles`,
    { method: 'POST', json: role },
  );
}

/** GET a realm role by name. Returns {http, body}. */
export async function getRole(
  request: APIRequestContext,
  realm: string,
  name: string,
): Promise<{ http: number; body: any }> {
  const res = await kcFetch(
    request,
    `/admin/realms/${realm}/roles/${encodeURIComponent(name)}`,
  );
  return { http: res.status(), body: await safeJson(res) };
}

/** GET a client role by name under a client UUID. */
export async function getClientRole(
  request: APIRequestContext,
  realm: string,
  clientUuid: string,
  name: string,
): Promise<{ http: number; body: any }> {
  const res = await kcFetch(
    request,
    `/admin/realms/${realm}/clients/${clientUuid}/roles/${encodeURIComponent(name)}`,
  );
  return { http: res.status(), body: await safeJson(res) };
}

/** Composites of a realm role (by name). Array of RoleRepresentation. */
export async function getRoleComposites(
  request: APIRequestContext,
  realm: string,
  name: string,
): Promise<{ http: number; body: any[] }> {
  const res = await kcFetch(
    request,
    `/admin/realms/${realm}/roles/${encodeURIComponent(name)}/composites`,
  );
  const body = await safeJson(res);
  return { http: res.status(), body: Array.isArray(body) ? body : [] };
}

/** Composites of a client role (by name + client UUID). */
export async function getClientRoleComposites(
  request: APIRequestContext,
  realm: string,
  clientUuid: string,
  name: string,
): Promise<{ http: number; body: any[] }> {
  const res = await kcFetch(
    request,
    `/admin/realms/${realm}/clients/${clientUuid}/roles/${encodeURIComponent(name)}/composites`,
  );
  const body = await safeJson(res);
  return { http: res.status(), body: Array.isArray(body) ? body : [] };
}

export async function createClient(
  request: APIRequestContext,
  realm: string,
  clientId: string,
): Promise<string> {
  const res = await kcFetch(request, `/admin/realms/${realm}/clients`, {
    method: 'POST',
    json: { clientId, enabled: true },
  });
  if (res.status() !== 201) {
    throw new Error(
      `createClient(${clientId}) expected 201, got HTTP ${res.status()}: ${await res.text()}`,
    );
  }
  return clientUuid(request, realm, clientId);
}

export async function clientUuid(
  request: APIRequestContext,
  realm: string,
  clientId: string,
): Promise<string> {
  const res = await kcFetch(
    request,
    `/admin/realms/${realm}/clients?clientId=${encodeURIComponent(clientId)}`,
  );
  const arr = await safeJson(res);
  if (!Array.isArray(arr) || arr.length === 0 || !arr[0].id) {
    throw new Error(`clientUuid(${clientId}) not found in realm ${realm}`);
  }
  return arr[0].id as string;
}

// ---------------------------------------------------------------------------
// Client scopes
// ---------------------------------------------------------------------------

export interface ProtocolMapperSpec {
  name: string;
  protocol: string;
  protocolMapper: string;
  config: Record<string, string>;
}

export interface ClientScopeSpec {
  name: string;
  description?: string;
  protocol?: string;
  attributes?: Record<string, string>;
  protocolMappers?: ProtocolMapperSpec[];
}

/** Create a client scope. Returns the raw response (caller asserts status). */
export function createClientScope(
  request: APIRequestContext,
  realm: string,
  scope: ClientScopeSpec,
): Promise<APIResponse> {
  return kcFetch(request, `/admin/realms/${realm}/client-scopes`, {
    method: 'POST',
    json: scope,
  });
}

/**
 * Find a client scope by name. KC has no get-by-name endpoint for scopes, so
 * we list and match. Returns {http, body} where body is the scope rep or
 * undefined if not present (http reflects the list call).
 */
export async function getClientScopeByName(
  request: APIRequestContext,
  realm: string,
  name: string,
): Promise<{ http: number; body: any }> {
  const res = await kcFetch(request, `/admin/realms/${realm}/client-scopes`);
  const list = await safeJson(res);
  const match = Array.isArray(list)
    ? list.find((s: any) => s?.name === name)
    : undefined;
  return { http: res.status(), body: match };
}

/** GET a client scope by its UUID. {http, body}. */
export async function getClientScopeById(
  request: APIRequestContext,
  realm: string,
  scopeId: string,
): Promise<{ http: number; body: any }> {
  const res = await kcFetch(
    request,
    `/admin/realms/${realm}/client-scopes/${scopeId}`,
  );
  return { http: res.status(), body: await safeJson(res) };
}

/** Protocol mappers of a client scope (by scope UUID). Array of mapper reps. */
export async function getClientScopeProtocolMappers(
  request: APIRequestContext,
  realm: string,
  scopeId: string,
): Promise<{ http: number; body: any[] }> {
  const res = await kcFetch(
    request,
    `/admin/realms/${realm}/client-scopes/${scopeId}/protocol-mappers/models`,
  );
  const body = await safeJson(res);
  return { http: res.status(), body: Array.isArray(body) ? body : [] };
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

/** Create a top-level group. Returns the raw response. */
export function createGroup(
  request: APIRequestContext,
  realm: string,
  name: string,
): Promise<APIResponse> {
  return kcFetch(request, `/admin/realms/${realm}/groups`, {
    method: 'POST',
    json: { name },
  });
}

/** Find a top-level group by name. {http, body} (body undefined if absent). */
export async function getGroupByName(
  request: APIRequestContext,
  realm: string,
  name: string,
): Promise<{ http: number; body: any }> {
  const res = await kcFetch(
    request,
    `/admin/realms/${realm}/groups?search=${encodeURIComponent(name)}`,
  );
  const list = await safeJson(res);
  const match = Array.isArray(list)
    ? list.find((g: any) => g?.name === name)
    : undefined;
  return { http: res.status(), body: match };
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

export interface CredentialSpec {
  type: string;
  value: string;
  temporary?: boolean;
}

export interface UserSpec {
  username: string;
  enabled?: boolean;
  email?: string;
  emailVerified?: boolean;
  firstName?: string;
  lastName?: string;
  attributes?: Record<string, string[]>;
  requiredActions?: string[];
  groups?: string[];
  realmRoles?: string[];
  clientRoles?: Record<string, string[]>;
  credentials?: CredentialSpec[];
}

/** Create a user via POST {realm}/users. Returns the raw response. */
export function createUser(
  request: APIRequestContext,
  realm: string,
  user: UserSpec,
): Promise<APIResponse> {
  return kcFetch(request, `/admin/realms/${realm}/users`, {
    method: 'POST',
    json: user,
  });
}

/** Find a user by exact username. {http, body} (body undefined if absent). */
export async function getUserByUsername(
  request: APIRequestContext,
  realm: string,
  username: string,
): Promise<{ http: number; body: any }> {
  const res = await kcFetch(
    request,
    `/admin/realms/${realm}/users?username=${encodeURIComponent(
      username,
    )}&exact=true`,
  );
  const list = await safeJson(res);
  const match = Array.isArray(list)
    ? list.find(
        (u: any) =>
          (u?.username || '').toLowerCase() === username.toLowerCase(),
      )
    : undefined;
  return { http: res.status(), body: match };
}

/** Groups a user belongs to (by user UUID). Array of group reps. */
export async function getUserGroups(
  request: APIRequestContext,
  realm: string,
  userId: string,
): Promise<{ http: number; body: any[] }> {
  const res = await kcFetch(
    request,
    `/admin/realms/${realm}/users/${userId}/groups`,
  );
  const body = await safeJson(res);
  return { http: res.status(), body: Array.isArray(body) ? body : [] };
}

/** Realm-role mappings of a user (by user UUID). Array of role reps. */
export async function getUserRealmRoleMappings(
  request: APIRequestContext,
  realm: string,
  userId: string,
): Promise<{ http: number; body: any[] }> {
  const res = await kcFetch(
    request,
    `/admin/realms/${realm}/users/${userId}/role-mappings/realm`,
  );
  const body = await safeJson(res);
  return { http: res.status(), body: Array.isArray(body) ? body : [] };
}

/**
 * Direct-grant (Resource Owner Password Credentials) token request for
 * username+password against the realm's admin-cli client. Used by Phase 3 to
 * prove the NEGATIVE: a governed-created user has NO usable password (the
 * password is not governed — the user sets it themselves post-approval), so
 * this MUST NOT return 200 for any password. admin-cli is a public client with
 * direct access grants enabled by default in every realm, so no extra client
 * setup is needed.
 */
export async function directGrantToken(
  request: APIRequestContext,
  realm: string,
  username: string,
  password: string,
): Promise<{ http: number; body: any }> {
  const { baseUrl } = kcEnv();
  const res = await request.post(
    `${baseUrl}/realms/${realm}/protocol/openid-connect/token`,
    {
      form: {
        grant_type: 'password',
        client_id: 'admin-cli',
        username,
        password,
      },
    },
  );
  return { http: res.status(), body: await safeJson(res) };
}

// ---------------------------------------------------------------------------
// IGA change requests
// ---------------------------------------------------------------------------

export interface ChangeRequest {
  id: string;
  realmId: string;
  entityType: string;
  entityId: string;
  actionType: string;
  status: string;
  [k: string]: unknown;
}

/** GET /admin/realms/{realm}/iga/change-requests/{id}. */
export async function getChangeRequest(
  request: APIRequestContext,
  realm: string,
  crId: string,
): Promise<{ http: number; body: ChangeRequest | any }> {
  const res = await kcFetch(
    request,
    `/admin/realms/${realm}/iga/change-requests/${crId}`,
  );
  return { http: res.status(), body: await safeJson(res) };
}

/**
 * List PENDING (or status-filtered) CRs and return the first one matching
 * actionType + an optional predicate. Useful when a 202 body / Location is
 * missing and the CR must be located by content.
 */
export async function findChangeRequest(
  request: APIRequestContext,
  realm: string,
  actionType: string,
  predicate?: (cr: ChangeRequest) => boolean,
  status = 'PENDING',
): Promise<ChangeRequest | undefined> {
  const res = await kcFetch(
    request,
    `/admin/realms/${realm}/iga/change-requests?status=${encodeURIComponent(status)}`,
  );
  const list = await safeJson(res);
  if (!Array.isArray(list)) return undefined;
  return list.find(
    (cr: ChangeRequest) =>
      cr.actionType === actionType && (!predicate || predicate(cr)),
  );
}

/**
 * Authorize then commit a change request. With the default attestor +
 * threshold 1 and no approver roles configured, the master admin can
 * self-authorize and immediately commit. Returns the per-step responses.
 */
export async function authorizeAndCommit(
  request: APIRequestContext,
  realm: string,
  crId: string,
): Promise<{
  authorize: { http: number; body: any };
  commit: { http: number; body: any };
}> {
  const authRes = await kcFetch(
    request,
    `/admin/realms/${realm}/iga/change-requests/${crId}/authorize`,
    { method: 'POST', json: {} },
  );
  const authorize = { http: authRes.status(), body: await safeJson(authRes) };

  const commitRes = await kcFetch(
    request,
    `/admin/realms/${realm}/iga/change-requests/${crId}/commit`,
    { method: 'POST' },
  );
  const commit = { http: commitRes.status(), body: await safeJson(commitRes) };
  return { authorize, commit };
}

/** Pull the Location header (case-insensitive) off a response, or undefined. */
export function locationHeader(res: APIResponse): string | undefined {
  const h = res.headers();
  return h['location'] || h['Location'];
}
