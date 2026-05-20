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

/**
 * Find a client by its human clientId. Returns {http, body} where body is the
 * full ClientRepresentation or undefined if not present. Used to assert
 * presence/absence and to verify field fidelity (attributes/redirectUris)
 * after a partialImport commits.
 */
export async function getClientByClientId(
  request: APIRequestContext,
  realm: string,
  clientId: string,
): Promise<{ http: number; body: any }> {
  const res = await kcFetch(
    request,
    `/admin/realms/${realm}/clients?clientId=${encodeURIComponent(clientId)}`,
  );
  const arr = await safeJson(res);
  const match = Array.isArray(arr)
    ? arr.find((c: any) => c?.clientId === clientId)
    : undefined;
  return { http: res.status(), body: match };
}

/** Protocol mappers of a client (by client UUID). Array of mapper reps. */
export async function getClientProtocolMappers(
  request: APIRequestContext,
  realm: string,
  clientUuid: string,
): Promise<{ http: number; body: any[] }> {
  const res = await kcFetch(
    request,
    `/admin/realms/${realm}/clients/${clientUuid}/protocol-mappers/models`,
  );
  const body = await safeJson(res);
  return { http: res.status(), body: Array.isArray(body) ? body : [] };
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

/**
 * GET a full group by its UUID. KC's `?search=` list endpoint returns the
 * BRIEF representation only (id/name/path/subGroupCount/access) — attributes
 * are not included. To assert per-attribute fidelity after a partialImport
 * commit, fetch the full group via `/groups/{id}` (which serializes
 * attributes alongside the rest of the rep).
 */
export async function getGroupById(
  request: APIRequestContext,
  realm: string,
  groupId: string,
): Promise<{ http: number; body: any }> {
  const res = await kcFetch(
    request,
    `/admin/realms/${realm}/groups/${groupId}`,
  );
  return { http: res.status(), body: await safeJson(res) };
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

export interface CredentialSpec {
  type: string;
  value: string;
  temporary?: boolean;
}

export interface FederatedIdentitySpec {
  identityProvider: string;
  userId: string;
  userName: string;
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
  federatedIdentities?: FederatedIdentitySpec[];
}

/**
 * Declare a custom user attribute in the realm's user-profile config so KC
 * actually applies it on user create.
 *
 * KC's DeclarativeUserProfileProvider DROPS any user attribute that is NOT
 * declared in the realm's user-profile config (stock KC behaviour, totally
 * independent of IGA). A POST /users carrying `attributes:{foo:[...]}` for an
 * undeclared `foo` silently never reaches the model — so the IGA capture (which
 * faithfully mirrors the model-layer setAttribute calls) correctly sees zero
 * custom attributes. The fix is on the TEST side: declare the attribute first.
 *
 * GET the current user-profile config, append an attribute entry (idempotent —
 * skipped if already present) with admin-view/admin-edit permissions and no
 * required constraint, then PUT it back. Must be called AFTER the realm exists
 * and BEFORE the (governed or ungoverned) user create that sends the attribute.
 */
export async function declareUserProfileAttribute(
  request: APIRequestContext,
  realm: string,
  attrName: string,
): Promise<void> {
  const getRes = await kcFetch(
    request,
    `/admin/realms/${realm}/users/profile`,
  );
  if (getRes.status() !== 200) {
    throw new Error(
      `declareUserProfileAttribute(${realm}, ${attrName}) GET profile ` +
        `expected 200, got HTTP ${getRes.status()}: ${await getRes.text()}`,
    );
  }
  const profile = (await safeJson(getRes)) || {};
  const attributes: any[] = Array.isArray(profile.attributes)
    ? profile.attributes
    : [];
  if (attributes.some((a) => a?.name === attrName)) {
    return; // already declared — idempotent
  }
  attributes.push({
    name: attrName,
    displayName: attrName,
    // No `required` block: the attribute is optional.
    permissions: { view: ['admin'], edit: ['admin'] },
    multivalued: true,
  });
  profile.attributes = attributes;
  const putRes = await kcFetch(
    request,
    `/admin/realms/${realm}/users/profile`,
    { method: 'PUT', json: profile },
  );
  if (putRes.status() !== 200) {
    throw new Error(
      `declareUserProfileAttribute(${realm}, ${attrName}) PUT profile ` +
        `expected 200, got HTTP ${putRes.status()}: ${await putRes.text()}`,
    );
  }
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
 * Assign one or more realm roles to a user via
 * {@code POST /admin/realms/{realm}/users/{id}/role-mappings/realm}. KC's
 * RoleMapperResource.addRealmRoleMappings consumes a list of full
 * RoleRepresentations and calls {@code roleMapper.grantRole(role)} per entry —
 * the exact production seam IGA's inline GRANT_ROLES governance intercepts.
 * Returns the raw response so callers can assert the (KC-default) status of
 * the void endpoint.
 */
export function assignRealmRoleMapping(
  request: APIRequestContext,
  realm: string,
  userId: string,
  roles: any[],
): Promise<APIResponse> {
  return kcFetch(
    request,
    `/admin/realms/${realm}/users/${userId}/role-mappings/realm`,
    { method: 'POST', json: roles },
  );
}

/** Federated identity links of a user (by user UUID). Array of FI reps. */
export async function getUserFederatedIdentities(
  request: APIRequestContext,
  realm: string,
  userId: string,
): Promise<{ http: number; body: any[] }> {
  const res = await kcFetch(
    request,
    `/admin/realms/${realm}/users/${userId}/federated-identity`,
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

// ---------------------------------------------------------------------------
// Partial import (Phase 4)
// ---------------------------------------------------------------------------

/**
 * POST /admin/realms/{realm}/partialImport with a
 * PartialImportRepresentation. Returns the raw response so the caller can
 * assert status (202 batch when IGA governs it) AND headers (Location).
 */
export function partialImport(
  request: APIRequestContext,
  realm: string,
  rep: unknown,
): Promise<APIResponse> {
  return kcFetch(request, `/admin/realms/${realm}/partialImport`, {
    method: 'POST',
    json: rep,
  });
}

/**
 * List change requests (default PENDING). Always returns an array (empty if
 * the endpoint yields a non-array).
 */
export async function listChangeRequests(
  request: APIRequestContext,
  realm: string,
  status = 'PENDING',
): Promise<ChangeRequest[]> {
  const res = await kcFetch(
    request,
    `/admin/realms/${realm}/iga/change-requests?status=${encodeURIComponent(
      status,
    )}`,
  );
  const list = await safeJson(res);
  return Array.isArray(list) ? list : [];
}

// ---------------------------------------------------------------------------
// Phase 5 — Tideless IGA gate helpers
//
// All helpers below are scope/threshold/approver-role plumbing for the Tideless
// gate documented in IgaScopeResolver.resolveThreshold / requireApprover and
// SimpleNameAttestor.getThreshold. They are deliberately small and symmetric
// with the existing helpers above; the source-of-truth is the resolver itself.
//
// Per-entity scope attributes (`iga.threshold`, `iga.approverRole`) are
// governed when IGA is active — they themselves become SET_REALM_ATTRIBUTE /
// SET_GROUP_ATTRIBUTE / SET_ROLE_ATTRIBUTE CRs. So every helper below MUST be
// called BEFORE enableIga() on the realm, exactly like the "configure bases
// before enabling IGA" rule the rest of the harness already follows.
// ---------------------------------------------------------------------------

/**
 * Merge a single realm attribute via PUT /admin/realms/{realm}. KC's PUT
 * payload REPLACES the attributes map (not merge), so we GET first to preserve
 * any existing entries. Used for `iga.threshold` / `iga.scopeMode`.
 */
export async function setRealmIgaAttr(
  request: APIRequestContext,
  realm: string,
  key: string,
  value: string,
): Promise<void> {
  const getRes = await kcFetch(request, `/admin/realms/${realm}`);
  if (getRes.status() !== 200) {
    throw new Error(
      `setRealmIgaAttr(${realm}, ${key}) GET realm expected 200, got HTTP ${getRes.status()}: ${await getRes.text()}`,
    );
  }
  const realmRep = (await safeJson(getRes)) || {};
  const attributes: Record<string, string> = {
    ...(realmRep.attributes || {}),
    [key]: value,
  };
  const putRes = await kcFetch(request, `/admin/realms/${realm}`, {
    method: 'PUT',
    json: { ...realmRep, attributes },
  });
  if (putRes.status() !== 204) {
    throw new Error(
      `setRealmIgaAttr(${realm}, ${key}=${value}) PUT realm expected 204, got HTTP ${putRes.status()}: ${await putRes.text()}`,
    );
  }
}

/**
 * Set a single attribute on a top-level group via PUT /groups/{id}. Like the
 * realm PUT, KC replaces the attributes map, so we GET first and merge. Used
 * for `iga.threshold` / `iga.approverRole` on a scope-marked group.
 */
export async function setGroupIgaAttr(
  request: APIRequestContext,
  realm: string,
  groupId: string,
  key: string,
  value: string,
): Promise<void> {
  const getRes = await kcFetch(
    request,
    `/admin/realms/${realm}/groups/${groupId}`,
  );
  if (getRes.status() !== 200) {
    throw new Error(
      `setGroupIgaAttr(${groupId}, ${key}) GET group expected 200, got HTTP ${getRes.status()}: ${await getRes.text()}`,
    );
  }
  const groupRep = (await safeJson(getRes)) || {};
  const attributes: Record<string, string[]> = {
    ...(groupRep.attributes || {}),
    [key]: [value],
  };
  const putRes = await kcFetch(
    request,
    `/admin/realms/${realm}/groups/${groupId}`,
    { method: 'PUT', json: { ...groupRep, attributes } },
  );
  if (putRes.status() !== 204) {
    throw new Error(
      `setGroupIgaAttr(${groupId}, ${key}=${value}) PUT group expected 204, got HTTP ${putRes.status()}: ${await putRes.text()}`,
    );
  }
}

/**
 * Set a single attribute on a realm role via PUT /roles/{name}. KC replaces
 * the attributes map, so we GET first and merge. Used for `iga.threshold` /
 * `iga.approverRole` on a scope-marked role.
 */
export async function setRoleIgaAttr(
  request: APIRequestContext,
  realm: string,
  roleName: string,
  key: string,
  value: string,
): Promise<void> {
  const getRes = await kcFetch(
    request,
    `/admin/realms/${realm}/roles/${encodeURIComponent(roleName)}`,
  );
  if (getRes.status() !== 200) {
    throw new Error(
      `setRoleIgaAttr(${roleName}, ${key}) GET role expected 200, got HTTP ${getRes.status()}: ${await getRes.text()}`,
    );
  }
  const roleRep = (await safeJson(getRes)) || {};
  const attributes: Record<string, string[]> = {
    ...(roleRep.attributes || {}),
    [key]: [value],
  };
  const putRes = await kcFetch(
    request,
    `/admin/realms/${realm}/roles/${encodeURIComponent(roleName)}`,
    { method: 'PUT', json: { ...roleRep, attributes } },
  );
  if (putRes.status() !== 204) {
    throw new Error(
      `setRoleIgaAttr(${roleName}, ${key}=${value}) PUT role expected 204, got HTTP ${putRes.status()}: ${await putRes.text()}`,
    );
  }
}

/**
 * Create a user in the test realm with a permanent password, the
 * `realm-management:manage-realm` client role (so {@code requireManageRealm}
 * passes for them in `/admin/realms/{realm}/iga/...`), and the supplied
 * additional realm roles (each must already exist as a realm role in the test
 * realm; these are the roles `IgaScopeResolver.requireApprover` checks via
 * {@code admin.getRoleMappingsStream}).
 *
 * MUST be called BEFORE enableIga() — user create, password set, and role
 * assignment all become governed CRs once IGA is on (CREATE_USER, GRANT_ROLES).
 * Returns the new user's UUID for further assertions if needed.
 */
export async function createAdminWithRoles(
  request: APIRequestContext,
  realm: string,
  username: string,
  password: string,
  extraRealmRoles: string[],
): Promise<string> {
  // Create the user without credentials first (so we can avoid temporary-
  // password defaults), then explicitly reset the password via
  // PUT /users/{id}/reset-password with temporary=false, then PUT /users/{id}
  // to clear any required actions and mark emailVerified — all needed so
  // the realm's direct-grant doesn't 400 with "Account is not fully set up"
  // when default-required actions or verify-email kicks in.
  //
  // email + emailVerified + firstName + lastName are all set so the realm's
  // default user-profile config (which marks email/firstName/lastName as
  // required for users holding the "user" role — the default-roles-{realm}
  // composite the new user automatically receives) does not trigger
  // VERIFY_PROFILE during the direct-grant flow.
  const createRes = await createUser(request, realm, {
    username,
    enabled: true,
    emailVerified: true,
    email: `${username}@example.test`,
    firstName: username,
    lastName: 'Admin',
  });
  if (createRes.status() !== 201) {
    throw new Error(
      `createAdminWithRoles(${username}) create expected 201, got HTTP ${createRes.status()}: ${await createRes.text()}`,
    );
  }
  const userLookup = await getUserByUsername(request, realm, username);
  if (userLookup.http !== 200 || !userLookup.body?.id) {
    throw new Error(
      `createAdminWithRoles(${username}) lookup failed: ${JSON.stringify(userLookup)}`,
    );
  }
  const userId = userLookup.body.id as string;

  // Reset password with temporary=false (the explicit reset-password endpoint
  // bypasses the realm's default-required-actions wiring on
  // POST /users in some KC builds).
  const pwRes = await kcFetch(
    request,
    `/admin/realms/${realm}/users/${userId}/reset-password`,
    {
      method: 'PUT',
      json: { type: 'password', value: password, temporary: false },
    },
  );
  if (pwRes.status() !== 204) {
    throw new Error(
      `createAdminWithRoles(${username}) reset-password expected 204, got HTTP ${pwRes.status()}: ${await pwRes.text()}`,
    );
  }

  // Clear any required actions left over from realm-level defaults. PUT on
  // the user replaces the full user rep, so we re-send the lookup result
  // with requiredActions=[] + emailVerified=true.
  const clearedRep = { ...userLookup.body, requiredActions: [], emailVerified: true };
  const clearRes = await kcFetch(
    request,
    `/admin/realms/${realm}/users/${userId}`,
    { method: 'PUT', json: clearedRep },
  );
  if (clearRes.status() !== 204) {
    throw new Error(
      `createAdminWithRoles(${username}) PUT-clear-required-actions expected 204, got HTTP ${clearRes.status()}: ${await clearRes.text()}`,
    );
  }

  // realm-management:manage-realm client role assignment — the per-realm
  // internal client KC creates automatically; its UUID must be looked up.
  const rmUuid = await clientUuid(request, realm, 'realm-management');
  const rmRolesRes = await kcFetch(
    request,
    `/admin/realms/${realm}/clients/${rmUuid}/roles/manage-realm`,
  );
  if (rmRolesRes.status() !== 200) {
    throw new Error(
      `createAdminWithRoles(${username}) GET manage-realm role expected 200, got HTTP ${rmRolesRes.status()}: ${await rmRolesRes.text()}`,
    );
  }
  const manageRealmRole = await safeJson(rmRolesRes);
  const assignRm = await kcFetch(
    request,
    `/admin/realms/${realm}/users/${userId}/role-mappings/clients/${rmUuid}`,
    { method: 'POST', json: [manageRealmRole] },
  );
  if (assignRm.status() !== 204) {
    throw new Error(
      `createAdminWithRoles(${username}) assign manage-realm expected 204, got HTTP ${assignRm.status()}: ${await assignRm.text()}`,
    );
  }

  // Extra realm roles — IgaScopeResolver.requireApprover walks
  // admin.getRoleMappingsStream() (REALM role mappings only), so the
  // iga.approverRole names MUST refer to realm roles in the admin's realm.
  if (extraRealmRoles.length > 0) {
    const realmRoleReps: any[] = [];
    for (const name of extraRealmRoles) {
      const rr = await getRole(request, realm, name);
      if (rr.http !== 200 || !rr.body?.id) {
        throw new Error(
          `createAdminWithRoles(${username}) extra realm role ${name} not found: ${JSON.stringify(rr)}`,
        );
      }
      realmRoleReps.push(rr.body);
    }
    const assignRr = await assignRealmRoleMapping(
      request,
      realm,
      userId,
      realmRoleReps,
    );
    if (assignRr.status() !== 204) {
      throw new Error(
        `createAdminWithRoles(${username}) assign realm roles ${JSON.stringify(extraRealmRoles)} expected 204, got HTTP ${assignRr.status()}: ${await assignRr.text()}`,
      );
    }
  }
  return userId;
}

/**
 * Direct-grant token for a user in the given (non-master) realm. Same shape
 * as {@link directGrantToken} but returns just the access_token string for
 * Bearer use, or throws on a non-200. Used to call /iga/.../authorize as a
 * specific test-realm admin (rather than the master admin {@link adminToken}
 * returns).
 */
export async function userTokenFor(
  request: APIRequestContext,
  realm: string,
  username: string,
  password: string,
): Promise<string> {
  const tok = await directGrantToken(request, realm, username, password);
  if (tok.http !== 200 || !tok.body?.access_token) {
    throw new Error(
      `userTokenFor(${realm}, ${username}) expected access_token, got HTTP ${tok.http} ${JSON.stringify(tok.body)}`,
    );
  }
  return tok.body.access_token as string;
}

/**
 * Lower-level `kcFetch` variant that authenticates with an EXPLICIT bearer
 * token instead of the cached master-admin token. Same call shape so the
 * rest of the harness reads naturally.
 */
export async function kcFetchAs(
  request: APIRequestContext,
  path: string,
  token: string,
  opts: KcFetchOpts = {},
): Promise<APIResponse> {
  const { baseUrl } = kcEnv();
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

/**
 * Authorize a CR as a SPECIFIC admin (separate from authorizeAndCommit so
 * tests can assert the partial / multi-signature / approver-role-rejected
 * states explicitly). Returns the raw {http, body} so callers can assert on
 * 200 (success), 403 (requireApprover rejected — IgaScopeResolver throws
 * ForbiddenException, JAX-RS maps to 403), 409 (duplicate signature), etc.
 */
export async function authorizeAs(
  request: APIRequestContext,
  realm: string,
  crId: string,
  token: string,
): Promise<{ http: number; body: any }> {
  const res = await kcFetchAs(
    request,
    `/admin/realms/${realm}/iga/change-requests/${crId}/authorize`,
    token,
    { method: 'POST', json: {} },
  );
  return { http: res.status(), body: await safeJson(res) };
}

/**
 * Commit a CR as a SPECIFIC admin. The commit endpoint runs requireApprover
 * itself (so the approver-role gate also applies to commit), then enforces
 * authCount >= threshold (412 with {threshold, authCount} when not met).
 */
export async function commitAs(
  request: APIRequestContext,
  realm: string,
  crId: string,
  token: string,
): Promise<{ http: number; body: any }> {
  const res = await kcFetchAs(
    request,
    `/admin/realms/${realm}/iga/change-requests/${crId}/commit`,
    token,
    { method: 'POST' },
  );
  return { http: res.status(), body: await safeJson(res) };
}

/**
 * Read the resolved CR status, mirroring what IgaAdminResource#toRepresentation
 * publishes: threshold (from IgaScopeResolver.resolveThreshold), authCount,
 * readyToCommit, requiredApproverRoles, scopeMode, and the CR status string.
 * Used to assert partial / pre-commit state when threshold > 1.
 */
export async function getChangeRequestStatus(
  request: APIRequestContext,
  realm: string,
  crId: string,
): Promise<{
  http: number;
  status?: string;
  authCount?: number;
  threshold?: number;
  readyToCommit?: boolean;
  requiredApproverRoles?: string[];
  scopeMode?: string;
  body?: any;
}> {
  const cr = await getChangeRequest(request, realm, crId);
  if (cr.http !== 200) return { http: cr.http };
  return {
    http: cr.http,
    status: cr.body?.status,
    authCount: cr.body?.authorizationCount,
    threshold: cr.body?.threshold,
    readyToCommit: cr.body?.readyToCommit,
    requiredApproverRoles: cr.body?.requiredApproverRoles,
    scopeMode: cr.body?.scopeMode,
    body: cr.body,
  };
}

/**
 * Assign one or more realm roles to a group via
 * POST /admin/realms/{realm}/groups/{id}/role-mappings/realm. This fires
 * KC's RoleMapperResource → groupAdapter.grantRole, which IgaGroupAdapter
 * intercepts as a GROUP_GRANT_ROLES CR (rows carry GROUP + ROLE — see
 * IgaScopeResolver line 76-80). Returns the raw APIResponse so callers can
 * assert the (KC-default 204) status; the CR must be found via
 * findChangeRequest('GROUP_GRANT_ROLES', ...) because IgaGroupAdapter.grantRole
 * does NOT throw IgaPendingApprovalException (no 202 / Location header).
 */
export function assignGroupRealmRoleMapping(
  request: APIRequestContext,
  realm: string,
  groupId: string,
  roles: any[],
): Promise<APIResponse> {
  return kcFetch(
    request,
    `/admin/realms/${realm}/groups/${groupId}/role-mappings/realm`,
    { method: 'POST', json: roles },
  );
}
