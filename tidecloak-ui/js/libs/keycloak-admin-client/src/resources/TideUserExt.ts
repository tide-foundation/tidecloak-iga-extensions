import type { KeycloakAdminClient } from "../client.js";
import Resource from "./resource.js";
import type RequestedChanges from "../defs/RequestedChanges.js";
import type RoleChangeRequest from "../defs/RoleChangeRequest.js";
import type CompositeRoleChangeRequest from "../defs/CompositeRoleChangeRequest.js";




interface SearchQuery {
  search?: string;
}

interface PaginationQuery {
  first?: number;
  max?: number;
}

interface UserBaseQuery {
  email?: string;
  firstName?: string;
  lastName?: string;
  username?: string;
}

export interface UserQuery extends PaginationQuery, SearchQuery, UserBaseQuery {
  exact?: boolean;
  [key: string]: string | number | undefined | boolean;
}

export class TideUsersExt extends Resource<{ realm?: string }> {


  public getUserDraftStatus = this.makeRequest<
    { id: string },
    string
  >({
    method: "GET",
    path: "/users/{id}/draft/status",
    urlParamKeys: ["id"],
  });

  public getUserRoleDraftStatus = this.makeRequest<
  { userId: string, roleId: string },
  string
>({
  method: "GET",
  path: "/users/{userId}/roles/{roleId}/draft/status",
  urlParamKeys: ["userId", "roleId"],
});

public getRoleDraftStatus = this.makeRequest<
  { parentId: string, childId: string },
  string
>({
  method: "GET",
  path: "/composite/{parentId}/child/{childId}/draft/status",
  urlParamKeys: ["parentId", "childId"],
});

public getRequestedChangesForUsers = this.makeRequest<void, RoleChangeRequest[]>({
  method: "GET",
  path: "/change-set/users/requests",
});

public getRequestedChangesForRoles = this.makeRequest<void, CompositeRoleChangeRequest[]|RoleChangeRequest[]>({
  method: "GET",
  path: "/change-set/roles/requests",
});

public getRequestedChangesForClients = this.makeRequest<void, RequestedChanges[]>({
  method: "GET",
  path: "/change-set/clients/requests",
});

  constructor(client: KeycloakAdminClient) {
    super(client, {
      path: "/admin/realms/{realm}/tide-admin",
      getUrlParams: () => ({
        realm: client.realmName,
      }),
      getBaseUrl: () => client.baseUrl,
    });
  }
}