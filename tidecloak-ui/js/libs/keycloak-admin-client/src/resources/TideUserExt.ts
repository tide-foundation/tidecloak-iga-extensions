import type { KeycloakAdminClient } from "../client.js";
import type CredentialRepresentation from "../defs/credentialRepresentation.js";
import type FederatedIdentityRepresentation from "../defs/federatedIdentityRepresentation.js";
import type GroupRepresentation from "../defs/groupRepresentation.js";
import type MappingsRepresentation from "../defs/mappingsRepresentation.js";
import type { RequiredActionAlias } from "../defs/requiredActionProviderRepresentation.js";
import type RoleRepresentation from "../defs/roleRepresentation.js";
import type { RoleMappingPayload } from "../defs/roleRepresentation.js";
import type UserConsentRepresentation from "../defs/userConsentRepresentation.js";
import type {
  UserProfileConfig,
  UserProfileMetadata,
} from "../defs/userProfileMetadata.js";
import type UserRepresentation from "../defs/userRepresentation.js";
import type UserSessionRepresentation from "../defs/userSessionRepresentation.js";
import Resource from "./resource.js";

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