import type ComponentRepresentation from "@keycloak/keycloak-admin-client/lib/defs/componentRepresentation";
import type RealmRepresentation from "@keycloak/keycloak-admin-client/lib/defs/realmRepresentation";
import type { UserProfileConfig } from "@keycloak/keycloak-admin-client/lib/defs/userProfileMetadata";
import type UserRepresentation from "@keycloak/keycloak-admin-client/lib/defs/userRepresentation";
import {
  AlertVariant,
  Button,
  ButtonVariant,
  Chip,
  ChipGroup,
  EmptyState,
  FlexItem,
  Label,
  Text,
  TextContent,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
  Tooltip,
} from "@patternfly/react-core";
import {
  ExclamationCircleIcon,
  InfoCircleIcon,
  WarningTriangleIcon,
} from "@patternfly/react-icons";
import type { IRowData } from "@patternfly/react-table";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useNavigate } from "react-router-dom";

import { adminClient } from "../../admin-client";
import { useRealm } from "../../context/realm-context/RealmContext";
import { SearchType } from "../../user/details/SearchFilter";
import { emptyFormatter } from "../../util";
import { useFetch } from "../../utils/useFetch";
import { useAlerts } from "../alert/Alerts";
import { KeycloakSpinner } from "../keycloak-spinner/KeycloakSpinner";
import { ListEmptyState } from "../list-empty-state/ListEmptyState";
import { KeycloakDataTable } from "../table-toolbar/KeycloakDataTable";

export type ChangeRequestAttribute = {
  name: string;
  displayName: string;
  value: string;
};

export function ChangeRequestDataTable() {
  const { t } = useTranslation();
  const { addAlert, addError } = useAlerts();
  const { realm: realmName } = useRealm();
  const navigate = useNavigate();
  const [userStorage, setUserStorage] = useState<ComponentRepresentation[]>();
  const [searchUser, setSearchUser] = useState("");
  const [realm, setRealm] = useState<RealmRepresentation | undefined>();
  const [selectedRows, setSelectedRows] = useState<UserRepresentation[]>([]);
  const [searchType, setSearchType] = useState<SearchType>("default");
  const [searchDropdownOpen, setSearchDropdownOpen] = useState(false);
  const [profile, setProfile] = useState<UserProfileConfig>({});
  const [query, setQuery] = useState("");

  const [key, setKey] = useState(0);
  const refresh = () => setKey(key + 1);

  useFetch(
    async () => {

      try {
        return await Promise.all([
          adminClient.realms.findOne({ realm: realmName }),
          adminClient.users.getProfile(),
        ]);
      } catch {
        return [[]] as [
          RealmRepresentation | undefined,
        ];
      }
    },
    ([realm]) => {
      setRealm(realm);
    },
    [],
  );

  const loader = async (first?: number, max?: number, search?: string) => {
    const params: { [name: string]: string | number } = {
      first: first!,
      max: max!,
      q: query!,
    };

    const searchParam = search || searchUser || "";
    if (searchParam) {
      params.search = searchParam;
    }

    if (!(params.search || params.q)) {
      return [];
    }

    try {
      // query our list of change sets here
    } catch (error) {
      return [];
    }
  };

  // const goToCreate = () => navigate(toAddUser({ realm: realmName }));

  if ( !realm) {
    return <KeycloakSpinner />;
  }

  return (
    <>
      <KeycloakDataTable
        key={key}
        loader={loader}
        isPaginated
        ariaLabelKey="changeRequestsList"
        canSelectAll
        //onSelect={(rows: UserRepresentation[]) => setSelectedRows([...rows])}
        emptyState={
          // (
          //   <>
          //     <Toolbar>
          //       <ToolbarContent>{toolbar()}</ToolbarContent>
          //     </Toolbar>
          //     <EmptyState data-testid="empty-state" variant="lg">
          //       <TextContent className="kc-search-users-text">
          //         <Text>{t("searchForUserDescription")}</Text>
          //       </TextContent>
          //     </EmptyState>
          //   </>
          // ) : (
            <ListEmptyState
              message={t("noChangeRequestsFound")}
              instructions={t("emptyInstructions")}
            />
          // )
        }
        columns={[
          {
            name: "user",
            displayKey: "user",
            cellFormatters: [emptyFormatter()],
          },
          {
            name: "Access Request",
            displayKey: "Access Request",
            cellFormatters: [emptyFormatter()],
          },
        ]}
      />
    </>
  );
}
