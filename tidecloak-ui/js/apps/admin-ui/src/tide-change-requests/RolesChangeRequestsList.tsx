import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  TextContent,
  Text,
  EmptyState,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
} from "@patternfly/react-core";
import { KeycloakDataTable } from "../components/table-toolbar/KeycloakDataTable";
import RequestChangesUserRecord from "@keycloak/keycloak-admin-client/lib/defs/RequestChangesUserRecord"
import CompositeRoleChangeRequest from "@keycloak/keycloak-admin-client/lib/defs/CompositeRoleChangeRequest"
import RoleChangeRequest from "@keycloak/keycloak-admin-client/lib/defs/RoleChangeRequest"


import { adminClient } from "../admin-client";

import "../events/events.css";


export const RolesChangeRequestsList = () => {
  const { t } = useTranslation();
  const [key, setKey] = useState(0);
  const refresh = () => setKey(key + 1);
  const [selectedRows, setSelectedRows] = useState<CompositeRoleChangeRequest[]| RoleChangeRequest[]>([]);

  function isCompositeRoleChangeRequest(row: RoleChangeRequest | CompositeRoleChangeRequest): row is CompositeRoleChangeRequest {
    return 'compositeRole' in row;
  }

  const columns = [
    {
      name: t('Action'),
      displayKey: 'Action',
      cellRenderer: (row: RoleChangeRequest|CompositeRoleChangeRequest) => row.action
    },
    {
      name: t('Role'),
      displayKey: 'Role',
      cellRenderer: (row: RoleChangeRequest|CompositeRoleChangeRequest) => row.role
    },
    {
      name: 'Composite Role',
      displayKey: 'Composite Role',
      cellRenderer: (row: RoleChangeRequest | CompositeRoleChangeRequest) => isCompositeRoleChangeRequest(row) ? row.compositeRole || '' : '',
      shouldDisplay: (row: RoleChangeRequest | CompositeRoleChangeRequest) => isCompositeRoleChangeRequest(row),
    },
    {
      name: t('Client ID'),
      displayKey: 'Client ID',
      cellRenderer: (row: RoleChangeRequest | CompositeRoleChangeRequest) => row.clientId
    },
    {
      name: t('Type'),
      displayKey: 'Type',
      cellRenderer: (row: RoleChangeRequest | CompositeRoleChangeRequest) => row.requestType
    },
    {
      name: t('Status'),
      displayKey: 'Status',
      cellRenderer: (row: RoleChangeRequest | CompositeRoleChangeRequest) => row.status
    },
  ];

    const DetailCell = (row: RoleChangeRequest|CompositeRoleChangeRequest) => (
      <DescriptionList isHorizontal className="keycloak_eventsection_details">
        <DescriptionListTerm>Affected Users:</DescriptionListTerm>
          {row.userRecord &&
            row.userRecord.map((value: RequestChangesUserRecord) => (
              <DescriptionListGroup key={value.username}>
                <DescriptionListDescription>{value.username} {value.clientId}</DescriptionListDescription>
              </DescriptionListGroup>
            ))}
      </DescriptionList>
    );

  const loader = async () => {
    try {
        return await adminClient.tideUsersExt.getRequestedChangesForRoles();
    } catch (error) {
        return [];
    }
  };

  return (
    <>
        <KeycloakDataTable
        isSearching={false}
        key={key}
        isRadio={true}
        loader={loader}
        ariaLabelKey="roleChangeRequestsList"
        detailColumns={[
            {
            name: "details",
            enabled: (row) => row.userRecord.length > 0,
            cellRenderer: DetailCell,
            },
        ]}
        columns={columns}
        isPaginated
        onSelect={(rows: RoleChangeRequest[]|CompositeRoleChangeRequest[]) => setSelectedRows([...rows])}
        emptyState={
            <EmptyState variant="lg">
                <TextContent>
                <Text>No requested changes found.</Text>
                </TextContent>
            </EmptyState>
        }
        />
    </>
  );
};
