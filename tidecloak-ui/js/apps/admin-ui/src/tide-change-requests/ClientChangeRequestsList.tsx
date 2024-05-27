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
import RequestedChanges from "@keycloak/keycloak-admin-client/lib/defs/RequestedChanges"
import RequestChangesUserRecord from "@keycloak/keycloak-admin-client/lib/defs/RequestChangesUserRecord"


import { adminClient } from "../admin-client";

import "../events/events.css";


export const ClientChangeRequestsList = () => {
  const { t } = useTranslation();
  const [key, setKey] = useState(0);
  const refresh = () => setKey(key + 1);
  const [selectedRows, setSelectedRows] = useState<RequestedChanges[]>([]);

  const columns = [
    {
      name: t('Action'),
      displayKey: 'Action',
      cellRenderer: (row: RequestedChanges) => row.action
    },
    {
      name: t('Client ID'),
      displayKey: 'Client ID',
      cellRenderer: (row: RequestedChanges) => row.clientId
    },
    {
      name: t('Type'),
      displayKey: 'Type',
      cellRenderer: (row: RequestedChanges) => row.requestType
    },
    {
      name: t('Status'),
      displayKey: 'Status',
      cellRenderer: (row: RequestedChanges) => row.status
    },
  ];

  const DetailCell = (row: RequestedChanges) => (
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
        return await adminClient.tideUsersExt.getRequestedChangesForClients();
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
        ariaLabelKey="clientChangeRequestsList"
        detailColumns={[
            {
            name: "details",
            enabled: (row) => row.userRecord.length > 0,
            cellRenderer: DetailCell,
            },
        ]}
        columns={columns}
        isPaginated
        onSelect={(rows: RequestedChanges[]) => setSelectedRows([...rows])}
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
