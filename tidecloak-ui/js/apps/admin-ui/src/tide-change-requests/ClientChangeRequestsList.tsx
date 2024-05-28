import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  TextContent,
  Text,
  EmptyState,
  ClipboardCopy, 
  ClipboardCopyVariant,
  Label,
} from "@patternfly/react-core";
import { KeycloakDataTable } from "../components/table-toolbar/KeycloakDataTable";
import RequestedChanges from "@keycloak/keycloak-admin-client/lib/defs/RequestedChanges"
import RequestChangesUserRecord from "@keycloak/keycloak-admin-client/lib/defs/RequestChangesUserRecord"
import { Table, Thead, Tr, Th, Tbody, Td } from '@patternfly/react-table';



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
      cellRenderer: (row: RequestedChanges) => statusLabel(row.status)
    },
  ];

  const statusLabel = (roleStatus: string) => {
    return (
      <>
        {roleStatus === "DRAFT" && (
          <Label className="keycloak-admin--role-mapping__client-name">
            {"DRAFT"}
          </Label>
        )}
        {roleStatus === "PENDING" && (
          <Label color="orange" className="keycloak-admin--role-mapping__client-name">
            {"PENDING"}
          </Label>
        )}
        {roleStatus === "APPROVED" && (
            <Label color="gold" className="keycloak-admin--role-mapping__client-name">
              {"APPROVED"}
            </Label>
        )}
      </>
    )
  }


  const parseAndFormatJson = (str: string) => {
    try {
      // Parse the JSON string
      const jsonObject = JSON.parse(str);
      // Format the JSON object into a readable string with indentation
      return JSON.stringify(jsonObject, null, 2);
    } catch (e) {
      return 'Invalid JSON';
    }
  };

  const columnNames = {
    username: 'Affected User',
    clientId: 'Affected Client',
    accessDraft: 'Access Draft',
  };

  const DetailCell = (row: RequestedChanges) => (
    <Table
      aria-label="Simple table"
      variant={'compact'}
      borders={false}
      isStriped
    >
      <Thead>
        <Tr>
          <Th width={20} modifier="wrap">{columnNames.username}</Th>
          <Th width={20} modifier="wrap">{columnNames.clientId}</Th>
          <Th width={40}>{columnNames.accessDraft}</Th>
        </Tr>
      </Thead>
      <Tbody>
        {row.userRecord.map((value: RequestChangesUserRecord) => (
          <Tr key={value.username}>
            <Td dataLabel={columnNames.username}>{value.username}</Td>
            <Td dataLabel={columnNames.clientId}>{value.clientId}</Td>
            <Td dataLabel={columnNames.accessDraft}>
              <ClipboardCopy isCode isReadOnly hoverTip="Copy" clickTip="Copied" variant={ClipboardCopyVariant.expansion}>
                {parseAndFormatJson(value.accessDraft)}
              </ClipboardCopy>
            </Td>
          </Tr>
        ))}
      </Tbody>
    </Table>
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
