import React, { useState, useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import {
  TextContent,
  Text,
  EmptyState,
  ClipboardCopy, 
  ClipboardCopyVariant,
  Label,
  Button,
  ToolbarItem
} from "@patternfly/react-core";
import { KeycloakDataTable } from "../components/table-toolbar/KeycloakDataTable";
import RequestChangesUserRecord from "@keycloak/keycloak-admin-client/lib/defs/RequestChangesUserRecord"
import CompositeRoleChangeRequest from "@keycloak/keycloak-admin-client/lib/defs/CompositeRoleChangeRequest"
import RoleChangeRequest from "@keycloak/keycloak-admin-client/lib/defs/RoleChangeRequest"
import { Table, Thead, Tr, Th, Tbody, Td } from '@patternfly/react-table';
import { useAccess } from '../context/access/Access';
import { adminClient } from "../admin-client";
import "../events/events.css";



export const RolesChangeRequestsList = () =>  {
  const { t } = useTranslation();
  const [key, setKey] = useState(0);
  const refresh = () => setKey(key + 1);
  const [selectedRow, setSelectedRow] = useState<CompositeRoleChangeRequest[] | RoleChangeRequest[]>([]);
  const [commitRecord, setCommitRecord] = useState<boolean>(false);
  const [approveRecord, setApproveRecord] = useState<boolean>(false);

  useEffect(() => {
    console.log(selectedRow)
    if (selectedRow && selectedRow[0] && selectedRow[0].status) {
      if (selectedRow[0].status === "DRAFT" || selectedRow[0].status === "PENDING") {
        setApproveRecord(true); // maybe we disable button if admin already signed this record or show messaged after we check on backend
      } else if (selectedRow[0].status === "APPROVED") {
        setCommitRecord(true);
        setApproveRecord(false);
      } else {
        setCommitRecord(false);
        setApproveRecord(false);
      }
    }
  }, [selectedRow]);

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
      cellRenderer: (row: RoleChangeRequest | CompositeRoleChangeRequest) => statusLabel(row.status)
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
            <Label color="blue" className="keycloak-admin--role-mapping__client-name">
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

    const DetailCell = (row: RoleChangeRequest|CompositeRoleChangeRequest) => (
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
    console.log("HELLO SASHA")
    try {
      return await adminClient.tideUsersExt.getRequestedChangesForRoles();
    } catch (error) {
        return [];
    }
  };

  const ToolbarItemsComponent = () => {
    const { t } = useTranslation();
    const { hasAccess } = useAccess();
    const isManager = hasAccess("manage-clients");
  
    if (!isManager) return <span />;
  
    return (
      <>
        <ToolbarItem>
          <Button variant="primary" isDisabled={!approveRecord} onClick={() => console.log(selectedRow)}>
            {t("Approve Draft")}
          </Button>
        </ToolbarItem>
        <ToolbarItem>
          <Button variant="secondary" isDisabled={!commitRecord}>
            {t("Commit Draft")}
          </Button>
        </ToolbarItem>
      </>
    );
  };

  return (
    <>
      <KeycloakDataTable
      toolbarItem={<ToolbarItemsComponent />}
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
      canSelectAll={false}
      onSelect={(value: RoleChangeRequest[]|CompositeRoleChangeRequest[]) => setSelectedRow([...value])}
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
