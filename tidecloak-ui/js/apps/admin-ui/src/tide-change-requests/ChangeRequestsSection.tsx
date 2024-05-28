import React, { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import {
  TextContent,
  Text,
  EmptyState,
  PageSection,
  Tab,
  TabTitleText,
  ClipboardCopy, 
  ClipboardCopyVariant,
  Label,
  Button
} from "@patternfly/react-core";
import { KeycloakDataTable } from "../components/table-toolbar/KeycloakDataTable";
import RoleChangeRequest from "@keycloak/keycloak-admin-client/lib/defs/RoleChangeRequest"
import RequestChangesUserRecord from "@keycloak/keycloak-admin-client/lib/defs/RequestChangesUserRecord"
import { ViewHeader } from "../components/view-header/ViewHeader";
import { adminClient } from "../admin-client";
import "../events/events.css";
import helpUrls from '../help-urls';
import {
  RoutableTabs,
  useRoutableTab,
} from "../components/routable-tabs/RoutableTabs";
import { ChangeRequestsTab, toChangeRequests } from './routes/ChangeRequests';
import { useRealm } from "../context/realm-context/RealmContext";
import { RolesChangeRequestsList } from "./RolesChangeRequestsList"
import { ClientChangeRequestsList } from './ClientChangeRequestsList';
import { Table, Thead, Tr, Th, Tbody, Td } from '@patternfly/react-table';
import { toAddClient } from '../clients/routes/AddClient';
import { toImportClient } from '../clients/routes/ImportClient';
import { useAccess } from '../context/access/Access';




export default function ChangeRequestsSection() {
  const { t } = useTranslation();
  const { realm } = useRealm();
  const [key, setKey] = useState(0);
  const refresh = () => setKey(key + 1);
  const [selectedRows, setSelectedRows] = useState<RoleChangeRequest[]>();
  const [commitRecord, setCommitRecord] = useState<boolean>(false);
  const [approveRecord, setApproveRecord] = useState<boolean>(false);

  useEffect(() => {
    console.log(selectedRows)
    // if (selectedRows && selectedRows.status) {
    //   if (selectedRows.status === "DRAFT" || selectedRows.status === "PENDING") {
    //     setApproveRecord(true);
    //   } else if (selectedRows.status === "APPROVED") {
    //     setCommitRecord(true);
    //     setApproveRecord(false);
    //   } else {
    //     setCommitRecord(false);
    //     setApproveRecord(false);
    //   }
    // }
  }, [selectedRows]);

  const ToolbarItemsComponent = () => {
    const { t } = useTranslation();
    const { hasAccess } = useAccess();
    const isManager = hasAccess("manage-clients");
  
    if (!isManager) return <span />;
  
    return (
      <>
        <div>
          <Button variant="primary" isDisabled={!approveRecord}>
            {t("Approve Draft")}
          </Button>
        </div>
        <div>
          <Button variant="secondary" isDisabled={!commitRecord}>
            {t("Commit Draft")}
          </Button>
        </div>
      </>
    );
  };

  const columns = [
    {
      name: 'Action',
      displayKey: 'Action',
      cellRenderer: (row: RoleChangeRequest) => row.action
    },
    {
      name: 'Role',
      displayKey: 'Role',
      cellRenderer: (row: RoleChangeRequest) => row.role
    },
    {
      name: 'Client ID',
      displayKey: 'Client ID',
      cellRenderer: (row: RoleChangeRequest) => row.clientId
    },
    {
      name: 'Type',
      displayKey: 'Type',
      cellRenderer: (row: RoleChangeRequest) => row.requestType
    },
    {
      name: 'Status',
      displayKey: 'Status',
      cellRenderer: (row: RoleChangeRequest) => statusLabel(row.status)
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

  const DetailCell = (row: RoleChangeRequest) => (
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
      return await adminClient.tideUsersExt.getRequestedChangesForUsers();
    } catch (error) {
      return [];
    }
  };

  const handleSelect = (rows: RoleChangeRequest[]) => {
    // Only keep the last selected row
    if (rows && rows.length > 0) {
      setSelectedRows(rows[rows.length - 1]);
    } else {
      setSelectedRows(undefined); // Clear selection if no rows are selected
    }
  };


  const useTab = (tab: ChangeRequestsTab) => useRoutableTab(toChangeRequests({ realm, tab }));

  const userRequestsTab = useTab("users");
  const roleRequestsTab = useTab("roles");
  const clientRequestsTab = useTab("clients");


  return (
    <>
      <ViewHeader
        titleKey="Change Requests"
        subKey="Change requests are change requests that require approval from adminstrators"
        helpUrl={helpUrls.changeRequests}
        divider={false}
      />
      <PageSection
        data-testid="change-request-page"
        variant="light"
        className="pf-v5-u-p-0"
      >
        <RoutableTabs
          mountOnEnter
          isBox
          defaultLocation={toChangeRequests({realm, tab: "users"})}
        >
          <Tab
            title={<TabTitleText>Users</TabTitleText>}
            {...userRequestsTab}
          >
            <div className="keycloak__events_table">
              <KeycloakDataTable
                key={key}
                toolbarItem={<ToolbarItemsComponent />}
                isRadio={true}
                loader={loader}
                ariaLabelKey="Requested Changes"
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
                onSelect={(row: RoleChangeRequest[]) => setSelectedRows([...row])}
                emptyState={
                  <EmptyState variant="lg">
                      <TextContent>
                        <Text>No requested changes found.</Text>
                      </TextContent>
                    </EmptyState>
                }
              />
            </div>
          </Tab>
          <Tab
            title={<TabTitleText>Roles</TabTitleText>}
            {...roleRequestsTab}
          >
            <RolesChangeRequestsList />
          </Tab>
          <Tab
            title={<TabTitleText>Clients</TabTitleText>}
            {...clientRequestsTab}
          >
            <ClientChangeRequestsList />
          </Tab>
        </RoutableTabs>
      </PageSection>
    </>
  );
}
