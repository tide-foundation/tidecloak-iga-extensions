import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useNavigate } from "react-router-dom";
import {
  Button,
  TextContent,
  Text,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
  EmptyState,
  AlertVariant,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  PageSection,
  Tab,
  TabTitleText,
} from "@patternfly/react-core";
import { KeycloakDataTable } from "../components/table-toolbar/KeycloakDataTable";
import { useAlerts } from '../components/alert/Alerts';
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



export default function ChangeRequestsSection() {
  const { t } = useTranslation();
  const { realm } = useRealm();
  const [key, setKey] = useState(0);
  const refresh = () => setKey(key + 1);
  const [selectedRows, setSelectedRows] = useState<RoleChangeRequest[]>([]);

  const columns = [
    {
      name: t('Action'),
      displayKey: 'Action',
      cellRenderer: (row: RoleChangeRequest) => row.action
    },
    {
      name: t('Role'),
      displayKey: 'Role',
      cellRenderer: (row: RoleChangeRequest) => row.role
    },
    {
      name: t('Client ID'),
      displayKey: 'Client ID',
      cellRenderer: (row: RoleChangeRequest) => row.clientId
    },
    {
      name: t('Type'),
      displayKey: 'Type',
      cellRenderer: (row: RoleChangeRequest) => row.requestType
    },
    {
      name: t('Status'),
      displayKey: 'Status',
      cellRenderer: (row: RoleChangeRequest) => row.status
    },
  ];

  const DetailCell = (row: RoleChangeRequest) => (
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
      return await adminClient.tideUsersExt.getRequestedChangesForUsers();
    } catch (error) {
      return [];
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
                onSelect={(rows: RoleChangeRequest[]) => setSelectedRows([...rows])}
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
