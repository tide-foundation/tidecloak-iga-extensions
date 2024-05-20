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
import RequestedChanges from "@keycloak/keycloak-admin-client/lib/defs/RequestedChanges"
import RequestChangesUserRecord from "@keycloak/keycloak-admin-client/lib/defs/RequestChangesUserRecord"
import { ViewHeader } from "../components/view-header/ViewHeader";


import { adminClient } from "../admin-client";
import { KeycloakSpinner } from "../components/keycloak-spinner/KeycloakSpinner";

import "../events/events.css";
import helpUrls from '../help-urls';
import {
  RoutableTabs,
  useRoutableTab,
} from "../components/routable-tabs/RoutableTabs";
import { ChangeRequestsTab, toChangeRequests } from './routes/ChangeRequests';
import { useRealm } from "../context/realm-context/RealmContext";


export default function ChangeRequestsSection() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { realm } = useRealm();
  const [data, setData] = useState<RequestedChanges[]>([]);
  const [loading, setLoading] = useState(true);
  const { addAlert, addError } = useAlerts();
  const [key, setKey] = useState(0);
  const refresh = () => setKey(key + 1);
  const [selectedRows, setSelectedRows] = useState<RequestedChanges[]>([]);
  const [selectedTab, setSelectedTab] = useState<ChangeRequestsTab>("users"); // Track the selected tab

  
  
  useEffect(() => {
    fetchData();
  }, [key, selectedTab]); // Re-fetch data when key or selected tab changes

  

  async function fetchData() {
    setLoading(true);
    try {
      let response : RequestedChanges[];
      switch (selectedTab) {
        case 'users':
          response = await adminClient.tideUsersExt.getRequestedChangesForUsers();
          break;
        case 'roles':
          response = await adminClient.tideUsersExt.getRequestedChangesForRoles();
          break;
        // Add more cases as needed
        default:
          response = [];
      }
      setData(response);
    } catch (error) {
      console.error('Failed to fetch data:', error);
      addAlert(t('dataFetchError'), AlertVariant.danger);
    } finally {
      setLoading(false);
    }
  }

  const columns = [
    {
      name: t('Description'),
      displayKey: 'Description',
      cellRenderer: (row: RequestedChanges ) => row.description
    },
    {
      name: t('Type'),
      displayKey: 'Type',
      cellRenderer: (row: RequestedChanges) => row.type
    },
    {
      name: t('Parent Record ID'),
      displayKey: 'Parent Record ID',
      cellRenderer: (row: RequestedChanges) => row.parentRecordId
    },
  ];

  const DetailCell = (row: RequestedChanges) => (
    <DescriptionList isHorizontal className="keycloak_eventsection_details">
      <DescriptionListTerm>Affected Users:</DescriptionListTerm>
        {row.userRecord &&
          row.userRecord.map((value: RequestChangesUserRecord) => (
            <DescriptionListGroup key={value.username}>
              <DescriptionListDescription>{value.username} {value.clientName}</DescriptionListDescription>
            </DescriptionListGroup>
          ))}
    </DescriptionList>
  );

  const loader = async () => {
    return data;
  };

  const useTab = (tab: ChangeRequestsTab) => useRoutableTab(toChangeRequests({ realm, tab }));

  const userRequestsTab = useTab("users");
  const roleRequestsTab = useTab("roles");
  const clientRequestsTab = useTab("clients");



  if (loading) return <KeycloakSpinner />;

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
          isBox
          defaultLocation={toChangeRequests({realm, tab: "users"})}
        >
          <Tab
            title={<TabTitleText>Users</TabTitleText>}
            onClick={() => setSelectedTab("users")}
            {...userRequestsTab}
          >
            <div className="keycloak__events_table">
              <KeycloakDataTable
                isSearching={false}
                key={key}
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
                onSelect={(rows: RequestedChanges[]) => setSelectedRows([...rows])}
                emptyState={
                  data.length === 0 && (
                    <EmptyState variant="lg">
                      <TextContent>
                        <Text>No requested changes found.</Text>
                      </TextContent>
                    </EmptyState>
                  )
                }
              />
            </div>
          </Tab>
          <Tab
            title={<TabTitleText>Roles</TabTitleText>}
            onClick={() => setSelectedTab("roles")}
            {...roleRequestsTab}
          >
            <div className="keycloak__events_table">
              <KeycloakDataTable
                isSearching={false}
                key={key}
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
                onSelect={(rows: RequestedChanges[]) => setSelectedRows([...rows])}
                emptyState={
                  data.length === 0 && (
                    <EmptyState variant="lg">
                      <TextContent>
                        <Text>No requested changes found.</Text>
                      </TextContent>
                    </EmptyState>
                  )
                }
              />
            </div>
          </Tab>
        </RoutableTabs>
      </PageSection>
    </>
  );
}
