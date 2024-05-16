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
} from "@patternfly/react-core";
import { KeycloakDataTable } from "../table-toolbar/KeycloakDataTable";
import { useAlerts } from '../alert/Alerts';
import RequestedChanges from "@keycloak/keycloak-admin-client/lib/defs/RequestedChanges"
import RequestChangesUserRecord from "@keycloak/keycloak-admin-client/lib/defs/RequestChangesUserRecord"

import { adminClient } from '../../admin-client';
import { KeycloakSpinner } from "../keycloak-spinner/KeycloakSpinner";

export const ChangeRequestsDataTable = () => {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [data, setData] = useState<RequestedChanges[]>([]);
  const [loading, setLoading] = useState(true);
  const { addAlert, addError } = useAlerts();
  const [key, setKey] = useState(0);
  const refresh = () => setKey(key + 1);

  useEffect(() => {
    fetchData();
  }, [key]);

  async function fetchData() {
    try {
      const response = await adminClient.tideUsersExt.getRequestedChanges();
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

  const goToCreateChangeRequest = () => {
    navigate("/path-to-create-change-request"); // Adjust path as needed
  };

  const toolbar = () => (
    <Toolbar>
      <ToolbarContent>
        <ToolbarItem>
          <Button onClick={goToCreateChangeRequest}>Create Change Request</Button>
        </ToolbarItem>
      </ToolbarContent>
    </Toolbar>
  );

  if (loading) return <KeycloakSpinner />;

  return (
    <>
      <Toolbar>{toolbar()}</Toolbar>
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
        isPaginated={true}
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
    </>
  );
};
