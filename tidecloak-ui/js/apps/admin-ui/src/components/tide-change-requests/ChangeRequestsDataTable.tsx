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
  AlertVariant
} from "@patternfly/react-core";
import { KeycloakDataTable } from "../table-toolbar/KeycloakDataTable";
import { useAlerts } from '../alert/Alerts';
import type { IRowData } from '@patternfly/react-table';
import RequestedChanges from "@keycloak/keycloak-admin-client/lib/defs/RequestedChanges"
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
      displayKey: 'Description', // Assuming there's a display key concept, similar to Keycloak's pattern
      cellRenderer: (row: { data: { description: any; }; }) => row.data.description
    },
    {
      name: t('Type'),
      displayKey: 'Type',
      cellRenderer: (row: { data: { type: any; }; }) => row.data.type
    },
    {
      name: t('Parent Record ID'),
      displayKey: 'Parent Record ID',
      cellRenderer: (row: { data: { parentRecordId: any; }; }) => row.data.parentRecordId
    },
  ];

  const loader = async () => {
    return data.map((item) => ({
      cells: [
        item.description,
        item.type,
        item.parentRecordId
      ],
      data: item
    }));
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
