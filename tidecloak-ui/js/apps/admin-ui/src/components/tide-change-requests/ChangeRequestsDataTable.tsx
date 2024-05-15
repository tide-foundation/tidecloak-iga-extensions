import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { KeycloakDataTable } from "../table-toolbar/KeycloakDataTable";
import { KeycloakSpinner } from "../keycloak-spinner/KeycloakSpinner";

import { useAlerts } from '../alert/Alerts';
import type { IRow } from '@patternfly/react-table';
import type RequestedChanges from "@keycloak/keycloak-admin-client/lib/defs/RequestedChanges";
import { adminClient } from '../../admin-client';

export const ChangeRequestsDataTable = () => {
  const { t } = useTranslation();
  const [data, setData] = useState<RequestedChanges[]>([]);
  const [loading, setLoading] = useState(true);
  const { addAlert } = useAlerts();

  useEffect(() => {
    async function fetchData() {
      try {
        const response = await adminClient.tideUserExt.getRequestedChanges();
        if (response) {
          setData(response);
        }
        setLoading(false);
      } catch (error) {
        console.error('Failed to fetch data:', error);
        // addAlert(t('dataFetchError'), 'danger');
        setLoading(false);
      }
    }

    fetchData();
  }, [addAlert, t]);

  const columns: ICell[] = [
    {
      title: 'Description',
      cellFormatters: [(cellValue, row) => row.data.description],
    },
    {
      title: 'Type',
      cellFormatters: [(cellValue, row) => row.data.type],
    },
    {
      title: 'Parent Record ID',
      cellFormatters: [(cellValue, row) => row.data.parentRecordId],
    },
  ];

  const loader = async () => {
    return data.map((item, idx) => ({
      cells: [item.description, item.type, item.parentRecordId],
      isOpen: false,
      parent: idx * 2,
      data: item // Storing the full item object here for use in cellFormatters
    }));
  };

  if (loading) return <KeycloakSpinner />;

  return (
    <div>
      <KeycloakDataTable
        isSearching={false}
        loader={loader}
        ariaLabelKey="Requested Changes"
        columns={columns}
        isPaginated={true}
        onSelect={(rows: IRow[]) => console.log("Selected rows:", rows)}
        emptyState={<div>No requested changes found.</div>}
      />
    </div>
  );
};
