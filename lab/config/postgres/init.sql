-- SPDX-License-Identifier: Apache-2.0
-- Create the Zitadel database beside the disposable registry_lab database.
SELECT 'CREATE DATABASE zitadel'
WHERE NOT EXISTS (
    SELECT FROM pg_database WHERE datname = 'zitadel'
)\gexec
