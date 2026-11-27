-- SPDX-License-Identifier: Apache-2.0
--
-- The activation ledger records the posture the activating process declared.
-- A row written before this column existed reads production: a database that
-- was never activated in development can never read as development.
ALTER TABLE casework_activations
    ADD COLUMN posture text NOT NULL DEFAULT 'production'
        CHECK (posture IN ('development', 'production'));
ALTER TABLE casework_activations ALTER COLUMN posture DROP DEFAULT;
