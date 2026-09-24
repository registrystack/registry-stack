-- SPDX-License-Identifier: Apache-2.0
--
-- The package ledger: one row for each package a deployment activated, in
-- activation order. The digest is the package identity the runtime verified;
-- the runtime version is the binary that activated it.
CREATE TABLE messaging_package_ledger (
    sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    package_digest text NOT NULL CHECK (package_digest ~ '^sha256:[0-9a-f]{64}$'),
    runtime_version text NOT NULL CHECK (length(runtime_version) BETWEEN 1 AND 64),
    activated_at timestamptz NOT NULL
);
