// SPDX-License-Identifier: Apache-2.0

//! Append-only PostgreSQL storage for disclosure-controlled statistical releases.

use tokio_postgres::GenericClient;

use crate::postgres::{RuntimeRevoke, SqlIdentifier};

/// Runtime-visible release tables and their exact privileges.
pub(crate) const STATISTICS_TABLES: &[(&str, &[&str])] = &[
    (
        "registry_statistical_release_versions",
        &["INSERT", "SELECT"],
    ),
    (
        "registry_statistical_release_contents",
        &["INSERT", "SELECT"],
    ),
    ("registry_statistical_release_withdrawals", &["SELECT"]),
];

pub(crate) const WITHDRAWAL_FUNCTION: &str =
    "registry_internal.withdraw_statistical_release(text, text, bigint, text)";

/// The largest canonical release document retained in one version.
pub(crate) const MAX_RELEASE_CONTENT_BYTES: usize =
    crate::compiler::MAX_STATISTICAL_RELEASE_DOCUMENT_BYTES;

/// Install the engine-owned release store with no runtime update or delete authority.
pub(crate) async fn install(
    migration: &impl GenericClient,
    runtime_role: &SqlIdentifier,
) -> Result<(), tokio_postgres::Error> {
    let revoke = RuntimeRevoke::detect(migration, runtime_role)
        .await?
        .with_public();
    migration
        .batch_execute(&format!(
            "CREATE TABLE IF NOT EXISTS registry_internal.registry_statistical_release_versions (
                 dataset_id text NOT NULL CHECK (
                     dataset_id <> '' AND octet_length(dataset_id) <= 64
                 ),
                 period_code text NOT NULL CHECK (
                     period_code <> '' AND octet_length(period_code) <= 10
                 ),
                 release_version bigint NOT NULL CHECK (release_version > 0),
                 release_status text NOT NULL CHECK (
                     release_status IN ('provisional', 'final')
                 ),
                 history_head_position bigint NOT NULL CHECK (history_head_position >= 0),
                 snapshot_reference uuid,
                 computed_at timestamptz NOT NULL,
                 package_digest text NOT NULL CHECK (
                     package_digest ~ '^sha256:[0-9a-f]{{64}}$'
                 ),
                 definition_digest text NOT NULL CHECK (
                     definition_digest ~ '^sha256:[0-9a-f]{{64}}$'
                 ),
                 content_digest text NOT NULL CHECK (
                     content_digest ~ '^sha256:[0-9a-f]{{64}}$'
                 ),
                 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 PRIMARY KEY (dataset_id, period_code, release_version)
             );
             CREATE TABLE IF NOT EXISTS registry_internal.registry_statistical_release_contents (
                 dataset_id text NOT NULL,
                 period_code text NOT NULL,
                 release_version bigint NOT NULL,
                 document bytea NOT NULL CHECK (
                     octet_length(document) BETWEEN 1 AND {MAX_RELEASE_CONTENT_BYTES}
                 ),
                 PRIMARY KEY (dataset_id, period_code, release_version),
                 FOREIGN KEY (dataset_id, period_code, release_version)
                     REFERENCES registry_internal.registry_statistical_release_versions
                         (dataset_id, period_code, release_version)
                     ON DELETE RESTRICT
             );
             CREATE TABLE IF NOT EXISTS registry_internal.registry_statistical_release_withdrawals (
                 dataset_id text NOT NULL,
                 period_code text NOT NULL,
                 release_version bigint NOT NULL,
                 withdrawn_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 reason_code text NOT NULL CHECK (
                     reason_code IN ('computation-error', 'source-data-error', 'disclosure-risk')
                 ),
                 PRIMARY KEY (dataset_id, period_code, release_version),
                 FOREIGN KEY (dataset_id, period_code, release_version)
                     REFERENCES registry_internal.registry_statistical_release_versions
                         (dataset_id, period_code, release_version)
                     ON DELETE RESTRICT
             );
             REVOKE ALL ON registry_internal.registry_statistical_release_versions,
                 registry_internal.registry_statistical_release_contents,
                 registry_internal.registry_statistical_release_withdrawals FROM {revoke};
             GRANT SELECT, INSERT
                 ON registry_internal.registry_statistical_release_versions,
                    registry_internal.registry_statistical_release_contents TO {role};
             GRANT SELECT
                 ON registry_internal.registry_statistical_release_withdrawals TO {role};
             CREATE OR REPLACE FUNCTION registry_internal.withdraw_statistical_release(
                 text, text, bigint, text
             ) RETURNS boolean LANGUAGE sql VOLATILE SECURITY DEFINER
                SET search_path = pg_catalog, registry_internal AS $body$
                WITH recorded AS (
                    INSERT INTO registry_internal.registry_statistical_release_withdrawals
                        (dataset_id, period_code, release_version, reason_code)
                    SELECT $1, $2, $3, $4
                    FROM registry_internal.registry_statistical_release_versions AS version
                    WHERE version.dataset_id = $1
                      AND version.period_code = $2
                      AND version.release_version = $3
                      AND NOT EXISTS (
                          SELECT 1
                          FROM registry_internal.registry_statistical_release_withdrawals AS prior
                          WHERE prior.dataset_id = $1
                            AND prior.period_code = $2
                            AND prior.release_version = $3
                      )
                    ON CONFLICT (dataset_id, period_code, release_version) DO NOTHING
                    RETURNING dataset_id, period_code, release_version
                ), removed AS (
                    DELETE FROM registry_internal.registry_statistical_release_contents AS content
                    USING recorded
                    WHERE content.dataset_id = recorded.dataset_id
                      AND content.period_code = recorded.period_code
                      AND content.release_version = recorded.release_version
                    RETURNING 1
                ) SELECT EXISTS (SELECT 1 FROM removed);
                $body$;
             REVOKE ALL ON FUNCTION registry_internal.withdraw_statistical_release(
                 text, text, bigint, text
             ) FROM {revoke};
             GRANT EXECUTE ON FUNCTION registry_internal.withdraw_statistical_release(
                 text, text, bigint, text
             ) TO {role};",
            role = runtime_role.quoted(),
        ))
        .await
}
