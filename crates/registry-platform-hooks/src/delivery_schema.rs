// SPDX-License-Identifier: Apache-2.0

//! The delivery schema: the event store and its delivery bookkeeping tables.
//!
//! Decision 1(b) of the platform hooks design: the tables are library-owned
//! and each product's kernel install includes these statements into its own
//! migration, the way a product includes a shipped migration. The statements
//! are rendered with the product's schema name; BReg installs them into
//! `registry_internal`.
//!
//! Every rendered statement is byte-identical to the statement the owning
//! product executed before the move, so existing databases upgrade in place
//! through the same idempotent `CREATE`/`ALTER`/`DO` sequence. The statements
//! are ordered: the deliveries table carries a foreign key into the outbox, so
//! the outbox is created first.
//!
//! The schema name is interpolated into DDL, so only a plain lowercase SQL
//! identifier is accepted; [`statements`] panics otherwise.

use tokio_postgres::GenericClient;

// Rendered statement templates, in execution order. `{schema}` is replaced
// with the product's schema name. The layout bytes are the ones the owning
// product executed before the move, so a rendered statement is
// byte-identical to the statement BReg ran while it carried this DDL
// inline.
const DELIVERY_STATEMENTS: &[&str] = &[
    // registry_outbox, the envelope store. Created first: the deliveries
    // table carries a foreign key into it.
    "             CREATE TABLE IF NOT EXISTS {schema}.registry_outbox (
                 outbox_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                 event_id uuid NOT NULL UNIQUE,
                 event_type text NOT NULL CHECK (event_type <> ''),
                 trigger text NOT NULL CHECK (trigger IN ('created', 'patched', 'tombstoned', 'request_lifecycle')),
                 entity_id text NOT NULL CHECK (entity_id <> ''),
                 record_reference text NOT NULL CHECK (record_reference <> ''),
                 record_revision bigint NOT NULL CHECK (record_revision > 0),
                 application_reference text CHECK (application_reference IS NULL OR application_reference <> ''),
                 package_revision text NOT NULL CHECK (package_revision <> ''),
                 schema_fingerprint text NOT NULL CHECK (schema_fingerprint <> ''),
                 payload bytea
                     CONSTRAINT registry_outbox_payload_bounds CHECK (
                         payload IS NULL OR
                         (octet_length(payload) > 0 AND octet_length(payload) <= 2097152)
                     ),
                 payload_expires_at timestamptz NOT NULL,
                 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 UNIQUE (event_id, package_revision, schema_fingerprint)
             );",
    "             CREATE TABLE IF NOT EXISTS {schema}.registry_webhook_deliveries (
                 event_id uuid NOT NULL,
                 compiled_delivery_id text NOT NULL
                     CHECK (compiled_delivery_id <> '' AND octet_length(compiled_delivery_id) <= 256),
                 logical_destination_id text NOT NULL
                     CHECK (logical_destination_id ~ '^[a-z][a-z0-9_-]{0,63}$'),
                 destination_binding_digest text NOT NULL
                     CHECK (destination_binding_digest ~ '^sha256:[0-9a-f]{64}$'),
                 package_revision text NOT NULL
                     CHECK (package_revision <> '' AND octet_length(package_revision) <= 256),
                 schema_fingerprint text NOT NULL
                     CHECK (schema_fingerprint <> '' AND octet_length(schema_fingerprint) <= 256),
                 data_schema text NOT NULL
                     CONSTRAINT registry_webhook_delivery_data_schema_bounds CHECK (
                         data_schema <> '' AND octet_length(data_schema) <= 2048
                     ),
                 classification_ceiling text NOT NULL
                     CHECK (classification_ceiling IN ('public', 'internal', 'restricted')),
                 authentication_profile text NOT NULL
                     CHECK (authentication_profile = 'hmac_sha256_v1'),
                 delivery_mode text NOT NULL CHECK (delivery_mode = 'after_commit'),
                 attempt_timeout_ms bigint NOT NULL
                     CHECK (attempt_timeout_ms BETWEEN 100 AND 10000),
                 initial_backoff_ms bigint NOT NULL
                     CHECK (initial_backoff_ms BETWEEN 100 AND 3600000),
                 maximum_backoff_ms bigint NOT NULL
                     CHECK (maximum_backoff_ms BETWEEN initial_backoff_ms AND 3600000),
                 exponential_backoff_multiplier smallint NOT NULL
                     CHECK (exponential_backoff_multiplier = 2),
                 maximum_attempts smallint NOT NULL
                     CHECK (maximum_attempts BETWEEN 1 AND 20),
                 retry_delays_ms bigint[] NOT NULL
                     CHECK (
                         cardinality(retry_delays_ms) = maximum_attempts - 1
                         AND array_position(retry_delays_ms, NULL) IS NULL
                         AND initial_backoff_ms <= ALL(retry_delays_ms)
                         AND maximum_backoff_ms >= ALL(retry_delays_ms)
                     ),
                 maximum_payload_bytes bigint NOT NULL
                     CHECK (maximum_payload_bytes BETWEEN 1 AND 1048576),
                 payload_digest bytea NOT NULL CHECK (octet_length(payload_digest) = 32),
                 deployed_attempt_timeout_ms bigint NOT NULL
                     CHECK (deployed_attempt_timeout_ms BETWEEN 100 AND attempt_timeout_ms),
                 deployed_maximum_attempts smallint NOT NULL
                     CHECK (deployed_maximum_attempts BETWEEN 1 AND maximum_attempts),
                 dead_letter text NOT NULL CHECK (dead_letter = 'required'),
                 operator_replay boolean NOT NULL,
                 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 PRIMARY KEY (event_id, compiled_delivery_id),
                 FOREIGN KEY (event_id, package_revision, schema_fingerprint)
                     REFERENCES {schema}.registry_outbox
                         (event_id, package_revision, schema_fingerprint)
                     ON DELETE RESTRICT
             );",
    "             CREATE TABLE IF NOT EXISTS {schema}.registry_webhook_delivery_state (
                 event_id uuid NOT NULL,
                 compiled_delivery_id text NOT NULL
                     CHECK (compiled_delivery_id <> '' AND octet_length(compiled_delivery_id) <= 256),
                 generation bigint NOT NULL CHECK (generation > 0),
                 state text NOT NULL
                     CONSTRAINT registry_webhook_delivery_state_values CHECK (
                         state IN ('pending', 'leased', 'delivered', 'dead_lettered', 'expired')
                     ),
                 attempt smallint NOT NULL CHECK (attempt BETWEEN 0 AND 20),
                 next_attempt_at timestamptz,
                 attempt_started_at timestamptz,
                 lease_expires_at timestamptz,
                 lease_token uuid,
                 delivered_at timestamptz,
                 dead_lettered_at timestamptz,
                 expired_at timestamptz,
                 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 PRIMARY KEY (event_id, compiled_delivery_id),
                 FOREIGN KEY (event_id, compiled_delivery_id)
                     REFERENCES {schema}.registry_webhook_deliveries
                         (event_id, compiled_delivery_id)
                     ON DELETE RESTRICT,
                 CONSTRAINT registry_webhook_delivery_state_shape CHECK (
                     (state = 'pending'
                         AND next_attempt_at IS NOT NULL
                         AND attempt_started_at IS NULL
                         AND lease_expires_at IS NULL
                         AND lease_token IS NULL
                         AND delivered_at IS NULL
                         AND dead_lettered_at IS NULL
                         AND expired_at IS NULL)
                     OR (state = 'leased'
                         AND attempt > 0
                         AND next_attempt_at IS NULL
                         AND attempt_started_at IS NOT NULL
                         AND lease_expires_at > attempt_started_at
                         AND lease_token IS NOT NULL
                         AND delivered_at IS NULL
                         AND dead_lettered_at IS NULL
                         AND expired_at IS NULL)
                     OR (state = 'delivered'
                         AND attempt > 0
                         AND next_attempt_at IS NULL
                         AND attempt_started_at IS NULL
                         AND lease_expires_at IS NULL
                         AND lease_token IS NULL
                         AND delivered_at IS NOT NULL
                         AND dead_lettered_at IS NULL
                         AND expired_at IS NULL)
                     OR (state = 'dead_lettered'
                         AND attempt > 0
                         AND next_attempt_at IS NULL
                         AND attempt_started_at IS NULL
                         AND lease_expires_at IS NULL
                         AND lease_token IS NULL
                         AND delivered_at IS NULL
                         AND dead_lettered_at IS NOT NULL)
                     OR (state = 'expired'
                         AND next_attempt_at IS NULL
                         AND attempt_started_at IS NULL
                         AND lease_expires_at IS NULL
                         AND lease_token IS NULL
                         AND delivered_at IS NULL
                         AND dead_lettered_at IS NULL
                         AND expired_at IS NOT NULL)
                 )
             );",
    // Delivery-state work indexes.
    "             CREATE INDEX IF NOT EXISTS registry_webhook_delivery_state_due_idx
                 ON {schema}.registry_webhook_delivery_state
                     (next_attempt_at, event_id, compiled_delivery_id)
                 WHERE state = 'pending';",
    "             CREATE INDEX IF NOT EXISTS registry_webhook_delivery_state_expired_idx
                 ON {schema}.registry_webhook_delivery_state
                     (lease_expires_at, event_id, compiled_delivery_id)
                 WHERE state = 'leased';",
    // Idempotent upgrades for databases activated by earlier engine builds,
    // where `CREATE TABLE IF NOT EXISTS` did not evolve these tables: legacy
    // outbox rows receive the conservative seven-day default from their
    // original capture time, and a legacy webhook row has no V1 data-schema
    // binding, so it cannot safely be reinterpreted as a V1 delivery and
    // requires explicit operator migration.
    "ALTER TABLE {schema}.registry_outbox
                 ADD COLUMN IF NOT EXISTS payload_expires_at timestamptz;",
    "             ALTER TABLE {schema}.registry_outbox
                 ADD COLUMN IF NOT EXISTS application_reference text
                     CHECK (application_reference IS NULL OR application_reference <> '');",
    "             ALTER TABLE {schema}.registry_outbox
                 DROP CONSTRAINT IF EXISTS registry_outbox_trigger_check;",
    "             ALTER TABLE {schema}.registry_outbox
                 ADD CONSTRAINT registry_outbox_trigger_check
                     CHECK (trigger IN ('created', 'patched', 'tombstoned', 'request_lifecycle'));",
    "             UPDATE {schema}.registry_outbox
                SET payload_expires_at = created_at + interval '7 days'
              WHERE payload_expires_at IS NULL;",
    // The deliveries/state upgrade blocks refuse pre-V1 webhook history
    // and restore the per-state shape constraints.
    "             DO $registry_outbox_upgrade$
             BEGIN
                 IF EXISTS (
                     SELECT 1 FROM pg_catalog.pg_attribute
                      WHERE attrelid = '{schema}.registry_outbox'::regclass
                        AND attname = 'payload' AND attnotnull
                 ) THEN
                     ALTER TABLE {schema}.registry_outbox
                         ALTER COLUMN payload DROP NOT NULL;
                 END IF;
                 IF EXISTS (
                     SELECT 1 FROM pg_catalog.pg_constraint
                      WHERE conrelid = '{schema}.registry_outbox'::regclass
                        AND conname = 'registry_outbox_payload_check'
                 ) THEN
                     ALTER TABLE {schema}.registry_outbox
                         DROP CONSTRAINT registry_outbox_payload_check;
                 END IF;
                 IF NOT EXISTS (
                     SELECT 1 FROM pg_catalog.pg_constraint
                      WHERE conrelid = '{schema}.registry_outbox'::regclass
                        AND conname = 'registry_outbox_payload_bounds'
                 ) THEN
                     ALTER TABLE {schema}.registry_outbox
                         ADD CONSTRAINT registry_outbox_payload_bounds CHECK (
                             payload IS NULL OR
                             (octet_length(payload) > 0 AND octet_length(payload) <= 2097152)
                         );
                 END IF;
                 IF EXISTS (
                     SELECT 1 FROM pg_catalog.pg_attribute
                      WHERE attrelid = '{schema}.registry_outbox'::regclass
                        AND attname = 'payload_expires_at' AND NOT attnotnull
                 ) THEN
                     ALTER TABLE {schema}.registry_outbox
                         ALTER COLUMN payload_expires_at SET NOT NULL;
                 END IF;
             END
             $registry_outbox_upgrade$;",
    "             ALTER TABLE {schema}.registry_webhook_deliveries
                 ADD COLUMN IF NOT EXISTS data_schema text;",
    "             DO $registry_webhook_delivery_upgrade$
             BEGIN
                 IF EXISTS (
                     SELECT 1
                       FROM {schema}.registry_webhook_deliveries
                      WHERE data_schema IS NULL
                 ) THEN
                     RAISE EXCEPTION USING
                         MESSAGE = 'pre-V1 webhook history requires explicit operator migration';
                 END IF;
                 IF EXISTS (
                     SELECT 1 FROM pg_catalog.pg_attribute
                      WHERE attrelid =
                            '{schema}.registry_webhook_deliveries'::regclass
                        AND attname = 'data_schema' AND NOT attnotnull
                 ) THEN
                     ALTER TABLE {schema}.registry_webhook_deliveries
                         ALTER COLUMN data_schema SET NOT NULL;
                 END IF;
                 IF NOT EXISTS (
                     SELECT 1 FROM pg_catalog.pg_constraint
                      WHERE conrelid =
                            '{schema}.registry_webhook_deliveries'::regclass
                        AND conname = 'registry_webhook_delivery_data_schema_bounds'
                 ) THEN
                     ALTER TABLE {schema}.registry_webhook_deliveries
                         ADD CONSTRAINT registry_webhook_delivery_data_schema_bounds CHECK (
                             data_schema <> '' AND octet_length(data_schema) <= 2048
                         );
                 END IF;
             END
             $registry_webhook_delivery_upgrade$;",
    "             ALTER TABLE {schema}.registry_webhook_delivery_state
                 ADD COLUMN IF NOT EXISTS expired_at timestamptz;",
    "             DO $registry_webhook_state_upgrade$
             BEGIN
                 IF EXISTS (
                     SELECT 1 FROM pg_catalog.pg_constraint
                      WHERE conrelid =
                            '{schema}.registry_webhook_delivery_state'::regclass
                        AND conname = 'registry_webhook_delivery_state_state_check'
                 ) THEN
                     ALTER TABLE {schema}.registry_webhook_delivery_state
                         DROP CONSTRAINT registry_webhook_delivery_state_state_check;
                 END IF;
                 IF EXISTS (
                     SELECT 1 FROM pg_catalog.pg_constraint
                      WHERE conrelid =
                            '{schema}.registry_webhook_delivery_state'::regclass
                        AND conname = 'registry_webhook_delivery_state_check'
                 ) THEN
                     ALTER TABLE {schema}.registry_webhook_delivery_state
                         DROP CONSTRAINT registry_webhook_delivery_state_check;
                 END IF;
                 IF NOT EXISTS (
                     SELECT 1 FROM pg_catalog.pg_constraint
                      WHERE conrelid =
                            '{schema}.registry_webhook_delivery_state'::regclass
                        AND conname = 'registry_webhook_delivery_state_values'
                 ) THEN
                     ALTER TABLE {schema}.registry_webhook_delivery_state
                         ADD CONSTRAINT registry_webhook_delivery_state_values CHECK (
                             state IN (
                                 'pending', 'leased', 'delivered', 'dead_lettered', 'expired'
                             )
                         );
                 END IF;
                 IF NOT EXISTS (
                     SELECT 1 FROM pg_catalog.pg_constraint
                      WHERE conrelid =
                            '{schema}.registry_webhook_delivery_state'::regclass
                        AND conname = 'registry_webhook_delivery_state_shape'
                 ) THEN
                     ALTER TABLE {schema}.registry_webhook_delivery_state
                         ADD CONSTRAINT registry_webhook_delivery_state_shape CHECK (
                             (state = 'pending'
                                 AND next_attempt_at IS NOT NULL
                                 AND attempt_started_at IS NULL
                                 AND lease_expires_at IS NULL
                                 AND lease_token IS NULL
                                 AND delivered_at IS NULL
                                 AND dead_lettered_at IS NULL
                                 AND expired_at IS NULL)
                             OR (state = 'leased'
                                 AND attempt > 0
                                 AND next_attempt_at IS NULL
                                 AND attempt_started_at IS NOT NULL
                                 AND lease_expires_at > attempt_started_at
                                 AND lease_token IS NOT NULL
                                 AND delivered_at IS NULL
                                 AND dead_lettered_at IS NULL
                                 AND expired_at IS NULL)
                             OR (state = 'delivered'
                                 AND attempt > 0
                                 AND next_attempt_at IS NULL
                                 AND attempt_started_at IS NULL
                                 AND lease_expires_at IS NULL
                                 AND lease_token IS NULL
                                 AND delivered_at IS NOT NULL
                                 AND dead_lettered_at IS NULL
                                 AND expired_at IS NULL)
                             OR (state = 'dead_lettered'
                                 AND attempt > 0
                                 AND next_attempt_at IS NULL
                                 AND attempt_started_at IS NULL
                                 AND lease_expires_at IS NULL
                                 AND lease_token IS NULL
                                 AND delivered_at IS NULL
                                 AND dead_lettered_at IS NOT NULL)
                             OR (state = 'expired'
                                 AND next_attempt_at IS NULL
                                 AND attempt_started_at IS NULL
                                 AND lease_expires_at IS NULL
                                 AND lease_token IS NULL
                                 AND delivered_at IS NULL
                                 AND dead_lettered_at IS NULL
                                 AND expired_at IS NOT NULL)
                         );
                 END IF;
             END
             $registry_webhook_state_upgrade$;",
];

/// Installs the delivery schema statements in order on the caller's client.
///
/// The statements join the caller's transaction; this function performs no
/// transaction management of its own.
pub async fn install(
    client: &impl GenericClient,
    schema: &str,
) -> Result<(), tokio_postgres::Error> {
    for statement in statements(schema) {
        client.batch_execute(&statement).await?;
    }
    Ok(())
}

/// The ordered, complete statement list for the delivery tables: creation,
/// upgrade `ALTER`s, rebuild `DO` blocks, and indexes, each schema-qualified.
///
/// # Panics
///
/// Panics when `schema` is not a plain lowercase SQL identifier of at most 63
/// bytes, because the name is interpolated directly into the statements.
pub fn statements(schema: &str) -> Vec<String> {
    let schema = require_plain_identifier(schema);
    DELIVERY_STATEMENTS
        .iter()
        .map(|template| template.replace("{schema}", schema))
        .collect()
}

fn require_plain_identifier(schema: &str) -> &str {
    let valid = !schema.is_empty()
        && schema.len() <= 63
        && schema
            .bytes()
            .next()
            .is_some_and(|byte| byte == b'_' || byte.is_ascii_lowercase())
        && schema
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_lowercase() || byte.is_ascii_digit());
    assert!(
        valid,
        "delivery schema must be a plain lowercase SQL identifier of at most 63 bytes"
    );
    schema
}

#[cfg(test)]
mod tests {
    use super::*;

    const KERNEL_SCHEMA: &str = "registry_internal";

    fn rendered(schema: &str) -> Vec<String> {
        statements(schema)
    }

    #[test]
    fn the_three_delivery_tables_are_created_in_foreign_key_order() {
        let statements = rendered(KERNEL_SCHEMA);
        let creation_prefixes = [
            format!("CREATE TABLE IF NOT EXISTS {KERNEL_SCHEMA}.registry_outbox ("),
            format!("CREATE TABLE IF NOT EXISTS {KERNEL_SCHEMA}.registry_webhook_deliveries ("),
            format!("CREATE TABLE IF NOT EXISTS {KERNEL_SCHEMA}.registry_webhook_delivery_state ("),
        ];
        let positions = creation_prefixes.map(|prefix| {
            statements
                .iter()
                .position(|statement| statement.trim_start().starts_with(&prefix))
                .expect("creation statement is present")
        });
        assert!(positions[0] < positions[1] && positions[1] < positions[2]);
        let deliveries = &statements[positions[1]];
        assert!(deliveries.contains(&format!(
            "FOREIGN KEY (event_id, package_revision, schema_fingerprint)
                     REFERENCES {KERNEL_SCHEMA}.registry_outbox"
        )));
        let state = &statements[positions[2]];
        assert!(state.contains(&format!(
            "FOREIGN KEY (event_id, compiled_delivery_id)
                     REFERENCES {KERNEL_SCHEMA}.registry_webhook_deliveries"
        )));
    }

    #[test]
    fn the_partial_indexes_keep_their_state_predicates() {
        let statements = rendered(KERNEL_SCHEMA).join("\n");
        assert!(statements.contains(&format!(
            "CREATE INDEX IF NOT EXISTS registry_webhook_delivery_state_due_idx
                 ON {KERNEL_SCHEMA}.registry_webhook_delivery_state
                     (next_attempt_at, event_id, compiled_delivery_id)
                 WHERE state = 'pending'"
        )));
        assert!(statements.contains(&format!(
            "CREATE INDEX IF NOT EXISTS registry_webhook_delivery_state_expired_idx
                 ON {KERNEL_SCHEMA}.registry_webhook_delivery_state
                     (lease_expires_at, event_id, compiled_delivery_id)
                 WHERE state = 'leased'"
        )));
    }

    #[test]
    fn the_outbox_payload_stays_bounded_at_two_mebibytes() {
        let statements = rendered(KERNEL_SCHEMA);
        let bounds = statements
            .iter()
            .filter(|statement| {
                statement.contains("registry_outbox_payload_bounds CHECK (")
                    && statement.contains("octet_length(payload) > 0")
                    && statement.contains("octet_length(payload) <= 2097152")
            })
            .count();
        // The bound exists both on the fresh creation and in the upgrade
        // block that rebuilds it on databases from earlier engine builds.
        assert_eq!(bounds, 2);
    }

    #[test]
    fn every_statement_is_qualified_by_the_schema() {
        let statements = rendered(KERNEL_SCHEMA);
        assert_eq!(statements.len(), 15);
        for statement in &statements {
            assert!(
                statement.contains(KERNEL_SCHEMA),
                "statement is not schema-qualified: {statement}"
            );
            assert!(statement.trim_end().ends_with(';'));
        }
    }

    #[test]
    fn a_different_schema_requalifies_every_reference() {
        let other_schema = "observability_internal";
        let baseline = rendered(KERNEL_SCHEMA).join("\n");
        let other = rendered(other_schema).join("\n");
        assert!(!other.contains(KERNEL_SCHEMA));
        assert_eq!(
            other,
            baseline.replace(&format!("{KERNEL_SCHEMA}."), &format!("{other_schema}."),)
        );
    }

    #[test]
    fn the_delivery_pattern_bounds_survive_rendering() {
        let statements = rendered(KERNEL_SCHEMA).join("\n");
        assert!(statements.contains("'^[a-z][a-z0-9_-]{0,63}$'"));
        assert!(statements.contains("'^sha256:[0-9a-f]{64}$'"));
    }

    #[test]
    #[should_panic(expected = "delivery schema must be a plain lowercase SQL identifier")]
    fn a_schema_that_is_not_a_plain_identifier_is_refused() {
        let _ = statements("registry; drop table users");
    }

    #[test]
    #[should_panic(expected = "delivery schema must be a plain lowercase SQL identifier")]
    fn an_empty_or_uppercase_schema_is_refused() {
        let _ = statements("");
        let _ = statements("Registry_Internal");
    }
}
