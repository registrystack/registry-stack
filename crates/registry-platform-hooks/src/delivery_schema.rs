// SPDX-License-Identifier: Apache-2.0

//! The delivery schema: the event store and its delivery bookkeeping tables.
//!
//! Decision 1(b) of the platform hooks design: the tables are library-owned
//! and each product's kernel install includes these statements into its own
//! migration, the way a product includes a shipped migration. The statements
//! are rendered with the adopting product's schema name.
//!
//! The statements are idempotent: a `CREATE ... IF NOT EXISTS` sequence, and
//! one upgrade that adds the dead-letter reason to a delivery-state table
//! created without it. Installing them again over the schema they created
//! changes nothing. They are ordered: the deliveries table carries a foreign
//! key into the outbox, so the outbox is created first.
//!
//! Installing the statements installs no ACL. Privileges on the delivery
//! objects stay with the adopting product: it owns every `GRANT` and
//! `REVOKE` deciding which roles may read or write them, and [`object_names`]
//! names the objects its inventory has to cover.
//!
//! The schema name is interpolated into DDL, so only a plain lowercase SQL
//! identifier is accepted; [`statements`] panics otherwise.

use tokio_postgres::GenericClient;

// Statement templates, in execution order. `{schema}` is replaced with the
// adopting product's schema name.
const DELIVERY_STATEMENTS: &[&str] = &[
    // registry_outbox, the envelope store. Created first: the deliveries
    // table carries a foreign key into it.
    "             CREATE TABLE IF NOT EXISTS {schema}.registry_outbox (
                 outbox_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                 event_id uuid NOT NULL UNIQUE,
                 event_type text NOT NULL CHECK (event_type <> ''),
                 trigger text NOT NULL
                     CONSTRAINT registry_outbox_trigger_check CHECK (
                         trigger <> '' AND octet_length(trigger) <= 128
                     ),
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
                 handler_kind text NOT NULL
                     CONSTRAINT registry_webhook_delivery_handler_kind_values CHECK (
                         handler_kind IN ('url', 'rhai', 'wasm')
                     ),
                 logical_destination_id text
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
                     CHECK (authentication_profile = 'hmac-sha256-v1'),
                 delivery_mode text NOT NULL CHECK (delivery_mode = 'after-commit'),
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
                     ON DELETE RESTRICT,
                 CONSTRAINT registry_webhook_delivery_handler_binding CHECK (
                     (handler_kind = 'url' AND logical_destination_id IS NOT NULL)
                     OR (handler_kind IN ('rhai', 'wasm')
                         AND logical_destination_id IS NULL)
                 )
             );",
    "             CREATE TABLE IF NOT EXISTS {schema}.registry_webhook_delivery_state (
                 event_id uuid NOT NULL,
                 compiled_delivery_id text NOT NULL
                     CHECK (compiled_delivery_id <> '' AND octet_length(compiled_delivery_id) <= 256),
                 generation bigint NOT NULL CHECK (generation > 0),
                 state text NOT NULL
                     CONSTRAINT registry_webhook_delivery_state_values CHECK (
                         state IN ('pending', 'leased', 'delivered', 'dead-lettered', 'expired')
                     ),
                 attempt smallint NOT NULL CHECK (attempt BETWEEN 0 AND 20),
                 next_attempt_at timestamptz,
                 attempt_started_at timestamptz,
                 lease_expires_at timestamptz,
                 lease_token uuid,
                 delivered_at timestamptz,
                 dead_lettered_at timestamptz,
                 expired_at timestamptz,
                 dead_letter_reason text
                     CONSTRAINT registry_webhook_delivery_state_dead_letter_reason_values CHECK (
                         dead_letter_reason IS NULL OR dead_letter_reason IN (
                             'http-non-success', 'destination-timeout',
                             'invalid-remaining-timeout', 'invalid-frozen-policy',
                             'invalid-frozen-request', 'resolution-failed',
                             'resolution-capacity-unavailable', 'too-many-resolver-answers',
                             'no-resolver-answers', 'resolver-port-mismatch',
                             'resolver-address-family-mismatch', 'literal-origin-mismatch',
                             'cloud-metadata-denied', 'always-denied-address',
                             'private-address-not-allowed', 'non-global-address-denied',
                             'development-address-denied', 'tls-material-unavailable',
                             'client-build-failed', 'transport-failed',
                             'transport-failed-after-connect', 'deadline-exceeded',
                             'deadline-exceeded-after-connect', 'too-many-response-headers',
                             'response-header-bytes-exceeded', 'destination-policy-refused',
                             'destination-binding-refused', 'handler-binding-refused',
                             'handler-deadline', 'handler-resource', 'handler-execution',
                             'handler-source', 'handler-unavailable', 'payload-refused',
                             'worker-interrupted', 'proposal-dead-lettered'
                         )
                     ),
                 handler_message bytea,
                 handler_message_digest bytea,
                 proposal_disposition text
                     CONSTRAINT registry_webhook_delivery_state_proposal_values CHECK (
                         proposal_disposition IS NULL
                         OR proposal_disposition IN ('none', 'applied', 'refused', 'dead-lettered')
                     ),
                 proposal_resulting_revision bigint
                     CHECK (proposal_resulting_revision IS NULL OR proposal_resulting_revision > 0),
                 proposal_code text
                     CONSTRAINT registry_webhook_delivery_state_proposal_code_bounds CHECK (
                         proposal_code IS NULL
                         OR (proposal_code <> '' AND octet_length(proposal_code) <= 128)
                     ),
                 proposal_summary text
                     CONSTRAINT registry_webhook_delivery_state_proposal_summary_bounds CHECK (
                         proposal_summary IS NULL
                         OR (proposal_summary <> '' AND octet_length(proposal_summary) <= 1024)
                     ),
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
                     OR (state = 'dead-lettered'
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
                 ),
                 CONSTRAINT registry_webhook_delivery_state_answer_digest_required CHECK (
                     (handler_message IS NULL AND handler_message_digest IS NULL)
                     OR (state = 'delivered'
                         AND handler_message IS NULL
                         AND handler_message_digest IS NOT NULL
                         AND octet_length(handler_message_digest) = 32)
                 ),
                 CONSTRAINT registry_webhook_delivery_state_proposal CHECK (
                     (proposal_disposition IS NULL
                         AND proposal_resulting_revision IS NULL
                         AND proposal_code IS NULL
                         AND proposal_summary IS NULL)
                     OR (proposal_disposition = 'none'
                         AND proposal_resulting_revision IS NULL
                         AND proposal_code IS NULL
                         AND proposal_summary IS NULL)
                     OR (proposal_disposition = 'applied'
                         AND proposal_resulting_revision IS NOT NULL
                         AND proposal_code IS NULL
                         AND proposal_summary IS NULL)
                     OR (proposal_disposition IN ('refused', 'dead-lettered')
                         AND proposal_resulting_revision IS NULL
                         AND proposal_code IS NOT NULL
                         AND proposal_summary IS NOT NULL)
                 )
             );",
    // The dead-letter reason, for a delivery-state table created without it.
    // The release that introduced the reason serves such a table without
    // installing again, so the table still reaches this install without it.
    "             ALTER TABLE {schema}.registry_webhook_delivery_state
                 ADD COLUMN IF NOT EXISTS dead_letter_reason text;",
    "             DO $registry_webhook_state_recovery_upgrade$
             BEGIN
                 IF NOT EXISTS (
                     SELECT 1 FROM pg_catalog.pg_constraint
                      WHERE conrelid =
                            '{schema}.registry_webhook_delivery_state'::regclass
                        AND conname = 'registry_webhook_delivery_state_dead_letter_reason_values'
                 ) THEN
                     ALTER TABLE {schema}.registry_webhook_delivery_state
                         ADD CONSTRAINT registry_webhook_delivery_state_dead_letter_reason_values
                         CHECK (
                             dead_letter_reason IS NULL OR dead_letter_reason IN (
                                 'http-non-success', 'destination-timeout',
                                 'invalid-remaining-timeout', 'invalid-frozen-policy',
                                 'invalid-frozen-request', 'resolution-failed',
                                 'resolution-capacity-unavailable', 'too-many-resolver-answers',
                                 'no-resolver-answers', 'resolver-port-mismatch',
                                 'resolver-address-family-mismatch', 'literal-origin-mismatch',
                                 'cloud-metadata-denied', 'always-denied-address',
                                 'private-address-not-allowed', 'non-global-address-denied',
                                 'development-address-denied', 'tls-material-unavailable',
                                 'client-build-failed', 'transport-failed',
                                 'transport-failed-after-connect', 'deadline-exceeded',
                                 'deadline-exceeded-after-connect', 'too-many-response-headers',
                                 'response-header-bytes-exceeded', 'destination-policy-refused',
                                 'destination-binding-refused', 'handler-binding-refused',
                                 'handler-deadline', 'handler-resource', 'handler-execution',
                                 'handler-source', 'handler-unavailable', 'payload-refused',
                                 'worker-interrupted', 'proposal-dead-lettered'
                             )
                         );
                 END IF;
             END
             $registry_webhook_state_recovery_upgrade$;",
    // Delivery-state work indexes.
    "             CREATE INDEX IF NOT EXISTS registry_webhook_delivery_state_due_idx
                 ON {schema}.registry_webhook_delivery_state
                     (next_attempt_at, event_id, compiled_delivery_id)
                 WHERE state = 'pending';",
    "             CREATE INDEX IF NOT EXISTS registry_webhook_delivery_state_expired_idx
                 ON {schema}.registry_webhook_delivery_state
                     (lease_expires_at, event_id, compiled_delivery_id)
                 WHERE state = 'leased';",
];

// The persistent objects the statements above create, unqualified. The
// sequence is implicit: PostgreSQL names the one behind an identity column
// `<table>_<column>_seq`.
const DELIVERY_OBJECTS: &[&str] = &[
    "registry_outbox",
    "registry_outbox_outbox_id_seq",
    "registry_webhook_deliveries",
    "registry_webhook_delivery_state",
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

/// The ordered, complete statement list for the delivery tables: creation
/// and indexes, each schema-qualified.
///
/// # Panics
///
/// Panics when `schema` is not a plain lowercase SQL identifier of at most 63
/// bytes, because the name is interpolated directly into the statements.
pub fn statements(schema: &str) -> Vec<String> {
    let schema = require_plain_identifier(schema);
    DELIVERY_STATEMENTS
        .iter()
        .map(|template| render(schema, template))
        .collect()
}

/// The delivery objects [`statements`] creates, schema-qualified: the three
/// tables and the identity sequence PostgreSQL creates for the outbox's
/// `GENERATED ALWAYS AS IDENTITY` key.
///
/// A product that keeps an exact inventory of its database, or that grants
/// privileges object by object, reads the names from here instead of
/// repeating them, so a rename in this crate reaches it. Indexes are not
/// listed: they carry no privileges of their own.
///
/// # Panics
///
/// Panics when `schema` is not a plain lowercase SQL identifier of at most 63
/// bytes, for the same reason [`statements`] does.
pub fn object_names(schema: &str) -> Vec<String> {
    let schema = require_plain_identifier(schema);
    DELIVERY_OBJECTS
        .iter()
        .map(|object| format!("{schema}.{object}"))
        .collect()
}

/// Render one delivery SQL template with a product's schema name. `{schema}`
/// is the only placeholder, and the caller has already accepted the name
/// through [`require_plain_identifier`].
pub(crate) fn render(schema: &str, template: &str) -> String {
    template.replace("{schema}", schema)
}

pub(crate) fn require_plain_identifier(schema: &str) -> &str {
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
        assert_eq!(bounds, 1);
    }

    #[test]
    fn the_shared_outbox_bounds_but_does_not_own_product_triggers() {
        let statements = rendered(KERNEL_SCHEMA).join("\n");
        assert!(statements.contains("trigger <> '' AND octet_length(trigger) <= 128"));
        for product_trigger in ["created", "patched", "tombstoned", "request-lifecycle"] {
            assert!(
                !statements.contains(&format!("trigger IN ('{product_trigger}'")),
                "the shared schema must not freeze {product_trigger} as platform vocabulary"
            );
        }
    }

    #[test]
    fn a_local_handler_row_carries_no_destination() {
        let statements = rendered(KERNEL_SCHEMA);
        let pairings = statements
            .iter()
            .filter(|statement| {
                statement.contains("registry_webhook_delivery_handler_binding CHECK (")
                    && statement
                        .contains("handler_kind = 'url' AND logical_destination_id IS NOT NULL")
                    && statement.contains("handler_kind IN ('rhai', 'wasm')")
                    && statement.contains("AND logical_destination_id IS NULL")
            })
            .count();
        assert_eq!(pairings, 1);
    }

    #[test]
    fn a_recorded_answer_belongs_to_a_delivered_row() {
        let statements = rendered(KERNEL_SCHEMA);
        let answers = statements
            .iter()
            .filter(|statement| {
                statement.contains("registry_webhook_delivery_state_answer_digest_required CHECK (")
                    && statement
                        .contains("handler_message IS NULL AND handler_message_digest IS NULL")
                    && statement.contains("state = 'delivered'")
                    && statement
                        .lines()
                        .any(|line| line.trim() == "AND handler_message IS NULL")
                    && statement.contains("handler_message_digest IS NOT NULL")
                    && statement.contains("octet_length(handler_message_digest) = 32")
            })
            .count();
        assert_eq!(answers, 1);
    }

    #[test]
    fn a_delivery_row_records_what_became_of_its_proposal() {
        // The operator's question is answerable from the row alone: did the
        // accepted answer propose anything, and what became of the proposal?
        // Four dispositions, each with exactly its own companions.
        let statements = rendered(KERNEL_SCHEMA);
        let values = statements
            .iter()
            .filter(|statement| {
                statement.contains("registry_webhook_delivery_state_proposal_values CHECK (")
                    && statement.contains(
                        "proposal_disposition IN ('none', 'applied', 'refused', 'dead-lettered')",
                    )
            })
            .count();
        assert_eq!(values, 1, "the closed disposition vocabulary is installed");
        let combinations = statements
            .iter()
            .filter(|statement| {
                statement.contains("registry_webhook_delivery_state_proposal CHECK (")
                    && statement.contains("proposal_resulting_revision IS NOT NULL")
                    && statement.contains("proposal_code IS NOT NULL")
                    && statement.contains("proposal_summary IS NOT NULL")
            })
            .count();
        assert_eq!(
            combinations, 1,
            "each disposition carries exactly its own companions"
        );
        let joined = statements.join("\n");
        for combination in [
            "proposal_disposition = 'none'",
            "proposal_disposition = 'applied'",
            "proposal_disposition IN ('refused', 'dead-lettered')",
        ] {
            assert!(
                joined.contains(combination),
                "{combination} is one of the recorded dispositions"
            );
        }
        assert!(
            joined.contains("octet_length(proposal_code) <= 128"),
            "a refusal code is bounded in the row, not only in the message"
        );
        assert!(
            joined.contains("octet_length(proposal_summary) <= 1024"),
            "a refusal summary is bounded in the row, not only in the message"
        );
        assert!(joined
            .contains("proposal_resulting_revision IS NULL OR proposal_resulting_revision > 0"));
    }

    // The words of every `dead_letter_reason IN (...)` list in the statements,
    // one list per occurrence, in statement order.
    fn dead_letter_reason_lists(statements: &[String]) -> Vec<Vec<String>> {
        let joined = statements.join("\n");
        joined
            .split("dead_letter_reason IN (")
            .skip(1)
            .map(|rest| {
                let (list, _) = rest.split_once(')').expect("the list is closed");
                list.split(',')
                    .map(|word| word.trim().trim_matches('\'').to_owned())
                    .collect()
            })
            .collect()
    }

    #[test]
    fn every_dead_letter_reason_list_holds_the_reasons_the_service_spells() {
        let spelled: Vec<String> = crate::delivery::DeliveryFailureReason::ALL
            .iter()
            .map(|reason| reason.as_str().to_owned())
            .collect();
        let lists = dead_letter_reason_lists(&rendered(KERNEL_SCHEMA));
        assert_eq!(
            lists.len(),
            2,
            "the table and the reason upgrade each list the reasons"
        );
        for list in lists {
            assert_eq!(list, spelled);
        }
    }

    #[test]
    fn the_tables_are_created_with_every_protocol_word_in_kebab_case() {
        let statements = rendered(KERNEL_SCHEMA);
        let created: Vec<&String> = statements
            .iter()
            .filter(|statement| statement.trim_start().starts_with("CREATE TABLE"))
            .collect();
        assert_eq!(created.len(), 3);
        let created = created
            .into_iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join("\n");
        for expected in [
            "CHECK (authentication_profile = 'hmac-sha256-v1')",
            "CHECK (delivery_mode = 'after-commit')",
            "state IN ('pending', 'leased', 'delivered', 'dead-lettered', 'expired')",
            "OR (state = 'dead-lettered'",
            "proposal_disposition IN ('none', 'applied', 'refused', 'dead-lettered')",
            "proposal_disposition IN ('refused', 'dead-lettered')",
        ] {
            assert!(created.contains(expected), "{expected} is installed");
        }
        for word in created.split('\'').skip(1).step_by(2) {
            assert!(
                word.starts_with('^') || !word.contains('_'),
                "{word} is a stored word spelled with an underscore"
            );
        }
    }

    #[test]
    fn every_statement_is_qualified_by_the_schema() {
        let statements = rendered(KERNEL_SCHEMA);
        assert_eq!(statements.len(), 7);
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
    fn an_empty_schema_is_refused() {
        let _ = statements("");
    }

    #[test]
    #[should_panic(expected = "delivery schema must be a plain lowercase SQL identifier")]
    fn an_uppercase_schema_is_refused() {
        let _ = statements("Registry_Internal");
    }

    #[test]
    #[should_panic(expected = "delivery schema must be a plain lowercase SQL identifier")]
    fn a_schema_that_starts_with_a_digit_is_refused() {
        let _ = statements("1registry_internal");
    }

    #[test]
    #[should_panic(expected = "delivery schema must be a plain lowercase SQL identifier")]
    fn a_schema_longer_than_sixty_three_bytes_is_refused() {
        let _ = statements(&"s".repeat(64));
    }

    #[test]
    fn a_schema_of_exactly_sixty_three_bytes_is_accepted() {
        let schema = "s".repeat(63);
        assert_eq!(rendered(&schema).len(), DELIVERY_STATEMENTS.len());
    }

    #[test]
    fn every_named_object_is_created_by_the_statements() {
        let statements = rendered(KERNEL_SCHEMA).join("\n");
        for name in object_names(KERNEL_SCHEMA) {
            if let Some(table) = name.strip_suffix("_outbox_id_seq") {
                // The identity sequence has no statement of its own: it is
                // created by the outbox's identity column, and PostgreSQL
                // derives its name from the table and the column.
                assert!(
                    statements.contains(&format!("CREATE TABLE IF NOT EXISTS {table} (")),
                    "no statement creates the table behind {name}"
                );
                assert!(statements.contains("outbox_id bigint GENERATED ALWAYS AS IDENTITY"));
            } else {
                assert!(
                    statements.contains(&format!("CREATE TABLE IF NOT EXISTS {name} (")),
                    "no statement creates {name}"
                );
            }
        }
    }

    #[test]
    fn the_named_objects_are_qualified_by_the_requested_schema() {
        assert_eq!(
            object_names("observability_internal"),
            vec![
                "observability_internal.registry_outbox".to_owned(),
                "observability_internal.registry_outbox_outbox_id_seq".to_owned(),
                "observability_internal.registry_webhook_deliveries".to_owned(),
                "observability_internal.registry_webhook_delivery_state".to_owned(),
            ]
        );
    }

    #[test]
    #[should_panic(expected = "delivery schema must be a plain lowercase SQL identifier")]
    fn object_names_refuse_a_schema_that_is_not_a_plain_identifier() {
        let _ = object_names("registry; drop table users");
    }

    // Every table, column, constraint, and index in `schema`, with the oid of
    // each relation and constraint, so a rebuilt object reads as a change.
    async fn installed_catalog(client: &tokio_postgres::Client, schema: &str) -> Vec<String> {
        client
            .query(
                "SELECT format('relation %s %s %s', c.relname, c.relkind, c.oid)
                   FROM pg_catalog.pg_class c
                   JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                  WHERE n.nspname = $1
                 UNION ALL
                 SELECT format('column %s.%s %s %s', c.relname, a.attname,
                               format_type(a.atttypid, a.atttypmod), a.attnotnull)
                   FROM pg_catalog.pg_attribute a
                   JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
                   JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                  WHERE n.nspname = $1 AND c.relkind = 'r'
                    AND a.attnum > 0 AND NOT a.attisdropped
                 UNION ALL
                 SELECT format('constraint %s.%s %s %s', c.relname, con.conname, con.oid,
                               pg_catalog.pg_get_constraintdef(con.oid))
                   FROM pg_catalog.pg_constraint con
                   JOIN pg_catalog.pg_class c ON c.oid = con.conrelid
                   JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                  WHERE n.nspname = $1
                  ORDER BY 1",
                &[&schema],
            )
            .await
            .expect("read the installed delivery catalog")
            .into_iter()
            .map(|row| row.get(0))
            .collect()
    }

    #[tokio::test]
    #[ignore = "requires a local PostgreSQL test database named by HOOKS_TEST_DATABASE_URL"]
    async fn installing_over_an_installed_schema_changes_nothing() {
        let url = std::env::var("HOOKS_TEST_DATABASE_URL")
            .expect("HOOKS_TEST_DATABASE_URL is required for the real PostgreSQL test");
        let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .expect("connect to the local PostgreSQL test database");
        tokio::spawn(async move {
            let _closed = connection.await;
        });
        let schema = "hooks_delivery_reinstall_test";
        client
            .batch_execute(&format!(
                "DROP SCHEMA IF EXISTS {schema} CASCADE; CREATE SCHEMA {schema};"
            ))
            .await
            .expect("reset the test schema");
        install(&client, schema)
            .await
            .expect("install the delivery schema");
        let installed = installed_catalog(&client, schema).await;
        for name in object_names(schema) {
            let relation = name
                .strip_prefix(&format!("{schema}."))
                .expect("object names are schema-qualified");
            assert!(
                installed
                    .iter()
                    .any(|entry| entry.starts_with(&format!("relation {relation} "))),
                "{name} is installed"
            );
        }

        install(&client, schema)
            .await
            .expect("install runs again over the installed schema");
        assert_eq!(installed_catalog(&client, schema).await, installed);
        client
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE;"))
            .await
            .expect("drop the test schema");
    }

    // The dead-letter reason column and its constraint, as the catalog
    // describes them, without the oids a rebuilt object would change.
    async fn dead_letter_reason_catalog(
        client: &tokio_postgres::Client,
        schema: &str,
    ) -> Vec<String> {
        client
            .query(
                "SELECT format('column %s %s', a.attname,
                               format_type(a.atttypid, a.atttypmod))
                   FROM pg_catalog.pg_attribute a
                   JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
                   JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                  WHERE n.nspname = $1
                    AND c.relname = 'registry_webhook_delivery_state'
                    AND a.attname = 'dead_letter_reason' AND NOT a.attisdropped
                 UNION ALL
                 SELECT format('constraint %s %s', con.conname,
                               pg_catalog.pg_get_constraintdef(con.oid))
                   FROM pg_catalog.pg_constraint con
                   JOIN pg_catalog.pg_class c ON c.oid = con.conrelid
                   JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                  WHERE n.nspname = $1
                    AND con.conname
                        = 'registry_webhook_delivery_state_dead_letter_reason_values'
                  ORDER BY 1",
                &[&schema],
            )
            .await
            .expect("read the dead-letter reason catalog")
            .into_iter()
            .map(|row| row.get(0))
            .collect()
    }

    #[tokio::test]
    #[ignore = "requires a local PostgreSQL test database named by HOOKS_TEST_DATABASE_URL"]
    async fn installing_over_a_table_without_dead_letter_reasons_adds_them() {
        let url = std::env::var("HOOKS_TEST_DATABASE_URL")
            .expect("HOOKS_TEST_DATABASE_URL is required for the real PostgreSQL test");
        let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .expect("connect to the local PostgreSQL test database");
        tokio::spawn(async move {
            let _closed = connection.await;
        });
        let schema = "hooks_delivery_reason_upgrade_test";
        client
            .batch_execute(&format!(
                "DROP SCHEMA IF EXISTS {schema} CASCADE; CREATE SCHEMA {schema};"
            ))
            .await
            .expect("reset the test schema");
        install(&client, schema)
            .await
            .expect("install the delivery schema");
        let installed = dead_letter_reason_catalog(&client, schema).await;
        assert_eq!(
            installed.len(),
            2,
            "a fresh install has the column and its constraint"
        );

        // The table as a release without dead-letter reasons left it, which
        // the release that introduced them serves without installing again.
        client
            .batch_execute(&format!(
                "ALTER TABLE {schema}.registry_webhook_delivery_state
                     DROP COLUMN dead_letter_reason;"
            ))
            .await
            .expect("shape the table without the dead-letter reason");
        assert!(dead_letter_reason_catalog(&client, schema).await.is_empty());

        install(&client, schema)
            .await
            .expect("install runs over the table without the dead-letter reason");
        assert_eq!(dead_letter_reason_catalog(&client, schema).await, installed);
        client
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE;"))
            .await
            .expect("drop the test schema");
    }
}
