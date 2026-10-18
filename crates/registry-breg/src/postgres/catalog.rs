// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write,
};

use sha2::{Digest, Sha256};
use tokio_postgres::GenericClient;

use registry_platform_crypto::field_encryption::FIELD_ENCRYPTION_ALGORITHM;

use crate::generated_ddl::{
    DdlObjectOwner, DdlPolicyRole, DdlStatementKind, PolicyCommand, TablePrivilege,
};
use crate::model::CompiledRegistry;

#[cfg(feature = "postgres-test")]
use super::schema::install_empty_history_baseline_for_compiled_registry;
use super::{
    migration_ledger::install_migration_ledger, spatial_bbox_role, PostgresKernelError, Result,
    RuntimeRevoke, SqlIdentifier,
};

pub(super) const MANAGED_SCHEMAS: &[&str] = &[
    "registry_internal",
    "registry_data",
    "registry_source",
    "registry_derived",
    "registry_context",
];
const TABLE_OWNER_PRIVILEGES: &[&str] = &[
    "DELETE",
    "INSERT",
    "MAINTAIN",
    "REFERENCES",
    "SELECT",
    "TRIGGER",
    "TRUNCATE",
    "UPDATE",
];
const SEQUENCE_OWNER_PRIVILEGES: &[&str] = &["SELECT", "UPDATE", "USAGE"];
const FUNCTION_OWNER_PRIVILEGES: &[&str] = &["EXECUTE"];
// The delivery objects belong to the platform delivery schema, so their
// names come from there. A unit test below holds this list against the
// library's own, and the runtime privileges on each stay Base Registry
// Engine's decision.
const DELIVERY_TABLE_PRIVILEGES: &[(&str, &[&str])] = &[
    (
        "registry_internal.registry_outbox",
        &["DELETE", "INSERT", "SELECT"],
    ),
    (
        "registry_internal.registry_webhook_deliveries",
        &["DELETE", "INSERT", "SELECT"],
    ),
    (
        "registry_internal.registry_webhook_delivery_state",
        &["DELETE", "INSERT", "SELECT", "UPDATE"],
    ),
];
const DELIVERY_SEQUENCE: &str = "registry_internal.registry_outbox_outbox_id_seq";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ManagedObjectKind {
    Schema,
    Table,
    View,
    Sequence,
    Function,
}

impl ManagedObjectKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Schema => "schema",
            Self::Table => "table",
            Self::View => "view",
            Self::Sequence => "sequence",
            Self::Function => "function",
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ManagedObject {
    kind: ManagedObjectKind,
    name: String,
    owner: DdlObjectOwner,
    runtime_privileges: BTreeSet<String>,
    spatial_bbox_privileges: BTreeSet<String>,
    row_security: Option<(bool, bool)>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ManagedColumnPrivilege {
    table: String,
    column: String,
    grantee: String,
    privilege: String,
    grantable: bool,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ManagedPolicy {
    table: String,
    name: String,
    command: String,
    role: ManagedPolicyRole,
    has_using: bool,
    has_check: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
enum ManagedPolicyRole {
    #[default]
    Public,
    Runtime,
    SpatialBbox,
}

/// Subject access-log table and expiry function, created by every apply.
const SUBJECT_ACCESS_LOG_TABLE: &str = "registry_internal.registry_subject_access_log";
const SUBJECT_ACCESS_LOG_EXPIRY: &str = "registry_internal.expire_subject_access_log()";

/// Product-owned indexes installed outside compiler-generated entity DDL.
///
/// The pristine-catalog diagnostic test compares this inventory with the
/// actual installed catalog, so a new installer-owned index cannot silently
/// fall out of drift localization.
const MANAGED_INTERNAL_INDEXES: &[&str] = &[
    "registry_internal.registry_action_evidence_uses_expiry",
    "registry_internal.registry_attachment_live_references",
    "registry_internal.registry_attachment_verification_pending",
    "registry_internal.registry_field_encryption_lifecycle_progress_idx",
    "registry_internal.registry_idempotency_caller_key",
    "registry_internal.registry_import_authorities_one_open",
    "registry_internal.registry_ingestion_run_chunk_records_erased_record",
    "registry_internal.registry_migrations_one_open_activation_per_digest",
    "registry_internal.registry_proposal_evidence_uses_expiry",
    "registry_internal.registry_proposal_idempotency_by_request",
    "registry_internal.registry_proposal_pending_targets",
    "registry_internal.registry_proposal_queue",
    "registry_internal.registry_proposal_review_completion_reconcile",
    "registry_internal.registry_proposal_review_submission_jobs",
    "registry_internal.registry_revision_commit_members_lookup_idx",
    "registry_internal.registry_revision_commit_members_position_idx",
    "registry_internal.registry_subject_access_log_expiry",
    "registry_internal.registry_subject_access_log_record",
    "registry_internal.registry_webhook_delivery_state_due_idx",
    "registry_internal.registry_webhook_delivery_state_expired_idx",
];
const IMMEDIATE_ACTION_RESULT_TARGET_INDEX: &str =
    "registry_internal.registry_immediate_action_results_target_idx";

/// Exact managed PostgreSQL inventory accepted by catalog verification.
///
/// Construction is deliberately closed to one compiler-produced Registry plus
/// the current product-owned mutation tables. There is no wildcard or
/// ambient-catalog mode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedManagedCatalog {
    objects: BTreeSet<ManagedObject>,
    column_privileges: BTreeSet<ManagedColumnPrivilege>,
    policies: BTreeSet<ManagedPolicy>,
}

const MAX_DIAGNOSTIC_CATALOG_OBJECTS: usize = 64;

/// Names managed catalog objects whose shape differs from the compiled
/// package. This inventory carries identifiers only and never reads table
/// values, connection settings, role names, or credentials.
pub async fn catalog_drift_objects(
    client: &impl GenericClient,
    registry: &CompiledRegistry,
    expected_catalog: &ExpectedManagedCatalog,
) -> Result<Vec<String>> {
    let mut differences = BTreeSet::new();
    let rows = client
        .query(
            "SELECT 'schema', n.nspname::text
         FROM pg_catalog.pg_namespace n
         WHERE n.nspname = ANY($1::text[])
         UNION ALL
         SELECT CASE c.relkind WHEN 'r' THEN 'table' WHEN 'v' THEN 'view' ELSE 'sequence' END,
                n.nspname || '.' || c.relname
         FROM pg_catalog.pg_class c
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = ANY($1::text[]) AND c.relkind IN ('r', 'v', 'S')
         UNION ALL
         SELECT 'function', n.nspname || '.' || p.proname || '(' ||
                pg_catalog.pg_get_function_identity_arguments(p.oid) || ')'
         FROM pg_catalog.pg_proc p
         JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname = ANY($1::text[])",
            &[&MANAGED_SCHEMAS],
        )
        .await?;
    let actual_objects: BTreeSet<(String, String)> = rows
        .into_iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    let expected_objects: BTreeSet<(String, String)> = expected_catalog
        .objects
        .iter()
        .map(|object| (object.kind.as_str().to_owned(), object.name.clone()))
        .collect();
    for (_, name) in actual_objects.symmetric_difference(&expected_objects) {
        differences.insert(name.clone());
    }

    let mut expected_indexes: BTreeSet<String> = registry
        .ddl()
        .statements
        .iter()
        .filter(|statement| statement.kind == DdlStatementKind::Index)
        .filter_map(|statement| {
            let name = sql_identifier_after(&statement.sql, " INDEX ")?;
            let table = qualified_table_after(&statement.sql, " ON ")?;
            let schema = table.split_once('.')?.0;
            Some(format!("{schema}.{name}"))
        })
        .chain(
            MANAGED_INTERNAL_INDEXES
                .iter()
                .map(|name| (*name).to_owned()),
        )
        .collect();
    if !registry.actions().actions.is_empty() {
        expected_indexes.insert(IMMEDIATE_ACTION_RESULT_TARGET_INDEX.to_owned());
    }
    let index_rows = client
        .query(
            "SELECT n.nspname || '.' || i.relname
         FROM pg_catalog.pg_index x
         JOIN pg_catalog.pg_class t ON t.oid = x.indrelid
         JOIN pg_catalog.pg_class i ON i.oid = x.indexrelid
         JOIN pg_catalog.pg_namespace n ON n.oid = t.relnamespace
         LEFT JOIN pg_catalog.pg_constraint c ON c.conindid = i.oid
         WHERE n.nspname = ANY($1::text[]) AND c.oid IS NULL",
            &[&MANAGED_SCHEMAS],
        )
        .await?;
    let actual_indexes: BTreeSet<String> = index_rows.into_iter().map(|row| row.get(0)).collect();
    for name in actual_indexes.symmetric_difference(&expected_indexes) {
        differences.insert(name.clone());
    }

    let constraint_rows = client
        .query(
            "SELECT n.nspname || '.' || t.relname, c.conname
         FROM pg_catalog.pg_constraint c
         JOIN pg_catalog.pg_class t ON t.oid = c.conrelid
         JOIN pg_catalog.pg_namespace n ON n.oid = t.relnamespace
         WHERE n.nspname = ANY($1::text[])",
            &[&MANAGED_SCHEMAS],
        )
        .await?;
    let actual_constraints: BTreeSet<(String, String)> = constraint_rows
        .into_iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    for statement in registry.ddl().statements.iter().filter(|statement| {
        statement.kind == DdlStatementKind::Constraint && statement.sql.contains(" UNIQUE ")
    }) {
        if let (Some(table), Some(name)) = (
            qualified_table_after(&statement.sql, "ALTER TABLE "),
            sql_identifier_after(&statement.sql, "ADD CONSTRAINT "),
        ) {
            if !actual_constraints.contains(&(table.clone(), name.clone())) {
                differences.insert(format!("{table}.{name}"));
            }
        }
    }

    let column_rows = client
        .query(
            "SELECT n.nspname || '.' || c.relname, a.attname, a.attnotnull
         FROM pg_catalog.pg_attribute a
         JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'registry_data' AND c.relkind = 'r'
           AND a.attnum > 0 AND NOT a.attisdropped",
            &[],
        )
        .await?;
    let actual_columns: BTreeMap<(String, String), bool> = column_rows
        .into_iter()
        .map(|row| ((row.get(0), row.get(1)), row.get(2)))
        .collect();
    for entity in registry.entities().values() {
        let table = format!("registry_data.{}", entity.physical_table);
        // A deleted table is already named above; its columns are not named
        // again, so they do not crowd the bounded inventory.
        if !actual_objects.contains(&("table".to_owned(), table.clone())) {
            continue;
        }
        for field in entity.fields.values().filter(|field| field.required) {
            // A deleted column is drift by the same name as a nullable one.
            if !matches!(
                actual_columns.get(&(table.clone(), field.physical_name.clone())),
                Some(true)
            ) {
                differences.insert(format!("{table}.{}", field.physical_name));
            }
        }
    }

    // A deleted schema is named once; the objects it held are not named
    // again, so they do not crowd the bounded inventory.
    let deleted_schemas: Vec<String> = MANAGED_SCHEMAS
        .iter()
        .filter(|schema| !actual_objects.contains(&("schema".to_owned(), (**schema).to_owned())))
        .map(|schema| format!("{schema}."))
        .collect();
    differences.retain(|name| {
        !deleted_schemas
            .iter()
            .any(|prefix| name.starts_with(prefix.as_str()))
    });

    Ok(differences
        .into_iter()
        .take(MAX_DIAGNOSTIC_CATALOG_OBJECTS)
        .collect())
}

fn sql_identifier_after(sql: &str, marker: &str) -> Option<String> {
    let rest = sql.split_once(marker)?.1.trim_start();
    if let Some(quoted) = rest.strip_prefix('"') {
        return quoted
            .split_once('"')
            .map(|(identifier, _)| identifier.to_owned());
    }
    rest.split_whitespace().next().map(str::to_owned)
}

fn qualified_table_after(sql: &str, marker: &str) -> Option<String> {
    Some(
        sql.split_once(marker)?
            .1
            .split_whitespace()
            .next()?
            .replace('"', ""),
    )
}

impl ExpectedManagedCatalog {
    fn add_statistical_release_store(&mut self) {
        for (table, privileges) in crate::statistics_store::STATISTICS_TABLES {
            self.table(
                &format!("registry_internal.{table}"),
                privileges.iter().copied(),
                std::iter::empty::<&str>(),
                Some((false, false)),
            );
        }
        self.function(
            crate::statistics_store::WITHDRAWAL_FUNCTION,
            Some("EXECUTE"),
            None,
        );
    }

    /// Exact product inventory for one compiled Registry.
    #[must_use]
    pub fn compiled(registry: &CompiledRegistry) -> Self {
        let mut catalog = Self::base();
        catalog.table(
            SUBJECT_ACCESS_LOG_TABLE,
            ["SELECT", "INSERT"],
            std::iter::empty::<&str>(),
            Some((false, false)),
        );
        catalog.function(SUBJECT_ACCESS_LOG_EXPIRY, Some("EXECUTE"), None);
        catalog.function(
            crate::action_evidence_retention::EXPIRY_FUNCTION,
            Some("EXECUTE"),
            None,
        );
        if registry.ddl().requires_postgis {
            catalog.grant_schema_spatial_bbox("registry_data");
            catalog.grant_schema_spatial_bbox("registry_context");
        }
        for (name, privileges) in DELIVERY_TABLE_PRIVILEGES.iter().copied().chain([
            (
                "registry_internal.registry_revisions",
                &["INSERT", "SELECT"][..],
            ),
            (
                "registry_internal.registry_idempotency",
                &["INSERT", "SELECT"][..],
            ),
            (
                "registry_internal.registry_action_evidence_uses",
                &["INSERT"][..],
            ),
            (
                "registry_internal.registry_immediate_action_applications",
                &["INSERT", "SELECT"][..],
            ),
            (
                "registry_internal.registry_immediate_action_results",
                &["INSERT", "SELECT"][..],
            ),
            (
                "registry_internal.registry_revision_commits",
                &["INSERT", "SELECT"][..],
            ),
            (
                "registry_internal.registry_revision_commit_members",
                &["INSERT", "SELECT"][..],
            ),
            (
                "registry_internal.registry_history_schemas",
                &["SELECT"][..],
            ),
        ]) {
            catalog.table(
                name,
                privileges.iter().copied(),
                std::iter::empty::<&str>(),
                Some((false, false)),
            );
        }
        catalog.table(
            "registry_internal.registry_commit_head",
            ["SELECT"],
            std::iter::empty::<&str>(),
            Some((false, false)),
        );
        // History maintenance facts. Only the migration authority reads or
        // writes them, in the commit of the maintenance step they record.
        for name in [
            "registry_internal.registry_history_erasure_coverage",
            "registry_internal.registry_field_encryption_lifecycle_progress",
        ] {
            catalog.table(
                name,
                std::iter::empty::<&str>(),
                std::iter::empty::<&str>(),
                Some((false, false)),
            );
        }
        // Runtime workers scrub retained webhook payload bytes after delivery
        // or expiry without widening update access to outbox identity columns.
        catalog.column_privilege(
            "registry_internal.registry_outbox",
            "payload",
            "runtime",
            "UPDATE",
        );
        catalog.column_privilege(
            "registry_internal.registry_commit_head",
            "latest_position",
            "runtime",
            "UPDATE",
        );
        catalog.column_privilege(
            "registry_internal.registry_commit_head",
            "updated_at",
            "runtime",
            "UPDATE",
        );
        catalog.sequence(DELIVERY_SEQUENCE, ["SELECT", "USAGE"]);
        for (table, privileges) in crate::proposal_store::PROPOSAL_TABLES {
            catalog.table(
                &format!("registry_internal.{table}"),
                privileges.iter().copied(),
                std::iter::empty::<&str>(),
                Some((false, false)),
            );
        }
        for (table, privileges) in crate::review_store::REVIEW_TABLES {
            catalog.table(
                &format!("registry_internal.{table}"),
                privileges.iter().copied(),
                std::iter::empty::<&str>(),
                Some((false, false)),
            );
        }
        for (table, privileges) in crate::ingestion_store::INGESTION_TABLES {
            catalog.table(
                &format!("registry_internal.{table}"),
                privileges.iter().copied(),
                std::iter::empty::<&str>(),
                Some((false, false)),
            );
        }
        catalog.add_statistical_release_store();
        for (table, privileges) in crate::import_authority::IMPORT_AUTHORITY_TABLES {
            let name = format!("registry_internal.{table}");
            catalog.table(
                &name,
                privileges.iter().copied(),
                std::iter::empty::<&str>(),
                Some((true, false)),
            );
            for column in crate::import_authority::RUNTIME_UPDATE_COLUMNS {
                catalog.column_privilege(&name, column, "runtime", "UPDATE");
            }
            for (policy, command, has_check) in [
                (crate::import_authority::READ_POLICY, "r", false),
                (crate::import_authority::ADVANCE_POLICY, "w", true),
            ] {
                catalog.policies.insert(ManagedPolicy {
                    table: name.clone(),
                    name: policy.to_owned(),
                    command: command.to_owned(),
                    role: ManagedPolicyRole::Runtime,
                    has_using: true,
                    has_check,
                });
            }
        }
        for (table, privileges) in crate::attachment_store::ATTACHMENT_TABLES {
            catalog.table(
                &format!("registry_internal.{table}"),
                privileges.iter().copied(),
                std::iter::empty::<&str>(),
                Some((true, true)),
            );
            for (name, role) in [
                ("attachment_runtime", ManagedPolicyRole::Runtime),
                ("attachment_operator", ManagedPolicyRole::Public),
            ] {
                catalog.policies.insert(ManagedPolicy {
                    table: format!("registry_internal.{table}"),
                    name: name.to_owned(),
                    command: "*".to_owned(),
                    role,
                    has_using: true,
                    has_check: true,
                });
            }
        }

        for table in &registry.ddl().tables {
            let name = format!("registry_data.{}", table.physical_name);
            catalog.table(
                &name,
                table
                    .runtime_privileges
                    .iter()
                    .copied()
                    .map(TablePrivilege::as_sql),
                table
                    .spatial_bbox_privileges
                    .iter()
                    .copied()
                    .map(TablePrivilege::as_sql),
                Some((true, true)),
            );
            if table.runtime_lock_column {
                catalog.column_privilege(&name, "record_id", "runtime", "UPDATE");
            }
            for policy in &table.policies {
                catalog.policies.insert(ManagedPolicy {
                    table: name.clone(),
                    name: policy.name.clone(),
                    command: policy_command_code(policy.command).to_owned(),
                    role: managed_policy_role(policy.applies_to),
                    has_using: policy.using_expression.is_some(),
                    has_check: policy.check_expression.is_some(),
                });
            }
        }
        for view in &registry.ddl().views {
            catalog.view(
                &format!("{}.{}", view.schema, view.name),
                view.owner,
                view.runtime_privileges
                    .iter()
                    .copied()
                    .map(TablePrivilege::as_sql),
                std::iter::empty::<&str>(),
            );
        }
        for function in &registry.ddl().functions {
            catalog.function(
                &format!(
                    "{}.{}({})",
                    function.schema, function.name, function.arguments
                ),
                function.runtime_execute.then_some("EXECUTE"),
                function.spatial_bbox_execute.then_some("EXECUTE"),
            );
        }
        catalog
    }

    fn base() -> Self {
        let mut catalog = Self {
            objects: BTreeSet::new(),
            column_privileges: BTreeSet::new(),
            policies: BTreeSet::new(),
        };
        for schema in MANAGED_SCHEMAS {
            catalog.schema(schema);
        }
        catalog.table(
            "registry_internal.registry_state",
            ["SELECT"],
            std::iter::empty::<&str>(),
            Some((false, false)),
        );
        catalog.table(
            "registry_internal.registry_migrations",
            std::iter::empty::<&str>(),
            std::iter::empty::<&str>(),
            Some((false, false)),
        );
        catalog.table(
            "registry_internal.registry_migration_steps",
            std::iter::empty::<&str>(),
            std::iter::empty::<&str>(),
            Some((false, false)),
        );
        catalog.table(
            "registry_internal.registry_field_encryption_keys",
            ["SELECT"],
            std::iter::empty::<&str>(),
            Some((false, false)),
        );
        catalog.table(
            "registry_internal.registry_field_encryption_flips",
            ["SELECT"],
            std::iter::empty::<&str>(),
            Some((false, false)),
        );
        catalog
    }

    fn schema(&mut self, name: &str) {
        self.objects.insert(ManagedObject {
            kind: ManagedObjectKind::Schema,
            name: name.to_owned(),
            owner: DdlObjectOwner::Migration,
            runtime_privileges: BTreeSet::from(["USAGE".to_owned()]),
            spatial_bbox_privileges: BTreeSet::new(),
            row_security: None,
        });
    }

    fn grant_schema_spatial_bbox(&mut self, name: &str) {
        let Some(existing) = self
            .objects
            .iter()
            .find(|object| object.kind == ManagedObjectKind::Schema && object.name == name)
            .cloned()
        else {
            return;
        };
        let mut object = self
            .objects
            .take(&existing)
            .expect("schema object from exact catalog is removable");
        object.spatial_bbox_privileges.insert("USAGE".to_owned());
        self.objects.insert(object);
    }

    fn table(
        &mut self,
        name: &str,
        runtime_privileges: impl IntoIterator<Item = impl Into<String>>,
        spatial_bbox_privileges: impl IntoIterator<Item = impl Into<String>>,
        row_security: Option<(bool, bool)>,
    ) {
        self.objects.insert(ManagedObject {
            kind: ManagedObjectKind::Table,
            name: name.to_owned(),
            owner: DdlObjectOwner::Migration,
            runtime_privileges: runtime_privileges.into_iter().map(Into::into).collect(),
            spatial_bbox_privileges: spatial_bbox_privileges
                .into_iter()
                .map(Into::into)
                .collect(),
            row_security,
        });
    }

    fn sequence(
        &mut self,
        name: &str,
        runtime_privileges: impl IntoIterator<Item = impl Into<String>>,
    ) {
        self.objects.insert(ManagedObject {
            kind: ManagedObjectKind::Sequence,
            name: name.to_owned(),
            owner: DdlObjectOwner::Migration,
            runtime_privileges: runtime_privileges.into_iter().map(Into::into).collect(),
            spatial_bbox_privileges: BTreeSet::new(),
            row_security: None,
        });
    }

    fn view(
        &mut self,
        name: &str,
        owner: DdlObjectOwner,
        runtime_privileges: impl IntoIterator<Item = impl Into<String>>,
        spatial_bbox_privileges: impl IntoIterator<Item = impl Into<String>>,
    ) {
        self.objects.insert(ManagedObject {
            kind: ManagedObjectKind::View,
            name: name.to_owned(),
            owner,
            runtime_privileges: runtime_privileges.into_iter().map(Into::into).collect(),
            spatial_bbox_privileges: spatial_bbox_privileges
                .into_iter()
                .map(Into::into)
                .collect(),
            row_security: None,
        });
    }

    fn function(
        &mut self,
        name: &str,
        runtime_privilege: Option<&str>,
        spatial_bbox_privilege: Option<&str>,
    ) {
        self.objects.insert(ManagedObject {
            kind: ManagedObjectKind::Function,
            name: name.to_owned(),
            owner: DdlObjectOwner::Migration,
            runtime_privileges: runtime_privilege.into_iter().map(str::to_owned).collect(),
            spatial_bbox_privileges: spatial_bbox_privilege
                .into_iter()
                .map(str::to_owned)
                .collect(),
            row_security: None,
        });
    }

    fn column_privilege(
        &mut self,
        table: &str,
        column: &str,
        grantee: &'static str,
        privilege: &'static str,
    ) {
        self.column_privileges.insert(ManagedColumnPrivilege {
            table: table.to_owned(),
            column: column.to_owned(),
            grantee: grantee.to_owned(),
            privilege: privilege.to_owned(),
            grantable: false,
        });
    }
}
fn policy_command_code(command: PolicyCommand) -> &'static str {
    match command {
        PolicyCommand::Select => "r",
        PolicyCommand::Insert => "a",
        PolicyCommand::Update => "w",
    }
}

fn managed_policy_role(role: DdlPolicyRole) -> ManagedPolicyRole {
    match role {
        DdlPolicyRole::Public => ManagedPolicyRole::Public,
        DdlPolicyRole::Runtime => ManagedPolicyRole::Runtime,
        DdlPolicyRole::SpatialBbox => ManagedPolicyRole::SpatialBbox,
    }
}

/// Package and schema identity expected by one loaded runtime: the registry
/// package id, the database the runtime identity names, the active package
/// digest, the activation that made it active, and its schema fingerprint.
///
/// The activation id is the scope value every revision, history descriptor,
/// cursor, and keyed audit hash of the active package is bound to. It is a
/// canonical lowercase UUID string, so it is written to settings and rows as
/// it stands.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedRegistryIdentity {
    pub package_id: String,
    pub database_id: String,
    pub package_digest: String,
    pub activation_id: String,
    pub schema_fingerprint: String,
}

impl ExpectedRegistryIdentity {
    pub fn validate(&self) -> Result<()> {
        if self.package_id.is_empty()
            || self.database_id.is_empty()
            || self.package_digest.is_empty()
            || self.schema_fingerprint.is_empty()
            || canonical_activation_id(&self.activation_id).is_none()
        {
            return Err(PostgresKernelError::Configuration(
                "Registry identity fields must be non-empty and the activation id a canonical UUID",
            ));
        }
        Ok(())
    }

    /// The activation id as a UUID, for binding to its `uuid` columns.
    pub fn activation_uuid(&self) -> Result<uuid::Uuid> {
        canonical_activation_id(&self.activation_id).ok_or(PostgresKernelError::Configuration(
            "Registry activation id must be a canonical UUID",
        ))
    }
}

/// The UUID a canonical, lowercase, hyphenated, non-nil activation id names.
fn canonical_activation_id(value: &str) -> Option<uuid::Uuid> {
    let parsed = uuid::Uuid::parse_str(value).ok()?;
    (!parsed.is_nil() && parsed.hyphenated().to_string() == value).then_some(parsed)
}

/// Verified identity read from the managed PostgreSQL catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogIdentity {
    pub package_id: String,
    pub database_id: String,
    pub package_digest: String,
    pub activation_id: String,
    pub schema_fingerprint: String,
}

impl CatalogIdentity {
    pub fn validate(&self) -> Result<()> {
        if self.package_id.is_empty()
            || self.database_id.is_empty()
            || self.package_digest.is_empty()
            || self.schema_fingerprint.is_empty()
            || canonical_activation_id(&self.activation_id).is_none()
        {
            return Err(PostgresKernelError::RegistryUnavailable);
        }
        Ok(())
    }
}

/// A Registry state identity a test fixture installs directly. The label
/// derives both the package digest and the activation id, so one label names
/// one reproducible activation.
#[cfg(feature = "postgres-test")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct RegistryStateTestIdentity<'a> {
    pub package_id: &'a str,
    pub database_id: &'a str,
    pub label: &'a str,
}

#[cfg(feature = "postgres-test")]
impl RegistryStateTestIdentity<'_> {
    fn validate(&self) -> Result<()> {
        if self.package_id.is_empty() || self.database_id.is_empty() || self.label.is_empty() {
            return Err(PostgresKernelError::Configuration(
                "initial Registry identity is incomplete",
            ));
        }
        Ok(())
    }

    /// The package digest the label names: the label itself when it is
    /// already a `sha256:` digest, otherwise the digest of its bytes.
    #[must_use]
    pub fn package_digest(&self) -> String {
        test_package_digest(self.label)
    }

    /// The activation id the label names.
    #[must_use]
    pub fn activation_id(&self) -> String {
        test_activation_id(self.label)
    }
}

/// The package digest a test label names: the label itself when it is already
/// a `sha256:` digest, otherwise the digest of its bytes.
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
#[must_use]
pub fn test_package_digest(label: &str) -> String {
    let is_digest = label.len() == 71
        && label.starts_with("sha256:")
        && label[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if is_digest {
        return label.to_owned();
    }
    let mut digest = String::from("sha256:");
    for byte in Sha256::digest(label.as_bytes()) {
        write!(&mut digest, "{byte:02x}").expect("writing to a String cannot fail");
    }
    digest
}

/// The reproducible activation id a test label names.
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
#[must_use]
pub fn test_activation_id(label: &str) -> String {
    let digest = Sha256::digest(label.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    uuid::Builder::from_random_bytes(bytes)
        .into_uuid()
        .hyphenated()
        .to_string()
}

/// The kernel state a database holds, read from the system catalogs alone so
/// a role without privileges on the managed schemas can still tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RegistryStateShape {
    /// No registry state table: no package was ever applied.
    Absent,
    /// A state table this release does not recognise: it records no
    /// activation id, as the one a release before the activation ledger
    /// created does.
    Unrecognized,
    /// The state table the activation ledger keeps.
    Ledger,
}

pub(crate) async fn registry_state_shape(
    client: &impl GenericClient,
) -> std::result::Result<RegistryStateShape, tokio_postgres::Error> {
    let row = client
        .query_one(
            "SELECT state.oid IS NOT NULL,
                    EXISTS (
                        SELECT 1 FROM pg_catalog.pg_attribute attribute
                         WHERE attribute.attrelid = state.oid
                           AND attribute.attname = 'active_activation_id'
                           AND NOT attribute.attisdropped
                    )
               FROM (SELECT NULL) AS one
               LEFT JOIN pg_catalog.pg_class state
                 ON state.relname = 'registry_state'
                AND state.relnamespace = (
                        SELECT oid FROM pg_catalog.pg_namespace
                         WHERE nspname = 'registry_internal'
                    )",
            &[],
        )
        .await?;
    Ok(
        match (row.try_get::<_, bool>(0)?, row.try_get::<_, bool>(1)?) {
            (false, _) => RegistryStateShape::Absent,
            (true, false) => RegistryStateShape::Unrecognized,
            (true, true) => RegistryStateShape::Ledger,
        },
    )
}

pub(crate) async fn install_registry_state_schema(
    migration: &impl GenericClient,
    runtime_role: &SqlIdentifier,
) -> Result<()> {
    migration
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS registry_internal.registry_state (
                 singleton boolean PRIMARY KEY DEFAULT true
                     CONSTRAINT registry_state_singleton_true CHECK (singleton),
                 package_id text NOT NULL
                     CONSTRAINT registry_state_package_id_nonempty CHECK (package_id <> ''),
                 database_id text NOT NULL
                     CONSTRAINT registry_state_database_id_nonempty CHECK (database_id <> ''),
                 active_package_digest text NOT NULL
                     CONSTRAINT registry_state_package_digest_nonempty CHECK (active_package_digest <> ''),
                 active_activation_id uuid NOT NULL,
                 schema_fingerprint text NOT NULL
                     CONSTRAINT registry_state_schema_fingerprint_nonempty CHECK (schema_fingerprint <> ''),
                 maintenance_status text NOT NULL
                     CONSTRAINT registry_state_maintenance_status_closed
                     CHECK (maintenance_status IN ('ready', 'applying', 'failed')),
                 maintenance_target_package_digest text,
                 system_identifier bigint,
                 database_oid oid,
                 epoch bigint NOT NULL DEFAULT 0
                     CONSTRAINT registry_state_epoch_nonnegative CHECK (epoch >= 0),
                 claimed_at timestamptz,
                 CONSTRAINT registry_state_maintenance_target_consistent CHECK (
                     (maintenance_status = 'ready' AND maintenance_target_package_digest IS NULL)
                     OR (maintenance_status IN ('applying', 'failed')
                         AND maintenance_target_package_digest IS NOT NULL)
                 ),
                 CONSTRAINT registry_state_claim_consistent CHECK (
                     (database_oid IS NULL AND system_identifier IS NULL
                         AND claimed_at IS NULL AND epoch = 0)
                     OR (database_oid IS NOT NULL AND claimed_at IS NOT NULL AND epoch >= 1)
                 ),
                 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp()
             );
             REVOKE ALL ON TABLE registry_internal.registry_state FROM PUBLIC;",
        )
        .await?;
    migration
        .batch_execute(&format!(
            "CREATE TABLE IF NOT EXISTS registry_internal.registry_field_encryption_keys (
                 key_version integer PRIMARY KEY
                     CONSTRAINT registry_field_encryption_key_version_one
                     CHECK (key_version = 1),
                 provider_kind text NOT NULL
                     CONSTRAINT registry_field_encryption_provider_kind_closed
                     CHECK (provider_kind IN ('transit_datakey', 'local_datakey_file')),
                 algorithm text NOT NULL
                     CONSTRAINT registry_field_encryption_algorithm_closed
                     CHECK (algorithm = '{FIELD_ENCRYPTION_ALGORITHM}'),
                 key_identifier text NOT NULL
                     CONSTRAINT registry_field_encryption_identifier_sha256
                     CHECK (key_identifier ~ '^sha256:[0-9a-f]{{64}}$'),
                 wrapped_dek text,
                 transit_key_version integer,
                 activated_package_revision text NOT NULL
                     CONSTRAINT registry_field_encryption_revision_nonempty
                     CHECK (activated_package_revision <> ''),
                 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 CONSTRAINT registry_field_encryption_provider_shape CHECK (
                     (provider_kind = 'transit_datakey'
                      AND wrapped_dek IS NOT NULL AND wrapped_dek <> ''
                      AND transit_key_version IS NOT NULL AND transit_key_version > 0)
                     OR
                     (provider_kind = 'local_datakey_file'
                      AND wrapped_dek IS NULL AND transit_key_version IS NULL)
                 )
             );
             REVOKE ALL ON TABLE registry_internal.registry_field_encryption_keys FROM PUBLIC;
             CREATE TABLE IF NOT EXISTS registry_internal.registry_field_encryption_flips (
                 entity_id text NOT NULL
                     CONSTRAINT registry_field_encryption_flip_entity_nonempty
                     CHECK (entity_id <> ''),
                 field_id text NOT NULL
                     CONSTRAINT registry_field_encryption_flip_field_nonempty
                     CHECK (field_id <> ''),
                 boundary_package_revision text NOT NULL
                     CONSTRAINT registry_field_encryption_flip_boundary_nonempty
                     CHECK (boundary_package_revision <> ''),
                 history_choice text NOT NULL
                     CONSTRAINT registry_field_encryption_flip_choice_closed
                     CHECK (history_choice IN ('erase-and-rebaseline', 'retain-plaintext-history')),
                 history_commit_position bigint NOT NULL
                     CONSTRAINT registry_field_encryption_flip_history_position_positive
                     CHECK (history_commit_position IS NULL OR history_commit_position > 0),
                 sealed_row_count bigint NOT NULL
                     CONSTRAINT registry_field_encryption_flip_sealed_rows_nonnegative
                     CHECK (sealed_row_count >= 0),
                 sealed_journal_row_count bigint NOT NULL
                     CONSTRAINT registry_field_encryption_flip_sealed_journal_nonnegative
                     CHECK (sealed_journal_row_count >= 0),
                 accepted_plaintext_journal_row_count bigint NOT NULL
                     CONSTRAINT registry_field_encryption_flip_accepted_journal_nonnegative
                     CHECK (accepted_plaintext_journal_row_count >= 0),
                 accepted_proposal_target_row_count bigint NOT NULL
                     CONSTRAINT registry_field_encryption_flip_accepted_targets_nonnegative
                     CHECK (accepted_proposal_target_row_count >= 0),
                 accepted_proposal_submission_row_count bigint NOT NULL
                     CONSTRAINT registry_field_encryption_flip_accepted_proposals_nonnegative
                     CHECK (accepted_proposal_submission_row_count >= 0),
                 accepted_idempotency_row_count bigint NOT NULL
                     CONSTRAINT registry_field_encryption_flip_accepted_idempotency_nonnegative
                     CHECK (accepted_idempotency_row_count >= 0),
                 accepted_outbox_row_count bigint NOT NULL
                     CONSTRAINT registry_field_encryption_flip_accepted_outbox_nonnegative
                     CHECK (accepted_outbox_row_count >= 0),
                 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 PRIMARY KEY (entity_id, field_id)
             );
             REVOKE ALL ON TABLE registry_internal.registry_field_encryption_flips FROM PUBLIC;",
        ))
        .await?;
    install_migration_ledger(migration, runtime_role).await?;
    let revoke = RuntimeRevoke::detect(migration, runtime_role).await?;
    migration
        .batch_execute(&format!(
            "REVOKE ALL ON SCHEMA registry_internal, registry_data, registry_source, registry_derived, registry_context FROM {};\n\
             GRANT USAGE ON SCHEMA registry_internal, registry_data, registry_source, registry_derived, registry_context TO {};\n\
             {}\n\
             GRANT SELECT ON TABLE registry_internal.registry_state TO {};\n\
             {}\n\
             GRANT SELECT ON TABLE registry_internal.registry_field_encryption_keys TO {};\n\
             {}\n\
             GRANT SELECT ON TABLE registry_internal.registry_field_encryption_flips TO {};",
            revoke.with_public(),
            runtime_role.quoted(),
            revoke.revoke_all_on("TABLE registry_internal.registry_state"),
            runtime_role.quoted(),
            revoke.revoke_all_on("TABLE registry_internal.registry_field_encryption_keys"),
            runtime_role.quoted(),
            revoke.revoke_all_on("TABLE registry_internal.registry_field_encryption_flips"),
            runtime_role.quoted(),
        ))
        .await?;
    Ok(())
}

/// Initializes a Registry state row against an explicit closed catalog,
/// records the applied initial activation in the ledger the way an initial
/// apply would, and records the physical claim of the database it runs in.
#[cfg(feature = "postgres-test")]
async fn initialize_registry_state_for_catalog(
    migration: &impl GenericClient,
    runtime_role: &SqlIdentifier,
    expected_catalog: &ExpectedManagedCatalog,
    initial: &RegistryStateTestIdentity<'_>,
) -> Result<ExpectedRegistryIdentity> {
    initial.validate()?;
    let schema_fingerprint =
        managed_schema_fingerprint(migration, runtime_role, expected_catalog).await?;
    let expected = ExpectedRegistryIdentity {
        package_id: initial.package_id.to_owned(),
        database_id: initial.database_id.to_owned(),
        package_digest: initial.package_digest(),
        activation_id: initial.activation_id(),
        schema_fingerprint,
    };
    let changed = migration
        .execute(
            "INSERT INTO registry_internal.registry_state (
                 singleton, package_id, database_id, active_package_digest,
                 active_activation_id, schema_fingerprint, maintenance_status
             ) VALUES (true, $1, $2, $3, $4, $5, 'ready')
             ON CONFLICT (singleton) DO NOTHING",
            &[
                &expected.package_id,
                &expected.database_id,
                &expected.package_digest,
                &expected.activation_uuid()?,
                &expected.schema_fingerprint,
            ],
        )
        .await?;
    if changed != 1 {
        return Err(PostgresKernelError::CatalogInvariant(
            "Registry state is already initialized",
        ));
    }
    migration
        .execute(
            "INSERT INTO registry_internal.registry_migrations (
                 activation_id, apply_order, package_digest, predecessor_package_digest,
                 registry_revision, plan_kind, migration_kind, statement_checksums,
                 artifact_paths, artifact_checksums, outcome, completed_at, applied_at,
                 role_mode, runtime_role
             ) VALUES (
                 $1, 1, $2, NULL, $3, 'initial', 'compiled-additive', ARRAY[$2]::text[],
                 ARRAY[]::text[], ARRAY[]::text[], 'applied', transaction_timestamp(),
                 transaction_timestamp(),
                 CASE WHEN $4 = current_user THEN 'single' ELSE 'split' END, $4
             )",
            &[
                &expected.activation_uuid()?,
                &expected.package_digest,
                &initial.label,
                &runtime_role.as_str(),
            ],
        )
        .await?;
    crate::instance_claim::record_if_unclaimed(migration).await?;
    Ok(expected)
}

/// Test-only helper for integration fixtures that install a compiled catalog
/// directly instead of loading a verified initial package.
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn initialize_registry_state_for_catalog_test(
    migration: &impl GenericClient,
    runtime_role: &SqlIdentifier,
    expected_catalog: &ExpectedManagedCatalog,
    identity: RegistryStateTestIdentity<'_>,
) -> Result<ExpectedRegistryIdentity> {
    initialize_registry_state_for_catalog(migration, runtime_role, expected_catalog, &identity)
        .await
}

/// Test-only helper for integration fixtures that install a compiled Registry
/// directly and need the same empty history boundary a verified initial package
/// would create. It refuses if any compiled live table or revision journal is
/// already nonempty. Fixtures seed and index current revisions after this
/// empty boundary has been installed.
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn initialize_compiled_registry_state_for_test(
    migration: &impl GenericClient,
    runtime_role: &SqlIdentifier,
    registry: &CompiledRegistry,
    identity: RegistryStateTestIdentity<'_>,
) -> Result<ExpectedRegistryIdentity> {
    let expected = initialize_registry_state_for_catalog(
        migration,
        runtime_role,
        &ExpectedManagedCatalog::compiled(registry),
        &identity,
    )
    .await?;
    install_empty_history_baseline_for_compiled_registry(
        migration,
        registry,
        &expected.activation_id,
    )
    .await?;
    Ok(expected)
}

pub async fn verify_catalog_identity_for_catalog(
    client: &impl GenericClient,
    expected: &ExpectedRegistryIdentity,
    expected_catalog: &ExpectedManagedCatalog,
    migration_role: &SqlIdentifier,
    runtime_role: &SqlIdentifier,
) -> Result<CatalogIdentity> {
    expected.validate()?;
    let row = client
        .query_opt(
            "SELECT package_id, database_id, active_package_digest,
                    active_activation_id::text, schema_fingerprint
             FROM registry_internal.registry_state
             WHERE singleton",
            &[],
        )
        .await?
        .ok_or(PostgresKernelError::RegistryUnavailable)?;
    let actual = CatalogIdentity {
        package_id: row.get(0),
        database_id: row.get(1),
        package_digest: row.get(2),
        activation_id: row.get(3),
        schema_fingerprint: row.get(4),
    };
    actual.validate()?;
    if actual.package_id != expected.package_id
        || actual.database_id != expected.database_id
        || actual.package_digest != expected.package_digest
        || actual.activation_id != expected.activation_id
        || actual.schema_fingerprint != expected.schema_fingerprint
    {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    verify_managed_catalog(
        client,
        expected,
        expected_catalog,
        migration_role,
        runtime_role,
    )
    .await?;
    Ok(actual)
}

pub(crate) async fn verify_managed_catalog(
    client: &impl GenericClient,
    expected: &ExpectedRegistryIdentity,
    expected_catalog: &ExpectedManagedCatalog,
    migration_role: &SqlIdentifier,
    runtime_role: &SqlIdentifier,
) -> Result<()> {
    verify_managed_owners_for_catalog(client, migration_role, runtime_role, expected_catalog)
        .await?;
    verify_closed_ambient_catalog(client).await?;
    verify_exact_acl(
        client,
        runtime_role,
        migration_role == runtime_role,
        expected_catalog,
    )
    .await?;
    verify_row_security(client, expected_catalog).await?;
    verify_policies(client, expected_catalog, runtime_role).await?;
    if fingerprint_catalog(client, runtime_role).await? != expected.schema_fingerprint {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    Ok(())
}

async fn verify_closed_ambient_catalog(client: &impl GenericClient) -> Result<()> {
    let row = client
        .query_one(
            "SELECT
                 EXISTS (
                     SELECT 1
                     FROM pg_catalog.pg_class c
                     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                     WHERE n.nspname = ANY($1::text[])
                       AND c.relkind NOT IN ('r', 'S', 'i', 'v')
                 ),
                 EXISTS (
                     SELECT 1
                     FROM pg_catalog.pg_trigger t
                     JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
                     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                     WHERE n.nspname = ANY($1::text[])
                       AND NOT t.tgisinternal
                 ),
                 EXISTS (
                     SELECT 1
                     FROM pg_catalog.pg_rewrite w
                     JOIN pg_catalog.pg_class c ON c.oid = w.ev_class
                     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                     WHERE n.nspname = ANY($1::text[])
                       AND c.relkind = 'r'
                 ),
                 EXISTS (
                     SELECT 1
                     FROM pg_catalog.pg_proc p
                     JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
                     WHERE n.nspname = ANY($1::text[])
                       AND NOT (
                           (n.nspname = 'registry_context'
                           AND ((p.proname IN ('evaluation_date', 'spatial_bbox_geometry')
                                 AND pg_catalog.pg_get_function_identity_arguments(p.oid) = '')
                                OR (p.proname ~ '^membership_[0-9a-f]{24}$'
                                    AND pg_catalog.pg_get_function_identity_arguments(p.oid) = 'uuid'
                                    AND p.prorettype = 'boolean'::regtype
                                    AND NOT p.proretset
                                    AND NOT p.prosecdef
                                    AND p.provolatile = 's')
                                OR (p.proname ~ '^consent_[0-9a-f]{24}$'
                                    AND pg_catalog.pg_get_function_identity_arguments(p.oid) = ''
                                    AND p.prorettype = 'uuid'::regtype
                                    AND p.proretset
                                    AND NOT p.prosecdef
                                    AND p.provolatile = 's')))
                           OR (n.nspname = 'registry_internal'
                               AND p.proname IN ('expire_subject_access_log', 'expire_action_evidence_uses')
                               AND pg_catalog.pg_get_function_identity_arguments(p.oid) = ''
                               AND p.prorettype = 'bigint'::regtype
                               AND NOT p.proretset AND p.prosecdef
                               AND p.provolatile = 'v'
                               AND p.prolang = (SELECT oid FROM pg_catalog.pg_language WHERE lanname = 'sql')
                               AND p.proconfig = ARRAY['search_path=pg_catalog, registry_internal'])
                           OR (n.nspname = 'registry_internal'
                               AND p.proname = 'withdraw_statistical_release'
                               AND pg_catalog.pg_get_function_identity_arguments(p.oid) = 'text, text, bigint, text'
                               AND p.prorettype = 'boolean'::regtype
                               AND NOT p.proretset AND p.prosecdef
                               AND p.provolatile = 'v'
                               AND p.prolang = (SELECT oid FROM pg_catalog.pg_language WHERE lanname = 'sql')
                               AND p.proconfig = ARRAY['search_path=pg_catalog, registry_internal'])
                       )
                 ),
                 EXISTS (
                     SELECT 1
                     FROM pg_catalog.pg_publication_rel pr
                     JOIN pg_catalog.pg_class c ON c.oid = pr.prrelid
                     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                     WHERE n.nspname = ANY($1::text[])
                 ) OR EXISTS (
                     SELECT 1
                     FROM pg_catalog.pg_publication_namespace pn
                     JOIN pg_catalog.pg_namespace n ON n.oid = pn.pnnspid
                     WHERE n.nspname = ANY($1::text[])
                 ) OR EXISTS (
                     SELECT 1 FROM pg_catalog.pg_publication WHERE puballtables
                 )",
            &[&MANAGED_SCHEMAS],
        )
        .await?;
    if (0..5).any(|index| row.get::<_, bool>(index)) {
        return Err(PostgresKernelError::CatalogInvariant(
            "managed catalog contains unsupported executable objects",
        ));
    }
    Ok(())
}

async fn verify_managed_owners_for_catalog(
    client: &impl GenericClient,
    migration_role: &SqlIdentifier,
    runtime_role: &SqlIdentifier,
    expected_catalog: &ExpectedManagedCatalog,
) -> Result<()> {
    // PostgreSQL otherwise resolves this UNION column to the 63-byte `name`
    // type and truncates schema-qualified identifiers that are valid as text.
    let rows = client
        .query(
            "SELECT 'schema', n.nspname::text, r.rolname
             FROM pg_catalog.pg_namespace n
             JOIN pg_catalog.pg_roles r ON r.oid = n.nspowner
             WHERE n.nspname = ANY($1::text[])
             UNION ALL
             SELECT CASE c.relkind WHEN 'r' THEN 'table' WHEN 'v' THEN 'view' ELSE 'sequence' END,
                    n.nspname || '.' || c.relname,
                    r.rolname
             FROM pg_catalog.pg_class c
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
             JOIN pg_catalog.pg_roles r ON r.oid = c.relowner
             WHERE n.nspname = ANY($1::text[])
               AND c.relkind IN ('r', 'v', 'S')
             UNION ALL
             SELECT 'function',
                    n.nspname || '.' || p.proname || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')',
                    r.rolname
             FROM pg_catalog.pg_proc p
             JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
             JOIN pg_catalog.pg_roles r ON r.oid = p.proowner
             WHERE n.nspname = ANY($1::text[])",
            &[&MANAGED_SCHEMAS],
        )
        .await?;
    let actual: BTreeSet<(String, String, String)> = rows
        .into_iter()
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .collect();
    let migration_owner = migration_role.as_str().to_owned();
    let spatial_bbox_owner = spatial_bbox_role(runtime_role).as_str().to_owned();
    let expected = expected_catalog
        .objects
        .iter()
        .map(|object| {
            let owner = match object.owner {
                DdlObjectOwner::Migration => &migration_owner,
                DdlObjectOwner::SpatialBbox => &spatial_bbox_owner,
            };
            (
                object.kind.as_str().to_owned(),
                object.name.clone(),
                owner.clone(),
            )
        })
        .collect();
    if actual != expected {
        return Err(PostgresKernelError::CatalogInvariant(
            "managed object ownership differs from the closed catalog",
        ));
    }
    Ok(())
}

async fn verify_row_security(
    client: &impl GenericClient,
    expected_catalog: &ExpectedManagedCatalog,
) -> Result<()> {
    let rows = client
        .query(
            "SELECT n.nspname || '.' || c.relname, c.relrowsecurity, c.relforcerowsecurity
             FROM pg_catalog.pg_class c
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = ANY($1::text[]) AND c.relkind = 'r'",
            &[&MANAGED_SCHEMAS],
        )
        .await?;
    let actual: BTreeSet<(String, bool, bool)> = rows
        .into_iter()
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .collect();
    let expected = expected_catalog
        .objects
        .iter()
        .filter_map(|object| {
            object
                .row_security
                .map(|(enabled, forced)| (object.name.clone(), enabled, forced))
        })
        .collect();
    if actual != expected {
        return Err(PostgresKernelError::CatalogInvariant(
            "managed row-security flags differ from the closed catalog",
        ));
    }
    Ok(())
}

async fn verify_policies(
    client: &impl GenericClient,
    expected_catalog: &ExpectedManagedCatalog,
    runtime_role: &SqlIdentifier,
) -> Result<()> {
    let rows = client
        .query(
            "SELECT n.nspname || '.' || c.relname,
                    p.polname,
                    p.polcmd::text,
                    p.polpermissive,
                    CASE
                        WHEN p.polroles = ARRAY[0::oid] THEN 'public'
                        WHEN p.polroles = ARRAY[runtime.oid] THEN 'runtime'
                        WHEN p.polroles = ARRAY[bbox.oid] THEN 'spatial_bbox'
                        ELSE 'other'
                    END,
                    p.polqual IS NOT NULL,
                    p.polwithcheck IS NOT NULL
             FROM pg_catalog.pg_policy p
             JOIN pg_catalog.pg_class c ON c.oid = p.polrelid
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
             LEFT JOIN pg_catalog.pg_roles runtime ON runtime.rolname = $2
             LEFT JOIN pg_catalog.pg_roles bbox ON bbox.rolname = $3
             WHERE n.nspname = ANY($1::text[])",
            &[
                &MANAGED_SCHEMAS,
                &runtime_role.as_str(),
                &spatial_bbox_role(runtime_role).as_str(),
            ],
        )
        .await?;
    let actual: BTreeSet<ManagedPolicy> = rows
        .into_iter()
        .map(|row| {
            if !row.get::<_, bool>(3) {
                return Err(PostgresKernelError::CatalogInvariant(
                    "managed policy mode differs from the closed catalog",
                ));
            }
            let role = match row.get::<_, String>(4).as_str() {
                "public" => ManagedPolicyRole::Public,
                "runtime" => ManagedPolicyRole::Runtime,
                "spatial_bbox" => ManagedPolicyRole::SpatialBbox,
                _ => {
                    return Err(PostgresKernelError::CatalogInvariant(
                        "managed policy role differs from the closed catalog",
                    ));
                }
            };
            Ok(ManagedPolicy {
                table: row.get(0),
                name: row.get(1),
                command: row.get(2),
                role,
                has_using: row.get(5),
                has_check: row.get(6),
            })
        })
        .collect::<Result<_>>()?;
    if actual != expected_catalog.policies {
        return Err(PostgresKernelError::CatalogInvariant(
            "managed policy inventory differs from the closed catalog",
        ));
    }
    Ok(())
}

async fn query_categorized_acl(
    client: &impl GenericClient,
    runtime_role: &SqlIdentifier,
) -> Result<Vec<tokio_postgres::Row>> {
    Ok(client
        .query(
            "WITH managed_objects(object_kind, object_name, owner_oid, acl) AS (
                 SELECT 'schema'::text,
                        n.nspname::text,
                        n.nspowner,
                        COALESCE(n.nspacl, pg_catalog.acldefault('n', n.nspowner))
                 FROM pg_catalog.pg_namespace n
                 WHERE n.nspname = ANY($2::text[])
                 UNION ALL
                 SELECT CASE c.relkind WHEN 'r' THEN 'table' WHEN 'v' THEN 'view' ELSE 'sequence' END,
                        n.nspname || '.' || c.relname,
                        c.relowner,
                        COALESCE(
                            c.relacl,
                            CASE c.relkind
                                WHEN 'r' THEN pg_catalog.acldefault('r', c.relowner)
                                WHEN 'v' THEN pg_catalog.acldefault('r', c.relowner)
                                ELSE pg_catalog.acldefault('S', c.relowner)
                            END
                        )
                 FROM pg_catalog.pg_class c
                 JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                 WHERE n.nspname = ANY($2::text[])
                   AND c.relkind IN ('r', 'v', 'S')
                 UNION ALL
                 SELECT 'function'::text,
                        n.nspname || '.' || p.proname || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')',
                        p.proowner,
                        COALESCE(p.proacl, pg_catalog.acldefault('f', p.proowner))
                 FROM pg_catalog.pg_proc p
                 JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
                 WHERE n.nspname = ANY($2::text[])
             ), runtime AS (
                 SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $1
             ), spatial_bbox AS (
                 SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $3
             )
             SELECT o.object_kind,
                    o.object_name,
                    CASE
                        WHEN a.grantee = 0 THEN 'public'
                        WHEN a.grantee = o.owner_oid THEN 'owner'
                        WHEN a.grantee = runtime.oid THEN 'runtime'
                        WHEN a.grantee = spatial_bbox.oid THEN 'spatial_bbox'
                        ELSE 'other'
                    END,
                    a.privilege_type,
                    a.is_grantable
             FROM managed_objects o
             CROSS JOIN runtime
             LEFT JOIN spatial_bbox ON true
             CROSS JOIN LATERAL pg_catalog.aclexplode(o.acl) a
             ORDER BY 1, 2, 3, 4, 5",
            &[
                &runtime_role.as_str(),
                &MANAGED_SCHEMAS,
                &spatial_bbox_role(runtime_role).as_str(),
            ],
        )
        .await?)
}

/// Compares every managed object ACL with the closed catalog. In single-role
/// mode the runtime role owns each migration-owned object, so its grants there
/// are the owner privileges and carry no separate runtime row.
async fn verify_exact_acl(
    client: &impl GenericClient,
    runtime_role: &SqlIdentifier,
    single_role: bool,
    expected_catalog: &ExpectedManagedCatalog,
) -> Result<()> {
    let actual: BTreeSet<(String, String, String, String, bool)> =
        query_categorized_acl(client, runtime_role)
            .await?
            .into_iter()
            .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4)))
            .collect();
    let mut expected = BTreeSet::new();
    for object in &expected_catalog.objects {
        let owner_privileges = match object.kind {
            ManagedObjectKind::Schema => &["CREATE", "USAGE"][..],
            ManagedObjectKind::Table => TABLE_OWNER_PRIVILEGES,
            ManagedObjectKind::View => TABLE_OWNER_PRIVILEGES,
            ManagedObjectKind::Sequence => SEQUENCE_OWNER_PRIVILEGES,
            ManagedObjectKind::Function => FUNCTION_OWNER_PRIVILEGES,
        };
        for privilege in owner_privileges {
            expected.insert((
                object.kind.as_str().to_owned(),
                object.name.clone(),
                "owner".to_owned(),
                (*privilege).to_owned(),
                false,
            ));
        }
        let runtime_is_owner = single_role && object.owner == DdlObjectOwner::Migration;
        for privilege in object
            .runtime_privileges
            .iter()
            .filter(|_| !runtime_is_owner)
        {
            expected.insert((
                object.kind.as_str().to_owned(),
                object.name.clone(),
                "runtime".to_owned(),
                privilege.clone(),
                false,
            ));
        }
        for privilege in &object.spatial_bbox_privileges {
            expected.insert((
                object.kind.as_str().to_owned(),
                object.name.clone(),
                "spatial_bbox".to_owned(),
                privilege.clone(),
                false,
            ));
        }
    }
    if actual != expected {
        return Err(PostgresKernelError::CatalogInvariant(
            "managed object privileges differ from the closed catalog",
        ));
    }
    verify_exact_column_acl(client, runtime_role, single_role, expected_catalog).await?;
    Ok(())
}

/// Whether a split-role runtime role lacks a grant the closed catalog gives
/// it. Reassigning an object's ownership back to the migration role strips
/// the grants the runtime role held on it, so an apply of the active package
/// treats missing grants as pending and reissues them.
pub(crate) async fn runtime_grants_missing(
    client: &impl GenericClient,
    runtime_role: &SqlIdentifier,
    expected_catalog: &ExpectedManagedCatalog,
) -> Result<bool> {
    let held: BTreeSet<(String, String, String)> = query_categorized_acl(client, runtime_role)
        .await?
        .into_iter()
        .filter(|row| row.get::<_, String>(2) == "runtime")
        .map(|row| (row.get(0), row.get(1), row.get(3)))
        .collect();
    let object_grant_missing = expected_catalog.objects.iter().any(|object| {
        object.runtime_privileges.iter().any(|privilege| {
            !held.contains(&(
                object.kind.as_str().to_owned(),
                object.name.clone(),
                privilege.clone(),
            ))
        })
    });
    if object_grant_missing {
        return Ok(true);
    }
    let checked_tables = expected_column_acl_tables(expected_catalog);
    let held_columns: BTreeSet<(String, String, String)> =
        query_categorized_column_acl(client, runtime_role, &checked_tables)
            .await?
            .into_iter()
            .filter(|row| row.get::<_, String>(2) == "runtime")
            .map(|row| (row.get(0), row.get(1), row.get(3)))
            .collect();
    Ok(expected_catalog
        .column_privileges
        .iter()
        .filter(|privilege| privilege.grantee == "runtime")
        .any(|privilege| {
            !held_columns.contains(&(
                privilege.table.clone(),
                privilege.column.clone(),
                privilege.privilege.clone(),
            ))
        }))
}

/// Compares every managed column ACL with the closed catalog. In single-role
/// mode a runtime column grant on a migration-owned table is held by the owner.
async fn verify_exact_column_acl(
    client: &impl GenericClient,
    runtime_role: &SqlIdentifier,
    single_role: bool,
    expected_catalog: &ExpectedManagedCatalog,
) -> Result<()> {
    let checked_tables = expected_column_acl_tables(expected_catalog);
    let rows = query_categorized_column_acl(client, runtime_role, &checked_tables).await?;
    let actual: BTreeSet<ManagedColumnPrivilege> = rows
        .into_iter()
        .map(|row| ManagedColumnPrivilege {
            table: row.get(0),
            column: row.get(1),
            grantee: row.get(2),
            privilege: row.get(3),
            grantable: row.get(4),
        })
        .collect();
    let expected: BTreeSet<ManagedColumnPrivilege> = expected_catalog
        .column_privileges
        .iter()
        .cloned()
        .map(|mut privilege| {
            if single_role
                && privilege.grantee == "runtime"
                && expected_catalog.objects.iter().any(|object| {
                    object.name == privilege.table && object.owner == DdlObjectOwner::Migration
                })
            {
                "owner".clone_into(&mut privilege.grantee);
            }
            privilege
        })
        .collect();
    if actual != expected {
        return Err(PostgresKernelError::CatalogInvariant(
            "managed column privileges differ from the closed catalog",
        ));
    }
    Ok(())
}

fn expected_column_acl_tables(expected_catalog: &ExpectedManagedCatalog) -> Vec<String> {
    expected_catalog
        .objects
        .iter()
        .filter(|object| {
            matches!(
                object.kind,
                ManagedObjectKind::Table | ManagedObjectKind::View
            )
        })
        .map(|object| object.name.clone())
        .collect()
}

async fn query_categorized_column_acl(
    client: &impl GenericClient,
    runtime_role: &SqlIdentifier,
    checked_tables: &[String],
) -> Result<Vec<tokio_postgres::Row>> {
    if checked_tables.is_empty() {
        return Ok(Vec::new());
    }
    Ok(client
        .query(
            "WITH managed_column_acl AS (
                 SELECT n.nspname || '.' || c.relname AS table_name,
                        n.nspname,
                        c.relname,
                        a.attname AS column_name,
                        c.relowner AS owner_oid,
                        a.attacl AS acl
                   FROM pg_catalog.pg_class c
                   JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                   JOIN pg_catalog.pg_attribute a
                     ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
                  WHERE n.nspname = ANY($2::text[])
                    AND n.nspname || '.' || c.relname = ANY($3::text[])
                    AND c.relkind IN ('r', 'v')
                    AND a.attacl IS NOT NULL
             ), runtime AS (
                 SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $1
             )
             SELECT a.table_name,
                    a.column_name,
                    CASE
                        WHEN x.grantee = 0 THEN 'public'
                        WHEN x.grantee = a.owner_oid THEN 'owner'
                        WHEN x.grantee = runtime.oid THEN 'runtime'
                        ELSE 'other'
                    END,
                    x.privilege_type,
                    x.is_grantable,
                    a.nspname,
                    a.relname
               FROM managed_column_acl a
               CROSS JOIN runtime
               CROSS JOIN LATERAL pg_catalog.aclexplode(a.acl) x
              ORDER BY 1, 2, 3, 4, 5",
            &[&runtime_role.as_str(), &MANAGED_SCHEMAS, &checked_tables],
        )
        .await?)
}

/// Computes a deterministic fingerprint over the exact expected managed
/// catalog, including sequences, indexes, constraints, policies, and ACLs.
/// Table columns are identified by name, not their physical PostgreSQL slots.
pub async fn managed_schema_fingerprint(
    client: &impl GenericClient,
    runtime_role: &SqlIdentifier,
    expected_catalog: &ExpectedManagedCatalog,
) -> Result<String> {
    let migration_role = current_role(client).await?;
    verify_managed_owners_for_catalog(client, &migration_role, runtime_role, expected_catalog)
        .await?;
    verify_closed_ambient_catalog(client).await?;
    verify_exact_acl(
        client,
        runtime_role,
        &migration_role == runtime_role,
        expected_catalog,
    )
    .await?;
    verify_row_security(client, expected_catalog).await?;
    verify_policies(client, expected_catalog, runtime_role).await?;
    fingerprint_catalog(client, runtime_role).await
}

async fn fingerprint_catalog(
    client: &impl GenericClient,
    runtime_role: &SqlIdentifier,
) -> Result<String> {
    let prior_search_path: String = client
        .query_one("SELECT pg_catalog.current_setting('search_path')", &[])
        .await?
        .get(0);
    let column_rows = client
        .query(
            "WITH deparse_context AS MATERIALIZED (
                 SELECT pg_catalog.set_config('search_path', 'pg_catalog', true)
             )
             SELECT n.nspname,
                    c.relname,
                    c.relkind::text,
                    c.relrowsecurity,
                    c.relforcerowsecurity,
                    c.relowner = n.nspowner,
                    a.attnum,
                    a.attname,
                    pg_catalog.format_type(a.atttypid, a.atttypmod),
                    a.attnotnull,
                    COALESCE(pg_catalog.pg_get_expr(d.adbin, d.adrelid), ''),
                    COALESCE(collation_namespace.nspname, ''),
                    COALESCE(coll.collname, '')
             FROM deparse_context
             CROSS JOIN pg_catalog.pg_class c
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
             JOIN pg_catalog.pg_attribute a
               ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
             LEFT JOIN pg_catalog.pg_attrdef d
               ON d.adrelid = c.oid AND d.adnum = a.attnum
             LEFT JOIN pg_catalog.pg_collation coll ON coll.oid = a.attcollation
             LEFT JOIN pg_catalog.pg_namespace collation_namespace
               ON collation_namespace.oid = coll.collnamespace
             WHERE n.nspname = ANY($1::text[])
               AND c.relkind IN ('r', 'v', 'S')
             ORDER BY n.nspname, c.relname,
                      CASE WHEN c.relkind = 'r' THEN a.attname END COLLATE \"C\",
                      a.attnum",
            &[&MANAGED_SCHEMAS],
        )
        .await?;
    let constraint_rows = client
        .query(
            "WITH deparse_context AS MATERIALIZED (
                 SELECT pg_catalog.set_config('search_path', 'pg_catalog', true)
             )
             SELECT n.nspname,
                    c.relname,
                    x.conname,
                    x.contype::text,
                    pg_catalog.pg_get_constraintdef(x.oid, false),
                    x.convalidated
             FROM deparse_context
             CROSS JOIN pg_catalog.pg_constraint x
             JOIN pg_catalog.pg_class c ON c.oid = x.conrelid
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = ANY($1::text[])
             ORDER BY n.nspname, c.relname, x.conname",
            &[&MANAGED_SCHEMAS],
        )
        .await?;
    let index_rows = client
        .query(
            "WITH deparse_context AS MATERIALIZED (
                 SELECT pg_catalog.set_config('search_path', 'pg_catalog', true)
             )
             SELECT n.nspname,
                    table_class.relname,
                    index_class.relname,
                    pg_catalog.pg_get_indexdef(index_class.oid, 0, false)
             FROM deparse_context
             CROSS JOIN pg_catalog.pg_index x
             JOIN pg_catalog.pg_class table_class ON table_class.oid = x.indrelid
             JOIN pg_catalog.pg_class index_class ON index_class.oid = x.indexrelid
             JOIN pg_catalog.pg_namespace n ON n.oid = table_class.relnamespace
             WHERE n.nspname = ANY($1::text[])
             ORDER BY n.nspname, table_class.relname, index_class.relname",
            &[&MANAGED_SCHEMAS],
        )
        .await?;
    let policy_rows = client
        .query(
            "WITH deparse_context AS MATERIALIZED (
                 SELECT pg_catalog.set_config('search_path', 'pg_catalog', true)
             )
             SELECT n.nspname,
                    c.relname,
                    p.polname,
                    p.polcmd::text,
                    p.polpermissive,
                    p.polroles = ARRAY[0::oid],
                    COALESCE(pg_catalog.pg_get_expr(p.polqual, p.polrelid), ''),
                    COALESCE(pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), '')
             FROM deparse_context
             CROSS JOIN pg_catalog.pg_policy p
             JOIN pg_catalog.pg_class c ON c.oid = p.polrelid
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = ANY($1::text[])
             ORDER BY n.nspname, c.relname, p.polname",
            &[&MANAGED_SCHEMAS],
        )
        .await?;
    let view_rows = client
        .query(
            "WITH deparse_context AS MATERIALIZED (
                 SELECT pg_catalog.set_config('search_path', 'pg_catalog', true)
             )
             SELECT n.nspname,
                    c.relname,
                    pg_catalog.pg_get_viewdef(c.oid, false),
                    COALESCE(array_to_string(c.reloptions, ','), '')
             FROM deparse_context
             CROSS JOIN pg_catalog.pg_class c
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = ANY($1::text[])
               AND c.relkind = 'v'
             ORDER BY n.nspname, c.relname",
            &[&MANAGED_SCHEMAS],
        )
        .await?;
    let function_rows = client
        .query(
            "WITH deparse_context AS MATERIALIZED (
                 SELECT pg_catalog.set_config('search_path', 'pg_catalog', true)
             )
             SELECT n.nspname,
                    p.proname,
                    pg_catalog.pg_get_function_identity_arguments(p.oid),
                    pg_catalog.format_type(p.prorettype, NULL),
                    p.provolatile::text,
                    p.prosecdef,
                    p.prokind::text,
                    pg_catalog.pg_get_functiondef(p.oid)
             FROM deparse_context
             CROSS JOIN pg_catalog.pg_proc p
             JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
             WHERE n.nspname = ANY($1::text[])
             ORDER BY n.nspname, p.proname, pg_catalog.pg_get_function_identity_arguments(p.oid)",
            &[&MANAGED_SCHEMAS],
        )
        .await?;
    let acl_rows = query_categorized_acl(client, runtime_role).await?;
    client
        .query_one(
            "SELECT pg_catalog.set_config('search_path', $1, true)",
            &[&prior_search_path],
        )
        .await?;
    let mut hasher = Sha256::new();
    // Runtime statements address table columns explicitly by name. ALTER TABLE
    // appends physical slots, whereas a fresh install uses compiler field order.
    // v6 hashes the same named table schema for both histories, including after
    // dropped-column gaps. View/sequence order and every other catalog input
    // remain covered. The versioned domain keeps a hash of physical column
    // order from ever matching this one.
    hasher.update(b"breg/catalog/v6/columns");
    for row in column_rows {
        for index in [0, 1, 2, 7, 8, 10, 11, 12] {
            hash_text(&mut hasher, &row.get::<_, String>(index));
        }
        for index in [3, 4, 5, 9] {
            hash_bool(&mut hasher, row.get(index));
        }
        if row.get::<_, &str>(2) != "r" {
            hasher.update(row.get::<_, i16>(6).to_be_bytes());
        }
    }
    hasher.update(b"breg/catalog/v4/constraints");
    for row in constraint_rows {
        let kind = row.get::<_, String>(3);
        if kind == "n" && !row.get::<_, bool>(5) {
            return Err(PostgresKernelError::CatalogInvariant(
                "a managed NOT NULL constraint is not validated; validate it before applying the package",
            ));
        }
        if !constraint_belongs_in_fingerprint(&kind) {
            continue;
        }
        for index in 0..5 {
            hash_text(&mut hasher, &row.get::<_, String>(index));
        }
    }
    hasher.update(b"breg/catalog/v3/indexes");
    for row in index_rows {
        for index in 0..4 {
            hash_text(&mut hasher, &row.get::<_, String>(index));
        }
    }
    hasher.update(b"breg/catalog/v3/policies");
    for row in policy_rows {
        for index in [0, 1, 2, 3, 6, 7] {
            hash_text(&mut hasher, &row.get::<_, String>(index));
        }
        hash_bool(&mut hasher, row.get(4));
        hash_bool(&mut hasher, row.get(5));
    }
    hasher.update(b"breg/catalog/v4/views");
    for row in view_rows {
        for index in 0..4 {
            hash_text(&mut hasher, &row.get::<_, String>(index));
        }
    }
    hasher.update(b"breg/catalog/v4/functions");
    for row in function_rows {
        for index in [0, 1, 2, 3, 4, 6, 7] {
            hash_text(&mut hasher, &row.get::<_, String>(index));
        }
        hash_bool(&mut hasher, row.get(5));
    }
    // The fingerprint leaves runtime grants out of the hash, so one
    // package fingerprint holds in single-role and split-role mode, where the
    // owner holds the runtime grants itself. Every runtime grant is still
    // compared exactly with the closed catalog before a fingerprint is taken.
    hasher.update(b"breg/catalog/v6/acl");
    for row in acl_rows {
        if row.get::<_, &str>(2) == "runtime" {
            continue;
        }
        for index in 0..4 {
            hash_text(&mut hasher, &row.get::<_, String>(index));
        }
        hash_bool(&mut hasher, row.get(4));
    }
    let digest = hasher.finalize();
    let mut fingerprint = String::with_capacity(7 + digest.len() * 2);
    fingerprint.push_str("sha256:");
    for byte in digest {
        write!(&mut fingerprint, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(fingerprint)
}

async fn current_role(client: &impl GenericClient) -> Result<SqlIdentifier> {
    let role: String = client.query_one("SELECT current_user", &[]).await?.get(0);
    SqlIdentifier::parse(&role)
}

fn hash_text(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn hash_bool(hasher: &mut Sha256, value: bool) {
    hasher.update([u8::from(value)]);
}

fn constraint_belongs_in_fingerprint(kind: &str) -> bool {
    // PostgreSQL 18 exposes NOT NULL constraints through pg_constraint as
    // contype=n. Requiredness is already hashed from pg_attribute.attnotnull,
    // which PostgreSQL 17 and 18 both expose, so including the new catalog row
    // would count the same invariant twice and make one schema major-specific.
    kind != "n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_null_is_fingerprinted_once_through_the_column_catalog() {
        assert!(!constraint_belongs_in_fingerprint("n"));
        for kind in ["c", "f", "p", "u", "x"] {
            assert!(
                constraint_belongs_in_fingerprint(kind),
                "constraint kind {kind} remains part of the fingerprint"
            );
        }
    }

    #[test]
    fn the_inventory_names_every_platform_delivery_object() {
        let inventoried: Vec<&str> = DELIVERY_TABLE_PRIVILEGES
            .iter()
            .map(|(name, _)| *name)
            .chain([DELIVERY_SEQUENCE])
            .collect();
        for object in
            registry_platform_hooks::delivery_schema::object_names(crate::webhook::DELIVERY_SCHEMA)
        {
            assert!(
                inventoried.contains(&object.as_str()),
                "the managed catalog does not inventory the delivery object {object}"
            );
        }
    }
}
