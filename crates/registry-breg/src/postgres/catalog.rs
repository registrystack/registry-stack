// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeSet, fmt::Write};

use sha2::{Digest, Sha256};
use tokio_postgres::GenericClient;

use crate::generated_ddl::{DdlObjectOwner, DdlPolicyRole, PolicyCommand, TablePrivilege};
use crate::model::CompiledRegistry;

#[cfg(feature = "postgres-test")]
use super::schema::install_empty_history_baseline_for_compiled_registry;
use super::{
    migration_ledger::install_migration_ledger, spatial_bbox_role, verify_btree_gist,
    PostgresKernelError, Result, SqlIdentifier,
};

const MANAGED_SCHEMAS: &[&str] = &[
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

/// Exact managed PostgreSQL inventory accepted by catalog verification.
///
/// Construction is deliberately closed to either the explicit feasibility
/// kernel or one compiler-produced Registry plus the current product-owned
/// mutation tables. There is no wildcard or ambient-catalog mode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedManagedCatalog {
    objects: BTreeSet<ManagedObject>,
    column_privileges: BTreeSet<ManagedColumnPrivilege>,
    policies: BTreeSet<ManagedPolicy>,
}

impl ExpectedManagedCatalog {
    /// Explicit compatibility inventory for the W2 feasibility kernel.
    #[must_use]
    pub fn kernel() -> Self {
        let mut catalog = Self::base();
        catalog.table(
            "registry_data.kernel_records",
            ["DELETE", "INSERT", "SELECT", "UPDATE"],
            std::iter::empty::<&str>(),
            Some((true, true)),
        );
        catalog.policies.insert(ManagedPolicy {
            table: "registry_data.kernel_records".to_owned(),
            name: "registry_authority_policy".to_owned(),
            command: "*".to_owned(),
            role: ManagedPolicyRole::Public,
            has_using: true,
            has_check: true,
        });
        catalog
    }

    /// Exact product inventory for one compiled Registry.
    #[must_use]
    pub fn compiled(registry: &CompiledRegistry) -> Self {
        let mut catalog = Self::base();
        if registry.ddl().requires_postgis {
            catalog.grant_schema_spatial_bbox("registry_data");
            catalog.grant_schema_spatial_bbox("registry_context");
        }
        for (name, privileges) in [
            (
                "registry_internal.registry_revisions",
                &["INSERT", "SELECT"][..],
            ),
            (
                "registry_internal.registry_outbox",
                &["INSERT", "SELECT"][..],
            ),
            (
                "registry_internal.registry_webhook_deliveries",
                &["INSERT", "SELECT"][..],
            ),
            (
                "registry_internal.registry_webhook_delivery_state",
                &["INSERT", "SELECT", "UPDATE"][..],
            ),
            (
                "registry_internal.registry_audit",
                &["INSERT", "SELECT"][..],
            ),
            (
                "registry_internal.registry_audit_head",
                &["INSERT", "SELECT", "UPDATE"][..],
            ),
            (
                "registry_internal.registry_idempotency",
                &["INSERT", "SELECT"][..],
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
        ] {
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
        catalog.sequence(
            "registry_internal.registry_outbox_outbox_id_seq",
            ["SELECT", "USAGE"],
        );
        for (table, privileges) in crate::request_store::REQUEST_TABLES {
            catalog.table(
                &format!("registry_internal.{table}"),
                privileges.iter().copied(),
                std::iter::empty::<&str>(),
                Some((false, false)),
            );
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

/// Package and schema identity expected by one loaded runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedRegistryIdentity {
    pub package_id: String,
    pub environment: String,
    pub instance_id: String,
    pub database_id: String,
    pub package_revision: String,
    pub schema_fingerprint: String,
    pub package_sequence: i64,
}

impl ExpectedRegistryIdentity {
    pub fn validate(&self) -> Result<()> {
        if self.package_id.is_empty()
            || self.environment.is_empty()
            || self.instance_id.is_empty()
            || self.database_id.is_empty()
            || self.package_revision.is_empty()
            || self.schema_fingerprint.is_empty()
            || self.package_sequence < 0
        {
            return Err(PostgresKernelError::Configuration(
                "Registry identity fields must be non-empty and sequence must be non-negative",
            ));
        }
        Ok(())
    }
}

/// Verified identity read from the managed PostgreSQL catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogIdentity {
    pub package_id: String,
    pub environment: String,
    pub instance_id: String,
    pub database_id: String,
    pub package_revision: String,
    pub schema_fingerprint: String,
    pub package_sequence: i64,
}

impl CatalogIdentity {
    pub fn validate(&self) -> Result<()> {
        if self.package_id.is_empty()
            || self.environment.is_empty()
            || self.instance_id.is_empty()
            || self.database_id.is_empty()
            || self.package_revision.is_empty()
            || self.schema_fingerprint.is_empty()
            || self.package_sequence < 0
        {
            return Err(PostgresKernelError::RegistryUnavailable);
        }
        Ok(())
    }
}

#[cfg(feature = "postgres-test")]
struct InitialRegistryState<'a> {
    package_id: &'a str,
    environment: &'a str,
    instance_id: &'a str,
    database_id: &'a str,
    package_revision: &'a str,
    package_sequence: i64,
}

#[cfg(feature = "postgres-test")]
impl InitialRegistryState<'_> {
    fn validate(&self) -> Result<()> {
        if self.package_id.is_empty()
            || self.environment.is_empty()
            || self.instance_id.is_empty()
            || self.database_id.is_empty()
            || self.package_revision.is_empty()
            || self.package_sequence < 0
        {
            return Err(PostgresKernelError::Configuration(
                "initial Registry identity is incomplete",
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "postgres-test")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct RegistryStateTestIdentity<'a> {
    pub package_id: &'a str,
    pub environment: &'a str,
    pub instance_id: &'a str,
    pub database_id: &'a str,
    pub package_revision: &'a str,
    pub package_sequence: i64,
}

/// Installs the minimal internal state and RLS-protected data surface used by
/// the feasibility proof. The caller must already be the verified migration role.
pub async fn install_kernel_schema(
    migration: &impl GenericClient,
    runtime_role: &SqlIdentifier,
) -> Result<()> {
    verify_btree_gist(migration).await?;
    install_registry_state_schema(migration, runtime_role).await?;
    migration
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS registry_data.kernel_records (
                 record_id uuid PRIMARY KEY,
                 authority text NOT NULL
                     CONSTRAINT kernel_records_authority_nonempty CHECK (authority <> ''),
                 payload text NOT NULL,
                 package_revision text NOT NULL
                     CONSTRAINT kernel_records_package_revision_nonempty CHECK (package_revision <> '')
             );
             ALTER TABLE registry_data.kernel_records ENABLE ROW LEVEL SECURITY;
             ALTER TABLE registry_data.kernel_records FORCE ROW LEVEL SECURITY;
             DROP POLICY IF EXISTS registry_authority_policy ON registry_data.kernel_records;
             CREATE POLICY registry_authority_policy ON registry_data.kernel_records
                 USING (
                     NULLIF(current_setting('registry.access_profile', true), '') = 'operator'
                     AND NULLIF(current_setting('registry.principal', true), '') IS NOT NULL
                     AND NULLIF(current_setting('registry.purpose', true), '') = 'registry-administration'
                     AND jsonb_typeof(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 'array'
                     AND jsonb_array_length(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 1
                     AND jsonb_typeof(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb -> 0) = 'object'
                     AND ((NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb -> 0) - 'field' - 'operator' - 'values') = '{}'::jsonb
                     AND NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb -> 0 ->> 'field' = 'authority'
                     AND NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb -> 0 ->> 'operator' = 'equals'
                     AND jsonb_array_length(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb -> 0 -> 'values') = 1
                     AND authority = (NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb -> 0 -> 'values' ->> 0)
                 )
                 WITH CHECK (
                     NULLIF(current_setting('registry.access_profile', true), '') = 'operator'
                     AND NULLIF(current_setting('registry.principal', true), '') IS NOT NULL
                     AND NULLIF(current_setting('registry.purpose', true), '') = 'registry-administration'
                     AND jsonb_typeof(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 'array'
                     AND jsonb_array_length(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb) = 1
                     AND jsonb_typeof(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb -> 0) = 'object'
                     AND ((NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb -> 0) - 'field' - 'operator' - 'values') = '{}'::jsonb
                     AND NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb -> 0 ->> 'field' = 'authority'
                     AND NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb -> 0 ->> 'operator' = 'equals'
                     AND jsonb_array_length(NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb -> 0 -> 'values') = 1
                     AND authority = (NULLIF(current_setting('registry.row_boundaries', true), '')::jsonb -> 0 -> 'values' ->> 0)
                 );",
        )
        .await?;
    migration
        .batch_execute(&format!(
            "REVOKE ALL ON ALL TABLES IN SCHEMA registry_data FROM PUBLIC;\n\
             GRANT SELECT, INSERT, UPDATE, DELETE ON registry_data.kernel_records TO {};",
            runtime_role.quoted(),
        ))
        .await?;
    Ok(())
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
                 environment text NOT NULL
                     CONSTRAINT registry_state_environment_nonempty CHECK (environment <> ''),
                 package_id text NOT NULL
                     CONSTRAINT registry_state_package_id_nonempty CHECK (package_id <> ''),
                 instance_id text NOT NULL
                     CONSTRAINT registry_state_instance_id_nonempty CHECK (instance_id <> ''),
                 database_id text NOT NULL
                     CONSTRAINT registry_state_database_id_nonempty CHECK (database_id <> ''),
                 active_package_revision text NOT NULL
                     CONSTRAINT registry_state_package_revision_nonempty CHECK (active_package_revision <> ''),
                 schema_fingerprint text NOT NULL
                     CONSTRAINT registry_state_schema_fingerprint_nonempty CHECK (schema_fingerprint <> ''),
                 package_sequence bigint NOT NULL
                     CONSTRAINT registry_state_package_sequence_nonnegative CHECK (package_sequence >= 0),
                 maintenance_status text NOT NULL
                     CONSTRAINT registry_state_maintenance_status_closed
                     CHECK (maintenance_status IN ('ready', 'applying', 'failed')),
                 maintenance_target_revision text,
                 CONSTRAINT registry_state_maintenance_target_consistent CHECK (
                     (maintenance_status = 'ready' AND maintenance_target_revision IS NULL)
                     OR (maintenance_status IN ('applying', 'failed') AND maintenance_target_revision IS NOT NULL)
                 ),
                 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp()
             );
             REVOKE ALL ON TABLE registry_internal.registry_state FROM PUBLIC;",
        )
        .await?;
    install_migration_ledger(migration, runtime_role).await?;
    migration
        .batch_execute(&format!(
            "REVOKE ALL ON SCHEMA registry_internal, registry_data, registry_source, registry_derived, registry_context FROM PUBLIC, {};\n\
             GRANT USAGE ON SCHEMA registry_internal, registry_data, registry_source, registry_derived, registry_context TO {};\n\
             REVOKE ALL ON TABLE registry_internal.registry_state FROM {};\n\
             GRANT SELECT ON TABLE registry_internal.registry_state TO {};",
            runtime_role.quoted(),
            runtime_role.quoted(),
            runtime_role.quoted(),
            runtime_role.quoted(),
        ))
        .await?;
    Ok(())
}

/// Initializes a Registry state row against an explicit closed catalog.
#[cfg(feature = "postgres-test")]
async fn initialize_registry_state_for_catalog(
    migration: &impl GenericClient,
    runtime_role: &SqlIdentifier,
    expected_catalog: &ExpectedManagedCatalog,
    initial: &InitialRegistryState<'_>,
) -> Result<ExpectedRegistryIdentity> {
    initial.validate()?;
    let schema_fingerprint =
        managed_schema_fingerprint(migration, runtime_role, expected_catalog).await?;
    let changed = migration
        .execute(
            "INSERT INTO registry_internal.registry_state (
                 singleton, package_id, environment, instance_id, database_id,
                 active_package_revision, schema_fingerprint, package_sequence,
                 maintenance_status
             ) VALUES (true, $1, $2, $3, $4, $5, $6, $7, 'ready')
             ON CONFLICT (singleton) DO NOTHING",
            &[
                &initial.package_id,
                &initial.environment,
                &initial.instance_id,
                &initial.database_id,
                &initial.package_revision,
                &schema_fingerprint,
                &initial.package_sequence,
            ],
        )
        .await?;
    if changed != 1 {
        return Err(PostgresKernelError::CatalogInvariant(
            "Registry state is already initialized",
        ));
    }
    Ok(ExpectedRegistryIdentity {
        package_id: initial.package_id.to_owned(),
        environment: initial.environment.to_owned(),
        instance_id: initial.instance_id.to_owned(),
        database_id: initial.database_id.to_owned(),
        package_revision: initial.package_revision.to_owned(),
        schema_fingerprint,
        package_sequence: initial.package_sequence,
    })
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
    let initial = InitialRegistryState {
        package_id: identity.package_id,
        environment: identity.environment,
        instance_id: identity.instance_id,
        database_id: identity.database_id,
        package_revision: identity.package_revision,
        package_sequence: identity.package_sequence,
    };
    initialize_registry_state_for_catalog(migration, runtime_role, expected_catalog, &initial).await
}

/// Test-only helper for integration fixtures that install a compiled Registry
/// directly and need the same empty history boundary a verified initial package
/// would create. It refuses if any compiled live table or revision journal is
/// already nonempty, so fixtures with existing history must use an explicit
/// predecessor-baseline path instead.
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn initialize_compiled_registry_state_for_test(
    migration: &impl GenericClient,
    runtime_role: &SqlIdentifier,
    registry: &CompiledRegistry,
    identity: RegistryStateTestIdentity<'_>,
) -> Result<ExpectedRegistryIdentity> {
    let initial = InitialRegistryState {
        package_id: identity.package_id,
        environment: identity.environment,
        instance_id: identity.instance_id,
        database_id: identity.database_id,
        package_revision: identity.package_revision,
        package_sequence: identity.package_sequence,
    };
    let expected = initialize_registry_state_for_catalog(
        migration,
        runtime_role,
        &ExpectedManagedCatalog::compiled(registry),
        &initial,
    )
    .await?;
    install_empty_history_baseline_for_compiled_registry(
        migration,
        registry,
        identity.package_revision,
    )
    .await?;
    Ok(expected)
}

/// Test-only helper for the W2 feasibility kernel catalog.
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn initialize_kernel_registry_state_for_test(
    migration: &impl GenericClient,
    runtime_role: &SqlIdentifier,
    identity: RegistryStateTestIdentity<'_>,
) -> Result<ExpectedRegistryIdentity> {
    initialize_registry_state_for_catalog_test(
        migration,
        runtime_role,
        &ExpectedManagedCatalog::kernel(),
        identity,
    )
    .await
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
            "SELECT package_id, environment, instance_id, database_id,
                    active_package_revision, schema_fingerprint, package_sequence
             FROM registry_internal.registry_state
             WHERE singleton",
            &[],
        )
        .await?
        .ok_or(PostgresKernelError::RegistryUnavailable)?;
    let actual = CatalogIdentity {
        package_id: row.get(0),
        environment: row.get(1),
        instance_id: row.get(2),
        database_id: row.get(3),
        package_revision: row.get(4),
        schema_fingerprint: row.get(5),
        package_sequence: row.get(6),
    };
    actual.validate()?;
    if actual.package_id != expected.package_id
        || actual.environment != expected.environment
        || actual.instance_id != expected.instance_id
        || actual.database_id != expected.database_id
        || actual.package_revision != expected.package_revision
        || actual.schema_fingerprint != expected.schema_fingerprint
        || actual.package_sequence != expected.package_sequence
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

/// Explicit W2 compatibility wrapper. New product startup paths must pass a
/// compiled expected catalog to [`verify_catalog_identity_for_catalog`].
pub async fn verify_catalog_identity(
    client: &impl GenericClient,
    expected: &ExpectedRegistryIdentity,
    migration_role: &SqlIdentifier,
    runtime_role: &SqlIdentifier,
) -> Result<CatalogIdentity> {
    verify_catalog_identity_for_catalog(
        client,
        expected,
        &ExpectedManagedCatalog::kernel(),
        migration_role,
        runtime_role,
    )
    .await
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
    verify_exact_acl(client, runtime_role, expected_catalog).await?;
    verify_row_security(client, expected_catalog).await?;
    verify_policies(client, expected_catalog, runtime_role).await?;
    let actual = fingerprint_catalog(
        client,
        runtime_role,
        CatalogFingerprintVersion::NamedTableColumns,
    )
    .await?;
    // Existing signed packages retain their original fingerprint and physical
    // column-order checks. Never reinterpret an old hash as a normalized hash.
    if actual != expected.schema_fingerprint
        && fingerprint_catalog(
            client,
            runtime_role,
            CatalogFingerprintVersion::LegacyPhysicalColumns,
        )
        .await?
            != expected.schema_fingerprint
    {
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
                           n.nspname = 'registry_context'
                           AND p.proname IN ('evaluation_date', 'spatial_bbox_geometry')
                           AND pg_catalog.pg_get_function_identity_arguments(p.oid) = ''
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

async fn verify_exact_acl(
    client: &impl GenericClient,
    runtime_role: &SqlIdentifier,
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
        for privilege in &object.runtime_privileges {
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
    verify_exact_column_acl(client, runtime_role, expected_catalog).await?;
    Ok(())
}

async fn verify_exact_column_acl(
    client: &impl GenericClient,
    runtime_role: &SqlIdentifier,
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
    if actual != expected_catalog.column_privileges {
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
    verify_exact_acl(client, runtime_role, expected_catalog).await?;
    verify_row_security(client, expected_catalog).await?;
    verify_policies(client, expected_catalog, runtime_role).await?;
    fingerprint_catalog(
        client,
        runtime_role,
        CatalogFingerprintVersion::NamedTableColumns,
    )
    .await
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CatalogFingerprintVersion {
    LegacyPhysicalColumns,
    NamedTableColumns,
}

/// Produce the pre-normalization fingerprint for compatibility regression tests.
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn legacy_schema_fingerprint_for_test(
    client: &impl GenericClient,
    runtime_role: &SqlIdentifier,
) -> Result<String> {
    fingerprint_catalog(
        client,
        runtime_role,
        CatalogFingerprintVersion::LegacyPhysicalColumns,
    )
    .await
}

async fn fingerprint_catalog(
    client: &impl GenericClient,
    runtime_role: &SqlIdentifier,
    version: CatalogFingerprintVersion,
) -> Result<String> {
    let named_table_columns = version == CatalogFingerprintVersion::NamedTableColumns;
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
                    COALESCE(pg_catalog.pg_get_expr(d.adbin, d.adrelid), '')
             FROM deparse_context
             CROSS JOIN pg_catalog.pg_class c
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
             JOIN pg_catalog.pg_attribute a
               ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
             LEFT JOIN pg_catalog.pg_attrdef d
               ON d.adrelid = c.oid AND d.adnum = a.attnum
             WHERE n.nspname = ANY($1::text[])
               AND c.relkind IN ('r', 'v', 'S')
             ORDER BY n.nspname, c.relname,
                      CASE WHEN $2 AND c.relkind = 'r' THEN a.attname END COLLATE \"C\",
                      a.attnum",
            &[&MANAGED_SCHEMAS, &named_table_columns],
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
                    pg_catalog.pg_get_constraintdef(x.oid, false)
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
    // v5 hashes the same named table schema for both histories, including after
    // dropped-column gaps. View/sequence order and every other catalog input
    // remain covered. The distinct domain preserves exact legacy verification.
    hasher.update(if named_table_columns {
        b"breg/catalog/v5/columns"
    } else {
        b"breg/catalog/v3/columns"
    });
    for row in column_rows {
        for index in [0, 1, 2, 7, 8, 10] {
            hash_text(&mut hasher, &row.get::<_, String>(index));
        }
        for index in [3, 4, 5, 9] {
            hash_bool(&mut hasher, row.get(index));
        }
        if !named_table_columns || row.get::<_, &str>(2) != "r" {
            hasher.update(row.get::<_, i16>(6).to_be_bytes());
        }
    }
    hasher.update(b"breg/catalog/v3/constraints");
    for row in constraint_rows {
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
    hasher.update(b"breg/catalog/v3/acl");
    for row in acl_rows {
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

/// Explicit W2 compatibility wrapper.
pub async fn kernel_schema_fingerprint(
    client: &impl GenericClient,
    runtime_role: &SqlIdentifier,
) -> Result<String> {
    managed_schema_fingerprint(client, runtime_role, &ExpectedManagedCatalog::kernel()).await
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
