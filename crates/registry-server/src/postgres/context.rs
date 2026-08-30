// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use deadpool_postgres::{Client, Transaction};
use registry_platform_canonical_json::canonicalize_json;
use serde_json::{json, Value};

use crate::contract::BoundaryOperator;
use crate::data::{validate_field_value as validate_data_field_value, FieldValue};
use crate::model::CompiledRegistry;

use super::{ExpectedRegistryIdentity, PostgresKernelError, RegistryLockKey, Result};

const MAX_CONTEXT_VALUE_BYTES: usize = 512;
const MAX_BOUNDARY_SET_VALUES: usize = 64;
const MAX_BOUNDARY_CONTEXT_BYTES: usize = 64 * 1024;
const MAX_ENTITY_ID_BYTES: usize = 256;

/// One finite compiler-validated row boundary installed into PostgreSQL.
#[derive(Clone, Eq, PartialEq)]
pub enum RowBoundaryContext {
    Equals {
        field: String,
        value: String,
    },
    In {
        field: String,
        values: BTreeSet<String>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RowBoundaryOperator {
    Equals,
    In,
}

impl RowBoundaryOperator {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Equals => "equals",
            Self::In => "in",
        }
    }
}

impl RowBoundaryContext {
    #[must_use]
    pub fn field(&self) -> &str {
        match self {
            Self::Equals { field, .. } | Self::In { field, .. } => field,
        }
    }

    #[must_use]
    pub fn operator(&self) -> RowBoundaryOperator {
        match self {
            Self::Equals { .. } => RowBoundaryOperator::Equals,
            Self::In { .. } => RowBoundaryOperator::In,
        }
    }

    #[must_use]
    pub fn values(&self) -> Vec<&str> {
        match self {
            Self::Equals { value, .. } => vec![value],
            Self::In { values, .. } => values.iter().map(String::as_str).collect(),
        }
    }
}

impl fmt::Debug for RowBoundaryContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RowBoundaryContext")
            .field("field", &self.field())
            .field("operator", &self.operator())
            .field("values", &"<redacted>")
            .finish()
    }
}

/// Complete verified authority installed into one PostgreSQL transaction.
///
/// Production construction is possible only against an exact compiled entity
/// and access profile. Raw tokens, headers, query values, and dynamic setting
/// names never enter this type.
#[derive(Clone, Eq, PartialEq)]
pub struct ClaimContext {
    entity_id: String,
    principal: Option<String>,
    access_profile: String,
    purpose: Option<String>,
    row_boundaries: Vec<RowBoundaryContext>,
    canonical_row_boundaries: String,
}

impl ClaimContext {
    pub fn for_compiled(
        registry: &CompiledRegistry,
        entity_id: &str,
        principal: Option<String>,
        access_profile: &str,
        purpose: Option<String>,
        row_boundaries: Vec<RowBoundaryContext>,
    ) -> Result<Self> {
        if entity_id.is_empty() || entity_id.len() > MAX_ENTITY_ID_BYTES {
            return Err(invalid_context());
        }
        let entity = registry
            .entities()
            .get(entity_id)
            .ok_or_else(invalid_context)?;
        let profile = entity
            .access_profiles
            .get(access_profile)
            .ok_or_else(invalid_context)?;
        validate_required_context_value(access_profile)?;
        principal
            .as_deref()
            .map(validate_required_context_value)
            .transpose()?;
        purpose
            .as_deref()
            .map(validate_required_context_value)
            .transpose()?;
        if !profile.anonymous && principal.is_none() {
            return Err(invalid_context());
        }
        if !profile.required_purposes.is_empty()
            && !purpose
                .as_ref()
                .is_some_and(|value| profile.required_purposes.contains(value))
        {
            return Err(invalid_context());
        }
        if row_boundaries.len() != profile.row_boundaries.len() {
            return Err(invalid_context());
        }
        for (actual, expected) in row_boundaries.iter().zip(&profile.row_boundaries) {
            let expected_operator = match expected.operator {
                BoundaryOperator::Equals => RowBoundaryOperator::Equals,
                BoundaryOperator::In => RowBoundaryOperator::In,
            };
            if actual.field() != expected.field || actual.operator() != expected_operator {
                return Err(invalid_context());
            }
            validate_boundary(actual)?;
            let field_type = if expected.field == entity.canonical_id.id {
                &entity.canonical_id.field_type
            } else {
                &entity
                    .fields
                    .get(&expected.field)
                    .ok_or_else(invalid_context)?
                    .field_type
            };
            for value in actual.values() {
                validate_field_value(value, field_type)?;
            }
        }
        let canonical_row_boundaries = canonical_boundaries(&row_boundaries)?;
        Ok(Self {
            entity_id: entity_id.to_owned(),
            principal,
            access_profile: access_profile.to_owned(),
            purpose,
            row_boundaries,
            canonical_row_boundaries,
        })
    }

    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    pub fn kernel_for_test(
        principal: String,
        access_profile: String,
        purpose: Option<String>,
        authority: String,
    ) -> Result<Self> {
        validate_required_context_value(&principal)?;
        validate_required_context_value(&access_profile)?;
        purpose
            .as_deref()
            .map(validate_required_context_value)
            .transpose()?;
        validate_required_context_value(&authority)?;
        let row_boundaries = vec![RowBoundaryContext::Equals {
            field: "authority".to_owned(),
            value: authority,
        }];
        let canonical_row_boundaries = canonical_boundaries(&row_boundaries)?;
        Ok(Self {
            entity_id: "kernel_records".to_owned(),
            principal: Some(principal),
            access_profile,
            purpose,
            row_boundaries,
            canonical_row_boundaries,
        })
    }

    #[must_use]
    pub fn entity_id(&self) -> &str {
        &self.entity_id
    }

    #[must_use]
    pub fn principal(&self) -> Option<&str> {
        self.principal.as_deref()
    }

    #[must_use]
    pub fn access_profile(&self) -> &str {
        &self.access_profile
    }

    #[must_use]
    pub fn purpose(&self) -> Option<&str> {
        self.purpose.as_deref()
    }

    #[must_use]
    pub fn row_boundaries(&self) -> &[RowBoundaryContext] {
        &self.row_boundaries
    }

    pub fn validate(&self) -> Result<()> {
        validate_required_context_value(&self.entity_id)?;
        self.principal
            .as_deref()
            .map(validate_required_context_value)
            .transpose()?;
        validate_required_context_value(&self.access_profile)?;
        self.purpose
            .as_deref()
            .map(validate_required_context_value)
            .transpose()?;
        for boundary in &self.row_boundaries {
            validate_boundary(boundary)?;
        }
        if canonical_boundaries(&self.row_boundaries)? != self.canonical_row_boundaries {
            return Err(invalid_context());
        }
        Ok(())
    }
}

impl fmt::Debug for ClaimContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaimContext")
            .field("entity_id", &self.entity_id)
            .field("principal", &self.principal.as_ref().map(|_| "<redacted>"))
            .field("access_profile", &self.access_profile)
            .field("purpose", &self.purpose.as_ref().map(|_| "<redacted>"))
            .field("row_boundaries", &self.row_boundaries)
            .finish()
    }
}

fn validate_boundary(boundary: &RowBoundaryContext) -> Result<()> {
    validate_required_context_value(boundary.field())?;
    let values = boundary.values();
    if values.is_empty()
        || values.len() > MAX_BOUNDARY_SET_VALUES
        || values
            .iter()
            .any(|value| validate_required_context_value(value).is_err())
    {
        return Err(invalid_context());
    }
    Ok(())
}

fn validate_required_context_value(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_CONTEXT_VALUE_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(invalid_context());
    }
    Ok(())
}

pub(crate) fn validate_field_value(
    value: &str,
    field_type: &crate::contract::FieldTypeSource,
) -> Result<()> {
    if !validate_data_field_value(FieldValue::Text(value), field_type) {
        return Err(invalid_context());
    }
    Ok(())
}

fn canonical_boundaries(boundaries: &[RowBoundaryContext]) -> Result<String> {
    let value = Value::Array(
        boundaries
            .iter()
            .map(|boundary| {
                json!({
                    "field": boundary.field(),
                    "operator": boundary.operator().as_str(),
                    "values": boundary.values(),
                })
            })
            .collect(),
    );
    let bytes = canonicalize_json(&value).map_err(|_| invalid_context())?;
    if bytes.len() > MAX_BOUNDARY_CONTEXT_BYTES {
        return Err(invalid_context());
    }
    String::from_utf8(bytes).map_err(|_| invalid_context())
}

fn invalid_context() -> PostgresKernelError {
    PostgresKernelError::Configuration("verified database context is incomplete or invalid")
}

/// A record transaction that has passed maintenance, package, and claim gates.
pub struct GuardedTransaction<'a> {
    transaction: Transaction<'a>,
}

impl GuardedTransaction<'_> {
    #[allow(
        dead_code,
        reason = "trusted transaction modules consume this crate-private handle"
    )]
    pub(crate) fn transaction(&self) -> &tokio_postgres::Transaction<'_> {
        &self.transaction
    }

    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    pub fn transaction_for_test(&self) -> &tokio_postgres::Transaction<'_> {
        self.transaction()
    }

    pub async fn commit(self) -> Result<()> {
        self.transaction.commit().await?;
        Ok(())
    }

    pub async fn rollback(self) -> Result<()> {
        self.transaction.rollback().await?;
        Ok(())
    }
}

/// Starts a record transaction and installs authority only after the shared
/// Registry lock and exact active-package checks succeed.
pub async fn begin_record_transaction<'a>(
    client: &'a mut Client,
    lock_key: RegistryLockKey,
    lock_timeout: Duration,
    expected: &ExpectedRegistryIdentity,
    claims: &ClaimContext,
) -> Result<GuardedTransaction<'a>> {
    expected.validate()?;
    claims.validate()?;
    if lock_timeout.is_zero() || lock_timeout > Duration::from_secs(30) {
        return Err(PostgresKernelError::Configuration(
            "record lock timeout must be between 1 millisecond and 30 seconds",
        ));
    }
    let transaction = client.transaction().await?;
    let timeout_millis = i32::try_from(lock_timeout.as_millis()).map_err(|_| {
        PostgresKernelError::Configuration("record lock timeout is outside PostgreSQL bounds")
    })?;
    transaction
        .execute(
            "SELECT set_config('lock_timeout', $1::text, true)",
            &[&format!("{timeout_millis}ms")],
        )
        .await?;
    transaction
        .execute(
            "SELECT pg_advisory_xact_lock_shared($1)",
            &[&lock_key.get()],
        )
        .await
        .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
    let state = transaction
        .query_opt(
            "SELECT package_id, environment, instance_id, database_id,
                    active_package_revision, schema_fingerprint, package_sequence,
                    maintenance_status
             FROM registry_internal.registry_state
             WHERE singleton",
            &[],
        )
        .await?
        .ok_or(PostgresKernelError::RegistryUnavailable)?;
    let ready = state.get::<_, String>(7) == "ready"
        && state.get::<_, String>(0) == expected.package_id
        && state.get::<_, String>(1) == expected.environment
        && state.get::<_, String>(2) == expected.instance_id
        && state.get::<_, String>(3) == expected.database_id
        && state.get::<_, String>(4) == expected.package_revision
        && state.get::<_, String>(5) == expected.schema_fingerprint
        && state.get::<_, i64>(6) == expected.package_sequence;
    if !ready {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    transaction
        .execute(
            "SELECT set_config('registry.principal', $1, true),
                    set_config('registry.access_profile', $2, true),
                    set_config('registry.purpose', $3, true),
                    set_config('registry.row_boundaries', $4, true),
                    set_config('registry.active_package_revision', $5, true)",
            &[
                &claims.principal.as_deref().unwrap_or(""),
                &claims.access_profile,
                &claims.purpose.as_deref().unwrap_or(""),
                &claims.canonical_row_boundaries,
                &expected.package_revision,
            ],
        )
        .await?;
    Ok(GuardedTransaction { transaction })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::compiler::{compile_project, CompileProfile};
    use crate::contract::{
        parse_project_json, AccessGrantSource, Classification, EntitySource, FieldSource,
        FieldTypeSource, MutationMode, Operation, ProjectAccessProfileSource, RegistryProject,
        RowBoundarySource,
    };

    use super::*;

    #[test]
    fn compiled_context_is_exact_bounded_and_value_redacted() {
        let registry = compiled_registry();
        let boundaries = vec![
            RowBoundaryContext::Equals {
                field: "tenant".to_owned(),
                value: "tenant-a".to_owned(),
            },
            RowBoundaryContext::In {
                field: "region".to_owned(),
                values: BTreeSet::from(["north".to_owned(), "south".to_owned()]),
            },
        ];
        let context = ClaimContext::for_compiled(
            &registry,
            "entry",
            Some("principal-canary".to_owned()),
            "operator",
            Some("operations".to_owned()),
            boundaries.clone(),
        )
        .expect("exact compiled context is accepted");
        assert_eq!(context.entity_id(), "entry");
        assert_eq!(context.access_profile(), "operator");
        assert_eq!(context.row_boundaries(), boundaries);
        assert_eq!(
            context.canonical_row_boundaries,
            r#"[{"field":"tenant","operator":"equals","values":["tenant-a"]},{"field":"region","operator":"in","values":["north","south"]}]"#
        );
        let debug = format!("{context:?}");
        assert!(!debug.contains("principal-canary"));
        assert!(!debug.contains("tenant-a"));

        assert!(ClaimContext::for_compiled(
            &registry,
            "entry",
            None,
            "operator",
            Some("operations".to_owned()),
            boundaries.clone(),
        )
        .is_err());
        assert!(ClaimContext::for_compiled(
            &registry,
            "entry",
            Some("principal".to_owned()),
            "operator",
            Some("wrong".to_owned()),
            boundaries.clone(),
        )
        .is_err());
        assert!(ClaimContext::for_compiled(
            &registry,
            "entry",
            Some("principal".to_owned()),
            "operator",
            Some("operations".to_owned()),
            boundaries.into_iter().rev().collect(),
        )
        .is_err());
    }

    #[test]
    fn compiled_context_rejects_every_noncanonical_field_value_before_postgres() {
        let registry = compiled_typed_registry();
        let valid = typed_boundaries();
        ClaimContext::for_compiled(
            &registry,
            "typed-entry",
            Some("principal".to_owned()),
            "typed",
            None,
            valid.clone(),
        )
        .expect("canonical values for every compiled field type are accepted");

        let invalid = [
            (0, equals("enabled", "TRUE")),
            (1, in_values("count", &["01"])),
            (1, in_values("count", &["9223372036854775808"])),
            (2, equals("amount", "01.20")),
            (2, equals("amount", "10.00")),
            (3, equals("effective-on", "2023-02-29")),
            (4, in_values("observed-at", &["2024-01-02 03:04:05+00"])),
            (5, equals("identifier", "123e4567e89b12d3a456426614174000")),
            (
                5,
                equals("identifier", "123E4567-E89B-12D3-A456-426614174000"),
            ),
            (
                6,
                in_values("parent", &["urn:uuid:123e4567-e89b-12d3-a456-426614174000"]),
            ),
            (
                6,
                in_values("parent", &["123E4567-E89B-12D3-A456-426614174000"]),
            ),
            (7, equals("short-name", "abcde")),
            (8, in_values("notes", &["1234567"])),
            (9, equals("color", "green")),
        ];
        for (index, replacement) in invalid {
            let mut boundaries = valid.clone();
            boundaries[index] = replacement;
            let error = ClaimContext::for_compiled(
                &registry,
                "typed-entry",
                Some("principal".to_owned()),
                "typed",
                None,
                boundaries,
            )
            .expect_err("noncanonical typed value must be refused before a transaction");
            assert_eq!(
                error.to_string(),
                "invalid PostgreSQL configuration: verified database context is incomplete or invalid"
            );
            assert!(!error.to_string().contains("green"));
        }
    }

    #[test]
    fn compiled_context_accepts_a_canonical_id_row_boundary() {
        let registry = compiled_registry();
        ClaimContext::for_compiled(
            &registry,
            "entry",
            Some("principal".to_owned()),
            "viewer",
            None,
            vec![equals("id", "123e4567-e89b-12d3-a456-426614174000")],
        )
        .expect("the compiled canonical UUID boundary is accepted");
        assert!(ClaimContext::for_compiled(
            &registry,
            "entry",
            Some("principal".to_owned()),
            "viewer",
            None,
            vec![equals("id", "not-a-uuid")],
        )
        .is_err());
    }

    fn equals(field: &str, value: &str) -> RowBoundaryContext {
        RowBoundaryContext::Equals {
            field: field.to_owned(),
            value: value.to_owned(),
        }
    }

    fn in_values(field: &str, values: &[&str]) -> RowBoundaryContext {
        RowBoundaryContext::In {
            field: field.to_owned(),
            values: values.iter().map(|value| (*value).to_owned()).collect(),
        }
    }

    fn typed_boundaries() -> Vec<RowBoundaryContext> {
        vec![
            equals("enabled", "true"),
            in_values("count", &["-1", "2"]),
            equals("amount", "1.20"),
            equals("effective-on", "2024-02-29"),
            in_values("observed-at", &["2024-01-02T03:04:05Z"]),
            equals("identifier", "123e4567-e89b-12d3-a456-426614174000"),
            in_values("parent", &["123e4567-e89b-12d3-a456-426614174001"]),
            equals("short-name", "abcd"),
            in_values("notes", &["abcdef"]),
            equals("color", "red"),
        ]
    }

    fn compiled_typed_registry() -> CompiledRegistry {
        let project = parse_project_json(
            br#"{
              "apiVersion":"registry.registrystack.org/v1alpha1",
              "kind":"RegistryProject",
              "registry":{"id":"typed-context","version":"1","defaultLanguage":"en"},
              "entities":[
                {
                  "id":"parent-entry","route":"parents","mutationMode":"mutable",
                  "fields":[{"id":"name","type":"string","minLength":1,"maxLength":8,"required":true,"classification":"internal"}]
                },
                {
                  "id":"typed-entry","route":"typed","mutationMode":"mutable",
                  "fields":[
                    {"id":"enabled","type":"boolean","required":true,"classification":"internal"},
                    {"id":"count","type":"int64","required":true,"classification":"internal"},
                    {"id":"amount","type":"decimal","precision":4,"scale":2,"minimum":"0.00","maximum":"9.99","required":true,"classification":"internal"},
                    {"id":"effective-on","type":"date","required":true,"classification":"internal"},
                    {"id":"observed-at","type":"timestamp","required":true,"classification":"internal"},
                    {"id":"identifier","type":"uuid","required":true,"classification":"internal"},
                    {"id":"parent","type":"reference","target":"parent-entry","required":true,"classification":"internal"},
                    {"id":"short-name","type":"string","minLength":1,"maxLength":4,"required":true,"classification":"internal"},
                    {"id":"notes","type":"text","maxLength":6,"required":true,"classification":"internal"},
                    {"id":"color","type":"vocabulary-code","vocabulary":"colors","required":true,"classification":"internal"}
                  ]
                }
              ],
              "accessProfiles":[{
                "id":"typed","default":true,"principalClaim":"registry_principal",
                "grants":[
                  {
                    "entity":"parent-entry","operations":["get"],"readableFields":["name"]
                  },
                  {
                    "entity":"typed-entry","operations":["get"],
                    "readableFields":["enabled","count","amount","effective-on","observed-at","identifier","parent","short-name","notes","color"],
                    "rowBoundaries":[
                      {"field":"enabled","claim":"enabled_claim","operator":"equals"},
                      {"field":"count","claim":"count_claim","operator":"in"},
                      {"field":"amount","claim":"amount_claim","operator":"equals"},
                      {"field":"effective-on","claim":"date_claim","operator":"equals"},
                      {"field":"observed-at","claim":"timestamp_claim","operator":"in"},
                      {"field":"identifier","claim":"uuid_claim","operator":"equals"},
                      {"field":"parent","claim":"reference_claim","operator":"in"},
                      {"field":"short-name","claim":"string_claim","operator":"equals"},
                      {"field":"notes","claim":"text_claim","operator":"in"},
                      {"field":"color","claim":"vocabulary_claim","operator":"equals"}
                    ]
                  }
                ]
              }],
              "vocabularies":[{"id":"colors","values":["red","blue"]}]
            }"#,
        )
        .expect("typed context project parses");
        compile_project(&project, &[], CompileProfile::Authoring)
            .expect("typed context project compiles")
    }

    fn compiled_registry() -> CompiledRegistry {
        let mut operations = BTreeSet::new();
        operations.insert(Operation::Get);
        let project = RegistryProject {
            api_version: crate::compiler::AUTHORING_API_VERSION.to_owned(),
            kind: "RegistryProject".to_owned(),
            registry: crate::contract::RegistryIdentitySource {
                id: "context-test".to_owned(),
                version: "0.1.0".to_owned(),
                default_language: "en".to_owned(),
            },
            package: None,
            manifest_projection: None,
            modules: Vec::new(),
            entities: vec![EntitySource {
                id: "entry".to_owned(),
                route: "entries".to_owned(),
                mutation_mode: MutationMode::Mutable,
                tombstone: false,
                batch: None,
                classification: Classification::Internal,
                derived: Vec::new(),
                selector_profiles: Vec::new(),
                read_paths: Vec::new(),
                fields: vec![
                    FieldSource {
                        id: "tenant".to_owned(),
                        api_name: None,
                        field_type: FieldTypeSource::String {
                            min_length: 1,
                            max_length: 64,
                        },
                        required: true,
                        classification: Classification::Internal,
                        valid_time_role: None,
                    },
                    FieldSource {
                        id: "region".to_owned(),
                        api_name: None,
                        field_type: FieldTypeSource::String {
                            min_length: 1,
                            max_length: 64,
                        },
                        required: true,
                        classification: Classification::Internal,
                        valid_time_role: None,
                    },
                ],
                constraints: Vec::new(),
                temporal: None,
                indexes: Vec::new(),
                access_profiles: Vec::new(),
                events: Vec::new(),
            }],
            access_profiles: vec![
                ProjectAccessProfileSource {
                    id: "operator".to_owned(),
                    default: true,
                    anonymous: false,
                    principal_claim: Some("registry_principal".to_owned()),
                    required_scopes: BTreeSet::new(),
                    required_purposes: BTreeSet::from(["operations".to_owned()]),
                    grants: vec![AccessGrantSource {
                        entity: "entry".to_owned(),
                        operations: operations.clone(),
                        readable_fields: BTreeSet::from(["tenant".to_owned(), "region".to_owned()]),
                        writable_fields: BTreeSet::new(),
                        filterable_fields: BTreeSet::new(),
                        sortable_fields: BTreeSet::new(),
                        row_boundaries: vec![
                            RowBoundarySource {
                                field: "tenant".to_owned(),
                                claim: "tenant_claim".to_owned(),
                                operator: BoundaryOperator::Equals,
                            },
                            RowBoundarySource {
                                field: "region".to_owned(),
                                claim: "region_claim".to_owned(),
                                operator: BoundaryOperator::In,
                            },
                        ],
                        revision_access: false,
                        allow_data_export: false,
                        lookups: Vec::new(),
                        read_paths: Vec::new(),
                        allow_count: false,
                    }],
                },
                ProjectAccessProfileSource {
                    id: "viewer".to_owned(),
                    default: false,
                    anonymous: false,
                    principal_claim: Some("registry_principal".to_owned()),
                    required_scopes: BTreeSet::new(),
                    required_purposes: BTreeSet::new(),
                    grants: vec![AccessGrantSource {
                        entity: "entry".to_owned(),
                        operations,
                        readable_fields: BTreeSet::from(["tenant".to_owned()]),
                        writable_fields: BTreeSet::new(),
                        filterable_fields: BTreeSet::new(),
                        sortable_fields: BTreeSet::new(),
                        row_boundaries: vec![RowBoundarySource {
                            field: "id".to_owned(),
                            claim: "record_id_claim".to_owned(),
                            operator: BoundaryOperator::Equals,
                        }],
                        revision_access: false,
                        allow_data_export: false,
                        lookups: Vec::new(),
                        read_paths: Vec::new(),
                        allow_count: false,
                    }],
                },
            ],
            vocabularies: Vec::new(),
        };
        compile_project(&project, &[], CompileProfile::Authoring).expect("test project compiles")
    }
}
