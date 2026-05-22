// SPDX-License-Identifier: Apache-2.0
//! Registry Relay source adapter for the generic Evidence Server runtime.

use std::future::Future;
use std::pin::Pin;

use evidence_core::{
    EvidenceConfig, EvidenceError, EvidencePrincipal, SourceBindingConfig, SourceConnectorKind,
    SubjectRequest,
};
use evidence_server::SourceReader;
use serde_json::Value;

use crate::auth::Principal;
use crate::config::Config;
use crate::query::{EntityCollectionQuery, EntityFilter, EntityFilterOp, EntityQueryEngine};

pub(crate) struct RegistryRelaySourceReader<'a> {
    config: &'a Config,
    query: &'a EntityQueryEngine,
}

impl<'a> RegistryRelaySourceReader<'a> {
    pub(crate) const fn new(config: &'a Config, query: &'a EntityQueryEngine) -> Self {
        Self { config, query }
    }
}

impl SourceReader for RegistryRelaySourceReader<'_> {
    fn read_one<'a>(
        &'a self,
        binding: &'a SourceBindingConfig,
        subject: &'a SubjectRequest,
        purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
        Box::pin(async move {
            if let Some(connection) = remote_source_connection(self.config, binding) {
                read_remote_registry_data_api_one(
                    self.config,
                    connection,
                    binding,
                    subject,
                    purpose,
                )
                .await
            } else {
                match binding.connector {
                    SourceConnectorKind::RegistryDataApi => {
                        read_registry_data_api_one(self.query, binding, subject).await
                    }
                    SourceConnectorKind::Dci => {
                        read_dci_one(self.config, self.query, binding, subject).await
                    }
                }
            }
        })
    }

    fn required_scopes(
        &self,
        evidence: &EvidenceConfig,
        claim_id: &str,
    ) -> Result<Vec<String>, EvidenceError> {
        let mut scopes = Vec::new();
        collect_claim_required_scopes(self.config, evidence, claim_id, &mut scopes)?;
        scopes.sort();
        scopes.dedup();
        Ok(scopes)
    }
}

fn remote_source_connection<'a>(
    config: &'a Config,
    binding: &SourceBindingConfig,
) -> Option<&'a evidence_core::config::SourceConnectionConfig> {
    binding
        .connection
        .as_deref()
        .and_then(|connection| config.evidence.source_connections.get(connection))
}

async fn read_remote_registry_data_api_one(
    config: &Config,
    connection: &evidence_core::config::SourceConnectionConfig,
    binding: &SourceBindingConfig,
    subject: &SubjectRequest,
    purpose: &str,
) -> Result<Value, EvidenceError> {
    let token =
        std::env::var(&connection.token_env).map_err(|_| EvidenceError::SourceUnavailable)?;
    let lookup_field = remote_lookup_field(config, binding);
    let lookup_value = lookup_value(binding, subject)?;
    let fields = remote_projected_fields(config, binding, &lookup_field);
    let base = connection.base_url.trim_end_matches('/');
    let url = format!("{base}/datasets/{}/{}", binding.dataset, binding.entity);
    let client = reqwest::Client::new();
    let response = client
        .get(url)
        .bearer_auth(token)
        .header("accept", "application/json")
        .header("data-purpose", purpose)
        .query(&[
            ("limit", "2".to_string()),
            ("fields", fields.join(",")),
            (lookup_field.as_str(), value_query_string(&lookup_value)?),
        ])
        .send()
        .await
        .map_err(|_| EvidenceError::SourceUnavailable)?;
    if !response.status().is_success() {
        return Err(EvidenceError::SourceUnavailable);
    }
    let body = response
        .json::<Value>()
        .await
        .map_err(|_| EvidenceError::SourceUnavailable)?;
    let rows = body
        .get("data")
        .and_then(Value::as_array)
        .ok_or(EvidenceError::SourceUnavailable)?;
    match rows.len() {
        0 => Err(EvidenceError::SourceNotFound),
        1 => rows
            .first()
            .cloned()
            .ok_or(EvidenceError::SourceUnavailable),
        _ => Err(EvidenceError::SourceAmbiguous),
    }
}

fn value_query_string(value: &Value) -> Result<String, EvidenceError> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Number(value) => Ok(value.to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        _ => Err(EvidenceError::InvalidRequest),
    }
}

fn remote_lookup_field(config: &Config, binding: &SourceBindingConfig) -> String {
    if binding.connector == SourceConnectorKind::Dci {
        if let Some(connection) = binding.connection.as_deref() {
            if let Some(field) = config
                .standards
                .spdci
                .as_ref()
                .and_then(|spdci| spdci.registries.get(connection))
                .and_then(|registry| {
                    registry
                        .identifiers
                        .get(&binding.lookup.field)
                        .or_else(|| registry.expression_fields.get(&binding.lookup.field))
                })
            {
                return field.clone();
            }
        }
    }
    binding.lookup.field.clone()
}

fn remote_projected_fields(
    config: &Config,
    binding: &SourceBindingConfig,
    lookup_field: &str,
) -> Vec<String> {
    let mut fields = projected_source_fields_with_lookup(binding, lookup_field);
    if binding.connector == SourceConnectorKind::Dci {
        if let Some(connection) = binding.connection.as_deref() {
            if let Some(registry) = config
                .standards
                .spdci
                .as_ref()
                .and_then(|spdci| spdci.registries.get(connection))
            {
                for field in registry.expression_fields.values() {
                    if binding.fields.values().any(|source| source.field == *field) {
                        fields.push(field.clone());
                    }
                }
            }
        }
    }
    fields.sort();
    fields.dedup();
    fields
}

async fn read_registry_data_api_one(
    query: &EntityQueryEngine,
    binding: &SourceBindingConfig,
    subject: &SubjectRequest,
) -> Result<Value, EvidenceError> {
    read_entity_one(
        query,
        &binding.dataset,
        &binding.entity,
        &binding.lookup.field,
        lookup_value(binding, subject)?,
        projected_source_fields(binding),
    )
    .await
}

async fn read_dci_one(
    config: &Config,
    query: &EntityQueryEngine,
    binding: &SourceBindingConfig,
    subject: &SubjectRequest,
) -> Result<Value, EvidenceError> {
    let connection = binding
        .connection
        .as_deref()
        .ok_or(EvidenceError::SourceUnavailable)?;
    let registry = config
        .standards
        .spdci
        .as_ref()
        .and_then(|spdci| spdci.registries.get(connection))
        .ok_or(EvidenceError::SourceUnavailable)?;
    if registry.dataset.as_str() != binding.dataset || registry.entity != binding.entity {
        return Err(EvidenceError::SourceUnavailable);
    }
    let field = registry
        .identifiers
        .get(&binding.lookup.field)
        .or_else(|| registry.expression_fields.get(&binding.lookup.field))
        .map(String::as_str)
        .unwrap_or(binding.lookup.field.as_str());
    read_entity_one(
        query,
        &binding.dataset,
        &binding.entity,
        field,
        lookup_value(binding, subject)?,
        projected_source_fields_with_lookup(binding, field),
    )
    .await
}

async fn read_entity_one(
    query: &EntityQueryEngine,
    dataset: &str,
    entity: &str,
    lookup_field: &str,
    lookup_value: Value,
    fields: Vec<String>,
) -> Result<Value, EvidenceError> {
    let rows = query
        .read_collection(
            dataset,
            entity,
            EntityCollectionQuery {
                fields: Some(fields),
                limit: Some(2),
                after_primary_key: None,
                filters: Vec::new(),
                trusted_filters: vec![EntityFilter {
                    field: lookup_field.to_string(),
                    op: EntityFilterOp::Eq,
                    value: lookup_value,
                }],
                expansions: Vec::new(),
            },
        )
        .await
        .map_err(|_| EvidenceError::SourceUnavailable)?;
    match rows.rows.len() {
        0 => Err(EvidenceError::SourceNotFound),
        1 => Ok(rows.rows.into_iter().next().expect("one row exists")),
        _ => Err(EvidenceError::SourceAmbiguous),
    }
}

fn lookup_value(
    binding: &SourceBindingConfig,
    subject: &SubjectRequest,
) -> Result<Value, EvidenceError> {
    if binding.lookup.op != "eq" {
        return Err(EvidenceError::InvalidRequest);
    }
    match binding.lookup.input.as_str() {
        "subject_id" | "subject.id" => Ok(Value::String(subject.id.clone())),
        _ => Err(EvidenceError::InvalidRequest),
    }
}

fn collect_claim_required_scopes(
    config: &Config,
    evidence: &EvidenceConfig,
    claim_id: &str,
    scopes: &mut Vec<String>,
) -> Result<(), EvidenceError> {
    let claim = evidence_server::find_claim(evidence, claim_id)?;
    for binding in claim.source_bindings.values() {
        if let Some(scope) = binding.required_scope.as_deref() {
            scopes.push(scope.to_string());
        } else {
            scopes.push(entity_evidence_scope(
                config,
                &binding.dataset,
                &binding.entity,
            )?);
        }
    }
    for dep in &claim.depends_on {
        collect_claim_required_scopes(config, evidence, dep, scopes)?;
    }
    Ok(())
}

fn entity_evidence_scope(
    config: &Config,
    dataset_id: &str,
    entity_name: &str,
) -> Result<String, EvidenceError> {
    let dataset = config
        .datasets
        .iter()
        .find(|dataset| dataset.id.as_str() == dataset_id)
        .ok_or(EvidenceError::SourceUnavailable)?;
    let entity = dataset
        .entities
        .iter()
        .find(|entity| entity.name == entity_name)
        .ok_or(EvidenceError::SourceUnavailable)?;
    if entity.access.evidence_verification_scope.is_empty() {
        Ok(entity.access.read_scope.clone())
    } else {
        Ok(entity.access.evidence_verification_scope.clone())
    }
}

fn projected_source_fields(binding: &SourceBindingConfig) -> Vec<String> {
    projected_source_fields_with_lookup(binding, &binding.lookup.field)
}

fn projected_source_fields_with_lookup(
    binding: &SourceBindingConfig,
    lookup_field: &str,
) -> Vec<String> {
    let mut fields = vec![lookup_field.to_string()];
    for field in binding.fields.values() {
        fields.push(field.field.clone());
    }
    fields.sort();
    fields.dedup();
    fields
}

pub(crate) fn evidence_principal(principal: &Principal) -> EvidencePrincipal {
    EvidencePrincipal {
        principal_id: principal.principal_id.clone(),
        scopes: principal.scopes.iter().map(str::to_string).collect(),
    }
}

pub(crate) fn require_evaluation_access(
    evidence: &EvidenceConfig,
    source: &RegistryRelaySourceReader<'_>,
    principal: &EvidencePrincipal,
    evaluation: &evidence_core::StoredEvaluation,
) -> Result<(), EvidenceError> {
    for claim_id in &evaluation.claim_ids {
        for scope in source.required_scopes(evidence, claim_id)? {
            if !principal.has_scope(&scope) {
                return Err(EvidenceError::ScopeDenied { required: scope });
            }
        }
    }
    Ok(())
}
