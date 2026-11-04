// SPDX-License-Identifier: Apache-2.0

//! Host-supplied metadata for a fixed inbound facade target.
//!
//! The engine executes source routes and projections without knowing the
//! public protocol that selected them. A host supplies the checked profile,
//! per-binding input and item projection, and effective-contract schemas as
//! one immutable attachment before the plan can be served.

use std::collections::BTreeMap;
use std::sync::Arc;

use registry_adapter_core::{AdapterProfile, ServedFilter, SourceReadSupport, SourceWriteSupport};
use serde::Serialize;
use serde_json::Value;

use crate::inbound_transform::CompiledProjectInputTransform;
use crate::project_transform::CompiledProjectTransform;
use crate::public_schema::CheckedPublicSchema;
use crate::read_request::ReadRequestTemplate;

/// A checked fixed target attached to one parsed project and pack.
#[derive(Debug)]
pub struct TargetAttachment {
    pub profile: AdapterProfile,
    /// Deterministic target bytes included in the deployment digest. They
    /// cover the public mount as well as the fixed profile definition.
    pub identity: Vec<u8>,
    /// One entry for every project binding the target selects.
    pub operations: BTreeMap<String, TargetOperation>,
}

/// Target behavior attached to one compiled source binding.
#[derive(Debug)]
pub enum TargetOperation {
    Read(Box<TargetReadOperation>),
    Write(TargetWriteOperation),
}

/// Fixed-target metadata for a source-backed read.
#[derive(Debug)]
pub struct TargetReadOperation {
    pub filters: Vec<ServedFilter>,
    pub request_template: Option<ReadRequestTemplate>,
    pub project_input_schema: Option<Arc<CheckedPublicSchema>>,
    pub project_transform: Arc<CompiledProjectTransform>,
    pub read_support: SourceReadSupport,
    pub source_input: SourceInput,
    pub item_projection: ItemProjection,
    pub effective_contract: EffectiveContractOperation,
}

/// The exact engine-native recovery form selected for one fixed-target write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceNativeReplayPlan {
    /// One outer idempotent consumer around deterministic preparation and one
    /// reviewed source-idempotent HTTP POST.
    ExactKeyedSinglePost,
}

/// Fixed-target metadata for one source-backed write. Public input validation
/// and transformation are separate: the public schema does not describe the
/// source route's private fields.
#[derive(Debug)]
pub struct TargetWriteOperation {
    pub project_input_schema: Arc<CheckedPublicSchema>,
    pub project_input_transform: Arc<CompiledProjectInputTransform>,
    pub write_support: SourceWriteSupport,
    pub native_replay: SourceNativeReplayPlan,
    pub effective_contract: EffectiveContractOperation,
}

/// How a fixed target maps admitted facade inputs to the source route body.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum SourceInput {
    EmptyObject,
    RecordId {
        header: String,
        source_input: String,
    },
    Filters,
}

/// How generic source items become the host's internal record object before
/// the already-compiled response envelope is rendered.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemProjection {
    pub record_id_member: String,
    pub value_member: String,
    pub revision_member: Option<String>,
    pub maximum_record_id_bytes: usize,
    pub maximum_record_id_characters: usize,
}

/// Host-authored effective-contract behavior for a fixed target operation.
#[derive(Clone, Debug)]
pub struct EffectiveContractOperation {
    /// Full externally reachable path, including the target mount.
    pub path: String,
    pub path_parameters: Value,
    pub request_body: Option<Value>,
    pub response_body: Value,
}

impl TargetAttachment {
    /// Apply the immutable target metadata to the generic authored plan.
    /// Every served binding must have metadata. Entries for known unserved
    /// bindings remain valid so one unavailable endpoint does not refuse the
    /// deployment; an entry naming no served or unserved binding is refused.
    pub fn apply(
        mut self,
        authored: &mut crate::load::CompiledAuthoring,
        pack: &registry_adapter_core::AdapterPack,
    ) -> Result<(AdapterProfile, Vec<u8>), crate::load::LoadError> {
        for operation in &mut authored.served {
            let attached = self.operations.remove(&operation.binding).ok_or_else(|| {
                crate::load::LoadError::Runtime(format!(
                    "binding {} has no host target attachment",
                    operation.binding
                ))
            })?;
            match attached {
                TargetOperation::Read(attached) => {
                    operation.filters = attached.filters;
                    operation.request_template = attached.request_template;
                    operation.record_schema =
                        attached.project_transform.schema().as_value().clone();
                    operation.project_input_schema = attached.project_input_schema;
                    operation.project_transform = Some(attached.project_transform);
                    operation.read_support = Some(attached.read_support);
                    operation.source_input = Some(attached.source_input);
                    operation.item_projection = Some(attached.item_projection);
                    operation.target_contract = Some(attached.effective_contract);
                }
                TargetOperation::Write(attached) => {
                    let resume = match attached.native_replay {
                        SourceNativeReplayPlan::ExactKeyedSinglePost => {
                            crate::resume::compile_source_native_single_resume_operation(
                                operation.steps.as_ref(),
                                pack,
                            )
                            .map_err(|reason| {
                                crate::load::LoadError::Runtime(format!(
                                    "binding {} source-native replay was refused: {reason}",
                                    operation.binding
                                ))
                            })?
                        }
                    };
                    operation.project_input_schema = Some(attached.project_input_schema);
                    operation.project_input_transform = Some(attached.project_input_transform);
                    operation.write_support = Some(attached.write_support);
                    operation.resume = Some(resume);
                    operation.target_contract = Some(attached.effective_contract);
                }
            }
        }
        let unserved: std::collections::BTreeSet<&str> = authored
            .unserved
            .iter()
            .map(|binding| binding.binding.as_str())
            .collect();
        if let Some(binding) = self
            .operations
            .keys()
            .find(|binding| !unserved.contains(binding.as_str()))
        {
            return Err(crate::load::LoadError::Runtime(format!(
                "host target attachment names unknown binding {binding}"
            )));
        }
        Ok((self.profile, self.identity))
    }
}
